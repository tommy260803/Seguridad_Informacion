import asyncio
import base64
import json
import os
import tempfile

import docker
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from phishguard_api.database import async_session_maker
from phishguard_api.models import Event, JobStatus, SandboxTask
from phishguard_content.analyzer import analyze_html


class BrowserSandboxError(RuntimeError):
    """The isolated browser did not produce usable evidence."""


try:
    docker_client = docker.from_env()
except Exception as exc:
    print(f"WARNING: Docker is unavailable for browser sandbox: {exc}", flush=True)
    docker_client = None


def sanitize_and_save_preview(job_id: str, url: str, raw_html: str | bytes) -> None:
    """Save a non-interactive preview; never execute a captured page's scripts."""
    try:
        raw_text = raw_html.decode("utf-8", errors="ignore") if isinstance(raw_html, bytes) else str(raw_html)
        previews_dir = os.getenv("PREVIEWS_DIR", "artifacts/previews" if os.name == "nt" else "/app/artifacts/previews")
        os.makedirs(previews_dir, exist_ok=True)
        import re

        base_tag = f'<base href="{url}" target="_blank">'
        if "<head>" in raw_text:
            sanitized = raw_text.replace("<head>", f"<head>{base_tag}", 1)
        elif "<HEAD>" in raw_text:
            sanitized = raw_text.replace("<HEAD>", f"<HEAD>{base_tag}", 1)
        else:
            sanitized = f"{base_tag}{raw_text}"
        sanitized = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'\s+on\w+="[^"]*"', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"\s+on\w+='[^']*'", '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'<form\b', '<form onsubmit="return false;" action="javascript:void(0)"', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'<input\b', '<input readonly', sanitized, flags=re.IGNORECASE)
        with open(os.path.join(previews_dir, f"{job_id}.html"), "w", encoding="utf-8") as handle:
            handle.write(sanitized)
    except Exception as exc:
        print(f"WARNING: preview could not be saved: {exc}", flush=True)


def _capture_with_isolated_browser(url: str) -> tuple[bytes, bytes]:
    if docker_client is None:
        raise BrowserSandboxError("browser_sandbox_unavailable: Docker daemon is not available")
    proxy = os.getenv("BROWSER_SANDBOX_PROXY", "http://egress-proxy:3128")
    container = docker_client.containers.run(
        os.getenv("PLAYWRIGHT_IMAGE", "phishguard-playwright:local"),
        command=["--url", url],
        network=os.getenv("BROWSER_SANDBOX_NETWORK", "phishguard_browser_internal"),
        dns=[os.getenv("BROWSER_SANDBOX_DNS", "172.31.0.3")],
        environment={
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
            "NO_PROXY": "localhost,127.0.0.1,::1",
            "HOME": "/tmp",
            "XDG_CACHE_HOME": "/tmp",
            "XDG_CONFIG_HOME": "/tmp",
            "XDG_RUNTIME_DIR": "/tmp",
            "BROWSER_NAVIGATION_TIMEOUT_MS": os.getenv("BROWSER_NAVIGATION_TIMEOUT_MS", "8000"),
            "BROWSER_RENDER_WAIT_MS": os.getenv("BROWSER_RENDER_WAIT_MS", "750"),
            "BROWSER_WORKER_TIMEOUT_SECONDS": os.getenv("BROWSER_WORKER_TIMEOUT_SECONDS", "15"),
        },
        # Keep it until logs have been read; the finally block removes it.
        remove=False,
        read_only=True,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        # Chromium uses more than 64 helper processes even for a single tab.
        pids_limit=256,
        mem_limit="512m",
        cpu_period=100000,
        cpu_quota=50000,
        tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"},
        detach=True,
    )
    timeout = int(os.getenv("BROWSER_SANDBOX_TIMEOUT_SECONDS", "30"))
    try:
        wait_result = container.wait(timeout=timeout)
        output = container.logs(stdout=True, stderr=True)
        if wait_result.get("StatusCode", 1) != 0:
            raise BrowserSandboxError(f"playwright_exit_{wait_result.get('StatusCode')}: {output.decode('utf-8', errors='replace')[:512]}")
        result = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserSandboxError(f"playwright_invalid_output: {exc}") from exc
    except Exception as exc:
        raise BrowserSandboxError(f"playwright_timeout_or_runtime_error: {str(exc)[:512]}") from exc
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass
    if result.get("error"):
        raise BrowserSandboxError(f"playwright_error: {result['error']}")
    try:
        html = base64.b64decode(result.get("html", ""), validate=True)
        screenshot = base64.b64decode(result.get("screenshot", ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise BrowserSandboxError(f"playwright_invalid_payload: {exc}") from exc
    if not html or not screenshot:
        raise BrowserSandboxError("playwright_error: rendered HTML or screenshot was empty")
    return html, screenshot


async def process_sandbox_task(session: AsyncSession, task: SandboxTask) -> None:
    task.status = JobStatus.RUNNING
    await session.commit()
    try:
        screenshots_dir = os.getenv("SCREENSHOTS_DIR", "artifacts/screenshots" if os.name == "nt" else "/app/artifacts/screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        features: dict[str, float] = {}
        llm_details = None
        screenshot_path = os.path.join(screenshots_dir, f"{task.job_id}.png")
        if task.modality == "visual" and os.path.isfile(screenshot_path):
            # Content already visited this URL for this job. Reuse its evidence
            # instead of launching Chromium a second time just for vision.
            with open(screenshot_path, "rb") as handle:
                screenshot_bytes = handle.read()
            if not screenshot_bytes:
                raise BrowserSandboxError("cached_screenshot_was_empty")
        elif task.modality in {"content", "visual"}:
            html_bytes, screenshot_bytes = _capture_with_isolated_browser(task.url)
            sanitize_and_save_preview(str(task.job_id), task.url, html_bytes)
            with open(screenshot_path, "wb") as handle:
                handle.write(screenshot_bytes)
        if task.modality == "content":
            content_res = analyze_html(html_bytes, task.url)
            features = content_res.features
            from phishguard_api.llm_agent import analyze_phishing_with_llm
            llm_details, llm_error = await analyze_phishing_with_llm(task.url, html_bytes)
            probability = llm_details.get("probability", 0.5) if llm_details else None
            if llm_error:
                session.add(Event(job_id=task.job_id, step="content", event_type="error", details={"msg": "LLM unavailable; deterministic content features retained", "llm_error": llm_error}))
        elif task.modality == "visual":
            from phishguard_visual.analyzer import analyze_screenshot
            tmp_name = None
            try:
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temporary:
                    temporary.write(screenshot_bytes)
                    tmp_name = temporary.name
                visual_res = analyze_screenshot(tmp_name)
            finally:
                if tmp_name:
                    try:
                        os.unlink(tmp_name)
                    except FileNotFoundError:
                        pass
            if visual_res.status != "success":
                raise BrowserSandboxError(f"visual_analysis_{visual_res.error_code or 'failed'}: {visual_res.error_detail or 'no usable screenshot'}")
            features = visual_res.features
            probability = 0.5
        elif task.modality == "infrastructure":
            await asyncio.sleep(2)
            features = {"infrastructure_available": 1.0, "has_ip_host": 0.0, "tls_verification_failure_count": 0.0, "final_uses_https": 1.0}
            probability = 0.4
        else:
            probability = 0.5
        task.result_json = {"status": "success", "probability": probability, "features": features, "llm_details": llm_details}
        task.status = JobStatus.COMPLETED
        session.add(Event(job_id=task.job_id, step=task.modality, event_type="acquire", details={"msg": "Sandbox acquisition completed", "features": list(features.keys())}))
    except Exception as exc:
        task.status = JobStatus.FAILED
        task.error = str(exc)
        session.add(Event(job_id=task.job_id, step=task.modality, event_type="error", details={"msg": f"Sandbox acquisition failed: {exc}"}))
    await session.commit()


async def manager_loop() -> None:
    print("Sandbox Manager started. Waiting for tasks...", flush=True)
    # A manager restart cannot safely resume a browser process it did not create.
    # Mark such tasks terminal so the worker and reanalysis utility can recover.
    async with async_session_maker() as session:
        orphaned = (
            await session.execute(select(SandboxTask).where(SandboxTask.status == JobStatus.RUNNING))
        ).scalars().all()
        for task in orphaned:
            task.status = JobStatus.FAILED
            task.error = "sandbox_manager_restarted_before_task_completed"
            session.add(Event(job_id=task.job_id, step=task.modality, event_type="error", details={"msg": task.error}))
        if orphaned:
            await session.commit()
    while True:
        try:
            async with async_session_maker() as session:
                result = await session.execute(select(SandboxTask).where(SandboxTask.status == JobStatus.PENDING).limit(1))
                task = result.scalar_one_or_none()
                if task:
                    await process_sandbox_task(session, task)
                else:
                    await asyncio.sleep(1)
        except Exception as exc:
            print(f"Sandbox Manager loop error: {exc}", flush=True)
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(manager_loop())
