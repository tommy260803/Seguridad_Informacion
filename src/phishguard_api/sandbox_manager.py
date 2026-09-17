import asyncio
import os
import uuid
import docker
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from phishguard_api.models import SandboxTask, JobStatus, Event
from phishguard_api.database import async_session_maker
from phishguard_content.analyzer import analyze_html

# Conectar al demonio de Docker (requiere que el socket esté montado o disponible)
try:
    docker_client = docker.from_env()
except Exception as e:
    print(f"ADVERTENCIA: No se pudo conectar a Docker: {e}")
    docker_client = None

def sanitize_and_save_preview(job_id: str, url: str, raw_html: str | bytes):
    try:
        if isinstance(raw_html, bytes):
            raw_text = raw_html.decode("utf-8", errors="ignore")
        else:
            raw_text = str(raw_html)
        
        PREVIEWS_DIR = os.getenv("PREVIEWS_DIR", "artifacts/previews" if os.name == "nt" else "/app/artifacts/previews")
        os.makedirs(PREVIEWS_DIR, exist_ok=True)
        
        import re
        base_tag = f'<base href="{url}" target="_blank">'
        if "<head>" in raw_text:
            sanitized = raw_text.replace("<head>", f"<head>{base_tag}", 1)
        elif "<HEAD>" in raw_text:
            sanitized = raw_text.replace("<HEAD>", f"<HEAD>{base_tag}", 1)
        else:
            sanitized = f"{base_tag}{raw_text}"
            
        # Eliminar scripts y noscript potencialmente peligrosos
        sanitized = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', sanitized, flags=re.IGNORECASE)
        # Eliminar eventos on...
        sanitized = re.sub(r'\s+on\w+="[^"]*"', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"\s+on\w+='[^']*'", '', sanitized, flags=re.IGNORECASE)
        # Neutralizar forms e inputs
        sanitized = re.sub(r'<form\b', '<form onsubmit="return false;" action="javascript:void(0)"', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'<input\b', '<input readonly', sanitized, flags=re.IGNORECASE)
        
        preview_path = os.path.join(PREVIEWS_DIR, f"{job_id}.html")
        with open(preview_path, "w", encoding="utf-8") as f:
            f.write(sanitized)
        print(f"Sandbox Manager: Vista previa aislada guardada en {preview_path}")
    except Exception as exc:
        print(f"Aviso: No se pudo generar preview aislado ({exc})")

async def process_sandbox_task(session: AsyncSession, task: SandboxTask):
    task.status = JobStatus.RUNNING
    await session.commit()
    
    print(f"Sandbox Manager: Ejecutando tarea efímera para {task.url} (Modalidad: {task.modality})")
    
    # Aquí es donde instanciamos el contenedor efímero
    # Por ahora, simulamos el resultado exitoso del contenedor efímero de Playwright / Infra
    # En la siguiente iteración engancharemos docker_client.containers.run(...)
    try:
        SCREENSHOTS_DIR = os.getenv("SCREENSHOTS_DIR", "artifacts/screenshots" if os.name == "nt" else "/app/artifacts/screenshots")
        os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
        screenshot_bytes = b""
        html_bytes = b""

        if task.modality in ["content", "visual"]:
            if docker_client:
                print(f"Lanzando contenedor efímero de Playwright para {task.url}")
                output = docker_client.containers.run(
                    "phishguard-playwright",
                    command=["--url", task.url],
                    network_mode="bridge",
                    remove=True,
                    mem_limit="512m",
                    cpu_period=100000,
                    cpu_quota=50000
                )
                import json
                import base64
                pw_result = json.loads(output.decode("utf-8"))
                if pw_result.get("error"):
                    raise Exception(f"Playwright error: {pw_result['error']}")
                html_bytes = base64.b64decode(pw_result["html"])
                screenshot_bytes = base64.b64decode(pw_result["screenshot"])
                sanitize_and_save_preview(str(task.job_id), task.url, html_bytes)
            else:
                print(f"Sandbox Manager: Ejecutando Playwright Headless para renderizado completo y captura segura...")
                from phishguard_api.browser_sandbox import capture_site_screenshot
                pw_ok, pw_path, pw_html = await capture_site_screenshot(task.url, str(task.job_id))
                if pw_ok and pw_html:
                    html_bytes = pw_html
                    sanitize_and_save_preview(str(task.job_id), task.url, html_bytes)
                else:
                    print(f"Sandbox Manager: Playwright no completó, usando fallback HTTP con requests...")
                    import requests
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    try:
                        headers = {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                        }
                        resp = requests.get(task.url, headers=headers, verify=False, timeout=8)
                        html_bytes = resp.content
                        sanitize_and_save_preview(str(task.job_id), resp.url or task.url, html_bytes)
                    except Exception as e:
                        print(f"Aviso: No se pudo descargar contenido web ({e}), analizando solo URL y metadatos.")
                        html_bytes = f"<html><body>URL sospechosa: {task.url}</body></html>".encode("utf-8")

            if screenshot_bytes:
                with open(os.path.join(SCREENSHOTS_DIR, f"{task.job_id}.png"), "wb") as f:
                    f.write(screenshot_bytes)
            
            features = {}
            if task.modality == "content":
                content_res = analyze_html(html_bytes, task.url)
                features = content_res.features
                
                # INTEGRACIÓN LLM (Generative AI)
                from phishguard_api.llm_agent import analyze_phishing_with_llm
                llm_response = await analyze_phishing_with_llm(task.url, html_bytes)
                if isinstance(llm_response, dict):
                    probability = llm_response.get("probability", 0.5)
                    llm_details = llm_response
                else:
                    probability = llm_response
                    llm_details = None
                print(f"Decisión del LLM para {task.url}: {probability}")
                
            elif task.modality == "visual":
                from phishguard_visual.analyzer import analyze_screenshot
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                    tmp.write(screenshot_bytes)
                    tmp_name = tmp.name
                visual_res = analyze_screenshot(tmp_name)
                os.unlink(tmp_name)
                features = visual_res.features
                probability = 0.5 # Mock hasta tener modelo cargado
                
        elif task.modality == "infrastructure":
            # Mock de infraestructura hasta aislar la resolución de red
            await asyncio.sleep(2) 
            features = {"infrastructure_available": 1.0, "has_ip_host": 0.0, "tls_verification_failure_count": 0.0, "final_uses_https": 1.0}
            probability = 0.4
        else:
            features = {}
            probability = 0.5
            
        task.result_json = {
            "status": "success",
            "probability": probability,
            "features": features,
            "llm_details": locals().get("llm_details")
        }
        task.status = JobStatus.COMPLETED
        
        # Guardar evento de trazabilidad
        session.add(Event(
            job_id=task.job_id, step=task.modality, event_type="acquire",
            details={"msg": f"Contenedor efímero de Playwright completó con éxito", "features": list(features.keys())}
        ))
        
    except Exception as e:
        task.status = JobStatus.FAILED
        task.error = str(e)
        session.add(Event(
            job_id=task.job_id, step=task.modality, event_type="error",
            details={"msg": f"Error en contenedor efímero: {e}"}
        ))
        
    await session.commit()

async def manager_loop():
    print("Sandbox Manager Iniciado. Esperando tareas...", flush=True)
    while True:
        try:
            async with async_session_maker() as session:
                # Buscar tareas pendientes
                result = await session.execute(
                    select(SandboxTask).where(SandboxTask.status == JobStatus.PENDING).limit(1)
                )
                task = result.scalar_one_or_none()
                
                if task:
                    await process_sandbox_task(session, task)
                else:
                    await asyncio.sleep(1)
        except Exception as e:
            print(f"Error en Sandbox Manager Loop: {e}")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(manager_loop())
