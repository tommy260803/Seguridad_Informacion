import argparse
import asyncio
import json
import base64
import os
from playwright.async_api import async_playwright

async def run_playwright(url: str):
    result = {"html": "", "screenshot": "", "error": None}
    try:
        async with async_playwright() as p:
            proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
            launch_args = ["--disable-dev-shm-usage", "--no-sandbox", "--disable-gpu"]
            if proxy_url:
                launch_args.append(f"--proxy-server={proxy_url}")
            browser = await p.chromium.launch(args=launch_args, timeout=10_000)
            context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 720})
            page = await context.new_page()
            navigation_timeout_ms = int(os.environ.get("BROWSER_NAVIGATION_TIMEOUT_MS", "8000"))
            render_wait_ms = int(os.environ.get("BROWSER_RENDER_WAIT_MS", "750"))
            await page.goto(url, timeout=navigation_timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(render_wait_ms)
            content = await page.content()
            result["html"] = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            screenshot_bytes = await page.screenshot(full_page=False)
            result["screenshot"] = base64.b64encode(screenshot_bytes).decode("utf-8")
            await browser.close()
    except Exception as exc:
        result["error"] = str(exc)
    print(json.dumps(result))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    
    try:
        worker_timeout_seconds = int(os.environ.get("BROWSER_WORKER_TIMEOUT_SECONDS", "15"))
        asyncio.run(asyncio.wait_for(run_playwright(args.url), timeout=worker_timeout_seconds))
    except asyncio.TimeoutError:
        print(json.dumps({"html": "", "screenshot": "", "error": "playwright_worker_timeout"}))
