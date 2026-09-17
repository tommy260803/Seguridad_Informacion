import argparse
import asyncio
import json
import base64
from playwright.async_api import async_playwright

async def run_playwright(url: str):
    result = {"html": "", "screenshot": "", "error": None}
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            args=["--disable-dev-shm-usage", "--no-sandbox"]
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            viewport={'width': 1280, 'height': 720}
        )
        page = await context.new_page()
        
        try:
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            try:
                await page.wait_for_timeout(2000)
            except:
                pass
            
            content = await page.content()
            result["html"] = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            
            screenshot_bytes = await page.screenshot(full_page=False)
            result["screenshot"] = base64.b64encode(screenshot_bytes).decode("utf-8")
            
        except Exception as e:
            result["error"] = str(e)
        finally:
            await browser.close()
            
    print(json.dumps(result))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    
    asyncio.run(run_playwright(args.url))
