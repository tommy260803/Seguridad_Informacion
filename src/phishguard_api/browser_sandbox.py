from __future__ import annotations

import asyncio
from pathlib import Path
import os
import time
from typing import Tuple, Optional

SCREENSHOTS_DIR = os.getenv("SCREENSHOTS_DIR", "artifacts/screenshots" if os.name == "nt" else "/app/artifacts/screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)


def _sync_capture(url: str, job_id: str, timeout_ms: int = 10000) -> Tuple[bool, Optional[str], Optional[bytes]]:
    out_path = Path(SCREENSHOTS_DIR) / f"{job_id}.png"
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright no está disponible en el entorno.")
        return False, None, None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--window-size=1280,800",
                ]
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
            )
            page = context.new_page()

            # Navegación con tolerancia a tiempos de carga
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception:
                try:
                    page.goto(url, wait_until="load", timeout=5000)
                except Exception as nav_err:
                    print(f"Aviso Playwright: Navegación parcial para {url}: {nav_err}")

            # Breve pausa para asegurar el render de SPAs (React, Vue, Angular)
            time.sleep(1.0)

            page.screenshot(path=str(out_path), full_page=False)
            rendered_html = page.content()
            browser.close()

            print(f"Browser Sandbox: Captura de pantalla generada exitosamente en {out_path}")
            return True, str(out_path), rendered_html.encode("utf-8")

    except Exception as exc:
        print(f"Browser Sandbox Error al capturar {url}: {exc}")
        return False, None, None


async def capture_site_screenshot(url: str, job_id: str, timeout_ms: int = 10000) -> Tuple[bool, Optional[str], Optional[bytes]]:
    """
    Ejecuta un navegador Chromium headless aislado en el servidor para renderizar
    el sitio sospechoso con JavaScript activo, tomar una captura de pantalla estática (PNG)
    y extraer el contenido HTML completamente hidratado.
    
    Compatible al 100% con Windows (evita el NotImplementedError de asyncio subprocess en Windows).
    """
    return await asyncio.to_thread(_sync_capture, url, job_id, timeout_ms)

