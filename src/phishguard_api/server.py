from __future__ import annotations

import argparse
from typing import Any
import uuid

from contextlib import asynccontextmanager
import asyncio
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.staticfiles import StaticFiles
import os
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from phishguard_api.database import engine, get_db
from phishguard_api.models import Base, Job, Analysis, Event
from phishguard_api.worker import worker_loop
from phishguard_api.sandbox_manager import manager_loop

worker_task = None
sandbox_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker_task, sandbox_task
    # Inicialización de la base de datos (crear tablas)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Iniciar el worker y el sandbox manager en segundo plano
    worker_task = asyncio.create_task(worker_loop())
    sandbox_task = asyncio.create_task(manager_loop())
    yield
    
    # Limpieza al apagar
    if worker_task:
        worker_task.cancel()
    if sandbox_task:
        sandbox_task.cancel()

app = FastAPI(
    title="PhishGuard API", 
    description="Plataforma científica local para análisis de Phishing",
    lifespan=lifespan
)

# Seguridad: Restringir orígenes según el plan
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # TODO: Restringir al ID de la extensión Chrome en producción
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

SCREENSHOTS_DIR = os.getenv("SCREENSHOTS_DIR", "artifacts/screenshots" if os.name == "nt" else "/app/artifacts/screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

@app.get("/screenshots/{filename}")
async def get_screenshot(filename: str, db: AsyncSession = Depends(get_db)):
    clean_id = filename.replace(".png", "")
    screenshot_file = Path(SCREENSHOTS_DIR) / f"{clean_id}.png"
    
    if not screenshot_file.exists():
        res = await db.execute(select(Job).where(Job.id == clean_id))
        job = res.scalar_one_or_none()
        if job and job.url:
            from phishguard_api.browser_sandbox import capture_site_screenshot
            ok, path, _ = await capture_site_screenshot(job.url, clean_id)
            if not ok or not screenshot_file.exists():
                raise HTTPException(
                    status_code=502,
                    detail={"error": "domain_offline", "message": "No se pudo generar la captura porque el sitio no responde o está fuera de línea."}
                )

    if not screenshot_file.exists():
        raise HTTPException(status_code=404, detail="Captura no encontrada")
        
    return FileResponse(screenshot_file, media_type="image/png")

app.mount("/screenshots-static", StaticFiles(directory=SCREENSHOTS_DIR), name="screenshots_static")

PREVIEWS_DIR = os.getenv("PREVIEWS_DIR", "artifacts/previews" if os.name == "nt" else "/app/artifacts/previews")
os.makedirs(PREVIEWS_DIR, exist_ok=True)

@app.get("/previews/{job_id}")
async def get_preview(job_id: str, db: AsyncSession = Depends(get_db)):
    preview_file = Path(PREVIEWS_DIR) / f"{job_id}.html"
    
    if not preview_file.exists():
        # Intentar buscar el trabajo para intentar generar la vista previa bajo demanda
        res = await db.execute(select(Job).where(Job.id == job_id))
        job = res.scalar_one_or_none()
        if job and job.url:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                resp = requests.get(job.url, headers=headers, verify=False, timeout=4)
                from phishguard_api.sandbox_manager import sanitize_and_save_preview
                sanitize_and_save_preview(str(job.id), resp.url or job.url, resp.content)
            except Exception as e:
                raise HTTPException(
                    status_code=502, 
                    detail={"error": "domain_offline", "message": f"El dominio no responde o está fuera de línea: {str(e)}"}
                )

    if not preview_file.exists():
        raise HTTPException(status_code=404, detail={"error": "preview_not_found", "message": "Vista previa no disponible"})
        
    content = preview_file.read_text(encoding="utf-8")
    resp = HTMLResponse(content=content)
    resp.headers["Content-Security-Policy"] = "default-src * 'unsafe-inline' data: blob:; script-src 'none'; object-src 'none';"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "ALLOWALL"
    return resp



class AnalyzeRequest(BaseModel):
    url: str

@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}

# Endpoint legacy temporal (Será eliminado cuando la extensión se adapte al asíncrono)
@app.post("/analyze")
async def analyze_legacy(req: AnalyzeRequest) -> dict[str, Any]:
    return {
        "status": "success",
        "decision": "uncertain",
        "probability_phishing": 0.5,
        "evidence_summary": [{"source": "system", "feature": "migration", "value": "Legacy endpoint active"}],
        "mode": "legacy-compatibility"
    }

# NUEVOS ENDPOINTS CIENTÍFICOS
@app.post("/analyses", status_code=202)
async def submit_analysis(req: AnalyzeRequest, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Crea un trabajo de análisis en la cola persistente (PostgreSQL)"""
    url = req.url.strip()
    if not url or len(url) > 8192:
        raise HTTPException(status_code=400, detail="URL inválida")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="Only HTTP/HTTPS schemes are allowed")
        
    job = Job(url=url)
    db.add(job)
    await db.commit()
    return {"id": str(job.id), "status": job.status.value}

@app.get("/analyses/{job_id}")
async def get_analysis(job_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Consulta el estado y resultado de un análisis"""
    result = await db.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Trabajo no encontrado")
        
    response = {"id": str(job.id), "status": job.status.value, "url": job.url}
    
    # Obtener eventos (Trazabilidad)
    events_result = await db.execute(select(Event).where(Event.job_id == job_id).order_by(Event.created_at))
    events = events_result.scalars().all()
    response["events"] = [
        {"step": e.step, "type": e.event_type, "details": e.details, "time": e.created_at.isoformat()} 
        for e in events
    ]
    
    if job.status == "completed":
        analysis_result = await db.execute(select(Analysis).where(Analysis.id == job_id))
        analysis = analysis_result.scalar_one_or_none()
        if analysis:
            response.update({
                "decision": analysis.decision,
                "probability": analysis.probability,
                "evidence": analysis.evidence_summary
            })
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    html_path = Path(__file__).parent / "dashboard.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI not found")
    return html_path.read_text(encoding="utf-8")

def main() -> None:
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser(prog="phishapi")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    
    print(f"Iniciando PhishGuard FastAPI en http://{args.host}:{args.port}", flush=True)
    uvicorn.run("phishguard_api.server:app", host=args.host, port=args.port, reload=True)

if __name__ == "__main__":
    main()
