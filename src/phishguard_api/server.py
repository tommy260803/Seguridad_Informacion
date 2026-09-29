from __future__ import annotations

import argparse
from typing import Any, Optional
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

worker_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker_task
    # Inicialización de la base de datos (crear tablas)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add brand_name column if missing (migration)
        await conn.execute(
            __import__('sqlalchemy').text(
                "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS brand_name VARCHAR"
            )
        )
    
    # The dedicated sandbox_manager service owns browser tasks.  Starting a
    # second manager here races it without the Docker socket or isolation.
    worker_task = asyncio.create_task(worker_loop())
    yield
    
    # Limpieza al apagar
    if worker_task:
        worker_task.cancel()

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

    # Captures are produced exclusively by sandbox_manager.  The API must not
    # launch a browser against an untrusted URL on demand.
    if not screenshot_file.exists():
        raise HTTPException(status_code=404, detail="Captura aislada no disponible")
    
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

class CheckRequest(BaseModel):
    url: str
    user_country: Optional[str] = None

@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/check")
async def check_url(req: CheckRequest, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Synchronous URL check using Hybrid M0+Brand+Rules model (for Chrome extension)."""
    from phishguard_ml.hybrid_model import predict_hybrid
    
    url = req.url.strip()
    if not url or len(url) > 8192:
        raise HTTPException(status_code=400, detail="URL invalida")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="Only HTTP/HTTPS schemes are allowed")
    
    user_country = (req.user_country or "").upper()
    
    try:
        result = predict_hybrid(url, user_country=user_country)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {exc}")
    
    brand_mismatch = result.get("brand_mismatch")
    
    if brand_mismatch and result["decision"] == "legitimate":
        result["decision"] = "warning"
        result["brand_mismatch"]["relevance"] = "medium"
    
    # Save to database for tracking
    try:
        from phishguard_api.models import Job, JobStatus, Analysis
        
        job = Job(url=url, status=JobStatus.COMPLETED)
        db.add(job)
        await db.flush()
        
        analysis = Analysis(
            id=job.id,
            decision=result["decision"],
            probability=result["probability"],
            confidence=1.0 - abs(result["probability"] - 0.5) * 2,
            uncertainty=0.0,
            brand_name=result.get("brand_analysis", {}).get("closest_brand") if result.get("brand_analysis") else None,
            modalities_consulted=["url", "brand", "rules"],
            evidence_summary=[{
                "source": "M0+Brand+Rules",
                "details": result.get("brand_analysis")
            }]
        )
        db.add(analysis)
        await db.commit()
    except Exception as e:
        print(f"Warning: Failed to save check to database: {e}")
        await db.rollback()
    
    return {
        "url": url,
        "probability": result["probability"],
        "decision": result["decision"],
        "model": result["model"],
        "brand_analysis": result["brand_analysis"],
        "brand_mismatch": result.get("brand_mismatch"),
        "rules_analysis": result.get("rules_analysis"),
    }

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

@app.get("/api/history")
async def get_history(
    limit: int = 50,
    offset: int = 0,
    decision: str = None,
    db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """Get analysis history with pagination and filtering."""
    # Join Analysis with Job to get URL
    query = (
        select(Analysis, Job.url, Job.created_at.label("job_created_at"))
        .join(Job, Analysis.id == Job.id)
        .order_by(Analysis.created_at.desc())
    )
    
    if decision:
        query = query.where(Analysis.decision == decision)
    
    query = query.offset(offset).limit(limit)
    
    result = await db.execute(query)
    rows = result.all()
    
    return {
        "count": len(rows),
        "analyses": [
            {
                "id": str(row.Analysis.id),
                "url": row.url,
                "decision": row.Analysis.decision,
                "probability": row.Analysis.probability,
                "created_at": row.Analysis.created_at.isoformat() if row.Analysis.created_at else None,
                "evidence": row.Analysis.evidence_summary
            }
            for row in rows
        ]
    }

@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Get analysis statistics."""
    from sqlalchemy import func
    
    # Total analyses
    total_result = await db.execute(select(func.count(Analysis.id)))
    total = total_result.scalar() or 0
    
    # Phishing count
    phishing_result = await db.execute(
        select(func.count(Analysis.id)).where(Analysis.decision == "phishing")
    )
    phishing_count = phishing_result.scalar() or 0
    
    # Legitimate count
    legitimate_result = await db.execute(
        select(func.count(Analysis.id)).where(Analysis.decision == "legitimate")
    )
    legitimate_count = legitimate_result.scalar() or 0
    
    # Warning count
    warning_result = await db.execute(
        select(func.count(Analysis.id)).where(Analysis.decision == "warning")
    )
    warning_count = warning_result.scalar() or 0
    
    # Average probability
    avg_result = await db.execute(select(func.avg(Analysis.probability)))
    avg_probability = avg_result.scalar() or 0
    
    return {
        "total_analyses": total,
        "phishing_count": phishing_count,
        "legitimate_count": legitimate_count,
        "warning_count": warning_count,
        "uncertain_count": total - phishing_count - legitimate_count - warning_count,
        "phishing_rate": round(phishing_count / total * 100, 2) if total > 0 else 0,
        "average_probability": round(float(avg_probability), 4)
    }

@app.get("/api/threat-landscape")
async def get_threat_landscape(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Get threat landscape data for visualization."""
    # Query brand_name directly from stored analyses (no re-running ML)
    result = await db.execute(
        select(Analysis.brand_name, Analysis.decision)
        .join(Job, Analysis.id == Job.id)
        .where(Analysis.brand_name.isnot(None))
        .where(Analysis.brand_name != "")
        .order_by(Analysis.created_at.desc())
        .limit(200)
    )
    rows = result.all()
    
    brand_counts = {}
    for row in rows:
        brand = row.brand_name
        if brand:
            brand_counts[brand] = brand_counts.get(brand, 0) + 1
    
    sorted_brands = sorted(brand_counts.items(), key=lambda x: x[1], reverse=True)
    
    return {
        "top_targeted_brands": [
            {"brand": brand, "count": count}
            for brand, count in sorted_brands[:10]
        ],
        "total_analyzed": len(rows)
    }

@app.get("/metrics")
async def get_metrics():
    """Endpoint de observabilidad en formato Prometheus / OpenMetrics."""
    from phishguard_api.metrics import metrics
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=metrics.export_prometheus_text(),
        media_type="text/plain; version=0.0.4"
    )

@app.get("/jobs/{job_id}/user-card")
async def get_user_card(job_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Genera una tarjeta de diagnóstico amigable en tiempo real para la extensión del navegador."""
    try:
        result = await db.execute(
            select(Job).where(Job.id == job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            raise HTTPException(status_code=404, detail="Job no encontrado")

        res_analysis = await db.execute(
            select(Analysis).where(Analysis.id == job_id)
        )
        analysis = res_analysis.scalar_one_or_none()
    except HTTPException:
        raise
    except Exception as db_err:
        raise HTTPException(status_code=503, detail=f"Base de datos temporalmente no disponible: {str(db_err)[:100]}")

    if not analysis:
        return {
            "status": job.status.value,
            "ready": False,
            "message": "Análisis en progreso..."
        }

    prob = analysis.probability or 0.0
    if prob >= 0.70 or analysis.decision == "phishing":
        badge = "DANGEROUS"
        color = "#ef4444"
        rec = "No ingreses contraseñas ni datos personales. Cierra esta pestaña inmediatamente."
    elif prob >= 0.35 or analysis.decision == "uncertain":
        badge = "SUSPICIOUS"
        color = "#eab308"
        rec = "Procede con precaución. Verifica que el dominio coincida exactamente con la entidad oficial."
    else:
        badge = "SAFE"
        color = "#22c55e"
        rec = "El sitio web no presenta indicios de suplantación ni patrones maliciosos conocidos."

    # Viñetas diagnósticas para el usuario final
    bullets = []
    if analysis.brand_name:
        bullets.append(f"Posible intento de suplantación de la marca {analysis.brand_name}.")
    
    if "url" in analysis.modalities_consulted:
        if prob >= 0.70:
            bullets.append("Estructura de URL con patrones típicos de ataque (subdominios engañosos o palabras clave de verificación).")
        else:
            bullets.append("Nombre de dominio y estructura léxica conformes a estándares habituales.")
            
    if "infrastructure" in analysis.modalities_consulted:
        bullets.append("Registros DNS e infraestructura de red inspeccionados por el motor de seguridad.")
        
    if "content" in analysis.modalities_consulted:
        bullets.append("Código fuente HTML y formularios de inicio de sesión validados semánticamente.")

    if not bullets:
        bullets.append("Análisis probabilístico completado satisfactoriamente.")

    return {
        "ready": True,
        "job_id": str(job.id),
        "url": job.url,
        "decision": analysis.decision,
        "risk_badge": badge,
        "badge_color": color,
        "risk_percentage": int(round(prob * 100)),
        "confidence_percentage": int(round((analysis.confidence or 0.85) * 100)),
        "brand_name": analysis.brand_name,
        "bullet_reasons": bullets[:3],
        "recommendation": rec
    }

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
