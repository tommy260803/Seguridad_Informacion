import asyncio
import os
import uuid
import docker
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from phishguard_api.models import SandboxTask, JobStatus, Event
from phishguard_api.database import async_session_maker

# Conectar al demonio de Docker (requiere que el socket esté montado o disponible)
try:
    docker_client = docker.from_env()
except Exception as e:
    print(f"ADVERTENCIA: No se pudo conectar a Docker: {e}")
    docker_client = None

async def process_sandbox_task(session: AsyncSession, task: SandboxTask):
    task.status = JobStatus.RUNNING
    await session.commit()
    
    print(f"Sandbox Manager: Ejecutando tarea efímera para {task.url} (Modalidad: {task.modality})")
    
    # Aquí es donde instanciamos el contenedor efímero
    # Por ahora, simulamos el resultado exitoso del contenedor efímero de Playwright / Infra
    # En la siguiente iteración engancharemos docker_client.containers.run(...)
    try:
        if task.modality in ["content", "visual"]:
            if not docker_client:
                raise Exception("Docker client no está disponible para lanzar Playwright")
                
            print(f"Lanzando contenedor efímero de Playwright para {task.url}")
            # Ejecutar contenedor efímero, esperando que imprima JSON en stdout
            output = docker_client.containers.run(
                "phishguard-playwright",
                command=["--url", task.url],
                network_mode="bridge", # Idealmente 'sandbox_sandbox_internal' si está configurada
                remove=True,
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000
            )
            
            import json
            import base64
            from phishguard_content.analyzer import analyze_html
            import tempfile
            
            pw_result = json.loads(output.decode("utf-8"))
            if pw_result.get("error"):
                raise Exception(f"Playwright error: {pw_result['error']}")
                
            html_bytes = base64.b64decode(pw_result["html"])
            screenshot_bytes = base64.b64decode(pw_result["screenshot"])
            
            features = {}
            if task.modality == "content":
                content_res = analyze_html(html_bytes, task.url)
                features = content_res.features
                
                # INTEGRACIÓN LLM (Generative AI)
                from phishguard_api.llm_agent import analyze_phishing_with_llm
                probability = await analyze_phishing_with_llm(task.url, html_bytes)
                print(f"Decisión del LLM para {task.url}: {probability}")
                
            elif task.modality == "visual":
                from phishguard_visual.analyzer import analyze_screenshot
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                    tmp.write(screenshot_bytes)
                    tmp_name = tmp.name
                visual_res = analyze_screenshot(tmp_name)
                import os
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
            "features": features
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
