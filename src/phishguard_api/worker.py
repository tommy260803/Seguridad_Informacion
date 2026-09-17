import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from phishguard_api.models import Job, JobStatus, Analysis, Event, SandboxTask
from phishguard_api.database import async_session_maker

from dataclasses import replace
from phishguard_orchestrator.engine import AdaptivePolicy, decide_next
from phishguard_api.inference import predict_m0, predict_m1, predict_m2, predict_m3, _extract_url_base_features

async def process_job(session: AsyncSession, job: Job):
    job.status = JobStatus.RUNNING
    await session.commit()
    
    try:
        print(f"Worker {job.id}: Inicializando policy", flush=True)
        policy = AdaptivePolicy()
        
        # Estado acumulado de características (M4 requiere concatenación)
        accumulated_features = {
            "url": _extract_url_base_features(job.url),
            "infrastructure": {},
            "content": {},
            "visual": {}
        }
        
        print(f"Worker {job.id}: Prediciendo M0", flush=True)
        # --- ETAPA 1: URL (M0) ---
        probability = predict_m0(job.url)
        
        session.add(Event(
            job_id=job.id, step="url", event_type="acquire",
            details={"msg": "Inferencia M0 completada", "probability": probability}
        ))
        
        consulted = ["url"]
        spent = 0.0
        step = 1
        decision = "uncertain"
        confidence = 0.0
        uncertainty = 1.0
        
        print(f"Worker {job.id}: Entrando al orquestador adaptativo", flush=True)
        # Bucle del orquestador adaptativo
        while True:
            print(f"Worker {job.id}: decidiendo paso {step}", flush=True)
            # 1. El orquestador matemático decide qué hacer (M5)
            action, reason, confidence, uncertainty = decide_next(
                probability, tuple(consulted), 
                replace(policy, budget=policy.budget - spent), 
                step=step
            )
            print(f"Worker {job.id}: Action={action} Reason={reason}", flush=True)
            
            session.add(Event(
                job_id=job.id, step="orchestrator", event_type="decision",
                details={"action": action, "reason": reason, "confidence": confidence, "uncertainty": uncertainty}
            ))
            
            # 2. Ejecutar la acción
            if action == "decide":
                # Si M5 dice "decide", es porque superó la confianza. Usamos 0.5 como pivote direccional.
                decision = "phishing" if probability >= 0.5 else "legitimate"
                break
            elif action == "abstain":
                # Al agotar el presupuesto, tomar decisión sobre la probabilidad acumulada
                if probability >= 0.65:
                    decision = "phishing"
                elif probability <= 0.35:
                    decision = "legitimate"
                else:
                    decision = "uncertain"
                break
            else:
                # Modality solicitada (infrastructure, content, visual)
                session.add(Event(
                    job_id=job.id, step=action, event_type="acquire",
                    details={"msg": f"Solicitando sandbox para {action}"}
                ))
                
                # Crear tarea para el sandbox manager
                print(f"Worker: Insertando SandboxTask para {action} (job {job.id})", flush=True)
                sandbox_task = SandboxTask(
                    job_id=job.id,
                    modality=action,
                    url=job.url
                )
                session.add(sandbox_task)
                await session.commit()
                
                print(f"Worker: Polling SandboxTask para {action}...", flush=True)
                # Polling esperando al sandbox manager
                while True:
                    await asyncio.sleep(1)
                    await session.refresh(sandbox_task)
                    if sandbox_task.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                        break
                        
                if sandbox_task.status == JobStatus.FAILED:
                    session.add(Event(
                        job_id=job.id, step=action, event_type="error",
                        details={"msg": sandbox_task.error or "Error en sandbox"}
                    ))
                    decision = "uncertain"
                    break
                    
                # Acumular features (M4)
                new_features = sandbox_task.result_json.get("features", {})
                llm_det = sandbox_task.result_json.get("llm_details")
                if llm_det:
                    new_features["llm_details"] = llm_det
                accumulated_features[action] = new_features
                
                # Adaptación M4 (concatenar estado y predecir)
                if action == "infrastructure":
                    probability = predict_m1(accumulated_features["url"], accumulated_features["infrastructure"], probability)
                elif action == "content":
                    # Usar la probabilidad calculada por la IA Generativa (LLM) en el Sandbox
                    llm_prob = sandbox_task.result_json.get("probability")
                    if llm_prob is not None:
                        probability = llm_prob
                        print(f"Probabilidad asignada por IA Generativa: {probability}", flush=True)
                    else:
                        print("Advertencia: IA falló (posible límite de cuota). Usando heurística Fail-Safe.", flush=True)
                        # Fail-Safe: Si la IA se cae, y la URL original era sospechosa (M0 > 0.5), bloqueamos por seguridad.
                        if probability > 0.5:
                            probability = 0.99
                        else:
                            probability = predict_m2(accumulated_features["url"], accumulated_features["infrastructure"], accumulated_features["content"], probability)
                elif action == "visual":
                    probability = predict_m3(accumulated_features["url"], accumulated_features["infrastructure"], accumulated_features["content"], accumulated_features["visual"], probability)
                
                consulted.append(action)
                step += 1
                
        print(f"Worker {job.id}: Terminado bucle adaptativo con decision {decision}", flush=True)
        # --- GUARDAR RESULTADOS ---
        evidence = [{"source": "M0", "feature": "probability", "value": probability}]
        if "content" in accumulated_features and "llm_details" in accumulated_features["content"]:
            evidence.append({"source": "LLM", "details": accumulated_features["content"]["llm_details"]})

        analysis = Analysis(
            id=job.id,
            decision=decision,
            probability=probability,
            confidence=confidence,
            uncertainty=uncertainty,
            modalities_consulted=consulted,
            evidence_summary=evidence
        )
        session.add(analysis)
        
        print(f"Worker {job.id}: Guardando analysis y job COMPLETED", flush=True)
        job.status = JobStatus.COMPLETED
        await session.commit()
        print(f"Worker {job.id}: Job {job.id} COMPLETADO con éxito", flush=True)
    except Exception as e:
        print(f"Error procesando job {job.id}: {e}")
        session.add(Event(
            job_id=job.id, step="system", event_type="error",
            details={"msg": str(e)}
        ))
        job.status = JobStatus.FAILED
        await session.commit()

async def worker_loop():
    """Bucle infinito del worker dedicado (Concurrencia 1)"""
    print("Worker asíncrono iniciado y esperando trabajos...", flush=True)
    while True:
        try:
            async with async_session_maker() as session:
                # Buscar un trabajo pendiente
                result = await session.execute(
                    select(Job).where(Job.status == JobStatus.PENDING).order_by(Job.created_at).limit(1)
                )
                job = result.scalar_one_or_none()
                
                if job:
                    print(f"Worker procesando job: {job.id}", flush=True)
                    await process_job(session, job)
                else:
                    await asyncio.sleep(1) # Esperar antes de volver a consultar
        except asyncio.CancelledError:
            print("Worker detenido.")
            break
        except Exception as e:
            print(f"Error crítico en el worker: {e}")
            await asyncio.sleep(5)
