import asyncio
import os
import time
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from phishguard_api.models import Job, JobStatus, Analysis, Event, SandboxTask
from phishguard_api.database import async_session_maker
from phishguard_api.cache import decision_cache
from phishguard_api.bloom_filter import domain_filter
from phishguard_api.metrics import metrics

from dataclasses import replace
from phishguard_orchestrator.engine import AdaptivePolicy, decide_next
from phishguard_api.inference import predict_m0, predict_m1, predict_m2, predict_m3, _extract_url_base_features

async def recover_zombie_jobs():
    """Identifica y cierra limpiamente trabajos que quedaron en RUNNING por reinicio abrupto del sistema."""
    try:
        async with async_session_maker() as session:
            # 1. Recuperar Jobs zombi
            result = await session.execute(
                select(Job).where(Job.status == JobStatus.RUNNING)
            )
            zombie_jobs = result.scalars().all()
            if zombie_jobs:
                print(f"Limpieza de arranque: Recuperando {len(zombie_jobs)} trabajos zombi...", flush=True)
                for zjob in zombie_jobs:
                    zjob.status = JobStatus.FAILED
                    session.add(Event(
                        job_id=zjob.id, step="system", event_type="error",
                        details={"msg": "Worker process restarted while job was running. Fail-safe recovery."}
                    ))
            
            # 2. Recuperar SandboxTasks zombi
            s_result = await session.execute(
                select(SandboxTask).where(SandboxTask.status == JobStatus.RUNNING)
            )
            zombie_tasks = s_result.scalars().all()
            for ztask in zombie_tasks:
                ztask.status = JobStatus.FAILED
                ztask.error = "Worker process restarted while sandbox task was running."

            await session.commit()
            if zombie_jobs or zombie_tasks:
                print("Limpieza de arranque completada con éxito.", flush=True)
    except Exception as e:
        print(f"Error en recover_zombie_jobs: {e}", flush=True)

async def process_job(session: AsyncSession, job: Job):
    job.status = JobStatus.RUNNING
    await session.commit()
    
    try:
        # --- VERIFICACIÓN DE CACHÉ DE DECISIONES ---
        cached = decision_cache.get(job.url)
        if cached:
            print(f"Worker {job.id}: Decisión obtenida desde CACHÉ en memoria para {job.url}", flush=True)
            evidence = list(cached.get("evidence_summary", [])) + [{"source": "cache", "hit": True}]
            analysis = Analysis(
                id=job.id,
                decision=cached["decision"],
                probability=cached["probability"],
                confidence=cached["confidence"],
                uncertainty=cached["uncertainty"],
                modalities_consulted=cached["modalities_consulted"],
                evidence_summary=evidence
            )
            session.add(analysis)
            session.add(Event(
                job_id=job.id, step="cache", event_type="decision",
                details={"msg": "Resuelto instantáneamente desde caché LRU", "decision": cached["decision"]}
            ))
            job.status = JobStatus.COMPLETED
            await session.commit()
            metrics.record_job_completed("cache", 0.1)
            print(f"Worker {job.id}: Job completado vía caché en < 1ms", flush=True)
            return

        # --- VERIFICACIÓN FAST-PATH CON BLOOM FILTER ---
        if domain_filter.is_trusted(job.url):
            print(f"Worker {job.id}: Dominio de alta confianza validado en BLOOM FILTER O(1) para {job.url}", flush=True)
            analysis = Analysis(
                id=job.id,
                decision="legitimate",
                probability=0.001,
                confidence=0.999,
                uncertainty=0.001,
                modalities_consulted=["bloom_filter"],
                evidence_summary=[{"source": "bloom_filter", "status": "trusted_domain", "probability": 0.001}]
            )
            session.add(analysis)
            session.add(Event(
                job_id=job.id, step="bloom_filter", event_type="decision",
                details={"msg": "Validado en O(1) vía Bloom Filter", "decision": "legitimate"}
            ))
            job.status = JobStatus.COMPLETED
            await session.commit()
            metrics.record_job_completed("bloom", 0.05)
            print(f"Worker {job.id}: Job completado vía Bloom Filter en < 0.1ms", flush=True)
            return

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

        retry_events = (
            await session.execute(
                select(Event).where(
                    Event.job_id == job.id,
                    Event.step == "system",
                    Event.event_type == "reanalysis",
                )
            )
        ).scalars().all()
        force_visual = any(event.details.get("force_visual") is True for event in retry_events)
        
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
            if force_visual and "visual" not in consulted:
                action, reason = "visual", "reanalysis_force_visual"
            elif action == "decide" and probability >= 0.5 and "visual" not in consulted:
                action, reason = "visual", "capture_for_blocked_site"
            print(f"Worker {job.id}: Action={action} Reason={reason}", flush=True)
            
            session.add(Event(
                job_id=job.id, step="orchestrator", event_type="decision",
                details={"action": action, "reason": reason, "confidence": confidence, "uncertainty": uncertainty}
            ))
            
            # 2. Ejecutar la acción
            if action == "decide":
                decision = "phishing" if probability >= 0.5 else "legitimate"
                break
            elif action == "abstain":
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
                # Polling adaptativo inteligente (empieza rápido 0.2s, luego 0.5s, luego 1.0s)
                polling_elapsed = 0.0
                timeout_limit = float(os.environ.get("SANDBOX_TASK_TIMEOUT_SECONDS", "70"))
                while True:
                    if polling_elapsed < 2.0:
                        poll_interval = 0.2
                    elif polling_elapsed < 10.0:
                        poll_interval = 0.5
                    else:
                        poll_interval = 1.0

                    await asyncio.sleep(poll_interval)
                    polling_elapsed += poll_interval

                    try:
                        await session.refresh(sandbox_task)
                    except Exception as refresh_err:
                        print(f"Advertencia en refresh de SandboxTask: {refresh_err}", flush=True)
                        await asyncio.sleep(0.5)
                        continue

                    if sandbox_task.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                        break
                    if polling_elapsed >= timeout_limit:
                        sandbox_task.status = JobStatus.FAILED
                        sandbox_task.error = "Timeout esperando al sandbox_manager"
                        await session.commit()
                        break
                        
                if sandbox_task.status == JobStatus.FAILED:
                    session.add(Event(
                        job_id=job.id, step=action, event_type="error",
                        details={"msg": sandbox_task.error or "Error en sandbox"}
                    ))
                    # Fail-Safe inteligente: usar la probabilidad acumulada
                    if probability >= 0.50:
                        decision = "phishing"
                    elif probability <= 0.35:
                        decision = "legitimate"
                    else:
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
                    llm_prob = sandbox_task.result_json.get("probability")
                    if llm_prob is not None:
                        probability = float(llm_prob)
                        print(f"Probabilidad asignada por IA Generativa: {probability}", flush=True)
                    else:
                        print("Advertencia: IA falló o no retornó probabilidad. Invocando predict_m2 (calibrador Platt).", flush=True)
                        probability = predict_m2(accumulated_features["url"], accumulated_features["infrastructure"], accumulated_features["content"], probability)
                elif action == "visual":
                    probability = predict_m3(accumulated_features["url"], accumulated_features["infrastructure"], accumulated_features["content"], accumulated_features["visual"], probability)
                
                consulted.append(action)
                step += 1
                
        print(f"Worker {job.id}: Terminado bucle adaptativo con decision {decision}", flush=True)
        # --- GUARDAR RESULTADOS E INSTRUMENTACIÓN ---
        evidence = [
            {"source": "M0", "feature": "probability", "value": probability},
            {"source": "orchestrator", "confidence": confidence, "uncertainty": uncertainty, "exit_stage": consulted[-1] if consulted else "url"}
        ]
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
        
        # Guardar en la caché de decisiones para futuras consultas de la misma URL
        decision_cache.set(job.url, {
            "decision": decision,
            "probability": probability,
            "confidence": confidence,
            "uncertainty": uncertainty,
            "modalities_consulted": consulted,
            "evidence_summary": evidence
        })
        
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
    """
    Bucle principal del worker con soporte de concurrencia configurable (WORKER_CONCURRENCY).
    Permite procesar múltiples trabajos simultáneamente sin bloquear la cola.
    """
    max_concurrency = max(1, int(os.environ.get("WORKER_CONCURRENCY", "5")))
    print(f"Worker asíncrono iniciado con concurrencia máxima de {max_concurrency}...", flush=True)
    
    # 1. Recuperar cualquier trabajo zombi de ejecuciones anteriores
    await recover_zombie_jobs()
    
    semaphore = asyncio.Semaphore(max_concurrency)
    active_tasks = set()

    async def _handle_job_wrapper(job_id):
        async with semaphore:
            try:
                async with async_session_maker() as session:
                    res = await session.execute(select(Job).where(Job.id == job_id))
                    job = res.scalar_one_or_none()
                    if job and job.status == JobStatus.PENDING:
                        print(f"Worker concurrente procesando job: {job.id}", flush=True)
                        await process_job(session, job)
            except Exception as exc:
                print(f"Error en worker task para job {job_id}: {exc}", flush=True)

    while True:
        try:
            # Limpiar tareas terminadas
            active_tasks = {t for t in active_tasks if not t.done()}
            available_slots = max_concurrency - len(active_tasks)

            if available_slots > 0:
                async with async_session_maker() as session:
                    # Buscar hasta available_slots trabajos pendientes
                    result = await session.execute(
                        select(Job.id)
                        .where(Job.status == JobStatus.PENDING)
                        .order_by(Job.created_at)
                        .limit(available_slots)
                    )
                    pending_ids = result.scalars().all()

                for jid in pending_ids:
                    task = asyncio.create_task(_handle_job_wrapper(jid))
                    active_tasks.add(task)

            # Espera breve antes de volver a sondear la cola
            await asyncio.sleep(0.5 if len(active_tasks) < max_concurrency else 1.0)
        except asyncio.CancelledError:
            print("Worker detenido. Cancelando tareas activas...", flush=True)
            for t in active_tasks:
                t.cancel()
            break
        except Exception as e:
            print(f"Error crítico en el bucle del worker: {e}", flush=True)
            await asyncio.sleep(5)
