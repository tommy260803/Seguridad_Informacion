"""Idempotently queue fresh jobs for analyses whose visual task failed."""

import argparse
import asyncio
import uuid

from sqlalchemy import select

from phishguard_api.database import async_session_maker
from phishguard_api.models import Event, Job, JobStatus, SandboxTask


async def queue_visual_retries(*, limit: int | None = None) -> list[str]:
    """Create one child job per original failed visual acquisition, preserving history."""
    queued: list[str] = []
    async with async_session_maker() as session:
        statement = (
            select(SandboxTask)
            .where(SandboxTask.modality == "visual", SandboxTask.status == JobStatus.FAILED)
            .order_by(SandboxTask.created_at)
        )
        if limit is not None:
            statement = statement.limit(limit)
        failed_tasks = (await session.execute(statement)).scalars().all()
        for failed_task in failed_tasks:
            previous = (
                await session.execute(
                    select(Event).where(
                        Event.job_id == failed_task.job_id,
                        Event.step == "system",
                        Event.event_type == "reanalysis",
                    )
                )
            ).scalars().all()
            already_verified = False
            retry_in_progress = False
            for event in previous:
                if event.details.get("reason") != "visual_failed":
                    continue
                retry_id = event.details.get("retry_job_id")
                try:
                    retry = await session.get(Job, uuid.UUID(str(retry_id)))
                except (TypeError, ValueError):
                    retry = None
                if retry is None:
                    continue
                if retry.status in {JobStatus.PENDING, JobStatus.RUNNING}:
                    retry_in_progress = True
                    continue
                visual = (
                    await session.execute(
                        select(SandboxTask).where(
                            SandboxTask.job_id == retry.id,
                            SandboxTask.modality == "visual",
                        )
                    )
                ).scalar_one_or_none()
                already_verified = already_verified or bool(visual and visual.status == JobStatus.COMPLETED)
            if already_verified or retry_in_progress:
                continue
            retry = Job(url=failed_task.url, status=JobStatus.PENDING)
            session.add(retry)
            await session.flush()
            session.add(Event(
                job_id=failed_task.job_id,
                step="system",
                event_type="reanalysis",
                details={"reason": "visual_failed", "retry_job_id": str(retry.id), "visual_error": failed_task.error},
            ))
            session.add(Event(
                job_id=retry.id,
                step="system",
                event_type="reanalysis",
                details={"force_visual": True, "source_job_id": str(failed_task.job_id)},
            ))
            queued.append(str(retry.id))
        await session.commit()
    return queued


def main() -> None:
    parser = argparse.ArgumentParser(description="Queue new jobs for prior visual sandbox failures.")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be positive")
    queued = asyncio.run(queue_visual_retries(limit=args.limit))
    print(f"Queued {len(queued)} visual reanalysis job(s): {', '.join(queued)}")


if __name__ == "__main__":
    main()
