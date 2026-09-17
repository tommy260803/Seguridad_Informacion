import asyncio
from sqlalchemy import select
from phishguard_api.database import async_session_maker
from phishguard_api.models import SandboxTask
async def test():
    async with async_session_maker() as session:
        r = await session.execute(select(SandboxTask).order_by(SandboxTask.created_at.desc()).limit(5))
        tasks = r.scalars().all()
        for t in tasks:
            print(t.url, t.modality, t.status.value, t.error)
asyncio.run(test())
