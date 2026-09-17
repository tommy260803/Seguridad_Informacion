import asyncio
from sqlalchemy import select
from phishguard_api.database import async_session_maker
from phishguard_api.models import SandboxTask
async def test():
    async with async_session_maker() as session:
        r = await session.execute(select(SandboxTask))
        print([t.status.value for t in r.scalars().all()])
asyncio.run(test())
