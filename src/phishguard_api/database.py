from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
import os

# Usamos la variable de entorno del docker-compose o una URL local por defecto
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://phishguard@127.0.0.1:5432/phishguard_db",
)

engine = create_async_engine(DATABASE_URL, echo=False)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency para inyectar la sesión de BD en los endpoints de FastAPI"""
    async with async_session_maker() as session:
        yield session
