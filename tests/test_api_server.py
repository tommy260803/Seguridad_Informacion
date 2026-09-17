import pytest
from fastapi.testclient import TestClient
from phishguard_api.server import app, get_db
from phishguard_api.models import JobStatus

# Mock DB Session
class MockSession:
    async def get(self, *args, **kwargs): return None
    async def commit(self): pass
    def add(self, entity, *args, **kwargs):
        if hasattr(entity, 'id') and getattr(entity, 'id') is None:
            import uuid
            entity.id = uuid.uuid4()
        if hasattr(entity, 'status') and getattr(entity, 'status') is None:
            entity.status = JobStatus.PENDING
    async def refresh(self, *args, **kwargs): pass

async def override_get_db():
    yield MockSession()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

def test_local_api_creates_analysis_job() -> None:
    response = client.post("/analyses", json={"url": "https://secure.example/login"})
    assert response.status_code == 202
    data = response.json()
    assert "id" in data
    assert data["status"] in [JobStatus.PENDING, JobStatus.RUNNING]

def test_local_api_rejects_unsafe_input() -> None:
    response = client.post("/analyses", json={"url": "file:///etc/passwd"})
    assert response.status_code == 422
    assert "detail" in response.json()
