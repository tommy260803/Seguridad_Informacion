import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class JobStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Job(Base):
    """Cola persistente de trabajos de análisis."""
    __tablename__ = "jobs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = Column(String, nullable=False)
    status = Column(Enum(JobStatus), default=JobStatus.PENDING, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    
    analysis = relationship("Analysis", back_populates="job", uselist=False, cascade="all, delete-orphan")
    events = relationship("Event", back_populates="job", cascade="all, delete-orphan", order_by="Event.created_at")

class Analysis(Base):
    """Resultados finales del análisis."""
    __tablename__ = "analyses"
    
    id = Column(UUID(as_uuid=True), ForeignKey("jobs.id"), primary_key=True)
    decision = Column(String, nullable=False) # legitimate, phishing, uncertain
    probability = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    uncertainty = Column(Float, nullable=True)
    modalities_consulted = Column(JSON, nullable=False, default=list)
    evidence_summary = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    job = relationship("Job", back_populates="analysis")

class Event(Base):
    """Trazabilidad detallada por etapa (URL -> Infra -> Content -> Visual)."""
    __tablename__ = "events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id"), nullable=False)
    step = Column(String, nullable=False) # url, infrastructure, content, visual, orchestrator
    event_type = Column(String, nullable=False) # acquire, error, decision
    details = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    job = relationship("Job", back_populates="events")
    
class SandboxTask(Base):
    """Cola para el Sandbox Manager (Contenedores efímeros)."""
    __tablename__ = "sandbox_tasks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id"), nullable=False)
    modality = Column(String(50), nullable=False) # infrastructure, content
    url = Column(String, nullable=False)
    status = Column(Enum(JobStatus), default=JobStatus.PENDING, nullable=False)
    result_json = Column(JSON, nullable=True)
    error = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
