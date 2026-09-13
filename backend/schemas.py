"""
schemas.py
Pydantic models — define what the API accepts and returns.
Kept separate from models.py (DB layer) so the API shape can evolve independently
of the DB schema.
"""

from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Any


# ---------------------------------------------------------------------------
# Alert schemas
# ---------------------------------------------------------------------------

class AlertBase(BaseModel):
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    alert_type: str
    raw_log: str


class AlertCreate(AlertBase):
    pass


class AlertOut(AlertBase):
    id: int
    timestamp: datetime

    # Rule-based
    rule_severity: Optional[str] = None
    rule_is_false_positive: Optional[bool] = None

    # LLM triage
    llm_severity: Optional[str] = None
    llm_is_false_positive: Optional[bool] = None
    llm_reasoning: Optional[str] = None
    llm_recommended_action: Optional[str] = None
    mitre_technique: Optional[str] = None

    # Enrichment
    threat_intel_score: Optional[float] = None
    threat_intel_summary: Optional[str] = None

    # Response pipeline
    pipeline_playbook: Optional[str] = None          # raw JSON string
    pipeline_playbook_status: Optional[str] = None

    status: str
    incident_id: Optional[int] = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Playbook schemas (used by response_agent and response_simulator)
# ---------------------------------------------------------------------------

class PlaybookStep(BaseModel):
    action: str          # block_ip | isolate_host | notify_analyst | collect_forensics |
                         # reset_credentials | escalate_to_incident | no_action_needed
    description: str     # human-readable explanation of the step


class Playbook(BaseModel):
    steps: List[PlaybookStep]


# ---------------------------------------------------------------------------
# Incident schemas
# ---------------------------------------------------------------------------

class IncidentOut(BaseModel):
    id: int
    title: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    created_at: datetime
    playbook: Optional[str] = None           # raw JSON string
    response_status: Optional[str] = None
    alerts: List[AlertOut] = []

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# AuditLog schemas
# ---------------------------------------------------------------------------

class AuditLogOut(BaseModel):
    id: int
    timestamp: datetime
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    action: str
    description: Optional[str] = None
    actor: str
    outcome: str

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Misc / status schemas
# ---------------------------------------------------------------------------

class TriageStatusOut(BaseModel):
    """Returned by GET /alerts/triage-status so the frontend can poll progress."""
    total: int
    new: int
    triaged: int
    in_progress: bool
