"""
models.py
Three core tables:
  Alert     -> a single raw security event (login failure, port scan, etc.)
  Incident  -> a group of correlated alerts triaged together
  AuditLog  -> immutable log of every simulated response action taken
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), nullable=True)          # e.g. "192.168.1.55"
    dest_ip = Column(String(45), nullable=True)
    alert_type = Column(String(100), nullable=False)        # e.g. "Brute Force", "Port Scan"
    raw_log = Column(Text, nullable=False)                  # the actual log line / description
    timestamp = Column(DateTime, default=datetime.utcnow)

    # --- rule-based triage results ---
    rule_severity = Column(String(20), nullable=True)       # Low / Medium / High / Critical
    rule_is_false_positive = Column(Boolean, nullable=True)

    # --- LLM triage results (written by triage_agent) ---
    llm_severity = Column(String(20), nullable=True)
    llm_is_false_positive = Column(Boolean, nullable=True)
    llm_reasoning = Column(Text, nullable=True)             # short explanation from the model
    llm_recommended_action = Column(Text, nullable=True)

    # --- Enrichment agent results ---
    threat_intel_score = Column(Float, nullable=True)       # AbuseIPDB 0–100 confidence score
    threat_intel_summary = Column(Text, nullable=True)      # human-readable enrichment note

    # --- Response agent results ---
    pipeline_playbook = Column(Text, nullable=True)         # JSON string of PlaybookStep list
    pipeline_playbook_status = Column(String(20), nullable=True)  # proposed / approved / executed

    status = Column(String(20), default="new")              # new / triaged / resolved
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)

    incident = relationship("Incident", back_populates="alerts")
    audit_logs = relationship("AuditLog", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    summary = Column(Text, nullable=True)                   # LLM-generated incident summary
    severity = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # --- Response / SOAR fields ---
    playbook = Column(Text, nullable=True)                  # JSON playbook for incident-level response
    response_status = Column(String(20), nullable=True)     # proposed / approved / executed

    alerts = relationship("Alert", back_populates="incident")
    audit_logs = relationship("AuditLog", back_populates="incident")


class AuditLog(Base):
    """Immutable audit trail — one row per simulated action executed."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)

    action = Column(String(50), nullable=False)             # block_ip, isolate_host, notify_analyst …
    description = Column(Text, nullable=True)               # human-readable step description
    actor = Column(String(20), nullable=False)              # "AI" | "analyst"
    outcome = Column(String(20), nullable=False)            # simulated / approved / rejected

    alert = relationship("Alert", back_populates="audit_logs")
    incident = relationship("Incident", back_populates="audit_logs")
