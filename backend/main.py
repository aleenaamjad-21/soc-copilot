"""
main.py
FastAPI app — run with: uvicorn main:app --reload --port 8000
API docs auto-generated at http://localhost:8000/docs

v2 changes:
  - /alerts/{id}/triage      → synchronous, calls full 4-agent pipeline
  - /alerts/triage-all       → background task (returns immediately, poll /alerts/triage-status)
  - GET  /alerts/triage-status   → progress counts (new vs triaged)
  - GET  /incidents              → list all incidents with their alerts
  - GET  /incidents/{id}         → single incident detail
  - POST /incidents/{id}/approve-response → analyst approval gate → triggers simulator
  - GET  /audit-logs             → full audit trail (filterable by alert_id / incident_id)
  - GET  /simulator-state        → current in-memory simulated firewall state
"""

import json
import logging
import time
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import get_db, engine, Base
from models import Alert, Incident, AuditLog
from schemas import (
    AlertOut, AlertCreate,
    IncidentOut, AuditLogOut,
    TriageStatusOut,
)
from rule_engine import rule_based_triage
from llm_triage import llm_based_triage       # kept for reference / backwards compat
from pipeline import run_pipeline
from response_simulator import approve_and_execute, firewall

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SOC Copilot API v2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten before deploying publicly
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Internal background-task state tracker (simple, no Redis needed for a demo)
# ---------------------------------------------------------------------------
_triage_all_running = False


# ===========================================================================
# Alert endpoints (existing — kept working, updated to use pipeline)
# ===========================================================================

@app.get("/alerts", response_model=List[AlertOut])
def list_alerts(db: Session = Depends(get_db)):
    """Returns all alerts, most recent first — powers the dashboard alert queue."""
    return db.query(Alert).order_by(Alert.timestamp.desc()).all()


@app.get("/alerts/triage-status", response_model=TriageStatusOut)
def triage_status(db: Session = Depends(get_db)):
    """
    Lightweight progress endpoint for the frontend to poll while triage-all runs.
    Returns counts of new vs triaged alerts and whether a bulk run is in progress.
    """
    all_alerts = db.query(Alert).all()
    new_count = sum(1 for a in all_alerts if a.status == "new")
    triaged_count = sum(1 for a in all_alerts if a.status == "triaged")
    return TriageStatusOut(
        total=len(all_alerts),
        new=new_count,
        triaged=triaged_count,
        in_progress=_triage_all_running,
    )


@app.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.post("/alerts", response_model=AlertOut)
def create_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    """Lets you manually add an alert (or later, feed it from a real log source)."""
    db_alert = Alert(**alert.model_dump())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


@app.post("/alerts/{alert_id}/triage", response_model=AlertOut)
def triage_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Runs the full 4-agent pipeline on a single alert:
      1. Enrichment Agent  — threat-intel lookup
      2. Rule Baseline     — deterministic severity
      3. Triage Agent      — LLM severity + reasoning (with enrichment context)
      4. Correlation Agent — group into an Incident if related alerts exist
      5. Response Agent    — generate containment playbook

    Synchronous (blocks until done). Single alerts are fast enough for this.
    Watch server logs to see each step's bracketed output.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    updated = run_pipeline(alert_id, db)
    return updated


@app.post("/alerts/triage-all")
def triage_all(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Bulk-triages all untriaged alerts using the full pipeline.
    Returns immediately with a "started" response — poll GET /alerts/triage-status
    (or GET /alerts) to watch progress as statuses flip from "new" → "triaged".

    Only one bulk run can be active at a time.
    """
    global _triage_all_running

    if _triage_all_running:
        return {"status": "already_running", "message": "A bulk triage run is already in progress — poll /alerts/triage-status for progress."}

    untriaged_ids = [
        a.id for a in db.query(Alert).filter(Alert.status == "new").all()
    ]

    if not untriaged_ids:
        return {"status": "nothing_to_do", "message": "All alerts are already triaged.", "count": 0}

    background_tasks.add_task(_run_triage_all_background, untriaged_ids)

    return {
        "status": "started",
        "message": f"Pipeline started for {len(untriaged_ids)} alert(s). Poll GET /alerts/triage-status for progress.",
        "count": len(untriaged_ids),
    }


def _run_triage_all_background(alert_ids: list[int]):
    """
    Background worker: runs the pipeline for each alert, one at a time.
    Uses its own DB session (required for background tasks — can't share the
    request session across threads).
    """
    global _triage_all_running
    from database import SessionLocal

    _triage_all_running = True
    db = SessionLocal()
    try:
        logger.info("[triage-all] Starting background pipeline for %d alerts", len(alert_ids))
        for i, alert_id in enumerate(alert_ids, 1):
            try:
                logger.info("[triage-all] Processing alert %d/%d (id=%d)", i, len(alert_ids), alert_id)
                run_pipeline(alert_id, db)
            except Exception as exc:
                logger.error("[triage-all] alert=%d failed: %s — skipping", alert_id, exc)
            time.sleep(6)  # stay under Groq's free-tier TPM limit — each alert can make up to 3 LLM calls
        logger.info("[triage-all] Completed all %d alerts", len(alert_ids))
    finally:
        db.close()
        _triage_all_running = False


# ===========================================================================
# Stats endpoint (existing — kept working)
# ===========================================================================

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Quick aggregate counts for the dashboard's summary cards / severity heatmap."""
    alerts = db.query(Alert).all()
    triaged = [a for a in alerts if a.status == "triaged"]
    incidents = db.query(Incident).all()

    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    agreement_count = 0
    for a in triaged:
        if a.llm_severity in severity_counts:
            severity_counts[a.llm_severity] += 1
        if a.llm_severity and a.rule_severity == a.llm_severity:
            agreement_count += 1

    return {
        "total_alerts": len(alerts),
        "triaged_alerts": len(triaged),
        "total_incidents": len(incidents),
        "severity_breakdown_llm": severity_counts,
        "rule_llm_agreement_rate": round(agreement_count / len(triaged), 2) if triaged else None,
    }


# ===========================================================================
# Incident endpoints (new)
# ===========================================================================

@app.get("/incidents", response_model=List[IncidentOut])
def list_incidents(db: Session = Depends(get_db)):
    """Returns all incidents (most recently created first) with their linked alerts."""
    return db.query(Incident).order_by(Incident.created_at.desc()).all()


@app.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/incidents/{incident_id}/approve-response")
def approve_incident_response(incident_id: int, db: Session = Depends(get_db)):
    """
    Analyst approval gate for the simulated automated response.

    Workflow:
      1. Validates incident exists and has a "proposed" playbook
      2. Writes an "analyst approved" AuditLog entry
      3. Calls the ResponseSimulator to execute each step against the simulated firewall
      4. Sets incident.response_status = "executed"

    Under no circumstances is any action taken against real infrastructure.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not incident.playbook:
        raise HTTPException(
            status_code=400,
            detail="Incident has no playbook — run triage first to generate one.",
        )

    if incident.response_status == "executed":
        raise HTTPException(
            status_code=409,
            detail="Response has already been executed for this incident.",
        )

    try:
        audit_entries = approve_and_execute(incident, db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status": "executed",
        "incident_id": incident_id,
        "actions_taken": len(audit_entries),
        "audit_entries": audit_entries,
        "message": "Playbook executed against simulated firewall. See /audit-logs for the full trail.",
    }


# ===========================================================================
# Audit log endpoints (new)
# ===========================================================================

@app.get("/audit-logs", response_model=List[AuditLogOut])
def list_audit_logs(
    alert_id: Optional[int] = Query(None, description="Filter by alert ID"),
    incident_id: Optional[int] = Query(None, description="Filter by incident ID"),
    db: Session = Depends(get_db),
):
    """
    Full audit trail of all simulated response actions.
    Optionally filter by alert_id or incident_id.
    """
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    if alert_id is not None:
        query = query.filter(AuditLog.alert_id == alert_id)
    if incident_id is not None:
        query = query.filter(AuditLog.incident_id == incident_id)
    return query.all()


# ===========================================================================
# Simulator state endpoint (new)
# ===========================================================================

@app.get("/simulator-state")
def get_simulator_state():
    """
    Returns the current in-memory state of the simulated firewall.
    Useful for the dashboard to show "what the AI did" in real time.
    Resets to empty every time the server restarts (by design — it's a simulator).
    """
    return firewall.get_state()