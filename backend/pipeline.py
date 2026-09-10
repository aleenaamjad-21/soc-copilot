"""
pipeline.py
Orchestrates the four-agent pipeline for a single alert:

  Step 1 — Enrichment Agent  : threat-intel lookup for source_ip
  Step 2 — Rule Baseline     : deterministic rule-based triage (kept intact)
  Step 3 — Triage Agent      : LLM triage enriched with threat-intel context
  Step 4 — Correlation Agent : group related alerts into an Incident
  Step 5 — Response Agent    : generate a structured containment playbook

Each step is logged with a bracketed prefix so the pipeline's reasoning is fully
auditable in server logs. Each agent's output is committed to the DB independently
so partial results are visible even if a later step fails.

Usage (from main.py):
    from pipeline import run_pipeline
    updated_alert = run_pipeline(alert_id, db)
"""

import logging
from sqlalchemy.orm import Session
from models import Alert
from rule_engine import rule_based_triage
from agents.enrichment_agent import enrich_alert
from agents.triage_agent import triage_alert
from agents.correlation_agent import correlate_alert
from agents.response_agent import generate_playbook

logger = logging.getLogger(__name__)


def run_pipeline(alert_id: int, db: Session) -> Alert:
    """
    Runs all pipeline agents in sequence for the given alert.
    Each step commits its results independently so they're always inspectable.
    Returns the refreshed Alert object.

    Raises:
        ValueError if the alert_id doesn't exist.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise ValueError(f"Alert {alert_id} not found")

    logger.info("=" * 60)
    logger.info("[Pipeline] START alert=%d type=%s", alert.id, alert.alert_type)

    # ------------------------------------------------------------------
    # Step 1: Enrichment Agent
    # ------------------------------------------------------------------
    logger.info("[Pipeline] Step 1/5 — Enrichment Agent (source_ip=%s)", alert.source_ip)
    try:
        enrich_result = enrich_alert(alert, db)
        logger.info("[Pipeline] Step 1 done → score=%s", enrich_result.get("threat_intel_score"))
    except Exception as exc:
        logger.error("[Pipeline] Step 1 FAILED: %s — continuing", exc)

    # ------------------------------------------------------------------
    # Step 2: Rule-Based Baseline (always runs, deterministic)
    # ------------------------------------------------------------------
    logger.info("[Pipeline] Step 2/5 — Rule Baseline (alert_type=%s)", alert.alert_type)
    try:
        rule_result = rule_based_triage(alert.alert_type)
        alert.rule_severity = rule_result["rule_severity"]
        alert.rule_is_false_positive = rule_result["rule_is_false_positive"]
        db.commit()
        logger.info("[Pipeline] Step 2 done → rule_severity=%s", alert.rule_severity)
    except Exception as exc:
        logger.error("[Pipeline] Step 2 FAILED: %s — continuing", exc)

    # ------------------------------------------------------------------
    # Step 3: LLM Triage Agent
    # ------------------------------------------------------------------
    logger.info("[Pipeline] Step 3/5 — Triage Agent")
    try:
        triage_result = triage_alert(alert, db)
        logger.info(
            "[Pipeline] Step 3 done → llm_severity=%s fp=%s",
            triage_result.get("llm_severity"),
            triage_result.get("llm_is_false_positive"),
        )
    except Exception as exc:
        logger.error("[Pipeline] Step 3 FAILED: %s — continuing", exc)

    # ------------------------------------------------------------------
    # Step 4: Correlation Agent
    # ------------------------------------------------------------------
    logger.info("[Pipeline] Step 4/5 — Correlation Agent")
    incident = None
    try:
        incident = correlate_alert(alert, db)
        if incident:
            logger.info("[Pipeline] Step 4 done → incident=%d", incident.id)
        else:
            logger.info("[Pipeline] Step 4 done → no incident (standalone alert)")
    except Exception as exc:
        logger.error("[Pipeline] Step 4 FAILED: %s — continuing", exc)

    # ------------------------------------------------------------------
    # Step 5: Response Agent
    # ------------------------------------------------------------------
    logger.info("[Pipeline] Step 5/5 — Response Agent")
    try:
        playbook = generate_playbook(alert, incident, db)
        step_count = len(playbook.get("steps", []))
        logger.info("[Pipeline] Step 5 done → %d playbook step(s)", step_count)
    except Exception as exc:
        logger.error("[Pipeline] Step 5 FAILED: %s — continuing", exc)

    # ------------------------------------------------------------------
    # Mark alert as triaged
    # ------------------------------------------------------------------
    alert.status = "triaged"
    db.commit()
    db.refresh(alert)

    logger.info("[Pipeline] DONE alert=%d final_status=triaged", alert.id)
    logger.info("=" * 60)

    return alert
