"""
agents/correlation_agent.py
Agent 3 of 4 in the pipeline.

Responsibility: group related alerts into an Incident.

Correlation logic:
  - Find alerts (excluding the current one) that share source_ip OR dest_ip
    AND were created within TIME_WINDOW_MINUTES of this alert
  - If 1+ related alerts found (i.e., 2+ total including this one):
      • Create or reuse an Incident row
      • Link all related alerts (and this alert) to that Incident
      • If the Incident is new, call Gemini once to generate Incident.summary
  - Idempotent: if this alert already has an incident_id, attempt to add any
    newly-found related alerts into the existing incident

Returns the Incident (or None if no correlation found).
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from models import Alert, Incident

logger = logging.getLogger(__name__)

TIME_WINDOW_MINUTES = 15

INCIDENT_SUMMARY_PROMPT = """\
You are a SOC analyst synthesizing a multi-alert incident.

Below are the related security alerts that have been grouped into a single incident.
Write a concise incident summary (3–5 sentences) that:
1. Describes what appears to be happening across all the alerts as a whole
2. Identifies the most likely threat actor goal or attack pattern
3. States the overall severity and your top recommendation

Respond with ONLY a plain-text paragraph. No JSON, no bullet points, no markdown.

Alerts:
{alerts_text}
"""


def correlate_alert(alert, db: Session) -> Optional[object]:
    """
    Agent 3 entry point called by pipeline.py.

    Finds related alerts, creates/updates an Incident, generates an LLM summary
    for new incidents.

    Returns the Incident object or None.
    """
    # Build the time window
    window_start = alert.timestamp - timedelta(minutes=TIME_WINDOW_MINUTES)
    window_end = alert.timestamp + timedelta(minutes=TIME_WINDOW_MINUTES)

    # Conditions for a "related" alert (must share at least one IP with us)
    ip_conditions = []
    if alert.source_ip and alert.source_ip.lower() not in ("unknown", "multiple", "external", ""):
        ip_conditions.append(Alert.source_ip == alert.source_ip)
        ip_conditions.append(Alert.dest_ip == alert.source_ip)
    if alert.dest_ip and alert.dest_ip.lower() not in ("unknown", "multiple", "external", ""):
        ip_conditions.append(Alert.source_ip == alert.dest_ip)
        ip_conditions.append(Alert.dest_ip == alert.dest_ip)

    if not ip_conditions:
        logger.info("[CorrelationAgent] alert=%d no correlatable IPs — skipping", alert.id)
        return None

    related = (
        db.query(Alert)
        .filter(
            Alert.id != alert.id,
            Alert.timestamp >= window_start,
            Alert.timestamp <= window_end,
            or_(*ip_conditions),
        )
        .all()
    )

    if not related:
        logger.info("[CorrelationAgent] alert=%d no related alerts found in window", alert.id)
        return None

    all_alerts = [alert] + related
    logger.info(
        "[CorrelationAgent] alert=%d correlated with %d other alert(s) → %d total",
        alert.id, len(related), len(all_alerts),
    )

    # --- Resolve or create the Incident ---
    # Prefer an existing incident already assigned to one of the related alerts
    existing_incident_id = None
    for a in all_alerts:
        if a.incident_id is not None:
            existing_incident_id = a.incident_id
            break

    if existing_incident_id:
        incident = db.query(Incident).filter(Incident.id == existing_incident_id).first()
        if incident is None:
            # Stale FK — create fresh
            incident = _create_incident(all_alerts, db)
    else:
        incident = _create_incident(all_alerts, db)

    # --- Link all alerts to this incident ---
    for a in all_alerts:
        if a.incident_id != incident.id:
            a.incident_id = incident.id
    db.commit()

    # --- Generate LLM summary if this is a new incident (no summary yet) ---
    if not incident.summary:
        _generate_summary(incident, all_alerts, db)

    db.refresh(incident)
    return incident


def _create_incident(alerts: list, db: Session) -> object:
    """Creates a new Incident row with a severity derived from the most severe alert."""
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, None: 0}
    max_severity = max(
        (a.llm_severity for a in alerts),
        key=lambda s: severity_order.get(s, 0),
        default="Medium",
    )

    # Title: most common alert_type in the group
    types = [a.alert_type for a in alerts]
    dominant_type = max(set(types), key=types.count)
    ips = {a.source_ip for a in alerts if a.source_ip} | {a.dest_ip for a in alerts if a.dest_ip}
    ip_label = ", ".join(sorted(ips)[:3])  # cap at 3 IPs for readability

    incident = Incident(
        title=f"{dominant_type} cluster ({len(alerts)} alerts) — {ip_label}",
        severity=max_severity or "Medium",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    logger.info("[CorrelationAgent] created incident=%d severity=%s", incident.id, incident.severity)
    return incident


def _generate_summary(incident, alerts: list, db: Session) -> None:
    """Calls Gemini once to write the incident narrative summary."""
    # Import here to avoid circular imports (triage_agent imports nothing from correlation)
    try:
        from agents.triage_agent import call_gemini, GEMINI_API_KEY
    except ImportError:
        from triage_agent import call_gemini, GEMINI_API_KEY

    if not GEMINI_API_KEY:
        incident.summary = "Gemini API key not set — incident summary skipped."
        db.commit()
        return

    alerts_text = "\n\n".join(
        f"Alert #{a.id} [{a.alert_type}] from {a.source_ip} → {a.dest_ip}\n"
        f"  Log: {a.raw_log}\n"
        f"  LLM severity: {a.llm_severity} | False positive: {a.llm_is_false_positive}\n"
        f"  Reasoning: {a.llm_reasoning or 'n/a'}"
        for a in alerts
    )

    prompt = INCIDENT_SUMMARY_PROMPT.format(alerts_text=alerts_text)

    try:
        summary = call_gemini(prompt).strip()
        incident.summary = summary
        db.commit()
        logger.info("[CorrelationAgent] generated summary for incident=%d", incident.id)
    except Exception as exc:
        incident.summary = f"Summary generation failed: {exc}"
        db.commit()
        logger.error("[CorrelationAgent] summary generation error for incident=%d: %s", incident.id, exc)
