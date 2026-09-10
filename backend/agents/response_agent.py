"""
agents/response_agent.py
Agent 4 of 4 in the pipeline.

Responsibility: given a triaged alert (optionally with an incident context),
generate a structured containment playbook — a list of concrete, ordered steps
with machine-readable action types.

Output stored in:
  alert.pipeline_playbook        (JSON string matching Playbook schema)
  alert.pipeline_playbook_status ("proposed")

Also sets incident.playbook / incident.response_status if an incident is linked.

The playbook is what Feature 2 (response_simulator.py) consumes when an
analyst approves the response.
"""

import json
import logging
from typing import Optional
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Valid action types — the simulator handles each of these
VALID_ACTIONS = {
    "block_ip",
    "isolate_host",
    "notify_analyst",
    "collect_forensics",
    "reset_credentials",
    "escalate_to_incident",
    "no_action_needed",
}

PLAYBOOK_PROMPT = """\
You are a SOC automation engine. Given a triaged security alert, produce a structured
containment playbook as STRICT JSON only — no markdown, no commentary, no code fences.

Use exactly this schema:
{{
  "steps": [
    {{"action": "<action_type>", "description": "<human-readable explanation>"}},
    ...
  ]
}}

Valid action types (use only these exact strings):
  block_ip            - Block the source IP at the network perimeter
  isolate_host        - Quarantine the affected host from the network
  notify_analyst      - Alert an on-call analyst or team
  collect_forensics   - Capture memory dump, disk image, or log bundle
  reset_credentials   - Force password/token reset for affected accounts
  escalate_to_incident - Escalate this alert into a tracked incident
  no_action_needed    - Confirm no response is required (false positive / low risk)

Rules:
  - Include 1–5 steps (no more)
  - Order steps by priority (most urgent first)
  - If severity is Low or it's a false positive, use no_action_needed as the only step
  - Be specific in descriptions — include the actual IPs, hostnames, or usernames from the alert

Alert details:
  Type: {alert_type}
  Source IP: {source_ip}
  Destination IP: {dest_ip}
  Severity: {severity}
  Is false positive: {is_fp}
  Threat intel score: {threat_intel_score}
  Threat intel: {threat_intel_summary}
  AI reasoning: {reasoning}
  Recommended action: {recommended_action}

{incident_context}
"""

INCIDENT_CONTEXT_TEMPLATE = """\
Incident context (this alert is part of a correlated incident):
  Incident ID: {incident_id}
  Incident title: {incident_title}
  Incident severity: {incident_severity}
  Incident summary: {incident_summary}
"""


def generate_playbook(alert, incident: Optional[object], db: Session) -> dict:
    """
    Agent 4 entry point called by pipeline.py.

    Mutates alert.pipeline_playbook and alert.pipeline_playbook_status.
    If an incident is linked, also sets incident.playbook and incident.response_status.

    Returns the parsed playbook dict ({"steps": [...]}).
    """
    try:
        from agents.triage_agent import call_gemini, GEMINI_API_KEY
    except ImportError:
        from triage_agent import call_gemini, GEMINI_API_KEY

    if not GEMINI_API_KEY:
        fallback = {"steps": [{"action": "notify_analyst", "description": "GEMINI_API_KEY not set — manual review required."}]}
        _save(alert, incident, db, fallback)
        logger.warning("[ResponseAgent] alert=%d skipped (no Gemini key)", alert.id)
        return fallback

    incident_context = ""
    if incident:
        incident_context = INCIDENT_CONTEXT_TEMPLATE.format(
            incident_id=incident.id,
            incident_title=incident.title,
            incident_severity=incident.severity or "unknown",
            incident_summary=incident.summary or "no summary yet",
        )

    prompt = PLAYBOOK_PROMPT.format(
        alert_type=alert.alert_type,
        source_ip=alert.source_ip or "unknown",
        dest_ip=alert.dest_ip or "unknown",
        severity=alert.llm_severity or "unknown",
        is_fp=str(alert.llm_is_false_positive),
        threat_intel_score=(
            f"{alert.threat_intel_score:.0f}/100"
            if alert.threat_intel_score is not None
            else "not available"
        ),
        threat_intel_summary=alert.threat_intel_summary or "no enrichment data",
        reasoning=alert.llm_reasoning or "n/a",
        recommended_action=alert.llm_recommended_action or "n/a",
        incident_context=incident_context,
    )

    try:
        raw = call_gemini(prompt)
        cleaned = (
            raw.strip()
            .removeprefix("```json")
            .removeprefix("```")
            .removesuffix("```")
            .strip()
        )
        playbook = json.loads(cleaned)

        # Validate and sanitise action types
        steps = playbook.get("steps", [])
        for step in steps:
            if step.get("action") not in VALID_ACTIONS:
                step["action"] = "notify_analyst"  # safe default for unexpected actions

        playbook["steps"] = steps
        _save(alert, incident, db, playbook)
        logger.info(
            "[ResponseAgent] alert=%d generated %d-step playbook",
            alert.id, len(steps),
        )
        return playbook

    except Exception as exc:
        fallback = {
            "steps": [{
                "action": "notify_analyst",
                "description": f"Playbook generation failed ({exc}) — manual analyst review required.",
            }]
        }
        _save(alert, incident, db, fallback)
        logger.error("[ResponseAgent] alert=%d playbook generation error: %s", alert.id, exc)
        return fallback


def _save(alert, incident: Optional[object], db: Session, playbook: dict) -> None:
    alert.pipeline_playbook = json.dumps(playbook)
    alert.pipeline_playbook_status = "proposed"

    if incident:
        incident.playbook = json.dumps(playbook)
        incident.response_status = "proposed"

    db.commit()
    db.refresh(alert)
    if incident:
        db.refresh(incident)
