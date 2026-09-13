"""
agents/triage_agent.py
Agent 2 of 4 in the pipeline.

Responsibility: LLM-based triage of a single alert, now enriched with threat-intel
context from the Enrichment Agent. This is a refactor of the original llm_triage.py:
  - Same _call_gemini helper (shared with other agents that need Gemini)
  - Prompt now includes threat_intel_score / threat_intel_summary
  - Same output contract: llm_severity, llm_is_false_positive, llm_reasoning,
    llm_recommended_action

Original llm_triage.py is preserved for reference. This module is what
pipeline.py calls going forward.
"""

import os
import json
import time
import logging
import requests
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

from llm_client import call_llm, GROQ_API_KEY

# Kept these names for backward compatibility — correlation_agent.py and
# response_agent.py both import call_gemini/GEMINI_API_KEY from this file
GEMINI_API_KEY = GROQ_API_KEY
call_gemini = call_llm


def _clean_json(raw: str) -> str:
    """Strip accidental markdown fences the model sometimes adds."""
    return (
        raw.strip()
        .removeprefix("```json")
        .removeprefix("```")
        .removesuffix("```")
        .strip()
    )


# ---------------------------------------------------------------------------
# Triage prompt — includes threat-intel context from Enrichment Agent
# ---------------------------------------------------------------------------

# Common MITRE ATT&CK techniques used for classification
_MITRE_TECHNIQUES = """\
  T1110 – Brute Force
  T1046 – Network Service Discovery
  T1071 – Application Layer Protocol (C2)
  T1566 – Phishing
  T1190 – Exploit Public-Facing Application
  T1059 – Command and Scripting Interpreter
  T1486 – Data Encrypted for Impact (Ransomware)
  T1041 – Exfiltration Over C2 Channel
  T1021 – Remote Services
  T1078 – Valid Accounts
  T1055 – Process Injection
  T1083 – File and Directory Discovery
  T1018 – Remote System Discovery
  T1498 – Network Denial of Service
  T1133 – External Remote Services
"""

TRIAGE_PROMPT = """\
You are a SOC (Security Operations Center) analyst assistant.
Analyze the following security alert — including any threat-intelligence data about
the source IP — and respond in STRICT JSON only. No markdown, no commentary, no code
fences. Use exactly this schema:

{{
  "severity": "Low" | "Medium" | "High" | "Critical",
  "is_false_positive": true | false,
  "reasoning": "one or two sentence explanation of your severity call",
  "recommended_action": "one concrete next step an analyst should take",
  "mitre_technique": "T#### – Technique Name (pick the SINGLE best match from the list below, or null if none fits)"
}}

Alert type: {alert_type}
Source IP: {source_ip}
Destination IP: {dest_ip}
Raw log / description: {raw_log}

Threat Intelligence (source: AbuseIPDB):
  Score: {threat_intel_score}
  Summary: {threat_intel_summary}

Use the threat-intel score to inform your severity decision. A score ≥ 75 should
push severity upward unless the alert context strongly contradicts it.

MITRE ATT&CK technique list (pick the single best match):
{mitre_techniques}
"""


def triage_alert(alert, db: Session) -> dict:
    """
    Agent 2 entry point called by pipeline.py.

    Mutates alert.llm_* fields and commits to DB.
    Returns the result dict for pipeline logging.
    """
    if not GEMINI_API_KEY:
        result = {
            "llm_severity": None,
            "llm_is_false_positive": None,
            "llm_reasoning": "GEMINI_API_KEY not set — AI triage skipped.",
            "llm_recommended_action": None,
            "mitre_technique": None,
        }
        _save(alert, db, result)
        logger.warning("[TriageAgent] alert=%d skipped (no Gemini key)", alert.id)
        return result

    prompt = TRIAGE_PROMPT.format(
        alert_type=alert.alert_type,
        source_ip=alert.source_ip or "unknown",
        dest_ip=alert.dest_ip or "unknown",
        raw_log=alert.raw_log,
        threat_intel_score=(
            f"{alert.threat_intel_score:.0f}/100"
            if alert.threat_intel_score is not None
            else "not available"
        ),
        threat_intel_summary=alert.threat_intel_summary or "no enrichment data",
        mitre_techniques=_MITRE_TECHNIQUES,
    )

    try:
        raw = call_gemini(prompt)
        parsed = json.loads(_clean_json(raw))
        raw_mitre = parsed.get("mitre_technique")
        # Normalise: accept null / "null" / empty string as None
        mitre = raw_mitre if raw_mitre and raw_mitre.lower() not in ("null", "none", "") else None
        result = {
            "llm_severity": parsed.get("severity"),
            "llm_is_false_positive": parsed.get("is_false_positive"),
            "llm_reasoning": parsed.get("reasoning"),
            "llm_recommended_action": parsed.get("recommended_action"),
            "mitre_technique": mitre,
        }
        logger.info(
            "[TriageAgent] alert=%d severity=%s fp=%s",
            alert.id, result["llm_severity"], result["llm_is_false_positive"],
        )
    except Exception as exc:
        result = {
            "llm_severity": None,
            "llm_is_false_positive": None,
            "llm_reasoning": f"Triage LLM call failed: {exc}",
            "llm_recommended_action": None,
            "mitre_technique": None,
        }
        logger.error("[TriageAgent] alert=%d error: %s", alert.id, exc)

    _save(alert, db, result)
    return result


def _save(alert, db: Session, result: dict) -> None:
    for key, value in result.items():
        setattr(alert, key, value)
    db.commit()
    db.refresh(alert)
