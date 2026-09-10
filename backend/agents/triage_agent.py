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

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
)

# ---------------------------------------------------------------------------
# Shared Gemini helper — imported by correlation_agent and response_agent too
# ---------------------------------------------------------------------------

def call_gemini(prompt: str, retries: int = 3, delay: int = 3) -> str:
    """
    Calls the Gemini API with retry-with-backoff for transient errors.
    Raises RuntimeError if all attempts fail.
    """
    # Rebuild URL each call in case GEMINI_API_KEY was set after module load
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    for attempt in range(retries):
        response = requests.post(url, json=payload, timeout=30)

        if response.status_code == 200:
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

        # Fail fast on quota exhaustion — retrying won't help
        if response.status_code == 429 and "Quota" in response.text:
            raise RuntimeError(f"Gemini quota exhausted: {response.text}")

        if response.status_code in (429, 500, 502, 503) and attempt < retries - 1:
            time.sleep(delay * (attempt + 1))
            continue

        raise RuntimeError(f"Gemini API error {response.status_code}: {response.text}")

    raise RuntimeError("Gemini API failed after all retries")


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

TRIAGE_PROMPT = """\
You are a SOC (Security Operations Center) analyst assistant.
Analyze the following security alert — including any threat-intelligence data about
the source IP — and respond in STRICT JSON only. No markdown, no commentary, no code
fences. Use exactly this schema:

{{
  "severity": "Low" | "Medium" | "High" | "Critical",
  "is_false_positive": true | false,
  "reasoning": "one or two sentence explanation of your severity call",
  "recommended_action": "one concrete next step an analyst should take"
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
    )

    try:
        raw = call_gemini(prompt)
        parsed = json.loads(_clean_json(raw))
        result = {
            "llm_severity": parsed.get("severity"),
            "llm_is_false_positive": parsed.get("is_false_positive"),
            "llm_reasoning": parsed.get("reasoning"),
            "llm_recommended_action": parsed.get("recommended_action"),
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
        }
        logger.error("[TriageAgent] alert=%d error: %s", alert.id, exc)

    _save(alert, db, result)
    return result


def _save(alert, db: Session, result: dict) -> None:
    for key, value in result.items():
        setattr(alert, key, value)
    db.commit()
    db.refresh(alert)
