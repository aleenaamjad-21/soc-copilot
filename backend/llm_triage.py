"""
llm_triage.py
Sends an alert to Gemini and gets back: severity, false-positive flag, reasoning,
and a recommended action — this is the "AI analyst" half of the demo.

Needs a GEMINI_API_KEY environment variable (get one free at aistudio.google.com,
same as you used for ReconBoard).

Set it before running the server:
    export GEMINI_API_KEY="your-key-here"        (Mac/Linux)
    set GEMINI_API_KEY=your-key-here              (Windows cmd)
"""

import os
import json
import time
import requests
from dotenv import load_dotenv

load_dotenv()  # reads the .env file and loads it into os.environ

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-3.6-flash"  # matches the model you're already using in ReconBoard
GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
)

TRIAGE_PROMPT_TEMPLATE = """You are a SOC (Security Operations Center) analyst assistant.
Analyze the following security alert and respond in STRICT JSON only — no markdown, no
commentary, no code fences. Use exactly this schema:

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
"""


def _call_gemini(prompt: str, retries: int = 3, delay: int = 3) -> str:
    """
    Calls the Gemini API with basic retry-with-backoff for transient errors
    (same pattern you used in ReconBoard's FindingTriageService).
    """
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    for attempt in range(retries):
        response = requests.post(GEMINI_URL, json=payload, timeout=30)

        if response.status_code == 200:
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

        # retry on rate-limit / server errors, fail fast on client errors (e.g. bad key)
        if response.status_code in (429, 500, 502, 503) and attempt < retries - 1:
            time.sleep(delay)
            continue

        raise RuntimeError(f"Gemini API error {response.status_code}: {response.text}")

    raise RuntimeError("Gemini API failed after retries")


def llm_based_triage(alert_type: str, source_ip: str, dest_ip: str, raw_log: str) -> dict:
    """
    Runs one alert through Gemini and returns a dict matching the Alert model's
    llm_* columns. Falls back to a clearly-marked error result instead of crashing
    the request if the API call fails (e.g. no API key set yet).
    """
    if not GEMINI_API_KEY:
        return {
            "llm_severity": None,
            "llm_is_false_positive": None,
            "llm_reasoning": "GEMINI_API_KEY not set — add it to your environment to enable AI triage.",
            "llm_recommended_action": None,
        }

    prompt = TRIAGE_PROMPT_TEMPLATE.format(
        alert_type=alert_type,
        source_ip=source_ip or "unknown",
        dest_ip=dest_ip or "unknown",
        raw_log=raw_log,
    )

    try:
        raw_text = _call_gemini(prompt)
        # strip accidental markdown fences if the model adds them anyway
        cleaned = raw_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(cleaned)

        return {
            "llm_severity": parsed.get("severity"),
            "llm_is_false_positive": parsed.get("is_false_positive"),
            "llm_reasoning": parsed.get("reasoning"),
            "llm_recommended_action": parsed.get("recommended_action"),
        }
    except Exception as e:
        return {
            "llm_severity": None,
            "llm_is_false_positive": None,
            "llm_reasoning": f"LLM triage failed: {e}",
            "llm_recommended_action": None,
        }
