"""
agents/enrichment_agent.py
Agent 1 of 4 in the pipeline.

Responsibility: look up the alert's source_ip against AbuseIPDB to get a
threat-intel reputation score. Stores the result in:
  alert.threat_intel_score   (0–100 abuse confidence, or None)
  alert.threat_intel_summary (human-readable description)

Graceful behaviour:
  - Private / RFC1918 IPs → skipped, marked "internal"
  - Missing ABUSEIPDB_API_KEY → skipped, marked "no API key configured"
  - API failures (timeout, 429, 5xx) → retried with backoff, then falls back
    to None — does NOT block the rest of the pipeline

Requires:
  ABUSEIPDB_API_KEY in environment / .env
"""

import os
import ipaddress
import time
import logging
import requests
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# IPs that should never be looked up externally
_SKIP_VALUES = {"unknown", "internal", "external", "multiple", "localhost", ""}

# How long to look back for reports (max allowed on free tier)
_LOOKBACK_DAYS = 90


def _is_private_ip(ip_str: str) -> bool:
    """Returns True for RFC1918, loopback, link-local, and other non-routable ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _query_abuseipdb(ip: str, retries: int = 3, delay: int = 2) -> dict | None:
    """
    Calls AbuseIPDB check endpoint. Returns the parsed 'data' dict on success,
    None on failure. Uses retry-with-backoff identical to llm_triage.py pattern.
    """
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": _LOOKBACK_DAYS, "verbose": False}

    for attempt in range(retries):
        try:
            resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)

            if resp.status_code == 200:
                return resp.json().get("data", {})

            # If quota is exhausted, retrying is pointless
            if resp.status_code == 429:
                logger.warning("EnrichmentAgent: AbuseIPDB rate limit hit for %s — skipping", ip)
                return None

            if resp.status_code in (500, 502, 503) and attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                continue

            logger.warning(
                "EnrichmentAgent: AbuseIPDB returned %s for %s — skipping",
                resp.status_code, ip,
            )
            return None

        except requests.exceptions.RequestException as exc:
            if attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                continue
            logger.warning("EnrichmentAgent: network error querying AbuseIPDB for %s: %s", ip, exc)
            return None

    return None


def enrich_alert(alert, db: Session) -> dict:
    """
    Main entry point called by pipeline.py.

    Mutates alert.threat_intel_score and alert.threat_intel_summary in-place,
    then commits to the DB.

    Returns a dict with those two keys so pipeline.py can log the result.
    """
    ip = (alert.source_ip or "").strip()

    # --- 1. No-op cases ---
    if ip.lower() in _SKIP_VALUES:
        result = {
            "threat_intel_score": None,
            "threat_intel_summary": f"Enrichment skipped: source_ip is '{ip or 'empty'}'",
        }
        _save(alert, db, result)
        logger.info("[EnrichmentAgent] alert=%d skipped (empty/sentinel IP)", alert.id)
        return result

    if _is_private_ip(ip):
        result = {
            "threat_intel_score": None,
            "threat_intel_summary": f"Internal/private IP ({ip}) — no external threat-intel lookup performed",
        }
        _save(alert, db, result)
        logger.info("[EnrichmentAgent] alert=%d skipped (private IP %s)", alert.id, ip)
        return result

    # --- 2. No API key ---
    if not ABUSEIPDB_API_KEY:
        result = {
            "threat_intel_score": None,
            "threat_intel_summary": "ABUSEIPDB_API_KEY not configured — enrichment skipped",
        }
        _save(alert, db, result)
        logger.info("[EnrichmentAgent] alert=%d skipped (no API key)", alert.id)
        return result

    # --- 3. Real lookup ---
    data = _query_abuseipdb(ip)

    if data is None:
        result = {
            "threat_intel_score": None,
            "threat_intel_summary": f"AbuseIPDB lookup failed for {ip} — pipeline continues without enrichment",
        }
        _save(alert, db, result)
        logger.warning("[EnrichmentAgent] alert=%d lookup failed for %s", alert.id, ip)
        return result

    score = float(data.get("abuseConfidenceScore", 0))
    reports = data.get("totalReports", 0)
    country = data.get("countryCode", "??")
    isp = data.get("isp", "unknown ISP")
    usage = data.get("usageType", "unknown usage")

    if score >= 75:
        label = "HIGH RISK"
    elif score >= 25:
        label = "SUSPICIOUS"
    elif score > 0:
        label = "LOW RISK"
    else:
        label = "CLEAN"

    summary = (
        f"{label} — AbuseIPDB score {score:.0f}/100 | "
        f"{reports} report(s) | Country: {country} | ISP: {isp} | Usage: {usage}"
    )

    result = {"threat_intel_score": score, "threat_intel_summary": summary}
    _save(alert, db, result)
    logger.info(
        "[EnrichmentAgent] alert=%d ip=%s score=%.0f label=%s",
        alert.id, ip, score, label,
    )
    return result


def _save(alert, db: Session, result: dict) -> None:
    alert.threat_intel_score = result["threat_intel_score"]
    alert.threat_intel_summary = result["threat_intel_summary"]
    db.commit()
    db.refresh(alert)
