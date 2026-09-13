"""
agents/enrichment_agent.py
Agent 1 of 4 in the pipeline.

Responsibility: look up the alert's source_ip against VirusTotal to get a
threat-intel reputation score. Stores the result in:
  alert.threat_intel_score   (0–100, derived from VT engine detections, or None)
  alert.threat_intel_summary (human-readable description)

Graceful behaviour:
  - Private / RFC1918 IPs → skipped, marked "internal"
  - Missing VIRUSTOTAL_API_KEY → skipped, marked "no API key configured"
  - API failures (timeout, 429, 5xx) → retried with backoff, then falls back
    to None — does NOT block the rest of the pipeline

Requires:
  VIRUSTOTAL_API_KEY in environment / .env
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

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# IPs that should never be looked up externally
_SKIP_VALUES = {"unknown", "internal", "external", "multiple", "localhost", ""}


def _is_private_ip(ip_str: str) -> bool:
    """Returns True for RFC1918, loopback, link-local, and other non-routable ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _query_virustotal(ip: str, retries: int = 3, delay: int = 2) -> dict | None:
    """
    Calls VirusTotal's IP address report endpoint. Returns the parsed
    'data.attributes' dict on success, None on failure. Retry-with-backoff,
    same pattern used elsewhere in the pipeline.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_URL.format(ip=ip)

    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                return resp.json().get("data", {}).get("attributes", {})

            # Free tier: 4 req/min — if we hit the limit, retrying immediately is pointless
            if resp.status_code == 429:
                logger.warning("EnrichmentAgent: VirusTotal rate limit hit for %s — skipping", ip)
                return None

            if resp.status_code in (500, 502, 503) and attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                continue

            logger.warning(
                "EnrichmentAgent: VirusTotal returned %s for %s — skipping",
                resp.status_code, ip,
            )
            return None

        except requests.exceptions.RequestException as exc:
            if attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                continue
            logger.warning("EnrichmentAgent: network error querying VirusTotal for %s: %s", ip, exc)
            return None

    return None


def _score_from_stats(stats: dict) -> float:
    """
    Converts VirusTotal's last_analysis_stats (per-engine vote counts) into a
    single 0-100 score, same scale AbuseIPDB used, so nothing downstream
    (threatScoreBadge, severity thresholds) needs to change.

    malicious counts fully, suspicious counts at half weight.
    """
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    total_engines = malicious + suspicious + harmless + undetected + timeout
    if total_engines == 0:
        return 0.0

    weighted = malicious + (suspicious * 0.5)
    return round((weighted / total_engines) * 100, 1)


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
    if not VIRUSTOTAL_API_KEY:
        result = {
            "threat_intel_score": None,
            "threat_intel_summary": "VIRUSTOTAL_API_KEY not configured — enrichment skipped",
        }
        _save(alert, db, result)
        logger.info("[EnrichmentAgent] alert=%d skipped (no API key)", alert.id)
        return result

    # --- 3. Real lookup ---
    attrs = _query_virustotal(ip)

    if attrs is None:
        result = {
            "threat_intel_score": None,
            "threat_intel_summary": f"VirusTotal lookup failed for {ip} — pipeline continues without enrichment",
        }
        _save(alert, db, result)
        logger.warning("[EnrichmentAgent] alert=%d lookup failed for %s", alert.id, ip)
        return result

    stats = attrs.get("last_analysis_stats", {})
    score = _score_from_stats(stats)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    country = attrs.get("country", "??")
    as_owner = attrs.get("as_owner", "unknown network")
    reputation = attrs.get("reputation", 0)  # VT community score, can be negative

    if score >= 75:
        label = "HIGH RISK"
    elif score >= 25:
        label = "SUSPICIOUS"
    elif score > 0:
        label = "LOW RISK"
    else:
        label = "CLEAN"

    summary = (
        f"{label} — VirusTotal score {score:.0f}/100 | "
        f"{malicious} malicious / {suspicious} suspicious detection(s) | "
        f"Country: {country} | Network: {as_owner} | Community reputation: {reputation}"
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