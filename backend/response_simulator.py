"""
response_simulator.py
Simulated SOAR-style automated response engine.

SAFETY CONTRACT:
  This module operates ENTIRELY against an in-memory Python object that
  represents a fictional firewall / endpoint management system.
  It touches NO real network devices, NO real operating system firewall rules,
  and NO external services of any kind.
  The simulated state resets to empty every time the server restarts.

Usage:
  1. An analyst calls POST /incidents/{id}/approve-response
  2. main.py calls SimulatedFirewall.execute_playbook()
  3. Each step is dispatched to the appropriate handler
  4. Every action is written to the AuditLog table

State is intentionally module-level (singleton) so all requests in a server
lifetime share the same simulated environment — makes the demo interesting.
"""

import json
import logging
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from models import AuditLog, Alert, Incident

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Simulated infrastructure state (in-memory, non-persistent, safe by design)
# ---------------------------------------------------------------------------

class SimulatedFirewall:
    """
    A fictional network security appliance living entirely in Python memory.
    Its state is printed in GET /simulator-state so the frontend can show it.
    """

    def __init__(self):
        self.blocked_ips: set[str] = set()
        self.isolated_hosts: set[str] = set()
        self.forensics_jobs: list[dict] = []          # {host, started_at}
        self.reset_credentials: list[dict] = []       # {account, reset_at}
        self.analyst_notifications: list[dict] = []   # {message, sent_at}
        self.action_log: list[str] = []               # human-readable chronological log

    # --- Action handlers ---

    def block_ip(self, ip: str, description: str) -> str:
        if ip in self.blocked_ips:
            msg = f"[SIMULATED] IP {ip} was already in blocklist — no change"
        else:
            self.blocked_ips.add(ip)
            msg = f"[SIMULATED] IP {ip} added to perimeter blocklist"
        self.action_log.append(msg)
        logger.info(msg)
        return msg

    def isolate_host(self, host: str, description: str) -> str:
        if host in self.isolated_hosts:
            msg = f"[SIMULATED] Host {host} already isolated — no change"
        else:
            self.isolated_hosts.add(host)
            msg = f"[SIMULATED] Host {host} quarantined from network"
        self.action_log.append(msg)
        logger.info(msg)
        return msg

    def notify_analyst(self, description: str) -> str:
        notification = {"message": description, "sent_at": datetime.utcnow().isoformat()}
        self.analyst_notifications.append(notification)
        msg = f"[SIMULATED] Analyst notification sent: {description}"
        self.action_log.append(msg)
        logger.info(msg)
        return msg

    def collect_forensics(self, host: str, description: str) -> str:
        job = {"host": host, "started_at": datetime.utcnow().isoformat(), "description": description}
        self.forensics_jobs.append(job)
        msg = f"[SIMULATED] Forensics collection started on {host}"
        self.action_log.append(msg)
        logger.info(msg)
        return msg

    def reset_credentials_action(self, account: str, description: str) -> str:
        entry = {"account": account, "reset_at": datetime.utcnow().isoformat()}
        self.reset_credentials.append(entry)
        msg = f"[SIMULATED] Credentials reset for account: {account}"
        self.action_log.append(msg)
        logger.info(msg)
        return msg

    def escalate_to_incident(self, description: str) -> str:
        msg = f"[SIMULATED] Escalated to incident tracker: {description}"
        self.action_log.append(msg)
        logger.info(msg)
        return msg

    def no_action_needed(self, description: str) -> str:
        msg = f"[SIMULATED] No action required — {description}"
        self.action_log.append(msg)
        logger.info(msg)
        return msg

    def get_state(self) -> dict:
        """Returns a JSON-serialisable snapshot of the current simulated state."""
        return {
            "blocked_ips": sorted(self.blocked_ips),
            "isolated_hosts": sorted(self.isolated_hosts),
            "forensics_jobs": self.forensics_jobs,
            "reset_credentials": self.reset_credentials,
            "analyst_notifications": self.analyst_notifications,
            "action_log": self.action_log[-50:],  # last 50 entries for the UI
        }

    # --- Main dispatch method ---

    def execute_playbook(
        self,
        playbook: dict,
        alert_id: Optional[int],
        incident_id: Optional[int],
        db: Session,
    ) -> list[dict]:
        """
        Iterates over playbook steps, dispatches each to the correct handler,
        and writes an AuditLog row for every action.

        Returns a list of audit log dicts for the API response.
        """
        steps = playbook.get("steps", [])
        audit_entries = []

        for step in steps:
            action = step.get("action", "notify_analyst")
            description = step.get("description", "")

            # Dispatch to the appropriate handler
            outcome_msg = self._dispatch(action, description, alert_id, incident_id)

            # Write AuditLog row
            log_entry = AuditLog(
                alert_id=alert_id,
                incident_id=incident_id,
                action=action,
                description=description,
                actor="AI",
                outcome="simulated",
            )
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)

            audit_entries.append({
                "id": log_entry.id,
                "action": action,
                "description": description,
                "outcome": "simulated",
                "actor": "AI",
                "timestamp": log_entry.timestamp.isoformat(),
            })

        return audit_entries

    def _dispatch(
        self,
        action: str,
        description: str,
        alert_id: Optional[int],
        incident_id: Optional[int],
    ) -> str:
        """Routes an action type to the correct handler. Falls back to notify_analyst."""
        # Extract an IP or host from the description for context where needed
        # (best-effort — the description is free text from the LLM)
        target = _extract_target(description)

        if action == "block_ip":
            return self.block_ip(target or "unknown-ip", description)
        elif action == "isolate_host":
            return self.isolate_host(target or "unknown-host", description)
        elif action == "notify_analyst":
            return self.notify_analyst(description)
        elif action == "collect_forensics":
            return self.collect_forensics(target or "unknown-host", description)
        elif action == "reset_credentials":
            return self.reset_credentials_action(target or "unknown-account", description)
        elif action == "escalate_to_incident":
            return self.escalate_to_incident(description)
        elif action == "no_action_needed":
            return self.no_action_needed(description)
        else:
            return self.notify_analyst(f"Unknown action '{action}': {description}")


# ---------------------------------------------------------------------------
# Module-level singleton — shared across all requests in a server lifetime
# ---------------------------------------------------------------------------
firewall = SimulatedFirewall()


# ---------------------------------------------------------------------------
# Approval + execution entry point (called by main.py)
# ---------------------------------------------------------------------------

def approve_and_execute(
    incident: Incident,
    db: Session,
) -> list[dict]:
    """
    Called when an analyst approves a response via POST /incidents/{id}/approve-response.

    Steps:
      1. Write analyst-approval AuditLog entry
      2. Set incident.response_status = "approved"
      3. Execute each playbook step via the simulated firewall
      4. Set incident.response_status = "executed"
      5. Also update alert.pipeline_playbook_status for each linked alert

    Returns the list of audit entries created.
    """
    if not incident.playbook:
        raise ValueError(f"Incident {incident.id} has no playbook to execute")

    if incident.response_status == "executed":
        raise ValueError(f"Incident {incident.id} response has already been executed")

    playbook = json.loads(incident.playbook)

    # --- Analyst approval audit entry ---
    approval_log = AuditLog(
        incident_id=incident.id,
        action="approve_response",
        description=f"Analyst approved response playbook for incident #{incident.id}",
        actor="analyst",
        outcome="approved",
    )
    db.add(approval_log)
    incident.response_status = "approved"
    db.commit()

    logger.info("[ResponseSimulator] incident=%d approved by analyst — executing playbook", incident.id)

    # --- Execute each step ---
    audit_entries = firewall.execute_playbook(
        playbook=playbook,
        alert_id=None,      # incident-level action
        incident_id=incident.id,
        db=db,
    )

    # --- Mark incident and its alerts as executed ---
    incident.response_status = "executed"
    for alert in incident.alerts:
        alert.pipeline_playbook_status = "executed"
    db.commit()

    logger.info(
        "[ResponseSimulator] incident=%d executed %d action(s)",
        incident.id, len(audit_entries),
    )

    # Prepend the approval entry to the returned list
    audit_entries.insert(0, {
        "id": approval_log.id,
        "action": "approve_response",
        "description": approval_log.description,
        "actor": "analyst",
        "outcome": "approved",
        "timestamp": approval_log.timestamp.isoformat(),
    })

    return audit_entries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_target(text: str) -> Optional[str]:
    """
    Best-effort extraction of an IP address or hostname from a description string.
    Used to give the simulated handlers something concrete to log.
    """
    import re
    # Try IP first
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    if ip_match:
        return ip_match.group(1)
    # Try hostname-like token (word before space or end)
    host_match = re.search(r"\b([a-zA-Z0-9][a-zA-Z0-9\-]{2,}(?:\.[a-zA-Z]{2,})?)\b", text)
    if host_match:
        return host_match.group(1)
    return None
