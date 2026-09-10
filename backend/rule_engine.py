"""
rule_engine.py
The "dumb" baseline your LLM triage gets compared against in the demo/README findings.
Pure keyword/type matching — no ML, no API calls, deterministic and instant.
This is intentionally simple: the point is to show the LLM adds value on top of it,
not to build a competitive rule engine.
"""

# alert_type -> (severity, is_false_positive_by_default)
# tune this table as you add more synthetic alert types
SEVERITY_RULES = {
    "brute force":          ("High", False),
    "port scan":            ("Low", False),
    "malware beacon":       ("Critical", False),
    "ddos":                 ("Critical", False),
    "data exfiltration":    ("Critical", False),
    "privilege escalation": ("High", False),
    "failed login":         ("Low", True),        # usually noise unless repeated
    "policy violation":     ("Medium", False),
    "unusual login time":   ("Medium", True),      # often a false positive (remote worker etc.)
}

DEFAULT_SEVERITY = "Medium"


def rule_based_triage(alert_type: str) -> dict:
    """
    Looks up a severity + false-positive guess purely from the alert_type string.
    Case-insensitive, falls back to a default when the type isn't in the table.
    """
    key = alert_type.strip().lower()
    severity, is_fp = SEVERITY_RULES.get(key, (DEFAULT_SEVERITY, False))
    return {
        "rule_severity": severity,
        "rule_is_false_positive": is_fp,
    }
