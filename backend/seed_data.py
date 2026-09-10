"""
seed_data.py
Populates the DB with ~25 synthetic alerts covering a realistic mix of severities
and a few genuine false positives — enough to demo triage and compute the
rule-vs-LLM comparison stats for your README "Findings" section later.

Run once: python seed_data.py
"""

from database import SessionLocal, engine, Base
from models import Alert

# alert_type, source_ip, dest_ip, raw_log
SAMPLE_ALERTS = [
    ("Brute Force", "203.0.113.5", "10.0.0.12", "47 failed SSH login attempts for user 'admin' in 60 seconds"),
    ("Port Scan", "198.51.100.23", "10.0.0.0/24", "Sequential SYN packets across ports 1-1024 detected from single host"),
    ("Malware Beacon", "10.0.0.44", "185.220.101.7", "Periodic outbound HTTPS beacon every 60s to known C2 IP range"),
    ("DDoS", "multiple", "10.0.0.1", "UDP flood, 4.2M packets/sec sustained for 3 minutes against public-facing endpoint"),
    ("Data Exfiltration", "10.0.0.19", "external", "2.3GB outbound transfer to unrecognized cloud storage endpoint at 3:14 AM"),
    ("Privilege Escalation", "10.0.0.19", "10.0.0.19", "Local user added to Domain Admins group outside change window"),
    ("Failed Login", "10.0.0.88", "10.0.0.12", "3 failed login attempts, user then succeeded on 4th try"),
    ("Policy Violation", "10.0.0.31", "external", "USB mass storage device connected on finance workstation"),
    ("Unusual Login Time", "10.0.0.52", "10.0.0.12", "VPN login from usual employee IP at 2:47 AM local time"),
    ("Port Scan", "192.168.1.200", "10.0.0.0/24", "Single port (443) probed across subnet — likely internal vuln scanner"),
    ("Brute Force", "203.0.113.88", "10.0.0.15", "RDP login failures, 12 attempts, single source IP, stopped after lockout"),
    ("Malware Beacon", "10.0.0.61", "91.203.5.44", "Irregular DNS queries to freshly-registered domain, high entropy subdomain"),
    ("Failed Login", "10.0.0.77", "10.0.0.12", "1 failed login, password typo pattern, succeeded immediately after"),
    ("Data Exfiltration", "10.0.0.9", "external", "Large ZIP archive uploaded to personal Gmail via webmail"),
    ("Policy Violation", "10.0.0.40", "internal", "Unauthorized software install detected: torrent client"),
    ("DDoS", "multiple", "10.0.0.3", "SYN flood against internal load balancer, mitigated by existing rate limiting"),
    ("Unusual Login Time", "10.0.0.66", "10.0.0.12", "Login from known device, known IP, but 40 mins outside usual pattern"),
    ("Privilege Escalation", "10.0.0.22", "10.0.0.22", "Sudo privileges requested and granted via standard change-ticket process"),
    ("Port Scan", "203.0.113.201", "10.0.0.0/24", "Full port range scanned from external IP, no prior contact with network"),
    ("Brute Force", "198.51.100.9", "10.0.0.18", "200+ failed logins across 15 usernames in 2 minutes — password spraying pattern"),
    ("Malware Beacon", "10.0.0.5", "5.188.10.22", "Known-malicious IP contacted once, connection immediately reset by firewall"),
    ("Failed Login", "10.0.0.100", "10.0.0.12", "Single failed login, MFA prompt not completed, session expired normally"),
    ("Data Exfiltration", "10.0.0.14", "external", "Scheduled nightly backup job to approved offsite backup provider"),
    ("Policy Violation", "10.0.0.28", "internal", "VPN split-tunneling enabled, against acceptable use policy"),
    ("Unusual Login Time", "10.0.0.71", "10.0.0.12", "Login at 4 AM from IP geolocated to different country than employee's usual location"),
]


def seed():
    Base.metadata.create_all(bind=engine)  # creates tables if they don't exist yet
    db = SessionLocal()

    if db.query(Alert).count() > 0:
        print("Alerts already exist — skipping seed. Delete soc_copilot.db to reseed from scratch.")
        db.close()
        return

    for alert_type, source_ip, dest_ip, raw_log in SAMPLE_ALERTS:
        db.add(Alert(
            alert_type=alert_type,
            source_ip=source_ip,
            dest_ip=dest_ip,
            raw_log=raw_log,
        ))

    db.commit()
    print(f"Seeded {len(SAMPLE_ALERTS)} alerts into soc_copilot.db")
    db.close()


if __name__ == "__main__":
    seed()
