import json
from datetime import datetime, timezone

AUDIT_LOG_PATH = "/data/audit.log"

def log_action(action, details="", ip=""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details,
        "ip": ip
    }
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def get_audit_log(limit=100):
    try:
        with open(AUDIT_LOG_PATH) as f:
            lines = f.readlines()
        entries = [json.loads(line) for line in lines if line.strip()]
        return list(reversed(entries[-limit:]))
    except FileNotFoundError:
        return []
