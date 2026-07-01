import json
import os
from datetime import datetime, timezone
from functools import wraps
from flask import session, redirect, url_for, request
from werkzeug.security import check_password_hash

MASTER_PASSWORD_HASH = "scrypt:32768:8:1$g87GM7bgGlfQCblV$6ba0d1baaa8ed247017c4f09ef57cb8369b955118218cd9e7da7fc1be1a68a5d67b6ac2488e899b74f632126d9b57075e174ae08c9acb9ef288f618670fc433a"
STATS_FILE = "/data/stats.json"

def master_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("master_auth"):
            return redirect(url_for("master_login"))
        return f(*args, **kwargs)
    return decorated

def track_visit(path):
    stats = _load_stats()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    stats.setdefault("visits", {})
    stats["visits"].setdefault(today, {})
    stats["visits"][today][path] = stats["visits"][today].get(path, 0) + 1
    stats["total_visits"] = stats.get("total_visits", 0) + 1
    _save_stats(stats)

def get_stats():
    return _load_stats()

def _load_stats():
    try:
        with open(STATS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"total_visits": 0, "visits": {}}

def _save_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=2)
