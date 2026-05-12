"""
utils.py — Shared helpers for Cyber Ultron v2
"""
from datetime import datetime, timezone
from backend.database import get_connection
import sqlite3


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def is_ip_blocked(ip: str) -> bool:
    conn = get_connection()
    row = conn.execute("SELECT id FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
    conn.close()
    return row is not None


def block_ip(ip: str) -> bool:
    if is_ip_blocked(ip):
        return False
    conn = get_connection()
    try:
        conn.execute("INSERT INTO blocked_ips (ip, blocked_at) VALUES (?,?)", (ip, utc_now()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def create_alert(ip: str, reason: str, severity: str) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO alerts (ip, reason, severity, timestamp) VALUES (?,?,?,?)",
        (ip, reason, severity, utc_now())
    )
    aid = cur.lastrowid
    conn.commit()
    conn.close()
    return aid


def build_alert_reason(requests: int, login_attempts: int) -> str:
    parts = []
    if requests > 400:
        parts.append(f"Extreme request rate ({requests}/min)")
    elif requests > 200:
        parts.append(f"High request rate ({requests}/min)")
    if login_attempts > 20:
        parts.append(f"Brute force ({login_attempts} attempts)")
    elif login_attempts > 10:
        parts.append(f"Excessive logins ({login_attempts})")
    return "; ".join(parts) if parts else "Statistical anomaly (ML model)"


def get_recent_logs(limit=200):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_alerts():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_blocked():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]
