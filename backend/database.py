"""
database.py — SQLite setup for Cyber Ultron v2
Tables: users, logs, alerts, blocked_ips
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "logs.db")


def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ip             TEXT NOT NULL,
            requests       INTEGER NOT NULL,
            login_attempts INTEGER NOT NULL,
            timestamp      TEXT NOT NULL,
            source         TEXT DEFAULT 'simulated'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT NOT NULL,
            reason    TEXT NOT NULL,
            severity  TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT UNIQUE NOT NULL,
            blocked_at TEXT NOT NULL
        )
    """)

    # Seed default admin user (password: admin123)
    c.execute("SELECT id FROM users WHERE username = 'admin'")
    if not c.fetchone():
        # bcrypt hash of 'admin123'
        from backend.auth import hash_password
        c.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", hash_password("admin123"))
        )

    conn.commit()
    conn.close()
    print("[DB] Initialized successfully.")
