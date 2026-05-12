"""
main.py — Cyber Ultron v2 FastAPI Backend
All endpoints with JWT protection, file upload, and AI detection.
"""
import sys
import os
import io
import json
import csv
from contextlib import asynccontextmanager
from datetime import timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.database import init_db, get_connection
from backend.auth import (
    verify_password, create_access_token, get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from backend.schemas import (
    LoginRequest, LoginResponse, LogEntry,
    BlockIPRequest, DetectionResult, APIResponse
)
from backend.model import predict, get_anomaly_scores, classify_severity, load_model
from backend.utils import (
    utc_now, is_ip_blocked, block_ip, create_alert,
    build_alert_reason, get_recent_logs, get_all_alerts, get_all_blocked
)

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    load_model()
    print("[Startup] Cyber Ultron v2 is ONLINE.")
    yield


app = FastAPI(title="Cyber Ultron API v2", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Static file serving ────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def root():
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"))

@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))

@app.get("/dashboard.js", include_in_schema=False)
def js(): return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.js"))

@app.get("/styles.css", include_in_schema=False)
def css(): return FileResponse(os.path.join(FRONTEND_DIR, "styles.css"))

@app.get("/login.html", include_in_schema=False)
def login_page(): return FileResponse(os.path.join(FRONTEND_DIR, "login.html"))

@app.get("/dashboard.html", include_in_schema=False)
def dash_page(): return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))


# ── Auth ───────────────────────────────────────────────────────────────────────
@app.post("/login", response_model=LoginResponse, tags=["Auth"])
def login(req: LoginRequest):
    """Validate credentials and return JWT token."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone()
    conn.close()
    if not row or not verify_password(req.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = create_access_token(
        {"sub": req.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return LoginResponse(access_token=token, username=req.username)


# ── Logs ───────────────────────────────────────────────────────────────────────
@app.post("/logs", response_model=APIResponse, tags=["Logs"])
def ingest_log(log: LogEntry, user: str = Depends(get_current_user)):
    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO logs (ip, requests, login_attempts, timestamp, source) VALUES (?,?,?,?,?)",
            (log.ip, log.requests, log.login_attempts, log.timestamp, log.source or "simulated")
        )
        conn.commit()
        return APIResponse(success=True, message="Log stored.", data={"log_id": cur.lastrowid})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/logs", tags=["Logs"])
def get_logs(limit: int = 200, user: str = Depends(get_current_user)):
    logs = get_recent_logs(limit=limit)
    return {"success": True, "count": len(logs), "logs": logs}


# ── Upload ─────────────────────────────────────────────────────────────────────
@app.post("/upload", tags=["Upload"])
async def upload_file(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    """
    Upload a JSON or CSV file containing logs.
    JSON: list of {ip, requests, login_attempts, timestamp}
    CSV:  columns ip,requests,login_attempts,timestamp
    """
    content = await file.read()
    filename = file.filename.lower()
    entries = []

    try:
        if filename.endswith(".json"):
            data = json.loads(content.decode("utf-8"))
            if isinstance(data, list):
                entries = data
            else:
                raise ValueError("JSON must be a list of log objects.")
        elif filename.endswith(".csv"):
            reader = csv.DictReader(io.StringIO(content.decode("utf-8")))
            for row in reader:
                entries.append({
                    "ip": row.get("ip", "0.0.0.0"),
                    "requests": int(row.get("requests", 0)),
                    "login_attempts": int(row.get("login_attempts", 0)),
                    "timestamp": row.get("timestamp", utc_now()),
                })
        else:
            raise HTTPException(status_code=400, detail="Only .json or .csv files are supported.")
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"File parse error: {str(e)}")

    if not entries:
        raise HTTPException(status_code=400, detail="File contains no valid log entries.")

    conn = get_connection()
    inserted = 0
    for e in entries:
        try:
            conn.execute(
                "INSERT INTO logs (ip, requests, login_attempts, timestamp, source) VALUES (?,?,?,?,?)",
                (
                    str(e.get("ip", "0.0.0.0")),
                    int(e.get("requests", 0)),
                    int(e.get("login_attempts", 0)),
                    str(e.get("timestamp", utc_now())),
                    "uploaded"
                )
            )
            inserted += 1
        except Exception:
            pass
    conn.commit()
    conn.close()

    return {"success": True, "message": f"Uploaded {inserted} log entries.", "count": inserted}


# ── Detection ──────────────────────────────────────────────────────────────────
@app.post("/detect", response_model=DetectionResult, tags=["Detection"])
def run_detection(limit: int = 200, user: str = Depends(get_current_user)):
    logs = get_recent_logs(limit=limit)
    if not logs:
        raise HTTPException(status_code=404, detail="No logs to analyze.")

    features = [[l["requests"], l["login_attempts"]] for l in logs]
    predictions = predict(features)
    scores = get_anomaly_scores(features)

    anomalies = 0
    blocked = 0
    details = []

    for log, pred, score in zip(logs, predictions, scores):
        if pred == 1:
            anomalies += 1
            sev = classify_severity(log["requests"], log["login_attempts"], score)
            reason = build_alert_reason(log["requests"], log["login_attempts"])
            create_alert(log["ip"], reason, sev)
            newly = block_ip(log["ip"])
            if newly: blocked += 1
            details.append({
                "ip": log["ip"],
                "requests": log["requests"],
                "login_attempts": log["login_attempts"],
                "anomaly_score": round(score, 4),
                "severity": sev,
                "reason": reason,
                "blocked": newly
            })

    return DetectionResult(
        total_logs_analyzed=len(logs),
        anomalies_detected=anomalies,
        blocked_ips_added=blocked,
        details=details
    )


# ── Alerts ─────────────────────────────────────────────────────────────────────
@app.get("/alerts", tags=["Alerts"])
def get_alerts(user: str = Depends(get_current_user)):
    alerts = get_all_alerts()
    return {"success": True, "count": len(alerts), "alerts": alerts}


# ── Blocked IPs ────────────────────────────────────────────────────────────────
@app.post("/block-ip", response_model=APIResponse, tags=["Blocking"])
def manual_block(req: BlockIPRequest, user: str = Depends(get_current_user)):
    if is_ip_blocked(req.ip):
        return APIResponse(success=False, message=f"{req.ip} already blocked.", data={"ip": req.ip})
    block_ip(req.ip)
    create_alert(req.ip, req.reason or "Manually blocked", "MEDIUM")
    return APIResponse(success=True, message=f"{req.ip} blocked.", data={"ip": req.ip})


@app.get("/blocked", tags=["Blocking"])
def get_blocked(user: str = Depends(get_current_user)):
    return {"success": True, "blocked_ips": get_all_blocked()}


@app.delete("/blocked/{ip}", response_model=APIResponse, tags=["Blocking"])
def unblock(ip: str, user: str = Depends(get_current_user)):
    conn = get_connection()
    affected = conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,)).rowcount
    conn.commit()
    conn.close()
    if not affected:
        raise HTTPException(status_code=404, detail=f"{ip} not in blocked list.")
    return APIResponse(success=True, message=f"{ip} unblocked.", data={"ip": ip})


# ── Stats ──────────────────────────────────────────────────────────────────────
@app.get("/stats", tags=["Dashboard"])
def get_stats(user: str = Depends(get_current_user)):
    conn = get_connection()
    total_logs    = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    total_blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    recent        = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE timestamp >= datetime('now','-5 minutes')"
    ).fetchone()[0]
    conn.close()
    return {
        "success": True,
        "status": "THREAT_DETECTED" if recent > 0 else "NORMAL",
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "total_blocked": total_blocked,
        "recent_alerts": recent
    }
