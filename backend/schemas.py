"""
schemas.py — Pydantic models for Cyber Ultron v2
"""
from pydantic import BaseModel, Field
from typing import Optional, List


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class LogEntry(BaseModel):
    ip: str
    requests: int = Field(..., ge=0)
    login_attempts: int = Field(..., ge=0)
    timestamp: str
    source: Optional[str] = "simulated"


class AlertResponse(BaseModel):
    id: int
    ip: str
    reason: str
    severity: str
    timestamp: str


class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manually blocked by admin"


class DetectionResult(BaseModel):
    total_logs_analyzed: int
    anomalies_detected: int
    blocked_ips_added: int
    details: list


class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None
