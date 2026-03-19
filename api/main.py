"""
Anthra Security Platform API
Multi-tenant security monitoring and log aggregation SaaS
"""

import logging
import os
import re
import secrets
import sqlite3
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
import psycopg2
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# =============================================================================
# Configuration
# =============================================================================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "anthra")
DB_USER = os.getenv("DB_USER", "anthra")
DB_PASSWORD = os.getenv("DB_PASSWORD")  # Required — no fallback
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
JWT_SECRET = os.getenv("JWT_SECRET")  # Required in production
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "8"))

# Generate a runtime secret if JWT_SECRET not set (dev only — logs a warning)
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)
    logging.warning("JWT_SECRET not set — using ephemeral key. Sessions won't survive restarts.")

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
MAX_LOGS_LIMIT = 500

# =============================================================================
# Structured Logging (no sensitive data)
# =============================================================================
logging.basicConfig(
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    level=logging.INFO,
)
logger = logging.getLogger("anthra-api")

# =============================================================================
# Rate Limiter — in-memory, per-IP
# =============================================================================
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_LOGIN = 5       # max attempts
RATE_LIMIT_WINDOW = 300    # per 5 minutes
RATE_LIMIT_GENERAL = 100   # general endpoints
RATE_LIMIT_GENERAL_WINDOW = 60


def _check_rate_limit(key: str, max_attempts: int, window_seconds: int) -> bool:
    """Return True if rate limit exceeded."""
    now = time.monotonic()
    attempts = _rate_store[key]
    # Prune old entries
    _rate_store[key] = [t for t in attempts if now - t < window_seconds]
    if len(_rate_store[key]) >= max_attempts:
        return True
    _rate_store[key].append(now)
    return False


app = FastAPI(
    title="Anthra Security Platform",
    version="1.2.0",
    description="Cloud-native security monitoring and threat detection",
    docs_url=None,    # Disable Swagger in production
    redoc_url=None,   # Disable ReDoc in production
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# =============================================================================
# Database Connection
# =============================================================================
def get_db():
    """Get database connection with fallback to SQLite for demos."""
    try:
        return psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )
    except Exception:
        logger.warning("PostgreSQL unavailable — using SQLite fallback")
        db_path = os.path.join(tempfile.gettempdir(), "anthra.db")
        conn = sqlite3.connect(db_path)
        _init_sqlite(conn)
        return conn


def _init_sqlite(conn):
    """Initialize SQLite schema for demo mode."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT,
            source TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'viewer',
            tenant_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed demo user with bcrypt hash
    try:
        hashed = bcrypt.hashpw(b"Change-Me-1!", bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO users (username, password_hash, email, role, tenant_id) VALUES (?, ?, ?, ?, ?)",
            ("admin", hashed, "admin@anthra.io", "admin", "tenant-1"),
        )
        for i in range(1, 4):
            conn.execute(
                "INSERT INTO logs (tenant_id, level, message, source) VALUES (?, ?, ?, ?)",
                (f"tenant-{i}", "INFO", f"System startup for tenant-{i}", "api"),
            )
        conn.commit()
    except Exception:
        pass


# =============================================================================
# JWT Helpers
# =============================================================================
def _create_token(user_id: int, username: str, role: str, tenant_id: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "tenant_id": tenant_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# =============================================================================
# Auth Dependency — extracts and validates JWT from Authorization header
# =============================================================================
async def require_auth(request: Request) -> dict:
    """Dependency that enforces authentication on protected endpoints."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header[7:]
    return _decode_token(token)


# =============================================================================
# Request/Response Models
# =============================================================================
PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*\-]).{10,}$")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(min_length=10, max_length=128)
    email: str = Field(max_length=254)
    tenant_id: str = Field(min_length=1, max_length=64)


class AlertRequest(BaseModel):
    severity: str = Field(min_length=1, max_length=16)
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(max_length=4096)


class LogRequest(BaseModel):
    level: str = Field(min_length=1, max_length=16)
    message: str = Field(max_length=4096)
    source: str = Field(min_length=1, max_length=128)


# =============================================================================
# Health Check (unauthenticated — needed for K8s probes)
# =============================================================================
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "anthra-api",
        "version": "1.2.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# Authentication Endpoints
# =============================================================================
@app.post("/api/auth/login")
async def login(request: LoginRequest, req: Request):
    client_ip = req.client.host if req.client else "unknown"

    # Rate limit: 5 login attempts per 5 minutes per IP
    if _check_rate_limit(f"login:{client_ip}", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW):
        logger.warning("login rate-limited ip=%s", client_ip)
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password_hash, role, tenant_id FROM users WHERE username = ?",
        (request.username,),
    )
    user = cur.fetchone()
    conn.close()

    if not user:
        # Constant-time comparison to avoid timing attacks
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        logger.info("login failed user=%s reason=not_found", request.username)
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})

    stored_hash = user[2].encode() if isinstance(user[2], str) else user[2]
    if not bcrypt.checkpw(request.password.encode(), stored_hash):
        logger.info("login failed user=%s reason=bad_password", request.username)
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})

    token = _create_token(user[0], user[1], user[3], user[4])
    logger.info("login success user=%s tenant=%s", user[1], user[4])

    return {
        "token": token,
        "token_type": "bearer",
        "user_id": user[0],
        "username": user[1],
        "role": user[3],
        "tenant_id": user[4],
    }


@app.post("/api/auth/register")
async def register(request: RegisterRequest, req: Request):
    client_ip = req.client.host if req.client else "unknown"

    if _check_rate_limit(f"register:{client_ip}", 3, 600):
        raise HTTPException(status_code=429, detail="Too many registration attempts.")

    if not PASSWORD_RE.match(request.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 10+ chars with uppercase, lowercase, digit, and special character.",
        )

    hashed = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt()).decode()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, email, tenant_id) VALUES (?, ?, ?, ?)",
            (request.username, hashed, request.email, request.tenant_id),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(status_code=409, detail="Username already exists")
    conn.close()

    logger.info("user registered user=%s tenant=%s", request.username, request.tenant_id)
    return {"status": "registered", "username": request.username}


# =============================================================================
# Log Management — all endpoints require auth + enforce tenant isolation
# =============================================================================
@app.get("/api/logs")
async def get_logs(
    claims: dict = Depends(require_auth),
    limit: int = 100,
):
    tenant_id = claims["tenant_id"]
    limit = min(limit, MAX_LOGS_LIMIT)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, tenant_id, level, message, source, timestamp FROM logs "
        "WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
        (tenant_id, limit),
    )
    rows = cur.fetchall()
    conn.close()

    logs = [
        {"id": r[0], "tenant_id": r[1], "level": r[2], "message": r[3], "source": r[4], "timestamp": str(r[5])}
        for r in rows
    ]
    return {"logs": logs, "count": len(logs)}


@app.post("/api/logs")
async def create_log(
    log: LogRequest,
    req: Request,
    claims: dict = Depends(require_auth),
):
    tenant_id = claims["tenant_id"]
    client_ip = req.client.host if req.client else "unknown"

    if _check_rate_limit(f"log:{tenant_id}", RATE_LIMIT_GENERAL, RATE_LIMIT_GENERAL_WINDOW):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    level_upper = log.level.upper()
    if level_upper not in VALID_LOG_LEVELS:
        raise HTTPException(status_code=400, detail=f"Invalid log level. Must be one of: {', '.join(sorted(VALID_LOG_LEVELS))}")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (tenant_id, level, message, source) VALUES (?, ?, ?, ?)",
        (tenant_id, level_upper, log.message, log.source),
    )
    conn.commit()
    conn.close()

    return {"status": "created", "tenant_id": tenant_id}


# =============================================================================
# Alert Management
# =============================================================================
@app.get("/api/alerts")
async def get_alerts(claims: dict = Depends(require_auth)):
    tenant_id = claims["tenant_id"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, tenant_id, severity, title, description, created_at FROM alerts "
        "WHERE tenant_id = ? ORDER BY created_at DESC",
        (tenant_id,),
    )
    rows = cur.fetchall()
    conn.close()

    alerts = [
        {"id": r[0], "tenant_id": r[1], "severity": r[2], "title": r[3], "description": r[4], "created_at": str(r[5])}
        for r in rows
    ]
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/api/alerts")
async def create_alert(
    alert: AlertRequest,
    claims: dict = Depends(require_auth),
):
    tenant_id = claims["tenant_id"]

    severity_lower = alert.severity.lower()
    if severity_lower not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO alerts (tenant_id, severity, title, description) VALUES (?, ?, ?, ?)",
        (tenant_id, severity_lower, alert.title, alert.description),
    )
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()

    logger.info("alert created tenant=%s severity=%s", tenant_id, severity_lower)
    return {"status": "created", "alert_id": alert_id}


# =============================================================================
# Search — authenticated, tenant-scoped
# =============================================================================
@app.get("/api/search")
async def search_logs(
    q: str = "",
    claims: dict = Depends(require_auth),
):
    tenant_id = claims["tenant_id"]

    if len(q) > 256:
        raise HTTPException(status_code=400, detail="Query too long")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, tenant_id, level, message, source, timestamp FROM logs "
        "WHERE tenant_id = ? AND message LIKE ? LIMIT 100",
        (tenant_id, f"%{q}%"),
    )
    rows = cur.fetchall()
    conn.close()

    results = [
        {"id": r[0], "tenant_id": r[1], "level": r[2], "message": r[3], "source": r[4], "timestamp": str(r[5])}
        for r in rows
    ]
    return {"results": results, "query": q, "count": len(results)}


# =============================================================================
# Stats — authenticated, tenant-scoped (admins see all)
# =============================================================================
@app.get("/api/stats")
async def get_stats(claims: dict = Depends(require_auth)):
    tenant_id = claims["tenant_id"]
    role = claims.get("role", "viewer")

    conn = get_db()
    cur = conn.cursor()

    if role == "admin":
        cur.execute("SELECT COUNT(*) FROM logs WHERE tenant_id = ?", (tenant_id,))
        log_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE tenant_id = ?", (tenant_id,))
        alert_count = cur.fetchone()[0]
    else:
        cur.execute("SELECT COUNT(*) FROM logs WHERE tenant_id = ?", (tenant_id,))
        log_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE tenant_id = ?", (tenant_id,))
        alert_count = cur.fetchone()[0]

    conn.close()

    return {
        "total_logs": log_count,
        "total_alerts": alert_count,
        "tenant_id": tenant_id,
    }
