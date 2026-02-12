"""
Anthra Security Platform API
Multi-tenant security monitoring and log aggregation SaaS

Built for speed-to-market by a development team focused on features.
Now needs FedRAMP Moderate hardening to enter federal market.
"""

import hashlib
import os
import sqlite3
from datetime import datetime
from typing import Optional

import psycopg2
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# =============================================================================
# Configuration - Credentials in environment variables
# CWE-798: Hard-coded credentials in fallback values
# =============================================================================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "anthra")
DB_USER = os.getenv("DB_USER", "anthra")
DB_PASSWORD = os.getenv("DB_PASSWORD", "anthra_default_pass_123")  # CWE-798

app = FastAPI(
    title="Anthra Security Platform",
    version="1.0.0",
    description="Cloud-native security monitoring and threat detection",
)

# CWE-942: Permissive CORS policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Should be restricted to known origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    except Exception as e:
        # Fallback to SQLite for local development
        print(f"PostgreSQL connection failed: {e}, using SQLite fallback")
        conn = sqlite3.connect("/tmp/anthra.db")
        _init_sqlite(conn)
        return conn


def _init_sqlite(conn):
    """Initialize SQLite schema for demo mode."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT,
            level TEXT,
            message TEXT,
            source TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT,
            role TEXT DEFAULT 'viewer',
            tenant_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed demo data
    try:
        # CWE-916: Use of password hash with insufficient computational effort (MD5)
        conn.execute(
            "INSERT INTO users (username, password_hash, email, role, tenant_id) VALUES (?, ?, ?, ?, ?)",
            ("admin", hashlib.md5(b"admin123").hexdigest(), "admin@anthra.io", "admin", "tenant-1"),
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
# Request/Response Models
# =============================================================================
class LoginRequest(BaseModel):
    username: str
    password: str


class AlertRequest(BaseModel):
    tenant_id: str
    severity: str
    title: str
    description: str


class LogRequest(BaseModel):
    tenant_id: str
    level: str
    message: str
    source: str


# =============================================================================
# Health Check
# =============================================================================
@app.get("/api/health")
def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "anthra-api",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


# =============================================================================
# Authentication Endpoints
# CWE-306: Missing authentication for critical function
# CWE-307: Improper restriction of excessive authentication attempts
# =============================================================================
@app.post("/api/auth/login")
async def login(request: LoginRequest):
    """
    User authentication endpoint.

    Security gaps:
    - CWE-916: MD5 password hashing (weak, should use bcrypt/argon2)
    - CWE-307: No rate limiting on login attempts
    - CWE-532: Logging of sensitive data (passwords in logs)
    """
    conn = get_db()
    cur = conn.cursor()

    # CWE-916: MD5 is cryptographically broken
    password_hash = hashlib.md5(request.password.encode()).hexdigest()

    # Using parameterized queries (good practice maintained)
    cur.execute(
        "SELECT id, username, email, role, tenant_id FROM users WHERE username = ? AND password_hash = ?",
        (request.username, password_hash),
    )
    user = cur.fetchone()
    conn.close()

    if user:
        # CWE-532: Logging sensitive authentication data
        print(f"Login successful: {request.username} from tenant {user[4]}")
        return {
            "status": "authenticated",
            "user_id": user[0],
            "username": user[1],
            "email": user[2],
            "role": user[3],
            "tenant_id": user[4],
        }

    # CWE-209: Information exposure through error message
    return JSONResponse(
        status_code=401,
        content={"error": "Invalid username or password"},
    )


@app.post("/api/auth/register")
async def register(request: Request):
    """
    User registration endpoint.

    Security gaps:
    - No email verification
    - No password complexity requirements
    - MD5 hashing
    """
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    email = body.get("email", "")
    tenant_id = body.get("tenant_id", "tenant-1")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    conn = get_db()
    cur = conn.cursor()

    # CWE-916: MD5 password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()

    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, email, tenant_id) VALUES (?, ?, ?, ?)",
            (username, password_hash, email, tenant_id),
        )
        conn.commit()
        conn.close()
        return {"status": "registered", "username": username}
    except Exception as e:
        conn.close()
        # CWE-209: Error message might leak database structure
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")


# =============================================================================
# Log Management
# CWE-306: Missing authentication - no auth middleware
# =============================================================================
@app.get("/api/logs")
async def get_logs(tenant_id: Optional[str] = None, limit: int = 100):
    """
    Retrieve logs for a tenant.

    Security gaps:
    - CWE-306: No authentication check (anyone can query)
    - CWE-284: Missing tenant isolation check
    - No pagination limit enforcement
    """
    conn = get_db()
    cur = conn.cursor()

    if tenant_id:
        # Using parameterized queries (good)
        cur.execute(
            "SELECT * FROM logs WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
            (tenant_id, limit),
        )
    else:
        # CWE-284: Returns logs from ALL tenants without auth
        cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))

    rows = cur.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            "id": row[0],
            "tenant_id": row[1],
            "level": row[2],
            "message": row[3],
            "source": row[4],
            "timestamp": row[5],
        })

    return {"logs": logs, "count": len(logs)}


@app.post("/api/logs")
async def create_log(log: LogRequest):
    """
    Create a new log entry.

    Security gaps:
    - CWE-306: No authentication
    - CWE-770: No rate limiting (could flood database)
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO logs (tenant_id, level, message, source) VALUES (?, ?, ?, ?)",
        (log.tenant_id, log.level, log.message, log.source),
    )
    conn.commit()
    conn.close()

    return {"status": "created", "tenant_id": log.tenant_id}


# =============================================================================
# Alert Management
# =============================================================================
@app.get("/api/alerts")
async def get_alerts(tenant_id: Optional[str] = None):
    """
    Retrieve security alerts.

    Security gaps:
    - CWE-306: No authentication
    - CWE-284: No tenant isolation
    """
    conn = get_db()
    cur = conn.cursor()

    if tenant_id:
        cur.execute(
            "SELECT * FROM alerts WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        )
    else:
        cur.execute("SELECT * FROM alerts ORDER BY created_at DESC")

    rows = cur.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "id": row[0],
            "tenant_id": row[1],
            "severity": row[2],
            "title": row[3],
            "description": row[4],
            "created_at": row[5],
        })

    return {"alerts": alerts, "count": len(alerts)}


@app.post("/api/alerts")
async def create_alert(alert: AlertRequest):
    """
    Create a new security alert.

    Security gaps:
    - CWE-306: No authentication
    - No input validation on severity levels
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO alerts (tenant_id, severity, title, description) VALUES (?, ?, ?, ?)",
        (alert.tenant_id, alert.severity, alert.title, alert.description),
    )
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()

    return {"status": "created", "alert_id": alert_id}


# =============================================================================
# Search Endpoint
# =============================================================================
@app.get("/api/search")
async def search_logs(q: str = "", tenant_id: Optional[str] = None):
    """
    Search logs by keyword.

    Security gaps:
    - CWE-306: No authentication
    - Basic string matching (not full-text search)
    """
    conn = get_db()
    cur = conn.cursor()

    if tenant_id:
        # Using LIKE with parameterized query (safe from SQLi)
        cur.execute(
            "SELECT * FROM logs WHERE tenant_id = ? AND message LIKE ? LIMIT 100",
            (tenant_id, f"%{q}%"),
        )
    else:
        cur.execute(
            "SELECT * FROM logs WHERE message LIKE ? LIMIT 100",
            (f"%{q}%",),
        )

    rows = cur.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "id": row[0],
            "tenant_id": row[1],
            "level": row[2],
            "message": row[3],
            "source": row[4],
            "timestamp": row[5],
        })

    return {"results": results, "query": q, "count": len(results)}


# =============================================================================
# Debug Endpoint (Development Only)
# CWE-489: Debug features enabled in production
# CWE-215: Information exposure through debug information
# =============================================================================
@app.get("/api/debug")
async def debug_info():
    """
    Debug endpoint exposing system information.

    Security gaps:
    - CWE-489: Should be disabled in production
    - CWE-215: Exposes sensitive environment variables
    - CWE-522: Insufficiently protected credentials
    """
    # CVE-522: Exposing database credentials
    return {
        "status": "debug_mode_active",
        "environment": {
            "DB_HOST": DB_HOST,
            "DB_NAME": DB_NAME,
            "DB_USER": DB_USER,
            "DB_PASSWORD": DB_PASSWORD,  # CVE-522: Exposed credentials
        },
        "config": {
            "cors_enabled": True,
            "auth_required": False,  # TODO: Enable auth middleware
            "rate_limiting": False,  # TODO: Add rate limiting
        },
    }


# =============================================================================
# Stats Endpoint
# =============================================================================
@app.get("/api/stats")
async def get_stats():
    """
    System statistics endpoint.

    Security gaps:
    - CWE-306: No authentication
    - Exposes tenant counts (information disclosure)
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM logs")
    log_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts")
    alert_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users")
    user_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT tenant_id) FROM logs")
    tenant_count = cur.fetchone()[0]

    conn.close()

    return {
        "total_logs": log_count,
        "total_alerts": alert_count,
        "total_users": user_count,
        "active_tenants": tenant_count,
    }


# =============================================================================
# TODO: Add authentication middleware across all endpoints
# TODO: Implement rate limiting per tenant
# TODO: Add CSRF protection for state-changing operations
# TODO: Move credentials to AWS Secrets Manager
# TODO: Replace MD5 with bcrypt/argon2 for password hashing
# TODO: Add request validation and sanitization
# TODO: Implement proper audit logging
# TODO: Add TLS/mTLS for service-to-service communication
# =============================================================================
