"""
NovaSec Cloud API — Security Monitoring Platform
DELIBERATELY INSECURE — This is a security training target.

Every endpoint contains at least one vulnerability mapped to a NIST 800-53
control gap. This mirrors DVWA vulnerability patterns in a modern Python
FastAPI stack, demonstrating what GuidePoint's Iron Legion overlay remediates.
"""

import hashlib
import os
import sqlite3

import psycopg2
from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

# ──────────────────────────────────────────────────────────────────────────────
# VULN: Hardcoded database credentials
# NIST gap: IA-5 (Authenticator Management)
# ──────────────────────────────────────────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "novasec")
DB_USER = os.getenv("DB_USER", "novasec")
DB_PASSWORD = "novasec_insecure_password_123"  # VULN: hardcoded fallback

app = FastAPI(title="NovaSec Cloud API", version="0.1.0")


def get_db():
    """Get a database connection. Falls back to SQLite for demo without Postgres."""
    try:
        return psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASSWORD,
        )
    except Exception:
        # Fallback to SQLite for local demo
        conn = sqlite3.connect("/tmp/novasec.db")
        conn.execute("""CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT, level TEXT, message TEXT, source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT, title TEXT, body TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'viewer'
        )""")
        # Seed demo data
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hashlib.md5(b"admin123").hexdigest(), "admin"),
            )
            for i in range(1, 4):
                conn.execute(
                    "INSERT INTO logs (tenant_id, level, message, source) VALUES (?, ?, ?, ?)",
                    (f"tenant-{i}", "INFO", f"System startup for tenant-{i}", "api"),
                )
            conn.commit()
        except Exception:
            pass
        return conn


# ──────────────────────────────────────────────────────────────────────────────
# Health check (not vulnerable, but no auth — AC-2 gap)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "novasec-api"}


# ──────────────────────────────────────────────────────────────────────────────
# VULN: SQL Injection — string concatenation in query
# DVWA equivalent: vulnerabilities/sqli/source/low.php
# NIST gap: SI-2 (Flaw Remediation)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/logs")
def get_logs(tenant_id: str = ""):
    conn = get_db()
    cur = conn.cursor()
    # VULN: Direct string interpolation — classic SQL injection
    query = f"SELECT * FROM logs WHERE tenant_id = '{tenant_id}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return {"logs": [dict(zip(["id", "tenant_id", "level", "message", "source", "created_at"], r)) for r in rows]}


# ──────────────────────────────────────────────────────────────────────────────
# VULN: Reflected XSS — user input rendered in HTML without escaping
# DVWA equivalent: vulnerabilities/xss_r/source/low.php
# NIST gap: SI-2 (Flaw Remediation)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/search", response_class=HTMLResponse)
def search_logs(q: str = ""):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs")
    rows = cur.fetchall()
    conn.close()
    # VULN: User input directly embedded in HTML response
    html = f"<h2>Search results for: {q}</h2><ul>"
    for r in rows:
        html += f"<li>{r}</li>"
    html += "</ul>"
    return html


# ──────────────────────────────────────────────────────────────────────────────
# VULN: Stored XSS — alert body stored and rendered without sanitization
# DVWA equivalent: vulnerabilities/xss_s/source/low.php
# NIST gap: SI-2 (Flaw Remediation)
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/api/alerts")
async def create_alert(request: Request):
    body = await request.json()
    conn = get_db()
    cur = conn.cursor()
    # VULN: Raw insert — stored XSS when body is rendered later
    cur.execute(
        f"INSERT INTO alerts (tenant_id, title, body) VALUES ('{body.get('tenant_id', '')}', '{body.get('title', '')}', '{body.get('body', '')}')"
    )
    conn.commit()
    conn.close()
    return {"status": "created"}


@app.get("/api/alerts", response_class=HTMLResponse)
def list_alerts(tenant_id: str = ""):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM alerts WHERE tenant_id = '{tenant_id}'")
    rows = cur.fetchall()
    conn.close()
    # VULN: Rendering stored user content without escaping
    html = "<h2>Alerts</h2><ul>"
    for r in rows:
        html += f"<li><b>{r[2]}</b>: {r[3]}</li>"
    html += "</ul>"
    return html


# ──────────────────────────────────────────────────────────────────────────────
# VULN: Command Injection — user input passed to os.system()
# DVWA equivalent: vulnerabilities/exec/source/low.php
# NIST gap: SI-2 (Flaw Remediation)
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/api/diagnostic")
async def run_diagnostic(request: Request):
    body = await request.json()
    target = body.get("target", "127.0.0.1")
    # VULN: Direct shell command injection
    result = os.popen(f"ping -c 1 {target}").read()
    return {"output": result}


# ──────────────────────────────────────────────────────────────────────────────
# VULN: Unrestricted File Upload — no type/size validation
# DVWA equivalent: vulnerabilities/upload/source/low.php
# NIST gap: CM-6 (Configuration Settings)
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/api/config/upload")
async def upload_config(file: UploadFile = File(...)):
    # VULN: No file type check, no size limit, writes to predictable path
    contents = await file.read()
    upload_path = f"/tmp/uploads/{file.filename}"
    os.makedirs("/tmp/uploads", exist_ok=True)
    with open(upload_path, "wb") as f:
        f.write(contents)
    return {"status": "uploaded", "path": upload_path}


# ──────────────────────────────────────────────────────────────────────────────
# VULN: Weak authentication — MD5 hash, no rate limiting, no lockout
# DVWA equivalent: vulnerabilities/brute/source/low.php
# NIST gap: AC-2 (Account Management), IA-5 (Authenticator Management)
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    # VULN: MD5 hashing (weak), no rate limit, no account lockout
    password_hash = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'")
    user = cur.fetchone()
    conn.close()
    if user:
        return {"status": "authenticated", "user": username, "role": user[3] if len(user) > 3 else "viewer"}
    return JSONResponse(status_code=401, content={"status": "failed"})


# ──────────────────────────────────────────────────────────────────────────────
# VULN: Path Traversal — open() with user-controlled filename
# DVWA equivalent: vulnerabilities/fi/source/low.php
# NIST gap: AC-3 (Access Enforcement)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/reports")
def get_report(file: str = "summary.txt"):
    # VULN: No path sanitization — directory traversal
    try:
        with open(f"/app/reports/{file}") as f:
            content = f.read()
        return {"file": file, "content": content}
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "Report not found"})


# ──────────────────────────────────────────────────────────────────────────────
# VULN: No CSRF protection — state-changing POST without token
# DVWA equivalent: vulnerabilities/csrf/source/low.php
# NIST gap: SC-7 (Boundary Protection)
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/api/tenant/settings")
async def update_tenant_settings(request: Request):
    body = await request.json()
    # VULN: No CSRF token, no origin check, no auth
    return {
        "status": "updated",
        "tenant_id": body.get("tenant_id"),
        "settings": body.get("settings", {}),
    }


# ──────────────────────────────────────────────────────────────────────────────
# VULN: Information Disclosure — debug endpoint exposes internals
# NIST gap: CM-6 (Configuration Settings), AC-6 (Least Privilege)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/debug")
def debug_info():
    # VULN: Exposes environment variables including credentials
    return {
        "env": dict(os.environ),
        "db_password": DB_PASSWORD,
        "python_path": os.sys.path,
    }


# ──────────────────────────────────────────────────────────────────────────────
# VULN: No authentication middleware on any endpoint
# NIST gap: AC-2 (Account Management), AC-6 (Least Privilege)
# ──────────────────────────────────────────────────────────────────────────────
# NOTE: Every endpoint above lacks authentication. In a real FedRAMP system,
# all endpoints would require JWT/OAuth tokens validated by middleware.
# The GP-Copilot overlay addresses this through Kyverno policies that enforce
# Istio sidecar injection (mTLS) and OPA policies that require auth annotations.
