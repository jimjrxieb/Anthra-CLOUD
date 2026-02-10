# NovaPay Federal's Application (DVWA)

This directory contains [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) — standing in as a simplified version of NovaPay Federal's web application for this FedRAMP compliance engagement.

## Why DVWA?

NovaPay's real production application contains proprietary code. DVWA is open-source and intentionally vulnerable, providing realistic vulnerabilities (SQLi, XSS, command injection, hardcoded credentials) that map directly to the kinds of findings we encounter in real-world FedRAMP assessments. The Iron Legion scans, classifies, and remediates these against NIST 800-53 controls — the same process used for any client application.

## Running Standalone

```bash
docker compose up -d
# Access at http://127.0.0.1:4280
# Default creds: admin / password
```

## Original Project

- **Upstream**: https://github.com/digininja/DVWA
- **License**: GPL-3.0 (see `../LICENSE`)
- **Original README**: `DVWA-README.md`
