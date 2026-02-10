# Target Application: DVWA

This directory contains [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) — an intentionally vulnerable PHP/MySQL web application used as the target for this FedRAMP compliance demonstration.

## Purpose

DVWA provides a realistic attack surface with known vulnerabilities (SQLi, XSS, command injection, CSRF, etc.) that our automated security toolchain detects, classifies, and remediates against FedRAMP NIST 800-53 controls.

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
