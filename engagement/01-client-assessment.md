# Step 1: Target Application Overview

## What is DVWA?

DVWA (Damn Vulnerable Web Application) is an intentionally vulnerable PHP/MySQL application. It serves as a realistic target for our FedRAMP compliance demo — a web app with known security weaknesses that our toolchain will detect, classify, remediate, and document.

## Why DVWA?

In the NovaPay Federal scenario, DVWA represents the client's existing application that needs to achieve FedRAMP authorization. It has:

- **SQL injection** vulnerabilities (tests AC-3, RA-5)
- **XSS** flaws (tests SI-2)
- **Command injection** (tests RA-5)
- **Authentication weaknesses** (tests IA-5)
- **Missing security controls** (tests CM-6, SC-7)

This gives us real findings to map to NIST 800-53 controls.

## Running the Target App

```bash
cd target-app
docker compose up -d
# Access at http://127.0.0.1:4280
# Default credentials: admin / password
```

## Application Stack

| Component | Technology | Port |
|-----------|-----------|------|
| Web App | PHP 8 + Apache | 80 (mapped to 4280) |
| Database | MariaDB 10 | 3306 (internal) |

## What's Next

With the target app running, we proceed to [Step 2: Pre-Deployment Scan](02-pre-deployment-scan.md) where JSA-DevSec runs a multi-scanner pipeline against it.
