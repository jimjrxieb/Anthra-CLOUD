# IA — Identification and Authentication

## IA-5: Authenticator Management

**Requirement**: Manage information system authenticators by verifying the identity of individuals, groups, roles, or devices receiving the authenticator and establishing initial authenticator content.

**Implementation**:
- **Secret Detection**: Gitleaks scans every commit for hardcoded credentials, API keys, tokens
- **Secret Rotation**: Kubernetes Secrets managed with rotation policies
- **No Hardcoded Secrets**: CI pipeline blocks commits containing secrets
- **Service Account Tokens**: Auto-mounted tokens disabled by default; explicitly bound where needed
- **Image Pull Secrets**: Scoped to specific namespaces

**Secret Detection Rules** (Gitleaks):
| Pattern | Description | Severity |
|---------|-------------|----------|
| AWS access keys | `AKIA[0-9A-Z]{16}` | Critical |
| Private keys | `-----BEGIN.*PRIVATE KEY-----` | Critical |
| API tokens | Generic high-entropy strings | High |
| Database passwords | Connection string passwords | High |
| JWT tokens | `eyJ...` base64 patterns | Medium |

**Evidence**:
- `automation/scanning/gitleaks.toml` — Secret detection configuration
- `evidence/scan-reports/initial-scan.json` — Historical scan showing secret audit
- `.github/workflows/fedramp-compliance.yml` — CI gate blocking secret commits

**Iron Legion Mapping**:
- **JSA-DevSec**: Gitleaks scanner detects secrets pre-commit/pre-merge (E-rank auto-block)
- **JSA-InfraSec**: Monitors Kubernetes Secrets for unauthorized access at runtime
- **JADE**: Escalates credential exposure as B-rank finding (human notification required)
