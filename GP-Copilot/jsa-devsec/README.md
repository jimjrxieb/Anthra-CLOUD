# JSA-DevSec — Pre-Deployment Security for NovaSec Cloud

Pre-deployment scanning configurations for FedRAMP Moderate compliance.
These configs are consumed by the `jsa-devsec` agent from `GP-BEDROCK-AGENTS/`.

## Scanners

| Tool | Config | What It Catches |
|------|--------|-----------------|
| Trivy | `trivy-config.yaml` | CVEs, misconfigs, secrets, SBOM |
| Semgrep | `semgrep-rules.yaml` | SAST: SQLi, XSS, command injection |
| Gitleaks | `gitleaks.toml` | Hardcoded secrets, API keys |
| Conftest | `conftest-runner.sh` | OPA policy violations on manifests |

## Usage

```bash
# Run all scanners against target-app (DVWA)
trivy fs --config trivy-config.yaml ../target-app/
semgrep --config semgrep-rules.yaml ../target-app/
gitleaks detect --source ../target-app/ --config gitleaks.toml
./conftest-runner.sh ../policies/opa/
```

## NIST Control Mapping

- **RA-5** (Vulnerability Scanning) — Trivy, Semgrep, Grype
- **SI-2** (Flaw Remediation) — Trivy CVE findings → patch guidance
- **SA-11** (Developer Security Testing) — Semgrep SAST, Gitleaks
- **CM-6** (Configuration Settings) — Conftest OPA policy checks
