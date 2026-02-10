# JSA-InfraSec — Runtime Security for NovaSec Cloud

Runtime enforcement and monitoring configurations for FedRAMP Moderate compliance.
These configs are consumed by the `jsa-infrasec` agent from `GP-BEDROCK-AGENTS/`.

## Components

| Tool | Config | What It Does |
|------|--------|-------------|
| Falco | `falco-rules.yaml` | Syscall-level runtime threat detection |
| Runtime Policies | `runtime-policies.yaml` | Alert → Iron Legion rank mapping |

## NIST Control Mapping

- **SI-4** (System Monitoring) — Falco runtime detection
- **AU-2** (Audit Events) — Audit log capture
- **IR-4** (Incident Handling) — Alert escalation via Iron Legion ranks
- **CA-7** (Continuous Monitoring) — Ongoing runtime enforcement

## Falco Rules

Custom rules for NovaSec Cloud multi-tenant environment:
1. Shell spawned in container
2. Crypto mining process detected
3. Sensitive file access (/etc/shadow, /etc/passwd)
4. Privilege escalation attempt
5. Cross-tenant network access attempt
6. Unexpected outbound connection
