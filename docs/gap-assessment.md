# NovaSec Cloud — Gap Assessment

## Methodology

Initial assessment scans DVWA (target-app/) as a representative vulnerable
application to demonstrate the gap between an unhardened deployment and
FedRAMP Moderate requirements.

**Scanners used:** Trivy (CVE/misconfig), Semgrep (SAST), Gitleaks (secrets)
**Mapping tool:** `jsa-secops/scan-and-map.py`
**Framework:** NIST 800-53 Rev 5, FedRAMP Moderate baseline

## Gap Summary by Priority Control

### AC-2: Account Management
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| Default ServiceAccount used | No tenant-scoped SAs | HIGH | D |
| automountServiceAccountToken: true | Unnecessary API access | MEDIUM | D |
| No tenant labels | Cannot scope accounts by tenant | HIGH | D |
| **Remediation:** OPA policy `ac2_account_management.rego` enforces dedicated SAs, token control, tenant labeling |

### AC-6: Least Privilege
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| DVWA runs as root | No runAsNonRoot | CRITICAL | D |
| Containers don't drop capabilities | Full capability set | HIGH | D |
| No readOnlyRootFilesystem | Writable container filesystem | HIGH | D |
| hostNetwork/hostPID not blocked | No admission control | CRITICAL | D |
| **Remediation:** OPA `ac6_least_privilege.rego`, Kyverno `require-least-privilege.yaml`, Gatekeeper `K8sLeastPrivilege` |

### AU-2: Audit Events
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| No Falco integration | Runtime events not captured | HIGH | C |
| No audit sidecar | Application logs not shipped | MEDIUM | D |
| No log format labels | Cannot parse heterogeneous logs | MEDIUM | E |
| **Remediation:** OPA `au2_audit_events.rego`, Kyverno `require-audit-logging.yaml`, Falco deployment |

### CM-6: Configuration Settings
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| No resource limits | Resource exhaustion risk | HIGH | E |
| Missing standard labels | Cannot inventory workloads | MEDIUM | E |
| :latest image tag | Mutable supply chain | HIGH | D |
| Unapproved container registries | No image provenance | HIGH | C |
| **Remediation:** OPA `cm6_configuration_settings.rego`, Kyverno `require-resource-limits.yaml` |

### SC-7: Boundary Protection
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| No NetworkPolicy | All pods can reach all pods | CRITICAL | D |
| NodePort services exposed | Bypasses ingress controls | HIGH | D |
| No tenant namespace labels | Cannot target by NetworkPolicy | MEDIUM | D |
| **Remediation:** OPA `sc7_boundary_protection.rego`, Kyverno `enforce-network-boundaries.yaml`, Gatekeeper `K8sNetworkBoundaries` |

### SC-8: Transmission Confidentiality
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| Ingress without TLS | Plaintext external traffic | CRITICAL | C |
| No mTLS between services | Internal traffic unencrypted | HIGH | C |
| Plaintext ports (80, 8080) exposed | Unencrypted communication | MEDIUM | D |
| No service mesh sidecar | Cannot enforce mTLS | HIGH | C |
| **Remediation:** OPA `sc8_transmission_confidentiality.rego`, Kyverno `require-tls-everywhere.yaml`, Istio deployment |

### SI-2: Flaw Remediation
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| DVWA has 50+ known CVEs | Unpatched vulnerabilities | CRITICAL | C-D |
| Mutable image tags | Cannot verify deployed version | HIGH | D |
| No Trivy scan annotation | No proof of pre-deploy scan | HIGH | D |
| Unapproved registries | No supply chain control | HIGH | C |
| **Remediation:** OPA `si2_flaw_remediation.rego`, Trivy CI integration |

### SI-4: System Monitoring
| Finding | Gap | Severity | Rank |
|---------|-----|----------|------|
| No Falco DaemonSet | No runtime detection | HIGH | C |
| No Prometheus annotations | No metrics collection | MEDIUM | D |
| No log-collection sidecar | Logs lost on pod restart | MEDIUM | D |
| No health probes | Silent service degradation | MEDIUM | E |
| **Remediation:** OPA `si4_system_monitoring.rego`, Falco custom rules, Prometheus integration |

## Risk Summary

| Rank | Count | Automation Level |
|------|-------|-----------------|
| E | 4 | Fully automated |
| D | 15 | Automated with logging |
| C | 8 | JADE approval required |
| B | 0 | Human review |
| S | 0 | Executive decision |

**Total gaps identified:** 27 across 8 priority controls
**Automated remediation coverage:** 70% (E+D rank)
**JADE-assisted coverage:** 30% (C rank)
