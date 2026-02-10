#!/usr/bin/env python3
"""
scan-and-map.py — Run security scans and map findings to NIST 800-53 controls.

FedRAMP Controls: CA-2 (Security Assessments), RA-5 (Vulnerability Scanning)

Usage:
    python scan-and-map.py [--target-dir TARGET] [--output-dir OUTPUT] [--dry-run]

Adapted from GP-Copilot Iron Legion compliance_mappings.py
"""

import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# NIST 800-53 control mapping for scan findings
FINDING_TO_NIST = {
    # Vulnerability types → NIST controls
    "sql_injection":        {"controls": ["RA-5", "SI-2"], "rank": "D", "family": "SI"},
    "xss":                  {"controls": ["RA-5", "SI-2"], "rank": "D", "family": "SI"},
    "command_injection":    {"controls": ["RA-5", "SI-2"], "rank": "C", "family": "SI"},
    "file_inclusion":       {"controls": ["RA-5", "AC-3"], "rank": "C", "family": "AC"},
    "csrf":                 {"controls": ["SC-7", "SI-2"], "rank": "D", "family": "SC"},
    "hardcoded_secret":     {"controls": ["IA-5"],         "rank": "B", "family": "IA"},
    "weak_crypto":          {"controls": ["SC-28"],        "rank": "C", "family": "SC"},
    "missing_auth":         {"controls": ["AC-3", "IA-5"], "rank": "C", "family": "AC"},

    # Container/infra findings → NIST controls
    "cve_critical":         {"controls": ["SI-2", "RA-5"], "rank": "C", "family": "SI"},
    "cve_high":             {"controls": ["SI-2", "RA-5"], "rank": "D", "family": "SI"},
    "cve_medium":           {"controls": ["SI-2"],         "rank": "D", "family": "SI"},
    "cve_low":              {"controls": ["SI-2"],         "rank": "E", "family": "SI"},
    "misconfiguration":     {"controls": ["CM-6"],         "rank": "D", "family": "CM"},
    "privileged_container": {"controls": ["AC-6", "CM-6"], "rank": "D", "family": "AC"},
    "no_resource_limits":   {"controls": ["CM-6"],         "rank": "E", "family": "CM"},
    "missing_netpol":       {"controls": ["SC-7"],         "rank": "D", "family": "SC"},
    "secret_exposed":       {"controls": ["IA-5"],         "rank": "B", "family": "IA"},

    # Policy violations → NIST controls
    "policy_violation":     {"controls": ["CM-6", "CA-7"], "rank": "D", "family": "CM"},
    "audit_gap":            {"controls": ["AU-2", "AU-3"], "rank": "C", "family": "AU"},
}

RANK_LABELS = {
    "E": "Auto-fix, no approval needed",
    "D": "Auto-fix with logging",
    "C": "JADE supervisor approval",
    "B": "Human review required",
    "S": "Executive decision",
}


def run_scanner(name, cmd, target_dir):
    """Run a scanner and return parsed results."""
    print(f"  Running {name}...")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, cwd=target_dir
        )
        return {"scanner": name, "exit_code": result.returncode, "output": result.stdout, "error": result.stderr}
    except FileNotFoundError:
        print(f"  WARNING: {name} not installed, skipping")
        return {"scanner": name, "exit_code": -1, "output": "", "error": f"{name} not found"}
    except subprocess.TimeoutExpired:
        print(f"  WARNING: {name} timed out")
        return {"scanner": name, "exit_code": -2, "output": "", "error": "timeout"}


def parse_trivy_results(raw):
    """Parse Trivy JSON output into normalized findings."""
    findings = []
    try:
        data = json.loads(raw) if raw else {}
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").lower()
                finding_type = f"cve_{severity}" if severity in ("critical", "high", "medium", "low") else "cve_medium"
                findings.append({
                    "id": vuln.get("VulnerabilityID", "UNKNOWN"),
                    "type": finding_type,
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "title": vuln.get("Title", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed": vuln.get("InstalledVersion", ""),
                    "fixed": vuln.get("FixedVersion", ""),
                    "source": "trivy",
                })
    except json.JSONDecodeError:
        pass
    return findings


def parse_semgrep_results(raw):
    """Parse Semgrep JSON output into normalized findings."""
    findings = []
    try:
        data = json.loads(raw) if raw else {}
        for result in data.get("results", []):
            rule_id = result.get("check_id", "")
            severity = result.get("extra", {}).get("severity", "WARNING")
            finding_type = "sql_injection" if "sql" in rule_id.lower() else \
                           "xss" if "xss" in rule_id.lower() else \
                           "command_injection" if "command" in rule_id.lower() else \
                           "hardcoded_secret" if "secret" in rule_id.lower() or "credential" in rule_id.lower() else \
                           "misconfiguration"
            findings.append({
                "id": rule_id,
                "type": finding_type,
                "severity": severity,
                "title": result.get("extra", {}).get("message", ""),
                "file": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
                "source": "semgrep",
            })
    except json.JSONDecodeError:
        pass
    return findings


def parse_gitleaks_results(raw):
    """Parse Gitleaks JSON output into normalized findings."""
    findings = []
    try:
        data = json.loads(raw) if raw else []
        if isinstance(data, list):
            for leak in data:
                findings.append({
                    "id": leak.get("RuleID", "unknown"),
                    "type": "secret_exposed",
                    "severity": "HIGH",
                    "title": leak.get("Description", "Secret detected"),
                    "file": leak.get("File", ""),
                    "line": leak.get("StartLine", 0),
                    "source": "gitleaks",
                })
    except json.JSONDecodeError:
        pass
    return findings


def map_to_nist(findings):
    """Map findings to NIST 800-53 controls with Iron Legion ranks."""
    mapped = []
    for finding in findings:
        mapping = FINDING_TO_NIST.get(finding["type"], {
            "controls": ["RA-5"],
            "rank": "D",
            "family": "RA"
        })
        mapped.append({
            **finding,
            "nist_controls": mapping["controls"],
            "iron_legion_rank": mapping["rank"],
            "rank_description": RANK_LABELS.get(mapping["rank"], "Unknown"),
            "control_family": mapping["family"],
        })
    return mapped


def generate_report(mapped_findings, output_dir):
    """Generate NIST compliance report."""
    report = {
        "report_type": "FedRAMP NIST 800-53 Compliance Scan",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(mapped_findings),
            "by_rank": {},
            "by_control": {},
            "by_family": {},
        },
        "findings": mapped_findings,
    }

    # Aggregate by rank
    for f in mapped_findings:
        rank = f["iron_legion_rank"]
        report["summary"]["by_rank"][rank] = report["summary"]["by_rank"].get(rank, 0) + 1

    # Aggregate by control
    for f in mapped_findings:
        for ctrl in f["nist_controls"]:
            report["summary"]["by_control"][ctrl] = report["summary"]["by_control"].get(ctrl, 0) + 1

    # Aggregate by family
    for f in mapped_findings:
        fam = f["control_family"]
        report["summary"]["by_family"][fam] = report["summary"]["by_family"].get(fam, 0) + 1

    # Write JSON report
    output_path = Path(output_dir) / "nist-mapping-report.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nReport written to: {output_path}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"NIST 800-53 Compliance Scan Report")
    print(f"{'='*60}")
    print(f"Total Findings: {report['summary']['total_findings']}")
    print(f"\nBy Iron Legion Rank:")
    for rank in sorted(report["summary"]["by_rank"]):
        count = report["summary"]["by_rank"][rank]
        print(f"  {rank}-rank: {count} ({RANK_LABELS.get(rank, '')})")
    print(f"\nBy NIST Control:")
    for ctrl in sorted(report["summary"]["by_control"]):
        count = report["summary"]["by_control"][ctrl]
        print(f"  {ctrl}: {count} findings")
    print(f"{'='*60}")

    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Scan target app and map to NIST 800-53")
    parser.add_argument("--target-dir", default="target-app", help="Directory to scan")
    parser.add_argument("--output-dir", default="evidence/scan-reports", help="Output directory")
    parser.add_argument("--dry-run", action="store_true", help="Show what would run without executing")
    args = parser.parse_args()

    target = Path(args.target_dir).resolve()
    output = Path(args.output_dir).resolve()

    if not target.exists():
        print(f"ERROR: Target directory not found: {target}")
        sys.exit(1)

    print(f"FedRAMP Compliance Scanner")
    print(f"Target: {target}")
    print(f"Output: {output}")

    if args.dry_run:
        print("\n[DRY RUN] Would execute:")
        print(f"  trivy fs --format json {target}")
        print(f"  semgrep --config automation/scanning/semgrep-rules.yaml --json {target}")
        print(f"  gitleaks detect --source {target} --report-format json")
        print(f"  conftest test automation/kubernetes/ --policy automation/policies/conftest/")
        return

    # Run scanners
    print("\nRunning scanners...")
    all_findings = []

    trivy = run_scanner("trivy", ["trivy", "fs", "--format", "json", str(target)], str(target))
    if trivy["exit_code"] >= 0:
        all_findings.extend(parse_trivy_results(trivy["output"]))

    semgrep = run_scanner("semgrep", [
        "semgrep", "--config", "automation/scanning/semgrep-rules.yaml",
        "--json", str(target)
    ], str(target.parent))
    if semgrep["exit_code"] >= 0:
        all_findings.extend(parse_semgrep_results(semgrep["output"]))

    gitleaks = run_scanner("gitleaks", [
        "gitleaks", "detect", "--source", str(target),
        "--report-format", "json", "--report-path", "/dev/stdout", "--no-git"
    ], str(target))
    if gitleaks["exit_code"] >= 0:
        all_findings.extend(parse_gitleaks_results(gitleaks["output"]))

    # Map to NIST controls
    print(f"\nMapping {len(all_findings)} findings to NIST 800-53 controls...")
    mapped = map_to_nist(all_findings)

    # Generate report
    generate_report(mapped, str(output))


if __name__ == "__main__":
    main()
