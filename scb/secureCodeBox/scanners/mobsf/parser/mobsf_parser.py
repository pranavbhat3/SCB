#!/usr/bin/env python3
import sys
import json
import requests

# MobSF to SecureCodeBox severity mapping
SEVERITY_MAP = {
    "info": "INFORMATIONAL",
    "warning": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
    "low": "LOW"
}

def parse_certificate_findings(cert_findings):
    findings = []
    for finding in cert_findings:
        severity, description, name = finding
        findings.append({
            "name": name,
            "description": description,
            "category": "Certificate Analysis",
            "location": "",
            "osi_layer": "APPLICATION",
            # Always output severity in uppercase
            "severity": SEVERITY_MAP.get(severity.lower(), "MEDIUM").upper(),
            "attributes": {
                "source": "certificate_analysis"
            }
        })
    return findings

def parse_manifest_findings(manifest_findings):
    findings = []
    for finding in manifest_findings:
        sev = SEVERITY_MAP.get(finding.get("severity", "medium").lower(), "MEDIUM").upper()
        findings.append({
            "name": finding.get("name", finding.get("title", "")),
            "description": finding.get("description", ""),
            "category": finding.get("rule", "Manifest Analysis"),
            "location": ", ".join(finding.get("component", [])),
            "osi_layer": "APPLICATION",
            "severity": sev,
            "attributes": {
                "source": "manifest_analysis"
            }
        })
    return findings

def main():
    # Debug and error output must go to stderr only
    input_data = ""
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        url = sys.argv[1]
        try:
            resp = requests.get(url)
            resp.raise_for_status()
            input_data = resp.text
        except Exception as e:
            print(f"Failed to fetch result from {url}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        input_data = sys.stdin.read()

    if not input_data.strip():
        print("No input received.", file=sys.stderr)
        sys.exit(0)
    try:
        report = json.loads(input_data)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    findings = []
    # Certificate findings
    cert_findings = report.get("certificate_analysis", {}).get("certificate_findings", [])
    findings.extend(parse_certificate_findings(cert_findings))
    # Manifest findings
    manifest_findings = report.get("manifest_analysis", {}).get("manifest_findings", [])
    findings.extend(parse_manifest_findings(manifest_findings))
    findings_json = json.dumps(findings, separators=(",", ":"))

    # If a second argument (output URL) is present, upload findings there (v2.x style)
    if len(sys.argv) > 2 and sys.argv[2].startswith("http"):
        output_url = sys.argv[2]
        try:
            resp = requests.put(output_url, data=findings_json, headers={"Content-Type": "application/json"})
            resp.raise_for_status()
        except Exception as e:
            print(f"Failed to upload findings to {output_url}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Otherwise, print to stdout (v3.x+ style)
        print(findings_json)

if __name__ == "__main__":
    main() 