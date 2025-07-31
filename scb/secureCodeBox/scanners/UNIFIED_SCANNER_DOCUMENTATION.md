# SecureCodeBox Scanner Suite - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Scanner Types](#scanner-types)
4. [Setup and Installation](#setup-and-installation)
5. [Individual Scanner Documentation](#individual-scanner-documentation)
6. [Automation Scripts](#automation-scripts)
7. [Script Usage Guide](#script-usage-guide)
8. [Cascading Scans](#cascading-scans)
9. [Results and Reporting](#results-and-reporting)
10. [Quick Reference Commands](#quick-reference-commands)
11. [Troubleshooting](#troubleshooting)


---

## Overview

This repository contains a comprehensive security scanning suite built on SecureCodeBox, featuring four specialized scanners for complete security assessment:

- **🔍 Naabu**: Fast port scanner for network reconnaissance
- **🔒 TLSX**: TLS/SSL certificate analyzer
- **⚡ Nuclei**: Template-based vulnerability scanner
- **🕷️ ZAP**: Web application security testing

All scanners are integrated with SecureCodeBox and can be used individually or in cascading workflows.

---

## Quick Start

### 1. Setup
```bash
# Apply scanner types and parser definitions
./apply_scanner_types.sh

# Setup MinIO access
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
mc alias set securecodebox http://localhost:9000 admin password
```

### 2. Run Complete Assessment
```bash
# Full security assessment (Naabu → TLSX → Nuclei)
./run_cascading_manual.sh target.com
```

### 3. Individual Scanners
```bash
# Port discovery
../naabu/run_naabu_scbctl.sh target.com

# TLS certificate analysis
../tlsx/run_tlsx_scan_multiport.sh target.com

# Vulnerability scanning
scbctl scan nuclei --name nuclei-scan -- -u https://target.com

# Web application security
../zap-automation-framework/run_zap_scan.sh https://target.com
```

---

## Scanner Types

### 1. Naabu Scanner
- **Purpose**: Network port scanning and reconnaissance
- **Capabilities**: Fast port discovery, JSON output, all ports scanning
- **Integration**: Full scbctl and kubectl support
- **Status**: ✅ Production Ready

### 2. TLSX Scanner
- **Purpose**: TLS/SSL certificate analysis
- **Capabilities**: Certificate validation, security assessment, multi-port scanning
- **Integration**: kubectl-based automation
- **Status**: ✅ Production Ready

### 3. Nuclei Scanner
- **Purpose**: Template-based vulnerability scanning
- **Capabilities**: Multiple protocols, zero false positives, extensive templates
- **Integration**: Helm-based deployment
- **Status**: ✅ Production Ready

### 4. ZAP Scanner
- **Purpose**: Web application security testing
- **Capabilities**: Passive/active scanning, API testing, automation framework
- **Integration**: Automation framework with configurable workflows
- **Status**: ✅ Production Ready

---

## Setup and Installation

### Prerequisites

1. **Kubernetes Cluster**: Running with SecureCodeBox operator
2. **kubectl**: Configured and accessible
3. **scbctl**: SecureCodeBox CLI tool
4. **MinIO**: For result storage (automatically configured)

### Initial Setup

```bash
# Apply scanner types and parser definitions
./apply_scanner_types.sh

# Verify installation
kubectl get scantypes -n securecodebox-system
kubectl get parsedefinitions -n securecodebox-system
```

### MinIO Access Setup

```bash
# Port forward MinIO service
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000

# Setup MinIO client (in separate terminal)
mc alias set securecodebox http://localhost:9000 admin password
```

---

## Individual Scanner Documentation

### Naabu Scanner

#### Overview
Naabu is a fast port scanner written in Go that allows you to map valid ports for hosts in a reliable manner using SYN scans.

**Official Documentation**: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

#### Key Features
- Fast SYN scanning
- JSON output support
- All ports scanning capability
- Integration with SecureCodeBox

#### Usage Methods

##### Method 1: SCBCTL (Recommended)
```bash
# Basic scan
../naabu/run_naabu_scbctl.sh scanme.nmap.org

# With custom parameters
scbctl scan naabu --name my-scan --namespace securecodebox-system -- -host target.com -p - -json
```

##### Method 2: kubectl
```bash
# Using automation script
../naabu/run_naabu_working.sh scanme.nmap.org

# Manual YAML creation
kubectl apply -f naabu-scan.yaml
```

#### Scripts Available
- `run_naabu_scbctl.sh`: Modern SCBCTL approach
- `run_naabu_working.sh`: Traditional kubectl approach
- `run_naabu_final.sh`: Results display
- `run_naabu_mc.sh`: Manual MinIO upload

#### Example Output
```json
{
  "host": "45.33.32.156",
  "port": 80,
  "protocol": "tcp",
  "timestamp": "2025-01-27T10:30:00Z"
}
```

### TLSX Scanner

#### Overview
TLSX is a fast and configurable TLS grabber focused on TLS based data collection.

**Official Documentation**: [https://github.com/projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx)

#### Key Features
- TLS/SSL certificate analysis
- Multi-port scanning
- Certificate validation
- Security assessment

#### Usage

```bash
# Basic scan
../tlsx/run_tlsx_scan_multiport.sh scanme.nmap.org

# With specific ports
../tlsx/run_tlsx_scan_multiport.sh scanme.nmap.org -p 443,8443,9443
```

#### Scripts Available
- `run_tlsx_scan_multiport.sh`: Multi-port TLS scanning
- Manual YAML creation for custom configurations

#### Example Output
```json
{
  "host": "scanme.nmap.org",
  "port": 443,
  "tls_version": "TLS 1.3",
  "certificate": {
    "subject": "CN=scanme.nmap.org",
    "issuer": "CN=Let's Encrypt Authority X3",
    "validity": "2025-01-01 to 2025-04-01"
  }
}
```

### Nuclei Scanner

#### Overview
Nuclei is a fast, template based vulnerability scanner focusing on extensive configurability, massive extensibility and ease of use.

**Official Documentation**: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

#### Key Features
- Template-based scanning
- Multiple protocols (HTTP, TCP, DNS, etc.)
- Zero false positives
- Extensive template library

#### Deployment

```bash
# Install via Helm
helm upgrade --install nuclei oci://ghcr.io/securecodebox/helm/nuclei

# Verify installation
kubectl get scantypes | grep nuclei
```

#### Usage

```bash
# Basic scan
scbctl scan nuclei --name nuclei-scan -- -u https://target.com

# With templates
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -t cves/

# With severity filter
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

#### Common Templates
- `cves/`: Common Vulnerabilities and Exposures
- `vulnerabilities/`: General vulnerabilities
- `misconfiguration/`: Configuration issues
- `exposures/`: Information exposure

### ZAP Scanner

#### Overview
The OWASP Zed Attack Proxy (ZAP) is one of the world's most popular free security tools for web application security testing.

**Official Documentation**: [https://www.zaproxy.org/](https://www.zaproxy.org/)

#### Key Features
- Web application security testing
- Passive and active scanning
- API security testing
- Automation framework

#### Deployment

```bash
# Install via Helm
helm upgrade --install zap-automation-framework oci://ghcr.io/securecodebox/helm/zap-automation-framework

# Verify installation
kubectl get scantypes | grep zap
```

#### Usage

```bash
# Basic baseline scan
../zap-automation-framework/run_zap_scan.sh https://target.com

# Using scbctl
scbctl scan zap-baseline-scan --name zap-scan -- -t https://target.com
```

#### Scan Types
- **Baseline Scan**: Quick security assessment
- **Full Scan**: Comprehensive testing
- **API Scan**: API-specific testing
- **Custom**: Configurable automation framework

---

## Automation Scripts

### Cascading Scan Script

The main automation script `run_cascading_manual.sh` orchestrates a complete security assessment:

```bash
# Basic usage
./run_cascading_manual.sh scanme.nmap.org

# With all ports option
./run_cascading_manual.sh scanme.nmap.org --all-ports

# With custom namespace
./run_cascading_manual.sh scanme.nmap.org default
```

#### Workflow
1. **Naabu**: Port discovery (all ports)
2. **TLSX**: TLS certificate analysis on discovered ports
3. **Nuclei**: Vulnerability scanning on web services
4. **Results**: Consolidated findings in MinIO

### Individual Scanner Scripts

#### Naabu Scripts
```bash
# Primary script (SCBCTL)
../naabu/run_naabu_scbctl.sh target.com

# Alternative (kubectl)
../naabu/run_naabu_working.sh target.com

# Results display
../naabu/run_naabu_final.sh target.com
```

#### TLSX Scripts
```bash
# Multi-port scanning
../tlsx/run_tlsx_scan_multiport.sh target.com

# With specific ports
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443
```

#### ZAP Scripts
```bash
# Web application scan
../zap-automation-framework/run_zap_scan.sh https://target.com
```

---

## Script Usage Guide

### When to Use Each Script

#### 1. Complete Security Assessment
**Use**: `./run_cascading_manual.sh`
**When**: You want a comprehensive security assessment of a target
**What it does**: Runs Naabu → TLSX → Nuclei in sequence
**Best for**: Initial security audits, compliance assessments, penetration testing

```bash
# Basic usage
./run_cascading_manual.sh target.com

# With all ports option
./run_cascading_manual.sh target.com --all-ports

# Custom namespace
./run_cascading_manual.sh target.com default
```

#### 2. Port Discovery Only
**Use**: `../naabu/run_naabu_scbctl.sh` (Recommended)
**When**: You need to discover open ports on a target
**What it does**: Fast SYN scanning of all ports (1-65535)
**Best for**: Network reconnaissance, service discovery, initial assessment

```bash
# Basic port scan
../naabu/run_naabu_scbctl.sh target.com

# Results are automatically uploaded to MinIO
# Raw results available in /tmp/naabu-findings.json
```

#### 3. TLS Certificate Analysis
**Use**: `../tlsx/run_tlsx_scan_multiport.sh`
**When**: You need to analyze TLS/SSL certificates
**What it does**: Certificate validation, security assessment, multi-port scanning
**Best for**: SSL/TLS security audits, certificate management, compliance checks

```bash
# Basic TLS scan
../tlsx/run_tlsx_scan_multiport.sh target.com

# Specific ports only
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443
```

#### 4. Vulnerability Scanning
**Use**: `scbctl scan nuclei`
**When**: You need to find specific vulnerabilities
**What it does**: Template-based vulnerability scanning with zero false positives
**Best for**: Vulnerability assessment, CVE scanning, security research

```bash
# Basic vulnerability scan
scbctl scan nuclei --name nuclei-scan -- -u https://target.com

# Focus on CVEs only
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -t cves/

# High severity vulnerabilities only
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

#### 5. Web Application Security Testing
**Use**: `../zap-automation-framework/run_zap_scan.sh`
**When**: You need comprehensive web application security testing
**What it does**: Passive/active scanning, API testing, automation framework
**Best for**: Web app security audits, API security testing, OWASP compliance

```bash
# Basic web app scan
../zap-automation-framework/run_zap_scan.sh https://target.com

# Using scbctl directly
scbctl scan zap-baseline-scan --name zap-scan -- -t https://target.com
```

### Script Workflows

#### Workflow 1: Initial Assessment
```bash
# 1. Port discovery
../naabu/run_naabu_scbctl.sh target.com

# 2. TLS analysis on discovered ports
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443

# 3. Vulnerability scan on web services
scbctl scan nuclei --name nuclei-scan -- -u https://target.com

# 4. Web app security test
../zap-automation-framework/run_zap_scan.sh https://target.com
```

#### Workflow 2: Quick Security Check
```bash
# Single command for complete assessment
./run_cascading_manual.sh target.com
```

#### Workflow 3: Focused Testing
```bash
# Only TLS certificates
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443

# Only high-severity vulnerabilities
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

### Script Comparison

| Script | Purpose | Speed | Output | Best Use Case |
|--------|---------|-------|--------|---------------|
| `run_cascading_manual.sh` | Complete assessment | Slow | Comprehensive | Full security audit |
| `run_naabu_scbctl.sh` | Port discovery | Fast | Port list | Network reconnaissance |
| `run_tlsx_scan_multiport.sh` | TLS analysis | Medium | Certificate details | SSL/TLS security |
| `scbctl scan nuclei` | Vulnerability scan | Medium | CVE findings | Vulnerability assessment |
| `run_zap_scan.sh` | Web app testing | Slow | Security report | Web application security |

### Use Case Scenarios

#### Scenario 1: New Target Assessment
**Goal**: Complete security assessment of a new target
**Scripts**:
```bash
./run_cascading_manual.sh target.com
```

#### Scenario 2: Network Reconnaissance
**Goal**: Discover what services are running
**Scripts**:
```bash
../naabu/run_naabu_scbctl.sh target.com
```

#### Scenario 3: SSL/TLS Security Audit
**Goal**: Check certificate security
**Scripts**:
```bash
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443
```

#### Scenario 4: Vulnerability Assessment
**Goal**: Find security vulnerabilities
**Scripts**:
```bash
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

#### Scenario 5: Web Application Security
**Goal**: Test web application security
**Scripts**:
```bash
../zap-automation-framework/run_zap_scan.sh https://target.com
```

#### Scenario 6: Compliance Check
**Goal**: Meet security compliance requirements
**Scripts**:
```bash
# Run complete assessment
./run_cascading_manual.sh target.com

# Focus on specific compliance areas
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -tags compliance
```

### Performance Considerations

#### Fast Scans (Under 5 minutes)
- `../naabu/run_naabu_scbctl.sh` - Port discovery
- `../tlsx/run_tlsx_scan_multiport.sh` - TLS analysis (small port lists)

#### Medium Scans (5-30 minutes)
- `scbctl scan nuclei` - Vulnerability scanning
- `../tlsx/run_tlsx_scan_multiport.sh` - TLS analysis (large port lists)

#### Slow Scans (30+ minutes)
- `./run_cascading_manual.sh` - Complete assessment
- `../zap-automation-framework/run_zap_scan.sh` - Web app testing

### Customization Options

#### Naabu Customization
```bash
# Custom ports only
scbctl scan naabu --name naabu-scan -- -host target.com -p 80,443,8080 -json

# Rate limiting
scbctl scan naabu --name naabu-scan -- -host target.com -rate 1000 -json
```

#### TLSX Customization
```bash
# Specific ports
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443

# Custom timeout
scbctl scan tlsx --name tlsx-scan -- -host target.com -timeout 10 -json
```

#### Nuclei Customization
```bash
# Specific templates
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -t cves/2023/

# Custom headers
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -H "Authorization: Bearer token"

# Rate limiting
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -rate 150
```

#### ZAP Customization
```bash
# Custom configuration
scbctl scan zap-baseline-scan --name zap-scan -- -t https://target.com -c custom-config.yaml

# API scanning
scbctl scan zap-api-scan --name zap-scan -- -t https://target.com/api
```

---

## Cascading Scans

### Overview
Cascading scans combine multiple scanners in a coordinated workflow to provide comprehensive security assessment.

### Workflow Steps

1. **Port Discovery (Naabu)**
   - Scans all ports (1-65535)
   - Identifies open services
   - Generates port list for next steps

2. **TLS Analysis (TLSX)**
   - Analyzes TLS certificates on discovered ports
   - Validates certificate security
   - Identifies SSL/TLS vulnerabilities

3. **Vulnerability Scanning (Nuclei)**
   - Scans web services for vulnerabilities
   - Uses template-based detection
   - Provides detailed findings

4. **Web Application Testing (ZAP)**
   - Comprehensive web app security testing
   - API security assessment
   - Detailed vulnerability reports

### Execution

```bash
# Run complete cascading scan
./run_cascading_manual.sh target.com

# Monitor progress
kubectl get scans -n securecodebox-system

# Check results
kubectl logs -n securecodebox-system -l job-name=parse-scan-name
```

---

## Results and Reporting

### MinIO Storage
All scan results are automatically stored in MinIO with the following structure:

```
securecodebox-system/
├── scan-{scan-uid}/
│   ├── raw-results.json
│   ├── findings.json
│   └── reports/
```

### Accessing Results

```bash
# List scans
mc ls securecodebox/securecodebox-system/

# Download results
mc cp securecodebox/securecodebox-system/scan-{uid}/findings.json ./local-results.json

# View in browser
# http://localhost:9001 (if port-forwarded)
```

### Result Formats

#### Naabu Results
```json
{
  "name": "naabu-scan",
  "findings": [
    {
      "host": "target.com",
      "port": 80,
      "protocol": "tcp",
      "severity": "info"
    }
  ]
}
```

#### TLSX Results
```json
{
  "name": "tlsx-scan",
  "findings": [
    {
      "host": "target.com",
      "port": 443,
      "tls_version": "TLS 1.3",
      "certificate_valid": true,
      "severity": "info"
    }
  ]
}
```

#### Nuclei Results
```json
{
  "name": "nuclei-scan",
  "findings": [
    {
      "template": "cves/2023/CVE-2023-1234.yaml",
      "host": "target.com",
      "severity": "high",
      "description": "Vulnerability description"
    }
  ]
}
```

#### ZAP Results
```json
{
  "name": "zap-scan",
  "findings": [
    {
      "alert": "XSS Vulnerability",
      "risk": "High",
      "url": "https://target.com/vulnerable-page",
      "description": "Cross-site scripting vulnerability"
    }
  ]
}
```

---

## Quick Reference Commands

### 🚀 Quick Start Commands

#### Setup
```bash
# Apply all scanner types
./apply_scanner_types.sh

# Setup MinIO access
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
mc alias set securecodebox http://localhost:9000 admin password
```

#### Cascading Scan (Complete Assessment)
```bash
# Full security assessment
./run_cascading_manual.sh target.com

# With all ports option
./run_cascading_manual.sh target.com --all-ports
```

### 📋 Individual Scanner Commands

#### Naabu (Port Scanner)
```bash
# SCBCTL method (recommended)
../naabu/run_naabu_scbctl.sh target.com

# kubectl method
../naabu/run_naabu_working.sh target.com

# View results
../naabu/run_naabu_final.sh target.com
```

#### TLSX (TLS Certificate Scanner)
```bash
# Basic scan
../tlsx/run_tlsx_scan_multiport.sh target.com

# Specific ports
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443
```

#### Nuclei (Vulnerability Scanner)
```bash
# Basic scan
scbctl scan nuclei --name nuclei-scan -- -u https://target.com

# With specific templates
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -t cves/

# High severity only
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

#### ZAP (Web Application Scanner)
```bash
# Baseline scan
../zap-automation-framework/run_zap_scan.sh https://target.com

# Using scbctl
scbctl scan zap-baseline-scan --name zap-scan -- -t https://target.com
```

### 🔍 Monitoring Commands

#### Check Scan Status
```bash
# List all scans
kubectl get scans -n securecodebox-system

# Check specific scan
kubectl get scan scan-name -n securecodebox-system

# View scan logs
kubectl logs -n securecodebox-system -l job-name=scan-scan-name
```

#### Check Parser Status
```bash
# List parser pods
kubectl get pods -n securecodebox-system | grep parse

# View parser logs
kubectl logs -n securecodebox-system parse-scan-name
```

#### Access Results
```bash
# List MinIO buckets
mc ls securecodebox/

# Download results
mc cp securecodebox/securecodebox-system/scan-{uid}/findings.json ./results.json

# View in browser
# http://localhost:9001 (if port-forwarded)
```

### 🎯 Use Cases

#### Quick Port Scan
```bash
../naabu/run_naabu_scbctl.sh target.com
```

#### TLS Certificate Check
```bash
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443
```

#### Web Application Security
```bash
../zap-automation-framework/run_zap_scan.sh https://target.com
```

#### Vulnerability Assessment
```bash
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

#### Complete Security Assessment
```bash
./run_cascading_manual.sh target.com
```

### 📊 Script Summary

| Scanner | Primary Script | Alternative Script | Purpose |
|---------|----------------|-------------------|---------|
| **Naabu** | `run_naabu_scbctl.sh` | `run_naabu_working.sh` | Port discovery |
| **TLSX** | `run_tlsx_scan_multiport.sh` | Manual YAML | TLS analysis |
| **Nuclei** | `scbctl scan nuclei` | Helm deployment | Vulnerability scanning |
| **ZAP** | `run_zap_scan.sh` | `scbctl scan zap-baseline-scan` | Web app testing |
| **Cascading** | `run_cascading_manual.sh` | - | Complete assessment |

### 📝 Output Locations

#### MinIO Structure
```
securecodebox-system/
├── scan-{scan-uid}/
│   ├── raw-results.json    # Raw scanner output
│   ├── findings.json       # Parsed findings
│   └── reports/            # Additional reports
```

#### Local Files
- `/tmp/naabu-findings.json` - Naabu results
- `/tmp/tlsx-findings.json` - TLSX results
- `cascading_results_*/` - Cascading scan results

---

## Troubleshooting

### Common Issues

#### 1. Scanner Not Found
```bash
# Check scanner types
kubectl get scantypes -n securecodebox-system

# Reapply if missing
./apply_scanner_types.sh
```

#### 2. Parser Issues
```bash
# Check parser pods
kubectl get pods -n securecodebox-system | grep parse

# View parser logs
kubectl logs -n securecodebox-system parse-scan-name
```

#### 3. MinIO Access Issues
```bash
# Check MinIO service
kubectl get svc -n securecodebox-system | grep minio

# Restart port-forward
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
```

#### 4. Scan Timeout
```bash
# Check scan status
kubectl get scans -n securecodebox-system

# View scan logs
kubectl logs -n securecodebox-system -l job-name=scan-scan-name
```

### Debug Commands

```bash
# Check all resources
kubectl get all -n securecodebox-system

# Check events
kubectl get events -n securecodebox-system --sort-by='.lastTimestamp'

# Check operator logs
kubectl logs -n securecodebox-system deployment/securecodebox-operator
```

### Performance Optimization

1. **Resource Limits**: Adjust CPU/memory limits in scanner configurations
2. **Concurrency**: Limit concurrent scans to prevent resource exhaustion
3. **Timeouts**: Set appropriate timeouts for long-running scans
4. **Storage**: Ensure adequate MinIO storage for results





## Project Structure

```
scanners/
├── UNIFIED_SCANNER_DOCUMENTATION.md      # This file
├── apply_scanner_types.sh                # Setup script
├── run_cascading_manual.sh               # Complete assessment
├── naabu/                                # Naabu scanner
│   ├── run_naabu_scbctl.sh               # SCBCTL automation
│   ├── run_naabu_working.sh              # kubectl automation
│   └── FINAL_SUMMARY.md                  # Integration report
├── tlsx/                                 # TLSX scanner
│   ├── run_tlsx_scan_multiport.sh        # Multi-port scanning
│   └── scantype-tlsx.yaml                # Scanner definition
├── nuclei/                               # Nuclei scanner
│   ├── README.md                         # Scanner documentation
│   └── values.yaml                       # Helm configuration
└── zap-automation-framework/             # ZAP scanner
    ├── run_zap_scan.sh                   # Web app scanning
    └── README.md                         # Scanner documentation
```

---

## 🔗 Official Documentation Links

- **Naabu**: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)
- **TLSX**: [https://github.com/projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx)
- **Nuclei**: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)
- **ZAP**: [https://www.zaproxy.org/](https://www.zaproxy.org/)
- **SecureCodeBox**: [https://www.securecodebox.io/](https://www.securecodebox.io/)

---

## Conclusion

This SecureCodeBox scanner setup provides a comprehensive security assessment platform with:

- ✅ **Four specialized scanners** covering different security aspects
- ✅ **Automated workflows** for efficient scanning
- ✅ **Integrated reporting** with MinIO storage
- ✅ **Production-ready scripts** for various use cases
- ✅ **Comprehensive documentation** for all components

The system is designed for both individual scanner usage and coordinated cascading scans, providing flexibility for different security assessment needs.

**Status**: ✅ **All scanners are production-ready and fully integrated with SecureCodeBox**

- **Naabu**: ✅ SCBCTL + kubectl support
- **TLSX**: ✅ kubectl automation
- **Nuclei**: ✅ SCBCTL integration
- **ZAP**: ✅ Automation framework
- **Cascading**: ✅ Complete workflow

---

**Last Updated**: January 2025  
**Version**: 1.0.0  
**Status**: Production Ready 