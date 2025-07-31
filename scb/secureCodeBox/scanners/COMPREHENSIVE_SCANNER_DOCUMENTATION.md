# SecureCodeBox Scanner Documentation

## Table of Contents
1. [Overview](#overview)
2. [Scanner Types](#scanner-types)
3. [Setup and Installation](#setup-and-installation)
4. [Individual Scanner Documentation](#individual-scanner-documentation)
5. [Automation Scripts](#automation-scripts)
6. [Cascading Scans](#cascading-scans)
7. [Results and Reporting](#results-and-reporting)
8. [Troubleshooting](#troubleshooting)

---

## Overview

This documentation covers the comprehensive scanner setup in your SecureCodeBox environment. The system includes four main scanners:

- **Naabu**: Fast port scanner for network reconnaissance
- **TLSX**: TLS/SSL certificate scanner
- **Nuclei**: Template-based vulnerability scanner
- **ZAP**: Web application security scanner

All scanners are integrated with SecureCodeBox and can be used individually or in cascading workflows.

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

---

## Best Practices

### Security Scanning
1. **Authorization**: Ensure you have permission to scan targets
2. **Rate Limiting**: Avoid overwhelming target systems
3. **Documentation**: Document all scanning activities
4. **Compliance**: Follow relevant security standards

### Operational Practices
1. **Monitoring**: Monitor scan execution and resource usage
2. **Backup**: Regularly backup scan configurations and results
3. **Updates**: Keep scanners and templates updated
4. **Testing**: Test new configurations in non-production environments

### Integration Practices
1. **CI/CD**: Integrate scans into development pipelines
2. **Automation**: Use automation scripts for consistent execution
3. **Reporting**: Generate regular security reports
4. **Remediation**: Track and remediate identified vulnerabilities

---

## Conclusion

This SecureCodeBox scanner setup provides a comprehensive security assessment platform with:

- ✅ **Four specialized scanners** covering different security aspects
- ✅ **Automated workflows** for efficient scanning
- ✅ **Integrated reporting** with MinIO storage
- ✅ **Production-ready scripts** for various use cases
- ✅ **Comprehensive documentation** for all components

The system is designed for both individual scanner usage and coordinated cascading scans, providing flexibility for different security assessment needs.

For additional support or questions, refer to the individual scanner documentation or the SecureCodeBox community resources. 