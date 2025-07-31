# SecureCodeBox Script Usage Guide

## 📋 Overview

This guide explains when to use each script in your SecureCodeBox scanner setup, providing context and examples for different scenarios.

---

## 🎯 When to Use Each Script

### 1. Complete Security Assessment

**Use**: `./run_cascading_manual.sh`
**When**: You want a comprehensive security assessment of a target
**What it does**: Runs Naabu → TLSX → Nuclei in sequence
**Best for**: Initial security audits, compliance assessments, penetration testing

```bash
# Basic usage
./run_cascading_manual.sh target.com

# With all ports scanning
./run_cascading_manual.sh target.com --all-ports

# Custom namespace
./run_cascading_manual.sh target.com default
```

**Output**: Complete findings in MinIO with structured results

---

### 2. Port Discovery Only

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

**Alternative**: `../naabu/run_naabu_working.sh` (kubectl method)

---

### 3. TLS Certificate Analysis

**Use**: `../tlsx/run_tlsx_scan_multiport.sh`
**When**: You need to analyze TLS/SSL certificates
**What it does**: Certificate validation, security assessment, multi-port scanning
**Best for**: SSL/TLS security audits, certificate management, compliance checks

```bash
# Basic TLS scan
../tlsx/run_tlsx_scan_multiport.sh target.com

# Specific ports only
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443

# Results show certificate details, validity, security issues
```

---

### 4. Vulnerability Scanning

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

# Specific vulnerability types
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -tags xss,sqli
```

---

### 5. Web Application Security Testing

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

---

## 🔄 Script Workflows

### Workflow 1: Initial Assessment
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

### Workflow 2: Quick Security Check
```bash
# Single command for complete assessment
./run_cascading_manual.sh target.com
```

### Workflow 3: Focused Testing
```bash
# Only TLS certificates
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443

# Only high-severity vulnerabilities
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

---

## 📊 Script Comparison

| Script | Purpose | Speed | Output | Best Use Case |
|--------|---------|-------|--------|---------------|
| `run_cascading_manual.sh` | Complete assessment | Slow | Comprehensive | Full security audit |
| `run_naabu_scbctl.sh` | Port discovery | Fast | Port list | Network reconnaissance |
| `run_tlsx_scan_multiport.sh` | TLS analysis | Medium | Certificate details | SSL/TLS security |
| `scbctl scan nuclei` | Vulnerability scan | Medium | CVE findings | Vulnerability assessment |
| `run_zap_scan.sh` | Web app testing | Slow | Security report | Web application security |

---

## 🎯 Use Case Scenarios

### Scenario 1: New Target Assessment
**Goal**: Complete security assessment of a new target
**Scripts**:
```bash
./run_cascading_manual.sh target.com
```

### Scenario 2: Network Reconnaissance
**Goal**: Discover what services are running
**Scripts**:
```bash
../naabu/run_naabu_scbctl.sh target.com
```

### Scenario 3: SSL/TLS Security Audit
**Goal**: Check certificate security
**Scripts**:
```bash
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443
```

### Scenario 4: Vulnerability Assessment
**Goal**: Find security vulnerabilities
**Scripts**:
```bash
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

### Scenario 5: Web Application Security
**Goal**: Test web application security
**Scripts**:
```bash
../zap-automation-framework/run_zap_scan.sh https://target.com
```

### Scenario 6: Compliance Check
**Goal**: Meet security compliance requirements
**Scripts**:
```bash
# Run complete assessment
./run_cascading_manual.sh target.com

# Focus on specific compliance areas
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -tags compliance
```

---

## ⚡ Performance Considerations

### Fast Scans (Under 5 minutes)
- `../naabu/run_naabu_scbctl.sh` - Port discovery
- `../tlsx/run_tlsx_scan_multiport.sh` - TLS analysis (small port lists)

### Medium Scans (5-30 minutes)
- `scbctl scan nuclei` - Vulnerability scanning
- `../tlsx/run_tlsx_scan_multiport.sh` - TLS analysis (large port lists)

### Slow Scans (30+ minutes)
- `./run_cascading_manual.sh` - Complete assessment
- `../zap-automation-framework/run_zap_scan.sh` - Web app testing

---

## 🔧 Customization Options

### Naabu Customization
```bash
# Custom ports only
scbctl scan naabu --name naabu-scan -- -host target.com -p 80,443,8080 -json

# Rate limiting
scbctl scan naabu --name naabu-scan -- -host target.com -rate 1000 -json
```

### TLSX Customization
```bash
# Specific ports
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443

# Custom timeout
scbctl scan tlsx --name tlsx-scan -- -host target.com -timeout 10 -json
```

### Nuclei Customization
```bash
# Specific templates
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -t cves/2023/

# Custom headers
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -H "Authorization: Bearer token"

# Rate limiting
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -rate 150
```

### ZAP Customization
```bash
# Custom configuration
scbctl scan zap-baseline-scan --name zap-scan -- -t https://target.com -c custom-config.yaml

# API scanning
scbctl scan zap-api-scan --name zap-scan -- -t https://target.com/api
```

---

## 🚨 Important Notes

### Security Considerations
1. **Authorization**: Always ensure you have permission to scan targets
2. **Rate Limiting**: Use appropriate rate limits to avoid overwhelming targets
3. **Documentation**: Document all scanning activities
4. **Compliance**: Follow relevant security standards and regulations

### Technical Considerations
1. **Resources**: Monitor CPU/memory usage during scans
2. **Storage**: Ensure adequate MinIO storage for results
3. **Network**: Consider network bandwidth and firewall rules
4. **Timeouts**: Set appropriate timeouts for large targets

### Best Practices
1. **Start Small**: Begin with focused scans before running complete assessments
2. **Monitor Progress**: Use monitoring commands to track scan progress
3. **Backup Results**: Regularly backup important scan results
4. **Update Regularly**: Keep scanners and templates updated

---

## 📞 Support

For issues or questions:
1. Check the troubleshooting section in the main documentation
2. Review scan logs using kubectl commands
3. Verify scanner types are properly installed
4. Ensure MinIO access is configured correctly 