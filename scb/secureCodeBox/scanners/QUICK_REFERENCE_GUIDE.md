# SecureCodeBox Scanner Quick Reference Guide

## 🚀 Quick Start Commands

### Setup
```bash
# Apply all scanner types
./apply_scanner_types.sh

# Setup MinIO access
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
mc alias set securecodebox http://localhost:9000 admin password
```

### Cascading Scan (Complete Assessment)
```bash
# Full security assessment
./run_cascading_manual.sh target.com

# With all ports option
./run_cascading_manual.sh target.com --all-ports
```

---

## 📋 Individual Scanner Commands

### Naabu (Port Scanner)
```bash
# SCBCTL method (recommended)
../naabu/run_naabu_scbctl.sh target.com

# kubectl method
../naabu/run_naabu_working.sh target.com

# View results
../naabu/run_naabu_final.sh target.com
```

### TLSX (TLS Certificate Scanner)
```bash
# Basic scan
../tlsx/run_tlsx_scan_multiport.sh target.com

# Specific ports
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443
```

### Nuclei (Vulnerability Scanner)
```bash
# Basic scan
scbctl scan nuclei --name nuclei-scan -- -u https://target.com

# With specific templates
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -t cves/

# High severity only
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

### ZAP (Web Application Scanner)
```bash
# Baseline scan
../zap-automation-framework/run_zap_scan.sh https://target.com

# Using scbctl
scbctl scan zap-baseline-scan --name zap-scan -- -t https://target.com
```

---

## 🔍 Monitoring Commands

### Check Scan Status
```bash
# List all scans
kubectl get scans -n securecodebox-system

# Check specific scan
kubectl get scan scan-name -n securecodebox-system

# View scan logs
kubectl logs -n securecodebox-system -l job-name=scan-scan-name
```

### Check Parser Status
```bash
# List parser pods
kubectl get pods -n securecodebox-system | grep parse

# View parser logs
kubectl logs -n securecodebox-system parse-scan-name
```

### Access Results
```bash
# List MinIO buckets
mc ls securecodebox/

# Download results
mc cp securecodebox/securecodebox-system/scan-{uid}/findings.json ./results.json

# View in browser
# http://localhost:9001 (if port-forwarded)
```

---

## 🛠️ Troubleshooting Commands

### Common Issues
```bash
# Scanner not found
kubectl get scantypes -n securecodebox-system
./apply_scanner_types.sh

# MinIO access issues
kubectl get svc -n securecodebox-system | grep minio
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000

# Check all resources
kubectl get all -n securecodebox-system

# View events
kubectl get events -n securecodebox-system --sort-by='.lastTimestamp'
```

---

## 📊 Script Summary

| Scanner | Primary Script | Alternative Script | Purpose |
|---------|----------------|-------------------|---------|
| **Naabu** | `run_naabu_scbctl.sh` | `run_naabu_working.sh` | Port discovery |
| **TLSX** | `run_tlsx_scan_multiport.sh` | Manual YAML | TLS analysis |
| **Nuclei** | `scbctl scan nuclei` | Helm deployment | Vulnerability scanning |
| **ZAP** | `run_zap_scan.sh` | `scbctl scan zap-baseline-scan` | Web app testing |
| **Cascading** | `run_cascading_manual.sh` | - | Complete assessment |

---

## 🎯 Use Cases

### Quick Port Scan
```bash
../naabu/run_naabu_scbctl.sh target.com
```

### TLS Certificate Check
```bash
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443
```

### Web Application Security
```bash
../zap-automation-framework/run_zap_scan.sh https://target.com
```

### Vulnerability Assessment
```bash
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

### Complete Security Assessment
```bash
./run_cascading_manual.sh target.com
```

---

## 📝 Output Locations

### MinIO Structure
```
securecodebox-system/
├── scan-{scan-uid}/
│   ├── raw-results.json    # Raw scanner output
│   ├── findings.json       # Parsed findings
│   └── reports/            # Additional reports
```

### Local Files
- `/tmp/naabu-findings.json` - Naabu results
- `/tmp/tlsx-findings.json` - TLSX results
- `cascading_results_*/` - Cascading scan results

---

## ⚡ Performance Tips

1. **Concurrent Scans**: Limit to 2-3 concurrent scans
2. **Resource Limits**: Monitor CPU/memory usage
3. **Timeouts**: Set appropriate timeouts for large targets
4. **Storage**: Ensure adequate MinIO storage

---

## 🔗 Useful Links

- **Naabu**: https://github.com/projectdiscovery/nuclei
- **TLSX**: https://github.com/projectdiscovery/tlsx
- **Nuclei**: https://github.com/projectdiscovery/nuclei
- **ZAP**: https://www.zaproxy.org/
- **SecureCodeBox**: https://www.securecodebox.io/ 