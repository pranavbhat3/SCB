# SecureCodeBox Scanner Suite

## 🚀 Overview

This repository contains a comprehensive security scanning suite built on SecureCodeBox, featuring four specialized scanners for complete security assessment:

- **🔍 Naabu**: Fast port scanner for network reconnaissance
- **🔒 TLSX**: TLS/SSL certificate analyzer
- **⚡ Nuclei**: Template-based vulnerability scanner
- **🕷️ ZAP**: Web application security testing

## 📚 Documentation

### 📖 [Comprehensive Documentation](COMPREHENSIVE_SCANNER_DOCUMENTATION.md)
Complete guide covering all aspects of the scanner setup, including:
- Detailed scanner descriptions
- Setup and installation instructions
- Individual scanner documentation
- Automation scripts
- Cascading scans
- Results and reporting
- Troubleshooting

### ⚡ [Quick Reference Guide](QUICK_REFERENCE_GUIDE.md)
Fast access to common commands and scripts:
- Quick start commands
- Individual scanner commands
- Monitoring commands
- Troubleshooting commands
- Performance tips

### 🎯 [Script Usage Guide](SCRIPT_USAGE_GUIDE.md)
Detailed guide explaining when to use each script:
- Use case scenarios
- Script workflows
- Performance considerations
- Customization options
- Best practices

## 🛠️ Quick Start

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

## 📊 Scanner Capabilities

| Scanner | Purpose | Speed | Output | Integration |
|---------|---------|-------|--------|-------------|
| **Naabu** | Port discovery | Fast | Port list | SCBCTL + kubectl |
| **TLSX** | TLS analysis | Medium | Certificate details | kubectl |
| **Nuclei** | Vulnerability scan | Medium | CVE findings | SCBCTL |
| **ZAP** | Web app testing | Slow | Security report | SCBCTL + kubectl |

## 🔗 Official Documentation Links

- **Naabu**: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)
- **TLSX**: [https://github.com/projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx)
- **Nuclei**: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)
- **ZAP**: [https://www.zaproxy.org/](https://www.zaproxy.org/)
- **SecureCodeBox**: [https://www.securecodebox.io/](https://www.securecodebox.io/)

## 📁 Project Structure

```
scanners/
├── COMPREHENSIVE_SCANNER_DOCUMENTATION.md  # Complete documentation
├── QUICK_REFERENCE_GUIDE.md               # Quick commands
├── SCRIPT_USAGE_GUIDE.md                  # Script usage guide
├── README.md                              # This file
├── apply_scanner_types.sh                 # Setup script
├── run_cascading_manual.sh                # Complete assessment
├── naabu/                                 # Naabu scanner
│   ├── run_naabu_scbctl.sh               # SCBCTL automation
│   ├── run_naabu_working.sh              # kubectl automation
│   └── FINAL_SUMMARY.md                  # Integration report
├── tlsx/                                  # TLSX scanner
│   ├── run_tlsx_scan_multiport.sh        # Multi-port scanning
│   └── scantype-tlsx.yaml                # Scanner definition
├── nuclei/                                # Nuclei scanner
│   ├── README.md                         # Scanner documentation
│   └── values.yaml                       # Helm configuration
└── zap-automation-framework/             # ZAP scanner
    ├── run_zap_scan.sh                   # Web app scanning
    └── README.md                         # Scanner documentation
```

## 🎯 Use Cases

### 🚀 Quick Security Check
```bash
./run_cascading_manual.sh target.com
```

### 🔍 Network Reconnaissance
```bash
../naabu/run_naabu_scbctl.sh target.com
```

### 🔒 SSL/TLS Security Audit
```bash
../tlsx/run_tlsx_scan_multiport.sh target.com -p 443,8443,9443
```

### ⚡ Vulnerability Assessment
```bash
scbctl scan nuclei --name nuclei-scan -- -u https://target.com -severity high,critical
```

### 🕷️ Web Application Security
```bash
../zap-automation-framework/run_zap_scan.sh https://target.com
```

## 📈 Results and Reporting

All scan results are automatically stored in MinIO with structured output:

```bash
# Access results
mc ls securecodebox/securecodebox-system/

# Download findings
mc cp securecodebox/securecodebox-system/scan-{uid}/findings.json ./results.json

# View in browser
# http://localhost:9001 (if port-forwarded)
```

## 🛠️ Troubleshooting

### Common Issues
```bash
# Scanner not found
kubectl get scantypes -n securecodebox-system
./apply_scanner_types.sh

# MinIO access issues
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000

# Check scan status
kubectl get scans -n securecodebox-system
```

### Debug Commands
```bash
# Check all resources
kubectl get all -n securecodebox-system

# View events
kubectl get events -n securecodebox-system --sort-by='.lastTimestamp'

# Check operator logs
kubectl logs -n securecodebox-system deployment/securecodebox-operator
```

## 🔧 Customization

### Performance Tuning
- **Concurrent Scans**: Limit to 2-3 concurrent scans
- **Resource Limits**: Monitor CPU/memory usage
- **Timeouts**: Set appropriate timeouts for large targets
- **Storage**: Ensure adequate MinIO storage

### Security Considerations
- **Authorization**: Always ensure permission to scan targets
- **Rate Limiting**: Use appropriate rate limits
- **Documentation**: Document all scanning activities
- **Compliance**: Follow relevant security standards

## 📞 Support

For additional support:
1. Check the [Comprehensive Documentation](COMPREHENSIVE_SCANNER_DOCUMENTATION.md)
2. Review the [Troubleshooting](COMPREHENSIVE_SCANNER_DOCUMENTATION.md#troubleshooting) section
3. Use the [Quick Reference Guide](QUICK_REFERENCE_GUIDE.md) for common commands
4. Refer to the [Script Usage Guide](SCRIPT_USAGE_GUIDE.md) for specific scenarios

## 🎉 Status

**✅ All scanners are production-ready and fully integrated with SecureCodeBox**

- **Naabu**: ✅ SCBCTL + kubectl support
- **TLSX**: ✅ kubectl automation
- **Nuclei**: ✅ SCBCTL integration
- **ZAP**: ✅ Automation framework
- **Cascading**: ✅ Complete workflow

---

**Last Updated**: January 2025  
**Version**: 1.0.0  
**Status**: Production Ready 