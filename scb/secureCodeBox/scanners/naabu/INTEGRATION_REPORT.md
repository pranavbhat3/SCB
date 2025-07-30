# NAABU Scanner Integration Report

## Overview
Successfully integrated the `naabu` port scanner into SecureCodeBox with full Kubernetes-native workflow, automated parsing, and MinIO storage integration. **Both kubectl and scbctl approaches are working!**

## Components Created

### 1. ScanType Definition
**File**: `scantype-naabu.yaml`
- Defines naabu scanner with proper command and arguments
- Uses `naabu` command with JSON output format
- Outputs to `/home/securecodebox/raw-results.json`

### 2. Parser Implementation
**File**: `parser/parser.js`
- Node.js parser that reads JSON lines from naabu output
- Generates structured findings with proper metadata
- Handles MinIO URLs for input
- Outputs findings to `/home/securecodebox/findings.json`

**File**: `parser/Dockerfile`
- Multi-stage build for optimized parser image
- Uses Node.js 18-alpine base
- Proper ENTRYPOINT for argument handling

**File**: `parser/parsedefinition-naabu.yaml`
- Defines ParseDefinition for naabu results
- Maps to `naabu-json` result type
- Uses `contentType: Text` for proper parsing

### 3. Automation Scripts

#### Primary Working Scripts
**File**: `run_naabu_scbctl.sh` ⭐ **NEW - SCBCTL VERSION**
- **Status**: ✅ **WORKING WITH SCBCTL**
- **Function**: Complete end-to-end automation using scbctl
- **Features**:
  - Uses `scbctl scan naabu` command
  - Creates naabu scan with target parameter
  - Waits for scan completion
  - Extracts findings from parser logs
  - Uploads to MinIO using mc client
  - Provides detailed logging and error handling

**File**: `run_naabu_working.sh`
- **Status**: ✅ **WORKING**
- **Function**: Complete end-to-end automation using kubectl
- **Features**:
  - Creates naabu scan with target parameter
  - Waits for scan completion
  - Extracts findings from parser logs
  - Uploads to MinIO using mc client
  - Provides detailed logging and error handling

#### Alternative Scripts
- `run_naabu_final.sh`: Shows parser output and MinIO URLs
- `run_naabu_mc.sh`: Manual PVC extraction with mc upload
- `run_naabu_simple.sh`: Basic scan execution

## Integration Workflow

### 1. Scan Execution (SCBCTL)
```bash
# Create scan with scbctl
scbctl scan naabu --name naabu-scan-xxx --namespace securecodebox-system -- -host scanme.nmap.org -json -o /home/securecodebox/raw-results.json

# Monitor progress
kubectl get scan naabu-scan-xxx -n securecodebox-system
```

### 2. Scan Execution (KUBECTL)
```bash
# Create scan with kubectl
kubectl apply -f scan.yaml

# Monitor progress
kubectl get scan naabu-scan-xxx -n securecodebox-system
```

### 3. Parser Processing
- Parser pod downloads raw results from MinIO
- Processes JSON lines into structured findings
- Generates 3 findings per scan (ports 21, 22, 80 for scanme.nmap.org)

### 4. Findings Storage
- Findings automatically uploaded to MinIO by SecureCodeBox
- Manual extraction available via parser logs
- MC client upload for custom filenames

## Test Results

### Target: scanme.nmap.org
**Findings Generated**:
1. **Port 21**: FTP service on 45.33.32.156
2. **Port 22**: SSH service on 45.33.32.156  
3. **Port 80**: HTTP service on 45.33.32.156

**Output Format**:
```json
{
  "name": "Open port 80 on 45.33.32.156",
  "description": "Port 80 is open on host 45.33.32.156",
  "category": "Open Port",
  "location": "45.33.32.156:80",
  "osi_layer": "NETWORK",
  "severity": "INFORMATIONAL",
  "attributes": {
    "host": "scanme.nmap.org",
    "ip": "45.33.32.156",
    "timestamp": "2025-07-19T04:54:49.83178824Z",
    "port": 80,
    "protocol": "tcp",
    "tls": false
  }
}
```

## Usage Instructions

### Quick Start with SCBCTL (Recommended)
```bash
# Run with default target (scanme.nmap.org)
../naabu/run_naabu_scbctl.sh

# Run with custom target
../naabu/run_naabu_scbctl.sh example.com
```

### Quick Start with KUBECTL
```bash
# Run with default target (scanme.nmap.org)
../naabu/run_naabu_working.sh

# Run with custom target
../naabu/run_naabu_working.sh example.com
```

### Manual Steps
1. Apply ScanType and ParseDefinition
2. Create scan with target parameter (scbctl or kubectl)
3. Wait for completion
4. Extract findings from parser logs
5. Upload to MinIO using mc client

## MinIO Integration

### Access Method
```bash
# Port forward MinIO
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000

# Setup mc client
mc alias set securecodebox http://localhost:9000 admin password

# List files
mc ls securecodebox/securecodebox/ | grep naabu
```

### File Naming
- Format: `naabu-findings-{target}-{timestamp}.json`
- Example: `naabu-findings-scanme_nmap_org-20250719_051230.json`

## SCBCTL Integration

### Installation
```bash
# Build scbctl
cd /home/pranav/scb/secureCodeBox/scbctl
go build -o scbctl .
sudo mv scbctl /usr/local/bin/scbctl
```

### Usage
```bash
# Create scan
scbctl scan naabu --name my-scan --namespace securecodebox-system -- -host example.com -json

# Follow logs
scbctl scan naabu --follow -- -host example.com -json
```

## Troubleshooting

### Common Issues
1. **Parser not triggered**: Check ParseDefinition name matches result type
2. **Volume mount errors**: Ensure PVC names match between scan and parser
3. **MinIO access denied**: Use mc client instead of direct curl
4. **Findings not found**: Extract from parser logs, not PVC
5. **scbctl not found**: Build and install scbctl binary

### Debug Commands
```bash
# Check scan status
kubectl get scan naabu-scan-xxx -n securecodebox-system

# View parser logs
kubectl logs parse-naabu-scan-xxx -n securecodebox-system

# Check MinIO files
mc ls securecodebox/securecodebox/ | grep naabu

# Test scbctl
scbctl scan --help
```

## Files Summary

| File | Purpose | Status |
|------|---------|--------|
| `scantype-naabu.yaml` | Scanner definition | ✅ Working |
| `parser/parser.js` | Results parser | ✅ Working |
| `parser/Dockerfile` | Parser image | ✅ Working |
| `parser/parsedefinition-naabu.yaml` | Parser definition | ✅ Working |
| `run_naabu_scbctl.sh` | **SCBCTL automation script** | ✅ **WORKING** |
| `run_naabu_working.sh` | kubectl automation script | ✅ Working |
| `run_naabu_final.sh` | Alternative script | ✅ Working |
| `run_naabu_mc.sh` | MC upload script | ✅ Working |
| `run_naabu_simple.sh` | Basic script | ✅ Working |

## Backup Location
All files have been backed up to: `../naabu/naabu-securecodebox-backup/`

## Conclusion

The naabu scanner integration is **complete and fully functional** with both kubectl and scbctl approaches working perfectly. The scanner successfully:
- Runs port scans on specified targets using scbctl or kubectl
- Parses results into structured findings
- Stores findings in MinIO automatically
- Provides automation scripts for easy usage
- Supports both modern scbctl CLI and traditional kubectl approaches

The integration follows SecureCodeBox best practices and matches the working tlsx scanner pattern.

**Integration Date**: July 19, 2025
**Status**: ✅ **PRODUCTION READY WITH SCBCTL SUPPORT** 