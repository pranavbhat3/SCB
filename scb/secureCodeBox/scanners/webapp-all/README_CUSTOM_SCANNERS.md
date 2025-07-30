# Custom Scanner Setup for SecureCodeBox

This directory contains a setup script to install custom TLSX and Naabu scanners for SecureCodeBox.

## What This Setup Does

The `setup_custom_scanners.sh` script applies the following Kubernetes resources:

### TLSX Scanner
- **ScanType**: `tlsx` - TLS/SSL scanner using projectdiscovery/tlsx
- **ParseDefinition**: `tlsx-parser` - Custom parser for TLSX results
- **PVC**: `tlsx-parser-pvc` - Persistent volume for storing results

### Naabu Scanner  
- **ScanType**: `naabu` - Port scanner using projectdiscovery/naabu
- **ParseDefinition**: `naabu-json` - Custom parser for Naabu results
- **PVC**: `naabu-parser-pvc` - Persistent volume for storing results

## Prerequisites

Before running the setup script, ensure you have:

1. **Kubernetes cluster** running and accessible
2. **kubectl** configured and pointing to your cluster
3. **SecureCodeBox operator** already installed
4. **Helm** installed (for operator installation if needed)

### Installing SecureCodeBox Operator (if not already installed)

```bash
# Install the operator
helm --namespace securecodebox-system upgrade --install --create-namespace securecodebox-operator oci://ghcr.io/securecodebox/helm/operator

# Verify installation
kubectl get pods -n securecodebox-system
```

## Quick Setup

1. **Run the setup script**:
   ```bash
   ./setup_custom_scanners.sh
   ```

2. **Verify installation**:
   ```bash
   kubectl get scantypes -n securecodebox-system
   kubectl get parsedefinitions -n securecodebox-system
   kubectl get pvc -n securecodebox-system
   ```

## Using the Scanners

### Method 1: Using scbctl (Recommended)

```bash
# TLSX scan
scbctl scan tlsx --name my-tlsx-scan -- -host example.com -json -o /home/securecodebox/raw-results.json

# Naabu scan  
scbctl scan naabu --name my-naabu-scan -- -host example.com -json -o /home/securecodebox/raw-results.json
```

### Method 2: Using kubectl

Create a scan YAML file:
```yaml
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: my-tlsx-scan
  namespace: securecodebox-system
spec:
  scanType: "tlsx"
  parameters:
    - "-host"
    - "example.com"
    - "-json"
    - "-o"
    - "/home/securecodebox/raw-results.json"
```

Then apply it:
```bash
kubectl apply -f scan.yaml
```

### Method 3: Using the provided scripts

```bash
# TLSX scan
../tlsx/run_tlsx_scan.sh example.com

# Naabu scan
../naabu/run_naabu_scan.sh example.com
```

## Monitoring Scans

```bash
# Check scan status
kubectl get scans -n securecodebox-system

# View scan logs
kubectl logs -n securecodebox-system -l job-name=scan-<scan-name>

# View parser logs
kubectl logs -n securecodebox-system -l job-name=parse-<scan-name>
```

## Accessing Results

### MinIO Storage
The results are automatically stored in MinIO. To access them:

```bash
# Port forward MinIO
kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000

# Setup MinIO client
mc alias set securecodebox http://localhost:9000 admin password

# List files
mc ls securecodebox/securecodebox/
```

### Direct PVC Access
Results are also stored in PVCs and can be accessed using the provided scripts.

## Troubleshooting

### Common Issues

1. **"namespace not found" error**
   - Ensure SecureCodeBox operator is installed
   - Check that `securecodebox-system` namespace exists

2. **"ScanType not found" error**
   - Run the setup script again
   - Check that all resources were applied successfully

3. **"Parser not triggered" error**
   - Verify ParseDefinition names match ScanType configuration
   - Check parser pod logs for errors

### Debug Commands

```bash
# Check all resources
kubectl get scantypes,parsedefinitions,pvc -n securecodebox-system

# Check operator status
kubectl get pods -n securecodebox-system

# View operator logs
kubectl logs -n securecodebox-system -l app=securecodebox-operator
```

## File Structure

```
webapp-all/
├── setup_custom_scanners.sh          # Main setup script
├── README_CUSTOM_SCANNERS.md         # This file
├── ../tlsx/
│   ├── scantype-tlsx.yaml           # TLSX ScanType definition
│   └── parser/
│       ├── parsedefinition-tlsx.yaml # TLSX parser definition
│       └── pvc-tlsx.yaml            # TLSX PVC definition
└── ../naabu/
    ├── scantype-naabu.yaml          # Naabu ScanType definition
    └── parser/
        ├── parsedefinition-naabu.yaml # Naabu parser definition
        └── pvc-naabu.yaml           # Naabu PVC definition
```

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Verify all prerequisites are met
3. Check the SecureCodeBox documentation: https://www.securecodebox.io/
4. Review the integration reports in the `../tlsx/` and `../naabu/` directories 