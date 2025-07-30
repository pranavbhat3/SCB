# MobSF secureCodeBox Integration

This Helm chart includes secureCodeBox integration for running mobile application security scans using MobSF.

## Overview

The integration provides:
- A **ScanType Custom Resource Definition** that defines how MobSF scans are executed
- Configurable scan parameters through Helm values
- Integration with secureCodeBox's MinIO storage for file handling
- Security-hardened container configuration

## Components

### 1. ScanType CRD (`templates/scantype.yaml`)

Defines the MobSF scanner as a secureCodeBox ScanType with:
- Container image configuration
- Environment variables for MinIO and MobSF connectivity
- Resource limits and security context
- Result extraction configuration

### 2. Example Scan CRD (`templates/example-scan.yaml`)

Provides a template for creating Scan resources that use the MobSF ScanType.

### 3. Configuration (`values.yaml`)

Configurable parameters under the `scan` section:
```yaml
scan:
  apkObject: "app.apk"  # Default APK object name
  scannerImage:
    repository: acc0lade/mobsf-wrapper
    tag: latest
    pullPolicy: IfNotPresent
  minio:
    endpoint: "http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000"
    accessKey: "admin"
    secretKey: "password"
    inputBucket: "securecodebox"
    outputBucket: "securecodebox"
```

## Usage

### Prerequisites

1. **secureCodeBox Operator**: Must be installed in your cluster
2. **MinIO**: Configured and accessible with the specified credentials
3. **APK Files**: Uploaded to the configured MinIO bucket

### Installation

1. Install the Helm chart:
   ```bash
   helm install mobsf ./mobsf
   ```

2. The ScanType CRD will be automatically created.

### Creating Scans

#### Basic Scan
```yaml
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: mobsf-scan-basic
spec:
  scanType: mobsf
```

#### Scan with Custom Parameters
```yaml
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: mobsf-scan-custom
spec:
  scanType: mobsf
  parameters:
    - name: APK_OBJECT
      value: "my-custom-app.apk"
```

#### Scan with Scope and Cascading
```yaml
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: mobsf-scan-advanced
spec:
  scanType: mobsf
  parameters:
    - name: APK_OBJECT
      value: "production-app.apk"
  scope:
    include:
      - namespace: default
    exclude:
      - namespace: kube-system
  cascades:
    - name: follow-up-analysis
      scanType: another-scanner
      parameters:
        - name: SEVERITY_THRESHOLD
          value: "HIGH"
```

### Monitoring Scans

```bash
# List all scans
kubectl get scans

# Get detailed information about a specific scan
kubectl describe scan mobsf-scan-basic

# View scan results
kubectl get scan mobsf-scan-basic -o yaml

# Check scan logs
kubectl logs -l job-name=mobsf-scan-basic
```

## Configuration

### Environment Variables

The scanner uses the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `MINIO_ENDPOINT` | MinIO server endpoint | From values.yaml |
| `MINIO_ACCESS_KEY` | MinIO access key | From values.yaml |
| `MINIO_SECRET_KEY` | MinIO secret key | From values.yaml |
| `INPUT_BUCKET` | MinIO bucket for input files | From values.yaml |
| `OUTPUT_BUCKET` | MinIO bucket for output files | From values.yaml |
| `APK_OBJECT` | APK file name in MinIO | From values.yaml |
| `MOBSF_URL` | MobSF service URL | Auto-generated |
| `MOBSF_API_KEY` | MobSF API key | From values.yaml |

### Security Features

The ScanType includes several security hardening features:
- Non-root user execution
- Read-only root filesystem
- Dropped capabilities
- Resource limits
- Security contexts at both container and pod levels

## Troubleshooting

### Common Issues

1. **MinIO Connection Failed**
   - Verify MinIO is running and accessible
   - Check credentials in values.yaml
   - Ensure network policies allow connectivity

2. **APK File Not Found**
   - Verify the APK file exists in the configured MinIO bucket
   - Check the `APK_OBJECT` parameter value

3. **MobSF Service Unreachable**
   - Ensure MobSF is running and healthy
   - Check service endpoints and network policies

4. **Permission Denied**
   - Verify the scanner image supports non-root execution
   - Check security context configurations

### Debug Commands

```bash
# Check ScanType status
kubectl get scantypes mobsf -o yaml

# View scan job details
kubectl get jobs -l scan-name=mobsf-scan-basic

# Check pod logs
kubectl logs -l job-name=mobsf-scan-basic

# Verify MinIO connectivity
kubectl run minio-test --image=minio/mc --rm -it --restart=Never -- \
  mc config host add myminio http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000 admin password
```

## Customization

### Custom Scanner Image

To use a custom scanner image, update the values.yaml:

```yaml
scan:
  scannerImage:
    repository: your-registry/mobsf-wrapper
    tag: v1.0.0
    pullPolicy: Always
```

### Custom MinIO Configuration

```yaml
scan:
  minio:
    endpoint: "http://your-minio-endpoint:9000"
    accessKey: "your-access-key"
    secretKey: "your-secret-key"
    inputBucket: "your-input-bucket"
    outputBucket: "your-output-bucket"
```

### Resource Limits

Modify the ScanType template to adjust resource limits:

```yaml
resources:
  requests:
    memory: "1Gi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "1000m"
```

## References

- [secureCodeBox ScanType Documentation](https://www.securecodebox.io/docs/api/crds/scan-type)
- [secureCodeBox Scan Documentation](https://www.securecodebox.io/docs/api/crds/scan)
- [MobSF Documentation](https://mobsf.github.io/docs/) 