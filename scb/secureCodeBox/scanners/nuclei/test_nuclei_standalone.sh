#!/bin/bash
set -e

# Standalone Nuclei test for SecureCodeBox with robust debugging
TARGET="${1:-8.8.8.8}"
NAMESPACE="securecodebox-system"
SCAN_NAME="nuclei-test-$(date +%s)"
SCAN_FILE="/tmp/$SCAN_NAME.yaml"
TARGET_FILE="/tmp/$SCAN_NAME-targets.txt"

echo "$TARGET" > "$TARGET_FILE"

# Use -target <file> for IPs/CIDRs
cat >"$SCAN_FILE" <<EOF
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: $SCAN_NAME
  namespace: $NAMESPACE
spec:
  scanType: nuclei
  parameters:
    - "-target"
    - "$TARGET_FILE"
    - "-o"
    - "/home/securecodebox/nuclei-results.jsonl"
  ttlSecondsAfterFinished: 0
EOF

echo "[INFO] Applying minimal Nuclei scan YAML: $SCAN_FILE"
kubectl apply -f "$SCAN_FILE"

# Wait for scan to complete
while true; do
    STATE=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
    echo "Current state: $STATE"
    if [ "$STATE" = "Done" ]; then
        echo "✅ Nuclei scan completed successfully!"
        break
    elif [ "$STATE" = "Errored" ]; then
        echo "❌ Nuclei scan failed!"
        kubectl describe scan "$SCAN_NAME" -n "$NAMESPACE"
        NUCLEI_POD=$(kubectl get pods -n "$NAMESPACE" | grep "$SCAN_NAME" | awk '{print $1}')
        if [ -n "$NUCLEI_POD" ]; then
            echo "--- Nuclei scan pod logs ---"
            kubectl logs $NUCLEI_POD -n "$NAMESPACE" || echo "Could not fetch Nuclei pod logs."
        else
            echo "Nuclei scan pod not found for logs. If you just reinstalled, try again and check logs quickly after failure."
        fi
        echo "--- Nuclei scan job events ---"
        kubectl get events -n "$NAMESPACE" --sort-by=.metadata.creationTimestamp | grep $SCAN_NAME || echo "No events found for Nuclei scan job."
        echo "[WARNING] If the pod failed, check PVCs and volumes for the Nuclei scanner:"
        echo "kubectl get pvc -n $NAMESPACE"
        exit 1
    fi
    sleep 10
done

# Get scan UID and download results from MinIO
SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}')
MINIO_PATH="securecodebox/securecodebox/scan-$SCAN_UID/nuclei-results.jsonl"
mc alias set securecodebox http://localhost:9000 admin password >/dev/null 2>&1 || true
if mc ls securecodebox/securecodebox/scan-$SCAN_UID/ 2>/dev/null | grep -q nuclei-results.jsonl; then
    echo "✅ Found nuclei results in MinIO!"
    mc cat "$MINIO_PATH" | head -10
else
    echo "⚠️  No nuclei results found in MinIO."
fi 
