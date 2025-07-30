#!/bin/bash
set -e

# Usage: ./run_zap_scbctl.sh <target>
if [ -z "$1" ]; then
  echo "Usage: $0 <target>"
  echo "Example: $0 https://scanme.nmap.org"
  exit 1
fi
TARGET="$1"
SCAN_NAME="zap-scan-$(date +%s)"
NAMESPACE="default"
SCAN_TYPE="zap-baseline-scan"

echo "=== ZAP SCANNER WITH SCBCTL ==="
echo "Target: $TARGET"
echo "Scan Name: $SCAN_NAME"
echo "Scan Type: $SCAN_TYPE"
echo "Namespace: $NAMESPACE"

# Print port-forward instructions
cat <<EOPF

[INFO] For MinIO access, keep these running in a separate terminal:
  kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
  # (Optional, for web UI) kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9001:9001
EOPF

# Create scan using scbctl
echo "[INFO] Creating ZAP scan with scbctl..."
scbctl scan $SCAN_TYPE --name $SCAN_NAME --namespace $NAMESPACE -- -target $TARGET

# Wait for scan to complete
echo "[INFO] Waiting for scan to complete..."
while true; do
  STATE=$(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.status.state}')
  echo "Current scan state: $STATE"
  if [[ "$STATE" == "Done" || "$STATE" == "Errored" ]]; then
    break
  fi
  sleep 10
done

if [[ "$STATE" == "Errored" ]]; then
  echo "[ERROR] Scan failed. Check logs with: kubectl logs -n $NAMESPACE -l job-name=scan-$SCAN_NAME"
  exit 1
fi

echo "[SUCCESS] ZAP scan completed successfully!"

# Get scan details
SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.metadata.uid}')
SCAN_FOLDER="scan-$SCAN_UID"
echo "[INFO] Scan folder in MinIO: $SCAN_FOLDER"

# Check if findings are available
FINDINGS_URL=$(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.status.findingDownloadLink}' 2>/dev/null || echo "")
if [ -n "$FINDINGS_URL" ]; then
  echo "[INFO] Findings are available at: $FINDINGS_URL"
  echo "[INFO] Raw results available at: $(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.status.rawResultDownloadLink}')"
else
  echo "[INFO] No findings URL available yet, check MinIO directly"
fi

echo ""
echo "=== COMPLETED ==="
echo "Scan: $SCAN_NAME"
echo "Target: $TARGET"
echo "Scan Type: $SCAN_TYPE"
echo "Namespace: $NAMESPACE"
echo "MinIO Folder: $SCAN_FOLDER"
echo ""
echo "🎉 ZAP SCANNER WITH SCBCTL - SUCCESS!"
echo "[SUCCESS] Check MinIO folder $SCAN_FOLDER for findings.json and raw-results.json." 