#!/bin/bash
set -e

# Usage: ./run_tlsx_scan.sh <target>
if [ -z "$1" ]; then
  echo "Usage: $0 <target>"
  exit 1
fi
TARGET="$1"
SCAN_NAME="tlsx-scan-$(date +%s)"
SCAN_FILE="${SCAN_NAME}.yaml"

# Generate scan YAML for the target
echo "Generating scan YAML for target: $TARGET"
cat > "$SCAN_FILE" <<EOF
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: $SCAN_NAME
  namespace: securecodebox-system
spec:
  scanType: "tlsx"
  parameters:
    - "-host"
    - "$TARGET"
    - "-json"
    - "-o"
    - "/home/securecodebox/raw-results.json"
EOF

# Run the scan
echo "Applying scan: $SCAN_FILE"
kubectl apply -f "$SCAN_FILE"

# Wait for scan to complete
echo "Waiting for scan to complete..."
while true; do
  STATE=$(kubectl get scan "$SCAN_NAME" -n securecodebox-system -o jsonpath='{.status.state}')
  echo "Current scan state: $STATE"
  if [[ "$STATE" == "Done" || "$STATE" == "Errored" ]]; then
    break
  fi
  sleep 10
done

if [[ "$STATE" == "Errored" ]]; then
  echo "Scan failed. Check logs with: kubectl logs -n securecodebox-system -l job-name=scan-$SCAN_NAME"
  exit 1
fi

echo "Scan completed. Getting scan folder ID..."
SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n securecodebox-system -o jsonpath='{.metadata.uid}')
SCAN_FOLDER="scan-$SCAN_UID"
echo "Scan folder in MinIO: $SCAN_FOLDER"

# Download raw-results.json from MinIO (optional, for local parsing)
echo "Downloading raw-results.json from MinIO..."
mc cp "myminio/securecodebox/$SCAN_FOLDER/raw-results.json" raw-results.json

# Run the parser locally to produce findings-local.json
echo "Running parser locally..."
node parser/parser.js raw-results.json

# Upload findings-local.json to MinIO
echo "Uploading findings-local.json to MinIO as findings.json..."
mc cp findings-local.json "myminio/securecodebox/$SCAN_FOLDER/findings.json"

echo "All done! Check MinIO folder $SCAN_FOLDER for findings.json and raw-results.json." 