#!/bin/bash
set -e

usage() {
  echo "Usage: $0 <target> [-p port1,port2,...]"
  echo "  <target> is required (e.g., google.com)"
  echo "  -p is optional for multiport (e.g., -p 443,8443)"
  exit 1
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
fi

if [ -z "$1" ]; then
  usage
fi
TARGET="$1"
shift
PORTS=""
EXTRA_PARAMS=""

# Parse optional -p argument
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -p|--ports)
      PORTS="$2"
      shift; shift
      ;;
    *)
      EXTRA_PARAMS+=" $1"
      shift
      ;;
  esac
done

# --- Robust Kubernetes resource name sanitization ---
# 1. Replace all non-alphanumeric and non-dash chars with dashes
# 2. Collapse multiple dashes
# 3. Trim leading/trailing dashes
# 4. Truncate to 63 chars (K8s max resource name length)
SAFE_TARGET=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g; s/-\{2,\}/-/g; s/^-*//; s/-*$//; s/\(.*\)/\1/;')
SAFE_TARGET=${SAFE_TARGET:0:50} # leave room for timestamp
if [ -z "$SAFE_TARGET" ]; then
  echo "[ERROR] Sanitized target name is empty. Aborting."
  exit 1
fi
SCAN_NAME="tlsx-scan-${SAFE_TARGET}-$(date +%s)"
SCAN_NAME=$(echo "$SCAN_NAME" | sed 's/-\{2,\}/-/g; s/^-*//; s/-*$//;')
SCAN_NAME=${SCAN_NAME:0:63}
NAMESPACE="securecodebox-system"
PVC="tlsx-parser-pvc"

cat <<EOPF
[INFO] For MinIO access, keep these running in a separate terminal:
  kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
  # (Optional, for web UI) kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9001:9001
EOPF

# Generate scan YAML for the target
SCAN_FILE="${SCAN_NAME}.yaml"
cat > "$SCAN_FILE" <<EOF
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: $SCAN_NAME
  namespace: $NAMESPACE
spec:
  scanType: "tlsx"
  parameters:
    - "-host"
    - "$TARGET"
EOF
if [ -n "$PORTS" ]; then
  cat >> "$SCAN_FILE" <<EOF
    - "-p"
    - "$PORTS"
EOF
fi
cat >> "$SCAN_FILE" <<EOF
    - "-json"
    - "-o"
    - "/home/securecodebox/raw-results.json"
EOF

# Show the YAML for debugging
if [[ "$DEBUG" == "1" ]]; then
  echo "--- Generated YAML ---"
  cat "$SCAN_FILE"
  echo "----------------------"
fi

# Run the scan
set +e
kubectl apply -f "$SCAN_FILE"
APPLY_STATUS=$?
set -e
if [ $APPLY_STATUS -ne 0 ]; then
  echo "[ERROR] Failed to apply scan YAML."
  cat "$SCAN_FILE"
  exit 1
fi

# Wait for scan to complete
echo "[INFO] Waiting for scan to complete..."
for i in {1..60}; do
  STATE=$(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.status.state}' 2>/dev/null || echo "")
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
if [[ "$STATE" != "Done" ]]; then
  echo "[ERROR] Scan did not complete in time."
  exit 1
fi

SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.metadata.uid}')
SCAN_FOLDER="scan-$SCAN_UID"
echo "[INFO] Scan folder in MinIO: $SCAN_FOLDER"

# Find the parser pod for this scan
PARSER_POD=$(kubectl get pods -n $NAMESPACE -o name | grep parse-tlsx-scan | grep "$SCAN_NAME" | head -1 | sed 's|pod/||')
if [ -z "$PARSER_POD" ]; then
  echo "[ERROR] Parser pod not found for scan $SCAN_NAME."
  exit 1
fi

echo "[INFO] Parser pod name: $PARSER_POD"

# Extract findings.json from the PVC using a helper pod
HELPER_POD="extract-findings-$SCAN_UID"
kubectl run $HELPER_POD --rm -i --tty --restart=Never -n $NAMESPACE \
  --image=busybox --overrides='{
    "spec": {
      "volumes": [{
        "name": "tlsx-parser-pvc",
        "persistentVolumeClaim": {"claimName": "tlsx-parser-pvc"}
      }],
      "containers": [{
        "name": "busybox",
        "image": "busybox",
        "command": ["sleep", "3600"],
        "volumeMounts": [{"name": "tlsx-parser-pvc", "mountPath": "/mnt"}]
      }]
    }
  }' &

# Wait for helper pod to be running
for i in {1..12}; do
  STATUS=$(kubectl get pod $HELPER_POD -n $NAMESPACE -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  if [[ "$STATUS" == "Running" ]]; then
    break
  fi
  sleep 5
done

if [[ "$STATUS" != "Running" ]]; then
  echo "[ERROR] Helper pod did not start."
  exit 1
fi

# Wait for findings.json to appear in the PVC
for i in {1..12}; do
  if kubectl exec -n $NAMESPACE $HELPER_POD -- test -f /mnt/findings.json; then
    break
  fi
  sleep 5
done

# Copy findings.json from PVC
kubectl cp -n $NAMESPACE $HELPER_POD:/mnt/findings.json findings-from-pvc.json || echo "[ERROR] findings.json not found in PVC."

# Clean up helper pod
kubectl delete pod $HELPER_POD -n $NAMESPACE --force --grace-period=0 || true

# Show findings.json content for proof
if [ -f findings-from-pvc.json ]; then
  # Create results folder for this scan
  RESULTS_DIR="$SCAN_NAME"
  mkdir -p "$RESULTS_DIR"
  mv findings-from-pvc.json "$RESULTS_DIR/"
  # Move raw-results.json if it exists
  if [ -f raw-results.json ]; then
    mv raw-results.json "$RESULTS_DIR/"
  fi
  echo "[SUCCESS] Scan finished! Results are in: $RESULTS_DIR/"
  echo "--- findings-from-pvc.json (first 20 lines) ---"
  head -20 "$RESULTS_DIR/findings-from-pvc.json"
else
  echo "[ERROR] findings.json not found in PVC."
  exit 1
fi

# Upload findings.json to MinIO
if command -v mc >/dev/null 2>&1; then
  echo "[INFO] Uploading findings.json to MinIO..."
  mc cp "$RESULTS_DIR/findings-from-pvc.json" "myminio/securecodebox/$SCAN_FOLDER/findings.json"
  echo "[SUCCESS] All done! Check MinIO folder $SCAN_FOLDER for findings.json and raw-results.json."
else
  echo "[WARNING] 'mc' (MinIO client) not found. Skipping upload."
fi 