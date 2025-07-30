#!/bin/bash
set -e

# Usage: ./run_tlsx_scan_pushwebhook.sh <target> <webhook_url>
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target> <webhook_url>"
  exit 1
fi
TARGET="$1"
WEBHOOK_URL="$2"
SCAN_NAME="tlsx-scan-$(date +%s)"
SCAN_FILE="${SCAN_NAME}.yaml"
NAMESPACE="securecodebox-system"
PVC="tlsx-parser-pvc"

cat <<EOPF

[INFO] For MinIO access, keep these running in a separate terminal:
  kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
  # (Optional, for web UI) kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9001:9001
EOPF

echo "[INFO] Generating scan YAML for target: $TARGET"
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
    - "-json"
    - "-o"
    - "/home/securecodebox/raw-results.json"
EOF

echo "[INFO] Applying scan: $SCAN_FILE"
kubectl apply -f "$SCAN_FILE"

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

SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.metadata.uid}')
SCAN_FOLDER="scan-$SCAN_UID"
echo "[INFO] Scan folder in MinIO: $SCAN_FOLDER"

PARSER_POD=$(kubectl get pods -n $NAMESPACE -o name | grep parse-tlsx-scan | grep "$SCAN_NAME" | head -1 | sed 's|pod/||')
if [ -z "$PARSER_POD" ]; then
  echo "[ERROR] Parser pod not found for scan $SCAN_NAME."
  exit 1
fi

echo "[INFO] Parser pod name: $PARSER_POD"

echo "[INFO] Launching helper pod to extract findings.json from PVC..."
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

for i in {1..12}; do
  if kubectl exec -n $NAMESPACE $HELPER_POD -- test -f /mnt/findings.json; then
    break
  fi
  sleep 5
done

kubectl cp -n $NAMESPACE $HELPER_POD:/mnt/findings.json findings-from-pvc.json || echo "[ERROR] findings.json not found in PVC."
kubectl delete pod $HELPER_POD -n $NAMESPACE --force --grace-period=0 || true

if [ -f findings-from-pvc.json ]; then
  echo "--- findings.json content (from PVC) ---"
  cat findings-from-pvc.json
else
  echo "[ERROR] findings.json not found in PVC."
  exit 1
fi

echo "[INFO] Uploading findings.json to MinIO..."
mc cp findings-from-pvc.json "myminio/securecodebox/$SCAN_FOLDER/findings.json"

# POST findings to webhook
if [ -n "$WEBHOOK_URL" ]; then
  echo "[INFO] Posting findings to webhook: $WEBHOOK_URL"
  # Wrap findings in a dictionary for FastAPI, include scan_folder
  jq -c --arg scan_name "$SCAN_NAME" --arg scan_folder "$SCAN_FOLDER" '{scan_name: $scan_name, scan_folder: $scan_folder, findings: .}' findings-from-pvc.json > findings-for-webhook.json
  curl -X POST -H "Content-Type: application/json" --data-binary @findings-for-webhook.json "$WEBHOOK_URL" || echo "[WARN] Failed to POST to webhook."
fi

echo "[SUCCESS] All done! Check MinIO folder $SCAN_FOLDER for findings.json and raw-results.json." 