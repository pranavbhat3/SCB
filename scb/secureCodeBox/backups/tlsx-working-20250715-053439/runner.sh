#!/bin/bash

set -e

NAMESPACE="securecodebox-system"
SCAN_NAME="tlsx-scan-scanme-$(date +%Y%m%d-%H%M%S)"
ORIG_SCAN_FILE="tlsxscan.yaml"
TEMP_SCAN_FILE="temp-scan.yaml"
LOG_KEYWORD="tls_connection"
OUTPUT_FILE="output.json"

echo "[*] Generating scan YAML: $SCAN_NAME"

# Create a fresh temp copy with correct name
cp "$ORIG_SCAN_FILE" "$TEMP_SCAN_FILE"
yq e ".metadata.name = \"$SCAN_NAME\"" -i "$TEMP_SCAN_FILE"

echo "[*] Applying scan..."
kubectl apply -f "$TEMP_SCAN_FILE"

echo "[*] Waiting for scan to error..."
while true; do
  STATUS=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "")
  if [[ "$STATUS" == "Errored" ]]; then
    echo "[✓] Scan status is 'Errored'"
    break
  fi
  sleep 2
done

echo "[*] Locating pod..."
POD_NAME=$(kubectl get pods -n "$NAMESPACE" \
  --selector=job-name=scan-$SCAN_NAME \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ -z "$POD_NAME" ]]; then
  echo "[!] Could not find scan pod"
  exit 1
fi

echo "[*] Fetching logs from pod: $POD_NAME (container: tlsx)"
LOGS=$(kubectl logs -n "$NAMESPACE" "$POD_NAME" -c tlsx 2>/dev/null || true)

if echo "$LOGS" | grep -q "$LOG_KEYWORD"; then
  echo "$LOGS" > "$OUTPUT_FILE"
  echo "[✓] Output written to $OUTPUT_FILE"
else
  echo "[!] No matching output found in logs"
  echo "$LOGS"
fi
