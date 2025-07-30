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
SCAN_NAME="tlsx-scbctl-${SAFE_TARGET}-$(date +%s)"
SCAN_NAME=$(echo "$SCAN_NAME" | sed 's/-\{2,\}/-/g; s/^-*//; s/-*$//;')
SCAN_NAME=${SCAN_NAME:0:63}
NAMESPACE="default"
SCAN_TYPE="tlsx"
RAW_RESULTS="raw-results.json"
FINDINGS_JSON="findings-manual.json"

# Step 1: Launch scan with scbctl
PARAMS=("-host" "$TARGET" "-json" "-o" "/home/securecodebox/$RAW_RESULTS")
if [ -n "$PORTS" ]; then
  PARAMS+=("-p" "$PORTS")
fi

echo "[INFO] Launching tlsx scan with scbctl..."
scbctl scan $SCAN_TYPE --name $SCAN_NAME --namespace $NAMESPACE -- "${PARAMS[@]}"

# Step 2: Wait for scan to complete
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

# Step 3: Download raw results using scbctl
RAW_URL=$(kubectl get scan "$SCAN_NAME" -n $NAMESPACE -o jsonpath='{.status.rawResultDownloadLink}' 2>/dev/null || echo "")
if [ -z "$RAW_URL" ]; then
  echo "[ERROR] Could not get raw result download link."
  exit 1
fi

echo "[INFO] Downloading raw results from $RAW_URL ..."
curl -sSL "$RAW_URL" -o "$RAW_RESULTS"
if [ ! -s "$RAW_RESULTS" ]; then
  echo "[ERROR] Failed to download raw results."
  exit 1
fi

# Step 4: Parse raw results
node parser/parser.js "$RAW_RESULTS" > "$FINDINGS_JSON"
if [ ! -s "$FINDINGS_JSON" ]; then
  echo "[ERROR] Parsing failed or no findings produced."
  exit 1
fi

echo "[INFO] Parsed findings written to $FINDINGS_JSON."

# Step 5: Upload findings using scbctl
scbctl findings upload "$FINDINGS_JSON" --name "$SCAN_NAME-findings" --namespace "$NAMESPACE" --scanner "$SCAN_TYPE" --target "$TARGET"
if [ $? -eq 0 ]; then
  echo "[SUCCESS] Findings uploaded with scan name $SCAN_NAME-findings."
  echo "[INFO] Check secureCodeBox UI or MinIO for results."
else
  echo "[ERROR] scbctl findings upload failed."
  exit 1
fi

# Step 6: Show findings for proof
if [ -f "$FINDINGS_JSON" ]; then
  echo "--- findings.json content (parsed) ---"
  cat "$FINDINGS_JSON"
else
  echo "[ERROR] findings.json not found."
fi 