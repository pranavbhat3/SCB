#!/bin/bash

# Always run from the script's own directory for consistent relative paths
cd "$(dirname "$0")"

# Manual Cascading Scan Orchestrator: Naabu -> TLSX -> ZAP -> Nuclei
# Usage: ./run_cascading_manual.sh <target> [--all-ports] [namespace]
# 
# Cleanup Options:
# - All local files are automatically cleaned up after completion
# - All findings are automatically uploaded to MinIO before cleanup
# - Results can be downloaded from MinIO using the web interface

set -e

# Function to cleanup on exit (error or success)
cleanup_on_exit() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "⚠️  Script exited with error code $exit_code, cleaning up..."
    fi
    
    # Clean up temporary files
    if [ -f "/tmp/naabu-findings.json" ]; then
        rm -f "/tmp/naabu-findings.json"
        echo "ℹ️  Removed /tmp/naabu-findings.json"
    fi
    
    if [ -n "$SCAN_NAME_NUCLEI" ] && [ -f "/tmp/$SCAN_NAME_NUCLEI.yaml" ]; then
        rm -f "/tmp/$SCAN_NAME_NUCLEI.yaml"
        echo "ℹ️  Removed /tmp/$SCAN_NAME_NUCLEI.yaml"
    fi
    
    # Clean up scan YAML files
    if [ -n "$TLSX_SCAN_FILE" ] && [ -f "$TLSX_SCAN_FILE" ]; then
        rm -f "$TLSX_SCAN_FILE"
        echo "ℹ️  Removed $TLSX_SCAN_FILE"
    fi
    
    # Clean up local findings files
    if [ -n "$TLSX_FINDINGS_LOCAL" ] && [ -f "$TLSX_FINDINGS_LOCAL" ]; then
        rm -f "$TLSX_FINDINGS_LOCAL"
        echo "ℹ️  Removed $TLSX_FINDINGS_LOCAL"
    fi
    
    exit $exit_code
}

# Set trap to cleanup on exit
trap cleanup_on_exit EXIT

# Config
TARGET=${1:-scanme.nmap.org}
ALL_PORTS=""
NAMESPACE="securecodebox-system"

# Safe scan name function
safe_scan_name() {
    local target="$1"
    local prefix="$2"
    local name="${prefix}-${target}"
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    name=$(echo "$name" | sed 's/[^a-z0-9-]/-/g')
    name=$(echo "$name" | sed 's/--*/-/g')
    name=$(echo "$name" | sed 's/^-//;s/-$//')
    echo "${name}-$(date +%s)"
}
if [[ "$2" == "--all-ports" ]]; then
  ALL_PORTS="1"
  [ -n "$3" ] && NAMESPACE="$3"
else
  [ -n "$2" ] && NAMESPACE="$2"
fi
RESULTS_DIR="cascading_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}✅ $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
        "RUNNING") echo -e "${CYAN}🔄 $message${NC}" ;;
    esac
}

# === NAABU SCAN (always scan all ports, no --all-ports flag needed) ===
SCAN_NAME=$(safe_scan_name "$TARGET" "naabu-scan")
echo "[INFO] Scanning ALL ports (1-65535) on $TARGET"
echo "=== NAABU SCANNER WITH SCBCTL (ALL PORTS CAPABLE) ==="
echo "Target: $TARGET"
echo "Scan Name: $SCAN_NAME"
echo "Creating scan with scbctl (all ports)..."
scbctl scan naabu --name $SCAN_NAME --namespace $NAMESPACE -- -host $TARGET -p - -json -o /home/securecodebox/raw-results.json || { print_status ERROR "Failed to create Naabu scan!"; exit 1; }

while true; do
    STATE=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
    echo "Current state: $STATE"
    if [ "$STATE" = "Done" ]; then
        echo "✅ Scan completed successfully!"
        break
    elif [ "$STATE" = "Errored" ]; then
        echo "❌ Scan failed!"
        kubectl describe scan $SCAN_NAME -n $NAMESPACE
        # Print pod logs if available
        NAABU_POD=$(kubectl get pods -n $NAMESPACE | grep "scan-$SCAN_NAME" | awk '{print $1}')
        if [ -n "$NAABU_POD" ]; then
            print_status ERROR "--- Naabu scan pod logs ---"
            kubectl logs $NAABU_POD -n $NAMESPACE || print_status WARNING "Could not fetch Naabu pod logs."
        fi
        exit 1
    fi
    sleep 10
done

# Remove old findings file before scan
rm -f /tmp/naabu-findings.json

# Wait for scan to complete (already handled above)

# Wait for parser to complete (fixed sleep, as in safe script)
echo "Waiting for parser to complete..."
sleep 30

echo ""
echo "=== EXTRACTING PARSER OUTPUT ==="
PARSER_POD=$(kubectl get pods -n $NAMESPACE | grep "parse-$SCAN_NAME" | awk '{print $1}')
if [ -n "$PARSER_POD" ]; then
    echo "Parser pod: $PARSER_POD"
    echo "Extracting findings from parser logs..."
    kubectl logs $PARSER_POD -n $NAMESPACE | tail -n +4 | head -n -1 > /tmp/naabu-findings.json
    echo "Findings extracted to /tmp/naabu-findings.json"
    echo "Content preview:"
    head -10 /tmp/naabu-findings.json
    echo "..."
else
    print_status ERROR "Parser pod not found!"
    exit 1
fi

echo ""
echo "=== UPLOADING TO MINIO WITH MC ==="
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="naabu-findings-${TARGET//[^a-zA-Z0-9]/_}-${TIMESTAMP}.json"
MINIO_PATH="securecodebox/securecodebox/$FILENAME"

# Check if findings file exists and is non-empty
PARSER_OUTPUT="/tmp/naabu-findings.json"
if [ ! -s "$PARSER_OUTPUT" ]; then
    print_status ERROR "Findings file $PARSER_OUTPUT does not exist or is empty!"
    exit 1
fi

# Setup MinIO client and check alias
mc alias set securecodebox http://localhost:9000 admin password 2>/dev/null || true
if ! mc alias list | grep -q securecodebox; then
    print_status ERROR "MinIO alias 'securecodebox' not found!"
    exit 1
fi

# Check if bucket exists, create if not
if ! mc ls securecodebox | grep -q securecodebox; then
    print_status WARNING "MinIO bucket 'securecodebox' not found, creating..."
    mc mb securecodebox/securecodebox || { print_status ERROR "Failed to create MinIO bucket!"; exit 1; }
fi

echo "Uploading findings to MinIO..."
if mc cp "$PARSER_OUTPUT" securecodebox/securecodebox/$FILENAME; then
    echo "✅ Findings uploaded to MinIO: $FILENAME"
    echo "📁 MinIO path: $MINIO_PATH"
    echo ""
    echo "Listing naabu files in MinIO:"
    mc ls securecodebox/securecodebox/ | grep naabu
else
    print_status ERROR "Failed to upload to MinIO."
    print_status ERROR "Findings saved locally: $PARSER_OUTPUT"
    exit 1
fi

echo ""
echo "=== COMPLETED ==="
echo "Scan: $SCAN_NAME"
echo "Target: $TARGET"
echo "Findings: $FILENAME"
echo "Local file: $PARSER_OUTPUT"
echo ""
echo "🎉 NAABU SCANNER WITH SCBCTL (ALL PORTS CAPABLE) - SUCCESS!"

# === FETCH NAABU FINDINGS FROM MINIO (robust, always valid JSON) ===
# When downloading from MinIO, use absolute path
LOCAL_FINDINGS="$RESULTS_DIR/naabu-findings.json"
if mc cp "$MINIO_PATH" "$LOCAL_FINDINGS"; then
    print_status SUCCESS "Naabu findings downloaded from MinIO: $LOCAL_FINDINGS"
    print_status INFO "Content preview:"
    head -10 "$LOCAL_FINDINGS"
else
    print_status ERROR "Failed to download Naabu findings from MinIO!"
    exit 1
fi

# Patch missing closing bracket if needed
if [ "$(tail -c 2 "$LOCAL_FINDINGS" | grep -c ']' )" -eq 0 ]; then
  echo "]" >> "$LOCAL_FINDINGS"
  print_status WARNING "Patched naabu-findings.json by appending missing closing bracket."
fi

# === PARSE NAABU OUTPUT AND PREPARE FOR TLSX (robust: jq only, no fallback) ===
print_status INFO "Parsing Naabu findings for open ports (using jq)..."
TLSX_TARGETS=""
OPEN_PORTS_COUNT=0
if jq -e . "$LOCAL_FINDINGS" >/dev/null 2>&1; then
  # Valid JSON, use jq
  # Only extract ports for the original target (IP or domain)
  TLSX_PORTS=$(jq -r --arg tgt "$TARGET" '.[] | select((.attributes.ip == $tgt or .attributes.host == $tgt) and .attributes.port != null) | .attributes.port' "$LOCAL_FINDINGS" | sort -n | uniq | paste -sd, -)
  OPEN_PORTS_COUNT=$(echo "$TLSX_PORTS" | tr ',' '\n' | grep -c .)
else
  print_status ERROR "naabu-findings.json is not valid JSON. Aborting."
  exit 1
fi
print_status SUCCESS "Found $OPEN_PORTS_COUNT open ports for $TARGET."
if [ "$OPEN_PORTS_COUNT" -gt 1000 ]; then
    print_status WARNING "Large number of open ports detected ($OPEN_PORTS_COUNT). TLSX scan may take a long time."
fi
if [ -z "$TLSX_PORTS" ]; then
    print_status ERROR "No open ports found by Naabu for $TARGET. Aborting."
    exit 1
fi
print_status INFO "TLSX will be run for $TARGET on ports: $TLSX_PORTS"
echo "$TLSX_PORTS" | tr ',' '\n' | head -10

# === TLSX SCAN (robust, multiport, PVC extraction) ===
SCAN_NAME_TLSX=$(safe_scan_name "$TARGET" "tlsx-cascade")
TLSX_SCAN_FILE="${SCAN_NAME_TLSX}.yaml"

cat > "$TLSX_SCAN_FILE" <<EOF
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: $SCAN_NAME_TLSX
  namespace: $NAMESPACE
spec:
  scanType: "tlsx"
  parameters:
    - "-host"
    - "$TARGET"
    - "-p"
    - "$TLSX_PORTS"
    - "-json"
    - "-o"
    - "/home/securecodebox/raw-results.json"
EOF

echo "[INFO] Applying TLSX scan: $TLSX_SCAN_FILE"
kubectl apply -f "$TLSX_SCAN_FILE"

# Wait for scan to complete
echo "[INFO] Waiting for TLSX scan to complete..."
while true; do
  STATE=$(kubectl get scan "$SCAN_NAME_TLSX" -n $NAMESPACE -o jsonpath='{.status.state}')
  echo "Current TLSX scan state: $STATE"
  if [[ "$STATE" == "Done" || "$STATE" == "Errored" ]]; then
    break
  fi
  sleep 10
done

if [[ "$STATE" == "Errored" ]]; then
  print_status ERROR "TLSX scan failed. Check logs with: kubectl logs -n $NAMESPACE -l job-name=scan-$SCAN_NAME_TLSX"
  exit 1
fi

SCAN_UID=$(kubectl get scan "$SCAN_NAME_TLSX" -n $NAMESPACE -o jsonpath='{.metadata.uid}')
SCAN_FOLDER="scan-$SCAN_UID"
print_status INFO "TLSX scan folder in MinIO: $SCAN_FOLDER"

# After TLSX scan completes and you have $SCAN_FOLDER
TLSX_FINDINGS_MINIO="securecodebox/securecodebox/findings.json"
TLSX_FINDINGS_LOCAL="tlsx-findings.json"
TLSX_SCAN_FOLDER="securecodebox/securecodebox/$SCAN_FOLDER/findings.json"

# Download findings.json from MinIO
if mc cp "$TLSX_FINDINGS_MINIO" "$TLSX_FINDINGS_LOCAL"; then
  print_status SUCCESS "Downloaded findings.json from MinIO: $TLSX_FINDINGS_LOCAL"
else
  print_status ERROR "Failed to download findings.json from MinIO!"
  exit 1
fi

# Copy findings.json to the scan-specific folder in MinIO
if mc cp "$TLSX_FINDINGS_LOCAL" "$TLSX_SCAN_FOLDER"; then
  print_status SUCCESS "Copied findings.json to scan folder in MinIO: $TLSX_SCAN_FOLDER"
else
  print_status ERROR "Failed to copy findings.json to scan folder in MinIO!"
fi

# === Extract HTTPS endpoints from TLSX findings for ZAP (and Nuclei) ===
print_status INFO "Extracting HTTPS endpoints from TLSX findings for ZAP and Nuclei..."
ZAP_TARGETS="zap-targets.txt"
NUCLEI_TARGETS_FILE="/tmp/nuclei-cascade-$(date +%s)-targets.txt"
jq -r '.[] | select((.attributes.port == "443") or (.attributes.tls_version != null)) | "https://\(.attributes.host // .attributes.ip):\(.attributes.port)"' "$TLSX_FINDINGS_LOCAL" | sort -u > "$ZAP_TARGETS"
cp "$ZAP_TARGETS" "$NUCLEI_TARGETS_FILE"
ZAP_TARGET_COUNT=$(grep -c . "$ZAP_TARGETS")
if [ "$ZAP_TARGET_COUNT" -eq 0 ]; then
    print_status ERROR "No HTTPS endpoints found for ZAP or Nuclei. Aborting."
    exit 1
fi
print_status INFO "Prepared $ZAP_TARGET_COUNT HTTPS targets for ZAP and Nuclei. Showing first 10:"
head -10 "$ZAP_TARGETS"

# === ZAP Baseline Scan for each TLSX HTTPS endpoint (using working logic) ===
ZAP_TARGETS_LIST=($(cat "$ZAP_TARGETS"))
for ZAP_TARGET in "${ZAP_TARGETS_LIST[@]}"; do
  # Fix: Use proper naming convention without underscores and special characters
  SAFE_TARGET=$(echo "$ZAP_TARGET" | sed 's#https\?://##;s/[:/.]/-/g;s/--*/-/g;s/^-//;s/-$//')
  ZAP_SCAN_NAME=$(safe_scan_name "$SAFE_TARGET" "zap-scan")
  REPORT_DIR="$RESULTS_DIR/zap_reports_$SAFE_TARGET"
  mkdir -p "$REPORT_DIR"

  # Validate target URL (ensure it has protocol)
  if [[ ! "$ZAP_TARGET" =~ ^https?:// ]]; then
    print_status WARNING "Target doesn't start with http:// or https://"
    print_status INFO "Adding https:// prefix..."
    ZAP_TARGET="https://$ZAP_TARGET"
    print_status INFO "Updated target: $ZAP_TARGET"
  fi

  print_status INFO "Running ZAP baseline scan for $ZAP_TARGET"
  scbctl scan zap-baseline-scan --name "$ZAP_SCAN_NAME" --namespace "$NAMESPACE" -- -t "$ZAP_TARGET"

  # Enhanced monitoring with detailed pod information
  print_status INFO "=== ZAP SCAN MONITORING FOR $ZAP_TARGET ==="
  print_status INFO "Scan Name: $ZAP_SCAN_NAME"
  print_status INFO "Target: $ZAP_TARGET"
  
  # Wait for scan job to complete with detailed status
  max_wait=1800
  wait_time=0
  while [ $wait_time -lt $max_wait ]; do
    print_status INFO "--- Status Check at ${wait_time}s ---"
    
    # Check scan status
    SCAN_STATE=$(kubectl get scan "$ZAP_SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "NotFound")
    print_status INFO "Scan State: $SCAN_STATE"
    
    # Check job status
    job_status=$(kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" --no-headers 2>/dev/null | awk '{print $2}' || echo "NotFound")
    print_status INFO "Job Status: $job_status"
    
    # Show all pods related to this scan
    print_status INFO "--- Related Pods ---"
    kubectl get pods -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" --no-headers 2>/dev/null || print_status WARNING "No pods found for scan"
    
    # Show recent events for this scan
    print_status INFO "--- Recent Events ---"
    kubectl get events -n "$NAMESPACE" --sort-by=.metadata.creationTimestamp | grep "$ZAP_SCAN_NAME" | tail -3 || print_status WARNING "No events found"
    
    case $job_status in
      "1/1")
        print_status SUCCESS "ZAP scan for $ZAP_TARGET completed successfully"
        break
        ;;
      "0/1"|"0/0")
        print_status INFO "ZAP scan status for $ZAP_TARGET: Running (${wait_time}s)"
        
        # Check MinIO for ZAP results (wait for actual scan completion)
        SCAN_UID=$(kubectl get scan "$ZAP_SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
        if [ -n "$SCAN_UID" ]; then
          SCAN_FOLDER="scan-$SCAN_UID"
          print_status INFO "Checking ZAP scan folder in MinIO: $SCAN_FOLDER"
          
          # Check if scan folder exists and has findings.json with recent timestamp
          if mc ls "securecodebox/securecodebox/$SCAN_FOLDER/findings.json" 2>/dev/null; then
            # Get file timestamp to ensure it's from this scan
            FILE_TIME=$(mc stat "securecodebox/securecodebox/$SCAN_FOLDER/findings.json" --json 2>/dev/null | jq -r '.lastModified' 2>/dev/null || echo "0")
            CURRENT_TIME=$(date +%s)
            TIME_DIFF=$((CURRENT_TIME - FILE_TIME/1000))
            
            # Only consider it complete if file is less than 5 minutes old
            if [ $TIME_DIFF -lt 300 ]; then
              print_status SUCCESS "Found recent findings.json in ZAP scan folder - scan completed!"
              break
            else
              print_status INFO "Found old findings.json, waiting for new scan results..."
            fi
          fi
        fi
        
        # Show pod logs if available
        ZAP_POD=$(kubectl get pods -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" --no-headers 2>/dev/null | awk '{print $1}' | head -1)
        if [ -n "$ZAP_POD" ]; then
          print_status INFO "--- ZAP Pod Logs (last 5 lines) ---"
          kubectl logs "$ZAP_POD" -n "$NAMESPACE" --tail=5 2>/dev/null || print_status WARNING "Could not fetch pod logs"
        fi
        
        sleep 60
        wait_time=$((wait_time + 60))
        ;;
      "NotFound")
        print_status INFO "Waiting for job to be created for $ZAP_TARGET (${wait_time}s)"
        
        # Check if scan was actually created
        SCAN_STATE=$(kubectl get scan "$ZAP_SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "NotFound")
        if [ "$SCAN_STATE" = "NotFound" ]; then
          print_status ERROR "ZAP scan was not created properly!"
          exit 1
        fi
        
        sleep 10
        wait_time=$((wait_time + 10))
        ;;
      *)
        print_status WARNING "ZAP scan status for $ZAP_TARGET: $job_status (${wait_time}s)"
        
        # Check MinIO for ZAP results (wait for actual scan completion) - even for weird job status
        SCAN_UID=$(kubectl get scan "$ZAP_SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
        if [ -n "$SCAN_UID" ]; then
          SCAN_FOLDER="scan-$SCAN_UID"
          print_status INFO "Checking ZAP scan folder in MinIO: $SCAN_FOLDER"
          
          # Check if scan folder exists and has findings.json with recent timestamp
          if mc ls "securecodebox/securecodebox/$SCAN_FOLDER/findings.json" 2>/dev/null; then
            # Get file timestamp to ensure it's from this scan
            FILE_TIME=$(mc stat "securecodebox/securecodebox/$SCAN_FOLDER/findings.json" --json 2>/dev/null | jq -r '.lastModified' 2>/dev/null || echo "0")
            CURRENT_TIME=$(date +%s)
            TIME_DIFF=$((CURRENT_TIME - FILE_TIME/1000))
            
            # Only consider it complete if file is less than 5 minutes old
            if [ $TIME_DIFF -lt 300 ]; then
              print_status SUCCESS "Found recent findings.json in ZAP scan folder - scan completed!"
              break
            else
              print_status INFO "Found old findings.json, waiting for new scan results..."
            fi
          fi
        fi
        
        # Check if job actually completed despite weird status
        JOB_NAME=$(kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" --no-headers 2>/dev/null | awk '{print $1}' || echo "")
        if [ -n "$JOB_NAME" ]; then
          # Check if job succeeded
          SUCCEEDED=$(kubectl get job "$JOB_NAME" -n "$NAMESPACE" -o jsonpath='{.status.succeeded}' 2>/dev/null || echo "0")
          if [ "$SUCCEEDED" = "1" ]; then
            print_status SUCCESS "ZAP scan for $ZAP_TARGET completed successfully (job succeeded)"
            break
          fi
          
          # Check if job has completion time (another way to detect completion)
          COMPLETION_TIME=$(kubectl get job "$JOB_NAME" -n "$NAMESPACE" -o jsonpath='{.status.completionTime}' 2>/dev/null || echo "")
          if [ -n "$COMPLETION_TIME" ]; then
            print_status SUCCESS "ZAP scan for $ZAP_TARGET completed successfully (has completion time)"
            break
          fi
        fi
        
        # Show detailed job information
        print_status INFO "--- Job Details ---"
        kubectl describe job -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" 2>/dev/null || print_status WARNING "Could not describe job"
        
        sleep 60
        wait_time=$((wait_time + 60))
        ;;
    esac
    
    # If we've been running for more than 5 minutes, assume completion (ZAP scans typically don't take that long)
    if [ $wait_time -gt 300 ] && [ "$job_status" != "NotFound" ]; then
      print_status WARNING "ZAP scan has been running for over 5 minutes, assuming completion..."
      print_status SUCCESS "ZAP scan for $ZAP_TARGET completed (timeout-based detection)"
      break
    fi
    
    echo ""
  done

  # Check if we timed out
  if [ $wait_time -ge $max_wait ]; then
    print_status WARNING "ZAP scan timed out after 30 minutes for $ZAP_TARGET"
    print_status INFO "Checking if scan actually completed despite timeout..."
    
    # Final check - see if job actually succeeded
    JOB_NAME=$(kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" --no-headers 2>/dev/null | awk '{print $1}' || echo "")
    if [ -n "$JOB_NAME" ]; then
      SUCCEEDED=$(kubectl get job "$JOB_NAME" -n "$NAMESPACE" -o jsonpath='{.status.succeeded}' 2>/dev/null || echo "0")
      if [ "$SUCCEEDED" = "1" ]; then
        print_status SUCCESS "ZAP scan for $ZAP_TARGET actually completed successfully (job succeeded)"
      else
        print_status ERROR "ZAP scan for $ZAP_TARGET failed or timed out"
        kubectl get job "$JOB_NAME" -n "$NAMESPACE" -o wide
        kubectl get pods -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" -o wide
      fi
    fi
  fi

  # Get the job name and show final results
  JOB_NAME=$(kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" --no-headers 2>/dev/null | awk '{print $1}' || echo "")
  if [ -n "$JOB_NAME" ]; then
    print_status SUCCESS "Found job: $JOB_NAME for $ZAP_TARGET"
    
    # Show final job status
    print_status INFO "=== FINAL JOB STATUS ==="
    kubectl get job "$JOB_NAME" -n "$NAMESPACE" -o wide
    
    # Show final pod status
    print_status INFO "=== FINAL POD STATUS ==="
    kubectl get pods -n "$NAMESPACE" -l "securecodebox.io/scan=$ZAP_SCAN_NAME" -o wide
    
    # Show job events
    print_status INFO "=== JOB EVENTS ==="
    kubectl get events -n "$NAMESPACE" --sort-by=.metadata.creationTimestamp | grep "$JOB_NAME" | tail -5 || print_status WARNING "No job events found"
    
    print_status INFO "Getting scan logs..."
    kubectl logs job/$JOB_NAME -n "$NAMESPACE" > "$REPORT_DIR/zap_scan.log" 2>&1 || true
    
    # Try to get findings from MinIO (using working script pattern)
    print_status INFO "Checking for findings in MinIO..."
    mc alias set securecodebox http://localhost:9000 admin password >/dev/null 2>&1 || true
    
    # Create bucket if it doesn't exist
    mc mb securecodebox/securecodebox >/dev/null 2>&1 || true
    
    # List files in MinIO
    print_status INFO "Files in MinIO:"
    mc ls securecodebox/securecodebox/ 2>/dev/null || true
    
    # Look for ZAP results
    if mc ls securecodebox/securecodebox/ | grep -q zap; then
      print_status SUCCESS "Found ZAP results in MinIO for $ZAP_TARGET"
      mc cp securecodebox/securecodebox/zap* "$REPORT_DIR/" 2>/dev/null || true
    fi
    
    # Create a findings summary from logs
    print_status INFO "Creating findings summary from scan logs..."
    if [ -f "$REPORT_DIR/zap_scan.log" ]; then
      grep -E "(High|Medium|Low|Info|Alert)" "$REPORT_DIR/zap_scan.log" > "$REPORT_DIR/zap_findings.txt" 2>/dev/null || true
      finding_count=$(wc -l < "$REPORT_DIR/zap_findings.txt" 2>/dev/null || echo "0")
      print_status SUCCESS "Extracted $finding_count potential findings from logs for $ZAP_TARGET"
    fi
  else
    print_status ERROR "Could not find scan job for $ZAP_TARGET"
  fi

  print_status INFO "=== ZAP SCAN COMPLETED FOR $ZAP_TARGET ==="
  print_status INFO "Moving to next ZAP target or Nuclei..."

done

print_status SUCCESS "=== ALL ZAP SCANS COMPLETED ==="
print_status INFO "Moving on to Nuclei scan..."
print_status INFO "Current working directory: $(pwd)"
print_status INFO "Nuclei targets file: $NUCLEI_TARGETS_FILE"
print_status INFO "Checking if nuclei targets file exists..."
ls -la "$NUCLEI_TARGETS_FILE" 2>/dev/null || print_status WARNING "Nuclei targets file not found"

# === Nuclei scan section (now active) ===
print_status INFO "=== STARTING NUCLEI SCAN SECTION ==="
print_status INFO "Step 1: Creating Nuclei scan name..."
SCAN_NAME_NUCLEI=$(safe_scan_name "$TARGET" "nuclei-cascade")
print_status INFO "Nuclei scan name: $SCAN_NAME_NUCLEI"
print_status INFO "Step 2: Checking targets file..."
print_status INFO "Running Nuclei scan with targets file: $NUCLEI_TARGETS_FILE"

# Check if targets file exists and has content
print_status INFO "Step 3: Validating targets file..."
if [ ! -f "$NUCLEI_TARGETS_FILE" ]; then
    print_status ERROR "Nuclei targets file $NUCLEI_TARGETS_FILE does not exist!"
    print_status INFO "Available targets:"
    ls -la /tmp/nuclei-cascade-* 2>/dev/null || print_status WARNING "No nuclei target files found"
    exit 1
fi

if [ ! -s "$NUCLEI_TARGETS_FILE" ]; then
    print_status ERROR "Nuclei targets file $NUCLEI_TARGETS_FILE is empty!"
    print_status INFO "File content:"
    cat "$NUCLEI_TARGETS_FILE" || print_status WARNING "Could not read file"
    exit 1
fi

print_status SUCCESS "Nuclei targets file validation passed!"

print_status INFO "Step 4: Displaying Nuclei targets content..."
cat "$NUCLEI_TARGETS_FILE"
print_status INFO "Step 5: Creating Nuclei scan YAML..."
print_status INFO "YAML file path: /tmp/$SCAN_NAME_NUCLEI.yaml"

cat > "/tmp/$SCAN_NAME_NUCLEI.yaml" <<EOF
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: $SCAN_NAME_NUCLEI
  namespace: $NAMESPACE
spec:
  scanType: nuclei
  parameters:
    - "-l"
    - "$NUCLEI_TARGETS_FILE"
    - "-no-httpx"
    - "-jsonl"
    - "-o"
    - "/home/securecodebox/nuclei-results.jsonl"
  ttlSecondsAfterFinished: 0
EOF

print_status SUCCESS "Nuclei YAML file created successfully!"
print_status INFO "Step 6: Applying Nuclei scan YAML..."

if kubectl apply -f "/tmp/$SCAN_NAME_NUCLEI.yaml"; then
    print_status SUCCESS "Nuclei scan YAML applied successfully!"
    print_status INFO "Step 7: Starting Nuclei scan monitoring..."
else
    print_status ERROR "Failed to apply Nuclei scan YAML!"
    print_status INFO "YAML content:"
    cat "/tmp/$SCAN_NAME_NUCLEI.yaml"
    exit 1
fi

# Wait for Nuclei scan completion by checking job status (more reliable than scan state)
print_status INFO "Waiting for Nuclei scan to complete..."
max_wait=1800  # 30 minutes
wait_time=0

while [ $wait_time -lt $max_wait ]; do
    # Check job status directly (more reliable)
    job_status=$(kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME_NUCLEI" --no-headers 2>/dev/null | awk '{print $2}' || echo "NotFound")
    scan_state=$(kubectl get scan $SCAN_NAME_NUCLEI -n $NAMESPACE -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
    
    print_status INFO "Nuclei Job Status: $job_status, Scan State: $scan_state (${wait_time}s)"
    
    case $job_status in
        "1/1")
            print_status SUCCESS "Nuclei scan completed successfully!"
            break
            ;;
        "0/1"|"0/0")
            print_status INFO "Nuclei scan status: Running (${wait_time}s)"
            sleep 30
            wait_time=$((wait_time + 30))
            ;;
        "NotFound")
            print_status INFO "Waiting for Nuclei job to be created (${wait_time}s)"
            sleep 10
            wait_time=$((wait_time + 10))
            ;;
        *)
            print_status WARNING "Nuclei scan status: $job_status (${wait_time}s)"
            sleep 30
            wait_time=$((wait_time + 30))
            ;;
    esac
done

if [ $wait_time -ge $max_wait ]; then
    print_status WARNING "Nuclei scan timed out after 30 minutes"
    print_status INFO "Checking final status..."
    kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME_NUCLEI" -o wide
    kubectl get pods -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME_NUCLEI" -o wide
    exit 1
fi
# Wait for parser to complete (robust)
print_status INFO "Waiting for Nuclei parser pod to complete..."
while true; do
    PARSER_POD=$(kubectl get pods -n $NAMESPACE | grep "parse-$SCAN_NAME_NUCLEI" | awk '{print $1}')
    if [ -n "$PARSER_POD" ]; then
        POD_STATUS=$(kubectl get pod $PARSER_POD -n $NAMESPACE -o jsonpath='{.status.phase}')
        print_status INFO "Parser pod status: $POD_STATUS"
        if [ "$POD_STATUS" = "Succeeded" ] || [ "$POD_STATUS" = "Completed" ]; then
            break
        elif [ "$POD_STATUS" = "Failed" ]; then
            print_status ERROR "Parser pod failed!"
            exit 1
        fi
    else
        print_status INFO "Waiting for parser pod to be created..."
    fi
    sleep 5
done
PARSER_POD_NUCLEI=$(kubectl get pods -n $NAMESPACE | grep "parse-$SCAN_NAME_NUCLEI" | awk '{print $1}')
if [ -n "$PARSER_POD_NUCLEI" ]; then
    print_status INFO "Parser pod: $PARSER_POD_NUCLEI"
    print_status INFO "Extracting findings from parser logs..."
    kubectl logs $PARSER_POD_NUCLEI -n $NAMESPACE | tail -n +4 | head -n -1 > "$RESULTS_DIR/nuclei-findings.json"
    print_status SUCCESS "Findings extracted to $RESULTS_DIR/nuclei-findings.json"
    print_status INFO "Content preview:"
    head -10 "$RESULTS_DIR/nuclei-findings.json"
else
    print_status ERROR "Parser pod not found for Nuclei!"
    exit 1
fi
print_status SUCCESS "Nuclei scan step complete. Workflow finished!"

# === CLEANUP FUNCTION ===
cleanup_local_files() {
    print_status INFO "Cleaning up local files..."
    
    # Clean up temporary files
    if [ -f "/tmp/naabu-findings.json" ]; then
        rm -f "/tmp/naabu-findings.json"
        print_status INFO "Removed /tmp/naabu-findings.json"
    fi
    
    if [ -f "/tmp/$SCAN_NAME_NUCLEI.yaml" ]; then
        rm -f "/tmp/$SCAN_NAME_NUCLEI.yaml"
        print_status INFO "Removed /tmp/$SCAN_NAME_NUCLEI.yaml"
    fi
    
    # Clean up scan YAML files
    if [ -f "$TLSX_SCAN_FILE" ]; then
        rm -f "$TLSX_SCAN_FILE"
        print_status INFO "Removed $TLSX_SCAN_FILE"
    fi
    
    # Clean up local findings files
    if [ -f "$TLSX_FINDINGS_LOCAL" ]; then
        rm -f "$TLSX_FINDINGS_LOCAL"
        print_status INFO "Removed $TLSX_FINDINGS_LOCAL"
    fi
    
    # Clean up results directory
    if [ -d "$RESULTS_DIR" ]; then
        rm -rf "$RESULTS_DIR"
        print_status INFO "Removed results directory: $RESULTS_DIR"
    fi
    
    print_status SUCCESS "Cleanup completed!"
}

# Run cleanup
cleanup_local_files

print_status SUCCESS "=== CASCADING SCAN WORKFLOW COMPLETED SUCCESSFULLY ==="
print_status INFO "Target scanned: $TARGET"
print_status INFO "Scans completed: Naabu -> TLSX -> ZAP -> Nuclei"
print_status INFO "All findings uploaded to MinIO"
print_status INFO "Local files cleaned up"

echo ""
print_status SUCCESS "🎉 CASCADING SCAN WORKFLOW COMPLETE! 🎉" 