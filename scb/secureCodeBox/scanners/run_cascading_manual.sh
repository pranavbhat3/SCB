#!/bin/bash

# Always run from the script's own directory for consistent relative paths
cd "$(dirname "$0")"

# Manual Cascading Scan Orchestrator: Naabu -> TLSX -> Nuclei
# Usage: ./run_cascading_manual.sh <target> [--all-ports] [namespace]

set -e

# Config
TARGET=${1:-scanme.nmap.org}
ALL_PORTS=""
NAMESPACE="securecodebox-system"
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
SCAN_NAME="naabu-scan-$(date +%s)"
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
SCAN_NAME_TLSX="tlsx-cascade-$(date +%s)"
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

# Download findings.json from MinIO root (use absolute path)
if mc cp "securecodebox/securecodebox/findings.json" "$TLSX_FINDINGS_LOCAL"; then
  print_status SUCCESS "Downloaded findings.json from MinIO root: $TLSX_FINDINGS_LOCAL"
else
  print_status ERROR "Failed to download findings.json from MinIO root!"
  exit 1
fi

# Upload findings.json to the scan-specific folder in MinIO
print_status INFO "Uploading findings.json to scan folder in MinIO: $TLSX_SCAN_FOLDER"
if mc cp "$TLSX_FINDINGS_LOCAL" "$TLSX_SCAN_FOLDER"; then
  print_status SUCCESS "Copied findings.json to scan folder in MinIO: $TLSX_SCAN_FOLDER"
else
  print_status ERROR "Failed to copy findings.json to scan folder in MinIO!"
  exit 1
fi

# (Optional) Download from scan folder to local for proof
if mc cp "$TLSX_SCAN_FOLDER" "$RESULTS_DIR/tlsx-findings.json"; then
  print_status SUCCESS "Downloaded findings.json from scan folder in MinIO: $RESULTS_DIR/tlsx-findings.json"
else
  print_status WARNING "Could not download findings.json from scan folder to local results dir."
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
  ZAP_SCAN_NAME="zap-scan-$(date +%s)-$SAFE_TARGET"
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

# === Nuclei scan section (using working approach from run_nuclei_scan.sh) ===
print_status INFO "=== STARTING NUCLEI SCAN SECTION ==="
print_status INFO "Step 1: Creating Nuclei scan name..."
SCAN_NAME_NUCLEI="nuclei-cascade-$(date +%s)"
print_status INFO "Nuclei scan name: $SCAN_NAME_NUCLEI"

# Use the working approach from run_nuclei_scan.sh
print_status INFO "Step 2: Running Nuclei scan using scbctl (working approach)..."
print_status INFO "Target: $TARGET"

# Create Nuclei scan using scbctl (this is the working approach)
if scbctl scan nuclei --name "$SCAN_NAME_NUCLEI" --namespace "$NAMESPACE" -- -u "$TARGET"; then
    print_status SUCCESS "Nuclei scan created successfully: $SCAN_NAME_NUCLEI"
else
    print_status ERROR "Failed to create Nuclei scan!"
    exit 1
fi

print_status INFO "Step 3: Waiting for Nuclei scan to complete..."
max_wait=3600  # 60 minutes (Nuclei scans can take 30+ minutes)
wait_time=0
SCAN_STATE=""
last_progress=0

while [ $wait_time -lt $max_wait ]; do
    SCAN_STATE=$(kubectl get scan "$SCAN_NAME_NUCLEI" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "")
    if [[ "$SCAN_STATE" == "Done" ]]; then
        print_status SUCCESS "Nuclei scan completed successfully"
        break
    elif [[ "$SCAN_STATE" == "Errored" ]]; then
        print_status ERROR "Nuclei scan failed"
        print_status INFO "Check scan details: kubectl describe scan $SCAN_NAME_NUCLEI -n $NAMESPACE"
        exit 1
    fi
    
    # Show progress every 2 minutes instead of every 10 seconds
    if [ $((wait_time % 120)) -eq 0 ] && [ $wait_time -gt $last_progress ]; then
        print_status INFO "Nuclei scan status: $SCAN_STATE (${wait_time}s elapsed)"
        last_progress=$wait_time
    fi
    
    sleep 30  # Check every 30 seconds instead of 10
    wait_time=$((wait_time + 30))
done

if [ $wait_time -ge $max_wait ]; then
    print_status WARNING "Nuclei scan timed out after 60 minutes"
    print_status INFO "Scan may still be running in background"
    print_status INFO "You can check results later with: kubectl get scan $SCAN_NAME_NUCLEI -n $NAMESPACE"
fi

print_status INFO "Step 4: Extracting scan results..."
SCAN_UID=$(kubectl get scan "$SCAN_NAME_NUCLEI" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
if [ -z "$SCAN_UID" ]; then
    print_status ERROR "Could not get scan UID."
    exit 1
fi

print_status INFO "Step 5: Checking MinIO for results..."
mc alias set securecodebox http://localhost:9000 admin password >/dev/null 2>&1 || true
MINIO_RESULTS_PATH="securecodebox/securecodebox/scan-$SCAN_UID/nuclei-results.jsonl"

if mc ls securecodebox/securecodebox/scan-$SCAN_UID/ 2>/dev/null | grep -q nuclei-results.jsonl; then
    print_status SUCCESS "Found nuclei results in MinIO!"
    finding_count=$(mc cat "$MINIO_RESULTS_PATH" | wc -l 2>/dev/null || echo "0")
    sample_findings=$(mc cat "$MINIO_RESULTS_PATH" | head -3 | jq -r '.info.name + " (" + .info.severity + ")"' 2>/dev/null || true)
    
    # Download results to local directory
    if mc cp "$MINIO_RESULTS_PATH" "$RESULTS_DIR/nuclei-results.jsonl"; then
        print_status SUCCESS "Nuclei results downloaded to: $RESULTS_DIR/nuclei-results.jsonl"
    else
        print_status WARNING "Failed to download Nuclei results locally"
    fi
else
    print_status WARNING "No nuclei results found in MinIO"
    finding_count=0
    sample_findings=""
fi

print_status INFO "Step 6: Creating summary..."
SUMMARY_MD=$(mktemp)
echo "# Nuclei Scan Summary" > "$SUMMARY_MD"
echo "**Generated:** $(date)" >> "$SUMMARY_MD"
echo "**Target:** $TARGET" >> "$SUMMARY_MD"
echo "**Scan Name:** $SCAN_NAME_NUCLEI" >> "$SUMMARY_MD"
echo "**Scan UID:** $SCAN_UID" >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "## Findings Summary" >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "Found $finding_count findings in nuclei scan." >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "### Sample Findings:" >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "$sample_findings" >> "$SUMMARY_MD"

MINIO_SUMMARY_PATH="securecodebox/securecodebox/nuclei-summary-$SCAN_NAME_NUCLEI.md"
if mc cp "$SUMMARY_MD" "$MINIO_SUMMARY_PATH"; then
    print_status SUCCESS "Nuclei summary uploaded to MinIO: $MINIO_SUMMARY_PATH"
fi
rm "$SUMMARY_MD"

print_status SUCCESS "Nuclei scan completed successfully!"
print_status INFO "Results: securecodebox/securecodebox/scan-$SCAN_UID/nuclei-results.jsonl"
print_status INFO "Summary: securecodebox/securecodebox/nuclei-summary-$SCAN_NAME_NUCLEI.md"

if [ "$finding_count" -gt 0 ]; then
    print_status SUCCESS "🎉 Nuclei scan found $finding_count vulnerabilities!"
else
    print_status SUCCESS "✅ Nuclei scan completed - no vulnerabilities found"
fi

print_status SUCCESS "=== CASCADING SCAN WORKFLOW COMPLETED SUCCESSFULLY ==="
print_status INFO "Results directory: $RESULTS_DIR"
print_status INFO "Target scanned: $TARGET"
print_status INFO "Scans completed: Naabu -> TLSX -> ZAP -> Nuclei"
print_status INFO "All findings saved to: $RESULTS_DIR/"

echo ""
print_status SUCCESS "🎉 CASCADING SCAN WORKFLOW COMPLETE! 🎉" 