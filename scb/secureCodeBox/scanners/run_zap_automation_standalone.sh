#!/bin/bash

# ZAP Automation Framework Standalone Script
# Based on official secureCodeBox documentation
# Usage: ./run_zap_automation_standalone.sh <target_url> [scan_type] [namespace]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TARGET=${1:-"https://scanme.nmap.org"}
SCAN_TYPE=${2:-"baseline"}  # Options: baseline, comprehensive, api, custom
NAMESPACE=${3:-"default"}
SCAN_NAME="zap-automation-$(date +%s)"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_DIR="zap_automation_reports_$TIMESTAMP"

# Create report directory
mkdir -p "$REPORT_DIR"

echo -e "${PURPLE}🕷️  ZAP AUTOMATION FRAMEWORK STANDALONE SCRIPT${NC}"
echo -e "${CYAN}Target: $TARGET${NC}"
echo -e "${CYAN}Scan Type: $SCAN_TYPE${NC}"
echo -e "${CYAN}Scan Name: $SCAN_NAME${NC}"
echo -e "${CYAN}Report Directory: $REPORT_DIR${NC}"
echo ""

# Function to print status
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "RUNNING")
            echo -e "${CYAN}🔄 $message${NC}"
            ;;
    esac
}

# Check prerequisites
print_status "INFO" "Checking prerequisites..."

# Check if scbctl is available
if ! command -v scbctl >/dev/null 2>&1; then
    print_status "ERROR" "scbctl is not available"
    print_status "INFO" "Please install scbctl first"
    exit 1
fi

# Check if ZAP automation framework is available
if ! kubectl get scantypes -n "$NAMESPACE" | grep -q zap-automation-framework; then
    print_status "ERROR" "ZAP automation framework is not available in namespace $NAMESPACE"
    print_status "INFO" "Available ZAP scantypes in $NAMESPACE:"
    kubectl get scantypes -n "$NAMESPACE" | grep zap || print_status "INFO" "No ZAP scantypes found"
    print_status "INFO" "Please ensure ZAP automation framework is installed in SecureCodeBox"
    exit 1
fi

print_status "SUCCESS" "All prerequisites met"
print_status "INFO" "Using zap-automation-framework with automation configuration"

# Validate target URL
if [[ ! "$TARGET" =~ ^https?:// ]]; then
    print_status "WARNING" "Target doesn't start with http:// or https://"
    print_status "INFO" "Adding https:// prefix..."
    TARGET="https://$TARGET"
    print_status "INFO" "Updated target: $TARGET"
fi

# Create scan configuration based on scan type
create_scan_config() {
    local scan_type=$1
    local target=$2
    local config_file="$REPORT_DIR/automation.yaml"
    
    case $scan_type in
        "baseline")
            cat > "$config_file" << EOF
env:
  contexts:
    - name: zap-baseline-automation-scan
      urls: ["$target"]
jobs:
  - type: spider
    parameters:
      context: zap-baseline-automation-scan
      maxDuration: 2
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
  - type: report
    parameters:
      template: traditional-xml
      reportDir: /home/securecodebox/
      reportFile: zap-results
    risks:
      - high
      - medium
      - low
EOF
            ;;
        "comprehensive")
            cat > "$config_file" << EOF
env:
  contexts:
    - name: zap-comprehensive-automation-scan
      urls: ["$target"]
jobs:
  - type: spider
    parameters:
      context: zap-comprehensive-automation-scan
      maxDuration: 10
  - type: ajaxSpider
    parameters:
      context: zap-comprehensive-automation-scan
      maxDuration: 10
  - type: passiveScan-wait
    parameters:
      maxDuration: 10
  - type: activeScan
    parameters:
      context: zap-comprehensive-automation-scan
      maxDuration: 30
  - type: passiveScan-wait
    parameters:
      maxDuration: 10
  - type: report
    parameters:
      template: traditional-xml
      reportDir: /home/securecodebox/
      reportFile: zap-results
    risks:
      - high
      - medium
      - low
      - info
EOF
            ;;
        "api")
            cat > "$config_file" << EOF
env:
  contexts:
    - name: zap-api-automation-scan
      urls: ["$target"]
jobs:
  - type: spider
    parameters:
      context: zap-api-automation-scan
      maxDuration: 5
  - type: apiScan
    parameters:
      context: zap-api-automation-scan
      definition: "$target/openapi.json"
  - type: passiveScan-wait
    parameters:
      maxDuration: 10
  - type: activeScan
    parameters:
      context: zap-api-automation-scan
      maxDuration: 20
  - type: report
    parameters:
      template: traditional-xml
      reportDir: /home/securecodebox/
      reportFile: zap-results
    risks:
      - high
      - medium
      - low
EOF
            ;;
        "custom")
            cat > "$config_file" << EOF
env:
  contexts:
    - name: zap-custom-automation-scan
      urls: ["$target"]
jobs:
  - type: spider
    parameters:
      context: zap-custom-automation-scan
      maxDuration: 15
  - type: ajaxSpider
    parameters:
      context: zap-custom-automation-scan
      maxDuration: 15
  - type: passiveScan-wait
    parameters:
      maxDuration: 15
  - type: activeScan
    parameters:
      context: zap-custom-automation-scan
      maxDuration: 45
  - type: passiveScan-wait
    parameters:
      maxDuration: 15
  - type: report
    parameters:
      template: traditional-xml
      reportDir: /home/securecodebox/
      reportFile: zap-results
    risks:
      - high
      - medium
      - low
      - info
EOF
            ;;
        *)
            print_status "ERROR" "Unknown scan type: $scan_type"
            print_status "INFO" "Available scan types: baseline, comprehensive, api, custom"
            exit 1
            ;;
    esac
    
    print_status "SUCCESS" "Created scan configuration: $config_file"
    print_status "INFO" "Configuration preview:"
    echo "---"
    cat "$config_file"
    echo "---"
}

# Create scan configuration
print_status "INFO" "Creating scan configuration for $SCAN_TYPE scan..."
create_scan_config "$SCAN_TYPE" "$TARGET"

# Create ConfigMap for the scan (following official docs)
print_status "RUNNING" "Creating ConfigMap for ZAP automation scan..."
kubectl create configmap "$SCAN_NAME-config" --from-file="$REPORT_DIR/automation.yaml" -n "$NAMESPACE" --dry-run=client -o yaml > "$REPORT_DIR/configmap.yaml"

# Apply the ConfigMap
kubectl apply -f "$REPORT_DIR/configmap.yaml"

# Create scan YAML following the official documentation structure
print_status "RUNNING" "Creating ZAP automation framework scan..."
cat > "$REPORT_DIR/scan.yaml" << EOF
apiVersion: "execution.securecodebox.io/v1"
kind: Scan
metadata:
  name: "$SCAN_NAME"
  namespace: "$NAMESPACE"
spec:
  scanType: "zap-automation-framework"
  parameters:
    - "-autorun"
    - "/home/securecodebox/scb-automation/automation.yaml"
  volumeMounts:
    - name: "$SCAN_NAME-config"
      mountPath: /home/securecodebox/scb-automation/automation.yaml
      subPath: automation.yaml
  volumes:
    - name: "$SCAN_NAME-config"
      configMap:
        name: "$SCAN_NAME-config"
EOF

# Apply the scan
kubectl apply -f "$REPORT_DIR/scan.yaml"

if [ $? -eq 0 ]; then
    print_status "SUCCESS" "ZAP automation scan created: $SCAN_NAME"
else
    print_status "ERROR" "Failed to create ZAP automation scan"
    exit 1
fi

# Wait for scan completion
print_status "INFO" "Waiting for ZAP automation scan to complete..."
max_wait=3600  # 60 minutes for comprehensive scans
wait_time=0

while [ $wait_time -lt $max_wait ]; do
    # Check scan status
    SCAN_STATE=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "NotFound")
    
    case $SCAN_STATE in
        "Done")
            print_status "SUCCESS" "ZAP automation scan completed successfully"
            break
            ;;
        "Errored")
            print_status "ERROR" "ZAP automation scan failed"
            print_status "INFO" "Check scan details: kubectl describe scan $SCAN_NAME -n $NAMESPACE"
            exit 1
            ;;
        "Scanning"|"Scheduled")
            print_status "INFO" "ZAP automation scan status: $SCAN_STATE (${wait_time}s)"
            
            # Show progress every 2 minutes
            if [ $((wait_time % 120)) -eq 0 ] && [ $wait_time -gt 0 ]; then
                print_status "INFO" "--- Progress Update ---"
                print_status "INFO" "Scan running for ${wait_time}s"
                
                # Show related pods
                kubectl get pods -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME" --no-headers 2>/dev/null || print_status "WARNING" "No scan pods found"
            fi
            
            sleep 30
            wait_time=$((wait_time + 30))
            ;;
        "NotFound")
            print_status "INFO" "Waiting for scan to be created (${wait_time}s)"
            sleep 10
            wait_time=$((wait_time + 10))
            ;;
        *)
            print_status "WARNING" "ZAP automation scan status: $SCAN_STATE (${wait_time}s)"
            sleep 30
            wait_time=$((wait_time + 30))
            ;;
    esac
done

if [ $wait_time -ge $max_wait ]; then
    print_status "WARNING" "ZAP automation scan timed out after 60 minutes"
    print_status "INFO" "Scan may still be running in background"
fi

# Extract scan results
print_status "INFO" "Extracting scan results..."

# Get scan UID for MinIO path
SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
if [ -n "$SCAN_UID" ]; then
    SCAN_FOLDER="scan-$SCAN_UID"
    print_status "INFO" "Scan folder in MinIO: $SCAN_FOLDER"
    
    # Download results from MinIO
    print_status "INFO" "Downloading results from MinIO..."
    
    # Setup MinIO client
    mc alias set myminio http://localhost:9000 admin password >/dev/null 2>&1 || true
    
    # Port forward to MinIO
    kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000 &
    PF_PID=$!
    sleep 5
    
    # Download all files from scan folder
    if mc ls "myminio/securecodebox/$SCAN_FOLDER/" 2>/dev/null; then
        print_status "SUCCESS" "Found scan results in MinIO"
        mc cp "myminio/securecodebox/$SCAN_FOLDER/" "$REPORT_DIR/" --recursive 2>/dev/null || true
    else
        print_status "WARNING" "No scan results found in MinIO folder: $SCAN_FOLDER"
    fi
    
    # Kill port-forward
    kill $PF_PID 2>/dev/null || true
else
    print_status "WARNING" "Could not determine scan UID"
fi

# Get scan logs
print_status "INFO" "Getting scan logs..."
kubectl logs -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME" --all-containers > "$REPORT_DIR/zap_automation_scan.log" 2>&1 || true

# Generate summary report
summary_file="$REPORT_DIR/zap_automation_summary.md"
echo "# ZAP Automation Framework Scan Summary" > "$summary_file"
echo "**Generated:** $(date)" >> "$summary_file"
echo "**Target:** $TARGET" >> "$summary_file"
echo "**Scan Type:** $SCAN_TYPE" >> "$summary_file"
echo "**Scan Name:** $SCAN_NAME" >> "$summary_file"
echo "**Scan UID:** $SCAN_UID" >> "$summary_file"
echo "**Duration:** ${wait_time}s" >> "$summary_file"
echo "" >> "$summary_file"

# Add scan configuration
echo "## Scan Configuration" >> "$summary_file"
echo "" >> "$summary_file"
echo "Used configuration for $SCAN_TYPE scan:" >> "$summary_file"
echo "" >> "$summary_file"
echo '```yaml' >> "$summary_file"
cat "$REPORT_DIR/automation.yaml" >> "$summary_file"
echo '```' >> "$summary_file"
echo "" >> "$summary_file"

# Add findings summary
echo "## Results Summary" >> "$summary_file"
echo "" >> "$summary_file"

# Count findings if JSON results exist
if [ -f "$REPORT_DIR/zap-results.json" ]; then
    finding_count=$(jq '.site[] | .alerts | length' "$REPORT_DIR/zap-results.json" 2>/dev/null | awk '{sum += $1} END {print sum}' || echo "0")
    echo "**Total Findings:** $finding_count" >> "$summary_file"
    
    # Count by risk level
    high_count=$(jq '.site[] | .alerts[] | select(.riskcode == 3) | .name' "$REPORT_DIR/zap-results.json" 2>/dev/null | wc -l || echo "0")
    medium_count=$(jq '.site[] | .alerts[] | select(.riskcode == 2) | .name' "$REPORT_DIR/zap-results.json" 2>/dev/null | wc -l || echo "0")
    low_count=$(jq '.site[] | .alerts[] | select(.riskcode == 1) | .name' "$REPORT_DIR/zap-results.json" 2>/dev/null | wc -l || echo "0")
    info_count=$(jq '.site[] | .alerts[] | select(.riskcode == 0) | .name' "$REPORT_DIR/zap-results.json" 2>/dev/null | wc -l || echo "0")
    
    echo "**High Risk:** $high_count" >> "$summary_file"
    echo "**Medium Risk:** $medium_count" >> "$summary_file"
    echo "**Low Risk:** $low_count" >> "$summary_file"
    echo "**Info:** $info_count" >> "$summary_file"
else
    echo "**Results:** JSON results not found" >> "$summary_file"
fi

echo "" >> "$summary_file"
echo "## Files Generated" >> "$summary_file"
echo "" >> "$summary_file"
echo "The following files were generated:" >> "$summary_file"
echo "" >> "$summary_file"
ls -la "$REPORT_DIR/" | grep -v "^total" >> "$summary_file" 2>/dev/null || echo "No files found" >> "$summary_file"

echo "" >> "$summary_file"
echo "## Next Steps" >> "$summary_file"
echo "" >> "$summary_file"
echo "1. Review the JSON results: \`cat $REPORT_DIR/zap-results.json\`" >> "$summary_file"
echo "2. Check scan logs: \`cat $REPORT_DIR/zap_automation_scan.log\`" >> "$summary_file"
echo "3. Clean up scan resources: \`kubectl delete scan $SCAN_NAME -n $NAMESPACE\`" >> "$summary_file"

print_status "SUCCESS" "Summary report generated: $summary_file"

# Final summary
echo ""
print_status "SUCCESS" "=== ZAP AUTOMATION FRAMEWORK SCAN COMPLETE ==="
print_status "INFO" "Scan Name: $SCAN_NAME"
print_status "INFO" "Scan Type: $SCAN_TYPE"
print_status "INFO" "Target: $TARGET"
print_status "INFO" "Duration: ${wait_time}s"
print_status "INFO" "Report Directory: $REPORT_DIR"
print_status "INFO" "Summary: $summary_file"

if [ "$finding_count" -gt 0 ]; then
    print_status "SUCCESS" "🎉 ZAP automation scan found $finding_count security issues!"
    print_status "INFO" "High: $high_count, Medium: $medium_count, Low: $low_count, Info: $info_count"
else
    print_status "SUCCESS" "✅ ZAP automation scan completed - no security issues found"
fi

echo ""
print_status "INFO" "To view results:"
echo "  cat $summary_file"
echo "  ls -la $REPORT_DIR/"
echo "  kubectl logs -n $NAMESPACE -l securecodebox.io/scan=$SCAN_NAME"
echo ""
print_status "INFO" "Available scan types:"
echo "  baseline     - Quick scan (2-5 minutes)"
echo "  comprehensive - Full scan with active testing (30-60 minutes)"
echo "  api         - API-focused scan (20-30 minutes)"
echo "  custom      - Extended scan (45-90 minutes)"
echo "" 