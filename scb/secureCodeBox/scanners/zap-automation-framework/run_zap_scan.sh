#!/bin/bash

# ZAP Scanner Script for SecureCodeBox
# Runs ZAP baseline scan and extracts findings

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
SCAN_NAME="zap-scan-$(date +%s)"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_DIR="zap_reports_$TIMESTAMP"

# Create report directory
mkdir -p "$REPORT_DIR"

echo -e "${PURPLE}🕷️  ZAP SCANNER SCRIPT${NC}"
echo -e "${CYAN}Target: $TARGET${NC}"
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

# Check if ZAP scanner is available
if ! kubectl get scantypes | grep -q zap-baseline-scan; then
    print_status "ERROR" "ZAP baseline scanner is not available"
    print_status "INFO" "Please ensure ZAP scanner is installed in SecureCodeBox"
    exit 1
fi

print_status "SUCCESS" "All prerequisites met"

# Validate target URL
if [[ ! "$TARGET" =~ ^https?:// ]]; then
    print_status "WARNING" "Target doesn't start with http:// or https://"
    print_status "INFO" "Adding https:// prefix..."
    TARGET="https://$TARGET"
    print_status "INFO" "Updated target: $TARGET"
fi

# Create ZAP scan
print_status "RUNNING" "Creating ZAP baseline scan..."
scbctl scan zap-baseline-scan --name "$SCAN_NAME" -- -t "$TARGET"

if [ $? -eq 0 ]; then
    print_status "SUCCESS" "ZAP scan created: $SCAN_NAME"
else
    print_status "ERROR" "Failed to create ZAP scan"
    exit 1
fi

# Wait for scan completion by checking job status
print_status "INFO" "Waiting for ZAP scan to complete..."
max_wait=1800  # 30 minutes for ZAP (it can take a while)
wait_time=0

while [ $wait_time -lt $max_wait ]; do
    # Check if job exists and get its status
    job_status=$(kubectl get job -l "securecodebox.io/scan=$SCAN_NAME" --no-headers 2>/dev/null | awk '{print $2}' || echo "NotFound")
    
    case $job_status in
        "1/1")
            print_status "SUCCESS" "ZAP scan completed successfully"
            break
            ;;
        "0/1"|"0/0")
            print_status "INFO" "ZAP scan status: Running (${wait_time}s)"
            sleep 60  # Check every minute for ZAP
            wait_time=$((wait_time + 60))
            ;;
        "NotFound")
            print_status "INFO" "Waiting for job to be created (${wait_time}s)"
            sleep 10
            wait_time=$((wait_time + 10))
            ;;
        *)
            print_status "WARNING" "ZAP scan status: $job_status (${wait_time}s)"
            sleep 60
            wait_time=$((wait_time + 60))
            ;;
    esac
done

if [ $wait_time -ge $max_wait ]; then
    print_status "WARNING" "ZAP scan timed out after 30 minutes"
    print_status "INFO" "Scan may still be running in background"
fi

# Get the job name
JOB_NAME=$(kubectl get job -l "securecodebox.io/scan=$SCAN_NAME" --no-headers 2>/dev/null | awk '{print $1}' || echo "")

if [ -n "$JOB_NAME" ]; then
    print_status "SUCCESS" "Found job: $JOB_NAME"
    
    # Get job logs
    print_status "INFO" "Getting scan logs..."
    kubectl logs job/$JOB_NAME > "$REPORT_DIR/zap_scan.log" 2>&1 || true
    
    # Check if scan was successful
    if kubectl get job $JOB_NAME -o jsonpath='{.status.succeeded}' 2>/dev/null | grep -q "1"; then
        print_status "SUCCESS" "Scan job completed successfully"
        
        # Try to get findings from MinIO
        print_status "INFO" "Checking for findings in MinIO..."
        kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000 &
        PF_PID=$!
        sleep 5
        
        # Configure mc client with correct credentials
        mc alias set myminio http://localhost:9000 admin password >/dev/null 2>&1 || true
        
        # Create bucket if it doesn't exist
        mc mb myminio/securecodebox >/dev/null 2>&1 || true
        
        # List files in MinIO
        print_status "INFO" "Files in MinIO:"
        mc ls myminio/securecodebox/ 2>/dev/null || true
        
        # Look for ZAP results
        if mc ls myminio/securecodebox/ | grep -q zap; then
            print_status "SUCCESS" "Found ZAP results in MinIO"
            mc cp myminio/securecodebox/zap* "$REPORT_DIR/" 2>/dev/null || true
        fi
        
        # Kill port-forward
        kill $PF_PID 2>/dev/null || true
        
        # Create a findings summary from logs
        print_status "INFO" "Creating findings summary from scan logs..."
        if [ -f "$REPORT_DIR/zap_scan.log" ]; then
            # Extract findings from logs
            grep -E "(High|Medium|Low|Info|Alert)" "$REPORT_DIR/zap_scan.log" > "$REPORT_DIR/zap_findings.txt" 2>/dev/null || true
            
            finding_count=$(wc -l < "$REPORT_DIR/zap_findings.txt" 2>/dev/null || echo "0")
            print_status "SUCCESS" "Extracted $finding_count potential findings from logs"
        fi
    else
        print_status "ERROR" "Scan job failed"
        print_status "INFO" "Check logs for details: kubectl logs job/$JOB_NAME"
    fi
else
    print_status "ERROR" "Could not find scan job"
fi

# Generate summary
summary_file="$REPORT_DIR/zap_summary.md"
echo "# ZAP Baseline Scan Summary" > "$summary_file"
echo "**Generated:** $(date)" >> "$summary_file"
echo "**Target:** $TARGET" >> "$summary_file"
echo "**Scan Name:** $SCAN_NAME" >> "$summary_file"
echo "**Job Name:** $JOB_NAME" >> "$summary_file"
echo "" >> "$summary_file"

if [ -f "$REPORT_DIR/zap_findings.txt" ]; then
    echo "## Findings Summary" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Found $finding_count potential findings in scan logs." >> "$summary_file"
    echo "" >> "$summary_file"
    echo "### Sample Findings:" >> "$summary_file"
    echo "" >> "$summary_file"
    head -10 "$REPORT_DIR/zap_findings.txt" >> "$summary_file" 2>/dev/null || true
fi

echo "" >> "$summary_file"
echo "## Scan Logs" >> "$summary_file"
echo "" >> "$summary_file"
echo "Full scan logs are available in: \`$REPORT_DIR/zap_scan.log\`" >> "$summary_file"

print_status "SUCCESS" "Summary report generated: $summary_file"

# Final summary
echo ""
print_status "SUCCESS" "=== ZAP SCAN COMPLETE ==="
print_status "INFO" "Scan Name: $SCAN_NAME"
print_status "INFO" "Job Name: $JOB_NAME"
print_status "INFO" "Findings: $finding_count"
print_status "INFO" "Report Directory: $REPORT_DIR"
print_status "INFO" "Summary: $summary_file"

if [ "$finding_count" -gt 0 ]; then
    print_status "SUCCESS" "🎉 ZAP scan found $finding_count potential security issues!"
else
    print_status "SUCCESS" "✅ ZAP scan completed - no security issues found"
fi

echo ""
print_status "INFO" "To view results:"
echo "  cat $summary_file"
echo "  ls -la $REPORT_DIR/"
echo "  kubectl logs job/$JOB_NAME"
echo "" 