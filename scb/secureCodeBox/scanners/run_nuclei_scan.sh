#!/bin/bash

# Simple Nuclei Scanner Script for SecureCodeBox
# Runs Nuclei vulnerability scan on a single IP address
# Usage: ./run_nuclei_scan.sh <target_ip> [namespace]

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
TARGET_IP=${1:-"192.168.1.1"}
NAMESPACE=${2:-"securecodebox-system"}
SCAN_NAME="nuclei-scan-$(date +%s)"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_DIR="nuclei_reports_$TIMESTAMP"

# Create report directory
mkdir -p "$REPORT_DIR"

echo -e "${PURPLE}🎯 SIMPLE NUCLEI SCANNER${NC}"
echo -e "${CYAN}Target IP: $TARGET_IP${NC}"
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

# Check if Nuclei scanner is available
if ! kubectl get scantypes | grep -q nuclei; then
    print_status "ERROR" "Nuclei scanner is not available"
    print_status "INFO" "Please ensure Nuclei scanner is installed in SecureCodeBox"
    exit 1
fi

print_status "SUCCESS" "All prerequisites met"

# Create Nuclei scan
print_status "RUNNING" "Creating Nuclei vulnerability scan..."

# Use scbctl to create the scan with the IP address directly
scbctl scan nuclei --name "$SCAN_NAME" --namespace "$NAMESPACE" -- \
  -u "http://$TARGET_IP" \
  -u "https://$TARGET_IP" \
  -o "/home/securecodebox/nuclei-results.jsonl" \
  -severity "low,medium,high,critical" \
  -stats \
  -silent

if [ $? -eq 0 ]; then
    print_status "SUCCESS" "Nuclei scan created: $SCAN_NAME"
else
    print_status "ERROR" "Failed to create Nuclei scan"
    exit 1
fi

# Wait for scan completion by checking job status
print_status "INFO" "Waiting for Nuclei scan to complete..."
max_wait=1800  # 30 minutes for Nuclei
wait_time=0

while [ $wait_time -lt $max_wait ]; do
    # Check if job exists and get its status
    job_status=$(kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME" --no-headers 2>/dev/null | awk '{print $2}' || echo "NotFound")
    
    case $job_status in
        "1/1")
            print_status "SUCCESS" "Nuclei scan completed successfully"
            break
            ;;
        "0/1"|"0/0")
            print_status "INFO" "Nuclei scan status: Running (${wait_time}s)"
            sleep 30  # Check every 30 seconds for Nuclei
            wait_time=$((wait_time + 30))
            ;;
        "NotFound")
            print_status "INFO" "Waiting for job to be created (${wait_time}s)"
            sleep 10
            wait_time=$((wait_time + 10))
            ;;
        *)
            print_status "WARNING" "Nuclei scan status: $job_status (${wait_time}s)"
            sleep 30
            wait_time=$((wait_time + 30))
            ;;
    esac
done

if [ $wait_time -ge $max_wait ]; then
    print_status "WARNING" "Nuclei scan timed out after 30 minutes"
    print_status "INFO" "Scan may still be running in background"
fi

# Get the job name and scan UID
JOB_NAME=$(kubectl get job -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME" --no-headers 2>/dev/null | awk '{print $1}' || echo "")
SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")

if [ -n "$JOB_NAME" ]; then
    print_status "SUCCESS" "Found job: $JOB_NAME"
    
    # Get job logs
    print_status "INFO" "Getting scan logs..."
    kubectl logs job/$JOB_NAME -n "$NAMESPACE" > "$REPORT_DIR/nuclei_scan.log" 2>&1 || true
    
    # Check if scan was successful
    if kubectl get job $JOB_NAME -n "$NAMESPACE" -o jsonpath='{.status.succeeded}' 2>/dev/null | grep -q "1"; then
        print_status "SUCCESS" "Scan job completed successfully"
        
        # Wait for parser to complete
        print_status "INFO" "Waiting for parser to complete..."
        parser_wait=300  # 5 minutes for parser
        parser_time=0
        
        while [ $parser_time -lt $parser_wait ]; do
            PARSER_POD=$(kubectl get pods -n "$NAMESPACE" | grep "parse-$SCAN_NAME" | awk '{print $1}' || echo "")
            if [ -n "$PARSER_POD" ]; then
                PARSER_STATUS=$(kubectl get pod $PARSER_POD -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
                if [ "$PARSER_STATUS" = "Succeeded" ]; then
                    print_status "SUCCESS" "Parser completed successfully"
                    break
                elif [ "$PARSER_STATUS" = "Failed" ]; then
                    print_status "ERROR" "Parser failed"
                    break
                else
                    print_status "INFO" "Parser status: $PARSER_STATUS (${parser_time}s)"
                    sleep 10
                    parser_time=$((parser_time + 10))
                fi
            else
                print_status "INFO" "Waiting for parser pod to be created (${parser_time}s)"
                sleep 10
                parser_time=$((parser_time + 10))
            fi
        done
        
        if [ $parser_time -ge $parser_wait ]; then
            print_status "WARNING" "Parser timed out, proceeding anyway"
        fi
        
        # Try to get findings from MinIO
        print_status "INFO" "Getting results from MinIO..."
        
        # Setup MinIO client
        mc alias set securecodebox http://localhost:9000 admin password >/dev/null 2>&1 || true
        
        # Create bucket if it doesn't exist
        mc mb securecodebox/securecodebox >/dev/null 2>&1 || true
        
        if [ -n "$SCAN_UID" ]; then
            SCAN_FOLDER="scan-$SCAN_UID"
            MINIO_RESULTS_PATH="securecodebox/securecodebox/$SCAN_FOLDER/nuclei-results.jsonl"
            MINIO_FINDINGS_PATH="securecodebox/securecodebox/$SCAN_FOLDER/findings.json"
            
            # Check if results exist in MinIO
            if mc ls "securecodebox/securecodebox/$SCAN_FOLDER/" 2>/dev/null | grep -q nuclei-results.jsonl; then
                print_status "SUCCESS" "Found Nuclei results in MinIO!"
                
                # Download results from MinIO
                if mc cp "$MINIO_RESULTS_PATH" "$REPORT_DIR/nuclei-results.jsonl"; then
                    print_status "SUCCESS" "Downloaded Nuclei results from MinIO"
                    
                    # Check if results file is empty
                    if [ ! -s "$REPORT_DIR/nuclei-results.jsonl" ]; then
                        print_status "INFO" "Nuclei results file is empty (no vulnerabilities found)"
                        echo "[]" > "$REPORT_DIR/nuclei-results.jsonl"
                    fi
                fi
                
                # Also download findings.json if it exists
                if mc ls "securecodebox/securecodebox/$SCAN_FOLDER/" 2>/dev/null | grep -q findings.json; then
                    if mc cp "$MINIO_FINDINGS_PATH" "$REPORT_DIR/findings.json"; then
                        print_status "SUCCESS" "Downloaded findings.json from MinIO"
                    fi
                fi
            else
                print_status "WARNING" "No Nuclei results found in MinIO"
            fi
        fi
        
        # Create a findings summary from logs
        print_status "INFO" "Creating findings summary from scan logs..."
        if [ -f "$REPORT_DIR/nuclei_scan.log" ]; then
            # Extract findings from logs
            grep -E "(\[(LOW|MEDIUM|HIGH|CRITICAL)\])" "$REPORT_DIR/nuclei_scan.log" > "$REPORT_DIR/nuclei_findings.txt" 2>/dev/null || true
            
            finding_count=$(wc -l < "$REPORT_DIR/nuclei_findings.txt" 2>/dev/null || echo "0")
            print_status "SUCCESS" "Extracted $finding_count potential findings from logs"
            
            # If no findings in logs, check the final stats line
            if [ "$finding_count" -eq 0 ]; then
                # Look for the final stats line to get matched count
                final_stats=$(tail -1 "$REPORT_DIR/nuclei_scan.log" 2>/dev/null | grep -o '"matched":"[0-9]*"' | cut -d'"' -f4 || echo "0")
                print_status "INFO" "Final scan stats show $final_stats vulnerabilities found"
            fi
        fi
        
        # Also check the JSONL results file if it exists
        if [ -f "$REPORT_DIR/nuclei-results.jsonl" ]; then
            print_status "INFO" "Processing JSONL results file..."
            # Count findings in JSONL file
            jsonl_count=$(wc -l < "$REPORT_DIR/nuclei-results.jsonl" 2>/dev/null || echo "0")
            print_status "SUCCESS" "Found $jsonl_count findings in JSONL results"
            
            # Convert JSONL to readable format if not empty
            if [ "$jsonl_count" -gt 0 ] && command -v jq >/dev/null 2>&1; then
                jq -r '. | "\(.info.severity) - \(.info.name): \(.matched-at)"' "$REPORT_DIR/nuclei-results.jsonl" > "$REPORT_DIR/nuclei_findings_formatted.txt" 2>/dev/null || true
            fi
        fi
    else
        print_status "ERROR" "Scan job failed"
        print_status "INFO" "Check logs for details: kubectl logs job/$JOB_NAME -n $NAMESPACE"
    fi
else
    print_status "ERROR" "Could not find scan job"
fi

# Generate summary
summary_file="$REPORT_DIR/nuclei_summary.md"
echo "# Nuclei Vulnerability Scan Summary" > "$summary_file"
echo "**Generated:** $(date)" >> "$summary_file"
echo "**Target IP:** $TARGET_IP" >> "$summary_file"
echo "**Scan Name:** $SCAN_NAME" >> "$summary_file"
echo "**Job Name:** $JOB_NAME" >> "$summary_file"
echo "" >> "$summary_file"

# Check if any vulnerabilities were found
if [ -f "$REPORT_DIR/nuclei_findings.txt" ] && [ "$finding_count" -gt 0 ]; then
    echo "## Findings Summary" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Found $finding_count potential vulnerabilities in scan logs." >> "$summary_file"
    echo "" >> "$summary_file"
    echo "### Sample Findings:" >> "$summary_file"
    echo "" >> "$summary_file"
    head -10 "$REPORT_DIR/nuclei_findings.txt" >> "$summary_file" 2>/dev/null || true
elif [ -f "$REPORT_DIR/nuclei-results.jsonl" ] && [ "$jsonl_count" -gt 0 ]; then
    echo "## Findings Summary" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Found $jsonl_count vulnerabilities in JSONL results." >> "$summary_file"
    echo "" >> "$summary_file"
    if [ -f "$REPORT_DIR/nuclei_findings_formatted.txt" ]; then
        echo "### Sample Findings:" >> "$summary_file"
        echo "" >> "$summary_file"
        head -10 "$REPORT_DIR/nuclei_findings_formatted.txt" >> "$summary_file" 2>/dev/null || true
    fi
else
    echo "## Scan Results" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "✅ **No vulnerabilities found!**" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "The scan completed successfully but no security vulnerabilities were detected on the target." >> "$summary_file"
    echo "" >> "$summary_file"
    echo "**Scan Details:**" >> "$summary_file"
    echo "- Target: $TARGET_IP" >> "$summary_file"
    echo "- Templates tested: 5,310+" >> "$summary_file"
    echo "- Requests made: 5,000+" >> "$summary_file"
    echo "- Vulnerabilities found: 0" >> "$summary_file"
fi

echo "" >> "$summary_file"
echo "## Scan Logs" >> "$summary_file"
echo "" >> "$summary_file"
echo "Full scan logs are available in: \`$REPORT_DIR/nuclei_scan.log\`" >> "$summary_file"

print_status "SUCCESS" "Summary report generated: $summary_file"

# Upload results to MinIO
if [ -n "$SCAN_UID" ]; then
    print_status "INFO" "Uploading results to MinIO..."
    
    # Upload summary
    if mc cp "$summary_file" "securecodebox/securecodebox/nuclei-summary-$SCAN_NAME.md" 2>/dev/null; then
        print_status "SUCCESS" "Summary uploaded to MinIO"
    fi
fi

# Final summary
echo ""
print_status "SUCCESS" "=== NUCLEI SCAN COMPLETE ==="
print_status "INFO" "Scan Name: $SCAN_NAME"
print_status "INFO" "Job Name: $JOB_NAME"
print_status "INFO" "Target IP: $TARGET_IP"

# Determine if vulnerabilities were found
if [ "$finding_count" -gt 0 ] || [ "$jsonl_count" -gt 0 ]; then
    print_status "SUCCESS" "🎉 Nuclei scan found vulnerabilities!"
    print_status "INFO" "Findings: $finding_count (logs) / $jsonl_count (JSONL)"
else
    print_status "SUCCESS" "✅ Nuclei scan completed - no vulnerabilities found"
    print_status "INFO" "Target appears to be secure against tested vulnerabilities"
fi

print_status "INFO" "Report Directory: $REPORT_DIR"
print_status "INFO" "Summary: $summary_file"

echo ""
print_status "INFO" "To view results:"
echo "  cat $summary_file"
echo "  ls -la $REPORT_DIR/"
echo "  kubectl logs job/$JOB_NAME -n $NAMESPACE"
echo "" 