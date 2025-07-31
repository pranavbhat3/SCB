#!/bin/bash

# Quick Nuclei Test Script
# Tests Nuclei scanner with the fixed MinIO paths

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Configuration
TARGET=${1:-"scanme.nmap.org"}

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

SCAN_NAME=$(safe_scan_name "$TARGET" "nuclei-test")
NAMESPACE="securecodebox-system"
RESULTS_DIR="nuclei_test_results_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

print_status "INFO" "=== NUCLEI QUICK TEST ==="
print_status "INFO" "Target: $TARGET"
print_status "INFO" "Scan Name: $SCAN_NAME"
print_status "INFO" "Results Dir: $RESULTS_DIR"

# Check prerequisites
print_status "INFO" "Checking prerequisites..."

if ! command -v kubectl &> /dev/null; then
    print_status "ERROR" "kubectl not found"
    exit 1
fi

if ! command -v scbctl &> /dev/null; then
    print_status "ERROR" "scbctl not found"
    exit 1
fi

if ! kubectl get scantypes -n securecodebox-system | grep -q nuclei; then
    print_status "ERROR" "Nuclei scantype not found"
    exit 1
fi

print_status "SUCCESS" "Prerequisites check passed"

# Setup MinIO access
print_status "INFO" "Setting up MinIO access..."
mc alias set securecodebox http://localhost:9000 admin password >/dev/null 2>&1 || true

# Create Nuclei scan with proper configuration for IP addresses
print_status "RUNNING" "Creating Nuclei scan..."
if scbctl scan nuclei --name "$SCAN_NAME" --namespace "$NAMESPACE" -- -u "https://$TARGET" -no-httpx -jsonl; then
    print_status "SUCCESS" "Nuclei scan created: $SCAN_NAME"
else
    print_status "ERROR" "Failed to create Nuclei scan"
    exit 1
fi

# Wait for scan completion
print_status "INFO" "Waiting for Nuclei scan to complete..."
max_wait=1800  # 30 minutes
wait_time=0

while [ $wait_time -lt $max_wait ]; do
    SCAN_STATE=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "")
    
    if [[ "$SCAN_STATE" == "Done" ]]; then
        print_status "SUCCESS" "Nuclei scan completed successfully"
        break
    elif [[ "$SCAN_STATE" == "Errored" ]]; then
        print_status "ERROR" "Nuclei scan failed"
        kubectl describe scan "$SCAN_NAME" -n "$NAMESPACE"
        exit 1
    fi
    
    if [ $((wait_time % 60)) -eq 0 ]; then
        print_status "INFO" "Nuclei scan status: $SCAN_STATE (${wait_time}s elapsed)"
    fi
    
    sleep 30
    wait_time=$((wait_time + 30))
done

if [ $wait_time -ge $max_wait ]; then
    print_status "WARNING" "Nuclei scan timed out after 30 minutes"
    print_status "INFO" "Checking if scan actually completed..."
fi

# Get scan UID
SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
if [ -z "$SCAN_UID" ]; then
    print_status "ERROR" "Could not get scan UID"
    exit 1
fi

print_status "INFO" "Scan UID: $SCAN_UID"

# Check MinIO for results
print_status "INFO" "Checking MinIO for results..."
MINIO_SCAN_PATH="securecodebox/securecodebox/scan-$SCAN_UID"

if mc ls "$MINIO_SCAN_PATH" 2>/dev/null; then
    print_status "SUCCESS" "Found scan folder in MinIO: $MINIO_SCAN_PATH"
    
    # List contents
    print_status "INFO" "Scan folder contents:"
    mc ls "$MINIO_SCAN_PATH" 2>/dev/null || true
    
    # Check for specific files
    if mc ls "$MINIO_SCAN_PATH" 2>/dev/null | grep -q "findings.json"; then
        print_status "SUCCESS" "Found findings.json in MinIO"
        
        # Download findings
        if mc cp "$MINIO_SCAN_PATH/findings.json" "$RESULTS_DIR/nuclei-findings.json"; then
            print_status "SUCCESS" "Downloaded findings to: $RESULTS_DIR/nuclei-findings.json"
            
            # Show sample findings
            print_status "INFO" "Sample findings:"
            head -5 "$RESULTS_DIR/nuclei-findings.json" 2>/dev/null || true
        fi
    else
        print_status "WARNING" "No findings.json found in MinIO"
    fi
    
    if mc ls "$MINIO_SCAN_PATH" 2>/dev/null | grep -q "raw-results"; then
        print_status "SUCCESS" "Found raw results in MinIO"
    fi
    
else
    print_status "WARNING" "No scan folder found in MinIO"
fi

# Check parser logs
print_status "INFO" "Checking parser logs..."
PARSER_POD=$(kubectl get pods -n "$NAMESPACE" | grep "parse-$SCAN_NAME" | awk '{print $1}' | head -1)

if [ -n "$PARSER_POD" ]; then
    print_status "SUCCESS" "Found parser pod: $PARSER_POD"
    
    # Extract findings from parser logs
    print_status "INFO" "Extracting findings from parser logs..."
    kubectl logs "$PARSER_POD" -n "$NAMESPACE" | tail -n +4 | head -n -1 > "$RESULTS_DIR/nuclei-parser-findings.json" 2>/dev/null || true
    
    if [ -s "$RESULTS_DIR/nuclei-parser-findings.json" ]; then
        print_status "SUCCESS" "Extracted findings from parser logs: $RESULTS_DIR/nuclei-parser-findings.json"
        print_status "INFO" "Parser findings preview:"
        head -3 "$RESULTS_DIR/nuclei-parser-findings.json" 2>/dev/null || true
    else
        print_status "WARNING" "No findings extracted from parser logs"
    fi
else
    print_status "WARNING" "Parser pod not found"
fi

# Summary
print_status "SUCCESS" "=== NUCLEI TEST COMPLETE ==="
print_status "INFO" "Scan Name: $SCAN_NAME"
print_status "INFO" "Scan UID: $SCAN_UID"
print_status "INFO" "Results Directory: $RESULTS_DIR"
print_status "INFO" "MinIO Path: $MINIO_SCAN_PATH"

# List all results
print_status "INFO" "All result files:"
ls -la "$RESULTS_DIR/" 2>/dev/null || true

print_status "SUCCESS" "🎉 Nuclei test completed!" 