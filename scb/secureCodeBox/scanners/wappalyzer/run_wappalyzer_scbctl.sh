#!/bin/bash

# Usage: ./run_wappalyzer_scbctl.sh <target> [namespace]
# Example: ./run_wappalyzer_scbctl.sh https://example.com

set -e

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

TARGET=${1:-"https://example.com"}
NAMESPACE=${2:-default}
SCAN_NAME="wappalyzer-scan-$(date +%s)"

print_status "RUNNING" "Creating Wappalyzer scan..."
scbctl scan wappalyzer --name "$SCAN_NAME" --namespace "$NAMESPACE" -- "$TARGET"
if [ $? -eq 0 ]; then
    print_status "SUCCESS" "Wappalyzer scan created: $SCAN_NAME in namespace $NAMESPACE"
else
    print_status "ERROR" "Failed to create Wappalyzer scan"
    exit 1
fi

print_status "INFO" "Waiting for Wappalyzer scan to complete..."
max_wait=600
wait_time=0
SCAN_STATE=""
while [ $wait_time -lt $max_wait ]; do
    SCAN_STATE=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "")
    if [[ "$SCAN_STATE" == "Done" ]]; then
        print_status "SUCCESS" "Wappalyzer scan completed successfully"
        break
    elif [[ "$SCAN_STATE" == "Errored" ]]; then
        print_status "ERROR" "Wappalyzer scan failed"
        print_status "INFO" "Check scan details: kubectl describe scan $SCAN_NAME -n $NAMESPACE"
        exit 1
    fi
    print_status "INFO" "Wappalyzer scan status: $SCAN_STATE (${wait_time}s)"
    sleep 10
    wait_time=$((wait_time + 10))
done
if [ $wait_time -ge $max_wait ]; then
    print_status "WARNING" "Wappalyzer scan timed out after 10 minutes"
    print_status "INFO" "Scan may still be running in background"
    exit 1
fi

SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
if [ -z "$SCAN_UID" ]; then
    print_status "ERROR" "Could not get scan UID."
    exit 1
fi

mc alias set myminio http://localhost:9000 admin password >/dev/null 2>&1 || true
MINIO_RESULTS_PATH="myminio/securecodebox/scan-$SCAN_UID/"
echo ""
echo "Wappalyzer scan results should be available in MinIO: $MINIO_RESULTS_PATH"
print_status "SUCCESS" "Done!" 