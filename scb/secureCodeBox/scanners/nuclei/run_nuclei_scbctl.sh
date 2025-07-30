#!/bin/bash

# Usage:
#   ./run_nuclei_scbctl.sh <target> [namespace] [nuclei_args...]
#
# Examples:
#   # Default (all templates):
#   ./run_nuclei_scbctl.sh https://example.com
#
#   # Custom namespace:
#   ./run_nuclei_scbctl.sh https://example.com my-namespace
#
#   # Custom template:
#   ./run_nuclei_scbctl.sh https://example.com default -t cves/2021/CVE-2021-12345.yaml
#
#   # Custom severity:
#   ./run_nuclei_scbctl.sh https://example.com default -severity high,critical

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

# Prerequisite checks
print_status "INFO" "Checking prerequisites..."
if ! command -v scbctl >/dev/null 2>&1; then
    print_status "ERROR" "scbctl is not available"
    print_status "INFO" "Please install scbctl first"
    exit 1
fi
if ! kubectl get scantypes | grep -q nuclei; then
    print_status "ERROR" "nuclei scanner is not available"
    print_status "INFO" "Please ensure nuclei scanner is installed in SecureCodeBox"
    exit 1
fi
if ! kubectl get pods -n securecodebox-system | grep -q nuclei; then
    print_status "ERROR" "Nuclei scanner pod is not running in namespace securecodebox-system."
    print_status "INFO" "Please install the Nuclei scanner with:"
    echo "  helm upgrade --install nuclei oci://ghcr.io/securecodebox/helm/nuclei -n securecodebox-system"
    exit 1
fi
if ! kubectl get pods -n securecodebox-system | grep -q operator; then
    print_status "ERROR" "SecureCodeBox operator pod is not running in namespace securecodebox-system."
    print_status "INFO" "Please ensure the operator is installed and running."
    exit 1
fi
print_status "SUCCESS" "All prerequisites met"

# Main scan logic
TARGET=${1:-"scanme.nmap.org"}
NAMESPACE=${2:-default}
SCAN_NAME="nuclei-scan-$(date +%s)"
shift 2 || true
NUCLEI_ARGS=("$@")

print_status "RUNNING" "Creating nuclei scan..."
if [ ${#NUCLEI_ARGS[@]} -eq 0 ]; then
    # Default: all templates
    scbctl scan nuclei --name "$SCAN_NAME" --namespace "$NAMESPACE" -- -u "$TARGET"
else
    # Custom: pass extra args
    scbctl scan nuclei --name "$SCAN_NAME" --namespace "$NAMESPACE" -- -u "$TARGET" "${NUCLEI_ARGS[@]}"
fi
if [ $? -eq 0 ]; then
    print_status "SUCCESS" "Nuclei scan created: $SCAN_NAME in namespace $NAMESPACE"
else
    print_status "ERROR" "Failed to create nuclei scan"
    exit 1
fi

print_status "INFO" "Waiting for nuclei scan to complete..."
max_wait=900  # 15 minutes
wait_time=0
SCAN_STATE=""
while [ $wait_time -lt $max_wait ]; do
    SCAN_STATE=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "")
    if [[ "$SCAN_STATE" == "Done" ]]; then
        print_status "SUCCESS" "Nuclei scan completed successfully"
        break
    elif [[ "$SCAN_STATE" == "Errored" ]]; then
        print_status "ERROR" "Nuclei scan failed"
        print_status "INFO" "Check scan details: kubectl describe scan $SCAN_NAME -n $NAMESPACE"
        exit 1
    fi
    print_status "INFO" "Nuclei scan status: $SCAN_STATE (${wait_time}s)"
    sleep 10
    wait_time=$((wait_time + 10))
done
if [ $wait_time -ge $max_wait ]; then
    print_status "WARNING" "Nuclei scan timed out after 15 minutes"
    print_status "INFO" "Scan may still be running in background"
    exit 1
fi

SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
if [ -z "$SCAN_UID" ]; then
    print_status "ERROR" "Could not get scan UID."
    exit 1
fi

mc alias set myminio http://localhost:9000 admin password >/dev/null 2>&1 || true
MINIO_RESULTS_PATH="myminio/securecodebox/scan-$SCAN_UID/nuclei-results.jsonl"
if mc ls myminio/securecodebox/scan-$SCAN_UID/ 2>/dev/null | grep -q nuclei-results.jsonl; then
    print_status "SUCCESS" "Found nuclei results in MinIO!"
    finding_count=$(mc cat "$MINIO_RESULTS_PATH" | wc -l 2>/dev/null || echo "0")
    sample_findings=$(mc cat "$MINIO_RESULTS_PATH" | head -3 | jq -r '.info.name + " (" + .info.severity + ")"' 2>/dev/null || true)
else
    print_status "WARNING" "No nuclei results found in MinIO"
    finding_count=0
    sample_findings=""
fi

SUMMARY_MD=$(mktemp)
echo "# Nuclei Scan Summary" > "$SUMMARY_MD"
echo "**Generated:** $(date)" >> "$SUMMARY_MD"
echo "**Target:** $TARGET" >> "$SUMMARY_MD"
echo "**Scan Name:** $SCAN_NAME" >> "$SUMMARY_MD"
echo "**Scan UID:** $SCAN_UID" >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "## Findings Summary" >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "Found $finding_count findings in nuclei scan." >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "### Sample Findings:" >> "$SUMMARY_MD"
echo "" >> "$SUMMARY_MD"
echo "$sample_findings" >> "$SUMMARY_MD"
MINIO_SUMMARY_PATH="myminio/securecodebox/nuclei-summary-$SCAN_NAME.md"
mc cp "$SUMMARY_MD" "$MINIO_SUMMARY_PATH"
rm "$SUMMARY_MD"

echo ""
echo "Nuclei results uploaded to MinIO: myminio/securecodebox/scan-$SCAN_UID/nuclei-results.jsonl"
echo "Nuclei summary uploaded to MinIO: myminio/securecodebox/nuclei-summary-$SCAN_NAME.md"

if [ "$finding_count" -gt 0 ]; then
    print_status "SUCCESS" "🎉 Nuclei scan found $finding_count vulnerabilities!"
else
    print_status "SUCCESS" "✅ Nuclei scan completed - no vulnerabilities found"
fi 