#!/bin/bash

# Quick Nuclei test script
# Usage: ./test_nuclei_quick.sh <target_url>

set -e

TARGET="${1:-https://example.com}"
NAMESPACE="securecodebox-system"
SCAN_NAME="nuclei-quick-$(date +%s)"
TEMPLATE="basic-detections/http/basic-get.yaml"

print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO") echo -e "\033[0;34mℹ️  $message\033[0m" ;;
        "SUCCESS") echo -e "\033[0;32m✅ $message\033[0m" ;;
        "WARNING") echo -e "\033[1;33m⚠️  $message\033[0m" ;;
        "ERROR") echo -e "\033[0;31m❌ $message\033[0m" ;;
    esac
}

print_status INFO "Running quick Nuclei scan on $TARGET with template $TEMPLATE"
scbctl scan nuclei --name "$SCAN_NAME" --namespace "$NAMESPACE" -- \
  -u "$TARGET" \
  -t $TEMPLATE \
  -o /home/securecodebox/raw-results.json

while true; do
    STATE=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
    echo "Current state: $STATE"
    if [ "$STATE" = "Done" ]; then
        print_status SUCCESS "Scan completed successfully!"
        break
    elif [ "$STATE" = "Errored" ]; then
        print_status ERROR "Scan failed!"
        kubectl describe scan $SCAN_NAME -n $NAMESPACE
        POD=$(kubectl get pods -n $NAMESPACE | grep "scan-$SCAN_NAME" | awk '{print $1}')
        if [ -n "$POD" ]; then
            print_status ERROR "--- Nuclei scan pod logs ---"
            kubectl logs $POD -n $NAMESPACE || print_status WARNING "Could not fetch pod logs."
        fi
        exit 1
    fi
    sleep 5
done

# Extract findings if parser pod exists
PARSER_POD=$(kubectl get pods -n $NAMESPACE | grep "parse-$SCAN_NAME" | awk '{print $1}')
if [ -n "$PARSER_POD" ]; then
    print_status INFO "Extracting findings from parser pod logs..."
    kubectl logs $PARSER_POD -n $NAMESPACE | tail -n +4 | head -n -1 > nuclei-findings.json
    print_status SUCCESS "Findings extracted to nuclei-findings.json"
    print_status INFO "Content preview:"
    head -10 nuclei-findings.json
else
    print_status WARNING "Parser pod not found. No findings extracted."
fi 