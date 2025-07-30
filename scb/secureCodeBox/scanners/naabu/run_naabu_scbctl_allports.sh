#!/bin/bash

set -e

TARGET=${1:-"scanme.nmap.org"}
SCAN_NAME="naabu-scan-$(date +%s)"
NAMESPACE="securecodebox-system"

# Always scan all ports
ALL_PORTS="1"
echo "[INFO] Scanning ALL ports (1-65535) on $TARGET"

echo "=== NAABU SCANNER WITH SCBCTL (ALL PORTS CAPABLE) ==="
echo "Target: $TARGET"
echo "Scan Name: $SCAN_NAME"

echo "Creating scan with scbctl (all ports)..."
scbctl scan naabu --name $SCAN_NAME --namespace $NAMESPACE -- -host $TARGET -p - -json -o /home/securecodebox/raw-results.json

# Wait for scan to complete
while true; do
    STATE=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
    echo "Current state: $STATE"
    if [ "$STATE" = "Done" ]; then
        echo "✅ Scan completed successfully!"
        break
    elif [ "$STATE" = "Errored" ]; then
        echo "❌ Scan failed!"
        kubectl describe scan $SCAN_NAME -n $NAMESPACE
        exit 1
    fi
    sleep 10
done

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
    echo "❌ Parser pod not found!"
    exit 1
fi

echo ""
echo "=== UPLOADING TO MINIO WITH MC ==="
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="naabu-findings-${TARGET//[^a-zA-Z0-9]/_}-${TIMESTAMP}.json"

# Setup MinIO client
mc alias set securecodebox http://localhost:9000 admin password 2>/dev/null || true

echo "Uploading findings to MinIO..."
if mc cp /tmp/naabu-findings.json securecodebox/securecodebox/$FILENAME; then
    echo "✅ Findings uploaded to MinIO: $FILENAME"
    echo "📁 MinIO path: securecodebox/securecodebox/$FILENAME"
    echo ""
    echo "Listing naabu files in MinIO:"
    mc ls securecodebox/securecodebox/ | grep naabu
else
    echo "❌ Failed to upload to MinIO"
    echo "📁 Findings saved locally: /tmp/naabu-findings.json"
fi

echo ""
echo "=== COMPLETED ==="
echo "Scan: $SCAN_NAME"
echo "Target: $TARGET"
echo "Findings: $FILENAME"
echo "Local file: /tmp/naabu-findings.json"
echo ""
echo "🎉 NAABU SCANNER WITH SCBCTL (ALL PORTS CAPABLE) - SUCCESS!" 