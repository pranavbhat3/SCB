#!/bin/bash

set -e

TARGET=${1:-"scanme.nmap.org"}
SCAN_NAME="naabu-scan-$(date +%s)"
NAMESPACE="securecodebox-system"

echo "=== NAABU SCANNER - FINAL VERSION ==="
echo "Target: $TARGET"
echo "Scan Name: $SCAN_NAME"

# Create scan YAML
cat > /tmp/naabu-scan.yaml << EOF
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: $SCAN_NAME
  namespace: $NAMESPACE
spec:
  scanType: naabu
  parameters:
    - "-host"
    - "$TARGET"
    - "-json"
    - "-o"
    - "/home/securecodebox/raw-results.json"
EOF

echo "Applying scan..."
kubectl apply -f /tmp/naabu-scan.yaml

echo "Waiting for scan to complete..."
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

echo ""
echo "=== PARSER OUTPUT ==="
PARSER_POD=$(kubectl get pods -n $NAMESPACE | grep "parse-$SCAN_NAME" | awk '{print $1}')
if [ -n "$PARSER_POD" ]; then
    echo "Parser pod: $PARSER_POD"
    echo "Parser logs:"
    kubectl logs $PARSER_POD -n $NAMESPACE
else
    echo "❌ Parser pod not found!"
fi

echo ""
echo "=== FINDINGS LOCATION ==="
FINDINGS_URL=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.findingDownloadLink}')
echo "📁 Findings are automatically uploaded to MinIO!"
echo "🔗 Download URL: $FINDINGS_URL"
echo ""
echo "To access MinIO locally, run:"
echo "kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000"
echo ""
echo "Then visit: http://localhost:9000/securecodebox/"
echo ""
echo "=== SCAN COMPLETED ==="
echo "Scan: $SCAN_NAME"
echo "Target: $TARGET"
echo "Findings: Available in MinIO (see URL above)"

# Cleanup
rm -f /tmp/naabu-scan.yaml 