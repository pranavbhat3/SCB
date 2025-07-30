#!/bin/bash

set -e

TARGET=${1:-"scanme.nmap.org"}
SCAN_NAME="naabu-test-$(date +%s)"

echo "=== Testing Naabu Scanner ==="
echo "Target: $TARGET"
echo "Scan Name: $SCAN_NAME"

# Create scan YAML
cat > /tmp/naabu-test.yaml << EOF
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: $SCAN_NAME
  namespace: securecodebox-system
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
kubectl apply -f /tmp/naabu-test.yaml

echo "Waiting for scan to start..."
sleep 5

echo "Checking scan status..."
kubectl get scan $SCAN_NAME -n securecodebox-system -o yaml | grep -A 5 "status:"

echo "Checking for scan pods..."
kubectl get pods -n securecodebox-system | grep $SCAN_NAME

echo "Waiting 30 seconds for scan to complete..."
sleep 30

echo "Final scan status:"
kubectl get scan $SCAN_NAME -n securecodebox-system -o yaml | grep -A 10 "status:"

echo "Scan pods:"
kubectl get pods -n securecodebox-system | grep $SCAN_NAME

echo "=== Test Complete ===" 