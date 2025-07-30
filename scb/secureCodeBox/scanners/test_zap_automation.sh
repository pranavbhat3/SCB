#!/bin/bash
set -e

# Minimal ZAP Automation Framework test for SecureCodeBox
TARGET="192.168.2.10"
NAMESPACE="securecodebox-system"
SCAN_NAME="zap-automation-test-$(date +%s)"
PLAN_FILE="/tmp/$SCAN_NAME-plan.yaml"

# Generate a minimal ZAP Automation Framework plan
cat > "$PLAN_FILE" <<EOF
env:
  contexts:
    - name: Default Context
      urls:
        - "https://$TARGET:443"
jobs:
  - type: passiveScan-config
  - type: spider
    parameters:
      context: Default Context
      maxDuration: 1
  - type: passiveScan-wait
  - type: report
    parameters:
      format: HTML
      reportDir: /home/securecodebox/
      reportFile: zap-results.html
  - type: report
    parameters:
      format: XML
      reportDir: /home/securecodebox/
      reportFile: zap-results.xml
EOF

echo "[INFO] Applying ZAP automation scan with plan: $PLAN_FILE"
scbctl scan zap-automation-framework --name "$SCAN_NAME" --namespace "$NAMESPACE" -- -p "$PLAN_FILE"

# Wait for scan to complete
while true; do
    STATE=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
    echo "Current state: $STATE"
    if [ "$STATE" = "Done" ]; then
        echo "✅ ZAP automation scan completed successfully!"
        break
    elif [ "$STATE" = "Errored" ]; then
        echo "❌ ZAP automation scan failed!"
        kubectl describe scan "$SCAN_NAME" -n "$NAMESPACE"
        ZAP_POD=$(kubectl get pods -n "$NAMESPACE" -l "securecodebox.io/scan=$SCAN_NAME" -o jsonpath='{.items[0].metadata.name}')
        if [ -n "$ZAP_POD" ]; then
            echo "--- ZAP scan pod logs ---"
            kubectl logs $ZAP_POD -n "$NAMESPACE" || echo "Could not fetch ZAP pod logs."
        else
            echo "ZAP scan pod not found for logs."
        fi
        exit 1
    fi
    sleep 10
done

# Fetch results from MinIO
SCAN_UID=$(kubectl get scan "$SCAN_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}')
MINIO_PATH_HTML="securecodebox/securecodebox/scan-$SCAN_UID/zap-results.html"
MINIO_PATH_XML="securecodebox/securecodebox/scan-$SCAN_UID/zap-results.xml"
mc alias set securecodebox http://localhost:9000 admin password >/dev/null 2>&1 || true
if mc ls securecodebox/securecodebox/scan-$SCAN_UID/ 2>/dev/null | grep -q zap-results.html; then
    echo "✅ Found zap-results.html in MinIO!"
    mc cat "$MINIO_PATH_HTML" | head -20
else
    echo "⚠️  No zap-results.html found in MinIO."
fi
if mc ls securecodebox/securecodebox/scan-$SCAN_UID/ 2>/dev/null | grep -q zap-results.xml; then
    echo "✅ Found zap-results.xml in MinIO!"
    mc cat "$MINIO_PATH_XML" | head -20
else
    echo "⚠️  No zap-results.xml found in MinIO."
fi 