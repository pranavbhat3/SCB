#!/bin/bash

set -e

TARGET=${1:-"scanme.nmap.org"}
SCAN_NAME="naabu-scan-$(date +%s)"
NAMESPACE="securecodebox-system"

echo "=== NAABU SCANNER AUTOMATION ==="
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

echo "Waiting for parser to complete..."
sleep 30

echo "Extracting findings from PVC..."
# Create a helper pod to extract findings from PVC
cat > /tmp/helper-pod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: naabu-helper-$(date +%s)
  namespace: $NAMESPACE
spec:
  containers:
  - name: helper
    image: busybox
    command: ['sh', '-c', 'cat /home/securecodebox/findings.json']
    volumeMounts:
    - name: naabu-parser-pvc
      mountPath: /home/securecodebox
  volumes:
  - name: naabu-parser-pvc
    persistentVolumeClaim:
      claimName: naabu-parser-pvc
  restartPolicy: Never
EOF

kubectl apply -f /tmp/helper-pod.yaml
HELPER_POD=$(kubectl get pods -n $NAMESPACE | grep naabu-helper | awk '{print $1}')

echo "Waiting for helper pod to be ready..."
kubectl wait --for=condition=Ready pod/$HELPER_POD -n $NAMESPACE --timeout=60s

echo "Extracting findings..."
kubectl logs $HELPER_POD -n $NAMESPACE > /tmp/naabu-findings.json

# Clean up helper pod
kubectl delete pod $HELPER_POD -n $NAMESPACE

echo "Setting up MinIO port-forward..."
kubectl port-forward -n $NAMESPACE svc/securecodebox-operator-minio 9000:9000 &
PORT_FORWARD_PID=$!
sleep 3

echo "Uploading findings to MinIO..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="naabu-findings-${TARGET//[^a-zA-Z0-9]/_}-${TIMESTAMP}.json"

if curl -s -X PUT -T /tmp/naabu-findings.json "http://localhost:9000/securecodebox/$FILENAME"; then
    echo "✅ Findings uploaded to MinIO: $FILENAME"
    echo "📁 MinIO URL: http://localhost:9000/securecodebox/$FILENAME"
else
    echo "❌ Failed to upload to MinIO"
    echo "📁 Findings saved locally: /tmp/naabu-findings.json"
fi

# Kill port-forward
kill $PORT_FORWARD_PID 2>/dev/null || true

echo "=== COMPLETED ==="
echo "Scan: $SCAN_NAME"
echo "Findings: $FILENAME"
echo "Local file: /tmp/naabu-findings.json"

# Cleanup
rm -f /tmp/naabu-scan.yaml /tmp/helper-pod.yaml 