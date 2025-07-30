#!/bin/bash
set -e

# Usage: ./extract_findings_from_pvc.sh <scan-uid>
if [ -z "$1" ]; then
  echo "Usage: $0 <scan-uid>"
  exit 1
fi
SCAN_UID="$1"
HELPER_POD="extract-findings-$SCAN_UID"
NAMESPACE="securecodebox-system"
PVC="tlsx-parser-pvc"

# Launch helper pod
kubectl run $HELPER_POD --rm -i --tty --restart=Never -n $NAMESPACE \
  --image=busybox --overrides='{
    "spec": {
      "volumes": [{
        "name": "tlsx-parser-pvc",
        "persistentVolumeClaim": {"claimName": "tlsx-parser-pvc"}
      }],
      "containers": [{
        "name": "busybox",
        "image": "busybox",
        "command": ["sleep", "3600"],
        "volumeMounts": [{"name": "tlsx-parser-pvc", "mountPath": "/mnt"}]
      }]
    }
  }' &

# Wait for pod to be running
for i in {1..12}; do
  STATUS=$(kubectl get pod $HELPER_POD -n $NAMESPACE -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  if [[ "$STATUS" == "Running" ]]; then
    break
  fi
  sleep 5
done

if [[ "$STATUS" != "Running" ]]; then
  echo "❌ Helper pod did not start."
  exit 1
fi

# Copy findings.json from PVC
kubectl cp -n $NAMESPACE $HELPER_POD:/mnt/findings.json findings-from-pvc.json || echo "❌ findings.json not found in PVC."

# Clean up helper pod
kubectl delete pod $HELPER_POD -n $NAMESPACE --force --grace-period=0 || true

# Show findings for proof
if [ -f findings-from-pvc.json ]; then
  echo "--- findings.json content (from PVC) ---"
  cat findings-from-pvc.json
else
  echo "❌ findings.json not found in PVC."
fi 