#!/bin/bash
# Usage: ./run_zap_automation.sh <target-url>
# Example: ./run_zap_automation.sh http://example.com

if [ -z "$1" ]; then
  echo "Usage: $0 <target-url>"
  exit 1
fi

target="$1"

# Update the target in the ConfigMap
tmpfile=$(mktemp)
sed "s|urls: \[.*\]|urls: [\"$target/\"]|" zap-automation-framework-config.yaml > "$tmpfile"
kubectl apply -f "$tmpfile"
rm "$tmpfile"

# Delete and re-apply the scan to trigger a new run
kubectl delete scan zap-automation-framework-example -n default --ignore-not-found
kubectl apply -f zap-automation-framework-scan.yaml

# Wait for the scan pod to complete
while true; do
  pod=$(kubectl get pods -n default -l job-name=scan-zap-automation-framework-example --field-selector=status.phase!=Succeeded --no-headers | awk '{print $1}')
  if [ -z "$pod" ]; then
    echo "ZAP Automation scan completed."
    break
  else
    echo "Waiting for ZAP scan pod ($pod) to complete..."
    sleep 10
  fi
done 