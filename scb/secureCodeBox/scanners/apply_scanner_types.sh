#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SecureCodeBox Scanner Types Installation Script ===${NC}"
echo "This script will apply all scantype definitions and parser definitions"
echo "for Naabu, TLSX, ZAP, and Nuclei scanners."
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl is not installed or not in PATH${NC}"
    exit 1
fi

# Check if we can connect to the cluster
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}Error: Cannot connect to Kubernetes cluster${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Kubernetes cluster connection verified${NC}"

# Function to apply a YAML file and check status
apply_yaml() {
    local file_path="$1"
    local description="$2"
    
    echo -e "${YELLOW}Applying $description...${NC}"
    
    if kubectl apply -f "$file_path" --dry-run=client &> /dev/null; then
        if kubectl apply -f "$file_path"; then
            echo -e "${GREEN}✓ Successfully applied $description${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to apply $description${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Invalid YAML in $description${NC}"
        return 1
    fi
}

# Function to create PVC if it doesn't exist
create_pvc() {
    local pvc_name="$1"
    local description="$2"
    
    echo -e "${YELLOW}Checking for PVC: $pvc_name...${NC}"
    
    if ! kubectl get pvc "$pvc_name" -n securecodebox-system &> /dev/null; then
        echo -e "${YELLOW}Creating PVC: $pvc_name...${NC}"
        cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $pvc_name
  namespace: securecodebox-system
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
EOF
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Successfully created PVC: $pvc_name${NC}"
        else
            echo -e "${RED}✗ Failed to create PVC: $pvc_name${NC}"
        fi
    else
        echo -e "${GREEN}✓ PVC $pvc_name already exists${NC}"
    fi
}

# Create namespace if it doesn't exist
echo -e "${YELLOW}Ensuring securecodebox-system namespace exists...${NC}"
kubectl create namespace securecodebox-system --dry-run=client -o yaml | kubectl apply -f -

# Create PVCs for parsers
create_pvc "naabu-parser-pvc" "Naabu Parser PVC"
create_pvc "tlsx-parser-pvc" "TLSX Parser PVC"

echo ""
echo -e "${BLUE}=== Applying Scanner Types ===${NC}"

# 1. Apply Naabu ScanType
cat <<EOF | kubectl apply -f -
apiVersion: execution.securecodebox.io/v1
kind: ScanType
metadata:
  name: naabu
  namespace: securecodebox-system
spec:
  extractResults:
    type: naabu-json
    location: "/home/securecodebox/raw-results.json"
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: naabu
              image: projectdiscovery/naabu:v2.3.3
              command:
                - "naabu"
              args:
                - "-host"
                - "scanme.nmap.org"
                - "-json"
                - "-o"
                - "/home/securecodebox/raw-results.json"
EOF

# 2. Apply TLSX ScanType
cat <<EOF | kubectl apply -f -
apiVersion: "execution.securecodebox.io/v1"
kind: ScanType
metadata:
  name: "tlsx"
  namespace: securecodebox-system
spec:
  extractResults:
    type: "tlsx-parser"
    location: "/home/securecodebox/raw-results.json"
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: tlsx
              image: "projectdiscovery/tlsx:v1.1.9"
              command:
                - "tlsx"
              args:
                - "-host"
                - "scanme.sh"
                - "-json"
                - "-o"
                - "/home/securecodebox/raw-results.json"
EOF

# 3. Apply ZAP ScanType (using zap-automation-framework)
cat <<EOF | kubectl apply -f -
apiVersion: "execution.securecodebox.io/v1"
kind: ScanType
metadata:
  name: "zap-automation-framework"
  namespace: securecodebox-system
spec:
  extractResults:
    type: zap-xml
    location: "/home/securecodebox/zap-results.xml"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: zap-automation-framework
              image: "securecodebox/zap-automation-framework:4.16.0"
              command:
                - "bash"
                - "/zap/zap-entrypoint.bash"
EOF

# 4. Apply Nuclei ScanType
cat <<EOF | kubectl apply -f -
apiVersion: "execution.securecodebox.io/v1"
kind: ScanType
metadata:
  name: "nuclei"
  namespace: securecodebox-system
spec:
  extractResults:
    type: nuclei-json
    location: "/home/securecodebox/nuclei-results.jsonl"
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: nuclei
              image: "projectdiscovery/nuclei:v3.4.2"
              command:
                - "nuclei"
                - "-disable-update-check"
                - "-jsonl"
                - "-output"
                - "/home/securecodebox/nuclei-results.jsonl"
EOF

echo ""
echo -e "${BLUE}=== Applying Parser Definitions ===${NC}"

# 1. Apply Naabu Parser Definition
cat <<EOF | kubectl apply -f -
apiVersion: execution.securecodebox.io/v1
kind: ParseDefinition
metadata:
  name: naabu-json
  namespace: securecodebox-system
spec:
  image: pranavbhat3/naabu-parser:latest
  contentType: Text
  ttlSecondsAfterFinished: 3600
  resources:
    limits:
      cpu: "400m"
      memory: "200Mi"
    requests:
      cpu: "200m"
      memory: "100Mi"
  volumeMounts:
    - name: naabu-parser-pvc
      mountPath: /home/securecodebox
  volumes:
    - name: naabu-parser-pvc
      persistentVolumeClaim:
        claimName: naabu-parser-pvc
EOF

# 2. Apply TLSX Parser Definition
cat <<EOF | kubectl apply -f -
apiVersion: execution.securecodebox.io/v1
kind: ParseDefinition
metadata:
  name: tlsx-parser
  namespace: securecodebox-system
spec:
  image: pranavbhat3/tlsx-parser:latest
  ttlSecondsAfterFinished: 3600
  resources:
    limits:
      cpu: "400m"
      memory: "200Mi"
    requests:
      cpu: "200m"
      memory: "100Mi"
  env:
    - name: MINIO_ENDPOINT
      value: "http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000"
    - name: MINIO_ACCESS_KEY
      value: "admin"
    - name: MINIO_SECRET_KEY
      value: "password"
    - name: MINIO_BUCKET
      value: "securecodebox"
    - name: MINIO_SECURE
      value: "false"
  volumeMounts:
    - name: tlsx-parser-pvc
      mountPath: /home/securecodebox
  volumes:
    - name: tlsx-parser-pvc
      persistentVolumeClaim:
        claimName: tlsx-parser-pvc
EOF

# 3. Apply ZAP Parser Definition
cat <<EOF | kubectl apply -f -
apiVersion: "execution.securecodebox.io/v1"
kind: ParseDefinition
metadata:
  name: "zap-xml"
  namespace: securecodebox-system
spec:
  image: "securecodebox/parser-zap:4.16.0"
  ttlSecondsAfterFinished: 3600
  resources:
    limits:
      cpu: "400m"
      memory: "200Mi"
    requests:
      cpu: "200m"
      memory: "100Mi"
EOF

# 4. Apply Nuclei Parser Definition
cat <<EOF | kubectl apply -f -
apiVersion: "execution.securecodebox.io/v1"
kind: ParseDefinition
metadata:
  name: "nuclei-json"
  namespace: securecodebox-system
spec:
  image: "securecodebox/parser-nuclei:4.16.0"
  ttlSecondsAfterFinished: 3600
  resources:
    limits:
      cpu: "400m"
      memory: "200Mi"
    requests:
      cpu: "200m"
      memory: "100Mi"
EOF

echo ""
echo -e "${BLUE}=== Verification ===${NC}"

# Verify all ScanTypes are applied
echo -e "${YELLOW}Verifying ScanTypes...${NC}"
kubectl get scantypes -n securecodebox-system

echo ""
echo -e "${YELLOW}Verifying ParseDefinitions...${NC}"
kubectl get parsedefinitions -n securecodebox-system

echo ""
echo -e "${GREEN}=== Installation Complete! ===${NC}"
echo ""
echo -e "${BLUE}Available Scanner Types:${NC}"
echo "  • naabu - Port scanning with Naabu"
echo "  • tlsx - TLS/SSL scanning with TLSX"
echo "  • zap-automation-framework - Web application scanning with ZAP"
echo "  • nuclei - Vulnerability scanning with Nuclei"
echo ""
echo -e "${BLUE}Usage Examples:${NC}"
echo "  kubectl create scan naabu-scan --scan-type=naabu --parameters='-host 8.8.8.8'"
echo "  kubectl create scan tlsx-scan --scan-type=tlsx --parameters='-host scanme.sh'"
echo "  kubectl create scan zap-scan --scan-type=zap-automation-framework --parameters='-t https://example.com'"
echo "  kubectl create scan nuclei-scan --scan-type=nuclei --parameters='-u https://example.com'"
echo ""
echo -e "${GREEN}All scanner types are now ready to use!${NC}" 