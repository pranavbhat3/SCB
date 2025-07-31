#!/bin/bash

set -e
set -o pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[ERROR] $1 is not installed. Please install it before running this script.${NC}"
        exit 1
    else
        echo -e "${GREEN}[OK] $1 is installed.${NC}"
    fi
}

# Check required tools
echo -e "\n${GREEN}--- Checking required tools ---${NC}"
check_command minikube
check_command helm
check_command kubectl


echo -e "\n${GREEN}--- Starting Minikube cluster ---${NC}"
if ! minikube status | grep -q "Running"; then
    minikube start --driver=docker
else
    echo -e "${GREEN}[OK] Minikube already running.${NC}"
fi


echo -e "\n${GREEN}--- Installing SecureCodeBox Operator ---${NC}"
retry=3
count=0
until helm --namespace securecodebox-system upgrade --install --create-namespace securecodebox-operator oci://ghcr.io/securecodebox/helm/operator; do
    ((count++))
    echo -e "${RED}[ERROR] Helm install failed. Retrying ($count/$retry)...${NC}"
    if [ "$count" -eq "$retry" ]; then
        echo -e "${RED}[FAIL] Helm install failed after $retry attempts.${NC}"
        exit 1
    fi
    sleep 5
done

echo -e "\n${GREEN}✅ Setup complete.${NC}"
echo -e "${GREEN}SecureCodeBox Operator has been deployed to your cluster.${NC}"
