#!/bin/bash

# Custom Scanner Setup Script for SecureCodeBox
# This script applies ScanTypes, ParseDefinitions, and PVCs for TLSX and Naabu scanners
# 
# Usage: ./setup_custom_scanners.sh
# 
# Prerequisites:
# - kubectl configured and pointing to your cluster
# - secureCodeBox operator already installed
# - Running from the webapp-all directory

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}✅ $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
    esac
}

# Function to check if kubectl is available
check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        print_status ERROR "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        print_status ERROR "kubectl is not configured or cannot connect to cluster"
        exit 1
    fi
    
    print_status SUCCESS "kubectl is available and configured"
}

# Function to check if secureCodeBox operator is running
check_operator() {
    print_status INFO "Checking if secureCodeBox operator is running..."
    
    if ! kubectl get namespace securecodebox-system &> /dev/null; then
        print_status ERROR "securecodebox-system namespace not found. Please install secureCodeBox operator first."
        print_status INFO "Run: helm --namespace securecodebox-system upgrade --install --create-namespace securecodebox-operator oci://ghcr.io/securecodebox/helm/operator"
        exit 1
    fi
    
    if ! kubectl get pods -n securecodebox-system | grep -q "securecodebox-operator"; then
        print_status ERROR "secureCodeBox operator pod not found in securecodebox-system namespace"
        exit 1
    fi
    
    print_status SUCCESS "secureCodeBox operator is running"
}

# Function to apply TLSX resources
apply_tlsx_resources() {
    print_status INFO "Applying TLSX scanner resources..."
    
    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    TLSX_DIR="$SCRIPT_DIR/../tlsx"
    
    # Check if TLSX directory exists
    if [ ! -d "$TLSX_DIR" ]; then
        print_status ERROR "TLSX directory not found at $TLSX_DIR"
        exit 1
    fi
    
    # Apply PVC first
    print_status INFO "Applying TLSX PVC..."
    kubectl apply -f "$TLSX_DIR/parser/pvc-tlsx.yaml"
    
    # Apply ParseDefinition
    print_status INFO "Applying TLSX ParseDefinition..."
    kubectl apply -f "$TLSX_DIR/parser/parsedefinition-tlsx.yaml"
    
    # Apply ScanType
    print_status INFO "Applying TLSX ScanType..."
    kubectl apply -f "$TLSX_DIR/scantype-tlsx.yaml"
    
    print_status SUCCESS "TLSX resources applied successfully"
}

# Function to apply Naabu resources
apply_naabu_resources() {
    print_status INFO "Applying Naabu scanner resources..."
    
    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    NAABU_DIR="$SCRIPT_DIR/../naabu"
    
    # Check if Naabu directory exists
    if [ ! -d "$NAABU_DIR" ]; then
        print_status ERROR "Naabu directory not found at $NAABU_DIR"
        exit 1
    fi
    
    # Apply PVC first
    print_status INFO "Applying Naabu PVC..."
    kubectl apply -f "$NAABU_DIR/parser/pvc-naabu.yaml"
    
    # Apply ParseDefinition
    print_status INFO "Applying Naabu ParseDefinition..."
    kubectl apply -f "$NAABU_DIR/parser/parsedefinition-naabu.yaml"
    
    # Apply ScanType
    print_status INFO "Applying Naabu ScanType..."
    kubectl apply -f "$NAABU_DIR/scantype-naabu.yaml"
    
    print_status SUCCESS "Naabu resources applied successfully"
}

# Function to verify installation
verify_installation() {
    print_status INFO "Verifying installation..."
    
    # Check ScanTypes
    print_status INFO "Checking ScanTypes..."
    kubectl get scantypes -n securecodebox-system | grep -E "(tlsx|naabu)" || {
        print_status WARNING "Some ScanTypes not found. This might be normal if they're in a different namespace."
    }
    
    # Check ParseDefinitions
    print_status INFO "Checking ParseDefinitions..."
    kubectl get parsedefinitions -n securecodebox-system | grep -E "(tlsx-parser|naabu-json)" || {
        print_status WARNING "Some ParseDefinitions not found. This might be normal if they're in a different namespace."
    }
    
    # Check PVCs
    print_status INFO "Checking PVCs..."
    kubectl get pvc -n securecodebox-system | grep -E "(tlsx-parser-pvc|naabu-parser-pvc)" || {
        print_status WARNING "Some PVCs not found. This might be normal if they're in a different namespace."
    }
    
    print_status SUCCESS "Installation verification completed"
}

# Function to show usage information
show_usage_info() {
    print_status INFO "Setup completed! Here's how to use the scanners:"
    echo ""
    echo "📋 Available ScanTypes:"
    echo "  - tlsx: TLS/SSL scanner"
    echo "  - naabu: Port scanner"
    echo ""
    echo "🚀 To run scans:"
    echo "  # Using scbctl (recommended):"
    echo "  scbctl scan tlsx --name my-tlsx-scan -- -host example.com -json -o /home/securecodebox/raw-results.json"
    echo "  scbctl scan naabu --name my-naabu-scan -- -host example.com -json -o /home/securecodebox/raw-results.json"
    echo ""
    echo "  # Using kubectl:"
    echo "  kubectl apply -f scan.yaml"
    echo ""
    echo "📁 Scripts available:"
    echo "  - ../tlsx/run_tlsx_scan.sh <target>"
    echo "  - ../naabu/run_naabu_scan.sh <target>"
    echo ""
    echo "🔍 To check scan status:"
    echo "  kubectl get scans -n securecodebox-system"
    echo "  kubectl get scantypes -n securecodebox-system"
    echo ""
}

# Main execution
main() {
    echo "🔧 Custom Scanner Setup Script for SecureCodeBox"
    echo "================================================"
    echo ""
    
    # Check prerequisites
    check_kubectl
    check_operator
    
    # Apply resources
    apply_tlsx_resources
    apply_naabu_resources
    
    # Verify installation
    verify_installation
    
    # Show usage information
    show_usage_info
    
    print_status SUCCESS "Custom scanner setup completed successfully!"
}

# Run main function
main "$@" 