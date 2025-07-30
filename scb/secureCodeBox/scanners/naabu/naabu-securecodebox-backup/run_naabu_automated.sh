#!/bin/bash

set -e

# Configuration
TARGET=${1:-"scanme.nmap.org"}
SCAN_NAME="naabu-scan-$(date +%s)"
NAMESPACE="securecodebox-system"
TIMEOUT=300  # 5 minutes timeout
WAIT_INTERVAL=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    if [ -f "/tmp/naabu-scan.yaml" ]; then
        rm -f /tmp/naabu-scan.yaml
    fi
    if [ -f "/tmp/naabu-findings.json" ]; then
        rm -f /tmp/naabu-findings.json
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Kubernetes cluster is not accessible"
        exit 1
    fi
    
    # Check if SecureCodeBox is installed
    if ! kubectl get namespace $NAMESPACE &> /dev/null; then
        log_error "SecureCodeBox namespace not found. Please install SecureCodeBox first."
        exit 1
    fi
    
    # Check if naabu ScanType exists
    if ! kubectl get scantype naabu -n $NAMESPACE &> /dev/null; then
        log_error "Naabu ScanType not found. Please apply the ScanType first."
        exit 1
    fi
    
    # Check if naabu-json ParseDefinition exists
    if ! kubectl get parsedefinition naabu-json -n $NAMESPACE &> /dev/null; then
        log_error "Naabu ParseDefinition not found. Please apply the ParseDefinition first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Setup MinIO port-forward
setup_minio_access() {
    log_info "Setting up MinIO access..."
    
    # Kill any existing port-forward
    pkill -f "kubectl port-forward.*minio" || true
    
    # Start port-forward in background
    kubectl port-forward -n $NAMESPACE svc/securecodebox-operator-minio 9000:9000 &
    PORT_FORWARD_PID=$!
    
    # Wait for port-forward to be ready
    sleep 3
    
    # Test MinIO access
    if ! curl -s http://localhost:9000 &> /dev/null; then
        log_warning "MinIO port-forward might not be working. Continuing anyway..."
    else
        log_success "MinIO port-forward established"
    fi
}

# Create and apply scan
create_scan() {
    log_info "Creating scan for target: $TARGET"
    
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
    
    # Apply scan
    kubectl apply -f /tmp/naabu-scan.yaml
    log_success "Scan created: $SCAN_NAME"
}

# Monitor scan progress
monitor_scan() {
    log_info "Monitoring scan progress..."
    
    local start_time=$(date +%s)
    local elapsed=0
    
    while [ $elapsed -lt $TIMEOUT ]; do
        # Get scan status
        local state=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
        
        case $state in
            "Scanning")
                log_info "Scan in progress... (${elapsed}s elapsed)"
                ;;
            "Parsing")
                log_info "Scan completed, parser running... (${elapsed}s elapsed)"
                ;;
            "Done")
                log_success "Scan completed successfully! (${elapsed}s total)"
                return 0
                ;;
            "Errored")
                log_error "Scan failed with error"
                show_scan_errors
                return 1
                ;;
            *)
                log_info "Scan state: $state (${elapsed}s elapsed)"
                ;;
        esac
        
        sleep $WAIT_INTERVAL
        elapsed=$(($(date +%s) - start_time))
    done
    
    log_error "Scan timed out after ${TIMEOUT}s"
    return 1
}

# Show scan errors
show_scan_errors() {
    log_info "Scan error details:"
    kubectl describe scan $SCAN_NAME -n $NAMESPACE | grep -A 10 "Events:"
    
    # Show pod logs
    local scan_pods=$(kubectl get pods -n $NAMESPACE | grep $SCAN_NAME | awk '{print $1}')
    for pod in $scan_pods; do
        log_info "Logs for pod: $pod"
        kubectl logs $pod -n $NAMESPACE --tail=20 2>/dev/null || true
    done
}

# Extract findings
extract_findings() {
    log_info "Extracting findings..."
    
    # Get scan details
    local scan_uid=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.metadata.uid}')
    local findings_url=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.findingDownloadLink}')
    
    if [ -z "$findings_url" ]; then
        log_error "No findings download link found"
        return 1
    fi
    
    log_info "Downloading findings from: $findings_url"
    
    # Download findings
    if curl -s "$findings_url" -o /tmp/naabu-findings.json; then
        log_success "Findings downloaded successfully"
        
        # Show findings summary
        local findings_count=$(jq length /tmp/naabu-findings.json 2>/dev/null || echo "0")
        log_info "Found $findings_count findings"
        
        # Show findings details
        if [ "$findings_count" -gt 0 ]; then
            log_info "Findings summary:"
            jq -r '.[] | "  - \(.name) (\(.location))"' /tmp/naabu-findings.json 2>/dev/null || true
        fi
        
        return 0
    else
        log_error "Failed to download findings"
        return 1
    fi
}

# Upload findings to MinIO (if needed)
upload_to_minio() {
    log_info "Uploading findings to MinIO..."
    
    if [ ! -f "/tmp/naabu-findings.json" ]; then
        log_warning "No findings file to upload"
        return 1
    fi
    
    # Create a timestamped filename
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local filename="naabu-findings-${TARGET//[^a-zA-Z0-9]/_}-${timestamp}.json"
    
    # Upload using curl (if MinIO is accessible)
    if curl -s -X PUT -T /tmp/naabu-findings.json "http://localhost:9000/securecodebox/$filename" &> /dev/null; then
        log_success "Findings uploaded to MinIO: $filename"
        log_info "MinIO URL: http://localhost:9000/securecodebox/$filename"
    else
        log_warning "Failed to upload to MinIO via port-forward"
        log_info "Findings saved locally at: /tmp/naabu-findings.json"
    fi
}

# Show final results
show_results() {
    log_success "=== NAABU SCAN COMPLETED ==="
    log_info "Target: $TARGET"
    log_info "Scan Name: $SCAN_NAME"
    log_info "Namespace: $NAMESPACE"
    
    if [ -f "/tmp/naabu-findings.json" ]; then
        local findings_count=$(jq length /tmp/naabu-findings.json 2>/dev/null || echo "0")
        log_info "Total Findings: $findings_count"
        log_info "Findings File: /tmp/naabu-findings.json"
        
        # Show raw results URL
        local raw_results_url=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.rawResultDownloadLink}' 2>/dev/null || echo "N/A")
        log_info "Raw Results URL: $raw_results_url"
    fi
    
    # Show scan status
    local final_state=$(kubectl get scan $SCAN_NAME -n $NAMESPACE -o jsonpath='{.status.state}' 2>/dev/null || echo "Unknown")
    log_info "Final Scan State: $final_state"
}

# Main execution
main() {
    log_info "=== NAABU SECURECODEBOX AUTOMATION ==="
    log_info "Target: $TARGET"
    log_info "Scan Name: $SCAN_NAME"
    log_info "Timeout: ${TIMEOUT}s"
    
    # Check prerequisites
    check_prerequisites
    
    # Setup MinIO access
    setup_minio_access
    
    # Create scan
    create_scan
    
    # Monitor scan
    if monitor_scan; then
        # Extract findings
        if extract_findings; then
            # Upload to MinIO
            upload_to_minio
            
            # Show results
            show_results
            
            log_success "Automation completed successfully!"
        else
            log_error "Failed to extract findings"
            exit 1
        fi
    else
        log_error "Scan failed or timed out"
        exit 1
    fi
}

# Run main function
main "$@" 