# SecureCodeBox + tlsx + Parser Integration Report

---

## 1. Overview

This report documents the integration of the `tlsx` scanner with SecureCodeBox, including the creation and deployment of a custom parser, troubleshooting steps, and all commands needed to recreate the setup. This does **not** include any instructions for the parser to push directly to MinIO.

---

## 2. Key Files and Configurations

### A. ScanType (`scantype-tlsx.yaml`)
```
apiVersion: execution.securecodebox.io/v1
kind: ScanType
metadata:
  name: tlsx
  namespace: securecodebox-system
spec:
  extractResults:
    type: tlsx-parser
    location: /home/securecodebox/raw-results.json
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: tlsx
              image: projectdiscovery/tlsx:v1.1.9
              command: ["tlsx"]
              args:
                - "-host"
                - "scanme.sh"
                - "-json"
                - "-o"
                - "/home/securecodebox/raw-results.json"
```

### B. ParseDefinition (`parser/parsedefinition-tlsx.yaml`)
```
apiVersion: execution.securecodebox.io/v1
kind: ParseDefinition
metadata:
  name: tlsx-parser
  namespace: securecodebox-system
spec:
  image: pranavbhat3/tlsx-parser:latest
  ttlSecondsAfterFinished: 300
  resources:
    limits:
      cpu: "400m"
      memory: "200Mi"
    requests:
      cpu: "200m"
      memory: "100Mi"
```

### C. Parser (`parser/parser.js`)
- Downloads tlsx output from MinIO (in-memory, no temp files).
- Outputs a JSON array of findings to stdout (for SecureCodeBox).
- Writes `findings-local.json` locally when run outside the cluster (for demo/progress).

---

## 3. How to Recreate the Setup

### A. Build and Push the Parser Image
```bash
cd parser
docker build -t pranavbhat3/tlsx-parser:latest .
docker push pranavbhat3/tlsx-parser:latest
```

### B. Apply the ScanType and ParseDefinition
```bash
kubectl apply -f scantype-tlsx.yaml
kubectl apply -f parser/parsedefinition-tlsx.yaml
```

### C. Run a Test Scan
```bash
kubectl apply -f test-scan.yaml
```

### D. Check Scan Status and Parser Logs
```bash
kubectl get scan tlsx-test-scan -n securecodebox-system
kubectl get pods -n securecodebox-system | grep parse
kubectl logs <parse-pod-name> -n securecodebox-system
```

### E. View Results in MinIO
- Open the MinIO web UI (port-forward if needed):
  ```bash
  kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000
  ```
- Go to [http://localhost:9000](http://localhost:9000), log in, and browse to the latest scan folder.

---

## 4. Manual Upload of findings-local.json to MinIO (for demo/progress)

If SecureCodeBox does not upload `findings.json` automatically, you can do it manually:

### A. Run the parser locally to get findings-local.json
```bash
node parser/parser.js tlsx-output.json
# or
cat tlsx-output.json | docker run -i --rm -v $PWD:/parser --user $(id -u):$(id -g) pranavbhat3/tlsx-parser:latest
```

### B. Upload to MinIO using mc
```bash
mc alias set myminio http://localhost:9000 minioadmin minioadmin
mc cp findings-local.json myminio/securecodebox/scan-<scan-id>/findings.json
```
Replace `<scan-id>` with the actual scan folder name.

---

## 5. Automated Demo Workflow: `run_tlsx_scan.sh`

To streamline demos and progress reporting, a script `run_tlsx_scan.sh` is provided. This script:
- Accepts a scan target (host/domain) as an argument
- Generates a scan YAML for that target
- Runs the scan and waits for completion
- Downloads the raw results from MinIO
- Runs the parser locally to produce `findings-local.json`
- Uploads `findings-local.json` to MinIO as `findings.json` using the `mc` tool
- Prints all key steps and outputs

**Purpose:**
- This script is for manual/demo workflows where you want to guarantee that `findings.json` appears in MinIO, even if SecureCodeBox's automatic upload fails or is delayed.
- It is not the default SecureCodeBox behavior, but is useful for demos, progress tracking, and troubleshooting.

**Usage:**
```bash
chmod +x run_tlsx_scan.sh
./run_tlsx_scan.sh scanme.sh
```
- Replace `scanme.sh` with any target you want to scan.
- The script will print the MinIO scan folder where you can find both `raw-results.json` and `findings.json`.

---

## 6. Troubleshooting & Key Learnings

- **Parser pods run with a read-only filesystem** in SecureCodeBox. Only stdout is guaranteed writable.
- **findings-local.json** is only created when running the parser locally (not in-cluster).
- **MinIO internal URLs** (like `securecodebox-operator-minio.securecodebox-system.svc.cluster.local`) are only accessible from inside the cluster.
- **If findings.json is missing in MinIO:**
  - Check scan status (`kubectl get scan ... -o yaml`)
  - Check parser logs
  - Manually upload findings-local.json for demo/progress

---

## 7. Summary of Commands

```bash
# Build and push parser image
cd parser
docker build -t pranavbhat3/tlsx-parser:latest .
docker push pranavbhat3/tlsx-parser:latest

# Apply configs
kubectl apply -f scantype-tlsx.yaml
kubectl apply -f parser/parsedefinition-tlsx.yaml
kubectl apply -f test-scan.yaml

# Check scan and parser logs
kubectl get scan tlsx-test-scan -n securecodebox-system
kubectl get pods -n securecodebox-system | grep parse
kubectl logs <parse-pod-name> -n securecodebox-system

# Run parser locally
node parser/parser.js tlsx-output.json

# Upload findings to MinIO (if needed)
mc alias set myminio http://localhost:9000 minioadmin minioadmin
mc cp findings-local.json myminio/securecodebox/scan-<scan-id>/findings.json
```

---

**This report covers all steps, troubleshooting, and commands for your SecureCodeBox + tlsx + parser integration, including the manual/demo findings upload workflow.** 