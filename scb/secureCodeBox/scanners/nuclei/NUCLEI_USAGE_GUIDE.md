# SecureCodeBox Nuclei Scan Usage Guide

This guide explains how to use the `run_nuclei_scbctl.sh` script to launch Nuclei scans via SecureCodeBox, covering all major options and use cases.

---

## Basic Usage

```bash
./run_nuclei_scbctl.sh <target> [namespace] [nuclei_args...]
```

- `<target>`: The domain or URL to scan (required)
- `[namespace]`: (Optional) Kubernetes namespace for the scan (default: `default`)
- `[nuclei_args...]`: (Optional) Any additional Nuclei CLI arguments (templates, tags, severity, etc.)

---

## Examples

### 1. **Default Scan (All Templates)**
Scans the target with the full set of default Nuclei templates.
```bash
./run_nuclei_scbctl.sh https://example.com
```

### 2. **Specify Namespace**
Run the scan in a custom namespace (e.g., `securecodebox-system`).
```bash
./run_nuclei_scbctl.sh https://example.com securecodebox-system
```

### 3. **Use a Specific Template**
Scan with a specific template file.
```bash
./run_nuclei_scbctl.sh https://example.com default -t cves/2021/CVE-2021-12345.yaml
```

### 4. **Use a Custom Template Directory**
Scan with all templates in a custom directory.
```bash
./run_nuclei_scbctl.sh https://example.com default -t /path/to/custom-templates/
```

### 5. **Filter by Severity**
Scan only for high and critical vulnerabilities.
```bash
./run_nuclei_scbctl.sh https://example.com default -severity high,critical
```

### 6. **Filter by Tags**
Scan only for templates tagged with `xss` or `sqli`.
```bash
./run_nuclei_scbctl.sh https://example.com default -tags xss,sqli
```

### 7. **Combine Multiple Options**
Use a custom template and filter by severity.
```bash
./run_nuclei_scbctl.sh https://example.com default -t /path/to/custom-templates/ -severity critical
```

### 8. **Pass Any Nuclei CLI Argument**
You can pass any valid Nuclei CLI argument after the target and namespace. For example, to enable verbose output:
```bash
./run_nuclei_scbctl.sh https://example.com default -v
```

---

## Output
- The script will print the MinIO URLs for both the raw results and a Markdown summary after the scan completes.
- No local files are stored; all results are in MinIO.

---

## Troubleshooting
- Ensure the SecureCodeBox Nuclei scanner and operator are running in your cluster.
- If you see errors, check pod and scan status with:
  ```bash
  kubectl get pods -n securecodebox-system
  kubectl get scans -A
  kubectl describe scan <scan-name> -n <namespace>
  ```

---

## More Information
- [Nuclei CLI Documentation](https://nuclei.projectdiscovery.io/cli/usage/)
- [SecureCodeBox Nuclei Docs](https://www.securecodebox.io/docs/scanners/nuclei) 