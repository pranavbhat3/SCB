import os, re, time, threading
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
import boto3
from kubernetes import client, config
import sys
import subprocess
import shlex
import yaml

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Configs (set these as env vars or hardcode for PoC)
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "admin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "password")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "securecodebox")
NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")

scan_in_progress = threading.Lock()
current_scan_name = None
current_scanner = None
current_target = None

SCANNERS = [
    ("nuclei", "Nuclei"),
    ("zap", "ZAP"),
    ("tlsx", "TLSX"),
    ("naabu", "Naabu"),
    ("tlsx-script", "TLSX (Script)"),
    ("mobsf", "MobSF"),
    ("semgrep", "Semgrep"),
    ("apkhunt", "APKHunt")
]

def safe_scan_name(scanner, target):
    name = f"{scanner}-{target}"
    name = name.lower()
    name = re.sub(r'[^a-z0-9.]', '-', name)
    name = name.strip('-')
    name = re.sub(r'-+', '-', name)
    # Always append a timestamp for uniqueness
    name = f"{name}-{int(time.time())}"
    return name

# At startup, print environment and config status
def print_startup_debug():
    print('--- WEBAPP-ALL STARTUP DEBUG ---')
    print(f'MINIO_ENDPOINT: {MINIO_ENDPOINT}')
    print(f'MINIO_ACCESS_KEY: {MINIO_ACCESS_KEY}')
    print(f'MINIO_SECRET_KEY: {MINIO_SECRET_KEY}')
    print(f'MINIO_BUCKET: {MINIO_BUCKET}')
    print(f'K8S_NAMESPACE: {NAMESPACE}')
    print('-------------------------------')

print_startup_debug()

# Helper to load kube config robustly
def load_kube():
    try:
        from kubernetes.config.config_exception import ConfigException
        try:
            config.load_incluster_config()
            print('Loaded in-cluster kube config')
        except ConfigException:
            config.load_kube_config()
            print('Loaded local kube config')
    except Exception as e:
        print(f'Kube config load failed: {e}')
        sys.exit(1)

@app.get("/reset")
def reset():
    if scan_in_progress.locked():
        scan_in_progress.release()
    global current_scan_name, current_scanner, current_target
    current_scan_name = None
    current_scanner = None
    current_target = None
    return {"status": "reset"}

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # Always set scan_in_progress to False unless a scan is running
    in_progress = scan_in_progress.locked() and current_scan_name is not None
    return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "scan_in_progress": in_progress})

@app.post("/scan")
def scan(request: Request, scanner: str = Form(...), target: str = Form(...)):
    print(f"Scan requested: scanner={scanner}, target={target}")
    if scan_in_progress.locked():
        print("Scan in progress, cannot start new scan.")
        return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "error": "Scan in progress.", "scan_in_progress": True})
    scan_in_progress.acquire()
    scan_name = safe_scan_name(scanner, target)
    print(f"Generated scan name: {scan_name}")
    global current_scan_name, current_scanner, current_target
    current_scan_name = scan_name
    current_scanner = scanner
    current_target = target
    if scanner == "tlsx-script":
        # Call the script as a subprocess (original logic)
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tlsx/run_tlsx_scan.sh'))
        print(f"Running script: {script_path} {target}")
        try:
            result = subprocess.run(["bash", script_path, target], capture_output=True, text=True, timeout=600)
            print(f"Script stdout:\n{result.stdout}")
            print(f"Script stderr:\n{result.stderr}")
            if result.returncode != 0:
                scan_in_progress.release()
                return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "error": f"Script failed: {result.stderr}", "scan_in_progress": False})
            # Assume findings-from-pvc.json is created in ../tlsx
            findings_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tlsx/findings-from-pvc.json'))
            if os.path.exists(findings_path):
                print(f"Findings file created: {findings_path}")
            else:
                print("Findings file not found after script run.")
            return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "scan_started": True, "scan_in_progress": False, "scan_name": scan_name, "script_mode": True})
        except Exception as e:
            scan_in_progress.release()
            print(f"Exception running script: {e}")
            return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "error": str(e), "scan_in_progress": False})
    if scanner == "tlsx":
        scan_yaml = {
            "apiVersion": "execution.securecodebox.io/v1",
            "kind": "Scan",
            "metadata": {"name": scan_name},
            "spec": {
                "scanType": scanner,
                "parameters": [
                    "-host",
                    target,
                    "-json",
                    "-o",
                    "/home/securecodebox/raw-results.json"
                ]
            }
        }
    elif scanner == "mobsf":
        # MobSF expects an APK file name as target
        scan_yaml = {
            "apiVersion": "execution.securecodebox.io/v1",
            "kind": "Scan",
            "metadata": {"name": scan_name},
            "spec": {
                "scanType": scanner,
                "parameters": [target]  # target should be APK filename
            }
        }
    elif scanner == "semgrep":
        # Semgrep expects a repository or directory path
        scan_yaml = {
            "apiVersion": "execution.securecodebox.io/v1",
            "kind": "Scan",
            "metadata": {"name": scan_name},
            "spec": {
                "scanType": scanner,
                "parameters": [
                    "--config=auto",
                    "--json",
                    "--output=/home/securecodebox/raw-results.json",
                    target
                ]
            }
        }
    elif scanner == "apkhunt":
        # APKHunt expects an APK file name as target
        scan_yaml = {
            "apiVersion": "execution.securecodebox.io/v1",
            "kind": "Scan",
            "metadata": {"name": scan_name},
            "spec": {
                "scanType": scanner,
                "parameters": [target]  # target should be APK filename
            }
        }
    else:
        scan_yaml = {
            "apiVersion": "execution.securecodebox.io/v1",
            "kind": "Scan",
            "metadata": {"name": scan_name},
            "spec": {"scanType": scanner, "parameters": [target]}
        }
    print(f"Scan YAML: {scan_yaml}")
    load_kube()
    k8s_api = client.CustomObjectsApi()
    try:
        k8s_api.create_namespaced_custom_object(
            group="execution.securecodebox.io",
            version="v1",
            namespace=NAMESPACE,
            plural="scans",
            body=scan_yaml
        )
        print("Scan CRD created successfully.")
    except Exception as e:
        print(f"Failed to create scan CRD: {e}")
        scan_in_progress.release()
        return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "error": str(e), "scan_in_progress": False})
    return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "scan_started": True, "scan_in_progress": True, "scan_name": scan_name})

@app.get("/status")
def status():
    if not current_scan_name:
        return {"status": "idle"}
    load_kube()
    k8s_api = client.CustomObjectsApi()
    try:
        scan = k8s_api.get_namespaced_custom_object(
            group="execution.securecodebox.io",
            version="v1",
            namespace=NAMESPACE,
            plural="scans",
            name=current_scan_name
        )
        print(f"Scan status: {scan.get('status', {})}")
        if scan.get("status", {}).get("state") == "Done":
            scan_in_progress.release()
            return {"status": "done"}
        return {"status": "running"}
    except Exception as e:
        print(f"Error fetching scan status: {e}")
        return {"status": "error", "error": str(e)}

@app.post("/download")
def download(request: Request, scan_name: str = Form(...), script_mode: bool = Form(False)):
    print(f"Download requested for scan_name: {scan_name}, script_mode={script_mode}")
    if script_mode:
        findings_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tlsx/findings-from-pvc.json'))
        if os.path.exists(findings_path):
            print(f"Serving findings file: {findings_path}")
            return FileResponse(findings_path, filename="findings.json")
        else:
            print("Findings file not found for download.")
            return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "error": "Findings file not found after script run.", "scan_in_progress": False})
    s3 = boto3.client("s3", endpoint_url=MINIO_ENDPOINT, aws_access_key_id=MINIO_ACCESS_KEY, aws_secret_access_key=MINIO_SECRET_KEY)
    scan_folder = f"scan-{scan_name}"
    findings_key = f"{scan_folder}/findings.json"
    local_path = f"/tmp/{scan_name}-findings.json"
    # Debug: List available scan folders
    try:
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET, Prefix="scan-")
        available_scans = []
        if 'Contents' in response:
            for obj in response['Contents']:
                if obj['Key'].endswith('/'):
                    available_scans.append(obj['Key'])
        print(f"Available scan folders: {available_scans}")
        print(f"Looking for findings at: {findings_key}")
    except Exception as e:
        print(f"Error listing scans: {e}")
    try:
        s3.download_file(MINIO_BUCKET, findings_key, local_path)
        print(f"Downloaded findings to {local_path}")
    except Exception as e:
        print(f"Could not download findings: {e}")
        return templates.TemplateResponse("index.html", {"request": request, "scanners": SCANNERS, "error": f"Could not download findings: {str(e)}", "scan_in_progress": False})
    return FileResponse(local_path, filename="findings.json")

@app.get("/debug")
def debug():
    return {
        "MINIO_ENDPOINT": MINIO_ENDPOINT,
        "MINIO_ACCESS_KEY": MINIO_ACCESS_KEY,
        "MINIO_SECRET_KEY": MINIO_SECRET_KEY,
        "MINIO_BUCKET": MINIO_BUCKET,
        "K8S_NAMESPACE": NAMESPACE,
        "current_scan_name": current_scan_name,
        "current_scanner": current_scanner,
        "current_target": current_target
    } 