import os, re, time, threading
from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import boto3
from kubernetes import client, config
import yaml

app = FastAPI()
templates = Jinja2Templates(directory="templates")
# app.mount("/static", StaticFiles(directory="static"), name="static")

# Configs (set these as env vars or hardcode for PoC)
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "admin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "password")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "securecodebox")
NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")

scan_in_progress = threading.Lock()
current_scan_name = None
current_filename = None

def safe_scan_name(filename):
    name = filename.lower()
    name = re.sub(r'[^a-z0-9.]', '-', name)
    if '.' in name:
        last_dot = name.rfind('.')
        name = name[:last_dot] + '-' + name[last_dot+1:]
    name = name.strip('-')
    name = re.sub(r'-+', '-', name)
    return name

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "scan_in_progress": scan_in_progress.locked()})

@app.post("/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".apk", ".ipa"]:
        return templates.TemplateResponse("index.html", {"request": request, "error": "Invalid file type. Only APK/IPA allowed.", "scan_in_progress": scan_in_progress.locked()})
    if scan_in_progress.locked():
        return templates.TemplateResponse("index.html", {"request": request, "error": "Scan in progress. Please wait.", "scan_in_progress": True})
    # Save to MinIO
    s3 = boto3.client("s3", endpoint_url=MINIO_ENDPOINT, aws_access_key_id=MINIO_ACCESS_KEY, aws_secret_access_key=MINIO_SECRET_KEY)
    s3.upload_fileobj(file.file, MINIO_BUCKET, file.filename)
    global current_filename
    current_filename = file.filename
    return templates.TemplateResponse("index.html", {"request": request, "filename": file.filename, "valid": True, "scan_in_progress": False})

@app.post("/scan")
def scan(request: Request, filename: str = Form(...)):
    if scan_in_progress.locked():
        return templates.TemplateResponse("index.html", {"request": request, "error": "Scan in progress. Please wait.", "scan_in_progress": True})
    scan_in_progress.acquire()
    scan_name = safe_scan_name(filename)
    global current_scan_name
    current_scan_name = scan_name
    print(f"Generated scan name: {scan_name} for filename: {filename}")
    # Generate scan.yaml
    scan_yaml = {
        "apiVersion": "execution.securecodebox.io/v1",
        "kind": "Scan",
        "metadata": {"name": scan_name},
        "spec": {"scanType": "mobsf", "parameters": [filename]}
    }
    # Apply scan.yaml
    config.load_incluster_config()
    k8s_api = client.CustomObjectsApi()
    k8s_api.create_namespaced_custom_object(
        group="execution.securecodebox.io",
        version="v1",
        namespace=NAMESPACE,
        plural="scans",
        body=scan_yaml
    )
    return templates.TemplateResponse("index.html", {"request": request, "scan_started": True, "filename": filename, "scan_in_progress": True, "scan_name": scan_name})

@app.get("/status")
def status():
    if not current_scan_name:
        return {"status": "idle"}
    config.load_incluster_config()
    k8s_api = client.CustomObjectsApi()
    scan = k8s_api.get_namespaced_custom_object(
        group="execution.securecodebox.io",
        version="v1",
        namespace=NAMESPACE,
        plural="scans",
        name=current_scan_name
    )
    if scan.get("status", {}).get("state") == "Done":
        scan_in_progress.release()
        return {"status": "done"}
    return {"status": "running"}


@app.post("/download")
async def download(request: Request, scan_name: str = Form(...)):
    # Download findings.json from MinIO for the given scan_name
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
    except Exception as e:
        return templates.TemplateResponse("index.html", {"request": request, "error": f"Could not download findings: {str(e)}", "scan_in_progress": False})
    return FileResponse(local_path, filename="findings.json")
