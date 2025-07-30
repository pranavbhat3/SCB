import os, re, time, threading
from fastapi import FastAPI, Request, Form, Body
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import boto3
from kubernetes import client, config
import sys
import subprocess
import json
import io
import time
import glob
import zipfile
import tempfile
import queue
import threading
import signal
import shutil
import concurrent.futures

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Configs (set these as env vars or hardcode for PoC)
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "admin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "password")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "securecodebox")
NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")

# Global state management
scan_in_progress = threading.Lock()
current_scan_name = None
current_target = None
current_results_dir = None
output_queue = queue.Queue()
current_process = None
output_thread = None
zap_done = False

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

def cleanup_process():
    """Clean up any running process"""
    global current_process, output_thread
    
    if current_process is not None:
        try:
            print(f"Terminating process (PID: {current_process.pid})")
            current_process.terminate()
            try:
                current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Process didn't terminate gracefully, forcing kill")
                current_process.kill()
                current_process.wait()
        except Exception as e:
            print(f"Error terminating process: {e}")
        finally:
            current_process = None
    
    if output_thread is not None and output_thread.is_alive():
        print("Output thread is still running, but will be cleaned up")

def clear_output_queue():
    """Clear the output queue"""
    global output_queue
    while not output_queue.empty():
        try:
            output_queue.get_nowait()
        except queue.Empty:
            break

def join_output_thread():
    global output_thread
    if output_thread is not None and output_thread.is_alive():
        print("Joining output thread...")
        output_thread.join(timeout=5)
        output_thread = None

def fetch_all_scan_results_from_minio(temp_dir):
    """Fetch all scan results from MinIO including Naabu, TLSX, ZAP, and Nuclei"""
    import boto3
    import time
    s3 = boto3.client(
        's3',
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
    )
    print(f"[MINIO] Fetching all scan results from bucket: {MINIO_BUCKET}")
    start = time.time()
    downloaded = []
    
    try:
        # List all objects in the bucket
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(s3.list_objects_v2, Bucket=MINIO_BUCKET)
            response = future.result(timeout=30)
    except concurrent.futures.TimeoutError:
        print("[MINIO] Timeout while listing objects!")
        return []
    except Exception as e:
        print(f"[MINIO] Error listing objects: {e}")
        return []
    
    print(f"[MINIO] List objects took {time.time()-start:.2f}s")
    
    if 'Contents' in response:
        for obj in response['Contents']:
            key = obj['Key']
            print(f"[MINIO] Found object: {key}")
            
            # Download all relevant scan result files
            if (key.endswith('findings.json') or 
                key.endswith('zap-results.xml') or 
                key.endswith('zap-results.json') or
                key.endswith('.jsonl') or
                'naabu-findings' in key or
                'tlsx-findings' in key or
                'nuclei' in key):
                
                # Create a meaningful filename
                if key.startswith('securecodebox/securecodebox/'):
                    # Remove the bucket prefix
                    clean_key = key.replace('securecodebox/securecodebox/', '')
                else:
                    clean_key = key
                
                # Create a safe filename
                safe_filename = clean_key.replace('/', '_').replace(':', '_')
                local_path = os.path.join(temp_dir, safe_filename)
                
                print(f"[MINIO] Downloading {key} to {local_path}")
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(s3.download_file, MINIO_BUCKET, key, local_path)
                        future.result(timeout=30)
                    downloaded.append(local_path)
                    print(f"[MINIO] Successfully downloaded: {safe_filename}")
                except concurrent.futures.TimeoutError:
                    print(f"[MINIO] Timeout downloading {key}")
                except Exception as e:
                    print(f"[MINIO] Error downloading {key} from MinIO: {e}")
    
    print(f"[MINIO] Total downloaded files: {len(downloaded)}")
    for file in downloaded:
        print(f"[MINIO] - {os.path.basename(file)}")
    
    return downloaded

def fetch_zap_reports_from_minio(scan_folder, temp_dir):
    """Legacy function for backward compatibility"""
    return fetch_all_scan_results_from_minio(temp_dir)

@app.get("/clear-scan")
def clear_scan():
    global current_scan_name, current_target, current_results_dir, output_queue, current_process, output_thread, zap_done
    print("=== CLEARING SCAN STATE ===")
    
    # Kill any running process
    if current_process is not None:
        try:
            print(f"Terminating process (PID: {current_process.pid})")
            current_process.terminate()
            try:
                current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Process didn't terminate gracefully, forcing kill")
                current_process.kill()
                current_process.wait()
        except Exception as e:
            print(f"Error terminating process: {e}")
        finally:
            current_process = None
    join_output_thread()
    
    # Release any locks
    if scan_in_progress.locked():
        print("Releasing scan lock")
        scan_in_progress.release()
    
    # Clear the output queue
    clear_output_queue()
    
    # Reset all global variables
    current_scan_name = None
    current_target = None
    current_results_dir = None
    zap_done = False
    
    # Clean up any temporary files
    try:
        import tempfile
        import glob
        import os
        
        # Clean up temporary ZIP files
        temp_dir = tempfile.gettempdir()
        for temp_file in glob.glob(os.path.join(temp_dir, "*.zip")):
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    print(f"Removed temp file: {temp_file}")
            except Exception as e:
                print(f"Error removing temp file {temp_file}: {e}")
                
        # Clean up temporary scan files
        for temp_file in glob.glob("/tmp/*-scan-*.yaml"):
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    print(f"Removed scan YAML: {temp_file}")
            except Exception as e:
                print(f"Error removing scan YAML {temp_file}: {e}")
                
    except Exception as e:
        print(f"Error during cleanup: {e}")
    
    print("=== SCAN STATE CLEARED ===")
    return {"status": "cleared", "message": "All scan state cleared and cleaned up"}

@app.get("/reset")
def reset():
    global current_scan_name, current_target, current_results_dir, zap_done
    print("=== RESETTING SCAN STATE ===")
    
    # Release any locks
    if scan_in_progress.locked():
        print("Releasing scan lock")
        scan_in_progress.release()
    
    # Reset all global variables
    current_scan_name = None
    current_target = None
    current_results_dir = None
    zap_done = False
    
    print("=== SCAN STATE RESET ===")
    return {"status": "reset"}

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    global current_scan_name, current_target, current_results_dir
    
    # Always set scan_in_progress to False unless a scan is running
    in_progress = scan_in_progress.locked() and current_scan_name is not None
    
    # If there's no active scan but we have old state, clear it
    if not in_progress and (current_scan_name is not None or current_target is not None):
        print("Clearing stale scan state on page load")
        current_scan_name = None
        current_target = None
        current_results_dir = None
    
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "scan_in_progress": in_progress, 
        "scan_name": current_scan_name, 
        "target": current_target,
        "results_dir": current_results_dir
    })

@app.post("/scan")
def scan(request: Request, target: str = Form(...)):
    global current_scan_name, current_target, current_results_dir, output_queue, output_thread, current_process, zap_done
    if scan_in_progress.locked() or (current_process is not None and current_process.poll() is None):
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "error": "Scan in progress. Please wait for current scan to complete or use 'Clear Scan State' to reset.", 
            "scan_in_progress": True, 
            "scan_name": current_scan_name, 
            "target": current_target,
            "results_dir": current_results_dir
        })
    acquired = scan_in_progress.acquire(blocking=False)
    if not acquired:
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "error": "Could not acquire scan lock. Please try again.", 
            "scan_in_progress": True, 
            "scan_name": current_scan_name, 
            "target": current_target,
            "results_dir": current_results_dir
        })
    scan_name = f"cascading-scan-{int(time.time())}"
    current_scan_name = scan_name
    current_target = target
    current_results_dir = None
    zap_done = False
    clear_output_queue()
    try:
        # Use the cascading script that runs Naabu -> TLSX -> ZAP -> Nuclei
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'run_cascading_manual.sh'))
        current_process = subprocess.Popen(
            ["bash", script_path, target], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            cwd=os.path.dirname(script_path)
        )
        def read_output():
            global current_results_dir, zap_done
            try:
                while True:
                    output = current_process.stdout.readline()
                    if output == '' and current_process.poll() is not None:
                        break
                    if output:
                        line = output.strip()
                        print(f"CASCADING SCRIPT OUTPUT: {line}")
                        output_queue.put(line)
                        # Detect cascading scan completion
                        if 'CASCADING SCAN WORKFLOW COMPLETE' in line or 'All scans completed successfully' in line:
                            zap_done = True
                            print("Cascading scan completed! Download available.")
                        if "nuclei-results.jsonl" in line:
                            print("Nuclei results file found!")
                        if "findings.json" in line:
                            print("Findings file found!")
            except Exception as e:
                print(f"Error in output reading thread: {e}")
            finally:
                print("Output reading thread finished")
                if scan_in_progress.locked():
                    scan_in_progress.release()
                current_scan_name = None
                current_target = None
        output_thread = threading.Thread(target=read_output, daemon=True)
        output_thread.start()
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "scan_in_progress": True, 
            "scan_name": scan_name, 
            "target": target,
            "results_dir": None,
            "script_stdout": f"Starting cascading scan (Naabu → TLSX → ZAP → Nuclei) for {target}...\nCheck the output below for real-time progress.",
            "script_stderr": ""
        })
    except Exception as e:
        if scan_in_progress.locked():
            scan_in_progress.release()
        current_scan_name = None
        current_target = None
        current_process = None
        output_thread = None
        zap_done = False
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "error": str(e), 
            "scan_in_progress": False, 
            "scan_name": scan_name, 
            "target": target,
            "results_dir": None
        })

@app.get("/zap-ready")
def zap_ready():
    global zap_done
    return {"zap_done": zap_done}

@app.get("/stream-output")
def stream_output():
    """Stream real-time output from the running script"""
    def generate():
        while True:
            try:
                # Get output from queue with timeout
                line = output_queue.get(timeout=1)
                yield f"data: {json.dumps({'output': line})}\n\n"
            except queue.Empty:
                # Send keepalive
                yield f"data: {json.dumps({'keepalive': True})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break
    
    return StreamingResponse(generate(), media_type="text/plain")

@app.get("/scan-status")
def get_scan_status():
    """Get current scan status"""
    global current_process, current_scan_name, current_target, current_results_dir
    
    if current_process is None:
        return {"status": "idle"}
    
    return_code = current_process.poll()
    if return_code is None:
        return {
            "status": "running", 
            "scan_name": current_scan_name,
            "target": current_target,
            "results_dir": current_results_dir
        }
    else:
        return {
            "status": "completed" if return_code == 0 else "failed",
            "return_code": return_code,
            "scan_name": current_scan_name,
            "target": current_target,
            "results_dir": current_results_dir
        }

@app.get("/status")
def status():
    if not current_scan_name:
        return {"status": "idle"}
    return {"status": "running", "scan_name": current_scan_name, "target": current_target}

@app.get("/download-results/{scan_name}")
def download_results(scan_name: str):
    """Legacy endpoint - redirects to individual file downloads"""
    return JSONResponse(
        content={"message": "Use individual file downloads instead of ZIP", "status": "redirect"},
        status_code=200
    )

@app.get("/list-results")
def list_results():
    """List all available result files from MinIO only"""
    try:
        files = []
        
        # Only add MinIO files
        try:
            import boto3
            s3 = boto3.client(
                's3',
                endpoint_url=MINIO_ENDPOINT,
                aws_access_key_id=MINIO_ACCESS_KEY,
                aws_secret_access_key=MINIO_SECRET_KEY,
            )
            
            response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
            if 'Contents' in response:
                for obj in response['Contents']:
                    key = obj['Key']
                    size = obj['Size']
                    
                    # Only include relevant scan result files
                    if (key.endswith('findings.json') or 
                        key.endswith('zap-results.xml') or 
                        key.endswith('zap-results.json') or
                        key.endswith('.jsonl') or
                        'naabu-findings' in key or
                        'tlsx-findings' in key or
                        'nuclei' in key):
                        
                        # Create a meaningful filename
                        if key.startswith('securecodebox/securecodebox/'):
                            clean_key = key.replace('securecodebox/securecodebox/', '')
                        else:
                            clean_key = key
                        
                        safe_filename = clean_key.replace('/', '_').replace(':', '_')
                        
                        files.append({
                            "name": safe_filename,
                            "path": f"minio://{key}",
                            "size": size,
                            "full_path": key,
                            "source": "minio"
                        })
        except Exception as e:
            print(f"[LIST-RESULTS] Error accessing MinIO: {e}")
        
        return JSONResponse(content={"files": files, "results_dir": "minio://securecodebox/securecodebox"})
    
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to list files: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-file/{filename:path}")
def download_file(filename: str):
    """Download a specific file from MinIO only"""
    
    # All files should be MinIO files
    if not filename.startswith('minio://'):
        return JSONResponse(
            content={"error": "Only MinIO files are supported"}, 
            status_code=400
        )
    
    minio_key = filename.replace('minio://', '')
    try:
        import boto3
        import tempfile
        s3 = boto3.client(
            's3',
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
        )
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp_file:
            s3.download_file(MINIO_BUCKET, minio_key, tmp_file.name)
            
            # Get the original filename
            original_filename = os.path.basename(minio_key)
            if original_filename == 'findings.json':
                # Try to get a more descriptive name from the path
                path_parts = minio_key.split('/')
                if len(path_parts) > 2:
                    scan_type = path_parts[-2]  # e.g., scan-56073cce-a9c6-480f-bd3a-aaa271a2f87e
                    original_filename = f"{scan_type}-findings.json"
            
            return FileResponse(
                tmp_file.name, 
                filename=original_filename,
                media_type='application/octet-stream'
            )
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to download MinIO file: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-naabu")
def download_naabu():
    """Download Naabu results from MinIO"""
    try:
        import boto3
        import tempfile
        import requests
        
        # First check if MinIO is accessible
        try:
            health_check = requests.get(f"{MINIO_ENDPOINT}/minio/health/ready", timeout=5)
            if health_check.status_code != 200:
                return JSONResponse(
                    content={"error": f"MinIO is not healthy. Status: {health_check.status_code}. Please ensure MinIO is running and port-forwarded to localhost:9000"}, 
                    status_code=503
                )
        except requests.exceptions.RequestException as e:
            return JSONResponse(
                content={"error": f"Cannot connect to MinIO at {MINIO_ENDPOINT}. Please ensure MinIO is running and port-forwarded. Error: {str(e)}"}, 
                status_code=503
            )
        
        s3 = boto3.client(
            's3',
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
        )
        
        # Find naabu findings files (cascading script creates scan-specific folders with findings.json)
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
        naabu_files = []
        
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                # Look for findings.json files in scan folders (Naabu scans create scan-{uid} folders)
                if key.endswith('findings.json') and 'scan-' in key:
                    naabu_files.append((key, obj['LastModified']))
                    print(f"[DOWNLOAD-NAABU] Found file: {key}")
        
        if not naabu_files:
            print("[DOWNLOAD-NAABU] No naabu files found in MinIO")
            return JSONResponse(
                content={"error": "No Naabu results found in MinIO. Please run a scan first."}, 
                status_code=404
            )
        
        # Get the most recent file
        latest_file = max(naabu_files, key=lambda x: x[1])
        minio_key = latest_file[0]
        print(f"[DOWNLOAD-NAABU] Downloading: {minio_key}")
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp_file:
            s3.download_file(MINIO_BUCKET, minio_key, tmp_file.name)
            
            # Create a nice filename
            filename = f"naabu-results-{int(time.time())}.json"
            
            return FileResponse(
                tmp_file.name, 
                filename=filename,
                media_type='application/json'
            )
    except Exception as e:
        print(f"[DOWNLOAD-NAABU] Error: {e}")
        return JSONResponse(
            content={"error": f"Failed to download Naabu results: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-tlsx")
def download_tlsx():
    """Download TLSX results from MinIO"""
    try:
        import boto3
        import tempfile
        s3 = boto3.client(
            's3',
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
        )
        
        # Find TLSX findings files (script uploads to scan-specific folders)
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
        tlsx_files = []
        
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                # Look for findings.json files in scan folders (TLSX scans create scan-{uid} folders)
                if key.endswith('findings.json') and 'scan-' in key:
                    # The script uploads TLSX results to scan-specific folders
                    # We need to find the most recent scan folder with findings.json
                    tlsx_files.append((key, obj['LastModified']))
                    print(f"[DOWNLOAD-TLSX] Found file: {key}")
        
        if not tlsx_files:
            print("[DOWNLOAD-TLSX] No TLSX files found in MinIO")
            return JSONResponse(
                content={"error": "No TLSX results found in MinIO"}, 
                status_code=404
            )
        
        # Get the most recent file
        latest_file = max(tlsx_files, key=lambda x: x[1])
        minio_key = latest_file[0]
        print(f"[DOWNLOAD-TLSX] Downloading: {minio_key}")
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp_file:
            s3.download_file(MINIO_BUCKET, minio_key, tmp_file.name)
            
            # Create a nice filename
            filename = f"tlsx-results-{int(time.time())}.json"
            
            return FileResponse(
                tmp_file.name, 
                filename=filename,
                media_type='application/json'
            )
    except Exception as e:
        print(f"[DOWNLOAD-TLSX] Error: {e}")
        return JSONResponse(
            content={"error": f"Failed to download TLSX results: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-zap")
def download_zap():
    """Download ZAP results from MinIO"""
    try:
        import boto3
        import tempfile
        s3 = boto3.client(
            's3',
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
        )
        
        # Find ZAP findings files (ZAP scans also create scan-specific folders)
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
        zap_files = []
        
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                # Look for findings.json files in scan folders
                if key.endswith('findings.json') and 'scan-' in key:
                    # ZAP scans create scan-{uid} folders with findings.json
                    zap_files.append((key, obj['LastModified']))
                    print(f"[DOWNLOAD-ZAP] Found file: {key}")
        
        if not zap_files:
            print("[DOWNLOAD-ZAP] No ZAP files found in MinIO")
            return JSONResponse(
                content={"error": "No ZAP results found in MinIO"}, 
                status_code=404
            )
        
        # Get the most recent file
        latest_file = max(zap_files, key=lambda x: x[1])
        minio_key = latest_file[0]
        print(f"[DOWNLOAD-ZAP] Downloading: {minio_key}")
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp_file:
            s3.download_file(MINIO_BUCKET, minio_key, tmp_file.name)
            
            # Create a nice filename
            filename = f"zap-results-{int(time.time())}.json"
            
            return FileResponse(
                tmp_file.name, 
                filename=filename,
                media_type='application/json'
            )
    except Exception as e:
        print(f"[DOWNLOAD-ZAP] Error: {e}")
        return JSONResponse(
            content={"error": f"Failed to download ZAP results: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-nuclei")
def download_nuclei():
    """Download Nuclei results from MinIO"""
    try:
        import boto3
        import tempfile
        import json
        s3 = boto3.client(
            's3',
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
        )
        
        # Find Nuclei results files (look for nuclei-results.jsonl in scan folders)
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
        nuclei_files = []
        
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                # Look for nuclei-results.jsonl files in scan folders (this is what the working script creates)
                if key.endswith('nuclei-results.jsonl') and 'scan-' in key:
                    nuclei_files.append((key, obj['LastModified']))
                    print(f"[DOWNLOAD-NUCLEI] Found file: {key}")
        
        if not nuclei_files:
            print("[DOWNLOAD-NUCLEI] No Nuclei results found in MinIO")
            return JSONResponse(
                content={"error": "No Nuclei results found in MinIO. Please run a Nuclei scan first."}, 
                status_code=404
            )
        
        # Get the most recent file
        latest_file = max(nuclei_files, key=lambda x: x[1])
        minio_key = latest_file[0]
        print(f"[DOWNLOAD-NUCLEI] Downloading: {minio_key}")
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp_file:
            s3.download_file(MINIO_BUCKET, minio_key, tmp_file.name)
            
            # Convert JSONL to JSON array format for better readability
            try:
                nuclei_results = []
                with open(tmp_file.name, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                nuclei_results.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                
                # Create a structured result
                structured_result = {
                    "scan_info": {
                        "scanner": "nuclei",
                        "target": "IP address",
                        "status": "completed",
                        "findings_count": len(nuclei_results),
                        "message": f"Found {len(nuclei_results)} vulnerabilities" if nuclei_results else "No vulnerabilities found"
                    },
                    "findings": nuclei_results
                }
                
                # Write the structured result back to the temp file
                with open(tmp_file.name, 'w') as f:
                    json.dump(structured_result, f, indent=2)
                
                print(f"[DOWNLOAD-NUCLEI] Processed {len(nuclei_results)} findings")
                
            except Exception as e:
                print(f"[DOWNLOAD-NUCLEI] Error processing file content: {e}")
                # If processing fails, return the raw file
                pass
            
            # Create a nice filename
            filename = f"nuclei-results-{int(time.time())}.json"
            
            return FileResponse(
                tmp_file.name, 
                filename=filename,
                media_type='application/json'
            )
    except Exception as e:
        print(f"[DOWNLOAD-NUCLEI] Error: {e}")
        return JSONResponse(
            content={"error": f"Failed to download Nuclei results: {str(e)}"}, 
            status_code=500
        )



@app.get("/debug")
def debug():
    # Get MinIO files for debugging
    minio_files = []
    try:
        import boto3
        s3 = boto3.client(
            's3',
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
        )
        
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
        if 'Contents' in response:
            for obj in response['Contents']:
                minio_files.append({
                    "key": obj['Key'],
                    "size": obj['Size'],
                    "last_modified": str(obj['LastModified'])
                })
    except Exception as e:
        minio_files = [{"error": str(e)}]
    
    return {
        "MINIO_ENDPOINT": MINIO_ENDPOINT,
        "MINIO_ACCESS_KEY": MINIO_ACCESS_KEY,
        "MINIO_SECRET_KEY": MINIO_SECRET_KEY,
        "MINIO_BUCKET": MINIO_BUCKET,
        "K8S_NAMESPACE": NAMESPACE,
        "current_scan_name": current_scan_name,
        "current_target": current_target,
        "current_results_dir": current_results_dir,
        "scan_in_progress_locked": scan_in_progress.locked(),
        "current_process_pid": current_process.pid if current_process else None,
        "current_process_returncode": current_process.poll() if current_process else None,
        "output_queue_size": output_queue.qsize(),
        "output_thread_alive": output_thread.is_alive() if output_thread else False,
        "minio_files": minio_files
    } 

@app.get("/minio-health")
def minio_health():
    import requests
    try:
        resp = requests.get(f"{MINIO_ENDPOINT}/minio/health/ready", timeout=3)
        if resp.status_code == 200:
            return {"minio": "ok", "endpoint": MINIO_ENDPOINT}
        else:
            return {"minio": "unhealthy", "status_code": resp.status_code, "endpoint": MINIO_ENDPOINT}
    except Exception as e:
        return {"minio": "unreachable", "error": str(e), "endpoint": MINIO_ENDPOINT}

@app.get("/check-minio")
def check_minio():
    """Check MinIO connectivity and list available files"""
    try:
        import boto3
        import requests
        
        # Check MinIO health
        try:
            health_check = requests.get(f"{MINIO_ENDPOINT}/minio/health/ready", timeout=5)
            health_status = "healthy" if health_check.status_code == 200 else f"unhealthy (status: {health_check.status_code})"
        except requests.exceptions.RequestException as e:
            health_status = f"unreachable: {str(e)}"
        
        # Try to list files
        try:
            s3 = boto3.client(
                's3',
                endpoint_url=MINIO_ENDPOINT,
                aws_access_key_id=MINIO_ACCESS_KEY,
                aws_secret_access_key=MINIO_SECRET_KEY,
            )
            
            response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    files.append({
                        "key": obj['Key'],
                        "size": obj['Size'],
                        "last_modified": str(obj['LastModified'])
                    })
            
            return {
                "minio_endpoint": MINIO_ENDPOINT,
                "health_status": health_status,
                "bucket": MINIO_BUCKET,
                "files_found": len(files),
                "files": files
            }
        except Exception as e:
            return {
                "minio_endpoint": MINIO_ENDPOINT,
                "health_status": health_status,
                "bucket": MINIO_BUCKET,
                "error": f"Failed to list files: {str(e)}",
                "files_found": 0,
                "files": []
            }
            
    except Exception as e:
        return {
            "minio_endpoint": MINIO_ENDPOINT,
            "error": f"General error: {str(e)}",
            "files_found": 0,
            "files": []
        } 