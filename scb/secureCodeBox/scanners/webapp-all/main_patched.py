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

# Add this new function after the existing imports and before the existing functions

def discover_scanner_files():
    """Discover all scanner files in MinIO and categorize them by scanner type and scan folders"""
    try:
        import boto3
        s3 = boto3.client(
            's3',
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
        )
        
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
        if 'Contents' not in response:
            return {}
        
        # Organize by scan folders and scanner types
        scan_folders = {}
        scanner_files = {
            'naabu': [],
            'tlsx': [],
            'zap': [],
            'nuclei': [],
            'other': []
        }
        
        for obj in response['Contents']:
            key = obj['Key']
            file_info = {
                'key': key,
                'size': obj['Size'],
                'last_modified': obj['LastModified'],
                'file_type': 'unknown',
                'scan_folder': None
            }
            
            # Extract scan folder if present
            if key.startswith('scan-') and '/' in key:
                parts = key.split('/')
                if len(parts) >= 2:
                    file_info['scan_folder'] = parts[0]
            
            # Categorize files by patterns and content
            if 'naabu' in key.lower() or (key.endswith('naabu-findings') and '.json' in key):
                file_info['file_type'] = 'findings'
                scanner_files['naabu'].append(file_info)
            elif 'tlsx' in key.lower() or (key.endswith('findings.json') and 'scan-' in key and 'tlsx' in key):
                file_info['file_type'] = 'findings'
                scanner_files['tlsx'].append(file_info)
            elif 'zap' in key.lower() or key.endswith('.html') or (key.endswith('.json') and 'zap' in key):
                if 'report' in key.lower() or key.endswith('.html'):
                    file_info['file_type'] = 'report'
                else:
                    file_info['file_type'] = 'findings'
                scanner_files['zap'].append(file_info)
            elif 'nuclei' in key.lower() or key.endswith('.jsonl') or key.endswith('nuclei-results'):
                if key.endswith('.jsonl'):
                    file_info['file_type'] = 'raw'
                elif key.endswith('.md'):
                    file_info['file_type'] = 'summary'
                else:
                    file_info['file_type'] = 'findings'
                scanner_files['nuclei'].append(file_info)
            elif key.endswith('findings.json') and 'scan-' in key:
                # Generic findings.json in scan folders - try to determine scanner type
                if file_info['scan_folder']:
                    # This could be TLSX, ZAP, or other scanner findings
                    file_info['file_type'] = 'findings'
                    scanner_files['tlsx'].append(file_info)  # Most likely TLSX
            else:
                scanner_files['other'].append(file_info)
            
            # Organize by scan folders
            if file_info['scan_folder']:
                if file_info['scan_folder'] not in scan_folders:
                    scan_folders[file_info['scan_folder']] = []
                scan_folders[file_info['scan_folder']].append(file_info)
        
        # Sort each scanner's files by last modified (newest first)
        for scanner in scanner_files:
            scanner_files[scanner].sort(key=lambda x: x['last_modified'], reverse=True)
        
        # Sort scan folders by last modified (newest first)
        for folder in scan_folders:
            scan_folders[folder].sort(key=lambda x: x['last_modified'], reverse=True)
        
        return {
            'scanner_files': scanner_files,
            'scan_folders': scan_folders
        }
        
    except Exception as e:
        print(f"[DISCOVER-FILES] Error: {e}")
        return {'scanner_files': {}, 'scan_folders': {}}

def get_latest_scanner_file(scanner_type, file_type=None):
    """Get the latest file for a specific scanner and optional file type"""
    scanner_files = discover_scanner_files()
    if scanner_type not in scanner_files or not scanner_files[scanner_type]:
        return None
    
    if file_type:
        # Filter by file type
        filtered_files = [f for f in scanner_files[scanner_type] if f['file_type'] == file_type]
        return filtered_files[0] if filtered_files else None
    else:
        # Return the most recent file regardless of type
        return scanner_files[scanner_type][0]

def download_file_by_key(minio_key, filename_prefix):
    """Generic function to download a file from MinIO by its key"""
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
            
            # Create a nice filename
            filename = f"{filename_prefix}-{int(time.time())}.json"
            
            return FileResponse(
                tmp_file.name, 
                filename=filename,
                media_type='application/json'
            )
    except Exception as e:
        print(f"[DOWNLOAD-FILE] Error downloading {minio_key}: {e}")
        raise e

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
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'run_cascading_manual.sh'))
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

# Add new comprehensive file discovery and download endpoints

@app.get("/discover-files")
def discover_files():
    """Discover and categorize all scanner files in MinIO"""
    try:
        scanner_files = discover_scanner_files()
        
        # Add summary information
        summary = {}
        for scanner, files in scanner_files['scanner_files'].items():
            summary[scanner] = {
                'total_files': len(files),
                'file_types': list(set(f['file_type'] for f in files)),
                'latest_file': files[0] if files else None,
                'files': files[:5]  # Show first 5 files for each scanner
            }
        
        return {
            "status": "success",
            "scanner_summary": summary,
            "total_files": sum(len(files) for files in scanner_files['scanner_files'].values())
        }
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to discover files: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-scanner/{scanner_type}")
def download_scanner_latest(scanner_type: str, file_type: str = None):
    """Download the latest file for a specific scanner with optional file type filter"""
    try:
        file_info = get_latest_scanner_file(scanner_type, file_type)
        
        if not file_info:
            return JSONResponse(
                content={"error": f"No {scanner_type} files found" + (f" of type {file_type}" if file_type else "")}, 
                status_code=404
            )
        
        return download_file_by_key(file_info['key'], f"{scanner_type}-latest")
        
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to download {scanner_type} results: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-scanner-file/{scanner_type}/{file_index}")
def download_scanner_file_by_index(scanner_type: str, file_index: int):
    """Download a specific file by index for a scanner"""
    try:
        scanner_files = discover_scanner_files()
        
        if scanner_type not in scanner_files['scanner_files'] or not scanner_files['scanner_files'][scanner_type]:
            return JSONResponse(
                content={"error": f"No {scanner_type} files found"}, 
                status_code=404
            )
        
        if file_index >= len(scanner_files['scanner_files'][scanner_type]):
            return JSONResponse(
                content={"error": f"File index {file_index} out of range. Available files: {len(scanner_files['scanner_files'][scanner_type])}"}, 
                status_code=400
            )
        
        file_info = scanner_files['scanner_files'][scanner_type][file_index]
        return download_file_by_key(file_info['key'], f"{scanner_type}-file-{file_index}")
        
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to download {scanner_type} file: {str(e)}"}, 
            status_code=500
        )

@app.get("/list-scanner-files/{scanner_type}")
def list_scanner_files(scanner_type: str):
    """List all available files for a specific scanner"""
    try:
        scanner_files = discover_scanner_files()
        
        if scanner_type not in scanner_files['scanner_files']:
            return JSONResponse(
                content={"error": f"Unknown scanner type: {scanner_type}"}, 
                status_code=400
            )
        
        files = scanner_files['scanner_files'][scanner_type]
        
        # Format file information for display
        formatted_files = []
        for i, file_info in enumerate(files):
            formatted_files.append({
                "index": i,
                "filename": file_info['key'].split('/')[-1],
                "full_path": file_info['key'],
                "size_bytes": file_info['size'],
                "size_human": f"{file_info['size'] / 1024:.1f} KB" if file_info['size'] < 1024*1024 else f"{file_info['size'] / (1024*1024):.1f} MB",
                "file_type": file_info['file_type'],
                "last_modified": str(file_info['last_modified']),
                "download_url": f"/download-scanner-file/{scanner_type}/{i}"
            })
        
        return {
            "scanner": scanner_type,
            "total_files": len(files),
            "files": formatted_files
        }
        
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to list {scanner_type} files: {str(e)}"}, 
            status_code=500
        )

@app.get("/list-scan-folders")
def list_scan_folders():
    """List all available scan folders with their contents"""
    try:
        scanner_files = discover_scanner_files()
        scan_folders = scanner_files['scan_folders']
        
        # Format folder information for display
        formatted_folders = []
        for folder_name, files in scan_folders.items():
            # Group files by scanner type within the folder
            folder_scanners = {}
            for file_info in files:
                scanner_type = 'unknown'
                if 'naabu' in file_info['key'].lower():
                    scanner_type = 'naabu'
                elif 'tlsx' in file_info['key'].lower() or file_info['key'].endswith('findings.json'):
                    scanner_type = 'tlsx'
                elif 'zap' in file_info['key'].lower() or file_info['key'].endswith('.html'):
                    scanner_type = 'zap'
                elif 'nuclei' in file_info['key'].lower() or file_info['key'].endswith('.jsonl'):
                    scanner_type = 'nuclei'
                
                if scanner_type not in folder_scanners:
                    folder_scanners[scanner_type] = []
                folder_scanners[scanner_type].append(file_info)
            
            formatted_folders.append({
                "folder_name": folder_name,
                "total_files": len(files),
                "scanners": list(folder_scanners.keys()),
                "files": files,
                "scanner_files": folder_scanners,
                "latest_modified": max(f['last_modified'] for f in files) if files else None
            })
        
        # Sort folders by latest modification time (newest first)
        formatted_folders.sort(key=lambda x: x['latest_modified'], reverse=True)
        
        return {
            "total_folders": len(formatted_folders),
            "folders": formatted_folders
        }
        
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to list scan folders: {str(e)}"}, 
            status_code=500
        )

@app.get("/list-folder-contents/{folder_name}")
def list_folder_contents(folder_name: str):
    """List all files in a specific scan folder"""
    try:
        scanner_files = discover_scanner_files()
        scan_folders = scanner_files['scan_folders']
        
        if folder_name not in scan_folders:
            return JSONResponse(
                content={"error": f"Folder {folder_name} not found"}, 
                status_code=404
            )
        
        files = scan_folders[folder_name]
        
        # Format file information for display
        formatted_files = []
        for i, file_info in enumerate(files):
            # Determine scanner type
            scanner_type = 'unknown'
            if 'naabu' in file_info['key'].lower():
                scanner_type = 'naabu'
            elif 'tlsx' in file_info['key'].lower() or file_info['key'].endswith('findings.json'):
                scanner_type = 'tlsx'
            elif 'zap' in file_info['key'].lower() or file_info['key'].endswith('.html'):
                scanner_type = 'zap'
            elif 'nuclei' in file_info['key'].lower() or file_info['key'].endswith('.jsonl'):
                scanner_type = 'nuclei'
            
            formatted_files.append({
                "index": i,
                "filename": file_info['key'].split('/')[-1],
                "full_path": file_info['key'],
                "scanner_type": scanner_type,
                "size_bytes": file_info['size'],
                "size_human": f"{file_info['size'] / 1024:.1f} KB" if file_info['size'] < 1024*1024 else f"{file_info['size'] / (1024*1024):.1f} MB",
                "file_type": file_info['file_type'],
                "last_modified": str(file_info['last_modified']),
                "download_url": f"/download-folder-file/{folder_name}/{i}"
            })
        
        return {
            "folder_name": folder_name,
            "total_files": len(files),
            "files": formatted_files
        }
        
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to list folder contents: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-folder-file/{folder_name}/{file_index}")
def download_folder_file(folder_name: str, file_index: int):
    """Download a specific file from a scan folder"""
    try:
        scanner_files = discover_scanner_files()
        scan_folders = scanner_files['scan_folders']
        
        if folder_name not in scan_folders:
            return JSONResponse(
                content={"error": f"Folder {folder_name} not found"}, 
                status_code=404
            )
        
        files = scan_folders[folder_name]
        
        if file_index >= len(files):
            return JSONResponse(
                content={"error": f"File index {file_index} out of range. Available files: {len(files)}"}, 
                status_code=400
            )
        
        file_info = files[file_index]
        filename = file_info['key'].split('/')[-1]
        
        return download_file_by_key(file_info['key'], f"{folder_name}-{filename}")
        
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to download folder file: {str(e)}"}, 
            status_code=500
        )

@app.get("/download-folder/{folder_name}")
def download_folder_zip(folder_name: str):
    """Download all files from a scan folder as a ZIP archive"""
    try:
        import zipfile
        import tempfile
        import boto3
        
        scanner_files = discover_scanner_files()
        scan_folders = scanner_files['scan_folders']
        
        if folder_name not in scan_folders:
            return JSONResponse(
                content={"error": f"Folder {folder_name} not found"}, 
                status_code=404
            )
        
        files = scan_folders[folder_name]
        
        # Create a temporary ZIP file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_zip:
            with zipfile.ZipFile(tmp_zip.name, 'w') as zip_file:
                s3 = boto3.client(
                    's3',
                    endpoint_url=MINIO_ENDPOINT,
                    aws_access_key_id=MINIO_ACCESS_KEY,
                    aws_secret_access_key=MINIO_SECRET_KEY,
                )
                
                for file_info in files:
                    # Download file from MinIO
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        s3.download_file(MINIO_BUCKET, file_info['key'], tmp_file.name)
                        
                        # Add to ZIP with original filename
                        filename = file_info['key'].split('/')[-1]
                        zip_file.write(tmp_file.name, filename)
                        
                        # Clean up temp file
                        import os
                        os.unlink(tmp_file.name)
            
            # Return the ZIP file
            return FileResponse(
                tmp_zip.name,
                filename=f"{folder_name}-results.zip",
                media_type='application/zip'
            )
        
    except Exception as e:
        return JSONResponse(
            content={"error": f"Failed to download folder: {str(e)}"}, 
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

# Add new cascading scanner routes after the existing routes

@app.get("/cascading")
def cascading_index(request: Request):
    """Cascading scanner tab - separate from main scanner"""
    global current_scan_name, current_target, current_results_dir
    
    # Always set scan_in_progress to False unless a scan is running
    in_progress = scan_in_progress.locked() and current_scan_name is not None
    
    # If there's no active scan but we have old state, clear it
    if not in_progress and (current_scan_name is not None or current_target is not None):
        print("Clearing stale scan state on cascading page load")
        current_scan_name = None
        current_target = None
        current_results_dir = None
    
    return templates.TemplateResponse("cascading.html", {
        "request": request, 
        "scan_in_progress": in_progress, 
        "scan_name": current_scan_name, 
        "target": current_target,
        "results_dir": current_results_dir
    })

@app.post("/cascading-scan")
def cascading_scan(request: Request, target: str = Form(...)):
    """Start a cascading scan using the existing GUI logic"""
    global current_scan_name, current_target, current_results_dir, output_queue, output_thread, current_process, zap_done
    if scan_in_progress.locked() or (current_process is not None and current_process.poll() is None):
        return templates.TemplateResponse("cascading.html", {
            "request": request, 
            "error": "Scan in progress. Please wait for current scan to complete or use 'Clear Scan State' to reset.", 
            "scan_in_progress": True, 
            "scan_name": current_scan_name, 
            "target": current_target,
            "results_dir": current_results_dir
        })
    acquired = scan_in_progress.acquire(blocking=False)
    if not acquired:
        return templates.TemplateResponse("cascading.html", {
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
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'run_cascading_manual.sh'))
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
        return templates.TemplateResponse("cascading.html", {
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
        return templates.TemplateResponse("cascading.html", {
            "request": request, 
            "error": str(e), 
            "scan_in_progress": False, 
            "scan_name": scan_name, 
            "target": target,
            "results_dir": None
        })

@app.get("/cascading-clear-scan")
def cascading_clear_scan():
    """Clear scan state for cascading scanner"""
    global current_scan_name, current_target, current_results_dir, output_queue, current_process, output_thread, zap_done
    print("=== CLEARING CASCADING SCAN STATE ===")
    
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
    
    print("=== CASCADING SCAN STATE CLEARED ===")
    return {"status": "cleared", "message": "All cascading scan state cleared and cleaned up"}

@app.get("/cascading-reset")
def cascading_reset():
    """Reset scan state for cascading scanner"""
    global current_scan_name, current_target, current_results_dir, zap_done
    print("=== RESETTING CASCADING SCAN STATE ===")
    
    # Release any locks
    if scan_in_progress.locked():
        print("Releasing scan lock")
        scan_in_progress.release()
    
    # Reset all global variables
    current_scan_name = None
    current_target = None
    current_results_dir = None
    zap_done = False
    
    print("=== CASCADING SCAN STATE RESET ===")
    return {"status": "reset"}

# Mobile App Scanner Routes (completely independent from cascading scanner)

# Global state for mobile scanner (separate from cascading)
mobile_scan_in_progress = threading.Lock()
mobile_current_scan_name = None
mobile_current_scanner = None
mobile_current_target = None

def safe_mobile_scan_name(scanner, target):
    name = f"{scanner}-{target}"
    name = name.lower()
    name = re.sub(r'[^a-z0-9.]', '-', name)
    name = name.strip('-')
    name = re.sub(r'-+', '-', name)
    # Always append a timestamp for uniqueness
    name = f"{name}-{int(time.time())}"
    return name

@app.get("/mobile")
def mobile_index(request: Request):
    """Mobile App Scanner tab - completely independent from cascading scanner"""
    global mobile_current_scan_name, mobile_current_scanner, mobile_current_target
    
    # Always set scan_in_progress to False unless a scan is running
    in_progress = mobile_scan_in_progress.locked() and mobile_current_scan_name is not None
    
    # If there's no active scan but we have old state, clear it
    if not in_progress and (mobile_current_scan_name is not None or mobile_current_target is not None):
        print("Clearing stale mobile scan state on page load")
        mobile_current_scan_name = None
        mobile_current_scanner = None
        mobile_current_target = None
    
    return templates.TemplateResponse("mobile.html", {
        "request": request, 
        "scan_in_progress": in_progress, 
        "scan_name": mobile_current_scan_name, 
        "scanner": mobile_current_scanner,
        "target": mobile_current_target
    })

@app.post("/mobile-scan")
def mobile_scan(request: Request, scanner: str = Form(...), target: str = Form(...)):
    """Start a mobile app scan using individual scanners"""
    global mobile_current_scan_name, mobile_current_scanner, mobile_current_target
    print(f"Mobile scan requested: scanner={scanner}, target={target}")
    
    if mobile_scan_in_progress.locked():
        print("Mobile scan in progress, cannot start new scan.")
        return templates.TemplateResponse("mobile.html", {
            "request": request, 
            "error": "Mobile scan in progress. Please wait for current scan to complete.", 
            "scan_in_progress": True, 
            "scan_name": mobile_current_scan_name, 
            "scanner": mobile_current_scanner,
            "target": mobile_current_target
        })
    
    mobile_scan_in_progress.acquire()
    scan_name = safe_mobile_scan_name(scanner, target)
    print(f"Generated mobile scan name: {scan_name}")
    
    mobile_current_scan_name = scan_name
    mobile_current_scanner = scanner
    mobile_current_target = target
    
    # Create scan YAML based on scanner type
    if scanner == "mobsf":
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
        mobile_scan_in_progress.release()
        return templates.TemplateResponse("mobile.html", {
            "request": request, 
            "error": f"Unknown scanner: {scanner}", 
            "scan_in_progress": False
        })
    
    print(f"Mobile Scan YAML: {scan_yaml}")
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
        print("Mobile scan CRD created successfully.")
    except Exception as e:
        print(f"Failed to create mobile scan CRD: {e}")
        mobile_scan_in_progress.release()
        return templates.TemplateResponse("mobile.html", {
            "request": request, 
            "error": str(e), 
            "scan_in_progress": False
        })
    
    return templates.TemplateResponse("mobile.html", {
        "request": request, 
        "scan_started": True, 
        "scan_in_progress": True, 
        "scan_name": scan_name,
        "scanner": scanner,
        "target": target
    })

@app.get("/mobile-status")
def mobile_status():
    """Get mobile scan status"""
    if not mobile_current_scan_name:
        return {"status": "idle"}
    
    load_kube()
    k8s_api = client.CustomObjectsApi()
    try:
        scan = k8s_api.get_namespaced_custom_object(
            group="execution.securecodebox.io",
            version="v1",
            namespace=NAMESPACE,
            plural="scans",
            name=mobile_current_scan_name
        )
        print(f"Mobile scan status: {scan.get('status', {})}")
        if scan.get("status", {}).get("state") == "Done":
            mobile_scan_in_progress.release()
            return {"status": "done"}
        return {"status": "running"}
    except Exception as e:
        print(f"Error fetching mobile scan status: {e}")
        return {"status": "error", "error": str(e)}

@app.post("/mobile-download")
def mobile_download(request: Request, scan_name: str = Form(...)):
    """Download mobile scan results"""
    print(f"Mobile download requested for scan_name: {scan_name}")
    
    s3 = boto3.client("s3", endpoint_url=MINIO_ENDPOINT, aws_access_key_id=MINIO_ACCESS_KEY, aws_secret_access_key=MINIO_SECRET_KEY)
    scan_folder = f"scan-{scan_name}"
    findings_key = f"{scan_folder}/findings.json"
    
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
        # Use temporary file that will be automatically cleaned up
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_file:
            s3.download_file(MINIO_BUCKET, findings_key, tmp_file.name)
            print(f"Downloaded mobile findings to temporary file")
            
            return FileResponse(
                tmp_file.name, 
                filename=f"mobile-findings-{scan_name}.json",
                media_type='application/json'
            )
    except Exception as e:
        print(f"Could not download mobile findings: {e}")
        return templates.TemplateResponse("mobile.html", {
            "request": request, 
            "error": f"Could not download findings: {str(e)}", 
            "scan_in_progress": False
        })

@app.get("/mobile-reset")
def mobile_reset():
    """Reset mobile scan state"""
    if mobile_scan_in_progress.locked():
        mobile_scan_in_progress.release()
    global mobile_current_scan_name, mobile_current_scanner, mobile_current_target
    mobile_current_scan_name = None
    mobile_current_scanner = None
    mobile_current_target = None
    return {"status": "reset"} 
