import os
import sys
import requests
import boto3

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "admin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "password")
INPUT_BUCKET = os.environ.get("INPUT_BUCKET", "securecodebox")
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET", "securecodebox")
# Prefer SCB_SCAN_PARAM_0, then sys.argv[1], then env var, then default
APK_OBJECT = os.environ.get("SCB_SCAN_PARAM_0") or (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("APK_OBJECT", "InsecureBankv2_2.apk"))
MOBSF_URL = os.environ.get("MOBSF_URL", "http://mobsf:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "my_mobsf_key")

print(f"Using APK_OBJECT: {APK_OBJECT}")

# Determine file extension and MIME type
if APK_OBJECT.lower().endswith(".apk"):
    mime_type = "application/vnd.android.package-archive"
elif APK_OBJECT.lower().endswith(".ipa"):
    mime_type = "application/octet-stream"
else:
    mime_type = "application/octet-stream"

# Use the original filename for local storage
local_file = f"/tmp/{os.path.basename(APK_OBJECT)}"

def download_apk():
    s3 = boto3.client(
        "s3",
        endpoint_url=f"{MINIO_ENDPOINT}",
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
    )
    s3.download_file(INPUT_BUCKET, APK_OBJECT, local_file)

def scan_with_mobsf():
    headers = {"Authorization": MOBSF_API_KEY}
    # Upload APK/IPA
    with open(local_file, "rb") as f:
        files = {"file": (os.path.basename(local_file), f, mime_type)}
        resp = requests.post(f"{MOBSF_URL}/api/v1/upload", files=files, headers=headers)
        resp.raise_for_status()
        scan_data = resp.json()
        scan_hash = scan_data["hash"]
    # Scan APK/IPA
    data = {"hash": scan_hash}
    resp = requests.post(f"{MOBSF_URL}/api/v1/scan", data=data, headers=headers)
    resp.raise_for_status()
    # Get report
    data = {"hash": scan_hash, "type": "json"}
    resp = requests.post(f"{MOBSF_URL}/api/v1/report_json", data=data, headers=headers)
    resp.raise_for_status()
    return resp.text

if __name__ == "__main__":
    download_apk()
    results = scan_with_mobsf()
    # Write results to the path expected by secureCodeBox
    os.makedirs("/home/securecodebox", exist_ok=True)
    with open("/home/securecodebox/result.json", "w") as f:
        f.write(results)
    print("Scan complete and results written to /home/securecodebox/result.json.")
