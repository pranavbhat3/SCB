#!/bin/bash

# Exit on error
set -e

# Function to check if MinIO is reachable
function wait_for_minio() {
  echo "Waiting for MinIO to be available at localhost:9000..."
  until curl -s http://localhost:9000/minio/health/ready > /dev/null; do
    sleep 1
done
  echo "MinIO is up!"
}

# Start MinIO port-forward if not already running
if ! lsof -i:9000 | grep -q LISTEN; then
  echo "Starting MinIO port-forward..."
  nohup kubectl port-forward svc/minio -n default 9000:9000 > minio-port-forward.log 2>&1 &
  sleep 2
else
  echo "MinIO port-forward already running."
fi

wait_for_minio

# Activate venv and start FastAPI backend using patched main_patched.py
source venv/bin/activate
uvicorn main_patched:app --host 0.0.0.0 --port 8000 --reload 