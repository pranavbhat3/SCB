#!/bin/bash

# Simple webapp startup script
echo "=== Starting SecureCodeBox WebApp ==="

# Check if we're in the right directory
if [ ! -f "main_patched.py" ]; then
    echo "Error: main_patched.py not found. Please run from webapp-all directory."
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run ./install_webapp.sh first."
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Start the webapp
echo "Starting webapp on http://0.0.0.0:8000"
echo "Press Ctrl+C to stop"
uvicorn main_patched:app --host 0.0.0.0 --port 8000 --reload 