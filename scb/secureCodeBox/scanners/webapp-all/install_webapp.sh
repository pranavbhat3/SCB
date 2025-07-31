#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SecureCodeBox WebApp Installation Script ===${NC}"
echo "This script will set up the virtual environment and install all dependencies."
echo ""

# Check if we're in the right directory
if [ ! -f "main_patched.py" ]; then
    echo -e "${RED}Error: main_patched.py not found. Please run this script from the webapp-all directory.${NC}"
    exit 1
fi

# Check if Python3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python3 is not installed. Please install Python3 first.${NC}"
    exit 1
fi

# Check if python3-venv is available
if ! python3 -c "import venv" 2>/dev/null; then
    echo -e "${YELLOW}Warning: python3-venv not found. Installing...${NC}"
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y python3-venv python3-full
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3-venv
    else
        echo -e "${RED}Error: Could not install python3-venv. Please install it manually.${NC}"
        exit 1
    fi
fi

# Remove existing virtual environment if it exists
if [ -d "venv" ]; then
    echo -e "${YELLOW}Removing existing virtual environment...${NC}"
    rm -rf venv
fi

# Create new virtual environment
echo -e "${GREEN}Creating new virtual environment...${NC}"
python3 -m venv venv

# Activate virtual environment
echo -e "${GREEN}Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "${GREEN}Upgrading pip...${NC}"
./venv/bin/python3 -m pip install --upgrade pip

# Install requirements
echo -e "${GREEN}Installing Python dependencies...${NC}"
./venv/bin/pip install -r requirements.txt

# Test installation
echo -e "${GREEN}Testing installation...${NC}"
./venv/bin/python3 -c "import fastapi, uvicorn, jinja2, boto3, kubernetes; print('All packages installed successfully!')"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}=== Installation completed successfully! ===${NC}"
    echo ""
    echo -e "${GREEN}To start the webapp, run:${NC}"
    echo -e "${YELLOW}./start_webapp_with_minio.sh${NC}"
    echo ""
    echo -e "${GREEN}Or manually:${NC}"
    echo -e "${YELLOW}source venv/bin/activate${NC}"
    echo -e "${YELLOW}uvicorn main_patched:app --host 0.0.0.0 --port 8000 --reload${NC}"
else
    echo -e "${RED}Installation failed. Please check the error messages above.${NC}"
    exit 1
fi 