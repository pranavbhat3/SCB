#!/bin/bash
# Usage: ./run_nuclei_scbctl.sh <target-url>
# Example: ./run_nuclei_scbctl.sh http://example.com

if [ -z "$1" ]; then
  echo "Usage: $0 <target-url>"
  exit 1
fi

target="$1"

scbctl scan nuclei -- -u "$target" 