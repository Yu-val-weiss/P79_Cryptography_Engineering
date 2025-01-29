#!/bin/bash
set -e;

# Navigate to the directory of the script
cd "$(dirname "$0")"

# Build the Docker image
docker build -t lab0_runner .

# Run the container
docker run --rm lab0_runner