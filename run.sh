#!/bin/bash
set -e;

# Navigate to the directory of the script
cd "$(dirname "$0")"

# Build the Docker image
docker build -t X_runner .

# Run the container
docker run -t --rm X_runner