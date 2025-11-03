#!/bin/bash
set -e

TAG=${1:-latest}
IMAGE="franczar/k8s-attestation-agent"

# Go to project root (two levels up from script dir)
cd "$(dirname "$0")/../.."

# Build the image using the Dockerfile in cmd/agent
docker build -t "${IMAGE}:${TAG}" -f cmd/agent/Dockerfile .

# Push to Docker Hub
docker push "${IMAGE}:${TAG}"

echo "✅ Successfully built and pushed ${IMAGE}:${TAG}"
