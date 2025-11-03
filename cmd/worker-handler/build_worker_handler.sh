#!/bin/bash
set -e

TAG=${1:-latest}
IMAGE="franczar/k8s-attestation-worker-handler"

cd "$(dirname "$0")/../.."

docker build -t "${IMAGE}:${TAG}" -f cmd/worker-handler/Dockerfile .
docker push "${IMAGE}:${TAG}"

echo "✅ Successfully built and pushed ${IMAGE}:${TAG}"
