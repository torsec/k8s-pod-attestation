#!/bin/bash
set -e

TAG=${1:-latest}
IMAGE="franczar/k8s-attestation-pod-watcher"

cd "$(dirname "$0")/../.."

docker build -t "${IMAGE}:${TAG}" -f cmd/pod-watcher/Dockerfile .
docker push "${IMAGE}:${TAG}"

echo "✅ Successfully built and pushed ${IMAGE}:${TAG}"
