#!/bin/bash
set -e

TAG=${1:-latest}
IMAGE="franczar/k8s-attestation-whitelist-provider"

cd "$(dirname "$0")/../.."

docker build -t "${IMAGE}:${TAG}" -f cmd/whitelist-provider/Dockerfile .
docker push "${IMAGE}:${TAG}"

echo "✅ Successfully built and pushed ${IMAGE}:${TAG}"
