#!/bin/bash
set -e

TAG=${1:-latest}
IMAGE="franczar/k8s-attestation-verifier"

cd "$(dirname "$0")/../.."

docker build -t "${IMAGE}:${TAG}" -f cmd/verifier/Dockerfile .
docker push "${IMAGE}:${TAG}"

echo "✅ Successfully built and pushed ${IMAGE}:${TAG}"
