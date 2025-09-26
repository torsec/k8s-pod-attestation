#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-worker-handler:"$tag" .
docker tag franczar/k8s-attestation-worker-handler:"$tag" franczar/k8s-attestation-worker-handler:"$tag"
docker push franczar/k8s-attestation-worker-handler:"$tag"