#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-pod-handler:"$tag" .
docker tag franczar/k8s-attestation-pod-handler:"$tag" franczar/k8s-attestation-pod-handler:"$tag"
docker push franczar/k8s-attestation-pod-handler:"$tag"