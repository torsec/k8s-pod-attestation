#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-pod-watcher:"$tag" .
docker tag franczar/k8s-attestation-pod-watcher:"$tag" franczar/k8s-attestation-pod-watcher:"$tag"
docker push franczar/k8s-attestation-pod-watcher:"$tag"