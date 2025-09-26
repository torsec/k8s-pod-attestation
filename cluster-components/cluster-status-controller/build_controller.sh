#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-cluster-status-controller:"$tag" .
docker tag franczar/k8s-attestation-cluster-status-controller:"$tag" franczar/k8s-attestation-cluster-status-controller:"$tag"
docker push franczar/k8s-attestation-cluster-status-controller:"$tag"