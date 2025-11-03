#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-agent:"$tag" .
docker tag franczar/k8s-attestation-agent:"$tag" franczar/k8s-attestation-agent:"$tag"
docker push franczar/k8s-attestation-agent:"$tag"
