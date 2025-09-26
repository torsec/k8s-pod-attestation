#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-registrar:"$tag" .
docker tag franczar/k8s-attestation-registrar:"$tag" franczar/k8s-attestation-registrar:"$tag"
docker push franczar/k8s-attestation-registrar:"$tag"
