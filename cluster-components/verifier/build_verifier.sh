#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-verifier:"$tag" .
docker tag franczar/k8s-attestation-verifier:"$tag" franczar/k8s-attestation-verifier:"$tag"
docker push franczar/k8s-attestation-verifier:"$tag"