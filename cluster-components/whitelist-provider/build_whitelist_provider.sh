#!/bin/bash
tag=${1:-latest}

docker build -t franczar/k8s-attestation-whitelist-provider:"$tag" .
docker tag franczar/k8s-attestation-whitelist-provider:"$tag" franczar/k8s-attestation-whitelist-provider:"$tag"
docker push franczar/k8s-attestation-whitelist-provider:"$tag"