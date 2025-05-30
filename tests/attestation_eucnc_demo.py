import base64
import hashlib
import hmac
import subprocess
import sys
import time
from datetime import datetime, timezone

from kubernetes import client, config
from kubernetes.client import ApiException


def compute_hmac(message: bytes, key: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def run_kubectl(args):
    try:
        result = subprocess.run(
            ["kubectl"] + args,
            check=True,
            capture_output=True,
            text=True
        )
        return result.stdout.replace("\"","")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"kubectl error: {e.stderr.strip()}")


attestation_secret_hmac_encoded = run_kubectl(["get", "secret", "attestation-secrets", "-n", "attestation-system", "-o", "jsonpath=\"{.data.attestation-secret-hmac}\""])
hmac_key = base64.b64decode(attestation_secret_hmac_encoded)
agent_ip = "192.168.0.122"


# kubectl get secret attestation-secrets -n attestation-system -o jsonpath="{.data.attestation-secret-hmac}"
# kubectl get pod pod-to-attest -n it6-ns -o jsonpath="{.status.phase}"
def pod_attestation(pod_name):
    # get attestation secret hmac key
    pod_status = run_kubectl(["get", "pod", pod_name, "-n", "it6-ns", "-o", "jsonpath=\"{.status.phase}\""])
    print(pod_status.replace("\"", ""))
    while pod_status != "Running":
        pod_status = run_kubectl(["get", "pod", pod_name, "-n", "it6-ns", "-o", "jsonpath=\"{.status.phase}\""])

    pod_uid = run_kubectl(["get", "pod", pod_name, "-n", "it6-ns", "-o", "jsonpath=\"{.metadata.uid}\""])
    node_name = run_kubectl(["get", "pod", pod_name, "-n", "it6-ns", "-o", "jsonpath=\"{.spec.nodeName}\""])
    agent_name = f"agent-{node_name}"

    integrity_message = f"{pod_name}::{pod_uid}::::{agent_name}::{agent_ip}".encode()
    attestation_request_hmac = base64.b64encode(compute_hmac(integrity_message, hmac_key)).decode()

    group = "attestation.com"
    version = "v1"
    namespace = "attestation-system"
    plural = "attestationrequests"  # Usually plural lowercase of Kind

    config.load_kube_config()
    api = client.CustomObjectsApi()

    body = {
        "apiVersion": f"{group}/{version}",
        "kind": "AttestationRequest",
        "metadata": {
            "name": f"attestation-request-{pod_name}",
            "namespace": namespace
        },
        "spec": {
            "agentIP": agent_ip,
            "agentName": agent_name,
            "hmac": attestation_request_hmac,
            "issued": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "podName": pod_name,
            "podUid": pod_uid,
            "tenantId": ""
        }
    }

    try:
        api_response = api.create_namespaced_custom_object(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            body=body,
        )
        print("Created AttestationRequest:")
        print(api_response)
    except ApiException as e:
        print(f"Exception when creating AttestationRequest: {e}")

while True:
    if len(sys.argv) != 2:
        print("usage: attestation.py <pod-name>")
        break
    pod_name = sys.argv[1]
    pod_attestation(pod_name)
    time.sleep(10)
