import base64
import hashlib
import hmac
import subprocess
import time


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
        return result.stdout
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

    while pod_status != "Running":
        pod_status = run_kubectl(["get", "pod", pod_name, "-n", "it6-ns", "-o", "jsonpath=\"{.status.phase}\""])

    pod_uid = run_kubectl(["get", "pod", pod_name, "-n", "it6-ns", "-o", "jsonpath=\"{.metadata.uid}\""])
    node_name = run_kubectl(["get", "pod", pod_name, "-n", "it6-ns", "-o", "jsonpath=\"{.spec.nodeName}\""])
    agent_name = f"agent-{node_name}"

    integrity_message = f"{pod_name}::{pod_uid}::::{agent_name}::{agent_ip}".encode()
    attestation_request_hmac = base64.b64encode(compute_hmac(integrity_message, hmac_key))






while True:
    pod_attestation()
    time.sleep(10)