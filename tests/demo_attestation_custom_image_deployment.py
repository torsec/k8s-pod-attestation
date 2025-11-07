import base64
import json
import random
import subprocess
import sys
import time

import requests
import rsa

# --- API endpoints ---
REGISTRAR_BASE_URL = 'http://localhost:30000'  # Pod registrar (tenant management)
POD_HANDLER_BASE_URL = 'http://localhost:30001'  # Pod handler
CREATE_TENANT_URL = f'{REGISTRAR_BASE_URL}/tenant/create'
VERIFY_SIGNATURE_URL = f'{REGISTRAR_BASE_URL}/tenant/verify'
POD_DEPLOYMENT_URL = f'{POD_HANDLER_BASE_URL}/resource/deploy'
POD_ATTEST_URL = f'{POD_HANDLER_BASE_URL}/pod/attest'

# --- RSA key generation (demo only) ---
public_key, private_key = rsa.newkeys(1024)

# --- PEM conversion ---
def public_key_to_pem(public_key):
    return public_key.save_pkcs1(format='PEM')

# --- Create tenant ---
def create_tenant(name, public_key):
    headers = {'Content-Type': 'application/json'}
    data = {
        'name': name,
        'publicKey': base64.b64encode(public_key_to_pem(public_key)).decode()
    }
    resp = requests.post(CREATE_TENANT_URL, headers=headers, data=json.dumps(data))
    if resp.status_code == 201:
        print(f"[+] Tenant '{name}' created")
    else:
        print(f"[!] Failed to create tenant: {resp.status_code} -> {resp.text}")

# --- Sign message ---
def sign_message(message: str) -> str:
    sig = rsa.sign(message.encode(), private_key, 'SHA-256')
    return base64.b64encode(sig).decode()

# --- Verify signature and deploy ---
def verify_and_deploy(name, manifest, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'resourceKind': 'Deployment',
        'manifest': manifest,
        'signature': {
            "rawSignature": signature,
            "hashAlg": 5  # SHA-256
        }
    }

    resp = requests.post(POD_DEPLOYMENT_URL, headers=headers, data=json.dumps(data))
    if resp.status_code == 200:
        print(f"[+] Deployment manifest verified for tenant '{name}'")
        return True
    else:
        print(f"[!] Verification failed: {resp.status_code} -> {resp.text}")
        return False

# --- Attest pod ---
def pod_attestation(name, pod_name, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'podName': pod_name,
        'signature': {
            "rawSignature": signature,
            "hashAlg": 5
        }
    }

    print(f'[*] Sending attestation for pod: {pod_name}')
    response = requests.post(POD_ATTEST_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        print(f'[+] Pod attestation request sent for "{pod_name}"')
    else:
        print(f'[!] Pod attestation failed: {response.status_code} -> {response.text}')

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

# --- Main execution ---
if __name__ == "__main__":
    tenant_name = f"Tenant-{random.randint(0, 999)}"
    create_tenant(tenant_name, public_key)

    pods_to_attest = []
    n_deployments = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    for i in range(n_deployments):
        deployment_name = f"deployment-{random.randint(0, 999999)}"
        manifest = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {deployment_name}
  namespace: it6-ns
spec:
  replicas: 2
  selector:
    matchLabels:
      app: demo-app
  template:
    metadata:
      labels:
        app: demo-app
    spec:
      containers:
      - name: demo-container
        image: franczar/app-to-attest:latest
        command: ["sh", "-c", "echo Deployment running && sleep 3600"]
"""
        # Encode manifest to base64
        encoded_manifest = base64.b64encode(manifest.encode()).decode()

        # Sign manifest
        signature = sign_message(manifest)

        # Send for verification/deployment
        if verify_and_deploy(tenant_name, encoded_manifest, signature):
            out = run_kubectl(["get", "pods", "-n", "it6-ns", "-l", "app=demo-app", "-o", "name"])
            pod_names = out.split("\n")
            for p in pod_names:
                pod_name = p.replace("pod/", "")
                pods_to_attest.append(pod_name)

    for i in range(3):
        time.sleep(20)
        # Perform pod attestation
        for pod_name in pods_to_attest:
            signature = sign_message(pod_name)
            pod_attestation(tenant_name, pod_name, signature)

