import base64
import json
import random
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


# Convert the public key to PEM format (bytes)
def public_key_to_pem(public_key):
    return public_key.save_pkcs1(format='PEM')


# --- Tenant creation ---
def create_tenant(name, public_key):
    headers = {'Content-Type': 'application/json'}
    data = {
        'name': name,
        'publicKey': base64.b64encode(public_key_to_pem(public_key)).decode()  # send PEM as base64
    }
    response = requests.post(CREATE_TENANT_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        print(f'[+] Tenant "{name}" created successfully')
    else:
        print(f'[!] Error creating tenant: {response.status_code} -> {response.text}')


# --- Sign message ---
def sign_message(message: str) -> str:
    signature = rsa.sign(message.encode(), private_key, 'SHA-256')
    return base64.b64encode(signature).decode()


# --- Verify signature / deploy pod ---
def verify_signature(name, message, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'resourceKind': 'Pod',
        'manifest': message,  # base64 YAML content
        'signature': {
            "rawSignature": signature,
            "hashAlg": 5  # 5 → SHA-256
        }
    }

    response = requests.post(POD_DEPLOYMENT_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print(f'[+] Pod manifest verified for tenant "{name}"')
        return True
    else:
        print(f'[!] Verification failed: {response.status_code} -> {response.text}')
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


# --- Main execution ---
if __name__ == "__main__":
    tenant_name = f'Tenant-{random.randint(0, 500)}'
    create_tenant(tenant_name, public_key)

    pods_to_attest = []
    n_pods = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    for i in range(n_pods):
        pod_name = f'pod-{random.randint(0, 2_000_000)}'

        manifest = f'''
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: it6-ns
spec:
  containers:
  - name: alpine-container
    image: franczar/app-to-attest:latest
    command: ["sh", "-c", "echo Hello Kubernetes! && sleep 3600"]
'''
        # Encode manifest for sending
        encoded_manifest = base64.b64encode(manifest.encode()).decode()

        # Sign manifest
        signature = sign_message(manifest)

        # Verify and collect pod for attestation
        if verify_signature(tenant_name, encoded_manifest, signature):
            pods_to_attest.append(pod_name)

    # Wait for pods to be deployed
    time.sleep(20)

    # Perform pod attestation
    for pod_name in pods_to_attest:
        signature = sign_message(pod_name)
        encoded_name = base64.b64encode(pod_name.encode()).decode()
        pod_attestation(tenant_name, encoded_name, signature)
