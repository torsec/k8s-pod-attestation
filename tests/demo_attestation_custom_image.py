import base64
import json
import random
import sys

import requests
import rsa

# Define API endpoints
REGISTRAR_BASE_URL = 'http://localhost:30000'  # Ensure this matches your pod-handler URL
POD_HANDLER_BASE_URL = 'http://localhost:30001'
CREATE_TENANT_URL = f'{REGISTRAR_BASE_URL}/tenant/create'
VERIFY_SIGNATURE_URL = f'{REGISTRAR_BASE_URL}/tenant/verify'
POD_DEPLOYMENT_URL = f'{POD_HANDLER_BASE_URL}/resource/deploy'
POD_ATTEST_URL = f'{POD_HANDLER_BASE_URL}/pod/attest'

# Generate RSA keys (for demonstration purposes)
(public_key, private_key) = rsa.newkeys(1024)


# Convert the public key to PEM format
def public_key_to_pem(public_key):
    pem_key = public_key.save_pkcs1(format='PEM')
    return pem_key


def create_tenant(name, public_key):
    headers = {'Content-Type': 'application/json'}
    data = {
        'name': name,
        'publicKey': base64.b64encode(public_key_to_pem(public_key)).decode()  # Pass public key in PEM format
    }
    response = requests.post(CREATE_TENANT_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        print('Tenant created successfully')
    else:
        print('Error creating tenant:', response.text)


def sign_message(message):
    # Hash and sign the message
    signature = rsa.sign(message.encode(), private_key, 'SHA-256')
    return base64.b64encode(signature).decode()


def verify_signature(name, message, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'resourceKind': 'Pod',
        'manifest': message,  # Send the entire YAML content as the message
        'signature': {
            "rawSignature": signature,
            "hashAlg": 5 # sha256
        }
    }
    response = requests.post(POD_DEPLOYMENT_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print('Signature verification successful')
    else:
        print('Signature verification failed:', response.text)


def pod_attestation(name, podName, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'podName': podName,  # Send the entire YAML content as the message
        'signature':  {
            "rawSignature": signature,
            "hashAlg": 5 # sha256
        }
    }
    print(data)
    response = requests.post(POD_ATTEST_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        print('Pod attestation request sent')
    else:
        print('Pod attestation request failed:', response.text)


# Usage
tenant_name = f'Tenant-{random.randint(0, 500)}'
# Create a new tenant with the public key in PEM format
create_tenant(tenant_name, public_key)

pods_to_attest = []
n_pods = int(sys.argv[1]) if len(sys.argv) > 1 else 1

for i in range(0, n_pods):
    # Usage
    pod_name = f'pod-{random.randint(0, 2000000)}'

    message = f'''
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
    to_sign = message

    # Sign the YAML content (message)
    signature = sign_message(to_sign)

    # Verify the signature
    if verify_signature(tenant_name, to_sign, signature):
        pods_to_attest.append(pod_name)

signatures = []
for pod_name in pods_to_attest:
    signature = sign_message(pod_name)   # or sign_message(to_sign) if you want to sign the YAML
    signatures.append(signature)

for i, pod_name in enumerate(pods_to_attest):
    pod_attestation(tenant_name, pod_name, signatures[i])