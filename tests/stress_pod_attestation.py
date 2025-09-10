import base64
import json
import random
import requests
import rsa
import sys
from datetime import datetime

# Define API endpoints
REGISTRAR_BASE_URL = 'http://localhost:30000' 
POD_HANDLER_BASE_URL = 'http://localhost:30001'
CREATE_TENANT_URL = f'{REGISTRAR_BASE_URL}/tenant/create'
VERIFY_SIGNATURE_URL = f'{REGISTRAR_BASE_URL}/tenant/verify'
POD_DEPLOYMENT_URL = f'{POD_HANDLER_BASE_URL}/pod/deploy'
POD_ATTEST_URL = f'{POD_HANDLER_BASE_URL}/pod/attest'

# Generate RSA keys (for demonstration purposes)
(public_key, private_key) = rsa.newkeys(1024)


# Convert the public key to PEM format
def public_key_to_pem(public_key):
    pem_key = public_key.save_pkcs1(format='PEM')
    return pem_key.decode()


def create_tenant(name, public_key):
    headers = {'Content-Type': 'application/json'}
    data = {
        'name': name,
        'publicKey': public_key_to_pem(public_key)  # Pass public key in PEM format
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
        'manifest': message,  # Send the entire YAML content as the message
        'signature': signature
    }
    response = requests.post(POD_DEPLOYMENT_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print('Signature verification successful')
        return True
    else:
        print('Signature verification failed:', response.text)
        return False

def pod_attestation(name, podName, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'podName': podName,  # Send the entire YAML content as the message
        'signature': signature
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
  name: pod-to-attest
  namespace: it6-ns
spec:
  nodeName: worker
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

# Step 2: Measure only attestation time
start_time = datetime.now()
print(f"start: {start_time.strftime('%H:%M:%S.%f')[:-3]}")

for i, pod_name in enumerate(pods_to_attest):
    pod_attestation(tenant_name, pod_name, signatures[i])

end_time = datetime.now()
print(f"end: {end_time.strftime('%H:%M:%S.%f')[:-3]}")

elapsed = (end_time - start_time).total_seconds()
print(f"Total attestation time for {len(pods_to_attest)} pods: {elapsed:.3f} seconds")
print(f"Average per pod: {elapsed/len(pods_to_attest):.3f} seconds")