import json

import requests

# Base URL of the server
BASE_URL = "http://localhost:30002"

# Headers for requests
headers = {'Content-Type': 'application/json'}

# Test data for storing a worker whitelist
store_worker_data = {
    "osName": "Debian GNU/Linux 12 (bookworm)",
    "validDigests": {
        "sha1": [],
        "sha256": ["7b6436b0c98f62380866d9432c2af0ee08ce16a171bda6951aecd95ee1307d61"]
    }
}

store_container_runtime_data = {
    "containerRuntimeName": "/usr/bin/containerd-shim-runc-v2",
    "validFiles": [
        {
            "filePath": "/usr/bin/containerd-shim-runc-v2",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "ce9f5c5940530c40e47218af3405107b9acc0465b8c193492bd6a00db16991ad"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/loopback",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "8741d0235613101b826c3babc1805f029335a559f2c3b5fffaab7ba1b3ee39c5"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/calico",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "b7c7e7f6527ac62d10670f4f0d15ce394d06bd4ade4845200a18b0a76f6f6a43"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/portmap",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "8e7fe8a9452ea49581ea0892c2b22181931899c827eb78eb5fb6729108988693"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/bandwidth",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "4c5bc4957c9a62d4b545483773f39bed173b7e448a16ce61041283cae5be57a9"
                ]
            }
        },
        {
            "filePath": "/usr/bin/unpigz",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "ffdb0ad613a9d22b02816d1c67765f611c90fa98047b83917abe2c4677d0f4b3"
                ]
            }
        }


    ]
}


# Test data for checking a worker whitelist
check_worker_data = {
    "osName": "Debian GNU/Linux 12 (bookworm)",
    "bootAggregate": "7b6436b0c98f62380866d9432c2af0ee08ce16a171bda6951aecd95ee1307d61",
    "hashalg": "sha256"
}

# Test data for appending new OS to the worker whitelist
worker_data_to_append = {
    "osName": "Debian GNU/Linux 12 (bookworm)",
    "validDigests": {
        "sha1": [],
        "sha256": ["6341e6b2646a79a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af2"]
    }
}

store_pod_data = {
    "imageName": "redis:7.4-alpine3.21",
    "imageDigest": "docker.io/library/redis@sha256:86c23b252bbdaa1a867e0e360480de1aaea96e6ab3b1e69743c626c07a2a0c17",
    "validFiles": [
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libm.so.6",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "958fd4988943ab6713d04d4c7de8e468e358c5671db2acf9a7b025b465d10910"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "0122e231f5a44c94d889f9ae6cafc8a3825f03587304e79041af21eeeadeeb5a"
                ]
            }
        },
        {
            "filePath": "/usr/local/bin/redis-server",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "7c1c35fe5f10c2dbab7a7312aab89baf30e309831decd9e26ec1422a5a030394"
                ]
            }
        },
        {
            "filePath": "/usr/lib/libssl.so.3",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "7adbac939206d75eef63e9017d32f88e2e33503cc024a2c9b62e5dafcfbc3cb2"
                ]
            }
        },
        {
            "filePath": "/usr/lib/libcrypto.so.3",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "21e33937ed7a12f965ad423a722251783df2506539873dbd49f94933a2cf1c31"
                ]
            }
        },
        {
            "filePath": "/usr/local/bin/redis-server",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "0b8fc686aa06ef967eabf5641cbf405573f04f7bec8abd8415c203df9ead1211"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "666bb96697d92290e2172a8403040f9e3ebdd06aa4d4769080649c92201a9aad"
                ]
            }
        },
        {
            "filePath": "/pause",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "11ef55f97205c88f7e1f680ce02eb581534d2ef654b823089ac258db56ca04d2"
                ]
            }
        },
        {
            "filePath": "/lib/ld-musl-x86_64.so.1",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "42a4d78387ad7ddbf75a1906d1540f43be782456fe7b8eec0efc9bd7d8101345"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "7288c75488697bad29619f7ad123b8e467744f500369689d97de13197d282e87"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "93b58397fb163b27e33bd4c4093ce0d9556f45913560ed32676bdfeafb57155e"
                ]
            }
        }

    ]
}

test_custom_pod_data = {
    "imageName": "franczar/app-to-attest:latest",
    "imageDigest": "docker.io/franczar/app-to-attest@sha256:277537fef9604983cad6ddba0845ee5d708738a7d4cb5892d696f408ce90dfcb",
    "validFiles": [
        {
            "filePath": "/bin/busybox",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "a3905f456410f615a54e2ad9664c9d2b9afc3fb9839c154e7ccd2a94ca86d128"
                ]
            }
        },
        {
            "filePath": "/lib/ld-musl-x86_64.so.1",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "42a4d78387ad7ddbf75a1906d1540f43be782456fe7b8eec0efc9bd7d8101345"
                ]
            }
        },
        {
            "filePath": "/pause",
            "validDigests": {
                "sha1": [],
                "sha256": [
                    "11ef55f97205c88f7e1f680ce02eb581534d2ef654b823089ac258db56ca04d2"
                ]
            }
        }
    ],
    "hashAlg": "SHA256"
}




# Test data for checking a pod whitelist
check_pod_data = {
    "podImageName": "nginx:1.21",
    "podFiles": [
        {
            "filePath": "/bin/sh",
            "fileHash": "c157a79031e1c40f85931829bc5fc552"
        },
        {
            "filePath": "/bin/kmod",
            "fileHash": "b157a79031e1c40f85931829bc5fc452"
        }
    ],
    "hashalg": "sha256"
}

def append_container_runtime_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/container/runtime/add", headers=headers, data=json.dumps(store_container_runtime_data))
    print("Add Container Runtime Response:", response.status_code, response.json())

# Test function for adding a worker whitelist
def append_worker_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/worker/os/add", headers=headers, data=json.dumps(store_worker_data))
    print("Add Worker Whitelist Response:", response.status_code, response.json())

# Test function for checking a worker whitelist
def check_worker_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/worker/os/check", headers=headers, data=json.dumps(check_worker_data))
    print("Check Worker Whitelist Response:", response.status_code, response.json())

# Test function for adding a pod whitelist
def append_pod_whitelist(store_pod_data):
    response = requests.post(f"{BASE_URL}/whitelist/pod/image/add", headers=headers, data=json.dumps(store_pod_data))
    print("Add Pod Whitelist Response:", response.status_code, response.json())

# Test function for checking a pod whitelist
def check_pod_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/pod/check", headers=headers, data=json.dumps(check_pod_data))
    print("Check Pod Whitelist Response:", response.status_code, response.json())

# Test function for deleting a file from pod whitelist
def delete_os_from_worker_whitelist(osName):
    # The image name and file path are passed as query parameters
    response = requests.delete(f"{BASE_URL}/whitelist/worker/delete", headers=headers, params={"osName": osName})
    print("Delete Os from Worker Whitelist Response:", response.status_code, response.text)

# Test function for deleting a file from pod whitelist
def delete_file_from_pod_whitelist(image_name, file_path):
    # The image name and file path are passed as query parameters
    response = requests.delete(f"{BASE_URL}/whitelist/pod/image/file/delete", headers=headers, params={"filePath": "/bin/kmod", "imageName": image_name})
    print("Delete File from Pod Whitelist Response:", response.status_code, response.text)


# Running the tests
if __name__ == "__main__":
    append_container_runtime_whitelist()
    append_worker_whitelist()      # Test adding worker whitelist
    #check_worker_whitelist()    # Test checking worker whitelist
    #delete_os_from_worker_whitelist("Ubuntu 22.04.6 LTS")
    #append_worker_whitelist()   # Test appending new OS to worker whitelist
    append_pod_whitelist(store_pod_data)         # Test adding pod whitelist
    append_pod_whitelist(test_custom_pod_data)
    #check_pod_whitelist()       # Test checking pod whitelist
    #delete_file_from_pod_whitelist("nginx:1.21", "/bin/sh")  # Test deleting a file from pod whitelist
