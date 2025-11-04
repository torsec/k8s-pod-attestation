import json

import requests

# Base URL of the server
BASE_URL = "http://localhost:30002"

# Headers for requests
headers = {'Content-Type': 'application/json'}

# Test data for storing a worker whitelist
store_worker_data = {
    "name": "Debian GNU/Linux 12 (bookworm)",
    "validDigests": {
        3: [],
        5: ["7b6436b0c98f62380866d9432c2af0ee08ce16a171bda6951aecd95ee1307d61"]
    }
}

store_container_runtime_data = {
    "name": "containerd",
    "validFiles": [
        {
            "filePath": "/usr/bin/containerd-shim-runc-v2",
            "validDigests": {
                3: [],
                5: [
                    "74cc9274df40f375864dfd0e3fc3d6d3b898faec7abb4b82218ca3c3c43e75e6"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/loopback",
            "validDigests": {
                3: [],
                5: [
                    "8741d0235613101b826c3babc1805f029335a559f2c3b5fffaab7ba1b3ee39c5"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/calico",
            "validDigests": {
                3: [],
                5: [
                    "b7c7e7f6527ac62d10670f4f0d15ce394d06bd4ade4845200a18b0a76f6f6a43"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/portmap",
            "validDigests": {
                3: [],
                5: [
                    "8e7fe8a9452ea49581ea0892c2b22181931899c827eb78eb5fb6729108988693"
                ]
            }
        },
        {
            "filePath": "/opt/cni/bin/bandwidth",
            "validDigests": {
                3: [],
                5: [
                    "4c5bc4957c9a62d4b545483773f39bed173b7e448a16ce61041283cae5be57a9"
                ]
            }
        },
    ]
}


# Test data for checking a worker whitelist
check_worker_data = {
    "osName": "Debian GNU/Linux 12 (bookworm)",
    "bootAggregate": "7b6436b0c98f62380866d9432c2af0ee08ce16a171bda6951aecd95ee1307d61",
    "hashalg": 5
}

# Test data for appending new OS to the worker whitelist
worker_data_to_append = {
    "name": "Debian GNU/Linux 12 (bookworm)",
    "validDigests": {
        3: [],
        5: ["6341e6b2646a79a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af2"]
    }
}

store_pod_data = {
    "name": "docker.io/library/grayscaler:offline",
    "digest": "sha256:f88d4dc06dcfeb1951730be5ff37a893806632ff64c9645ef22ada5e6199a2de",
    "validFiles": [
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_datetime.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "f575124dba01c1558c09294decada46b17fe21d86c4dac19a25ce1296644df8b"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/pillow.libs/libopenjp2-56811f71.so.2.5.3",
            "validDigests": {
                3: [],
                5: [
                    "686f62cbed321379e3e38be7ae94c56411d4345bde8d54e557b40472d9a7693a"
                ]
            }
        },
        {
            "filePath": "/usr/local/bin/python3.11",
            "validDigests": {
                3: [],
                5: [
                    "22e747b1e8a04719d4af2094133a0479b33728d2e4d03ab01539064dc6f45cfb"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/PIL/_imaging.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "d7ab038165923c2978232d2c8264ca4ce8c27fca77c2044a62c4c34f6552f4c7"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_contextvars.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "55ba81c458e959b5b8bd1c04786b1b8f6bd729a74cb679e6bc77b672c4160642"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_asyncio.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "3e5930c17c661f6cea3082f4893b3e185580619b1bb3b61b0382a63af2eb341b"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_json.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "327a49ffb47c00e76ff717201c5c44c53bb128b79200696e0536e819270dc087"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_sha512.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "f57f49958e4512cabad82bce2f2a2ecfdbe71794260ef205087c49423556257e"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/pillow.libs/libxcb-55eab65a.so.1.1.0",
            "validDigests": {
                3: [],
                5: [
                    "2b1150ac9cba5177560b0c3858c9647fbc5bbc9a964f44f51d24fae3db4117d2"
                ]
            }
        },
        {
            "filePath": "/pause",
            "validDigests": {
                3: [],
                5: [
                    "11ef55f97205c88f7e1f680ce02eb581534d2ef654b823089ac258db56ca04d2"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libz.so.1.2.13",
            "validDigests": {
                3: [],
                5: [
                    "7e2a72b4c4b38c61e6962de6e3f4a5e9ae692e732c68deead10a7ce2135a7f68"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_struct.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "d9ef1f3b0160698f84499bceb07d727256a02e2f49be7910f0a9be13a5805c14"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_lzma.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "7e3d94d4395d3fe2260437300bfa4489b1a4bbeed5e5c30543916cdad2624fc5"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
            "validDigests": {
                3: [],
                5: [
                    "df8e371a04bcf4ea2d455277ecc9cd47fc9b4c58ed27a7f4e6c8343122a4d270"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_csv.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "d1e1725ba481a601186c8adf1dce098296382b9b43f16dbc5e4bd3e2808fb129"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/pillow.libs/libtiff-5df1d27b.so.6.1.0",
            "validDigests": {
                3: [],
                5: [
                    "975acc7c170298489482adaaec4fbe4255455a4690505384cbd8efc22d13a88a"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/pydantic_core/_pydantic_core.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "47c6e9f5519f00b789121fb70c2b5ad202d8e438d294c1cffb983536f8610f68"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/pillow.libs/libjpeg-b82026ff.so.62.4.0",
            "validDigests": {
                3: [],
                5: [
                    "267551247c7d2c7cef4f20a0bc82dc7e9757b870789bd99f27a20a9d009c802f"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libm.so.6",
            "validDigests": {
                3: [],
                5: [
                    "067650d84b8f554cedf0b9ff26137bdd10cd03d4bbcdba1029a543c59d1798e5"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_opcode.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "4994d8aef3efa1e6120091615cb0317c41dd242589320209e5ada3e594f6abbd"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_decimal.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "6132e29e535d90390e77be7465eefa125757ec244e0a2c6a88aadb0908e2c053"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_uuid.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "6560893d36cd2f6969c9d4d7ef811f8118105ed6179ab6f888a97ce053fc7d84"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_hashlib.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "e3ae47f311302eba35aa615c6e03cc0d3b47b743e8a75649ce017626810449d2"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "validDigests": {
                3: [],
                5: [
                    "582f2d3d4edab86d601c54b37f04bd18fa2cda28be30e9f8c87df73c1c581354"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/fcntl.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "62d0a04919a7b0bd11d0352211eea63bed15e39bc82a4247421e5f6a53c47335"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_zoneinfo.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "d423593c7c5299133298839aef2489168f505e8e515a529bde1a0359a733b326"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/binascii.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "dfbc998e8bdb566bbc10d515878d4bb952e588006946ebd8b555ee9aa5ca9fda"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/zlib.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "ea1779a12064d8ecc8968e070f94187d4f705839666cdff255fd04b9ccfbc5a4"
                ]
            }
        },
        {
            "filePath": "/usr/local/bin/uvicorn",
            "validDigests": {
                3: [],
                5: [
                    "53cb7d976f4ff5dd89e15d5e5336aaf1cced23d27467e1e45db4e892f9f81316"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/select.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "7f5204526dea7b43bbe9b39a620a413a373784c99cfeee4ce7b9d88e1d12a444"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_bisect.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "d40afc91244ba2ec72acaf3199a32bdb8c1717d4bf3e7d01de70318db760f703"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/pillow.libs/libXau-154567c4.so.6.0.0",
            "validDigests": {
                3: [],
                5: [
                    "05484d24bf78cb8ed03169f1cb067204d829cb7af21de8820400d29d115e4320"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_socket.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "aa10d28b792575defe27d1f6109fd94d61c5146036276f987bb90390ac0b8b72"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/math.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "9e44bd78c59ab97bead76b8cfd38e8788986e457fd12068f5c6be1d5f896237c"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libbz2.so.1.0.4",
            "validDigests": {
                3: [],
                5: [
                    "e4f501c8bd22390e42422691093d8af4e744a3e854809b809948055e8b08bda5"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_multiprocessing.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "3948c1d0065cc78d3579a455e6a869dc535065997670ab6a78a21ca0ead90088"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_typing.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "be3ad3df8f9d2208b03571f702b0eb58ca1e7f9bf5a742210eea483213b75715"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_queue.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "670d8ac33587e5d8c9a02ff9cc8c4e431595f84ccb86f6b279d8ab865f311069"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_posixsubprocess.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "ee94da9608305089920ceee9fb3884b76abc82d5e07dbab70641f8de46aee696"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_pickle.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "b2c4501561bd253f8fd926e8f07be1c53c7926f8fd9e7aab5d0b7ec5416171fb"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/librt.so.1",
            "validDigests": {
                3: [],
                5: [
                    "6445c275f2477ebf619b1e4ec6fe5a0e460b9745e360ef9b671cb5a2f9f362ae"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "validDigests": {
                3: [],
                5: [
                    "1d25fd63234b59e4c581564c7a6d8f5c6cf36eee757e3d26f4b0808dd36a4896"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_heapq.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "50ce303e8b0e09142415bef21d40c253a7aad3b3dcebc2ebdb9473560d21a7d9"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_blake2.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "8a139104464b88c9ba54af0a17965c4e57e2f6c37be024003f3fed68e77c1c66"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/site-packages/pillow.libs/liblzma-64b7ab39.so.5.8.1",
            "validDigests": {
                3: [],
                5: [
                    "84dd81d913c433ac0e82f111fe0e377cd8db350fd2b2b7a75f6c2501f1d6fa70"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_random.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "416e5880725923a1a37c4d7789899662da8b766b9ece90d947c984e113742b15"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
            "validDigests": {
                3: [],
                5: [
                    "2bd1552c47799ef67e701e81d4383061fd76059868e446e63560f0dd0d5ec14e"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_bz2.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "51486f186eaa0f12ab5e0c033024cdd4e82b29aa30b58768496173e291d3ac9b"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "validDigests": {
                3: [],
                5: [
                    "4a764d83ab327f6ccb0f5269956dec4972b0104811ff968e1a1bf45355415e78"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "validDigests": {
                3: [],
                5: [
                    "f12d9946b6c7b1a21b9a1b0b4086a2220320210339e3b729b48cc8c397cdc110"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0",
            "validDigests": {
                3: [],
                5: [
                    "94176513740e4b8d24a68e6c37a43986b488f2910c9eaa34f69bd7ba8c49307d"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/array.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "642d6a8efecdb318c00227a78a611b0cfe1de9642b5e0efce7ccc2f169e609cd"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/python3.11/lib-dynload/_ssl.cpython-311-x86_64-linux-gnu.so",
            "validDigests": {
                3: [],
                5: [
                    "0ca5d899ef0a98fc76949dadcb0984261d2f5d9d3deaaafad52a1dd7405474bc"
                ]
            }
        },
        {
            "filePath": "/usr/local/lib/libpython3.11.so.1.0",
            "validDigests": {
                3: [],
                5: [
                    "6d674a4f706088a44780bddb5fbfe47485f5eabe8f2f9ff9563117a645833d75"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/liblzma.so.5.4.1",
            "validDigests": {
                3: [],
                5: [
                    "aaead752b2f290547267341891424f17244d86a95202c3f3a41cc75c77d76821"
                ]
            }
        }
    ]

}

test_custom_pod_data = {
    "name": "franczar/app-to-attest:latest",
    "digest": "docker.io/franczar/app-to-attest@sha256:277537fef9604983cad6ddba0845ee5d708738a7d4cb5892d696f408ce90dfcb",
    "validFiles": [
        {
            "filePath": "/bin/busybox",
            "validDigests": {
                3: [],
                5: [
                    "a3905f456410f615a54e2ad9664c9d2b9afc3fb9839c154e7ccd2a94ca86d128"
                ]
            }
        },
        {
            "filePath": "/lib/ld-musl-x86_64.so.1",
            "validDigests": {
                3: [],
                5: [
                    "42a4d78387ad7ddbf75a1906d1540f43be782456fe7b8eec0efc9bd7d8101345"
                ]
            }
        },
        {
            "filePath": "/pause",
            "validDigests": {
                3: [],
                5: [
                    "11ef55f97205c88f7e1f680ce02eb581534d2ef654b823089ac258db56ca04d2"
                ]
            }
        }
    ],
    "hashAlg": 5
}




# Test data for checking a pod whitelist
check_pod_data = {
    "imageName": "nginx:1.21",
    "files": [
        {
            "filePath": "/bin/sh",
            "fileHash": "c157a79031e1c40f85931829bc5fc552"
        },
        {
            "filePath": "/bin/kmod",
            "fileHash": "b157a79031e1c40f85931829bc5fc452"
        }
    ],
    "hashalg": 5
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
