import requests
from web3 import Web3
from eth_account.messages import encode_defunct

# CONFIG
ADDR = "0x0FFDA72cD3b8bC602d5E59ddc2972387eBa30eBE"
KEY = "0x5b9150120869e5f5a1e6620552f776c0cb2e88d8bb57ec6e07035269657d3d53"

API = "http://127.0.0.1:5000"


# Get challenge
r = requests.post(API + "/challenge", json={
    "address": ADDR
})

challenge = r.json()["challenge"]

print("[+] Challenge:", challenge)


# Sign
w3 = Web3()

msg = encode_defunct(text=challenge)

signed = w3.eth.account.sign_message(msg, private_key=KEY)

sig = signed.signature.hex()

print("[+] Signature:", sig)


# Verify
r = requests.post(API + "/verify", json={
    "address": ADDR,
    "signature": sig
})

print("[+] Verify:", r.text)


# Store
headers = {
    "X-ADDR": ADDR
}

r = requests.post(API + "/store",
    json={"data": "REK_AUTH_TEST"},
    headers=headers
)

print("[+] Store:", r.text)


# Read
r = requests.get(API + "/read", headers=headers)

print("[+] Read:", r.text)
