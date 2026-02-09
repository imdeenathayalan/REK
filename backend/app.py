from web3 import Web3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import os

# ---------------- CONFIG ---------------- #

GANACHE_URL = "http://127.0.0.1:7545"

# Update if redeployed
VAULT_ADDRESS = "0xCcfd7bFA933C4E785294C73a70B891e0D305c1C6"

# Load ABI
with open("../blockchain/build/contracts/Vault.json") as f:
    vault_json = json.load(f)
    VAULT_ABI = vault_json["abi"]

# ---------------------------------------- #

w3 = Web3(Web3.HTTPProvider(GANACHE_URL))

if not w3.is_connected():
    raise Exception("Blockchain not connected")

account = w3.eth.accounts[0]
w3.eth.default_account = account

vault = w3.eth.contract(
    address=VAULT_ADDRESS,
    abi=VAULT_ABI
)


# ---------------- CRYPTO ---------------- #

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    payload = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "cipher": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }

    return base64.b64encode(json.dumps(payload).encode()).decode()


def decrypt(enc_data, key):
    payload = json.loads(base64.b64decode(enc_data).decode())

    nonce = base64.b64decode(payload["nonce"])
    cipher = base64.b64decode(payload["cipher"])
    tag = base64.b64decode(payload["tag"])

    aes = AES.new(key, AES.MODE_EAX, nonce)
    data = aes.decrypt_and_verify(cipher, tag)

    return data.decode()


# ------------- KEY MANAGEMENT ----------- #

def get_master_key():
    if not os.path.exists("master.key"):
        key = get_random_bytes(32)
        with open("master.key", "wb") as f:
            f.write(key)
        return key

    return open("master.key", "rb").read()


MASTER_KEY = get_master_key()


# ----------- BLOCKCHAIN OPS ------------ #

def save_data(plain_text):

    encrypted = encrypt(plain_text, MASTER_KEY)

    tx = vault.functions.setRecord(encrypted).transact()

    w3.eth.wait_for_transaction_receipt(tx)

    print("[+] Data saved on blockchain")


def load_data():

    data, ts = vault.functions.getRecord().call()

    if data == "":
        print("[-] No record found")
        return

    decrypted = decrypt(data, MASTER_KEY)

    print("[+] Decrypted Data:", decrypted)
    print("[+] Last Updated:", ts)


# ---------------- TEST ------------------ #

if __name__ == "__main__":

    while True:

        print("\n=== REK VAULT ===")
        print("1. Store Data")
        print("2. Read Data")
        print("3. Exit")

        ch = input("> ")

        if ch == "1":
            msg = input("Enter secret: ")
            save_data(msg)

        elif ch == "2":
            load_data()

        elif ch == "3":
            break

        else:
            print("Invalid")
