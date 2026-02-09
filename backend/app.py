from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from web3_client import w3, vault, account
import base64
import json
import os

# Use deployer account for tx signing
w3.eth.default_account = account.address

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

def save_data(data):
    encrypted = encrypt(data, MASTER_KEY)

    nonce = w3.eth.get_transaction_count(account.address)

    tx = vault.functions.setRecord(encrypted).build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": 300000,
        "gasPrice": w3.eth.gas_price,
        "chainId": 11155111
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key=account.key)

    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    print("[+] Stored on-chain")
    print("TX:", tx_hash.hex())


def load_data():

    result = vault.functions.getRecord().call({
        "from": account.address
    })

    # result = (encrypted_string, timestamp)
    if not result or len(result) < 1:
        print("[-] No record found")
        return

    encrypted = result[0]   # FIRST element = data

    if not encrypted:
        print("[-] No record found")
        return

    try:
        decrypted = decrypt(encrypted, MASTER_KEY)
        print("[+] Decrypted:", decrypted)

    except Exception as e:
        print("[-] Decryption failed:", e)



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
