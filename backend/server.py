from flask import Flask, request, jsonify
from flask_cors import CORS
from eth_account.messages import encode_defunct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64, json, os, secrets
import hashlib

# ---------------------------------------- #

app = Flask(__name__)
CORS(app)

# Sessions (temporary)
sessions = {}

# ---------------- CRYPTO ---------------- #

def get_key(addr):

    path = f"keys/{addr}.key"

    if not os.path.exists("keys"):
        os.mkdir("keys")

    if not os.path.exists(path):
        key = get_random_bytes(32)
        open(path, "wb").write(key)
        return key

    return open(path, "rb").read()


def encrypt(data, key):

    aes = AES.new(key, AES.MODE_EAX)
    c, t = aes.encrypt_and_digest(data.encode())

    obj = {
        "n": base64.b64encode(aes.nonce).decode(),
        "c": base64.b64encode(c).decode(),
        "t": base64.b64encode(t).decode()
    }

    return base64.b64encode(json.dumps(obj).encode()).decode()


def decrypt(enc, key):

    o = json.loads(base64.b64decode(enc))

    aes = AES.new(
        key,
        AES.MODE_EAX,
        base64.b64decode(o["n"])
    )

    return aes.decrypt_and_verify(
        base64.b64decode(o["c"]),
        base64.b64decode(o["t"])
    ).decode()

# ---------- BACKUP CRYPTO ---------- #

def pass_key(password):

    return hashlib.sha256(password.encode()).digest()


def encrypt_backup(data, password):

    key = pass_key(password)

    return encrypt(json.dumps(data), key)


def decrypt_backup(enc, password):

    key = pass_key(password)

    return json.loads(decrypt(enc, key))

# --------------- AUTH ------------------ #

@app.route("/challenge", methods=["POST"])
def challenge():

    addr = Web3.to_checksum_address(request.json["address"])

    token = secrets.token_hex(16)

    sessions[addr] = token

    return jsonify({"challenge": token})


@app.route("/verify", methods=["POST"])
def verify():

    addr = Web3.to_checksum_address(request.json["address"])
    sig = request.json["signature"]

    if addr not in sessions:
        return {"error": "No session"}, 401

    msg = encode_defunct(text=sessions[addr])

    rec = w3.eth.account.recover_message(msg, signature=sig)

    if rec.lower() != addr.lower():
        return {"error": "Invalid sig"}, 401

    sessions[addr] = True

    return {"status": "ok"}


def auth(req):

    addr = req.headers.get("X-ADDR")

    if not addr:
        return None

    try:
        addr = Web3.to_checksum_address(addr)
    except:
        return None

    if sessions.get(addr) != True:
        return None

    return addr



# ------------ BLOCKCHAIN -------------- #

def get_vault(addr):

    with open("../blockchain/build/contracts/Vault.json") as f:
        abi = json.load(f)["abi"]

    return w3.eth.contract(
        address=os.environ["VAULT"],
        abi=abi
    )


# ------------- API ------------------- #

@app.route("/store", methods=["POST"])
def store():

    addr = auth(request)
    if not addr:
        return {"error": "auth"}, 401

    vault = get_vault(addr)

    key = get_key(addr)

    enc = encrypt(request.json["data"], key)

    tx = vault.functions.setRecord(enc).transact({
        "from": addr
    })

    w3.eth.wait_for_transaction_receipt(tx)

    return {"status": "saved"}


@app.route("/read", methods=["GET"])
def read():

    addr = auth(request)
    if not addr:
        return {"error": "auth"}, 401

    vault = get_vault(addr)

    enc, ts = vault.functions.getRecord().call({
        "from": addr
    })

    if enc == "":
        return {"data": None}

    key = get_key(addr)

    return {
        "data": decrypt(enc, key),
        "time": ts
    }

# ----------- BACKUP ----------- #

@app.route("/backup", methods=["POST"])
def backup():

    addr = auth(request)
    if not addr:
        return {"error": "auth"}, 401

    pwd = request.json["password"]

    key = get_key(addr)

    vault = get_vault(addr)

    enc, ts = vault.functions.getRecord().call({"from": addr})

    data = {
        "key": base64.b64encode(key).decode(),
        "record": enc,
        "time": ts
    }

    secured = encrypt_backup(data, pwd)

    path = f"backup/{addr}.bak"

    open(path, "w").write(secured)

    return {"status": "backup_saved", "file": path}

# ----------- RESTORE ----------- #

@app.route("/restore", methods=["POST"])
def restore():

    addr = auth(request)
    if not addr:
        return {"error": "auth"}, 401

    pwd = request.json["password"]

    path = f"backup/{addr}.bak"

    if not os.path.exists(path):
        return {"error": "no_backup"}, 404

    enc = open(path).read()

    data = decrypt_backup(enc, pwd)

    # Restore key
    key = base64.b64decode(data["key"])

    open(f"keys/{addr}.key", "wb").write(key)

    # Restore record
    vault = get_vault(addr)

    tx = vault.functions.setRecord(
        data["record"]
    ).transact({"from": addr})

    w3.eth.wait_for_transaction_receipt(tx)

    return {"status": "restored"}
# ----------- ROTATE KEY ----------- #

@app.route("/rotate", methods=["POST"])
def rotate():

    addr = auth(request)
    if not addr:
        return {"error": "auth"}, 401

    vault = get_vault(addr)

    old_key = get_key(addr)

    enc, _ = vault.functions.getRecord().call({"from": addr})

    if enc == "":
        return {"error": "no_data"}, 400

    plain = decrypt(enc, old_key)

    # Generate new key
    new_key = get_random_bytes(32)

    open(f"keys/{addr}.key", "wb").write(new_key)

    new_enc = encrypt(plain, new_key)

    tx = vault.functions.setRecord(
        new_enc
    ).transact({"from": addr})

    w3.eth.wait_for_transaction_receipt(tx)

    return {"status": "rotated"}

# ------------------------------------- #

if __name__ == "__main__":

    if "VAULT" not in os.environ:
        raise Exception("Set VAULT address first")

    app.run(port=5000, debug=True)
