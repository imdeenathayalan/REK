import os
import json
from web3 import Web3
from dotenv import load_dotenv
from eth_account import Account

# Load env
load_dotenv()

SEPOLIA_RPC = os.getenv("SEPOLIA_RPC")
VAULT_ADDRESS = os.getenv("VAULT_ADDRESS")
PRIVATE_KEY = os.getenv("DEPLOYER_KEY")

if not SEPOLIA_RPC or not VAULT_ADDRESS:
    raise Exception("Missing environment variables")

# Connect
w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC))

if not w3.is_connected():
    raise Exception("Web3 not connected to Sepolia")

# Load ABI
with open("Vault.json") as f:
    vault_abi = json.load(f)["abi"]

# Account
account = Account.from_key(PRIVATE_KEY)

# Contract
vault = w3.eth.contract(
    address=Web3.to_checksum_address(VAULT_ADDRESS),
    abi=vault_abi
)

print("[+] Web3 connected")
print("[+] Vault loaded:", VAULT_ADDRESS)
print("[+] Backend wallet:", account.address)
