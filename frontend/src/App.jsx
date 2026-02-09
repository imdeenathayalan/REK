import { useState } from "react";
import { ethers } from "ethers";
import vaultJson from "./Vault.json";
import "bootstrap-icons/font/bootstrap-icons.css";

/* =======================
   CRYPTO HELPERS
======================= */

async function deriveKey(signer) {
  const msg = "REK_ENCRYPTION_KEY";

  const sig = await signer.signMessage(msg);

  const enc = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(sig),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("rek_salt"),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();

  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(text)
  );

  return btoa(
    JSON.stringify({
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(cipher)),
    })
  );
}

async function decryptText(payload, key) {
  const obj = JSON.parse(atob(payload));

  const iv = new Uint8Array(obj.iv);
  const data = new Uint8Array(obj.data);

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(plain);
}

/* =======================
   CONFIG
======================= */

const VAULT_ADDRESS = import.meta.env.VITE_VAULT_ADDRESS;
const SEPOLIA_HEX = "0xaa36a7";

/* =======================
   APP
======================= */

function App() {

  const [account, setAccount] = useState("");
  const [contract, setContract] = useState(null);
  const [signer, setSigner] = useState(null);
  const [cryptoKey, setCryptoKey] = useState(null);

  const [secret, setSecret] = useState("");
  const [stored, setStored] = useState("");
  const [status, setStatus] = useState("");

  const [showSecret, setShowSecret] = useState(false);
  const [showWallet, setShowWallet] = useState(false);

  /* =======================
     CONNECT
  ======================= */

  const connectWallet = async () => {
    try {

      if (!window.ethereum) {
        alert("Install MetaMask first");
        return;
      }

      setStatus("Connecting...");

      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });

      const addr = accounts[0];

      const chainId = await window.ethereum.request({
        method: "eth_chainId",
      });

      if (chainId !== SEPOLIA_HEX) {

        try {
          await window.ethereum.request({
            method: "wallet_switchEthereumChain",
            params: [{ chainId: SEPOLIA_HEX }],
          });
        } catch {
          alert("Switch to Sepolia first");
          return;
        }
      }

      const provider = new ethers.BrowserProvider(window.ethereum);
      const signerObj = await provider.getSigner();

      const key = await deriveKey(signerObj);

      const vault = new ethers.Contract(
        VAULT_ADDRESS,
        vaultJson.abi,
        signerObj
      );

      setAccount(addr);
      setSigner(signerObj);
      setCryptoKey(key);
      setContract(vault);

      setStatus("Connected ✔");

    } catch (err) {
      console.error(err);
      setStatus("Connection failed");
    }
  };

  /* =======================
     STORE
  ======================= */

  const saveSecret = async () => {

    if (!contract || !cryptoKey) {
      alert("Reconnect wallet");
      return;
    }

    if (!secret) {
      alert("Enter secret");
      return;
    }

    try {

      setStatus("Encrypting...");

      const encrypted = await encryptText(secret, cryptoKey);

      setStatus("Sending TX...");

      const tx = await contract.setRecord(encrypted);

      await tx.wait();

      setStatus("Stored ✔");
      setSecret("");

    } catch (err) {
      console.error(err);
      setStatus("Store failed");
    }
  };

  /* =======================
     READ
  ======================= */

  const readSecret = async () => {

    if (!contract || !cryptoKey) {
      alert("Reconnect wallet");
      return;
    }

    try {

      setStatus("Reading...");

      const res = await contract.getRecord();

      const encrypted = res[0];

      if (!encrypted) {
        setStored("");
        return;
      }

      const decrypted = await decryptText(encrypted, cryptoKey);

      setStored(decrypted);

      setStatus("Loaded ✔");

    } catch (err) {
      console.error(err);
      setStatus("Read failed");
    }
  };

  /* =======================
     COPY
  ======================= */

  const copySecret = () => {
    if (!stored) return;

    navigator.clipboard.writeText(stored);
    setStatus("Copied ✔");
  };

  /* =======================
     UI
  ======================= */

  return (
    <div className="min-h-screen bg-slate-950 text-gray-100 flex items-center justify-center px-4">

      <div className="w-full max-w-md md:max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-xl p-7 space-y-6">

        {/* Header */}
        <div className="text-center">
          <h1 className="text-3xl font-bold tracking-wide text-blue-400">
            REK
          </h1>
        </div>

        {/* Connect */}
        {!account && (
          <button
            onClick={connectWallet}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold transition"
          >
            Connect Wallet
          </button>
        )}

        {account && (
          <div className="space-y-5">

            {/* Wallet */}
            <div className="bg-slate-800 px-4 py-3 rounded-lg text-xs text-center">

              {!showWallet ? (
                <button
                  onClick={() => setShowWallet(true)}
                  className="text-blue-400 hover:underline"
                >
                  Show Wallet Address
                </button>
              ) : (
                <span className="break-all text-gray-300">
                  {account}
                </span>
              )}

            </div>

            {/* Input */}
            <div className="space-y-1">

              <label className="text-xs text-gray-400 uppercase">
                Secret
              </label>

              <div className="relative">

                <input
                  type={showSecret ? "text" : "password"}
                  placeholder="••••••••••"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  className="w-full px-4 py-2.5 pr-10 rounded-lg bg-slate-800 border border-slate-700 focus:outline-none focus:border-blue-500"
                />

                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-blue-400"
                >
                  <i className={`bi ${showSecret ? "bi-eye-slash" : "bi-eye"}`}></i>
                </button>

              </div>

            </div>

            {/* Buttons */}
            <div className="grid grid-cols-2 gap-3">

              <button
                onClick={saveSecret}
                className="py-2.5 bg-emerald-600 hover:bg-emerald-700 rounded-lg font-medium transition"
              >
                Store
              </button>

              <button
                onClick={readSecret}
                className="py-2.5 bg-sky-600 hover:bg-sky-700 rounded-lg font-medium transition"
              >
                Read
              </button>

            </div>

            {/* Output + Copy */}
            <div className="bg-slate-800 px-4 py-3 rounded-lg text-sm min-h-[48px] flex items-center justify-between gap-3">

              <div className="flex-1 break-all text-center">

                {stored
                  ? stored
                  : <span className="text-gray-500">No data</span>
                }

              </div>

              {stored && (
                <button
                  onClick={copySecret}
                  className="text-gray-400 hover:text-blue-400 text-lg"
                  title="Copy"
                >
                  <i className="bi bi-clipboard"></i>
                </button>
              )}

            </div>

          </div>
        )}

        {/* Status */}
        <div className="text-center text-xs text-gray-400 min-h-[16px]">
          {status}
        </div>

      </div>

    </div>
  );
}

export default App;
