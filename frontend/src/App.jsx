import { useState } from "react";
import axios from "axios";
import { ethers } from "ethers";

const API = "http://127.0.0.1:5000";

function App() {

  const [address, setAddress] = useState("");
  const [secret, setSecret] = useState("");
  const [result, setResult] = useState("");
  const [status, setStatus] = useState("Not Connected");


  // Connect MetaMask
  async function connectWallet() {

    if (!window.ethereum) {
      alert("Install MetaMask first");
      return;
    }

    try {

      const provider = new ethers.BrowserProvider(window.ethereum);

      const accounts = await provider.send(
        "eth_requestAccounts",
        []
      );

      const addr = accounts[0];

      setAddress(addr);

      await authenticate(addr, provider);

    } catch (err) {

      console.error(err);
      alert("Wallet connection failed");
    }
  }


  // Sign challenge
  async function authenticate(addr, provider) {

    try {

      setStatus("Authenticating...");

      // Get challenge
      const c = await axios.post(
        API + "/challenge",
        { address: addr }
      );

      const challenge = c.data.challenge;

      // Sign
      const signer = await provider.getSigner();

      const sig = await signer.signMessage(challenge);

      // Verify
      const v = await axios.post(
        API + "/verify",
        {
          address: addr,
          signature: sig
        }
      );

      if (v.data.status === "ok") {
        setStatus("Authenticated");
      } else {
        setStatus("Auth Failed");
      }

    } catch (err) {

      console.error(err);
      setStatus("Auth Error");
    }
  }


  // Store secret
  async function storeData() {

    if (!secret) {
      alert("Enter data first");
      return;
    }

    try {

      await axios.post(
        API + "/store",
        { data: secret },
        {
          headers: {
            "X-ADDR": address
          }
        }
      );

      setSecret("");
      alert("Saved to REK");

    } catch (err) {

      console.error(err);
      alert("Store failed");
    }
  }


  // Read secret
  async function readData() {

    try {

      const r = await axios.get(
        API + "/read",
        {
          headers: {
            "X-ADDR": address
          }
        }
      );

      if (r.data.data) {
        setResult(r.data.data);
      } else {
        setResult("No Data");
      }

    } catch (err) {

      console.error(err);
      alert("Read failed");
    }
  }


  return (
    <div style={{
      padding: "40px",
      fontFamily: "Arial"
    }}>

      <h1>REK Secure Vault</h1>

      <p>Status: <b>{status}</b></p>

      {!address && (
        <button onClick={connectWallet}>
          Connect MetaMask
        </button>
      )}

      {address && (

        <div>

          <p><b>Wallet:</b> {address}</p>

          <input
            type="text"
            placeholder="Enter secret"
            value={secret}
            onChange={e => setSecret(e.target.value)}
            style={{ width: "300px" }}
          />

          <br /><br />

          <button onClick={storeData}>
            Store
          </button>

          <button
            onClick={readData}
            style={{ marginLeft: "10px" }}
          >
            Read
          </button>

          <p><b>Result:</b> {result}</p>

        </div>
      )}

    </div>
  );
}

export default App;
