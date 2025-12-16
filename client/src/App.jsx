// client/src/App.jsx
import { useEffect, useState } from "react";
import { mlkemEncapsulate, mlkemInit } from "./mlkem.js";

const API = "http://localhost:4000";

function b64FromBytes(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.slice(i, i + chunk));
  }
  return btoa(bin);
}

function bytesFromB64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hkdfToAesKey(sharedSecretBytes) {
  // sharedSecretBytes: Uint8Array
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    sharedSecretBytes,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array([]),
      info: new TextEncoder().encode("pq-upload-aes-256-key"),
    },
    ikmKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
}

function splitGcmTag(cipherWithTag) {
  // WebCrypto returns ciphertext||tag (tag is last 16 bytes for 128-bit GCM tag)
  const all = new Uint8Array(cipherWithTag);
  const tag = all.slice(all.length - 16);
  const ciphertext = all.slice(0, all.length - 16);
  return { ciphertext, tag };
}

export default function App() {
  const [file, setFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState("");

  async function refresh() {
    const res = await fetch(`${API}/files`);
    const data = await res.json();
    setFiles(Array.isArray(data) ? data : []);
  }

  useEffect(() => {
    refresh();
    // init ML-KEM wasm once
    mlkemInit().catch(() => {});
  }, []);

  async function uploadFile(e) {
    e.preventDefault();
    if (!file) return;

    try {
      setStatus("PQ handshake…");

      // 1) Get ML-KEM public key from server
      const r1 = await fetch(`${API}/kem-pubkey`);
      const { keyId, pkB64 } = await r1.json();
      if (!r1.ok) throw new Error("kem-pubkey failed");

      const pk = bytesFromB64(pkB64);

      // 2) ML-KEM encapsulate(pk) => (ct, sharedSecret)
      await mlkemInit();
      const { ct, sharedSecret } = await mlkemEncapsulate(pk);

      // 3) HKDF(sharedSecret) => AES-256-GCM key
      const aesKey = await hkdfToAesKey(sharedSecret);

      // 4) Encrypt file (AES-256-GCM)
      setStatus("Encrypting file (AES-256-GCM)…");
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plain = new Uint8Array(await file.arrayBuffer());

      const cipherWithTag = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        plain
      );

      const { ciphertext, tag } = splitGcmTag(cipherWithTag);

      // 5) Upload encrypted payload; server decrypts and stores plaintext
      setStatus("Uploading encrypted…");
      const form = new FormData();
      form.append("keyId", keyId);
      form.append("kemCtB64", b64FromBytes(ct));
      form.append("ivB64", b64FromBytes(iv));
      form.append("tagB64", b64FromBytes(tag));
      form.append("originalName", file.name);

      // send ciphertext as a "file" field named "cipher"
      form.append("cipher", new Blob([ciphertext]), "cipher.bin");

      const r2 = await fetch(`${API}/upload-pq`, { method: "POST", body: form });
      const data2 = await r2.json();

      if (!r2.ok) {
        setStatus(data2?.error || "Upload failed");
        return;
      }

      setStatus(`Uploaded: ${data2.name}`);
      setFile(null);
      await refresh();
    } catch (err) {
      console.error(err);
      setStatus("Upload failed (PQ/AES)");
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: "system-ui" }}>
      <h2>File Upload + Download</h2>

      <form onSubmit={uploadFile} style={{ marginBottom: 16 }}>
        <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
        <button type="submit" style={{ marginLeft: 8 }}>Upload</button>
      </form>

      <div style={{ marginBottom: 16 }}>{status}</div>

      <h3>Files</h3>
      <ul>
        {files.map((f) => (
          <li key={f.id}>
            {f.originalName} ({Math.round((f.size || 0) / 1024)} KB) —{" "}
            <a href={`${API}/files/${f.id}`}>Download</a>
          </li>
        ))}
      </ul>
    </div>
  );
}
