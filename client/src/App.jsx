// client/src/App.jsx (Requirement 2b: ML-KEM-768 + HKDF -> AES-256-GCM; server stores plaintext)
import { useEffect, useState } from "react";
import { mlkemEncapsulate, mlkemInit } from "./mlkem.js";

const API = "http://localhost:4000";

// ---------- helpers ----------
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

async function readJsonSafe(res) {
  const text = await res.text();
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return { json: null, text };
  }
}

async function hkdfToAesKey(sharedSecretBytes) {
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
  const all = new Uint8Array(cipherWithTag); // ciphertext||tag (tag last 16 bytes)
  const tag = all.slice(all.length - 16);
  const ciphertext = all.slice(0, all.length - 16);
  return { ciphertext, tag };
}

// ---------- App ----------
export default function App() {
  const [file, setFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState("");

  async function refresh() {
    try {
      const res = await fetch(`${API}/files`);
      const { json, text } = await readJsonSafe(res);
      if (!res.ok) throw new Error(json?.error || text || "refresh failed");
      setFiles(Array.isArray(json) ? json : []);
    } catch (e) {
      console.error(e);
      setFiles([]);
    }
  }

  useEffect(() => {
    refresh();
    mlkemInit().catch((e) => {
      console.error(e);
      setStatus("ML-KEM WASM init failed. Check /public/mlkem768/*.mjs/.wasm is served.");
    });
  }, []);

  async function uploadFile(e) {
    e.preventDefault();
    if (!file) return;

    try {
      setStatus("PQ handshake (ML-KEM-768)…");

      // 1) Get ML-KEM-768 public key from server
      const r1 = await fetch(`${API}/kem-pubkey`);
      const { json: j1, text: t1 } = await readJsonSafe(r1);
      if (!r1.ok) throw new Error(j1?.error || t1 || "kem-pubkey failed");

      const { keyId, pkB64 } = j1;
      const pk = bytesFromB64(pkB64);

      console.log("[FE] pk bytes =", pk.length);

      // 2) Encapsulate(pk) => (ct, sharedSecret)
      await mlkemInit();
      const { ct, sharedSecret } = await mlkemEncapsulate(pk);

      console.log("[FE] ct bytes =", ct.length, "ss bytes =", sharedSecret.length);

      // 3) HKDF(sharedSecret) => AES-256-GCM key
      const aesKey = await hkdfToAesKey(sharedSecret);

      // 4) Encrypt file with AES-256-GCM
      setStatus("Encrypting file (AES-256-GCM)…");
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plain = new Uint8Array(await file.arrayBuffer());

      const cipherWithTag = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        plain
      );

      const { ciphertext, tag } = splitGcmTag(cipherWithTag);

      // 5) Upload encrypted payload; server decapsulates + decrypts and stores plaintext
      setStatus("Uploading encrypted payload…");
      const form = new FormData();
      form.append("keyId", keyId);
      form.append("kemCtB64", b64FromBytes(ct));
      form.append("ivB64", b64FromBytes(iv));
      form.append("tagB64", b64FromBytes(tag));
      form.append("originalName", file.name);
      form.append("cipher", new Blob([ciphertext]), "cipher.bin");

      const r2 = await fetch(`${API}/upload-pq`, { method: "POST", body: form });
      const { json: j2, text: t2 } = await readJsonSafe(r2);

      if (!r2.ok) {
        setStatus(j2?.error || t2 || "Upload failed");
        return;
      }

      setStatus(`Uploaded: ${j2.name}`);
      setFile(null);
      await refresh();
    } catch (err) {
      console.error(err);
      setStatus(`Upload failed (2b: ML-KEM/AES): ${err?.message || err}`);
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: "system-ui" }}>
      <h2>File Upload + Download (2b: ML-KEM-768 + AES-256-GCM)</h2>

      <form onSubmit={uploadFile} style={{ marginBottom: 16 }}>
        <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
        <button type="submit" style={{ marginLeft: 8 }}>
          Upload (PQ)
        </button>
      </form>

      <div style={{ marginBottom: 16 }}>{status}</div>

      <h3>Files (stored plaintext server-side)</h3>
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
