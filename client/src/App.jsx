// client/src/App.jsx
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
  const ikmKey = await crypto.subtle.importKey("raw", sharedSecretBytes, "HKDF", false, ["deriveKey"]);
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
  const all = new Uint8Array(cipherWithTag);
  const tag = all.slice(all.length - 16);
  const ciphertext = all.slice(0, all.length - 16);
  return { ciphertext, tag };
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha512Hex(arrayBuffer) {
  const digest = await crypto.subtle.digest("SHA-512", arrayBuffer);
  return bytesToHex(new Uint8Array(digest));
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename || "download.bin";
  a.click();
  URL.revokeObjectURL(url);
}

// ---------- App ----------
export default function App() {
  const [token, setToken] = useState(localStorage.getItem("demo_token") || "");
  const [username, setUsername] = useState(localStorage.getItem("demo_user") || "alice");
  const [password, setPassword] = useState("alice123");

  const [file, setFile] = useState(null);
  const [encryptBeforeSend, setEncryptBeforeSend] = useState(true);
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState("");

  function authHeaders() {
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  function clearAuth(message = "Session expired. Please login again.") {
    setToken("");
    localStorage.removeItem("demo_token");
    setFiles([]);
    setStatus(message);
  }

  async function authedFetch(url, options = {}) {
    const res = await fetch(url, {
      ...options,
      headers: { ...(options.headers || {}), ...authHeaders() },
    });
    if (res.status === 401) {
      clearAuth("Session expired (401). Please login again.");
      throw new Error("Unauthorized");
    }
    return res;
  }

  async function refresh() {
    if (!token) {
      setFiles([]);
      return;
    }
    try {
      const res = await authedFetch(`${API}/files`);
      const { json, text } = await readJsonSafe(res);
      if (!res.ok) throw new Error(json?.error || text || "refresh failed");
      setFiles(Array.isArray(json) ? json : []);
    } catch (e) {
      console.error(e);
      setFiles([]);
    }
  }

  useEffect(() => {
    if (token) refresh();
    mlkemInit().catch((e) => {
      console.error(e);
      setStatus("ML-KEM WASM init failed. Check /public/mlkem768/*.mjs/.wasm is served.");
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  async function login(e) {
    e.preventDefault();
    try {
      setStatus("Logging in…");
      const r = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const { json, text } = await readJsonSafe(r);
      if (!r.ok) throw new Error(json?.error || text || "login failed");

      setToken(json.token);
      localStorage.setItem("demo_token", json.token);
      localStorage.setItem("demo_user", username);
      setStatus(`Logged in as ${json.name} (${json.clientId})`);
      await refresh();
    } catch (e2) {
      console.error(e2);
      setStatus(`Login failed: ${e2?.message || e2}`);
    }
  }

  async function logout() {
    try {
      if (token) {
        await authedFetch(`${API}/auth/logout`, { method: "POST" });
      }
    } finally {
      setToken("");
      localStorage.removeItem("demo_token");
      setFiles([]);
      setStatus("Logged out");
    }
  }

  async function uploadFile(e) {
    e.preventDefault();
    if (!file) return;
    if (!token) {
      setStatus("Please login first.");
      return;
    }

    try {
      if (encryptBeforeSend) {
        setStatus("PQ handshake (ML-KEM-768)...");

        // 1) Get ML-KEM-768 public key from server
        const r1 = await authedFetch(`${API}/kem-pubkey`);
        const { json: j1, text: t1 } = await readJsonSafe(r1);
        if (!r1.ok) throw new Error(j1?.error || t1 || "kem-pubkey failed");

        const { keyId, pkB64 } = j1;
        const pk = bytesFromB64(pkB64);

        // 2) Encapsulate(pk) => (ct, sharedSecret)
        await mlkemInit();
        const { ct, sharedSecret } = await mlkemEncapsulate(pk);

        // 3) HKDF(sharedSecret) => AES-256-GCM key
        const aesKey = await hkdfToAesKey(sharedSecret);

        // 4) Encrypt file on client
        setStatus("Encrypting file (AES-256-GCM)...");
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const plain = new Uint8Array(await file.arrayBuffer());

        const cipherWithTag = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plain);
        const { ciphertext, tag } = splitGcmTag(cipherWithTag);

        // 5) Upload encrypted payload
        setStatus("Uploading encrypted payload...");
        const form = new FormData();
        form.append("keyId", keyId);
        form.append("kemCtB64", b64FromBytes(ct));
        form.append("ivB64", b64FromBytes(iv));
        form.append("tagB64", b64FromBytes(tag));
        form.append("originalName", file.name);
        form.append("cipher", new Blob([ciphertext]), "cipher.bin");

        const r2 = await authedFetch(`${API}/upload-pq`, {
          method: "POST",
          body: form,
        });
        const { json: j2, text: t2 } = await readJsonSafe(r2);
        if (!r2.ok) throw new Error(j2?.error || t2 || "Upload failed");

        setStatus(`Uploaded: ${j2.name} (encrypted before sending to backend)`);
      } else {
        setStatus("Uploading plaintext payload...");
        const form = new FormData();
        form.append("originalName", file.name);
        form.append("file", file);

        const r = await authedFetch(`${API}/upload-plain`, {
          method: "POST",
          body: form,
        });
        const { json, text } = await readJsonSafe(r);
        if (!r.ok) throw new Error(json?.error || text || "Plain upload failed");

        setStatus(`Uploaded: ${json.name} (plaintext sent to backend)`);
      }

      setFile(null);
      await refresh();
    } catch (err) {
      console.error(err);
      setStatus(`Upload failed: ${err?.message || err}`);
    }
  }

  async function deleteFile(fileId) {
    try {
      setStatus("Deleting…");
      const r = await authedFetch(`${API}/files/${fileId}`, {
        method: "DELETE",
      });
      const { json, text } = await readJsonSafe(r);
      if (!r.ok) throw new Error(json?.error || text || "delete failed");
      setStatus(`Deleted: ${fileId}`);
      await refresh();
    } catch (e) {
      console.error(e);
      setStatus(`Delete failed: ${e?.message || e}`);
    }
  }

  async function downloadAndVerify(f) {
    try {
      setStatus("Downloading…");

      // 1) manifest
      const mRes = await authedFetch(`${API}/files/${f.id}/manifest`);
      const { json: manifest, text: mt } = await readJsonSafe(mRes);
      if (!mRes.ok) throw new Error(manifest?.error || mt || "manifest failed");

      // 2) download bytes
      const res = await authedFetch(`${API}/files/${f.id}`);
      if (!res.ok) {
        const { json, text } = await readJsonSafe(res);
        throw new Error(json?.error || text || "download failed");
      }

      const buf = await res.arrayBuffer();

      // 3) verify SHA-512
      setStatus("Verifying SHA-512…");
      const got = (await sha512Hex(buf)).toLowerCase();
      const expected = String(manifest.sha512 || "").toLowerCase();

      if (got !== expected) {
        setStatus("❌ Integrity FAILED (SHA-512 mismatch). Not saving file.");
        return;
      }

      downloadBlob(new Blob([buf], { type: "application/octet-stream" }), manifest.originalName);
      setStatus("✅ Downloaded + verified (SHA-512 match).");
    } catch (e) {
      console.error(e);
      setStatus(`Download/verify failed: ${e?.message || e}`);
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: "system-ui" }}>
      <h2>Demo: Username/Password Auth + Multi-client + Optional Client-side Encryption + Integrity</h2>

      {!token ? (
        <form onSubmit={login} style={{ marginBottom: 16 }}>
          <div style={{ marginBottom: 8 }}>
            <input
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{ marginRight: 8 }}
            />
            <input
              placeholder="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{ marginRight: 8 }}
            />
            <button type="submit">Login</button>
          </div>
          <div style={{ fontSize: 12, opacity: 0.85 }}>
            Demo accounts: alice/alice123, bob/bob123
          </div>
        </form>
      ) : (
        <div style={{ marginBottom: 16 }}>
          <button onClick={logout}>Logout</button>
        </div>
      )}

      <form onSubmit={uploadFile} style={{ marginBottom: 16 }}>
        <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
        <label style={{ marginLeft: 8, fontSize: 13 }}>
          <input
            type="checkbox"
            checked={encryptBeforeSend}
            onChange={(e) => setEncryptBeforeSend(e.target.checked)}
            style={{ marginRight: 4 }}
          />
          Encrypt before sending to backend
        </label>
        <button type="submit" style={{ marginLeft: 8 }} disabled={!token}>
          Upload
        </button>
      </form>

      <div style={{ marginBottom: 16 }}>{status}</div>

      <h3>My Files (isolated per user)</h3>
      <ul>
        {files.map((f) => (
          <li key={f.id} style={{ marginBottom: 10 }}>
            <div>
              <b>{f.originalName}</b> ({Math.round((f.size || 0) / 1024)} KB) — state:{" "}
              <code>{f.state}</code>
            </div>
            <div style={{ fontSize: 12, opacity: 0.85 }}>
              sha512: <code>{String(f.sha512 || "").slice(0, 16)}…</code>
            </div>
            <div style={{ marginTop: 6 }}>
              <button onClick={() => downloadAndVerify(f)} disabled={!token}>
                Download + Verify
              </button>

              <button
                onClick={() => deleteFile(f.id)}
                style={{ marginLeft: 8 }}
                disabled={!token}
              >
                Delete
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}


