// client/src/App.jsx
import { useEffect, useState } from "react";

const API = "http://localhost:4000";
const PBKDF2_ITERATIONS = 310000;
const PBKDF2_HASH = "SHA-256";

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

async function derivePasswordAesKey(password, saltBytes, iterations, hash, usages) {
  const pwdBytes = new TextEncoder().encode(password);
  const pwdKey = await crypto.subtle.importKey("raw", pwdBytes, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash,
      salt: saltBytes,
      iterations,
    },
    pwdKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
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
  const [uploadMode, setUploadMode] = useState("encrypt_before_send");
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
      if (uploadMode === "encrypt_before_send") {
        const password = window.prompt("Enter password to encrypt this file before upload:");
        if (!password) {
          setStatus("Upload canceled: password is required.");
          return;
        }

        setStatus("Deriving encryption key (PBKDF2)...");
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const aesKey = await derivePasswordAesKey(
          password,
          salt,
          PBKDF2_ITERATIONS,
          PBKDF2_HASH,
          ["encrypt"]
        );

        setStatus("Encrypting file on client (AES-256-GCM)...");
        const plain = new Uint8Array(await file.arrayBuffer());
        const cipherWithTag = new Uint8Array(
          await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plain)
        );

        setStatus("Uploading client-encrypted payload...");
        const form = new FormData();
        form.append("originalName", file.name);
        form.append("saltB64", b64FromBytes(salt));
        form.append("ivB64", b64FromBytes(iv));
        form.append(
          "kdf",
          JSON.stringify({
            name: "PBKDF2",
            hash: PBKDF2_HASH,
            iterations: PBKDF2_ITERATIONS,
          })
        );
        form.append("cipher", new Blob([cipherWithTag]), "cipher.bin");

        const r2 = await authedFetch(`${API}/upload-client-encrypted`, {
          method: "POST",
          body: form,
        });
        const { json: j2, text: t2 } = await readJsonSafe(r2);
        if (!r2.ok) throw new Error(j2?.error || t2 || "Upload failed");

        setStatus(`Uploaded: ${j2.name} (client-encrypted with password)`);
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
        if (uploadMode === "encrypt_backend") {
          setStatus("Encrypting file at backend...");
          const r2 = await authedFetch(`${API}/files/${json.id}/encrypt-at-rest`, { method: "POST" });
          const { json: j2, text: t2 } = await readJsonSafe(r2);
          if (!r2.ok) throw new Error(j2?.error || t2 || "Backend encrypt failed");
          setStatus(`Uploaded: ${json.name} (encrypted at backend)`);
        } else {
          setStatus(`Uploaded: ${json.name} (saved plaintext at backend)`);
        }
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
      setStatus("Downloading...");

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

      // 3) verify SHA-512 on downloaded bytes
      setStatus("Verifying SHA-512...");
      const got = (await sha512Hex(buf)).toLowerCase();
      const expected = String(manifest.sha512 || "").toLowerCase();
      if (got !== expected) {
        setStatus("Integrity FAILED (SHA-512 mismatch). Not saving file.");
        return;
      }

      if (manifest.state === "CLIENT_ENCRYPTED") {
        const password = window.prompt("Enter password to decrypt this file:");
        if (!password) {
          setStatus("Download canceled: password is required to decrypt.");
          return;
        }

        const meta = manifest.clientEncMeta || {};
        const kdf = meta.kdf || {};
        const salt = bytesFromB64(String(meta.saltB64 || ""));
        const iv = bytesFromB64(String(meta.ivB64 || ""));
        if (!salt.length || !iv.length) {
          throw new Error("Missing client encryption metadata");
        }

        setStatus("Deriving decryption key (PBKDF2)...");
        const aesKey = await derivePasswordAesKey(
          password,
          salt,
          Number(kdf.iterations || PBKDF2_ITERATIONS),
          String(kdf.hash || PBKDF2_HASH),
          ["decrypt"]
        );

        setStatus("Decrypting file on client...");
        let plain;
        try {
          plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, buf);
        } catch {
          throw new Error("Decryption failed. Password may be incorrect.");
        }

        downloadBlob(new Blob([plain], { type: "application/octet-stream" }), manifest.originalName);
        setStatus("Downloaded + decrypted successfully.");
        return;
      }

      downloadBlob(new Blob([buf], { type: "application/octet-stream" }), manifest.originalName);
      setStatus("Downloaded + verified (SHA-512 match).");
    } catch (e) {
      console.error(e);
      setStatus(`Download/verify failed: ${e?.message || e}`);
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: "system-ui" }}>
      <h2>Demo: Username/Password Auth + Multi-client + 3 Upload Modes + Integrity + Password Encryption</h2>

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
        <label style={{ marginLeft: 8, fontSize: 13, fontWeight: "bold" }}>
          Upload mode:{" "}
          <select value={uploadMode} onChange={(e) => setUploadMode(e.target.value)}>
            <option value="plain">Save plain</option>
            <option value="encrypt_backend">Encrypt at backend side</option>
            <option value="encrypt_before_send">Encrypt before sending (password)</option>
          </select>
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





