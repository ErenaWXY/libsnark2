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

function bytesFromHex(hex) {
  const clean = String(hex || "").trim();
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error("Invalid hexadecimal key");
  }

  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function normalizeKeyInput(value) {
  const clean = String(value || "").trim();

  if (!clean) {
    throw new Error("Please enter the decryption key");
  }

  // AES-256 raw key represented as 64 hex characters.
  if (/^[0-9a-fA-F]{64}$/.test(clean)) {
    return bytesFromHex(clean);
  }

  // Otherwise treat it as Base64.
  try {
    const bytes = bytesFromB64(clean);
    if (bytes.length !== 32) {
      throw new Error("AES-256 key must be exactly 32 bytes");
    }
    return bytes;
  } catch {
    throw new Error("Invalid key. Paste the Base64 key shown after upload.");
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
  const all = new Uint8Array(cipherWithTag);
  const tag = all.slice(all.length - 16);
  const ciphertext = all.slice(0, all.length - 16);
  return { ciphertext, tag };
}

async function sha256Hex(data) {
  const bytes =
    data instanceof Uint8Array
      ? data
      : new Uint8Array(data);

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength
    )
  );

  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function formatTime(value) {
  if (!value) return "N/A";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function shortHash(value) {
  if (!value) return "N/A";
  return `${value.slice(0, 16)}...`;
}

export default function App() {
  const [file, setFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState("");
  const [uploadMode, setUploadMode] = useState("normal");
  const [lastEncryptionKey, setLastEncryptionKey] = useState("");
  const [decryptKeys, setDecryptKeys] = useState({});
  const [decryptStatus, setDecryptStatus] = useState({});

  async function refresh() {
    try {
      const res = await fetch(`${API}/files`);
      const data = await res.json();
      setFiles(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error(e);
      setStatus("Failed to load file list");
    }
  }

  useEffect(() => {
    refresh();
    mlkemInit().catch(() => {});
  }, []);

  async function uploadFile(e) {
    e.preventDefault();
    if (!file) return;

    if (uploadMode === "private") {
      await uploadPrivateFile();
    } else {
      await uploadNormalFile();
    }
  }

  async function uploadNormalFile() {
    try {
      setLastEncryptionKey("");
      setStatus("PQ handshake...");

      const r1 = await fetch(`${API}/kem-pubkey`);
      const { keyId, pkB64 } = await r1.json();
      if (!r1.ok) throw new Error("kem-pubkey failed");

      const pk = bytesFromB64(pkB64);

      await mlkemInit();
      const { ct, sharedSecret } = await mlkemEncapsulate(pk);

      const aesKey = await hkdfToAesKey(sharedSecret);

      setStatus("Encrypting file for secure transport...");
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plain = new Uint8Array(await file.arrayBuffer());

      const cipherWithTag = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        plain
      );

      const { ciphertext, tag } = splitGcmTag(cipherWithTag);

      setStatus("Uploading securely...");
      const form = new FormData();
      form.append("keyId", keyId);
      form.append("kemCtB64", b64FromBytes(ct));
      form.append("ivB64", b64FromBytes(iv));
      form.append("tagB64", b64FromBytes(tag));
      form.append("originalName", file.name);
      form.append("cipher", new Blob([ciphertext]), "cipher.bin");

      const r2 = await fetch(`${API}/upload-pq`, {
        method: "POST",
        body: form,
      });
      const data2 = await r2.json();

      if (!r2.ok) {
        throw new Error(data2?.error || "Normal upload failed");
      }

      setStatus(
        `Normal upload completed: ${data2.name}. Server stores plaintext after secure transport.`
      );
      setFile(null);
      await refresh();
    } catch (err) {
      console.error(err);
      setStatus(`Normal upload failed: ${err.message || "PQ/AES error"}`);
    }
  }

  async function uploadPrivateFile() {
    try {
      setLastEncryptionKey("");
      setStatus("Encrypting file locally with AES-256-GCM...");

      const plaintext = new Uint8Array(await file.arrayBuffer());

      const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      const rawKey = new Uint8Array(
        await crypto.subtle.exportKey("raw", aesKey)
      );

      const iv = crypto.getRandomValues(new Uint8Array(12));

      const cipherWithTag = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        plaintext
      );

      const { ciphertext, tag } = splitGcmTag(cipherWithTag);
      const ciphertextHash = await sha256Hex(ciphertext);
      const plaintextHash = await sha256Hex(plaintext);

      const form = new FormData();
      form.append("originalName", file.name);
      form.append("ivB64", b64FromBytes(iv));
      form.append("tagB64", b64FromBytes(tag));
      form.append("ciphertextHash", ciphertextHash);
      form.append("plaintextHash", plaintextHash);
      form.append("plaintextSize", String(plaintext.byteLength));
      form.append("ciphertextSize", String(ciphertext.byteLength));
      form.append(
        "cipher",
        new Blob([ciphertext], { type: "application/octet-stream" }),
        `${file.name}.enc`
      );

      setStatus("Uploading ciphertext only...");

      const response = await fetch(`${API}/upload-ciphertext`, {
        method: "POST",
        body: form,
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error || "Private upload failed");
      }

      setLastEncryptionKey(b64FromBytes(rawKey));
      setStatus(
        `Privacy-preserving upload completed: ${data.name}. Server stores ciphertext only.`
      );
      setFile(null);
      await refresh();
    } catch (err) {
      console.error(err);
      setStatus(`Private upload failed: ${err.message || "Local encryption error"}`);
    }
  }


  async function downloadAndDecrypt(fileMeta) {
    try {
      setDecryptStatus((prev) => ({
        ...prev,
        [fileMeta.id]: "Downloading ciphertext...",
      }));

      if (fileMeta.storageMode !== "ciphertext") {
        throw new Error("This file is not stored as ciphertext");
      }

      const keyInput = decryptKeys[fileMeta.id] || "";
      const rawKey = normalizeKeyInput(keyInput);

      if (rawKey.length !== 32) {
        throw new Error("AES-256 key must be exactly 32 bytes");
      }

      const response = await fetch(`${API}/files/${fileMeta.id}`);
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || "Failed to download ciphertext");
      }

      const ciphertext = new Uint8Array(await response.arrayBuffer());
      const iv = bytesFromB64(fileMeta.encryption?.ivB64 || "");
      const tag = bytesFromB64(fileMeta.encryption?.tagB64 || "");

      if (iv.length !== 12) {
        throw new Error("Invalid IV metadata");
      }

      if (tag.length !== 16) {
        throw new Error("Invalid authentication tag metadata");
      }

      const aesKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // Web Crypto expects ciphertext and authentication tag concatenated.
      const cipherWithTag = new Uint8Array(ciphertext.length + tag.length);
      cipherWithTag.set(ciphertext, 0);
      cipherWithTag.set(tag, ciphertext.length);

      setDecryptStatus((prev) => ({
        ...prev,
        [fileMeta.id]: "Decrypting locally...",
      }));

      let plaintextBuffer;
      try {
        plaintextBuffer = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv,
            tagLength: 128,
          },
          aesKey,
          cipherWithTag
        );
      } catch {
        throw new Error(
          "AES-GCM authentication failed. The key is wrong or the ciphertext/tag was modified."
        );
      }

      const plaintext = new Uint8Array(plaintextBuffer);
      const computedPlaintextHash = await sha256Hex(plaintext);

      if (
        fileMeta.plaintextHash &&
        computedPlaintextHash !== fileMeta.plaintextHash
      ) {
        throw new Error(
          "Plaintext hash verification failed after decryption."
        );
      }

      const blob = new Blob([plaintext], {
        type: "application/octet-stream",
      });

      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = fileMeta.originalName || "decrypted-file";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(objectUrl);

      setDecryptStatus((prev) => ({
        ...prev,
        [fileMeta.id]:
          "PASS: decrypted locally and plaintext hash verified.",
      }));
    } catch (error) {
      console.error(error);
      setDecryptStatus((prev) => ({
        ...prev,
        [fileMeta.id]: `FAIL: ${error.message || "Decryption failed"}`,
      }));
    }
  }

  async function refreshPoRepStatus(fileId) {
    try {
      setStatus("Refreshing PoRep status...");

      const r = await fetch(`${API}/files/${fileId}/porep/status`);
      const data = await r.json();

      if (!r.ok) {
        setStatus(data?.error || "Failed to refresh PoRep status");
        return;
      }

      setStatus("PoRep status refreshed");
      await refresh();
    } catch (e) {
      console.error(e);
      setStatus("Failed to refresh PoRep status");
    }
  }

  async function verifyPoRep(fileId) {
    try {
      setStatus("Verifying PoRep...");
      const r = await fetch(`${API}/files/${fileId}/porep/verify`, {
        method: "POST",
      });
      const data = await r.json();

      if (!r.ok) {
        setStatus(data?.error || "Verify failed");
        return;
      }

      setStatus(data?.message || "Verification finished");
      await refresh();
    } catch (e) {
      console.error(e);
      setStatus("Verify request failed");
    }
  }

  async function runPostChallenge(fileId) {
    try {
      setStatus("Running PoSt-like challenge...");

      const r = await fetch(`${API}/files/${fileId}/post/challenge`, {
        method: "POST",
      });
      const data = await r.json();

      if (!r.ok) {
        setStatus(data?.error || "PoSt-like challenge failed");
        return;
      }

      const passed =
        data.challenge?.passed ??
        data.challenge?.verified ??
        data.postVerified ??
        false;

      setStatus(passed ? "PoSt-like challenge PASS" : "PoSt-like challenge FAIL");
      await refresh();
    } catch (e) {
      console.error(e);
      setStatus(`PoSt-like challenge error: ${e.message}`);
    }
  }

  async function runRealWindowPost(id) {
    try {
      setStatus("Running Real WindowPoSt...");

      const res = await fetch(`${API}/files/${id}/post/window`, {
        method: "POST",
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data?.error || "Real WindowPoSt failed");
      }

      setStatus(
        data.realPost?.verified
          ? "Real WindowPoSt PASS"
          : "Real WindowPoSt FAIL"
      );

      await refresh();
    } catch (e) {
      setStatus(`Real WindowPoSt error: ${e.message}`);
    }
  }


  async function deleteFile(fileMeta) {
    const confirmed = window.confirm(
      `Delete "${fileMeta.originalName}"?\n\nThis will also delete its PoRep cache.`
    );

    if (!confirmed) return;

    try {
      setStatus(`Deleting ${fileMeta.originalName}...`);

      const res = await fetch(
        `${API}/files/${fileMeta.id}`,
        {
          method: "DELETE",
        }
      );

      const data = await res.json();

      if (!res.ok) {
        throw new Error(
          data?.error || "Delete failed"
        );
      }

      setStatus(
        `Deleted: ${fileMeta.originalName}`
      );

      await refresh();
    } catch (e) {
      console.error(e);

      setStatus(
        `Delete failed: ${e.message}`
      );
    }
  }

    async function generateCryptographicVc(fileId) {
    try {
      setStatus(
        "Generating real RISC Zero proof... This may take several minutes."
      );

      const response = await fetch(
        `${API}/files/${fileId}/computation/vc/prove`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.cryptographicVc?.error ||
          data?.error ||
          data?.message ||
          "VC proof generation failed"
        );
      }

      setStatus(
        `Cryptographic VC proof generated in ${Number(
          data.cryptographicVc?.generationSeconds || 0
        ).toFixed(2)} seconds`
      );

      await refresh();
    } catch (error) {
      console.error(error);

      setStatus(
        `VC proof generation failed: ${error.message}`
      );

      await refresh();
    }
  }

  async function verifyCryptographicVc(fileId) {
    try {
      setStatus("Verifying cryptographic VC proof...");

      const response = await fetch(
        `${API}/files/${fileId}/computation/vc/verify`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.cryptographicVc?.error ||
          data?.error ||
          data?.message ||
          "VC proof verification failed"
        );
      }

      setStatus(
        data.verified
          ? "Cryptographic VC verification PASS"
          : "Cryptographic VC verification FAIL"
      );

      await refresh();
    } catch (error) {
      console.error(error);

      setStatus(
        `VC proof verification failed: ${error.message}`
      );

      await refresh();
    }
  }

  async function verifyPreprocessing(fileId) {
    try {
      setStatus("Running Verifiable Pre-processing...");

      const res = await fetch(
        `${API}/files/${fileId}/computation/verify-preprocessing`,
        {
          method: "POST",
        }
      );

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data?.error || "Verification failed");
      }

      setStatus(
        data.verified
          ? "Verifiable Pre-processing PASS"
          : "Verifiable Pre-processing FAIL"
      );

      await refresh();
    } catch (e) {
      console.error(e);
      setStatus(`Verification error: ${e.message}`);
    }
  }

  async function refreshPreprocessingStatus(fileId) {
  try {
    setStatus("Refreshing Verifiable Pre-processing status...");

    const res = await fetch(
      `${API}/files/${fileId}/computation`
    );

    const data = await res.json();

    if (!res.ok) {
      throw new Error(
        data?.error ||
        "Failed to refresh preprocessing status"
      );
    }

    await refresh();

    setStatus(
      data.computation?.sectorization?.verified === true
        ? "Verifiable Pre-processing status: PASS"
        : data.computation?.sectorization?.verified === false
          ? "Verifiable Pre-processing status: FAIL"
          : "Verifiable Pre-processing has not been verified yet"
    );
  } catch (e) {
    console.error(e);

    setStatus(
      `Failed to refresh preprocessing status: ${e.message}`
    );
  }
}


  return (
    <div
      style={{
        maxWidth: 1100,
        margin: "0 auto",
        padding: "32px 20px 60px",
        fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
        color: "#1f2937",
      }}
    >
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ margin: 0, fontSize: 32 }}>
          Privacy-Preserving Verifiable Storage System
        </h1>
        <p style={{ marginTop: 8, color: "#6b7280", fontSize: 15 }}>
          Compare normal secure upload with client-side encrypted storage.
        </p>
      </div>

      <form
        onSubmit={uploadFile}
        style={{
          marginBottom: 20,
          padding: 20,
          border: "1px solid #e5e7eb",
          borderRadius: 14,
          background: "#ffffff",
          boxShadow: "0 4px 16px rgba(0,0,0,0.04)",
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: 12 }}>
          1. Choose storage mode
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
            gap: 12,
            marginBottom: 16,
          }}
        >
          <label
            style={{
              display: "block",
              padding: 14,
              border:
                uploadMode === "normal"
                  ? "2px solid #2563eb"
                  : "1px solid #d1d5db",
              borderRadius: 10,
              cursor: "pointer",
              background: uploadMode === "normal" ? "#eff6ff" : "#ffffff",
            }}
          >
            <input
              type="radio"
              name="uploadMode"
              value="normal"
              checked={uploadMode === "normal"}
              onChange={(e) => setUploadMode(e.target.value)}
              style={{ marginRight: 8 }}
            />
            <strong>Normal Upload</strong>
            <div style={{ marginTop: 8, fontSize: 13, color: "#6b7280" }}>
              ML-KEM + AES protects transmission. Server decrypts and stores plaintext.
            </div>
          </label>

          <label
            style={{
              display: "block",
              padding: 14,
              border:
                uploadMode === "private"
                  ? "2px solid #059669"
                  : "1px solid #d1d5db",
              borderRadius: 10,
              cursor: "pointer",
              background: uploadMode === "private" ? "#ecfdf5" : "#ffffff",
            }}
          >
            <input
              type="radio"
              name="uploadMode"
              value="private"
              checked={uploadMode === "private"}
              onChange={(e) => setUploadMode(e.target.value)}
              style={{ marginRight: 8 }}
            />
            <strong>Privacy-Preserving Upload</strong>
            <div style={{ marginTop: 8, fontSize: 13, color: "#6b7280" }}>
              Browser encrypts locally. Server stores ciphertext only.
            </div>
          </label>
        </div>

        <div style={{ fontWeight: 700, marginBottom: 10 }}>
          2. Select a file
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <input
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />

          <button
            type="submit"
            style={{
              padding: "10px 22px",
              border: "none",
              borderRadius: 8,
              background: uploadMode === "private" ? "#059669" : "#2563eb",
              color: "#ffffff",
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            Upload
          </button>
        </div>
      </form>

      {status && (
        <div
          style={{
            marginBottom: 18,
            padding: "12px 14px",
            borderRadius: 10,
            background: status.includes("failed") || status.includes("FAIL")
              ? "#fef2f2"
              : "#f3f4f6",
            border: status.includes("failed") || status.includes("FAIL")
              ? "1px solid #fecaca"
              : "1px solid #e5e7eb",
          }}
        >
          {status}
        </div>
      )}

      {lastEncryptionKey && (
        <div
          style={{
            marginBottom: 16,
            padding: 12,
            border: "2px solid #cc8800",
            borderRadius: 8,
            background: "#fff8e1",
            wordBreak: "break-all",
          }}
        >
          <div>
            <strong>Decryption Key — save this now</strong>
          </div>
          <div style={{ marginTop: 8, fontFamily: "monospace" }}>
            {lastEncryptionKey}
          </div>
          <button
            type="button"
            style={{ marginTop: 8 }}
            onClick={() => navigator.clipboard.writeText(lastEncryptionKey)}
          >
            Copy Key
          </button>
          <div style={{ marginTop: 8, fontSize: 12 }}>
            This key is not uploaded to the server.
          </div>
        </div>
      )}

      <div style={{ marginTop: 28, marginBottom: 14 }}>
        <h2 style={{ margin: 0 }}>Stored Files</h2>
        <div style={{ color: "#6b7280", fontSize: 14, marginTop: 4 }}>
          PoRep and PoSt operate on the stored object shown below.
        </div>
      </div>

      {files.length === 0 && <div>No files uploaded yet.</div>}

      <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
        {files.map((f) => (
          <li
            key={f.id}
            style={{
              marginBottom: 20,
              padding: 20,
              border: "1px solid #e5e7eb",
              borderRadius: 14,
              background: "#ffffff",
              boxShadow: "0 4px 16px rgba(0,0,0,0.04)",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 12,
              }}
            >
              <div>
                <strong>{f.originalName}</strong>{" "}
                ({Math.round((f.size || 0) / 1024)} KB)
              </div>

              <button
                type="button"
                onClick={() => deleteFile(f)}
                style={{
                  padding: "6px 12px",
                  border: "1px solid #ef4444",
                  borderRadius: 7,
                  background: "#fff",
                  color: "#dc2626",
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                Delete
              </button>
            </div>

            <div
              style={{
                display: "flex",
                gap: 8,
                flexWrap: "wrap",
                marginTop: 10,
                marginBottom: 12,
              }}
            >
              <span
                style={{
                  padding: "4px 9px",
                  borderRadius: 999,
                  fontSize: 12,
                  fontWeight: 700,
                  background:
                    f.uploadMode === "private" ? "#d1fae5" : "#dbeafe",
                  color:
                    f.uploadMode === "private" ? "#065f46" : "#1e40af",
                }}
              >
                {f.uploadMode === "private"
                  ? "Privacy-Preserving"
                  : "Normal Upload"}
              </span>

              <span
                style={{
                  padding: "4px 9px",
                  borderRadius: 999,
                  fontSize: 12,
                  fontWeight: 700,
                  background: "#f3f4f6",
                }}
              >
                Stored as {f.storageMode === "ciphertext" ? "Ciphertext" : "Plaintext"}
              </span>

              <span
                style={{
                  padding: "4px 9px",
                  borderRadius: 999,
                  fontSize: 12,
                  fontWeight: 700,
                  background:
                    f.serverCanDecrypt === false ? "#dcfce7" : "#fee2e2",
                  color:
                    f.serverCanDecrypt === false ? "#166534" : "#991b1b",
                }}
              >
                Server can decrypt: {String(f.serverCanDecrypt ?? true)}
              </span>
            </div>

            <div style={{ marginTop: 8 }}>
              {f.storageMode === "ciphertext" ? (
                <>
                  <a href={`${API}/files/${f.id}`}>Download Ciphertext</a>

                  <div style={{ marginTop: 10 }}>
                    <input
                      type="text"
                      placeholder="Paste Base64 decryption key"
                      value={decryptKeys[f.id] || ""}
                      onChange={(e) =>
                        setDecryptKeys((prev) => ({
                          ...prev,
                          [f.id]: e.target.value,
                        }))
                      }
                      style={{
                        width: "min(520px, 90%)",
                        padding: 8,
                        fontFamily: "monospace",
                      }}
                    />

                    <button
                      type="button"
                      onClick={() => downloadAndDecrypt(f)}
                      style={{ marginLeft: 8 }}
                    >
                      Download & Decrypt
                    </button>
                  </div>

                  {decryptStatus[f.id] && (
                    <div
                      style={{
                        marginTop: 8,
                        fontSize: 13,
                        color: decryptStatus[f.id].startsWith("FAIL")
                          ? "crimson"
                          : decryptStatus[f.id].startsWith("PASS")
                            ? "green"
                            : "inherit",
                      }}
                    >
                      {decryptStatus[f.id]}
                    </div>
                  )}
                </>
              ) : (
                <a href={`${API}/files/${f.id}`}>Download Plaintext</a>
              )}
            </div>

            <div style={{ marginTop: 10 }}>
              <strong>PoRep</strong>
            </div>

            <div style={{ marginTop: 4 }}>
              State: <strong>{f.porep?.state || "N/A"}</strong>
            </div>

            {f.porep?.jobId && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                jobId: {f.porep.jobId}
              </div>
            )}

            {f.porep?.commD && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                commD: {shortHash(f.porep.commD)}
              </div>
            )}

            {f.porep?.commR && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                commR: {shortHash(f.porep.commR)}
              </div>
            )}

            {f.porep?.verified !== null && f.porep?.verified !== undefined && (
              <div style={{ marginTop: 4 }}>
                Verified: <strong>{String(f.porep.verified)}</strong>
              </div>
            )}

            {f.porep?.verifyMessage && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                {f.porep.verifyMessage}
              </div>
            )}

            {f.porep?.error && (
              <div style={{ color: "red", marginTop: 4 }}>
                Error: {f.porep.error}
              </div>
            )}

            {f.computation?.sectorization && (
              <div
                style={{
                  marginTop: 12,
                  padding: 10,
                  background: "#f8fafc",
                  borderRadius: 8,
                  fontSize: 13,
                }}
              >
                <strong>Verifiable Pre-processing</strong>

                <div>
                  Verified:
                  <strong>
                    {" "}
                    {String(f.computation.sectorization.verified)}
                  </strong>
                </div>

                <div>
                  Sector Count:
                  {" "}
                  {f.computation.sectorization.actualSectorCount}
                  {" / "}
                  {f.computation.sectorization.expectedSectorCount}
                </div>

                <div>
                  Sector Size:
                  {" "}
                  {f.computation.sectorization.sectorSize}
                  {" Bytes"}
                </div>

                <div>
                  Content Verified:
                  {" "}
                  {String(f.computation.sectorization.sectorContentVerified)}
                </div>

                <div>
                  Padding Verified:
                  {" "}
                  {String(f.computation.sectorization.paddingVerified)}
                </div>

                <div>
                  Reconstruction:
                  {" "}
                  {String(f.computation.sectorization.reconstructionVerified)}
                </div>

                <div>
                  Client Commitment Matched:
                  {" "}
                  {String(f.computation.sectorization.clientCommitmentMatched)}
                </div>

                <div>
                  PoRep Job Binding:
                  {" "}
                  <strong>
                    {String(f.computation.sectorization.porepInputBindingVerified)}
                  </strong>
                </div>

                <div>
                  Sector Inputs Bound:
                  {" "}
                  {String(f.computation.sectorization.sectorInputsMatched)}
                </div>

                {f.computation.sectorization.error && (
                  <div style={{ color: "crimson", marginTop: 4 }}>
                    Error: {f.computation.sectorization.error}
                  </div>
                )}
              </div>
            )}
                        {f.computation?.cryptographicVc && (
              <div
                style={{
                  marginTop: 12,
                  padding: 12,
                  background: "#f5f3ff",
                  border: "1px solid #ddd6fe",
                  borderRadius: 8,
                  fontSize: 13,
                }}
              >
                <strong>
                  Cryptographic VC — RISC Zero
                </strong>

                <div style={{ marginTop: 6 }}>
                  State:{" "}
                  <strong>
                    {f.computation.cryptographicVc.state ||
                      "NOT_GENERATED"}
                  </strong>
                </div>

                <div>
                  Real Proof Generated:{" "}
                  <strong>
                    {String(
                      f.computation.cryptographicVc.generated
                    )}
                  </strong>
                </div>

                <div>
                  Cryptographically Verified:{" "}
                  <strong>
                    {f.computation.cryptographicVc.verified === null
                      ? "NOT_VERIFIED"
                      : String(
                          f.computation.cryptographicVc.verified
                        )}
                  </strong>
                </div>

                <div>
                  Proof Type:{" "}
                  {f.computation.cryptographicVc.proofType}
                </div>

                {f.computation.cryptographicVc
                  .generationSeconds != null && (
                  <div>
                    Generation Time:{" "}
                    {Number(
                      f.computation.cryptographicVc
                        .generationSeconds
                    ).toFixed(2)}{" "}
                    seconds
                  </div>
                )}

                {f.computation.cryptographicVc
                  .receiptSize != null && (
                  <div>
                    Receipt Size:{" "}
                    {(
                      f.computation.cryptographicVc
                        .receiptSize / 1024
                    ).toFixed(1)}{" "}
                    KiB
                  </div>
                )}

                {f.computation.cryptographicVc.error && (
                  <div
                    style={{
                      color: "crimson",
                      marginTop: 4,
                    }}
                  >
                    Error:{" "}
                    {f.computation.cryptographicVc.error}
                  </div>
                )}

                <div
                  style={{
                    marginTop: 10,
                    color: "#6b7280",
                  }}
                >
                  Real CPU proving may take several minutes.
                </div>

                <div style={{ marginTop: 10 }}>
                  <button
                    type="button"
                    onClick={() =>
                      generateCryptographicVc(f.id)
                    }
                    disabled={
                      f.computation.cryptographicVc.state ===
                      "PROVING"
                    }
                    style={{ marginRight: 8 }}
                  >
                    Generate Real VC Proof
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      verifyCryptographicVc(f.id)
                    }
                    disabled={
                      !f.computation.cryptographicVc.generated
                    }
                  >
                    Verify VC Proof
                  </button>
                </div>
              </div>
            )}
            <div style={{ marginTop: 8 }}>
              <button
                onClick={() => refreshPoRepStatus(f.id)}
                style={{ marginRight: 8 }}
              >
                Refresh PoRep Status
              </button>
              <button
                onClick={() => refreshPreprocessingStatus(f.id)}
                style={{ marginRight: 8 }}
              >
                Refresh Pre-processing
              </button>
              <button
                  onClick={() => verifyPreprocessing(f.id)}
                  style={{ marginRight: 8 }}
              >
                  Verify Pre-processing
              </button>
              <button
                onClick={() => verifyPoRep(f.id)}
                disabled={f.porep?.state !== "proved"}
              >
                Verify PoRep
              </button>
            </div>

            <div style={{ marginTop: 14 }}>
              <strong>PoSt-like Challenge</strong>
            </div>

            <div style={{ marginTop: 4 }}>
              Status:{" "}
              <strong>{f.post?.latestStatus || "NOT_CHALLENGED"}</strong>
            </div>

            {f.post?.latestCheckedAt && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                Last check: {formatTime(f.post.latestCheckedAt)}
              </div>
            )}

            {f.post?.latestMessage && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                {f.post.latestMessage}
              </div>
            )}

            <div style={{ marginTop: 8 }}>
              <button onClick={() => runPostChallenge(f.id)}>
                Run PoSt Challenge
              </button>
              <button
                onClick={() => runRealWindowPost(f.id)}
                disabled={f.porep?.state !== "proved"}
                style={{ marginLeft: 8 }}
              >
                Run Real WindowPoSt
              </button>
            </div>

            <div style={{ marginTop: 6 }}>
              Real WindowPoSt:{" "}
              <strong>{f.realPost?.latestStatus || "NOT_RUN"}</strong>
            </div>

            {f.realPost?.latestCheckedAt && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                Last Real WindowPoSt check: {formatTime(f.realPost.latestCheckedAt)}
              </div>
            )}

            {f.realPost?.verified !== undefined && (
              <div style={{ fontSize: 12, marginTop: 4 }}>
                Verified: <strong>{String(f.realPost.verified)}</strong>, Sector Count:{" "}
                {f.realPost.sectorCount}
              </div>
            )}

            {f.post?.challengeHistory?.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <strong>Challenge History</strong>
                <table
                  border="1"
                  cellPadding="6"
                  style={{
                    marginTop: 6,
                    borderCollapse: "collapse",
                    fontSize: 12,
                  }}
                >
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Result</th>
                      <th>Current Size</th>
                      <th>Current Hash</th>
                      <th>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {f.post.challengeHistory.map((c) => (
                      <tr key={c.challengeId}>
                        <td>{formatTime(c.checkedAt)}</td>
                        <td>{c.result}</td>
                        <td>{c.currentSize ?? "N/A"}</td>
                        <td>{shortHash(c.currentHash)}</td>
                        <td>{c.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
