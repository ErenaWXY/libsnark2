// server/index.js
import express from "express";
import cors from "cors";
import multer from "multer";
import { v4 as uuid } from "uuid";
import path from "path";
import fs from "fs";
import crypto from "crypto";

import { mlkemKeypair, mlkemDecapsulate } from "./pqkem.js";

const app = express();
const PORT = 4000;

app.use(cors({ origin: "http://localhost:5173" })); // adjust for your FE origin
app.use(express.json({ limit: "2mb" }));

const uploadDisk = multer({ dest: "uploads_tmp" });
const uploadMem = multer({ storage: multer.memoryStorage() });

const UPLOAD_DIR = path.resolve("uploads_plain");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Simple in-memory “DB”
const files = new Map();

// Store server-side ML-KEM secret keys by keyId (short-lived)
const kemKeys = new Map(); // keyId -> { sk: Uint8Array, pk: Uint8Array, createdAt: number }
const KEM_TTL_MS = 10 * 60 * 1000; // 10 minutes

function cleanupKemKeys() {
  const now = Date.now();
  for (const [keyId, obj] of kemKeys.entries()) {
    if (now - obj.createdAt > KEM_TTL_MS) kemKeys.delete(keyId);
  }
}

function safeName(name) {
  return String(name || "file.bin").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function hkdfAesKey(sharedSecretBytes) {
  // sharedSecretBytes: Buffer | Uint8Array
  const ss = Buffer.from(sharedSecretBytes);
  return crypto.hkdfSync(
    "sha256",
    ss,
    Buffer.alloc(0),
    Buffer.from("pq-upload-aes-256-key"),
    32 // 32 bytes = AES-256
  );
}

function decryptAes256Gcm({ key32, iv, ciphertext, tag }) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key32, iv);
  decipher.setAuthTag(tag);
  const p1 = decipher.update(ciphertext);
  const p2 = decipher.final();
  return Buffer.concat([p1, p2]);
}

/**
 * PQ handshake: server generates a fresh ML-KEM keypair and returns pk to client.
 * Client does encapsulate(pk) -> (ct, ss) and sends ct + AES-GCM encrypted file.
 */
app.get("/kem-pubkey", async (req, res) => {
  cleanupKemKeys();

  const { pk, sk } = await mlkemKeypair(); // Uint8Array, Uint8Array
  const keyId = uuid();

  kemKeys.set(keyId, { pk, sk, createdAt: Date.now() });

  res.json({
    keyId,
    kem: "ML-KEM",
    pkB64: Buffer.from(pk).toString("base64"),
    ttlSeconds: Math.floor(KEM_TTL_MS / 1000),
  });
});

/**
 * Upload encrypted (PQ application-layer):
 * multipart form-data fields:
 * - keyId: string
 * - kemCtB64: base64(ML-KEM ciphertext)
 * - ivB64: base64(12 bytes)
 * - tagB64: base64(16 bytes)
 * - originalName: string
 * - cipher: file (binary)  <-- AES-GCM ciphertext without tag
 */
app.post("/upload-pq", uploadMem.single("cipher"), async (req, res) => {
  try {
    cleanupKemKeys();

    const { keyId, kemCtB64, ivB64, tagB64, originalName } = req.body;
    if (!keyId || !kemCtB64 || !ivB64 || !tagB64 || !req.file?.buffer) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const kemObj = kemKeys.get(keyId);
    if (!kemObj) return res.status(404).json({ error: "KEM key expired/invalid" });

    const kemCt = Buffer.from(kemCtB64, "base64");
    const iv = Buffer.from(ivB64, "base64");
    const tag = Buffer.from(tagB64, "base64");
    const ciphertext = Buffer.from(req.file.buffer);

    if (iv.length !== 12) return res.status(400).json({ error: "IV must be 12 bytes" });
    if (tag.length !== 16) return res.status(400).json({ error: "Tag must be 16 bytes" });

    // Decapsulate -> shared secret
    const sharedSecret = await mlkemDecapsulate(new Uint8Array(kemCt), kemObj.sk);

    // Derive AES-256 key
    const key32 = hkdfAesKey(sharedSecret);

    // Decrypt to plaintext (stored unencrypted)
    const plaintext = decryptAes256Gcm({ key32, iv, ciphertext, tag });

    // Save plaintext on disk
    const id = uuid();
    const safeOriginal = safeName(originalName);
    const storedName = `${id}__${safeOriginal}`;
    const outPath = path.join(UPLOAD_DIR, storedName);
    fs.writeFileSync(outPath, plaintext);

    files.set(id, {
      id,
      originalName: safeOriginal,
      storedName,
      size: plaintext.length,
      uploadedAt: new Date().toISOString(),
    });

    // one-time use keyId (recommended)
    kemKeys.delete(keyId);

    res.json({
      id,
      name: safeOriginal,
      size: plaintext.length,
      downloadUrl: `http://localhost:${PORT}/files/${id}`,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Decrypt/upload failed" });
  }
});

// List plaintext files
app.get("/files", (req, res) => {
  res.json(Array.from(files.values()));
});

// Download plaintext file
app.get("/files/:id", (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  const filePath = path.resolve(UPLOAD_DIR, meta.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Missing on disk" });

  res.download(filePath, meta.originalName);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
