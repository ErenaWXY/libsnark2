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
const POREP_API = "http://127.0.0.1:8787";

app.use(cors({
  origin: ["http://localhost:5173", "http://127.0.0.1:5173"]
}));
app.use(express.json({ limit: "2mb" }));

const uploadMem = multer({ storage: multer.memoryStorage() });

const UPLOAD_DIR = path.resolve("uploads_plain");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Simple in-memory DB
const files = new Map();

// Store server-side ML-KEM secret keys by keyId (short-lived)
const kemKeys = new Map();
const KEM_TTL_MS = 10 * 60 * 1000;

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
  const ss = Buffer.from(sharedSecretBytes);
  return crypto.hkdfSync(
    "sha256",
    ss,
    Buffer.alloc(0),
    Buffer.from("pq-upload-aes-256-key"),
    32
  );
}

function decryptAes256Gcm({ key32, iv, ciphertext, tag }) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key32, iv);
  decipher.setAuthTag(tag);
  const p1 = decipher.update(ciphertext);
  const p2 = decipher.final();
  return Buffer.concat([p1, p2]);
}

async function startPoRepSeal(fileMeta, outPath) {
  try {
    fileMeta.porep.state = "sealing";
    fileMeta.porep.error = null;

    const r = await fetch(`${POREP_API}/seal-file`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_id: fileMeta.id,
        path: outPath,
      }),
    });

    const data = await r.json();

    if (!r.ok) {
      fileMeta.porep.state = "failed";
      fileMeta.porep.error = data?.error || "seal-file failed";
      return;
    }

    fileMeta.porep.jobId = data.job_id;
    fileMeta.porep.state = data.state || "sealing";
    fileMeta.porep.cacheDir = data.cache_dir || null;
  } catch (e) {
    console.error("PoRep seal-file error:", e);
    fileMeta.porep.state = "failed";
    fileMeta.porep.error = String(e.message || e);
  }
}

app.get("/kem-pubkey", async (req, res) => {
  cleanupKemKeys();

  const { pk, sk } = await mlkemKeypair();
  const keyId = uuid();

  kemKeys.set(keyId, { pk, sk, createdAt: Date.now() });

  res.json({
    keyId,
    kem: "ML-KEM",
    pkB64: Buffer.from(pk).toString("base64"),
    ttlSeconds: Math.floor(KEM_TTL_MS / 1000),
  });
});

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

    const sharedSecret = await mlkemDecapsulate(new Uint8Array(kemCt), kemObj.sk);
    const key32 = hkdfAesKey(sharedSecret);
    const plaintext = decryptAes256Gcm({ key32, iv, ciphertext, tag });

    const id = uuid();
    const safeOriginal = safeName(originalName);
    const storedName = `${id}__${safeOriginal}`;
    const outPath = path.join(UPLOAD_DIR, storedName);
    fs.writeFileSync(outPath, plaintext);

    const meta = {
      id,
      originalName: safeOriginal,
      storedName,
      size: plaintext.length,
      uploadedAt: new Date().toISOString(),
      porep: {
        state: "pending",
        jobId: null,
        commD: null,
        commR: null,
        proof: null,
        sealedAt: null,
        verified: null,
        verifyMessage: null,
        error: null,
      },
    };

    files.set(id, meta);

    kemKeys.delete(keyId);

    // fire-and-forget seal
    startPoRepSeal(meta, outPath);

    res.json({
      id,
      name: safeOriginal,
      size: plaintext.length,
      porepState: meta.porep.state,
      downloadUrl: `http://localhost:${PORT}/files/${id}`,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Decrypt/upload failed" });
  }
});

app.get("/files", (req, res) => {
  res.json(Array.from(files.values()));
});

app.get("/files/:id", (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  const filePath = path.resolve(UPLOAD_DIR, meta.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Missing on disk" });

  res.download(filePath, meta.originalName);
});

app.get("/files/:id/porep/status", async (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  if (!meta.porep?.jobId) {
    return res.json({
      id: meta.id,
      porep: meta.porep,
    });
  }

  try {
    const r = await fetch(`${POREP_API}/jobs/${meta.porep.jobId}`);
    const data = await r.json();

    if (r.ok) {
      meta.porep.state = data.state || meta.porep.state;
      meta.porep.commD = data.comm_d || meta.porep.commD;
      meta.porep.commR = data.comm_r || meta.porep.commR;
      meta.porep.proof = data.proof || meta.porep.proof;
      meta.porep.error = data.error || meta.porep.error;
    }

    res.json({
      id: meta.id,
      porep: meta.porep,
    });
  } catch (e) {
    res.status(500).json({ error: "Failed to query PoRep status" });
if (r.ok) {
  meta.porep.state = data.state || meta.porep.state;
  meta.porep.error = data.error || meta.porep.error;
  meta.porep.cacheDir = data.cache_dir || meta.porep.cacheDir;
  meta.porep.helperStdout = data.stdout || meta.porep.helperStdout;
  meta.porep.helperStderr = data.stderr || meta.porep.helperStderr;
}  }
});

app.post("/files/:id/porep/verify", async (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  if (!meta.porep?.jobId) {
    return res.status(400).json({ error: "PoRep job not ready" });
  }

  try {
    const r = await fetch(`${POREP_API}/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: meta.porep.jobId,
      }),
    });

    const data = await r.json();

    if (!r.ok) {
      return res.status(500).json({ error: data?.error || "Verify failed" });
    }

    meta.porep.verified = !!data.ok;
    meta.porep.verifyMessage = data.message || null;

    res.json({
      id: meta.id,
      verified: meta.porep.verified,
      message: meta.porep.verifyMessage,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to verify PoRep" });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
