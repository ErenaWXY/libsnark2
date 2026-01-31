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
const API_ORIGIN = "http://localhost:5173";

// ---- CORS: allow Authorization header ----
app.use(
  cors({
    origin: API_ORIGIN,
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["X-File-SHA512"],
  })
);
app.use(express.json({ limit: "2mb" }));

const uploadMem = multer({ storage: multer.memoryStorage() });

// ---- "DB" demo persistence ----
const DB_PATH = path.resolve("db.json");
function loadDb() {
  try {
    if (!fs.existsSync(DB_PATH)) return {};
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    return {};
  }
}
function saveDb(obj) {
  fs.writeFileSync(DB_PATH, JSON.stringify(obj, null, 2));
}
const db = loadDb();
if (!db.files) db.files = {};
saveDb(db);

// ---- Clients from JSON ----
const CLIENTS_JSON = path.resolve("clients.json");
function loadClients() {
  if (!fs.existsSync(CLIENTS_JSON)) throw new Error(`Missing ${CLIENTS_JSON}`);
  const arr = JSON.parse(fs.readFileSync(CLIENTS_JSON, "utf8"));
  const byUsername = new Map();
  for (const c of arr) {
    if (!c?.username || !c?.password || !c?.clientId) continue;
    byUsername.set(String(c.username), {
      clientId: String(c.clientId),
      name: String(c.name || c.clientId),
      username: String(c.username),
      password: String(c.password), // demo only
    });
  }
  return byUsername;
}
const clientsByUsername = loadClients();

// ---- Sessions (no JWT) ----
const sessions = new Map(); // token -> { clientId, name, username, expiresAt }
const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

function getBearerToken(req) {
  const auth = req.header("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function requireAuth(req, res, next) {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: "Unauthorized (missing Bearer token)" });

  const sess = sessions.get(token);
  if (!sess) return res.status(401).json({ error: "Unauthorized (invalid token)" });

  if (Date.now() > sess.expiresAt) {
    sessions.delete(token);
    return res.status(401).json({ error: "Unauthorized (token expired)" });
  }

  req.client = { clientId: sess.clientId, name: sess.name, username: sess.username };
  next();
}

// ---- Storage dirs ----
const UPLOAD_PLAIN_DIR = path.resolve("uploads_plain");
const UPLOAD_ENC_DIR = path.resolve("uploads_enc");
fs.mkdirSync(UPLOAD_PLAIN_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_ENC_DIR, { recursive: true });

function safeName(name) {
  return String(name || "file.bin").replace(/[^a-zA-Z0-9._-]/g, "_");
}

// ---- KEM key cache ----
// keyId -> { pk, sk, createdAt, ownerClientId }
const kemKeys = new Map();
const KEM_TTL_MS = 10 * 60 * 1000;
function cleanupKemKeys() {
  const now = Date.now();
  for (const [keyId, obj] of kemKeys.entries()) {
    if (now - obj.createdAt > KEM_TTL_MS) kemKeys.delete(keyId);
  }
}

// ---- App-layer key derivation (same as client) ----
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

// ---- Integrity (SHA-512 over PLAINTEXT) ----
function sha512Hex(buf) {
  return crypto.createHash("sha512").update(buf).digest("hex");
}

// ---- Server-side encryption at rest (envelope) ----
const KEK_FILE = path.resolve("kek.key");
function loadOrCreateKek() {
  const envB64 = process.env.SERVER_KEK_B64;
  if (envB64) {
    const k = Buffer.from(envB64, "base64");
    if (k.length !== 32) throw new Error("SERVER_KEK_B64 must be 32 bytes base64");
    return k;
  }
  if (fs.existsSync(KEK_FILE)) {
    const b64 = fs.readFileSync(KEK_FILE, "utf8").trim();
    const k = Buffer.from(b64, "base64");
    if (k.length !== 32) throw new Error("kek.key invalid (must be 32 bytes base64)");
    return k;
  }
  const k = crypto.randomBytes(32);
  fs.writeFileSync(KEK_FILE, k.toString("base64"));
  console.log("[KEK] Created kek.key (demo). DO NOT COMMIT it.");
  return k;
}
const KEK = loadOrCreateKek();

function aesGcmEncrypt({ key32, plaintext }) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key32, iv);
  const c1 = cipher.update(plaintext);
  const c2 = cipher.final();
  const tag = cipher.getAuthTag();
  return { iv, ciphertext: Buffer.concat([c1, c2]), tag };
}
function aesGcmDecrypt({ key32, iv, ciphertext, tag }) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key32, iv);
  decipher.setAuthTag(tag);
  const p1 = decipher.update(ciphertext);
  const p2 = decipher.final();
  return Buffer.concat([p1, p2]);
}

// wrap/unwrap DEK with KEK
function wrapDek(dek32) {
  const { iv, ciphertext, tag } = aesGcmEncrypt({ key32: KEK, plaintext: dek32 });
  return {
    wrapIvB64: iv.toString("base64"),
    wrappedDekB64: ciphertext.toString("base64"),
    wrapTagB64: tag.toString("base64"),
  };
}
function unwrapDek(encMeta) {
  const iv = Buffer.from(encMeta.wrapIvB64, "base64");
  const ciphertext = Buffer.from(encMeta.wrappedDekB64, "base64");
  const tag = Buffer.from(encMeta.wrapTagB64, "base64");
  return aesGcmDecrypt({ key32: KEK, iv, ciphertext, tag });
}

// -------------------- AUTH --------------------

// Login -> returns token (no JWT)
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = clientsByUsername.get(String(username || ""));
  if (!u || u.password !== String(password || "")) {
    return res.status(401).json({ error: "Invalid username/password" });
  }

  const token = uuid();
  sessions.set(token, {
    clientId: u.clientId,
    name: u.name,
    username: u.username,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });

  res.json({
    token,
    clientId: u.clientId,
    name: u.name,
    expiresInSeconds: Math.floor(SESSION_TTL_MS / 1000),
  });
});

app.post("/auth/logout", requireAuth, (req, res) => {
  const token = getBearerToken(req);
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// -------------------- CRYPTO + FILES --------------------

// KEM pubkey (bind to client)
app.get("/kem-pubkey", requireAuth, async (req, res) => {
  cleanupKemKeys();

  const { pk, sk } = await mlkemKeypair();
  const keyId = uuid();
  kemKeys.set(keyId, { pk, sk, createdAt: Date.now(), ownerClientId: req.client.clientId });

  res.json({
    keyId,
    kem: "ML-KEM-768",
    pkB64: Buffer.from(pk).toString("base64"),
    ttlSeconds: Math.floor(KEM_TTL_MS / 1000),
  });
});

// Upload: decapsulate+decrypt -> store plaintext + sha512
app.post("/upload-pq", requireAuth, uploadMem.single("cipher"), async (req, res) => {
  try {
    cleanupKemKeys();

    const { keyId, kemCtB64, ivB64, tagB64, originalName } = req.body;
    if (!keyId || !kemCtB64 || !ivB64 || !tagB64 || !req.file?.buffer) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const kemObj = kemKeys.get(keyId);
    if (!kemObj) return res.status(404).json({ error: "KEM key expired/invalid" });
    if (kemObj.ownerClientId !== req.client.clientId) {
      return res.status(403).json({ error: "Forbidden (keyId not owned by this user)" });
    }

    const kemCt = Buffer.from(kemCtB64, "base64");
    const iv = Buffer.from(ivB64, "base64");
    const tag = Buffer.from(tagB64, "base64");
    const ciphertext = Buffer.from(req.file.buffer);

    if (iv.length !== 12) return res.status(400).json({ error: "IV must be 12 bytes" });
    if (tag.length !== 16) return res.status(400).json({ error: "Tag must be 16 bytes" });

    const sharedSecret = await mlkemDecapsulate(new Uint8Array(kemCt), kemObj.sk);
    const key32 = hkdfAesKey(sharedSecret);
    const plaintext = decryptAes256Gcm({ key32, iv, ciphertext, tag });

    const checksum = sha512Hex(plaintext);

    const id = uuid();
    const safeOriginal = safeName(originalName);
    const storedName = `${id}__${safeOriginal}`;
    const plainPath = path.join(UPLOAD_PLAIN_DIR, storedName);
    fs.writeFileSync(plainPath, plaintext);

    db.files[id] = {
      id,
      ownerClientId: req.client.clientId,
      originalName: safeOriginal,
      size: plaintext.length,
      sha512: checksum,
      state: "PLAINTEXT",
      plainPath,
      encPath: null,
      encMeta: null,
      uploadedAt: new Date().toISOString(),
      encryptedAt: null,
    };
    saveDb(db);

    kemKeys.delete(keyId);

    res.json({ id, name: safeOriginal, size: plaintext.length, sha512: checksum, state: "PLAINTEXT" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Decrypt/upload failed" });
  }
});

// List files (per user)
app.get("/files", requireAuth, (req, res) => {
  const list = Object.values(db.files).filter((f) => f.ownerClientId === req.client.clientId);
  res.json(list);
});

// Manifest (checksum etc.)
app.get("/files/:id/manifest", requireAuth, (req, res) => {
  const meta = db.files[req.params.id];
  if (!meta) return res.status(404).json({ error: "Not found" });
  if (meta.ownerClientId !== req.client.clientId) return res.status(403).json({ error: "Forbidden" });

  res.json({
    id: meta.id,
    originalName: meta.originalName,
    size: meta.size,
    sha512: meta.sha512,
    state: meta.state,
    uploadedAt: meta.uploadedAt,
    encryptedAt: meta.encryptedAt,
  });
});

// Encrypt at rest (later time)
app.post("/files/:id/encrypt-at-rest", requireAuth, (req, res) => {
  try {
    const meta = db.files[req.params.id];
    if (!meta) return res.status(404).json({ error: "Not found" });
    if (meta.ownerClientId !== req.client.clientId) return res.status(403).json({ error: "Forbidden" });

    if (meta.state === "ENCRYPTED_AT_REST") {
      return res.json({ ok: true, state: meta.state, message: "Already encrypted" });
    }
    if (!meta.plainPath || !fs.existsSync(meta.plainPath)) {
      return res.status(404).json({ error: "Plaintext missing on disk" });
    }

    const plaintext = fs.readFileSync(meta.plainPath);

    const dek = crypto.randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt({ key32: dek, plaintext });
    const wrapped = wrapDek(dek);

    const encName = `${meta.id}__${meta.originalName}.enc`;
    const encPath = path.join(UPLOAD_ENC_DIR, encName);
    fs.writeFileSync(encPath, ciphertext);

    fs.unlinkSync(meta.plainPath);

    meta.state = "ENCRYPTED_AT_REST";
    meta.encPath = encPath;
    meta.plainPath = null;
    meta.encMeta = {
      alg: "AES-256-GCM",
      fileIvB64: iv.toString("base64"),
      fileTagB64: tag.toString("base64"),
      ...wrapped,
    };
    meta.encryptedAt = new Date().toISOString();
    saveDb(db);

    res.json({ ok: true, id: meta.id, state: meta.state, encryptedAt: meta.encryptedAt });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Encrypt-at-rest failed" });
  }
});

// Download (decrypt on-the-fly if encrypted at rest)
app.get("/files/:id", requireAuth, (req, res) => {
  const meta = db.files[req.params.id];
  if (!meta) return res.status(404).json({ error: "Not found" });
  if (meta.ownerClientId !== req.client.clientId) return res.status(403).json({ error: "Forbidden" });

  res.setHeader("X-File-SHA512", meta.sha512);

  try {
    if (meta.state === "PLAINTEXT") {
      if (!meta.plainPath || !fs.existsSync(meta.plainPath)) return res.status(404).json({ error: "Missing on disk" });
      return res.download(meta.plainPath, meta.originalName);
    }

    if (meta.state === "ENCRYPTED_AT_REST") {
      if (!meta.encPath || !fs.existsSync(meta.encPath)) return res.status(404).json({ error: "Missing encrypted blob" });

      const ciphertext = fs.readFileSync(meta.encPath);
      const dek = unwrapDek(meta.encMeta);
      const iv = Buffer.from(meta.encMeta.fileIvB64, "base64");
      const tag = Buffer.from(meta.encMeta.fileTagB64, "base64");

      const plaintext = aesGcmDecrypt({ key32: dek, iv, ciphertext, tag });

      res.setHeader("Content-Disposition", `attachment; filename="${meta.originalName}"`);
      res.setHeader("Content-Type", "application/octet-stream");
      return res.end(plaintext);
    }

    return res.status(400).json({ error: "Unknown state" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Download/decrypt failed" });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
