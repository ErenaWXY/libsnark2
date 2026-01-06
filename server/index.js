// server/index.js (TLS 1.3 ONLY - Requirement 2a)
import express from "express";
import cors from "cors";
import multer from "multer";
import { v4 as uuid } from "uuid";
import path from "path";
import fs from "fs";
import https from "https";

const app = express();
const PORT = 4000;

// If Vite runs at http://localhost:5173 keep this.
// If you switch Vite to https later, change accordingly.
app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json({ limit: "2mb" }));

// Use memory upload; we will write plaintext to disk ourselves
const uploadMem = multer({ storage: multer.memoryStorage() });

const UPLOAD_DIR = path.resolve("uploads_plain");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// In-memory metadata store
const files = new Map();

function safeName(name) {
  return String(name || "file.bin").replace(/[^a-zA-Z0-9._-]/g, "_");
}

// Evidence for report: log TLS protocol & cipher for each request
app.use((req, res, next) => {
  const s = req.socket;
  if (typeof s.getProtocol === "function") {
    console.log("TLS protocol:", s.getProtocol()); // expect TLSv1.3
    if (typeof s.getCipher === "function") console.log("TLS cipher:", s.getCipher());
  }
  next();
});

/**
 * Upload PLAINTEXT over TLS (TLS provides encryption in transit).
 * multipart form-data:
 * - file: uploaded file (plaintext)
 */
app.post("/upload", uploadMem.single("file"), async (req, res) => {
  try {
    if (!req.file?.buffer) return res.status(400).json({ error: "Missing file" });

    const id = uuid();
    const originalName = safeName(req.file.originalname || "file.bin");
    const storedName = `${id}__${originalName}`;
    const outPath = path.join(UPLOAD_DIR, storedName);

    // Store plaintext on disk (requirement: unencrypted server-side)
    fs.writeFileSync(outPath, req.file.buffer);

    const meta = {
      id,
      originalName,
      storedName,
      size: req.file.buffer.length,
      uploadedAt: new Date().toISOString(),
    };
    files.set(id, meta);

    res.json({
      id,
      name: originalName,
      size: meta.size,
      downloadUrl: `https://localhost:${PORT}/files/${id}`,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Upload failed" });
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

// TLS 1.3 HTTPS server
const tlsOptions = {
  pfx: fs.readFileSync(path.resolve("certs/localhost.pfx")),
  passphrase: process.env.TLS_PFX_PASSPHRASE || "changeit",
  minVersion: "TLSv1.3",
  maxVersion: "TLSv1.3",
  // TLS 1.3 AES-256-GCM suite (good evidence for AES-256 in transit)
  ciphersuites: ["TLS_AES_256_GCM_SHA384"],
};

https.createServer(tlsOptions, app).listen(PORT, () => {
  console.log(`TLS1.3 server running on https://localhost:${PORT}`);
});