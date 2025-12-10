// server.js (ESM)
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import https from 'https';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import selfsigned from 'selfsigned';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middlewares
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Simple storage dir
const storageDir = path.join(__dirname, 'storage');
fs.mkdirSync(storageDir, { recursive: true });

// Multer for file upload
const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, storageDir),
    filename: (_, file, cb) => cb(null, file.originalname),
  }),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
});

// Routes
app.get('/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.get('/api/files', (req, res) => {
  const files = fs.readdirSync(storageDir).map((name) => {
    const p = path.join(storageDir, name);
    const st = fs.statSync(p);
    return { name, size: st.size, mtime: st.mtimeMs };
  });
  res.json({ files });
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Missing file field "file"' });
  res.json({ ok: true, name: req.file.originalname, size: req.file.size });
});

app.get('/api/download/:name', (req, res) => {
  const safeName = path.basename(req.params.name);
  const filePath = path.join(storageDir, safeName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  res.sendFile(filePath);
});

// Server start (HTTP/HTTPS)
const useHttps = (process.env.USE_HTTPS ?? 'true').toLowerCase() !== 'false';
const PORT = Number(process.env.PORT) || 4000;

function start() {
  if (useHttps) {
    const keyPath = path.join(__dirname, 'dev-key.pem');
    const certPath = path.join(__dirname, 'dev-cert.pem');

    let key, cert;
    try {
      key = fs.readFileSync(keyPath);
      cert = fs.readFileSync(certPath);
    } catch {
      console.log('No dev cert found — generating self-signed cert...');
      const pems = selfsigned.generate(
        [{ name: 'commonName', value: 'localhost' }],
        { days: 365 }
      );
      fs.writeFileSync(keyPath, pems.private);
      fs.writeFileSync(certPath, pems.cert);
      key = pems.private;
      cert = pems.cert;
    }

    https.createServer({ key, cert }, app).listen(PORT, () => {
      console.log(`HTTPS server at https://localhost:${PORT}`);
    });
  } else {
    http.createServer(app).listen(PORT, () => {
      console.log(`HTTP server at http://localhost:${PORT}`);
    });
  }
}

start();
