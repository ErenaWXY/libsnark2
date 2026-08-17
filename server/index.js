import express from "express";
import cors from "cors";
import multer from "multer";
import { v4 as uuid } from "uuid";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import http from "http";

import { mlkemKeypair, mlkemDecapsulate } from "./pqkem.js";

const app = express();
const PORT = 4000;
const POREP_API = "http://127.0.0.1:8787";

app.use(
  cors({
    origin: ["http://localhost:5173", "http://127.0.0.1:5173"],
  })
);
app.use(express.json({ limit: "2mb" }));

const uploadMem = multer({ storage: multer.memoryStorage() });

const UPLOAD_DIR = path.resolve("uploads_plain");
const CIPHER_UPLOAD_DIR = path.resolve("uploads_cipher");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(CIPHER_UPLOAD_DIR, { recursive: true });

// Simple in-memory DB
const files = new Map();

// Store server-side ML-KEM secret keys by keyId
const kemKeys = new Map();
const KEM_TTL_MS = 10 * 60 * 1000;

function cleanupKemKeys() {
  const now = Date.now();
  for (const [keyId, obj] of kemKeys.entries()) {
    if (now - obj.createdAt > KEM_TTL_MS) kemKeys.delete(keyId);
  }
}

function sha256File(filePath) {
  const data = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(data).digest("hex");
}

function sha256Buffer(buffer) {
  return crypto
    .createHash("sha256")
    .update(buffer)
    .digest("hex");
}

function safeName(name) {
  return String(name || "file.bin").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function getFilePath(meta) {
  const baseDir =
    meta.storageMode === "ciphertext"
      ? CIPHER_UPLOAD_DIR
      : UPLOAD_DIR;

  return path.resolve(baseDir, meta.storedName);
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

function postJsonWithoutTimeout(url) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      url,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
        },
      },
      (response) => {
        let body = "";

        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
        });

        response.on("end", () => {
          try {
            resolve({
              ok:
                response.statusCode >= 200 &&
                response.statusCode < 300,
              data: body ? JSON.parse(body) : {},
            });
          } catch {
            reject(
              new Error(
                `Invalid response from proof service: ${body}`
              )
            );
          }
        });
      }
    );

    request.on("error", reject);

    request.setTimeout(15 * 60 * 1000, () => {
      request.destroy(
        new Error("VC proving exceeded 15 minutes")
      );
    });

    request.end();
  });
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

function createComputationMeta() {
  return {
    uploadIntegrity: {
      clientCiphertextHash: null,
      serverCiphertextHash: null,
      clientCiphertextSize: null,
      serverCiphertextSize: null,
      hashMatched: null,
      sizeMatched: null,
      verified: null,
      checkedAt: null,
    },

    sectorization: {
      sectorSize: 2048,

      expectedSectorCount: null,
      actualSectorCount: null,

      inputHash: null,
      reconstructionHash: null,

      sectorSizesVerified: null,
      sectorContentVerified: null,
      paddingVerified: null,
      reconstructionVerified: null,

      verified: null,
      checkedAt: null,
      error: null,
    },

    commitments: {
      state: "pending",

      jobId: null,
      sectorId: null,
      proverId: null,

      commD: null,
      commR: null,
      sectors: [],

      bindingVerified: null,

      checkedAt: null,
    },

    cryptographicVc: {
      state: "NOT_GENERATED",
      proofType: "RISC0_CRYPTOGRAPHIC_PREPROCESSING",

      jobId: null,
      generated: false,
      verified: null,

      receiptPath: null,
      receiptSize: null,
      generationSeconds: null,

      generatedAt: null,
      verifiedAt: null,

      verifierOutput: null,
      error: null,
    },

    storageProof: {
      porepVerified: null,
      windowPostVerified: null,
      commitmentMatched: null,
      checkedAt: null,
    },

    retrieval: {
      decryptedLocally: null,
      plaintextHashMatched: null,
      checkedAt: null,
    },
  };
}

async function verifyPreprocessing(meta) {
  const sectorSize = 2048;
  const checkedAt = new Date().toISOString();

  const result = {
    sectorSize,

    expectedSectorCount: null,
    actualSectorCount: null,

    inputHash: null,
    reconstructionHash: null,

    sectorSizesVerified: false,
    sectorContentVerified: false,
    paddingVerified: false,
    reconstructionVerified: false,

    clientCommitmentMatched: false,
    jobIdMatched: false,
    fileIdMatched: false,
    inputPathMatched: false,
    cacheDirMatched: false,
    jobInputHashMatched: false,
    jobSectorParametersMatched: false,
    sectorInputsMatched: false,
    poRepCommitmentsPresent: false,
    porepInputBindingVerified: false,

    verified: false,
    checkedAt,
    error: null,
  };

  try {
    const inputPath = getFilePath(meta);

    if (!fs.existsSync(inputPath)) {
      throw new Error("Original input file is missing.");
    }

    if (!meta.porep?.cacheDir) {
      throw new Error("PoRep cache directory is not available.");
    }

    if (!meta.porep?.jobId) {
      throw new Error("PoRep job ID is not available.");
    }

    if (!fs.existsSync(meta.porep.cacheDir)) {
      throw new Error(
        `PoRep cache directory does not exist: ${meta.porep.cacheDir}`
      );
    }

    const inputData = fs.readFileSync(inputPath);
    const inputSize = inputData.length;

    const expectedSectorCount =
      Math.ceil(inputSize / sectorSize);

    result.expectedSectorCount = expectedSectorCount;
    result.inputHash = sha256Buffer(inputData);

    // The upload commitment is the client-supplied ciphertext hash in private
    // mode, and the original stored-object hash in normal mode.
    const clientCommittedHash =
      meta.computation?.uploadIntegrity?.clientCiphertextHash ||
      meta.originalHash;

    result.clientCommitmentMatched =
      Boolean(clientCommittedHash) &&
      result.inputHash === clientCommittedHash &&
      meta.computation?.uploadIntegrity?.verified === true;

    const jobResponse = await fetch(
      `${POREP_API}/jobs/${meta.porep.jobId}`
    );
    const job = await jobResponse.json();

    if (!jobResponse.ok) {
      throw new Error(job?.error || "Unable to query the PoRep job for input binding.");
    }

    const resolvedInputPath = fs.realpathSync(inputPath);
    const resolvedCacheDir = fs.realpathSync(meta.porep.cacheDir);

    result.jobIdMatched = job.job_id === meta.porep.jobId;
    result.fileIdMatched = job.file_id === meta.id;
    result.inputPathMatched =
      Boolean(job.input_path) &&
      fs.existsSync(job.input_path) &&
      fs.realpathSync(job.input_path) === resolvedInputPath;
    result.cacheDirMatched =
      Boolean(job.cache_dir) &&
      fs.existsSync(job.cache_dir) &&
      fs.realpathSync(job.cache_dir) === resolvedCacheDir;
    result.jobInputHashMatched =
      Boolean(job.input_hash) &&
      job.input_hash === result.inputHash &&
      job.input_hash === clientCommittedHash;

    /*
     * Rust writes files in this format:
     *
     * cacheDir/sector_0.bin
     * cacheDir/sector_1.bin
     * cacheDir/sector_2.bin
     */
    const sectorFiles = fs
      .readdirSync(meta.porep.cacheDir)
      .filter((name) => /^sector_\d+\.bin$/.test(name))
      .sort((a, b) => {
        const aIndex = Number(
          a.match(/^sector_(\d+)\.bin$/)?.[1]
        );

        const bIndex = Number(
          b.match(/^sector_(\d+)\.bin$/)?.[1]
        );

        return aIndex - bIndex;
      });

    result.actualSectorCount = sectorFiles.length;

    result.jobSectorParametersMatched =
      job.sector_size === sectorSize &&
      job.sector_count === expectedSectorCount;

    if (sectorFiles.length !== expectedSectorCount) {
      throw new Error(
        `Sector count mismatch: expected ${expectedSectorCount}, actual ${sectorFiles.length}.`
      );
    }

    let sectorSizesVerified = true;
    let sectorContentVerified = true;
    let paddingVerified = true;

    const reconstructedParts = [];

    for (
      let sectorIndex = 0;
      sectorIndex < sectorFiles.length;
      sectorIndex++
    ) {
      const sectorFileName = sectorFiles[sectorIndex];

      if (sectorFileName !== `sector_${sectorIndex}.bin`) {
        sectorContentVerified = false;
      }

      const sectorPath = path.join(
        meta.porep.cacheDir,
        sectorFileName
      );

      const sectorData = fs.readFileSync(sectorPath);

      /*
       * Every stored sector must be exactly 2048 bytes.
       */
      if (sectorData.length !== sectorSize) {
        sectorSizesVerified = false;
      }

      const start = sectorIndex * sectorSize;

      const end = Math.min(
        start + sectorSize,
        inputSize
      );

      const expectedContent = inputData.subarray(
        start,
        end
      );

      const actualContent = sectorData.subarray(
        0,
        expectedContent.length
      );

      /*
       * Verify that the non-padding part of the sector
       * is identical to the corresponding input bytes.
       */
      if (!actualContent.equals(expectedContent)) {
        sectorContentVerified = false;
      }

      /*
       * For the final partial sector, all remaining bytes
       * must be zero padding.
       */
      const padding = sectorData.subarray(
        expectedContent.length
      );

      const allPaddingBytesAreZero = padding.every(
        (byte) => byte === 0
      );

      if (!allPaddingBytesAreZero) {
        paddingVerified = false;
      }

      reconstructedParts.push(actualContent);
    }

    const sectorRecords = Array.isArray(job.sector_records)
      ? job.sector_records
      : [];

    result.sectorInputsMatched =
      sectorRecords.length === sectorFiles.length &&
      sectorFiles.every((sectorFileName, sectorIndex) => {
        const record = sectorRecords.find(
          (item) => item.sector_index === sectorIndex
        );
        const sectorPath = path.join(meta.porep.cacheDir, sectorFileName);

        return Boolean(record) &&
          record.input_path &&
          fs.existsSync(record.input_path) &&
          fs.realpathSync(record.input_path) === fs.realpathSync(sectorPath) &&
          record.input_hash === sha256File(sectorPath);
      });

    result.poRepCommitmentsPresent =
      job.state === "proved" &&
      sectorRecords.length === expectedSectorCount &&
      sectorRecords.every(
        (record) => Boolean(record.comm_d) && Boolean(record.comm_r)
      );

    result.porepInputBindingVerified =
      result.clientCommitmentMatched &&
      result.jobIdMatched &&
      result.fileIdMatched &&
      result.inputPathMatched &&
      result.cacheDirMatched &&
      result.jobInputHashMatched &&
      result.jobSectorParametersMatched &&
      result.sectorInputsMatched &&
      job.sectorization_verified === true;

    const reconstructedData = Buffer.concat(
      reconstructedParts
    );

    result.reconstructionHash =
      sha256Buffer(reconstructedData);

    result.sectorSizesVerified =
      sectorSizesVerified;

    result.sectorContentVerified =
      sectorContentVerified;

    result.paddingVerified =
      paddingVerified;

    result.reconstructionVerified =
      reconstructedData.equals(inputData) &&
      result.reconstructionHash === result.inputHash;

    result.verified =
      result.actualSectorCount ===
        result.expectedSectorCount &&
      result.sectorSizesVerified &&
      result.sectorContentVerified &&
      result.paddingVerified &&
      result.reconstructionVerified &&
      result.porepInputBindingVerified;

    result.job = {
      jobId: job.job_id,
      fileId: job.file_id,
      state: job.state,
      inputHash: job.input_hash,
      sectorCount: job.sector_count,
      sectorCommitments: sectorRecords.map((record) => ({
        sectorIndex: record.sector_index,
        inputHash: record.input_hash,
        commD: record.comm_d,
        commR: record.comm_r,
        sectorId: record.sector_id,
        proverId: record.prover_id,
      })),
    };

    return result;
  } catch (error) {
    result.error = String(
      error?.message || error
    );

    return result;
  }
}

function ensurePostMeta(meta) {
  if (!meta.post) {
    meta.post = {
      latestStatus: "NOT_CHALLENGED",
      latestCheckedAt: null,
      latestMessage: null,
      challengeHistory: [],
    };
  }

  if (!Array.isArray(meta.post.challengeHistory)) {
    meta.post.challengeHistory = [];
  }
}

function runPostLikeChallenge(meta) {
  ensurePostMeta(meta);

  const challengeId = uuid();
  const checkedAt = new Date().toISOString();
  const nonce = crypto.randomBytes(16).toString("hex");

  const filePath = getFilePath(meta);
  const fileExists = fs.existsSync(filePath);

  let currentHash = null;
  let currentSize = null;
  let passed = false;
  let message = "";

  if (!fileExists) {
    message = "PoSt-like failed: file is missing on disk.";
  } else {
    const stat = fs.statSync(filePath);
    currentSize = stat.size;
    currentHash = sha256File(filePath);

    passed = currentHash === meta.originalHash && currentSize === meta.size;

    message = passed
      ? "PoSt-like verified: file still exists and hash is unchanged."
      : "PoSt-like failed: file content or size has changed.";
  }

  const record = {
    challengeId,
    nonce,
    checkedAt,
    result: passed ? "PASS" : "FAIL",
    passed,
    fileExists,
    expectedSize: meta.size,
    currentSize,
    originalHash: meta.originalHash,
    currentHash,
    message,
  };

  meta.post.latestStatus = record.result;
  meta.post.latestCheckedAt = checkedAt;
  meta.post.latestMessage = message;
  meta.post.challengeHistory.unshift(record);
  meta.post.challengeHistory = meta.post.challengeHistory.slice(0, 20);

  return record;
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
    if (!kemObj) {
      return res.status(404).json({ error: "KEM key expired/invalid" });
    }

    const kemCt = Buffer.from(kemCtB64, "base64");
    const iv = Buffer.from(ivB64, "base64");
    const tag = Buffer.from(tagB64, "base64");
    const ciphertext = Buffer.from(req.file.buffer);

    if (iv.length !== 12) {
      return res.status(400).json({ error: "IV must be 12 bytes" });
    }
    if (tag.length !== 16) {
      return res.status(400).json({ error: "Tag must be 16 bytes" });
    }

    const sharedSecret = await mlkemDecapsulate(new Uint8Array(kemCt), kemObj.sk);
    const key32 = hkdfAesKey(sharedSecret);
    const plaintext = decryptAes256Gcm({ key32, iv, ciphertext, tag });

    const id = uuid();
    const safeOriginal = safeName(originalName);
    const storedName = `${id}__${safeOriginal}`;
    const outPath = path.join(UPLOAD_DIR, storedName);

    fs.writeFileSync(outPath, plaintext);
    const originalHash = sha256File(outPath);

    const meta = {
      id,
      originalName: safeOriginal,
      storedName,
      size: plaintext.length,
      uploadedAt: new Date().toISOString(),
      originalHash,
      storageMode: "plaintext",
      uploadMode: "normal",
      serverCanDecrypt: true,

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
        cacheDir: null,
        helperStdout: null,
        helperStderr: null,
      },

      post: {
        latestStatus: "NOT_CHALLENGED",
        latestCheckedAt: null,
        latestMessage: null,
        challengeHistory: [],
      },

      computation: createComputationMeta(),

    };

    meta.computation.uploadIntegrity = {
      clientCiphertextHash: null,
      serverCiphertextHash: originalHash,
      ciphertextSize: plaintext.length,
      hashMatched: true,
      sizeMatched: true,
      verified: true,
      checkedAt: new Date().toISOString(),
    };

    files.set(id, meta);
    kemKeys.delete(keyId);

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

app.post(
  "/upload-ciphertext",
  uploadMem.single("cipher"),
  async (req, res) => {
    try {
      const {
        originalName,
        ivB64,
        tagB64,
        ciphertextHash,
        plaintextHash,
        plaintextSize,
        ciphertextSize,
      } = req.body;

      if (
        !originalName ||
        !ivB64 ||
        !tagB64 ||
        !ciphertextHash ||
        !req.file?.buffer
      ) {
        return res.status(400).json({
          error: "Missing ciphertext upload fields",
        });
      }

      const ciphertext = Buffer.from(req.file.buffer);

      const computedCiphertextHash = crypto
        .createHash("sha256")
        .update(ciphertext)
        .digest("hex");

      if (computedCiphertextHash !== ciphertextHash) {
        return res.status(400).json({
          error: "Ciphertext hash mismatch",
        });
      }

      const id = uuid();

      const safeOriginal = safeName(originalName);

      const storedName = `${id}__${safeOriginal}.enc`;

      const outPath = path.join(
        CIPHER_UPLOAD_DIR,
        storedName
      );

      fs.writeFileSync(outPath, ciphertext);

      const meta = {
        id,

        originalName: safeOriginal,

        storedName,

        size: ciphertext.length,

        ciphertextSize: ciphertext.length,

        plaintextSize:
          plaintextSize == null
            ? null
            : Number(plaintextSize),

        uploadedAt: new Date().toISOString(),

        originalHash: computedCiphertextHash,

        ciphertextHash: computedCiphertextHash,

        plaintextHash,

        storageMode: "ciphertext",

        uploadMode: "private",

        serverCanDecrypt: false,

        encryption: {
          algorithm: "AES-256-GCM",
          ivB64,
          tagB64,
          keyLocation: "CLIENT_ONLY",
        },

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
          cacheDir: null,
          helperStdout: null,
          helperStderr: null,
        },

        post: {
          latestStatus: "NOT_CHALLENGED",
          latestCheckedAt: null,
          latestMessage: null,
          challengeHistory: [],
        },

        computation: createComputationMeta(),

      };

      const sizeMatched =
        !ciphertextSize ||
        Number(ciphertextSize) === ciphertext.length;

      meta.computation.uploadIntegrity = {
        clientCiphertextHash: ciphertextHash,
        serverCiphertextHash: computedCiphertextHash,

        clientCiphertextSize:
          ciphertextSize == null
            ? null
            : Number(ciphertextSize),

        serverCiphertextSize:
          ciphertext.length,

        hashMatched:
          ciphertextHash === computedCiphertextHash,

        sizeMatched,

        verified:
          ciphertextHash === computedCiphertextHash &&
          sizeMatched,

        checkedAt:
          new Date().toISOString(),
      };

      files.set(id, meta);

      startPoRepSeal(meta, outPath);

      return res.json({
        id,

        name: safeOriginal,

        size: ciphertext.length,

        uploadMode: "private",

        storageMode: "ciphertext",

        serverCanDecrypt: false,

        porepState: meta.porep.state,

        downloadUrl: `http://localhost:${PORT}/files/${id}`,
      });
    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error: "Ciphertext upload failed",
      });
    }
  }
);

app.get("/files", (req, res) => {
  res.json(Array.from(files.values()));
});

app.delete("/files/:id", (req, res) => {
  const meta = files.get(req.params.id);

  if (!meta) {
    return res.status(404).json({
      error: "File not found",
    });
  }

  try {
    // 1. 删除实际保存的 plaintext / ciphertext
    const filePath = getFilePath(meta);

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // 2. 删除整个 PoRep cache
    if (
      meta.porep?.cacheDir &&
      fs.existsSync(meta.porep.cacheDir)
    ) {
      fs.rmSync(meta.porep.cacheDir, {
        recursive: true,
        force: true,
      });
    }

    // 3. 删除内存 metadata
    files.delete(meta.id);

    return res.json({
      deleted: true,
      id: meta.id,
      fileName: meta.originalName,
      message: "File, metadata and PoRep cache deleted.",
    });
  } catch (e) {
    console.error("Delete file failed:", e);

    return res.status(500).json({
      error: "Delete file failed",
      message: String(e.message || e),
    });
  }
});

app.get("/files/:id", (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  const filePath = getFilePath(meta);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Missing on disk" });
  }

  const downloadName =
    meta.storageMode === "ciphertext"
      ? `${meta.originalName}.enc`  
      : meta.originalName;

  res.download(filePath, downloadName);
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
        if (!meta.computation) {
          meta.computation = createComputationMeta();
        }

        meta.computation.commitments.state =
          meta.porep.state;

        meta.computation.commitments.jobId =
          meta.porep.jobId;

        meta.computation.commitments.commD =
          data.comm_d || meta.porep.commD || null;

        meta.computation.commitments.commR =
          data.comm_r || meta.porep.commR || null;

        meta.computation.commitments.sectorId =
          data.sector_id ?? null;

        meta.computation.commitments.proverId =
          data.prover_id ?? null;

        meta.computation.commitments.checkedAt =
          new Date().toISOString();
      meta.porep.proof = data.proof || meta.porep.proof;
      meta.porep.error = data.error || meta.porep.error;
      meta.porep.cacheDir = data.cache_dir || meta.porep.cacheDir;
      meta.porep.helperStdout = data.stdout || meta.porep.helperStdout;
      meta.porep.helperStderr = data.stderr || meta.porep.helperStderr;
    }

    return res.json({
      id: meta.id,
      porep: meta.porep,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to query PoRep status" });
  }
});

app.post("/files/:id/porep/verify", async (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  if (!meta.porep?.jobId) {
    return res.status(400).json({ error: "PoRep job not ready" });
  }

  const filePath = getFilePath(meta);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "File missing on disk" });
  }

  const currentHash = sha256File(filePath);
  if (currentHash !== meta.originalHash) {
    meta.porep.verified = false;
    meta.porep.verifyMessage = "File has been modified after PoRep was generated.";

    return res.json({
      id: meta.id,
      verified: false,
      message: meta.porep.verifyMessage,
    });
  }

  try {
    const r = await fetch(`${POREP_API}/jobs/${meta.porep.jobId}`);
    const data = await r.json();

    if (!r.ok) {
      return res.status(500).json({
        error: data?.error || "Failed to query PoRep job",
      });
    }

    meta.porep.state = data.state || meta.porep.state;
    meta.porep.commD = data.comm_d || meta.porep.commD;
    meta.porep.commR = data.comm_r || meta.porep.commR;
    meta.porep.proof = data.proof || meta.porep.proof;
    meta.porep.cacheDir = data.cache_dir || meta.porep.cacheDir;
    meta.porep.helperStdout = data.stdout || meta.porep.helperStdout;
    meta.porep.helperStderr = data.stderr || meta.porep.helperStderr;

    const ok = meta.porep.state === "proved";

    meta.porep.verified = ok;
    if (!meta.computation) {
      meta.computation = createComputationMeta();
    }

    meta.computation.storageProof.porepVerified = ok;
    meta.computation.storageProof.checkedAt =
      new Date().toISOString();
    meta.porep.verifyMessage = ok
      ? "PoRep job is proved."
      : `PoRep job is not proved yet. Current state: ${meta.porep.state}`;

    return res.json({
      id: meta.id,
      verified: ok,
      message: meta.porep.verifyMessage,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to verify PoRep" });
  }
});

app.post("/files/:id/post/challenge", (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  if (!meta.originalHash) {
    return res.status(400).json({ error: "Original file commitment is missing" });
  }

  try {
    const challenge = runPostLikeChallenge(meta);
    return res.json({
      id: meta.id,
      fileName: meta.originalName,
      post: meta.post,
      challenge,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "PoSt-like challenge failed" });
  }
});


app.post("/files/:id/post/window", async (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  if (!meta.porep?.jobId) {
    return res.status(400).json({ error: "PoRep job not ready" });
  }

  if (meta.porep?.state !== "proved") {
    return res.status(400).json({
      error: `PoRep job is not proved yet. Current state: ${meta.porep?.state}`,
    });
  }

  try {
    const r = await fetch(`${POREP_API}/jobs/${meta.porep.jobId}/window-post`, {
      method: "POST",
    });

    const data = await r.json();

    if (!r.ok) {
      return res.status(500).json({
        error: data?.error || "Real WindowPoSt failed",
        detail: data,
      });
    }

    meta.realPost = {
      latestStatus: data.verified ? "PASS" : "FAIL",
      latestCheckedAt: new Date().toISOString(),
      postType: data.post_type,
      sectorCount: data.sector_count,
      verified: data.verified,
      stdout: data.stdout,
      stderr: data.stderr,
    };

    if (!meta.computation) {
      meta.computation = createComputationMeta();
    }

    meta.computation.storageProof.windowPostVerified =
      Boolean(data.verified);

    meta.computation.storageProof.checkedAt =
      new Date().toISOString();

    return res.json({
      id: meta.id,
      fileName: meta.originalName,
      realPost: meta.realPost,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      error: "Failed to run Real WindowPoSt",
      message: String(e.message || e),
    });
  }
});

app.get("/files/:id/post/history", (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  ensurePostMeta(meta);

  return res.json({
    id: meta.id,
    fileName: meta.originalName,
    post: meta.post,
  });
});

app.get("/files/:id/post/status", (req, res) => {
  const meta = files.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "Not found" });

  ensurePostMeta(meta);

  return res.json({
    id: meta.id,
    fileName: meta.originalName,
    post: meta.post,
  });
});

app.post(
  "/files/:id/computation/vc/prove",
  async (req, res) => {
    const meta = files.get(req.params.id);

    if (!meta) {
      return res.status(404).json({
        error: "File not found",
      });
    }

    if (!meta.porep?.jobId) {
      return res.status(400).json({
        error: "PoRep job is not ready",
      });
    }

    if (meta.porep.state !== "proved") {
      return res.status(400).json({
        error: `PoRep job is not proved: ${meta.porep.state}`,
      });
    }

    if (!meta.computation) {
      meta.computation = createComputationMeta();
    }

    meta.computation.cryptographicVc.state = "PROVING";
    meta.computation.cryptographicVc.jobId =
      meta.porep.jobId;
    meta.computation.cryptographicVc.error = null;

    try {
      const { ok, data } =
        await postJsonWithoutTimeout(
          `${POREP_API}/jobs/${meta.porep.jobId}/vc/prove`
        );

      if (!ok || !data.generated) {
        meta.computation.cryptographicVc.state = "FAILED";
        meta.computation.cryptographicVc.generated = false;
        meta.computation.cryptographicVc.error =
          data?.error ||
          data?.stderr ||
          "Cryptographic VC proof generation failed";

        return res.status(500).json({
          id: meta.id,
          cryptographicVc:
            meta.computation.cryptographicVc,
          detail: data,
        });
      }

      Object.assign(
        meta.computation.cryptographicVc,
        {
          state: "GENERATED",
          proofType: data.proof_type,
          jobId: data.job_id,
          generated: true,
          verified: null,
          receiptPath: data.receipt_path,
          receiptSize: data.receipt_size,
          generationSeconds:
            data.generation_seconds,
          generatedAt:
            new Date().toISOString(),
          error: null,
        }
      );

      return res.json({
        id: meta.id,
        fileName: meta.originalName,
        cryptographicVc:
          meta.computation.cryptographicVc,
      });
    } catch (error) {
      meta.computation.cryptographicVc.state =
        "FAILED";
      meta.computation.cryptographicVc.error =
        String(error?.message || error);

      return res.status(500).json({
        error: "Failed to generate VC proof",
        message: String(error?.message || error),
      });
    }
  }
);

app.post(
  "/files/:id/computation/vc/verify",
  async (req, res) => {
    const meta = files.get(req.params.id);

    if (!meta) {
      return res.status(404).json({
        error: "File not found",
      });
    }

    if (!meta.porep?.jobId) {
      return res.status(400).json({
        error: "PoRep job is not ready",
      });
    }

    if (!meta.computation) {
      meta.computation = createComputationMeta();
    }

    try {
      const response = await fetch(
        `${POREP_API}/jobs/${meta.porep.jobId}/vc/verify`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      meta.computation.cryptographicVc.state =
        data.verified ? "VERIFIED" : "VERIFICATION_FAILED";

      meta.computation.cryptographicVc.jobId =
        meta.porep.jobId;

      meta.computation.cryptographicVc.verified =
        Boolean(data.verified);

      meta.computation.cryptographicVc.receiptPath =
        data.receipt_path || null;

      meta.computation.cryptographicVc.verifierOutput =
        data.stdout || null;

      meta.computation.cryptographicVc.verifiedAt =
        new Date().toISOString();

      meta.computation.cryptographicVc.error =
        data.verified
          ? null
          : data.stderr || "VC verification failed";

      return res.status(response.ok ? 200 : 500).json({
        id: meta.id,
        fileName: meta.originalName,
        verified: Boolean(data.verified),
        cryptographicVc:
          meta.computation.cryptographicVc,
        detail: data,
      });
    } catch (error) {
      meta.computation.cryptographicVc.state =
        "VERIFICATION_FAILED";

      meta.computation.cryptographicVc.verified =
        false;

      meta.computation.cryptographicVc.error =
        String(error?.message || error);

      return res.status(500).json({
        error: "Failed to verify VC proof",
        message: String(error?.message || error),
      });
    }
  }
);

app.post(
  "/files/:id/computation/verify-preprocessing",
  async (req, res) => {
    const meta = files.get(req.params.id);

    if (!meta) {
      return res.status(404).json({
        error: "File not found",
      });
    }

    if (!meta.computation) {
      meta.computation =
        createComputationMeta();
    }

    if (!meta.porep?.cacheDir) {
      return res.status(400).json({
        error:
          "PoRep cache is not ready. Wait for sealing to start or finish first.",
      });
    }

    const verification =
      await verifyPreprocessing(meta);

    meta.computation.sectorization =
      verification;

    meta.computation.commitments.jobId =
      meta.porep.jobId;
    meta.computation.commitments.commD =
      meta.porep.commD;
    meta.computation.commitments.commR =
      meta.porep.commR;
    meta.computation.commitments.sectors =
      verification.job?.sectorCommitments || [];
    meta.computation.commitments.bindingVerified =
      verification.porepInputBindingVerified;
    meta.computation.commitments.checkedAt =
      verification.checkedAt;

    meta.computation.storageProof.commitmentMatched =
      verification.porepInputBindingVerified;

    return res.json({
      id: meta.id,
      fileName: meta.originalName,
      uploadMode: meta.uploadMode,

      verificationType:
        "VERIFIABLE_PREPROCESSING",

      verified: verification.verified,

      sectorization: verification,
    });
  }
);

app.get("/files/:id/computation", (req, res) => {
  const meta = files.get(req.params.id);

  if (!meta) {
    return res.status(404).json({
      error: "File not found",
    });
  }

  if (!meta.computation) {
    meta.computation = createComputationMeta();
  }

  return res.json({
    id: meta.id,
    fileName: meta.originalName,
    uploadMode: meta.uploadMode,
    storageMode: meta.storageMode,
    computation: meta.computation,
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
