// server/client_cli.mjs
import fs from "fs";
import crypto from "crypto";

import {
  mlkem768Encapsulate,
  MLKEM768_CT_BYTES,
  MLKEM768_SS_BYTES,
} from "./mlkem768.js";

const API = "http://localhost:4000";

function hkdfAesKey(ss) {
  return crypto.hkdfSync(
    "sha256",
    Buffer.from(ss),
    Buffer.alloc(0),
    Buffer.from("pq-upload-aes-256-key"),
    32
  );
}

function encryptAes256Gcm(key32, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key32, iv);
  const c1 = cipher.update(plaintext);
  const c2 = cipher.final();
  const tag = cipher.getAuthTag(); // 16 bytes
  return { iv, ciphertext: Buffer.concat([c1, c2]), tag };
}

function safeBaseName(p) {
  return p.split(/[\\/]/).pop() || "file.bin";
}

async function main() {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error("Usage: node client_cli.mjs <path_to_file>");
    process.exit(1);
  }

  // 1) get server pk
  const r1 = await fetch(`${API}/kem-pubkey`);
  const j1 = await r1.json();
  if (!r1.ok) throw new Error(`kem-pubkey failed: ${JSON.stringify(j1)}`);

  const { keyId, pkB64 } = j1;
  const pk = Buffer.from(pkB64, "base64");

  // 2) ML-KEM-768 encapsulate(pk) => (ct, ss)
  const { ct, sharedSecret } = mlkem768Encapsulate(pk);

  console.log("[CLIENT ML-KEM-768] ct bytes =", ct.length, "(expected", MLKEM768_CT_BYTES + ")",
              "ss bytes =", sharedSecret.length, "(expected", MLKEM768_SS_BYTES + ")");

  // 3) HKDF(ss) => AES-256 key; encrypt file with AES-256-GCM
  const plain = fs.readFileSync(filePath);
  const key32 = hkdfAesKey(sharedSecret);
  const { iv, ciphertext, tag } = encryptAes256Gcm(key32, plain);

  // 4) upload ciphertext + KEM ct
  const form = new FormData();
  form.append("keyId", keyId);
  form.append("kemCtB64", Buffer.from(ct).toString("base64"));
  form.append("ivB64", iv.toString("base64"));
  form.append("tagB64", tag.toString("base64"));
  form.append("originalName", safeBaseName(filePath));
  form.append("cipher", new Blob([ciphertext]), "cipher.bin");

  const r2 = await fetch(`${API}/upload-pq`, { method: "POST", body: form });
  const txt = await r2.text();

  console.log("Upload status:", r2.status);
  console.log("Response:", txt);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
