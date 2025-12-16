// server/pqkem.js
// TEMP WORKING KEM-LIKE IMPLEMENTATION (ECDH P-256)
// -------------------------------------------------
// This is NOT post-quantum. It is a placeholder so your system works end-to-end:
// /kem-pubkey -> returns a public key
// client "encapsulates" by sending its ephemeral public key as ct
// server "decapsulates" using ECDH to derive the same shared secret
//
// Later, swap these functions with real ML-KEM keypair/decapsulate.

import crypto from "crypto";

export async function mlkemKeypair() {
  const ecdh = crypto.createECDH("prime256v1"); // P-256
  ecdh.generateKeys();

  const pk = new Uint8Array(ecdh.getPublicKey());  // raw uncompressed point
  const sk = new Uint8Array(ecdh.getPrivateKey()); // private key bytes
  return { pk, sk };
}

export async function mlkemDecapsulate(ct, sk) {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(sk));

  // ct is the client's ephemeral public key in this placeholder
  const shared = ecdh.computeSecret(Buffer.from(ct)); // 32 bytes
  return new Uint8Array(shared);
}
