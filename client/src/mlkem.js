// client/src/mlkem.js
// TEMP WORKING "encapsulate" using WebCrypto ECDH P-256
// NOT post-quantum. Placeholder until ML-KEM WASM is integrated.

let ready = false;

export async function mlkemInit() {
  ready = true;
}

export async function mlkemEncapsulate(serverPkBytes) {
  if (!ready) await mlkemInit();

  // generate ephemeral ECDH keypair
  const clientKeys = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  // import server public key (raw point)
  const serverPubKey = await crypto.subtle.importKey(
    "raw",
    serverPkBytes,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  // derive shared secret (256 bits)
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPubKey },
    clientKeys.privateKey,
    256
  );

  // ct = client's ephemeral public key
  const clientPubRaw = await crypto.subtle.exportKey("raw", clientKeys.publicKey);

  return {
    ct: new Uint8Array(clientPubRaw),
    sharedSecret: new Uint8Array(bits),
  };
}
