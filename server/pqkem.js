// server/pqkem.js (ML-KEM-768 via WASM in ./wasm, IMPORTED_MEMORY)
// Fix: provide Module.HEAPU8 for EM_JS randombytes(), ensure global crypto.getRandomValues exists.

import path from "path";
import { fileURLToPath, pathToFileURL } from "url";
import nodeCrypto from "crypto";

const PK_LEN = 1184;
const SK_LEN = 2400;
const CT_LEN = 1088;
const SS_LEN = 32;

// Node: ensure WebCrypto getRandomValues exists (used by EM_JS)
if (!globalThis.crypto?.getRandomValues) {
  globalThis.crypto = nodeCrypto.webcrypto;
}

// IMPORTANT: must match module declared max (yours is 1024 pages = 64MB)
const wasmMemory = new WebAssembly.Memory({ initial: 1024, maximum: 1024 });

let modulePromise = null;

async function getModule() {
  if (modulePromise) return modulePromise;

  modulePromise = (async () => {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const mjsPath = path.join(__dirname, "wasm", "mlkem768.mjs");
    const mjsUrl = pathToFileURL(mjsPath).href;

    const ns = await import(mjsUrl);
    const factory = ns.default ?? ns;
    if (typeof factory !== "function") {
      throw new Error("mlkem768.mjs does not export an Emscripten factory function");
    }

    let Module = await factory({
      locateFile: (p) => path.join(__dirname, "wasm", p),
      wasmMemory, // because you built with IMPORTED_MEMORY=1
    });

    if (Module && typeof Module.ready?.then === "function") {
      Module = await Module.ready;
    }

    if (typeof Module._malloc !== "function" || typeof Module._free !== "function") {
      throw new Error("Missing export: _malloc/_free");
    }
    if (typeof Module._mlkem768_keypair_export !== "function") {
      throw new Error("Missing export: _mlkem768_keypair_export");
    }
    if (typeof Module._mlkem768_decapsulate !== "function") {
      throw new Error("Missing export: _mlkem768_decapsulate");
    }

    // CRITICAL FIX: EM_JS randombytes() expects Module.HEAPU8 to exist
    Module.HEAPU8 = new Uint8Array(wasmMemory.buffer);

    // helper: always return a fresh view (safe if memory ever grows)
    Module.__heapU8 = () => new Uint8Array(wasmMemory.buffer);

    return Module;
  })();

  return modulePromise;
}

export async function mlkemKeypair() {
  const M = await getModule();

  const pkPtr = M._malloc(PK_LEN);
  const skPtr = M._malloc(SK_LEN);

  try {
    const rc = M._mlkem768_keypair_export(pkPtr, PK_LEN, skPtr, SK_LEN);
    if (rc !== 0) throw new Error(`mlkem768_keypair_export failed rc=${rc}`);

    const heap = M.__heapU8();
    return {
      pk: heap.slice(pkPtr, pkPtr + PK_LEN),
      sk: heap.slice(skPtr, skPtr + SK_LEN),
    };
  } finally {
    M._free(pkPtr);
    M._free(skPtr);
  }
}

export async function mlkemDecapsulate(ctBytes, skBytes) {
  const M = await getModule();

  const ct = ctBytes instanceof Uint8Array ? ctBytes : new Uint8Array(ctBytes);
  const sk = skBytes instanceof Uint8Array ? skBytes : new Uint8Array(skBytes);

  if (ct.length !== CT_LEN) throw new Error(`Expected ct length ${CT_LEN}, got ${ct.length}`);
  if (sk.length !== SK_LEN) throw new Error(`Expected sk length ${SK_LEN}, got ${sk.length}`);

  const ctPtr = M._malloc(CT_LEN);
  const skPtr = M._malloc(SK_LEN);
  const ssPtr = M._malloc(SS_LEN);

  try {
    let heap = M.__heapU8();
    heap.set(ct, ctPtr);
    heap.set(sk, skPtr);

    const rc = M._mlkem768_decapsulate(ctPtr, CT_LEN, skPtr, SK_LEN, ssPtr, SS_LEN);
    if (rc !== 0) throw new Error(`mlkem768_decapsulate failed rc=${rc}`);

    heap = M.__heapU8();
    return heap.slice(ssPtr, ssPtr + SS_LEN);
  } finally {
    M._free(ctPtr);
    M._free(skPtr);
    M._free(ssPtr);
  }
}
