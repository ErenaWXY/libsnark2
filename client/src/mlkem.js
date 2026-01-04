// client/src/mlkem.js
// ML-KEM-768 (WASM) wrapper for browser (Vite-safe)
// Loads /public/mlkem768/mlkem768.mjs via fetch -> blob -> dynamic import.
// IMPORTANT: shim/randombytes expects Module.HEAPU8, but some Emscripten builds don't export it,
// so we derive HEAPU8 from the wasm memory buffer.

const PK_LEN = 1184;
const CT_LEN = 1088;
const SS_LEN = 32;

const MJS_PATH = "/mlkem768/mlkem768.mjs";
const WASM_PATH = "/mlkem768/mlkem768.wasm";

// Must match your module's declared max (=1024 pages = 64MB)
const wasmMemory = new WebAssembly.Memory({ initial: 1024, maximum: 1024 });

let modulePromise = null;

async function importFromPublicAsBlob(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Cannot fetch ${url} (${res.status})`);
  const code = await res.text();
  const blobUrl = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
  try {
    return await import(/* @vite-ignore */ blobUrl);
  } finally {
    URL.revokeObjectURL(blobUrl);
  }
}

function pickMemory(Module) {
  // Prefer memory that module actually uses; otherwise fall back to our imported memory.
  const mem =
    Module?.wasmMemory ||
    Module?.memory ||
    Module?.wasmExports?.memory ||
    Module?.asm?.memory ||
    wasmMemory;

  if (mem instanceof WebAssembly.Memory) return mem;
  return wasmMemory;
}

async function loadModule() {
  if (modulePromise) return modulePromise;

  modulePromise = (async () => {
    const ns = await importFromPublicAsBlob(MJS_PATH);
    const factory = ns.default ?? ns;

    if (typeof factory !== "function") {
      throw new Error("mlkem768.mjs does not export an Emscripten factory function");
    }

    let Module = await factory({
      locateFile: (p) => (p.endsWith(".wasm") ? WASM_PATH : p),
      wasmMemory, // for IMPORTED_MEMORY builds (safe even if ignored)
    });

    if (Module && typeof Module.ready?.then === "function") {
      Module = await Module.ready;
    }

    // Build HEAPU8 ourselves from memory buffer (critical for js_randombytes in shim)
    const mem = pickMemory(Module);
    const heapU8 = new Uint8Array(mem.buffer);
    Module.HEAPU8 = heapU8;
    Module.__heapU8 = () => new Uint8Array(mem.buffer); // fresh view

    // Validate exports (these MUST exist)
    if (typeof Module._mlkem768_encapsulate !== "function") {
      throw new Error("WASM missing export: _mlkem768_encapsulate");
    }
    if (typeof Module._malloc !== "function" || typeof Module._free !== "function") {
      throw new Error("WASM missing exports: _malloc/_free");
    }

    return Module;
  })();

  return modulePromise;
}

export async function mlkemInit() {
  await loadModule();
}

export async function mlkemEncapsulate(serverPkBytes) {
  const Module = await loadModule();

  const pk = serverPkBytes instanceof Uint8Array ? serverPkBytes : new Uint8Array(serverPkBytes);
  if (pk.length !== PK_LEN) {
    throw new Error(`Expected ML-KEM-768 pk length ${PK_LEN}, got ${pk.length}`);
  }

  const pkPtr = Module._malloc(PK_LEN);
  const ctPtr = Module._malloc(CT_LEN);
  const ssPtr = Module._malloc(SS_LEN);

  try {
    let heap = Module.__heapU8();
    heap.set(pk, pkPtr);

    const rc = Module._mlkem768_encapsulate(pkPtr, PK_LEN, ctPtr, CT_LEN, ssPtr, SS_LEN);
    if (rc !== 0) throw new Error(`mlkem768_encapsulate failed rc=${rc}`);

    heap = Module.__heapU8();
    return {
      ct: heap.slice(ctPtr, ctPtr + CT_LEN),
      sharedSecret: heap.slice(ssPtr, ssPtr + SS_LEN),
    };
  } finally {
    Module._free(pkPtr);
    Module._free(ctPtr);
    Module._free(ssPtr);
  }
}
