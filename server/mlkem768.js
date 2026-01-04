// server/mlkem768.js
import * as mlkem from "mlkem-native";

/**
 * Resolve ML-KEM-768 API from mlkem-native.
 * Package exports may differ by version/build, so we support several patterns.
 */
function resolveKem768(mod) {
  // Pattern A: mod.kem768.{keypair, encapsulate, decapsulate}
  if (mod?.kem768?.keypair && mod?.kem768?.encapsulate && mod?.kem768?.decapsulate) {
    return mod.kem768;
  }
  // Pattern B: mod.mlkem768.{keypair, encapsulate, decapsulate}
  if (mod?.mlkem768?.keypair && mod?.mlkem768?.encapsulate && mod?.mlkem768?.decapsulate) {
    return mod.mlkem768;
  }
  // Pattern C: mod.MLKEM768.{keypair, encapsulate, decapsulate}
  if (mod?.MLKEM768?.keypair && mod?.MLKEM768?.encapsulate && mod?.MLKEM768?.decapsulate) {
    return mod.MLKEM768;
  }

  // Pattern D: flat functions
  const flatCandidates = [
    ["mlkem768_keypair", "mlkem768_encapsulate", "mlkem768_decapsulate"],
    ["keypair768", "encapsulate768", "decapsulate768"],
    ["kem768_keypair", "kem768_encapsulate", "kem768_decapsulate"],
  ];

  for (const [kp, enc, dec] of flatCandidates) {
    if (typeof mod[kp] === "function" && typeof mod[enc] === "function" && typeof mod[dec] === "function") {
      return {
        keypair: () => mod[kp](),
        encapsulate: (pk) => mod[enc](pk),
        decapsulate: (ct, sk) => mod[dec](ct, sk),
      };
    }
  }

  // Pattern E: generic API e.g., mod.keypair(768) / mod.encapsulate(768, pk) ...
  if (typeof mod.keypair === "function" && typeof mod.encapsulate === "function" && typeof mod.decapsulate === "function") {
    // Try common signatures safely at runtime
    return {
      keypair: () => mod.keypair(768),
      encapsulate: (pk) => mod.encapsulate(768, pk),
      decapsulate: (ct, sk) => mod.decapsulate(768, ct, sk),
    };
  }

  throw new Error(
    "Unsupported mlkem-native API shape. Run: node --input-type=module -e \"import * as m from 'mlkem-native'; console.log(Object.keys(m)); console.log(m);\""
  );
}

const kem768 = resolveKem768(mlkem);

// Expected sizes for ML-KEM-768 (FIPS 203):
export const MLKEM768_PK_BYTES = 1184;
export const MLKEM768_SK_BYTES = 2400;
export const MLKEM768_CT_BYTES = 1088;
export const MLKEM768_SS_BYTES = 32;

function toU8(x) {
  if (x instanceof Uint8Array) return x;
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  // Some bindings may return Buffer
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(x)) return new Uint8Array(x);
  throw new Error("Cannot convert value to Uint8Array");
}

export function mlkem768Keypair() {
  const out = kem768.keypair();
  // Some libs return {pk, sk}, others return [pk, sk]
  const pk = toU8(out.pk ?? out[0]);
  const sk = toU8(out.sk ?? out[1]);

  return { pk, sk };
}

export function mlkem768Encapsulate(pkBytes) {
  const out = kem768.encapsulate(toU8(pkBytes));
  // Some libs return {ct, ss} or {ct, sharedSecret}
  const ct = toU8(out.ct ?? out.ciphertext ?? out[0]);
  const ss = toU8(out.ss ?? out.sharedSecret ?? out.secret ?? out[1]);

  return { ct, sharedSecret: ss };
}

export function mlkem768Decapsulate(ctBytes, skBytes) {
  const ss = kem768.decapsulate(toU8(ctBytes), toU8(skBytes));
  return toU8(ss);
}
