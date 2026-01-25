// wasm/shim_mlkem768.c
#include <stdint.h>
#include <stddef.h>
#include <emscripten.h>

// API follow repo mlkem-native (example monolithic_build_multilevel)
int mlkem768_keypair(uint8_t *pk, uint8_t *sk);
int mlkem768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// randomness for browser (if implementation call randombytes())
EM_JS(void, js_randombytes, (uint8_t* out, int len), {
  crypto.getRandomValues(Module.HEAPU8.subarray(out, out + len));
});
void randombytes(uint8_t* out, size_t outlen) { js_randombytes(out, (int)outlen); }

// ML-KEM-768 sizes
#define PK_LEN 1184
#define SK_LEN 2400
#define CT_LEN 1088
#define SS_LEN 32

int mlkem768_keypair_export(uint8_t* pk, int pk_len, uint8_t* sk, int sk_len) {
  if (pk_len != PK_LEN || sk_len != SK_LEN) return -1;
  return mlkem768_keypair(pk, sk);
}

int mlkem768_encapsulate(uint8_t* pk, int pk_len,
                         uint8_t* ct, int ct_len,
                         uint8_t* ss, int ss_len) {
  if (pk_len != PK_LEN || ct_len != CT_LEN || ss_len != SS_LEN) return -1;
  return mlkem768_enc(ct, ss, pk);
}

int mlkem768_decapsulate(uint8_t* ct, int ct_len,
                         uint8_t* sk, int sk_len,
                         uint8_t* ss, int ss_len) {
  if (ct_len != CT_LEN || sk_len != SK_LEN || ss_len != SS_LEN) return -1;
  return mlkem768_dec(ss, ct, sk);
}
