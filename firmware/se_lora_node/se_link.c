/* se_link.c - see se_link.h. Written from the STM32 secure_link.c packet
 * format and RFC 4493; only the AES block function is different. */
#include "se_link.h"
#include <string.h>

static void put_u32le(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Doubling in GF(2^128) for the CMAC subkeys (RFC 4493 section 2.3). */
static void dbl(const uint8_t in[16], uint8_t out[16])
{
  uint8_t carry = (uint8_t)(in[0] >> 7);
  int i;
  for (i = 0; i < 15; i++) out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
  out[15] = (uint8_t)(in[15] << 1);
  if (carry) out[15] ^= 0x87U;
}

int se_cmac(se_aes_fn aes, void *ctx, uint8_t key_block,
            const uint8_t *msg, size_t len, uint8_t tag[16])
{
  uint8_t zero[16] = {0}, L[16], K1[16], K2[16], X[16], Y[16], last[16];
  size_t n, i, j;
  int complete;

  if (aes(ctx, key_block, zero, L) != 0) return SE_ERR_AES;
  dbl(L, K1);
  dbl(K1, K2);

  n = (len + 15U) / 16U;
  if (n == 0) { n = 1; complete = 0; }
  else complete = (len % 16U) == 0;

  if (complete) {
    for (j = 0; j < 16; j++) last[j] = (uint8_t)(msg[(n - 1) * 16 + j] ^ K1[j]);
  } else {
    size_t rem = len - (n - 1) * 16U;
    memset(last, 0, 16);
    if (rem) memcpy(last, &msg[(n - 1) * 16], rem);
    last[rem] = 0x80U;
    for (j = 0; j < 16; j++) last[j] ^= K2[j];
  }

  memset(X, 0, 16);
  for (i = 0; i + 1 < n; i++) {
    for (j = 0; j < 16; j++) Y[j] = (uint8_t)(X[j] ^ msg[i * 16 + j]);
    if (aes(ctx, key_block, Y, X) != 0) return SE_ERR_AES;
  }
  for (j = 0; j < 16; j++) Y[j] = (uint8_t)(X[j] ^ last[j]);
  if (aes(ctx, key_block, Y, tag) != 0) return SE_ERR_AES;
  return 0;
}

int se_seal(se_aes_fn aes, void *ctx, uint8_t dev_id, uint32_t fcnt,
            const uint8_t *payload, uint8_t len, uint8_t *out, uint8_t out_max)
{
  uint8_t block[16], ks[16], tag[16];
  uint8_t i, done = 0, blk = 1;
  uint8_t total = (uint8_t)(SE_HDR_LEN + len + SE_MIC_LEN);

  if (len > SE_MAX_PAYLOAD || total > out_max) return SE_ERR_LENGTH;

  out[0] = dev_id;
  put_u32le(&out[1], fcnt);

  while (done < len) {                         /* AES-CTR, exactly as secure_link.c */
    memset(block, 0, 16);
    block[0] = 0x01U;
    block[1] = dev_id;
    put_u32le(&block[2], fcnt);
    block[15] = blk++;
    if (aes(ctx, SE_KEY_ENC, block, ks) != 0) return SE_ERR_AES;
    for (i = 0; i < 16 && done < len; i++, done++) out[SE_HDR_LEN + done] = (uint8_t)(payload[done] ^ ks[i]);
  }

  if (se_cmac(aes, ctx, SE_KEY_MIC, out, SE_HDR_LEN + len, tag) != 0) return SE_ERR_AES;
  memcpy(&out[SE_HDR_LEN + len], tag, SE_MIC_LEN);
  return total;
}
