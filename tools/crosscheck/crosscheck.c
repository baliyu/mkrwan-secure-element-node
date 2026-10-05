/*
 * tools/crosscheck/crosscheck.c - proves the MKR's se_link.c builds packets
 * byte-identical to the STM32 project's secure_link.c, which the Feather
 * receiver runs, and that sl_open() on the receiver side accepts them.
 *
 *   make            (STM32_SL defaults to /mnt/c/stm32/l072_blinky/secure_link)
 *   ./crosscheck
 *
 * se_link gets its AES blocks from the STM32's own software aes128_encrypt(),
 * so this compares the two packet/CMAC implementations, not two AES engines
 * (the chip's AES was checked against FIPS-197 and the PC in steps 6a/6).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secure_link.h"     /* from the STM32 project */
#include "se_link.h"         /* from firmware/se_lora_node */

static aes128_ctx g_enc, g_mic;

static int soft_aes(void *ctx, uint8_t kb, const uint8_t in[16], uint8_t out[16])
{
  (void)ctx;
  aes128_encrypt(kb == SE_KEY_ENC ? &g_enc : &g_mic, in, out);
  return 0;
}

static uint32_t rng = 12345;
static uint8_t rnd8(void) { rng = rng * 1103515245u + 12345u; return (uint8_t)(rng >> 16); }

int main(void)
{
  int fails = 0, i, cases = 2000;
  for (i = 0; i < cases; i++) {
    uint8_t enc[16], mic[16], payload[SL_MAX_PAYLOAD], a[SL_MAX_PACKET], b[SE_MAX_PACKET], out[SL_MAX_PAYLOAD];
    uint8_t len = (uint8_t)(rnd8() % (SL_MAX_PAYLOAD + 1)), dev = rnd8(), dev_out = 0;
    uint32_t fcnt = ((uint32_t)rnd8() << 24) | ((uint32_t)rnd8() << 16) | ((uint32_t)rnd8() << 8) | rnd8();
    uint32_t last = 0;
    sl_keys k;
    int j, na, nb, r;
    for (j = 0; j < 16; j++) { enc[j] = rnd8(); mic[j] = rnd8(); }
    for (j = 0; j < len; j++) payload[j] = rnd8();
    if (fcnt == 0) fcnt = 1;

    sl_init_keys(&k, enc, mic);
    aes128_init(&g_enc, enc);
    aes128_init(&g_mic, mic);

    na = sl_seal(&k, dev, fcnt, payload, len, a, sizeof(a));
    nb = se_seal(soft_aes, NULL, dev, fcnt, payload, len, b, sizeof(b));
    if (na != nb || memcmp(a, b, (size_t)na) != 0) { fails++; if (fails < 5) printf("[FAIL] case %d: packets differ (len %u)\n", i, len); continue; }

    r = sl_open(&k, &last, b, (uint8_t)nb, &dev_out, out, sizeof(out));
    if (r != len || dev_out != dev || last != fcnt || memcmp(out, payload, len) != 0) {
      fails++; if (fails < 5) printf("[FAIL] case %d: receiver rejected an se_link packet (%d)\n", i, r);
    }
  }
  printf("%s: %d random packets, %d failure(s) - se_link.c vs STM32 secure_link.c\n",
         fails ? "FAILED" : "ALL MATCH", cases, fails);
  return fails ? 1 : 0;
}
