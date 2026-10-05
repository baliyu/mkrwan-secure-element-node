/*
 * se_link.h - the secure_link packet format from the STM32 project, with
 * every AES block computed by a caller-supplied function. On the MKR WAN 1310
 * that function asks the ATECC608, so the link keys never leave the chip.
 *
 * Packet (identical to secure_link/secure_link.h in stm32l0-freertos-sensor-node):
 *   [dev_id 1B][fcnt 4B little-endian][AES-128-CTR ciphertext][AES-CMAC MIC 4B]
 *   CTR counter block: 01 | dev_id | fcnt (LE, 4B) | 0x00 x9 | block index (from 1)
 *   MIC: first 4 bytes of AES-CMAC (RFC 4493) over dev_id || fcnt || ciphertext
 *   Key block 0 = encryption key, key block 1 = MIC key (slot 10 of the ATECC608).
 */
#ifndef SE_LINK_H
#define SE_LINK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SE_HDR_LEN      5U
#define SE_MIC_LEN      4U
#define SE_MAX_PAYLOAD  48U
#define SE_MAX_PACKET   (SE_HDR_LEN + SE_MAX_PAYLOAD + SE_MIC_LEN)

#define SE_KEY_ENC      0U      /* AES key block 0 */
#define SE_KEY_MIC      1U      /* AES key block 1 */

#define SE_ERR_LENGTH   (-1)
#define SE_ERR_AES      (-4)    /* the AES function reported a failure */

/* One AES-128 block encryption with key block 'key_block'. Return 0 on success. */
typedef int (*se_aes_fn)(void *ctx, uint8_t key_block, const uint8_t in[16], uint8_t out[16]);

/* RFC 4493 AES-CMAC with key block 'key_block'. Returns 0 or SE_ERR_AES. */
int se_cmac(se_aes_fn aes, void *ctx, uint8_t key_block,
            const uint8_t *msg, size_t len, uint8_t tag[16]);

/* Build a packet. Returns its length, SE_ERR_LENGTH or SE_ERR_AES. */
int se_seal(se_aes_fn aes, void *ctx, uint8_t dev_id, uint32_t fcnt,
            const uint8_t *payload, uint8_t len, uint8_t *out, uint8_t out_max);

#ifdef __cplusplus
}
#endif

#endif
