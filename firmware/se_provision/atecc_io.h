/*
 * atecc_io.h - minimal ATECC608 command layer (I2C), written for this
 * project from Microchip's public ATECC508A Complete Data Sheet
 * (DS20005927A, sections 6 and 9) and CryptoAuthLib's command constants.
 *
 * Why not just ArduinoECCX08? Its lock() always sends mode 0x80, which tells
 * the chip to IGNORE the CRC check, and it has no AES command. This layer
 * sends exactly the command we choose, nothing more.
 *
 * Packet to the chip:   0x03 | count | opcode | param1 | param2 (LE) | data | CRC (LE)
 *                       (count covers itself, opcode, params, data and CRC)
 * Packet from the chip: count | data | CRC (LE); a 4-byte packet carries a status byte.
 */
#pragma once
#include <Arduino.h>
#include <Wire.h>

#ifdef CRYPTO_WIRE
#define ATECC_WIRE CRYPTO_WIRE
#else
#define ATECC_WIRE Wire
#endif

namespace atecc {

const uint8_t I2C_ADDR       = 0x60;
const uint8_t OP_LOCK        = 0x17;   // CryptoAuthLib ATCA_LOCK
const uint8_t OP_AES         = 0x51;   // CryptoAuthLib ATCA_AES
const uint8_t OP_NONCE       = 0x16;   // CryptoAuthLib ATCA_NONCE
const uint8_t OP_WRITE       = 0x12;   // CryptoAuthLib ATCA_WRITE
const uint16_t TEMPKEY_ID    = 0xFFFF; // CryptoAuthLib ATCA_TEMPKEY_KEYID
const uint8_t LOCK_ZONE_CONFIG = 0x00; // + summary CRC check (bit 7 clear)
const uint8_t LOCK_ZONE_DATA   = 0x01;
const uint8_t LOCK_NO_CRC      = 0x80; // CryptoAuthLib LOCK_ZONE_NO_CRC
const uint8_t STATUS_WAKE    = 0x11;   // "after wake, prior to first command"

// ATECC CRC-16 (poly 0x8005, LSB first) - identical to CryptoAuthLib atCRC.
inline uint16_t crc16(const uint8_t *data, size_t len)
{
  uint16_t crc = 0;
  for (size_t i = 0; i < len; i++) {
    for (uint8_t bit = 0x01; bit != 0; bit <<= 1) {
      uint8_t data_bit = (data[i] & bit) ? 1 : 0;
      uint8_t crc_bit = (uint8_t)(crc >> 15);
      crc <<= 1;
      if (data_bit != crc_bit) crc ^= 0x8005;
    }
  }
  return crc;
}

// Reads a response. Returns:
//   0  -> 'len' data bytes copied to 'out'
//  >0  -> the chip answered with a 4-byte status packet instead (error code)
//  -1  -> no valid answer (timeout, bad length or bad CRC)
// The chip NACKs its address while it is still executing, so this polls.
inline int receive(uint8_t *out, size_t len, uint16_t timeout_ms)
{
  const size_t total = len + 3;
  uint8_t buf[80];
  if (total > sizeof(buf)) return -1;
  for (uint16_t waited = 0; waited <= timeout_ms; waited += 2) {
    if (ATECC_WIRE.requestFrom(I2C_ADDR, (uint8_t)total) == total) {
      for (size_t i = 0; i < total; i++) buf[i] = (uint8_t)ATECC_WIRE.read();
      size_t n = buf[0];
      if (n != total && n != 4) return -1;
      uint16_t crc = crc16(buf, n - 2);
      if (buf[n - 2] != (crc & 0xFF) || buf[n - 1] != (crc >> 8)) return -1;
      if (n == 4 && total != 4) return buf[1] ? buf[1] : -1;   // status instead of data
      memcpy(out, &buf[1], len);
      return 0;
    }
    while (ATECC_WIRE.available()) ATECC_WIRE.read();
    delay(2);
  }
  return -1;
}

// Reads a 1-byte status packet. Returns the status, or -1 on failure.
inline int receiveStatus(uint16_t timeout_ms)
{
  uint8_t s;
  return receive(&s, 1, timeout_ms) == 0 ? s : -1;
}

inline bool wake()
{
  ATECC_WIRE.setClock(100000);
  ATECC_WIRE.beginTransmission(0x00);     // SDA held low long enough = wake token
  ATECC_WIRE.endTransmission();
  delayMicroseconds(1500);
  int s = receiveStatus(10);
  ATECC_WIRE.setClock(400000);
  return s == STATUS_WAKE;
}

inline void idle()
{
  ATECC_WIRE.beginTransmission(I2C_ADDR);
  ATECC_WIRE.write((uint8_t)0x02);        // word address 0x02 = idle
  ATECC_WIRE.endTransmission();
}

inline bool send(uint8_t opcode, uint8_t p1, uint16_t p2, const uint8_t *data, size_t len)
{
  uint8_t pkt[80];
  const size_t count = 1 + 1 + 1 + 2 + len + 2;
  if (count + 1 > sizeof(pkt)) return false;
  pkt[0] = 0x03;                          // word address: command
  pkt[1] = (uint8_t)count;
  pkt[2] = opcode;
  pkt[3] = p1;
  pkt[4] = (uint8_t)(p2 & 0xFF);
  pkt[5] = (uint8_t)(p2 >> 8);
  if (len) memcpy(&pkt[6], data, len);
  uint16_t crc = crc16(&pkt[1], count - 2);
  pkt[6 + len] = (uint8_t)(crc & 0xFF);
  pkt[7 + len] = (uint8_t)(crc >> 8);
  ATECC_WIRE.beginTransmission(I2C_ADDR);
  ATECC_WIRE.write(pkt, count + 1);
  return ATECC_WIRE.endTransmission() == 0;
}

// One complete command that returns a 1-byte status (0 = success, -1 = no answer).
inline int commandStatus(uint8_t op, uint8_t p1, uint16_t p2, const uint8_t *data, size_t len, uint16_t timeout_ms)
{
  if (!wake()) return -1;
  if (!send(op, p1, p2, data, len)) { idle(); return -1; }
  int s = receiveStatus(timeout_ms);
  idle();
  return s;
}

// One complete command that returns 'outlen' bytes (0 = success, >0 chip error, -1 no answer).
inline int commandData(uint8_t op, uint8_t p1, uint16_t p2, const uint8_t *data, size_t len,
                       uint8_t *out, size_t outlen, uint16_t timeout_ms)
{
  if (!wake()) return -1;
  if (!send(op, p1, p2, data, len)) { idle(); return -1; }
  int r = receive(out, outlen, timeout_ms);
  idle();
  return r;
}

// Nonce pass-through: load 32 bytes directly into TempKey (CryptoAuthLib nonce_load).
inline int nonceLoadTempKey(const uint8_t in32[32])
{
  return commandStatus(OP_NONCE, 0x03, 0x0000, in32, 32, 50);
}

// Write one 32-byte block into a data slot (data zone: zone 2 + 32-byte flag 0x80).
// Address encoding (CryptoAuthLib calib_get_addr): slot << 3 | block << 8.
inline int writeSlotBlock(uint8_t slot, uint8_t block, const uint8_t in32[32])
{
  uint16_t addr = (uint16_t)((slot << 3) | (block << 8));
  return commandStatus(OP_WRITE, 0x82, addr, in32, 32, 50);
}

// AES-128 ECB encrypt of one block with key 'key_block' (0-3) of 'key_id'
// (a slot number, or TEMPKEY_ID). Mode: encrypt 0x00 | key_block << 6.
inline int aesEncrypt(uint16_t key_id, uint8_t key_block, const uint8_t in[16], uint8_t out[16])
{
  return commandData(OP_AES, (uint8_t)((key_block & 0x03) << 6), key_id, in, 16, out, 16, 100);
}

// Lock with the summary-CRC check: the chip refuses unless the CRC of its
// whole zone equals 'crc'. Returns the chip's status byte (0 = locked) or -1.
inline int lockWithCrc(uint8_t zone, uint16_t crc)
{
  if (!wake()) return -1;
  if (!send(OP_LOCK, zone, crc, nullptr, 0)) { idle(); return -1; }
  int s = receiveStatus(100);             // Lock takes up to ~32 ms (508A data sheet)
  idle();
  return s;
}

// Lock the DATA (and OTP) zone WITHOUT the summary CRC. A CRC is impossible
// here: it would have to cover slot 0's private key, which nobody knows.
// CryptoAuthLib's own atcab_lock_data_zone() uses the same mode.
inline int lockDataNoCrc()
{
  if (!wake()) return -1;
  if (!send(OP_LOCK, (uint8_t)(LOCK_NO_CRC | LOCK_ZONE_DATA), 0x0000, nullptr, 0)) { idle(); return -1; }
  int s = receiveStatus(100);
  idle();
  return s;
}

}  // namespace atecc
