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
const uint8_t LOCK_ZONE_CONFIG = 0x00; // + summary CRC check (bit 7 clear)
const uint8_t LOCK_ZONE_DATA   = 0x01;
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

// Reads a response packet of exactly 'len' data bytes (status = 1 byte).
// Polls: the chip NACKs its address while it is still executing.
inline bool receive(uint8_t *out, size_t len, uint16_t timeout_ms)
{
  const size_t total = len + 3;
  uint8_t buf[80];
  if (total > sizeof(buf)) return false;
  for (uint16_t waited = 0; waited <= timeout_ms; waited += 2) {
    if (ATECC_WIRE.requestFrom(I2C_ADDR, (uint8_t)total) == total) {
      for (size_t i = 0; i < total; i++) buf[i] = (uint8_t)ATECC_WIRE.read();
      if (buf[0] != total) return false;                          // wrong length (e.g. error status)
      uint16_t crc = crc16(buf, total - 2);
      if (buf[total - 2] != (crc & 0xFF) || buf[total - 1] != (crc >> 8)) return false;
      memcpy(out, &buf[1], len);
      return true;
    }
    while (ATECC_WIRE.available()) ATECC_WIRE.read();
    delay(2);
  }
  return false;
}

// Reads a 1-byte status packet. Returns -1 on a communication failure.
inline int receiveStatus(uint16_t timeout_ms)
{
  uint8_t s;
  return receive(&s, 1, timeout_ms) ? s : -1;
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

}  // namespace atecc
