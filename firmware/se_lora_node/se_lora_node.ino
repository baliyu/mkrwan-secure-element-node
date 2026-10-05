/*
 * se_lora_node.ino - secure element project, step 7: LoRa sensor node whose
 * link keys live in the ATECC608 and never leave it.
 *
 * Every AES block for the packet (AES-CTR encryption and the AES-CMAC MIC)
 * is computed by the secure element from slot 10. The packet format is the
 * STM32 project's secure_link format, so the existing Feather receiver
 * (software AES, same keys) must accept it unchanged.
 *
 * Frame counter: the ATECC608's monotonic Counter[1]. It can only go up and
 * survives resets and power loss, so a counter value (and therefore an
 * AES-CTR keystream) is never reused - no EEPROM/flash bookkeeping needed.
 * It is incremented BEFORE the packet is built (reserve-before-use).
 *
 * Libraries: ArduinoECCX08, LoRa (Sandeep Mistry; needs Murata firmware >= 1.1.6).
 * Radio: 868.1 MHz, SF7, BW125, CR4/5, CRC on, +14 dBm (same as the STM32 node).
 */
#include <SPI.h>
#include <LoRa.h>
#include <ArduinoECCX08.h>
#include "atecc_io.h"
#include "se_link.h"
#include "se_node_config.h"

static void printHex(uint8_t b)
{
  if (b < 0x10) Serial.print('0');
  Serial.print(b, HEX);
}

static void halt(const char *why)
{
  Serial.print("HALTED: ");
  Serial.println(why);
  while (1) { }
}

// AES block function for se_link: one AES-128 encryption inside the ATECC608.
static int chipAes(void *ctx, uint8_t key_block, const uint8_t in[16], uint8_t out[16])
{
  (void)ctx;
  return atecc::aesEncrypt(NODE_AES_SLOT, key_block, in, out) == 0 ? 0 : 1;
}

void setup()
{
  Serial.begin(115200);
  unsigned long t0 = millis();
  while (!Serial && millis() - t0 < 5000) { }   // also runs without a PC attached
  Serial.println();
  Serial.println("=== MKR WAN 1310 secure-element LoRa node ===");

  if (!ECCX08.begin()) halt("no ATECC608 at I2C 0x60");
  uint8_t cfg[128];
  if (!ECCX08.readConfiguration(cfg)) halt("cannot read the ATECC608 configuration");
  if (cfg[87] != 0x00 || cfg[86] != 0x00) halt("ATECC608 is not fully locked (steps 4 and 6)");

  // Boot self-test: the link keys in slot 10 still give the recorded answers
  for (uint8_t kb = 0; kb < 2; kb++) {
    uint8_t out[16];
    if (chipAes(nullptr, kb, KAT_PT[kb], out) != 0 || memcmp(out, KAT_CT[kb], 16) != 0) {
      halt(kb == 0 ? "self-test failed: encryption key block" : "self-test failed: MIC key block");
    }
  }
  Serial.println("Self-test: slot 10 link keys give the recorded known answers.");

  long c = 0;
  if (!ECCX08.readCounter(NODE_FCNT_COUNTER, c)) halt("cannot read the monotonic counter");
  Serial.print("Monotonic Counter[1] = ");
  Serial.print(c);
  Serial.println(" (next packet uses the next value)");

  if (!LoRa.begin(868.1E6)) halt("LoRa.begin failed (Murata firmware older than 1.1.6?)");
  LoRa.setSpreadingFactor(7);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(5);
  LoRa.enableCrc();
  LoRa.setTxPower(14);
  Serial.println("LoRa: 868.1 MHz, SF7, BW125, CR4/5, CRC on, +14 dBm");
  Serial.print("Device id 0x0"); Serial.println(NODE_DEV_ID, HEX);
}

void loop()
{
  static unsigned long last = 0;
  if (last != 0 && millis() - last < NODE_TX_PERIOD_MS) return;
  last = millis();

  // 1. Reserve the frame counter in the secure element BEFORE using it
  long c = 0;
  if (!ECCX08.incrementCounter(NODE_FCNT_COUNTER, c)) { Serial.println("counter increment FAILED - not sending"); return; }
  uint32_t fcnt = (uint32_t)c;

  // 2. Payload (plain text, encrypted by se_seal)
  char text[24];
  int n = snprintf(text, sizeof(text), "MKR SE #%lu", (unsigned long)fcnt);

  // 3. Seal: every AES block computed by the ATECC608 from slot 10
  uint8_t pkt[SE_MAX_PACKET];
  unsigned long t0 = micros();
  int len = se_seal(chipAes, nullptr, NODE_DEV_ID, fcnt, (const uint8_t *)text, (uint8_t)n, pkt, sizeof(pkt));
  unsigned long seal_us = micros() - t0;
  if (len < 0) { Serial.print("seal FAILED ("); Serial.print(len); Serial.println(") - not sending"); return; }

  // 4. Send
  LoRa.beginPacket();
  LoRa.write(pkt, (size_t)len);
  int ok = LoRa.endPacket();

  Serial.print("TX "); Serial.print(ok ? "ok" : "FAILED");
  Serial.print(": fcnt="); Serial.print((unsigned long)fcnt);
  Serial.print(" len="); Serial.print(len);
  Serial.print(" seal="); Serial.print(seal_us / 1000.0, 1); Serial.print(" ms");
  Serial.print(" ("); Serial.print(text); Serial.println(")");
  Serial.print("   AIR: ");
  for (int i = 0; i < len; i++) { printHex(pkt[i]); Serial.print(' '); }
  Serial.println();
}
