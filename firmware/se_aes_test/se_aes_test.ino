/*
 * se_aes_test.ino - secure element project, step 6a: first test of the
 * ATECC608's AES engine, with PUBLISHED TEST KEYS only (nothing secret).
 *
 * Test A - AES engine, key in TempKey (volatile RAM inside the chip):
 *   Nonce pass-through loads two test keys into TempKey; AES encrypts the
 *   published plaintexts; results must equal the published ciphertexts.
 *   Microchip's own CryptoAuthLib runs this test without a locked data zone.
 *
 * Test B - AES from slot 10 (our secret AES slot), same test keys:
 *   writes the two test keys into slot 10 (32 bytes, block 0) and repeats.
 *   Microchip's CryptoAuthLib only runs slot-AES tests AFTER the data zone
 *   is locked, so this may be refused now - which is exactly what we want to
 *   find out while nothing is permanent yet. Test keys in slot 10 are
 *   overwritten with the real link keys in step 6b.
 *
 * Test vectors:
 *   key block 0: FIPS-197 Appendix C.1  key 000102..0F, pt 00112233..FF -> 69C4E0D8..C55A
 *   key block 1: SP 800-38A F.1.1 ECB   key 2B7E1516..4F3C, pt 6BC1BEE2..172A -> 3AD77BB4..EF97
 *
 * Serial Monitor: 115200 baud, line ending "Newline".
 */
#include <ArduinoECCX08.h>
#include "se_config_image.h"
#include "atecc_io.h"

const int OFF_LOCK_VALUE = 86;
const int OFF_LOCK_CONFIG = 87;

static const uint8_t TEST_KEYS[32] = {
  // key block 0: FIPS-197 C.1
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  // key block 1: SP 800-38A (also the RFC 4493 CMAC key)
  0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
static const uint8_t PT[2][16] = {
  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
  { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A } };
static const uint8_t CT[2][16] = {
  { 0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A },
  { 0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97 } };

static void printHex(uint8_t b)
{
  if (b < 0x10) Serial.print('0');
  Serial.print(b, HEX);
}

static void printBytes(const uint8_t *d, int n)
{
  for (int i = 0; i < n; i++) printHex(d[i]);
}

static void stop(const char *why)
{
  Serial.print("STOPPED: ");
  Serial.println(why);
  Serial.println("Nothing more will be done.");
  while (1) { }
}

static void explainStatus(int s)
{
  if (s < 0)          Serial.print("no valid answer from the chip");
  else if (s == 0x0F) Serial.print("status 0x0F (execution error: not allowed in the current state)");
  else if (s == 0x03) Serial.print("status 0x03 (parse error: command or parameters rejected)");
  else if (s == 0x01) Serial.print("status 0x01 (miscompare)");
  else if (s == 0xFF) Serial.print("status 0xFF (CRC error on the bus)");
  else { Serial.print("status 0x"); printHex((uint8_t)s); }
}

static String readLine()
{
  String line;
  while (true) {
    if (Serial.available()) {
      int c = Serial.read();
      if (c < 0) continue;
      if (c == '\n' || c == '\r') {
        if (line.length() > 0) break;
      } else if (c >= 0x20 && c <= 0x7E) {
        line += (char)c;
      }
    }
  }
  line.trim();
  Serial.print("Received: \"");
  Serial.print(line.c_str());
  Serial.println("\"");
  return line;
}

// Runs AES on both test vectors with 'key_id'. Returns number passed (0-2),
// or -(status) if the chip refused the command.
static int runVectors(uint16_t key_id)
{
  int passed = 0;
  for (uint8_t kb = 0; kb < 2; kb++) {
    uint8_t out[16];
    int r = atecc::aesEncrypt(key_id, kb, PT[kb], out);
    Serial.print("  key block "); Serial.print((int)kb); Serial.print(": ");
    if (r != 0) {
      Serial.print("AES refused - "); explainStatus(r); Serial.println();
      return r > 0 ? -r : -0x100;
    }
    bool ok = memcmp(out, CT[kb], 16) == 0;
    printBytes(out, 16);
    Serial.println(ok ? "  MATCH" : "  MISMATCH");
    if (ok) passed++;
  }
  return passed;
}

void setup()
{
  Serial.begin(115200);
  while (!Serial) { }
  delay(200);
  Serial.println();
  Serial.println("=== Step 6a: AES test with published test keys ===");

  if (!ECCX08.begin()) stop("no ATECC608 answering at I2C 0x60");
  uint8_t cfg[128];
  if (!ECCX08.readConfiguration(cfg)) stop("could not read the configuration zone");
  if (cfg[OFF_LOCK_CONFIG] != 0x00) stop("config zone is NOT locked");
  if (cfg[OFF_LOCK_VALUE] != 0x55) stop("data zone is already locked - this step must come before the data lock");
  for (int i = 0; i < 128; i++) {
    if (i != OFF_LOCK_CONFIG && cfg[i] != SE_CONFIG_IMAGE[i]) stop("configuration differs from the reviewed image");
  }
  Serial.println("Config locked and as reviewed; data zone unlocked.");

  // ---- Test A: TempKey ----
  Serial.println();
  Serial.println("Test A: AES engine with the test keys in TempKey");
  int s = atecc::nonceLoadTempKey(TEST_KEYS);
  if (s != 0) { Serial.print("  Nonce load failed - "); explainStatus(s); Serial.println(); stop("cannot load TempKey"); }
  int a = runVectors(atecc::TEMPKEY_ID);
  Serial.println(a == 2 ? "Test A PASSED: the chip's AES matches FIPS-197 and SP 800-38A."
                        : "Test A FAILED.");
  if (a != 2) stop("AES engine or command layer problem - paste this output");

  // ---- Test B: slot 10 ----
  Serial.println();
  Serial.print("Test B writes the two PUBLIC test keys into slot ");
  Serial.print(SE_AES_SLOT);
  Serial.println(" (data zone still unlocked, so they will be replaced in step 6b).");
  delay(100);
  while (Serial.available()) Serial.read();
  Serial.println("Type LOAD TEST KEYS and press Enter to continue, anything else to stop here:");
  String in = readLine();
  if (!(in == "LOAD TEST KEYS")) stop("stopped after Test A by user");

  s = atecc::writeSlotBlock(SE_AES_SLOT, 0, TEST_KEYS);
  Serial.print("Write test keys to slot 10, block 0: ");
  if (s == 0) Serial.println("OK");
  else { explainStatus(s); Serial.println(); stop("the slot could not be written while the data zone is unlocked"); }

  Serial.println("Test B: AES with the keys in slot 10");
  int b = runVectors(SE_AES_SLOT);
  if (b == 2) {
    Serial.println("Test B PASSED: slot 10 works as an AES key slot BEFORE the data lock.");
  } else if (b < 0) {
    Serial.println("Test B: the chip refuses AES from a slot while the data zone is unlocked.");
    Serial.println("  This matches Microchip's own tests, which only use slot AES after the data lock.");
    Serial.println("  Not a failure of the design - it decides how step 6b/6c are ordered.");
  } else {
    Serial.println("Test B FAILED: AES ran but the result is wrong.");
  }
  Serial.println("Step 6a complete.");
}

void loop()
{
}
