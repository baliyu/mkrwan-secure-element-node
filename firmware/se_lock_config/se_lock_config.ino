/*
 * se_lock_config.ino - secure element project, step 4: LOCK the
 * configuration zone of the ATECC608. THIS IS PERMANENT.
 *
 * Safety:
 *   - Runs only if the chip's whole configuration (all 128 bytes) already
 *     equals the reviewed image from step 3.
 *   - Sends Lock with the summary CRC (0x67BF for this chip), so the chip
 *     itself refuses to lock anything else - unlike the library's lock(),
 *     which skips that check.
 *   - Needs the words LOCK CONFIG typed in the Serial Monitor.
 *   - Locks the configuration zone only. The data zone stays unlocked
 *     (keys are loaded and tested in steps 5-6 first).
 *
 * Proof it worked: LockConfig (byte 87) reads 0x00, and the random number
 * generator, which returns a fixed test pattern while the configuration is
 * unlocked (ATECC508A data sheet 3.3.2), returns real random bytes.
 *
 * Serial Monitor: 115200 baud, line ending "Newline".
 */
#include <ArduinoECCX08.h>
#include "se_config_image.h"
#include "atecc_io.h"

const int OFF_LOCK_VALUE = 86;
const int OFF_LOCK_CONFIG = 87;

static void printHex(uint8_t b)
{
  if (b < 0x10) Serial.print('0');
  Serial.print(b, HEX);
}

static void printBytes(const uint8_t *d, int n)
{
  for (int i = 0; i < n; i++) { printHex(d[i]); Serial.print(' '); }
  Serial.println();
}

static void stop(const char *why)
{
  Serial.print("STOPPED: ");
  Serial.println(why);
  Serial.println("Nothing more will be done.");
  while (1) { }
}

static bool waitForLine(const char *expected)
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
  return line == expected;
}

// True if the 32 bytes are the unlocked-RNG test pattern ff ff 00 00 ...
static bool isTestPattern(const uint8_t *r)
{
  for (int i = 0; i < 32; i++) {
    uint8_t want = ((i % 4) < 2) ? 0xFF : 0x00;
    if (r[i] != want) return false;
  }
  return true;
}

void setup()
{
  Serial.begin(115200);
  while (!Serial) { }
  delay(200);
  Serial.println();
  Serial.println("=== Step 4: lock the CONFIGURATION zone (permanent) ===");

  if (atecc::crc16(SE_CONFIG_IMAGE, 128) != SE_CONFIG_LOCK_CRC) stop("image and its CRC disagree - regenerate the header");
  if (!ECCX08.begin()) stop("no ATECC608 answering at I2C 0x60");

  uint8_t cfg[128];
  if (!ECCX08.readConfiguration(cfg)) stop("could not read the configuration zone");

  if (cfg[OFF_LOCK_VALUE] != 0x55) stop("data zone is already locked - unexpected");
  if (cfg[OFF_LOCK_CONFIG] != 0x55) {
    Serial.println("Config zone is ALREADY locked (byte 87 = 0x00).");
    stop("nothing to do");
  }

  for (int i = 0; i < 128; i++) {
    if (cfg[i] != SE_CONFIG_IMAGE[i]) {
      Serial.print("byte "); Serial.print(i);
      Serial.print(": chip 0x"); printHex(cfg[i]);
      Serial.print("  image 0x"); printHex(SE_CONFIG_IMAGE[i]); Serial.println();
      stop("chip configuration differs from the reviewed image - run step 3 first");
    }
  }
  uint16_t crc = atecc::crc16(cfg, 128);
  Serial.print("All 128 bytes match the reviewed image. CRC 0x");
  printHex(crc >> 8); printHex(crc & 0xFF); Serial.println();

  uint8_t rnd[32];
  if (ECCX08.random(rnd, sizeof(rnd))) {
    Serial.print("RNG before lock: "); printBytes(rnd, 16);
    Serial.println(isTestPattern(rnd) ? "  (fixed test pattern, as expected while unlocked)"
                                      : "  (not the test pattern - noted, not an error)");
  }

  Serial.println();
  Serial.println("About to LOCK the configuration zone. This can never be undone:");
  Serial.println("  - slot 0 stays the identity private-key slot");
  Serial.println("  - slot 10 becomes a secret AES key slot (never readable)");
  Serial.println("  - the data zone stays UNLOCKED (keys are tested before it is locked)");
  Serial.println("The chip will refuse the lock unless its CRC equals 0x67BF.");
  delay(100);
  while (Serial.available()) Serial.read();   // drop anything sent before the prompt
  Serial.println("Type LOCK CONFIG and press Enter to lock, anything else to cancel:");
  if (!waitForLine("LOCK CONFIG")) stop("cancelled by user - nothing was locked");

  int status = atecc::lockWithCrc(atecc::LOCK_ZONE_CONFIG, SE_CONFIG_LOCK_CRC);
  Serial.print("Lock command status: ");
  if (status < 0) Serial.println("no valid response");
  else { Serial.print("0x"); printHex((uint8_t)status); Serial.println(status == 0 ? " (success)" : " (chip refused)"); }

  // Whatever the status said, the chip's own lock byte is the truth.
  uint8_t after[128];
  if (!ECCX08.readConfiguration(after)) stop("could not read the configuration back");
  Serial.print("LockConfig (byte 87) now: 0x"); printHex(after[OFF_LOCK_CONFIG]);
  Serial.println(after[OFF_LOCK_CONFIG] == 0x00 ? "  -> LOCKED" : "  -> still unlocked");
  Serial.print("LockValue  (byte 86) now: 0x"); printHex(after[OFF_LOCK_VALUE]);
  Serial.println(after[OFF_LOCK_VALUE] == 0x55 ? "  -> data zone still unlocked (as intended)" : "  -> UNEXPECTED");

  int diffs = 0;
  for (int i = 0; i < 128; i++) if (i != OFF_LOCK_CONFIG && after[i] != SE_CONFIG_IMAGE[i]) diffs++;
  Serial.print("Other bytes changed: "); Serial.println(diffs);

  if (ECCX08.random(rnd, sizeof(rnd))) {
    Serial.print("RNG after lock:  "); printBytes(rnd, 16);
    Serial.println(isTestPattern(rnd) ? "  (still the test pattern)" : "  (real random data)");
  }

  if (after[OFF_LOCK_CONFIG] == 0x00 && diffs == 0) Serial.println("Step 4 complete: configuration zone locked.");
  else Serial.println("Step 4 did NOT complete - paste this output before doing anything else.");
}

void loop()
{
}
