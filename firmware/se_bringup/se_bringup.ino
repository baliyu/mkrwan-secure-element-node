/*
 * se_bringup.ino - secure element project, step 1: READ-ONLY bring-up.
 * Board: Arduino MKR WAN 1310 (SAMD21 + Microchip ATECCx08A at I2C 0x60)
 * Library: ArduinoECCX08 (Library Manager)
 *
 * What it does (nothing is written to the chip):
 *   1. Wakes the secure element and checks it answers (begin()).
 *   2. Reads the 128-byte configuration zone.
 *   3. Prints serial number, revision (which chip is it really?),
 *      I2C address and the lock state of the config and data zones.
 *   4. Prints the whole configuration zone as hex, for the record.
 *
 * Why it matters: locking the config/data zones is PERMANENT. Before any
 * key is created we need to know whether this chip is still blank or was
 * already locked by an earlier sketch (e.g. Arduino IoT Cloud provisioning).
 */
#include <ArduinoECCX08.h>

// Configuration zone byte offsets (ATECC508A/608A)
const int CFG_SN0        = 0;    // SN[0..3]
const int CFG_REVNUM     = 4;    // RevNum[0..3]
const int CFG_SN4        = 8;    // SN[4..8]
const int CFG_I2C_ADDR   = 16;   // I2C address (7-bit address << 1)
const int CFG_LOCK_VALUE = 86;   // data + OTP zones: 0x55 = unlocked, 0x00 = locked
const int CFG_LOCK_CFG   = 87;   // config zone:      0x55 = unlocked, 0x00 = locked
const int CFG_SLOT_LOCK  = 88;   // SlotLocked bits (2 bytes), bit = 0 means that slot is locked

static void printHex(byte b)
{
  if (b < 0x10) Serial.print('0');
  Serial.print(b, HEX);
}

static void printLock(const char *name, byte v)
{
  Serial.print(name);
  Serial.print(": 0x");
  printHex(v);
  if (v == 0x55)      Serial.println("  (UNLOCKED)");
  else if (v == 0x00) Serial.println("  (LOCKED - permanent)");
  else                Serial.println("  (unexpected value)");
}

void setup()
{
  Serial.begin(115200);
  while (!Serial) { }            // native USB: wait for the Serial Monitor
  delay(200);

  Serial.println();
  Serial.println("=== Secure element bring-up (read-only) ===");

  if (!ECCX08.begin()) {
    Serial.println("ECCX08.begin() FAILED: no ATECC508A/608A answering at I2C 0x60.");
    Serial.println("Check board selection (MKR WAN 1310) and the ArduinoECCX08 library.");
    while (1) { }
  }
  Serial.println("Secure element found at I2C 0x60.");

  byte cfg[128];
  if (!ECCX08.readConfiguration(cfg)) {
    Serial.println("readConfiguration() FAILED.");
    while (1) { }
  }

  // Serial number: 9 bytes, SN[0..3] at 0-3 and SN[4..8] at 8-12
  Serial.print("Serial number: ");
  for (int i = 0; i < 4; i++) printHex(cfg[CFG_SN0 + i]);
  for (int i = 0; i < 5; i++) printHex(cfg[CFG_SN4 + i]);
  Serial.println();

  // Revision: byte 6 high nibble tells the family (0x50 = 508A, 0x60 = 608A)
  Serial.print("Revision:      ");
  for (int i = 0; i < 4; i++) printHex(cfg[CFG_REVNUM + i]);
  byte fam = cfg[CFG_REVNUM + 2] & 0xF0;
  if (fam == 0x50)      Serial.println("  -> ATECC508A");
  else if (fam == 0x60) Serial.println("  -> ATECC608A/B");
  else                  Serial.println("  -> unknown family");

  Serial.print("I2C address:   0x");
  printHex(cfg[CFG_I2C_ADDR] >> 1);
  Serial.println();

  printLock("Config zone lock (byte 87)", cfg[CFG_LOCK_CFG]);
  printLock("Data zone lock   (byte 86)", cfg[CFG_LOCK_VALUE]);

  Serial.print("SlotLocked (bytes 88-89): 0x");
  printHex(cfg[CFG_SLOT_LOCK]);
  printHex(cfg[CFG_SLOT_LOCK + 1]);
  Serial.println("  (0xFFFF = no individual slot locked)");

  Serial.print("Library locked(): ");
  Serial.println(ECCX08.locked() ? "yes (config AND data locked)" : "no");

  Serial.println();
  Serial.println("Configuration zone (128 bytes):");
  for (int i = 0; i < 128; i++) {
    if (i % 16 == 0) {
      if (i < 0x10) Serial.print('0');
      Serial.print(i, HEX);
      Serial.print(": ");
    }
    printHex(cfg[i]);
    Serial.print(i % 16 == 15 ? '\n' : ' ');
  }

  Serial.println();
  Serial.println("Done. Nothing was written to the secure element.");
}

void loop()
{
}
