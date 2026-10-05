/*
 * se_identity_key.ino - secure element project, step 5: create the device
 * identity key INSIDE the ATECC608 and export its public key.
 *
 * - The private key is made by the chip's own random generator (GenKey) in
 *   slot 0 and can never be read out (slot 0 is IsSecret, private ECC key).
 * - Only the 64-byte public key (X then Y) leaves the chip. It is printed on
 *   one "PUBKEY:" line for tools/se_pubkey.py, which checks it lies on the
 *   P-256 curve and saves it as a PEM file.
 * - Asks for the public key again (GenKey public mode) and checks it matches.
 * - Running it twice does not silently replace the key: if slot 0 already
 *   holds a key it is shown and kept unless you type NEW KEY.
 *
 * Signing is tested after the data zone is locked (step 6): Microchip's own
 * CryptoAuthLib tests require a locked data zone before Sign.
 *
 * Serial Monitor: 115200 baud, line ending "Newline".
 */
#include <ArduinoECCX08.h>
#include "se_config_image.h"

const int OFF_LOCK_VALUE = 86;
const int OFF_LOCK_CONFIG = 87;
const int OFF_SLOT_CONFIG = 20;
const int OFF_KEY_CONFIG = 96;

static void printHex(uint8_t b)
{
  if (b < 0x10) Serial.print('0');
  Serial.print(b, HEX);
}

static void printKey(const char *label, const uint8_t *k)
{
  Serial.print(label);
  for (int i = 0; i < 64; i++) printHex(k[i]);
  Serial.println();
}

static void stop(const char *why)
{
  Serial.print("STOPPED: ");
  Serial.println(why);
  Serial.println("Nothing more will be done.");
  while (1) { }
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

static String prompt(const char *text)
{
  delay(100);
  while (Serial.available()) Serial.read();   // drop anything sent before the prompt
  Serial.println(text);
  return readLine();
}

void setup()
{
  Serial.begin(115200);
  while (!Serial) { }
  delay(200);
  Serial.println();
  Serial.println("=== Step 5: device identity key (slot 0) ===");

  if (!ECCX08.begin()) stop("no ATECC608 answering at I2C 0x60");

  uint8_t cfg[128];
  if (!ECCX08.readConfiguration(cfg)) stop("could not read the configuration zone");
  if (cfg[OFF_LOCK_CONFIG] != 0x00) stop("config zone is NOT locked - do step 4 first");
  if (cfg[OFF_LOCK_VALUE] != 0x55) stop("data zone is already locked - this step comes before step 6");
  for (int i = 0; i < 2; i++) {
    if (cfg[OFF_SLOT_CONFIG + i] != SE_CONFIG_IMAGE[OFF_SLOT_CONFIG + i] ||
        cfg[OFF_KEY_CONFIG + i]  != SE_CONFIG_IMAGE[OFF_KEY_CONFIG + i]) {
      stop("slot 0 configuration differs from the reviewed image");
    }
  }
  Serial.println("Config locked, data zone unlocked, slot 0 = private P-256 key slot.");

  uint8_t pub[64];
  bool haveKey = ECCX08.generatePublicKey(SE_IDENTITY_SLOT, pub);
  if (haveKey) {
    printKey("Slot 0 already holds a key. Its public key: ", pub);
    String a = prompt("Type NEW KEY to replace it with a new one, or anything else to keep it:");
    if (a == "NEW KEY") haveKey = false;
    else Serial.println("Keeping the existing key.");
  } else {
    Serial.println("Slot 0 holds no valid key yet (expected on first run).");
    String a = prompt("Type GENKEY to create the identity key inside the chip, anything else to cancel:");
    if (!(a == "GENKEY")) stop("cancelled by user - no key created");
  }

  if (!haveKey) {
    unsigned long t0 = millis();
    if (!ECCX08.generatePrivateKey(SE_IDENTITY_SLOT, pub)) stop("GenKey (create) failed");
    Serial.print("Private key created inside the chip in ");
    Serial.print((int)(millis() - t0));
    Serial.println(" ms (it can never be read out).");
  }

  uint8_t again[64];
  if (!ECCX08.generatePublicKey(SE_IDENTITY_SLOT, again)) stop("could not recompute the public key");
  bool same = true;
  for (int i = 0; i < 64; i++) if (again[i] != pub[i]) same = false;
  Serial.println(same ? "Public key recomputed by the chip: MATCH" : "Public key recomputed by the chip: MISMATCH");
  if (!same) stop("public keys differ - do not continue");

  Serial.println();
  Serial.println("Copy the next line into docs/step5_identity_key_output.txt:");
  printKey("PUBKEY: ", pub);
  Serial.println();
  Serial.println("Step 5 complete. Next on the PC: python3 tools/se_pubkey.py docs/step5_identity_key_output.txt");
}

void loop()
{
}
