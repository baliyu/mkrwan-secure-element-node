# MKR WAN 1310 Secure-Element LoRa Node

Device identity and LoRa link keys held in a hardware secure element (Microchip **ATECC608**) on an Arduino **MKR WAN 1310**. The keys are generated or loaded once, locked inside the chip, and never leave it: every AES block of every LoRa packet is computed by the secure element. The packets are byte-identical to my software implementation in [stm32l0-freertos-sensor-node](https://github.com/baliyu/stm32l0-freertos-sensor-node), and the unchanged Feather M0 receiver from that project accepts them.

This project fixes a limitation I documented there: *"link keys are compiled into the app in internal flash"*.

## Result in one picture

| | MKR WAN 1310 (sender) | Feather M0 (receiver, from the STM32 project) |
|---|---|---|
| Keys | inside the ATECC608, slot 10, never readable | software, `secure_link_keys.h` |
| AES | hardware, in the secure element | software (`aes128.c`) |
| Frame counter | ATECC608 monotonic Counter[1] | replay floor in flash |
| Packet `fcnt=1` on air | `02 01 00 00 00 38 95 23 1C 72 FA B1 4A 90 57 D7 4C 62` | **same 18 bytes → `OK dev=2 fcnt=1 data=MKR SE #1`** |

## Progress
- [x] Step 1 – Read-only bring-up: the chip is an **ATECC608** (RevNum `00 00 60 03`), not the ATECC508A listed in the board's older documentation; configuration and data zones unlocked
- [x] Step 2 – Configuration designer (`tools/se_config.py`): builds the 128-byte configuration from the chip's own dump, explains every slot, refuses unsafe designs; 19 host tests
- [x] Step 3 – Configuration written and read back (all 128 bytes match, CRC `0x67BF`), still unlocked
- [x] Step 4 – **Configuration zone locked** with the summary-CRC check, so the chip itself would refuse to lock anything but the reviewed image; RNG switched from the documented test pattern to real output
- [x] Step 5 – Device identity key generated **inside** the chip (slot 0, 120 ms); public key validated as a P-256 point (fingerprint `5426fcf9e7676c8f`)
- [x] Step 6a – Chip AES checked against FIPS-197 and SP 800-38A known answers
- [x] Step 6 – Link keys loaded into slot 10, **data zone locked**; chip AES from slot 10 matched answers computed on the PC; ECDSA signature from slot 0 verified on the PC
- [x] Step 7 – LoRa node: AES-CTR + AES-CMAC built from the chip's single-block AES; 2,000 random packets byte-identical to the STM32 `secure_link.c`; Feather accepts the packets on air

## Hardware

| Part | Role |
|---|---|
| Arduino MKR WAN 1310 (SAMD21 Cortex-M0+, Murata LoRa module, firmware ARD-078 1.2.3) | Sender |
| Microchip ATECC608 on the MKR (I2C 0x60) | Secure element: identity key, link keys, AES, frame counter |
| Adafruit Feather M0 + RFM95 (`feather_receiver/` in the STM32 repo) | Receiver, unchanged |

Radio: 868.1 MHz, SF7, BW125, CR4/5, CRC on, +14 dBm, one packet every 15 s (EU 1 % duty cycle).

## Secure element layout

| Slot | Contents | Configuration | Who can read it |
|---|---|---|---|
| 0 | Device identity key, ECDSA P-256, generated inside the chip | SlotConfig `0x2083`, KeyConfig `0x0033` (factory/Arduino default) | Nobody; only the public key leaves the chip |
| 10 | LoRa link keys: AES key block 0 = encryption, key block 1 = MIC | SlotConfig `0x208F` (IsSecret, never readable, Write "never"), KeyConfig `0x0018` (AES) | Nobody, after the data lock |
| Counter[1] | LoRa frame counter | Monotonic, cannot decrease | — |

Only three configuration bytes were changed from the factory values (40, 41, 116), which kept the design small enough to review line by line.

## Packet format

Same as the STM32 project (LoRaWAN-style):
```
[dev_id 1B][fcnt 4B LE][AES-128-CTR ciphertext][AES-CMAC MIC 4B]
CTR block:  01 | dev_id | fcnt (LE) | 00 x9 | block index (from 1)
MIC:        first 4 bytes of AES-CMAC (RFC 4493) over dev_id || fcnt || ciphertext
```
The ATECC608 only offers AES-ECB on a single block. `firmware/se_lora_node/se_link.c` builds CTR and CMAC from those blocks; a short packet costs 3 chip operations (1 CTR + 2 CMAC).

## Measurements

| What | Value |
|---|---|
| Identity key generation (GenKey inside the chip) | 120 ms |
| Sealing one packet (9–10 byte payload, 3 chip AES operations over I2C) | 16.8 ms |
| Packets cross-checked against the STM32 `secure_link.c` | 2,000, 0 differences |
| Configuration bytes changed from factory | 3 |

## Evidence

Every step's Serial Monitor output is in `docs/` (`step1_bringup_output.txt` to `step7_mkr_output.txt` and `step7_feather_output.txt`), together with `device_identity_pub.pem`.

## Repository layout
```
firmware/
  se_bringup/        step 1  read-only dump of the configuration zone
  se_write_config/   step 3  write + verify the reviewed configuration
  se_lock_config/    step 4  lock with summary CRC (atecc_io.h: own command layer)
  se_identity_key/   step 5  GenKey in slot 0, export the public key
  se_aes_test/       step 6a AES known answers (TempKey and slot)
  se_provision/      step 6  load link keys, lock data zone, test AES + signature
  se_lora_node/      step 7  the LoRa node (se_link.c = CTR + CMAC over chip AES)
tools/
  se_config.py       configuration designer + lock CRC         (test_se_config.py)
  se_pubkey.py       validate/save the identity public key     (test_se_pubkey.py)
  se_provision.py    build the provisioning header (secret)    (test_se_provision.py)
  se_verify_sig.py   verify the chip's ECDSA signature
  test_se_link.py    tests the firmware's se_link.c from Python with real AES
  crosscheck/        se_link.c vs the STM32 secure_link.c, 2,000 packets
keys/                link keys (git-ignored; encrypted backup off the machine)
```

## Build and test
PC tests (Ubuntu/WSL2, `pip install cryptography`):
```bash
python3 tools/test_se_config.py
python3 tools/test_se_pubkey.py
python3 tools/test_se_provision.py
python3 tools/test_se_link.py
cd tools/crosscheck && make && ./crosscheck      # needs the STM32 repo's secure_link/
```
Firmware: Arduino IDE 2, board *Arduino MKR WAN 1310*, libraries **ArduinoECCX08** and **LoRa** (Sandeep Mistry). The LoRa library needs Murata firmware 1.1.6 or later (`MKRWAN` → `MKRWANFWUpdate_standalone`).

Steps 4 and 6 are permanent. Their sketches refuse to run from an unexpected state and need a typed confirmation (`LOCK CONFIG`, `LOCK DATA`).

## Findings
- **Read the chip, not the spec sheet.** The board was documented with an ATECC508A; the revision bytes said ATECC608. The 608 adds AES, which changed the whole design.
- **The vendor library locks without checking.** ArduinoECCX08's `lock()` sends the Lock command with the CRC check disabled and locks both zones at once. I wrote a small command layer (`atecc_io.h`, from Microchip's public data sheet and CryptoAuthLib) so the configuration lock carries the CRC of the reviewed image and the chip refuses anything else. A PC simulation showed that refusal before the real lock.
- **Slot AES before the data lock returns a parse error.** With the configuration locked but the data zone unlocked, AES from a key slot was refused with status `0x03` (parse error), while AES with the key in TempKey worked. Microchip's own tests only use slot AES after the data lock, but the public documentation does not say which error to expect, and a parse error usually suggests a configuration problem. I could not resolve this before the permanent lock, so I planned a fallback (AES via TempKey) in advance; after the lock, slot AES worked and matched the PC's answers.
- **A data-zone lock cannot be CRC-checked here**: the CRC would have to cover slot 0's private key, which nobody knows. The keys were proven correct by known answers instead.
- **The RNG doubles as a lock indicator.** Before the configuration lock the chip returns `FF FF 00 00 …` (as Microchip's ATECC508A data sheet documents); afterwards it returns real random data, an independent check that the lock took effect.
- **The hardware counter removed a whole class of bookkeeping.** The STM32 node needed EEPROM reserve-before-use blocks and jumped up to 100 counter values after a reset; here a reset or power cut continues from the next value (fcnt 10 → 11 and 13 → 14 on hardware).
- **Weak link budget noticed from RSSI.** The receiver reported about −112 dBm with the boards side by side, a reminder to check the MKR's external antenna (it has no on-board antenna).

## Known limitations
- **The I2C bus is visible.** An attacker with probes on the board sees the AES inputs and outputs (never the keys). The ATECC608's I/O protection key feature, not used here, encrypts that traffic.
- **Provisioning was in the clear.** The link keys crossed I2C once, unencrypted, at my desk; production would use encrypted writes or Microchip's secure provisioning.
- **The identity key can be replaced, not read.** Slot 0 keeps the factory setting that allows GenKey after the lock, so faulty or hostile firmware could overwrite the identity (denial of service) but never extract it. The configuration is locked, so this stays.
- **The link keys can never be changed.** Slot 10 is Write "never"; rotating keys means a new device. LoRaWAN instead derives session keys at each join.
- **Counter limit.** The monotonic counter stops at 2,097,151, about a year at one packet per 15 s. LoRaWAN uses 32-bit counters and rejoins.
- **The receiver still uses software keys** and a flash replay floor in steps of 100, so after a receiver reboot packets are rejected until the sender passes the floor (observed on hardware: `REJECTED: replay (fcnt not newer than 101)`).
- **Secure element, not secure system.** The SAMD21 firmware is not secure-booted, so modified firmware could still use the keys (without learning them). The STM32 project shows how a signed-boot chain closes that gap.
- **The link keys also exist as a file** on the development PC (git-ignored, with an encrypted backup off the machine), because the receiver needs them. Only the copy inside the chip cannot leak through software.

## Secure element vs SRAM PUF (my PhD)
My PhD used SRAM Physical Unclonable Functions for LoRaWAN device authentication, so this project was partly a comparison.

| | ATECC608 secure element | SRAM PUF |
|---|---|---|
| Where the secret comes from | Random key generated or written once, stored in protected memory | Power-up state of SRAM cells, unique per chip, nothing stored |
| Extra hardware | A dedicated chip (cost, board space, I2C) | None: uses memory already on the board |
| Reproducibility | Exact, every time | Noisy: needs error correction (helper data) or threshold matching, and varies with supply voltage, temperature and host platform |
| Crypto | ECDSA, ECDH, AES, SHA in hardware | Needs a software crypto stack once a key is derived |
| Attack surface | I2C bus, provisioning, firmware that can use the keys | Helper data, modelling and environmental attacks, the reconstruction code |
| Maturity | Commercial parts, vendor libraries, provisioning services | Largely research-grade outside commercial IP |

The two are complementary: a PUF can protect a key without storing it, while a secure element gives exact key storage and hardware crypto. The PhD characterised where SRAM PUF responses become unreliable; this project shows what the stored-key alternative costs in practice: an extra chip, 16.8 ms of I2C traffic per packet, and irreversible provisioning steps.

## Tools
Arduino IDE 2 · ArduinoECCX08 · LoRa (Sandeep Mistry) · MKRWAN (firmware update) · Microchip CryptoAuthLib (reference) · Python `cryptography` · gcc · gpg · Git
