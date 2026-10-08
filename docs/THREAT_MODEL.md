# Threat model: MKR WAN 1310 secure-element LoRa node

Design-level analysis written by the author on 8 October 2026, using STRIDE on each trust boundary. It is a self-assessment, not an independent review. "Evidence" points to results already in this repository; items marked *analysis* are reasoning I have not tested.

## Scope and attackers
**In scope:** the ATECC608 configuration and key slots, the SAMD21 firmware that uses them, the LoRa packets, and the provisioning steps.
**Out of scope:** the Feather receiver's own security, side channels on the chip, and the Murata radio module's firmware.

| Attacker | Capability |
|---|---|
| A1 Radio attacker | Receives, replays, forges and jams on 868.1 MHz. |
| A2 Board-level attacker | Probes the I2C bus between the SAMD21 and the ATECC608, or runs their own code on the SAMD21. |
| A3 Provisioning/PC attacker | Gets at the development PC while keys are loaded or backed up. |

## Assets
Link keys (slot 10) · device identity key (slot 0) · monotonic counter 1 (frame counter) · chip configuration and lock state · authenticity and secrecy of the payload.

## Data flow and trust boundaries
```
 SAMD21 firmware (not secure-booted) --I2C (B2, probe-able)--> ATECC608: slot 0 identity, slot 10 link keys, counter 1
        |
        +--- LoRa packet: [dev_id][fcnt][AES-CTR ciphertext][AES-CMAC MIC] --- boundary B1: radio (A1) ---> Feather receiver
 Provisioning at the desk (B3): link keys cross I2C once, unencrypted; a copy of the keys lives on the PC
```

## Threats and mitigations
| ID | STRIDE | Threat | What stops it (evidence) | Residual risk |
|---|---|---|---|---|
| SE-01 | I | Firmware or an attacker reads the link keys | Slot 10 is secret, never readable, write "never"; data zone locked; every AES block is computed inside the chip. Evidence: chip AES matched answers computed on the PC after the lock. | Keys crossed I2C once in clear during provisioning, and also exist as a git-ignored file on the PC with an encrypted backup (A3). |
| SE-02 | I | A2 watches the I2C bus | Keys never travel, only AES inputs and outputs. | Plaintext, ciphertext and CMAC blocks are visible. The chip's I/O protection key (not used) would encrypt that traffic. |
| SE-03 | S, T | A1 forges or alters a packet | Without the chip's keys the MIC and keystream cannot be computed. Evidence: 2,000 random packets byte-identical to the software implementation; the unchanged receiver accepts the packets on air. | The MIC is 4 bytes (2^-32 guess chance per attempt). Keys are symmetric and also held by the receiver and the PC, so compromising either allows impersonation. |
| SE-04 | S | Impersonating the device identity | Identity key generated inside the chip; only the public key leaves it; an ECDSA signature from slot 0 verified on the PC. | The identity key is not used in the packet protocol today. |
| SE-05 | T | A1 replays a packet | Hardware monotonic counter used as the frame counter; it cannot decrease and continued after resets (fcnt 10 to 11 and 13 to 14 on hardware). | The counter stops at 2,097,151 (about a year at one packet per 15 s). The receiver floor moves in steps of 100 and rejected packets after a receiver reboot (observed). |
| SE-06 | D | A2 or malicious firmware burns through the counter | *Analysis:* not mitigated. As far as I know the counter increment needs no authorisation; I have not tested it. | Would permanently stop the node once the limit is hit. |
| SE-07 | T | Someone changes the chip configuration | Configuration zone locked with a summary-CRC check (the chip refuses any image other than the reviewed one); a real RNG output confirms the lock. | Slot 0 keeps the factory setting that allows key generation after the lock: faulty or hostile firmware could overwrite the identity (denial of service), never extract it. |
| SE-08 | E | Modified SAMD21 firmware uses the keys without learning them | Not mitigated: the SAMD21 is not secure-booted. The STM32 project shows the boot chain that would close this. | An attacker with flash access can seal valid packets using the chip. |
| SE-09 | D | Irreversible mistakes bricking the chip | Permanent steps are guarded: typed confirmations (LOCK CONFIG, LOCK DATA), a CRC-checked lock, a PC simulation that showed the refusal first. | The link keys can never be changed; rotation means a new device. |
| SE-10 | I | A1 reads the payload | AES-128-CTR with chip keys. | Device id, counter, length and timing stay visible. |
| SE-11 | D | A1 jams the channel | Not mitigated. | Accepted. The receiver saw about -112 dBm with the boards side by side, a reminder to check the external antenna. |
| SE-12 | R | No signed record of what the node sent | Not implemented. | Gap, and low priority for this demo. |

## Top residual risks
1. **Unprotected I2C bus and clear-text provisioning** (SE-01, SE-02): use the I/O protection key and encrypted writes.
2. **Unsigned SAMD21 firmware** (SE-08): add secure boot, as in the STM32 project.
3. **Counter exhaustion** (SE-05, SE-06): move to session keys with a rejoin, as LoRaWAN does.
