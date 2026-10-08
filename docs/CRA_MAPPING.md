# CRA gap analysis: MKR WAN 1310 secure-element LoRa node

Self-assessment by the author, 8 October 2026, against Annex I of the EU Cyber Resilience Act (Regulation (EU) 2024/2847). **This repository is a demonstrator, not a product placed on the EU market, so the Act does not apply to it.** The exercise asks how it would measure up if it were a product. It is not legal advice and not a conformity assessment. Requirement wording is paraphrased; the exact text is in the Official Journal.

**Dates:** the reporting obligations (Article 14) apply from 11 September 2026; the rest of the Act, including all Annex I requirements and CE marking, applies from 11 December 2027.

**Reporting (Article 14), for a real product:** a manufacturer must notify actively exploited vulnerabilities and severe incidents through ENISA's single reporting platform: an early warning within 24 hours, a notification within 72 hours, and a final report within 14 days after a fix is available (vulnerabilities). The contact point for this repository is in `SECURITY.md`.

Status: **Met** / **Partly** (something required is missing) / **Not met** / **Not assessed** (I have not checked).

**Result:** 4 met, 11 partly, 5 not met, 2 not assessed, out of 22 requirements. Threat model: [THREAT_MODEL.md](THREAT_MODEL.md).

## Part I: properties of the product

| Annex I | Requirement (paraphrased) | Status | Evidence or gap |
|---|---|---|---|
| Part I, 1 | Appropriate cybersecurity level, based on the risks | **Partly** | A design-level threat model exists (`THREAT_MODEL.md`), self-assessed. |
| Part I, 2(a) | No known exploitable vulnerabilities when released | **Not assessed** | I have not checked the Arduino libraries and the SAMD21 core against published advisories. |
| Part I, 2(b) | Secure by default; the product can be reset to its original state | **Not met** | Secure by default in the sense that the keys are locked inside the chip, but the lock is permanent, so the product cannot be reset to its original state. |
| Part I, 2(c) | Vulnerabilities can be fixed by security updates (automatic by default with opt-out, update notices, postponement) | **Not met** | No update mechanism and no signed firmware. The link keys can never be changed. |
| Part I, 2(d) | Protection from unauthorised access (authentication, access management) and reporting of possible unauthorised access | **Partly** | Packets are authenticated with keys that never leave the secure element. Nothing reports attempted unauthorised access. |
| Part I, 2(e) | Confidentiality of stored and transmitted data (state-of-the-art encryption) | **Partly** | Keys are protected inside the chip and the payload is encrypted. The I2C bus is visible and the keys crossed it once in the clear during provisioning. |
| Part I, 2(f) | Integrity of data, commands, programs and configuration; reporting of corruption | **Partly** | CMAC on packets, a hardware monotonic counter, a CRC-checked configuration lock. The SAMD21 firmware itself is not integrity-protected. |
| Part I, 2(g) | Data minimisation | **Met** | Only a short payload and a device id are sent; no personal data. |
| Part I, 2(h) | Availability of essential functions, also after an incident; resilience against denial of service | **Partly** | The counter ends after about a year at one packet per 15 s, and firmware or an I2C attacker could use it up (analysis, not tested). Jamming is not addressed. |
| Part I, 2(i) | Limited negative impact on the availability of other devices and networks | **Met** | One short packet every 15 s, inside the EU 1 % duty cycle. |
| Part I, 2(j) | Limited attack surface, including external interfaces | **Partly** | LoRa, USB and the internal I2C bus; the board's external interfaces are otherwise unused. |
| Part I, 2(k) | Exploitation mitigation to reduce the impact of an incident | **Not assessed** | I have not examined the SAMD21's exploit-mitigation options. |
| Part I, 2(l) | Security logging and monitoring of relevant internal activity (with user opt-out) | **Not met** | Nothing is logged persistently. |
| Part I, 2(m) | Users can securely and easily remove all data and settings permanently | **Not met** | By design the keys and configuration can never be erased or changed. |

## Part II: vulnerability handling

| Annex I | Requirement (paraphrased) | Status | Evidence or gap |
|---|---|---|---|
| Part II, (1) | Identify and document vulnerabilities and components, including a machine-readable SBOM (at least top-level dependencies) | **Partly** | Libraries are named in the README (ArduinoECCX08, LoRa). No machine-readable SBOM. |
| Part II, (2) | Fix vulnerabilities without delay, including by security updates | **Partly** | `SECURITY.md` commits to fixing reported issues, but fixes need a manual reflash and keys cannot be rotated. |
| Part II, (3) | Effective and regular security tests and reviews | **Partly** | Python tests for the configuration designer and packet code, 2,000 packets cross-checked against the STM32 implementation, known-answer tests, a threat model. No fuzzing or independent review. |
| Part II, (4) | Publicly disclose fixed vulnerabilities once an update is available | **Partly** | `SECURITY.md` promises a GitHub security advisory once a fix exists; none has been needed yet. |
| Part II, (5) | A coordinated vulnerability disclosure policy | **Met** | `SECURITY.md` states the coordinated disclosure policy. |
| Part II, (6) | Facilitate reporting, including a contact address, for the product and its third-party components | **Met** | `SECURITY.md` gives a private reporting route and an email address. |
| Part II, (7) | Mechanisms to distribute updates securely (automatic where applicable) | **Not met** | No secure update channel. |
| Part II, (8) | Disseminate updates without delay, free of charge, with advisory messages | **Partly** | Free (MIT) and advisories would go through GitHub; no delivery to devices. |

## The three gaps I would close first

1. **No update path or signed firmware** (I.2c, I.2f, II.7): add secure boot for the SAMD21, as in the STM32 project.
1. **Immutable keys** (I.2b, I.2m): derive session keys at each join, as LoRaWAN does, instead of one permanent key.
1. **Security event log and counter exhaustion** (I.2l, I.2h): log events and plan for a rejoin before the counter ends.
