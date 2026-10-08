# Security policy

`mkrwan-secure-element-node` is a personal engineering project (a demonstrator), not a commercial product. I take security reports seriously and handle them on a best-effort basis.

## Supported versions
Only the latest commit on `main` is maintained.

## Reporting a vulnerability
Please do **not** open a public issue for a security problem.

1. Preferred: use GitHub's private vulnerability reporting (Security tab, then "Report a vulnerability").
2. Or email baliyu70@gmail.com with the subject `SECURITY: mkrwan-secure-element-node`.

Please include what you found, the affected files or commit, how to reproduce it (including any hardware or phone you used), the impact you see, and whether you plan to publish.

## What to expect
- I aim to acknowledge a report within 7 days. I work alone, so this is a target, not a guarantee.
- I will tell you whether I can reproduce it and agree a disclosure date with you (coordinated disclosure). I aim to fix or document the problem within 90 days.
- Once a fix exists I publish a GitHub security advisory with a description, the affected commits, the severity and what to do, and credit you if you wish.

## In scope
- Any way for firmware or a bus attacker to read slot 10 or otherwise extract the link keys from the secure element.
- Flaws in the configuration design (`tools/se_config.py`) or the lock sequence.
- Weaknesses in the packet format, counter use or the provisioning tools.

## Out of scope
- Eavesdropping on the I2C bus, which exposes AES inputs and outputs but not keys: a documented limitation.
- Attacks on the ATECC608 chip itself.
- The unsigned SAMD21 firmware, a documented limitation.
- Denial of service by radio jamming.

## Known limitations
The residual risks I already know about are listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). A report that only restates one of them is welcome as a discussion but is not a new vulnerability.
