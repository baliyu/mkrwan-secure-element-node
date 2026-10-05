#!/usr/bin/env python3
"""tools/se_config.py - ATECC608 configuration designer (step 2, PC only).

Reads the configuration zone dumped by firmware/se_bringup (Serial Monitor
text), applies this project's slot design, checks it against safety rules,
explains every slot in words, and writes the 128-byte image plus the CRC
that the Lock command will be given in step 4.

    python3 tools/se_config.py docs/step1_bringup_output.txt
    python3 tools/se_config.py docs/step1_bringup_output.txt --header firmware/se_config_image.h

Nothing here talks to the chip.

Sources for every field position and bit (no NDA datasheet used):
  - Microchip CryptoAuthLib, lib/calib/calib_device.h (atecc608_config_t,
    ATCA_SLOT_CONFIG_* and ATCA_KEY_CONFIG_* masks) and calib_command.h
    (ATCA_P256_KEY_TYPE=4, ATCA_AES_KEY_TYPE=6, ATCA_SHA_KEY_TYPE=7, atCRC).
  - Microchip's own ATECC608 test configuration (test_calib_config.c), whose
    AES key slot uses KeyConfig KeyType=6.
  - ArduinoECCX08 ECCX08DefaultTLSConfig.h: slot 0 = 0x2083 / 0x0033 is the
    ECC private-key slot the Arduino library generates keys in on MKR boards.
"""
import argparse
import re
import sys

CONFIG_SIZE = 128

# ---- field offsets (CryptoAuthLib atecc608_config_t) ------------------------
OFF_SN03, OFF_REVNUM, OFF_SN48 = 0, 4, 8
OFF_AES_ENABLE = 13
OFF_I2C_ENABLE = 14
OFF_I2C_ADDRESS = 16
OFF_SLOT_CONFIG = 20            # 16 x uint16 little-endian
OFF_USER_EXTRA = 84
OFF_LOCK_VALUE = 86
OFF_LOCK_CONFIG = 87
OFF_SLOT_LOCKED = 88
OFF_KEY_CONFIG = 96             # 16 x uint16 little-endian (ATCA_KEY_CONFIG_OFFSET)

# Bytes the chip does not let us write with the Write command: 0-15 are
# factory/read-only, 84-87 (UserExtra, UserExtraAdd, LockValue, LockConfig)
# are changed only by dedicated commands. The image must keep them as read.
PROTECTED = list(range(0, 16)) + list(range(84, 88))

# ---- SlotConfig bits (ATCA_SLOT_CONFIG_*) ------------------------------------
SC_READKEY_MASK = 0x000F         # for ECC private keys: ExtSig, IntSig, ECDH, WriteECDH
SC_NOMAC = 1 << 4
SC_LIMITED_USE = 1 << 5
SC_ENC_READ = 1 << 6
SC_IS_SECRET = 1 << 7
SC_WRITE_KEY_SHIFT = 8
SC_WRITE_CONFIG_SHIFT = 12
SC_EXT_SIG, SC_INT_SIG, SC_ECDH = 1 << 0, 1 << 1, 1 << 2

# ---- KeyConfig bits (ATCA_KEY_CONFIG_*) --------------------------------------
KC_PRIVATE = 1 << 0
KC_PUB_INFO = 1 << 1
KC_KEY_TYPE_SHIFT = 2
KC_LOCKABLE = 1 << 5
KC_REQ_RANDOM = 1 << 6
KC_REQ_AUTH = 1 << 7
KC_PERSIST_DISABLE = 1 << 12
KEY_TYPE_P256, KEY_TYPE_AES, KEY_TYPE_SHA = 4, 6, 7
KEY_TYPE_NAMES = {KEY_TYPE_P256: "P-256 ECC", KEY_TYPE_AES: "AES-128", KEY_TYPE_SHA: "SHA / other data"}

WRITE_CONFIG_NEVER = 0x2         # Arduino's default config labels 0x2 "Write Configure Never"

# ---- this project's design ---------------------------------------------------
IDENTITY_SLOT = 0                # device identity key: kept exactly as the factory/Arduino default
AES_SLOT = 10                    # LoRa link keys: key block 0 = encryption, block 1 = MIC (same slot
                                 # Microchip's own 608 test configuration uses for AES)
DESIGN = {
    AES_SLOT: {
        # IsSecret=1, EncRead=0 -> never readable; ReadKey=0xF as in Microchip's test AES slot;
        # WriteConfig=0x2 (Never) -> no Write command can change it once the data zone is locked.
        "slot_config": SC_IS_SECRET | 0xF | (WRITE_CONFIG_NEVER << SC_WRITE_CONFIG_SHIFT),   # 0x208F
        # KeyType=AES, not lockable, no random nonce or authorisation needed to use it.
        "key_config": KEY_TYPE_AES << KC_KEY_TYPE_SHIFT,                                       # 0x0018
        "purpose": "LoRa link keys (AES-128): block 0 = encryption key, block 1 = MIC key",
    },
}
PURPOSE = {
    IDENTITY_SLOT: "Device identity private key (generated inside, never readable)",
    AES_SLOT: DESIGN[AES_SLOT]["purpose"],
}


# ---- helpers -----------------------------------------------------------------
def crc16(data):
    """ATECC CRC-16 (poly 0x8005, LSB-first), same as CryptoAuthLib atCRC.
    Returns the two bytes in the order the chip uses (little-endian)."""
    crc = 0
    for byte in data:
        for bit in range(8):
            data_bit = (byte >> bit) & 1
            crc_bit = (crc >> 15) & 1
            crc = (crc << 1) & 0xFFFF
            if data_bit != crc_bit:
                crc ^= 0x8005
    return bytes([crc & 0xFF, crc >> 8])


def parse_dump(text):
    """Extract the 128 config bytes from se_bringup's Serial Monitor output."""
    rows = {}
    for line in text.splitlines():
        m = re.match(r"\s*([0-7][0-9A-Fa-f]):((?:\s+[0-9A-Fa-f]{2}){16})\s*$", line)
        if m:
            rows[int(m.group(1), 16)] = bytes(int(x, 16) for x in m.group(2).split())
    expected = list(range(0, CONFIG_SIZE, 16))
    if sorted(rows) != expected:
        raise ValueError("dump must contain the 8 rows 00..70, found: %s" %
                         ", ".join("%02X" % r for r in sorted(rows)))
    return b"".join(rows[r] for r in expected)


def get16(cfg, off):
    return cfg[off] | (cfg[off + 1] << 8)


def put16(cfg, off, value):
    cfg[off] = value & 0xFF
    cfg[off + 1] = (value >> 8) & 0xFF


def slot_config(cfg, slot):
    return get16(cfg, OFF_SLOT_CONFIG + 2 * slot)


def key_config(cfg, slot):
    return get16(cfg, OFF_KEY_CONFIG + 2 * slot)


def key_type(kc):
    return (kc >> KC_KEY_TYPE_SHIFT) & 0x7


def apply_design(factory):
    if len(factory) != CONFIG_SIZE:
        raise ValueError("config must be 128 bytes")
    image = bytearray(factory)
    for slot, d in DESIGN.items():
        put16(image, OFF_SLOT_CONFIG + 2 * slot, d["slot_config"])
        put16(image, OFF_KEY_CONFIG + 2 * slot, d["key_config"])
    return bytes(image)


def check(image, factory):
    """Safety rules. Returns a list of problems (empty = OK)."""
    p = []
    if len(image) != CONFIG_SIZE:
        return ["image is not 128 bytes"]
    for i in PROTECTED:
        if image[i] != factory[i]:
            p.append("byte %d (read-only / command-only) differs from the chip" % i)
    if factory[OFF_LOCK_CONFIG] != 0x55:
        p.append("config zone is already locked on this chip")
    if factory[OFF_LOCK_VALUE] != 0x55:
        p.append("data zone is already locked on this chip")
    if (factory[OFF_REVNUM + 2] & 0xF0) != 0x60:
        p.append("not an ATECC608 (RevNum %s)" % factory[4:8].hex())
    if not (factory[OFF_AES_ENABLE] & 0x01):
        p.append("AES is not enabled on this chip (AES_Enable bit 0 clear)")
    if image[OFF_I2C_ADDRESS] != 0xC0:
        p.append("I2C address changed from 0xC0 (0x60): the board would lose the chip")

    sc, kc = slot_config(image, IDENTITY_SLOT), key_config(image, IDENTITY_SLOT)
    if sc != slot_config(factory, IDENTITY_SLOT) or kc != key_config(factory, IDENTITY_SLOT):
        p.append("identity slot must stay as the factory/Arduino default")
    if not (kc & KC_PRIVATE) or key_type(kc) != KEY_TYPE_P256:
        p.append("identity slot is not a P-256 private key slot")
    if not (sc & SC_IS_SECRET) or (sc & SC_ENC_READ):
        p.append("identity slot would be readable")

    sc, kc = slot_config(image, AES_SLOT), key_config(image, AES_SLOT)
    if key_type(kc) != KEY_TYPE_AES:
        p.append("AES slot KeyType is not AES (6)")
    if kc & KC_PRIVATE:
        p.append("AES slot marked as ECC private key")
    if kc & (KC_REQ_RANDOM | KC_REQ_AUTH):
        p.append("AES slot needs a nonce/authorisation: firmware could not use it simply")
    if not (sc & SC_IS_SECRET) or (sc & SC_ENC_READ):
        p.append("AES slot would be readable (needs IsSecret=1, EncRead=0)")
    if (sc >> SC_WRITE_CONFIG_SHIFT) != WRITE_CONFIG_NEVER:
        p.append("AES slot could be overwritten after the data zone is locked")
    if sc & SC_LIMITED_USE:
        p.append("AES slot is limited-use: every packet would count against a counter")
    return p


def describe_slot(cfg, slot):
    sc, kc = slot_config(cfg, slot), key_config(cfg, slot)
    kt = key_type(kc)
    secret = bool(sc & SC_IS_SECRET)
    parts = ["%s key" % KEY_TYPE_NAMES.get(kt, "type %d" % kt)]
    if kc & KC_PRIVATE:
        parts.append("private")
        sig = [n for b, n in ((SC_EXT_SIG, "ext-sign"), (SC_INT_SIG, "int-sign"), (SC_ECDH, "ECDH")) if sc & b]
        parts.append("uses: " + (", ".join(sig) if sig else "none"))
    if secret and not (sc & SC_ENC_READ):
        parts.append("NEVER readable")
    elif secret:
        parts.append("encrypted reads only (ReadKey slot %d)" % (sc & SC_READKEY_MASK))
    else:
        parts.append("readable in clear")
    wc = sc >> SC_WRITE_CONFIG_SHIFT
    parts.append("writes after data lock: %s" % {0x0: "always", WRITE_CONFIG_NEVER: "never"}.get(
        wc, "WriteConfig=0x%X (see datasheet)" % wc))
    if kc & KC_LOCKABLE:
        parts.append("slot-lockable")
    if kc & KC_REQ_RANDOM:
        parts.append("needs random nonce")
    if kc & KC_REQ_AUTH:
        parts.append("needs auth by slot %d" % ((kc >> 8) & 0xF))
    if sc & SC_LIMITED_USE:
        parts.append("limited use")
    return "slot %2d  SlotConfig=0x%04X KeyConfig=0x%04X  %s" % (slot, sc, kc, "; ".join(parts))


def report(image, factory):
    out = []
    out.append("ATECC608 configuration design")
    out.append("Serial: %s%s   RevNum: %s   I2C: 0x%02X   AES_Enable: 0x%02X" % (
        image[0:4].hex().upper(), image[8:13].hex().upper(), image[4:8].hex().upper(),
        image[OFF_I2C_ADDRESS] >> 1, image[OFF_AES_ENABLE]))
    out.append("")
    for s in range(16):
        tag = ""
        if s in PURPOSE:
            tag = "  <- " + PURPOSE[s]
        changed = (slot_config(image, s), key_config(image, s)) != (slot_config(factory, s), key_config(factory, s))
        out.append(("* " if changed else "  ") + describe_slot(image, s) + tag)
    out.append("")
    diff = [i for i in range(CONFIG_SIZE) if image[i] != factory[i]]
    out.append("Bytes changed from the chip's factory values: %s" % (
        ", ".join("%d (0x%02X->0x%02X)" % (i, factory[i], image[i]) for i in diff) or "none"))
    crc = crc16(image)
    out.append("Lock CRC (summary of all 128 bytes): bytes %02X %02X, value 0x%04X" % (
        crc[0], crc[1], crc[0] | (crc[1] << 8)))
    return "\n".join(out)


def c_header(image):
    lines = ["/* Generated by tools/se_config.py - do not edit by hand. */",
             "#pragma once", "#include <stdint.h>", "",
             "/* Full 128-byte ATECC608 configuration image for this device. */",
             "static const uint8_t SE_CONFIG_IMAGE[128] = {"]
    for r in range(0, CONFIG_SIZE, 16):
        lines.append("  " + ", ".join("0x%02X" % b for b in image[r:r + 16]) + ",")
    crc = crc16(image)
    lines += ["};", "",
              "/* CRC the Lock command must be given (little-endian bytes %02X %02X). */" % (crc[0], crc[1]),
              "#define SE_CONFIG_LOCK_CRC 0x%04XU" % (crc[0] | (crc[1] << 8)),
              "#define SE_IDENTITY_SLOT %d" % IDENTITY_SLOT,
              "#define SE_AES_SLOT %d" % AES_SLOT, ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dump", help="Serial Monitor output from se_bringup")
    ap.add_argument("--header", help="write the C header with the image and lock CRC")
    a = ap.parse_args(argv)
    with open(a.dump) as f:
        factory = parse_dump(f.read())
    image = apply_design(factory)
    print(report(image, factory))
    problems = check(image, factory)
    print()
    if problems:
        for x in problems:
            print("PROBLEM:", x)
        print("Design REJECTED - nothing written.")
        return 1
    print("All safety checks passed.")
    if a.header:
        with open(a.header, "w") as f:
            f.write(c_header(image))
        print("Wrote", a.header)
    return 0


if __name__ == "__main__":
    sys.exit(main())
