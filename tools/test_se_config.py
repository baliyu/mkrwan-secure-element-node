#!/usr/bin/env python3
"""tools/test_se_config.py - PC tests for the ATECC608 configuration designer.

    python3 tools/test_se_config.py

CRC known answers were produced by Microchip CryptoAuthLib's own atCRC()
(lib/calib/calib_command.c), compiled unchanged; the Info packet CRC (03 5D)
is the widely published value for the ATECC Info command.
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import se_config as sc  # noqa: E402

DUMP = os.path.join(HERE, "..", "docs", "step1_bringup_output.txt")


def read(path):
    with open(path) as f:
        return f.read()


def factory():
    return sc.parse_dump(read(DUMP))


def mutate(image, offset, value):
    b = bytearray(image)
    b[offset] = value
    return bytes(b)


def set_slot(image, slot, slot_config=None, key_config=None):
    b = bytearray(image)
    if slot_config is not None:
        sc.put16(b, sc.OFF_SLOT_CONFIG + 2 * slot, slot_config)
    if key_config is not None:
        sc.put16(b, sc.OFF_KEY_CONFIG + 2 * slot, key_config)
    return bytes(b)


class Crc(unittest.TestCase):
    def test_known_answers_from_cryptoauthlib(self):
        self.assertEqual(sc.crc16(b"123456789").hex().upper(), "DDBC")
        self.assertEqual(sc.crc16(bytes(range(128))).hex().upper(), "9F24")
        self.assertEqual(sc.crc16(bytes([0x07, 0x02, 0, 0, 0])).hex().upper(), "1E2D")
        self.assertEqual(sc.crc16(b"\x00").hex().upper(), "0000")

    def test_info_command_packet(self):
        # count, opcode Info (0x30), param1, param2 -> CRC 03 5D
        self.assertEqual(sc.crc16(bytes([0x07, 0x30, 0x00, 0x00, 0x00])), bytes([0x03, 0x5D]))


class Dump(unittest.TestCase):
    def test_real_dump(self):
        f = factory()
        self.assertEqual(len(f), 128)
        self.assertEqual(f[0:2], bytes([0x01, 0x23]))            # every ATECC serial starts 01 23
        self.assertEqual(f[4:8], bytes([0x00, 0x00, 0x60, 0x03]))  # RevNum read on the board
        self.assertEqual(f[sc.OFF_LOCK_CONFIG], 0x55)
        self.assertEqual(f[sc.OFF_LOCK_VALUE], 0x55)
        self.assertEqual(sc.slot_config(f, 0), 0x2083)
        self.assertEqual(sc.key_config(f, 0), 0x0033)

    def test_missing_row_rejected(self):
        text = "\n".join(l for l in read(DUMP).splitlines() if not l.startswith("40:"))
        with self.assertRaises(ValueError):
            sc.parse_dump(text)


class Design(unittest.TestCase):
    def setUp(self):
        self.f = factory()
        self.img = sc.apply_design(self.f)

    def test_only_the_aes_slot_changes(self):
        diff = [i for i in range(128) if self.img[i] != self.f[i]]
        self.assertEqual(diff, [40, 41, 116])                  # SlotConfig[10] and KeyConfig[10] low byte
        self.assertEqual(sc.slot_config(self.img, 10), 0x208F)
        self.assertEqual(sc.key_config(self.img, 10), 0x0018)
        self.assertEqual(sc.key_type(sc.key_config(self.img, 10)), sc.KEY_TYPE_AES)

    def test_design_passes(self):
        self.assertEqual(sc.check(self.img, self.f), [])

    def test_lock_crc_is_crc_of_whole_image(self):
        self.assertEqual(sc.crc16(self.img), sc.crc16(bytes(self.img)))
        self.assertNotEqual(sc.crc16(self.img), sc.crc16(self.f))   # a 1-byte change moves the CRC

    def rejects(self, image, words):
        problems = sc.check(image, self.f)
        self.assertTrue(any(words in p for p in problems), "expected '%s' in %s" % (words, problems))

    def test_protected_byte_changed(self):
        self.rejects(mutate(self.img, 5, 0xFF), "read-only")       # RevNum byte (chip has 0x00)
        self.rejects(mutate(self.img, sc.OFF_LOCK_CONFIG, 0x00), "read-only")

    def test_aes_slot_readable(self):
        self.rejects(set_slot(self.img, 10, slot_config=0x200F), "readable")       # IsSecret cleared
        self.rejects(set_slot(self.img, 10, slot_config=0x20CF), "readable")       # EncRead set

    def test_aes_slot_rewritable(self):
        self.rejects(set_slot(self.img, 10, slot_config=0x008F), "overwritten")

    def test_aes_slot_wrong_type(self):
        self.rejects(set_slot(self.img, 10, key_config=0x001C), "not AES")
        self.rejects(set_slot(self.img, 10, key_config=0x0019), "private")

    def test_aes_slot_needs_auth_or_nonce(self):
        self.rejects(set_slot(self.img, 10, key_config=0x0098), "nonce/authorisation")
        self.rejects(set_slot(self.img, 10, key_config=0x0058), "nonce/authorisation")

    def test_aes_slot_limited_use(self):
        self.rejects(set_slot(self.img, 10, slot_config=0x20AF), "limited-use")

    def test_identity_slot_changed(self):
        self.rejects(set_slot(self.img, 0, slot_config=0x2003), "factory/Arduino default")

    def test_chip_already_locked(self):
        f = mutate(self.f, sc.OFF_LOCK_CONFIG, 0x00)
        self.assertTrue(any("already locked" in p for p in sc.check(sc.apply_design(f), f)))

    def test_not_a_608(self):
        f = mutate(self.f, 6, 0x50)
        self.assertTrue(any("not an ATECC608" in p for p in sc.check(sc.apply_design(f), f)))

    def test_aes_disabled(self):
        f = mutate(self.f, sc.OFF_AES_ENABLE, 0x60)
        self.assertTrue(any("AES is not enabled" in p for p in sc.check(sc.apply_design(f), f)))

    def test_i2c_address_changed(self):
        self.rejects(mutate(self.img, sc.OFF_I2C_ADDRESS, 0xC2), "I2C address")


class Header(unittest.TestCase):
    def test_header_compiles_and_matches(self):
        img = sc.apply_design(factory())
        with tempfile.TemporaryDirectory() as d:
            h = os.path.join(d, "se_config_image.h")
            with open(h, "w") as fh:
                fh.write(sc.c_header(img))
            c = os.path.join(d, "t.c")
            with open(c, "w") as fc:
                fc.write(
                '#include <stdio.h>\n#include "se_config_image.h"\n'
                "int main(void){for(int i=0;i<128;i++)printf(\"%02X\",SE_CONFIG_IMAGE[i]);"
                'printf(" %04X %d %d\\n",SE_CONFIG_LOCK_CRC,SE_IDENTITY_SLOT,SE_AES_SLOT);return 0;}\n')
            exe = os.path.join(d, "t")
            subprocess.check_call(["gcc", "-Wall", "-Werror", "-o", exe, c])
            out = subprocess.check_output([exe]).decode().split()
        self.assertEqual(out[0], img.hex().upper())
        crc = sc.crc16(img)
        self.assertEqual(int(out[1], 16), crc[0] | (crc[1] << 8))
        self.assertEqual((int(out[2]), int(out[3])), (sc.IDENTITY_SLOT, sc.AES_SLOT))


if __name__ == "__main__":
    unittest.main(verbosity=2)
