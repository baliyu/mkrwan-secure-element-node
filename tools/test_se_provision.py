#!/usr/bin/env python3
"""tools/test_se_provision.py - PC tests for step 6 tools.

    python3 tools/test_se_provision.py
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import se_provision as sp  # noqa: E402
import se_verify_sig as sv  # noqa: E402

ENC = bytes(range(0x10, 0x20))
MIC = bytes(range(0x20, 0x30))
KEYS_H = ("#define SL_DEV_ID 0x01U\n"
          "static const uint8_t SL_ENC_KEY[16] = { %s };\n"
          "static const uint8_t SL_MIC_KEY[16] = { %s };\n") % (
    ", ".join("0x%02X" % b for b in ENC), ", ".join("0x%02X" % b for b in MIC))


def quiet(fn, *a):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a)


class Keys(unittest.TestCase):
    def test_parse_gen_keys_format(self):
        self.assertEqual(sp.parse_keys(KEYS_H), (ENC, MIC))

    def test_example_file_rejected(self):
        with self.assertRaises(ValueError):
            sp.parse_keys("SL_ENC_KEY[16] = { 0 }; SL_MIC_KEY[16] = { 0 };")

    def test_all_zero_rejected(self):
        z = ", ".join(["0x00"] * 16)
        with self.assertRaises(ValueError):
            sp.parse_keys("SL_ENC_KEY[16] = { %s }; SL_MIC_KEY[16] = { %s };" % (z, z))

    def test_equal_keys_rejected(self):
        h = KEYS_H.replace("SL_MIC_KEY", "XX").replace("SL_ENC_KEY", "SL_MIC_KEY")
        h = h.replace("XX", "SL_ENC_KEY")
        same = h.split("\n")
        same[2] = same[1].replace("SL_MIC_KEY", "SL_ENC_KEY")
        with self.assertRaises(ValueError):
            sp.parse_keys("\n".join(same))

    def test_kat_matches_fips197_with_its_key(self):
        # FIPS-197 C.1: key 00..0F, pt 00112233..FF -> 69C4E0D8..
        self.assertEqual(sp.aes_ecb(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")


class Header(unittest.TestCase):
    def test_header_compiles_and_holds_the_right_values(self):
        pub_key = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        pub = pub_key.x.to_bytes(32, "big") + pub_key.y.to_bytes(32, "big")
        text, ct = sp.build_header(ENC, MIC, pub)
        self.assertEqual(ct[0], sp.aes_ecb(ENC, sp.KAT_PT[0]))
        self.assertEqual(ct[1], sp.aes_ecb(MIC, sp.KAT_PT[1]))
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "p.h"), "w") as f:
                f.write(text)
            with open(os.path.join(d, "t.c"), "w") as f:
                f.write('#include <stdio.h>\n#include "p.h"\nint main(void){int i;'
                        'for(i=0;i<32;i++)printf("%02X",SE_LINK_KEYS[i]);printf(" ");'
                        'for(i=0;i<16;i++)printf("%02X",SE_KAT_CT[1][i]);printf(" ");'
                        'for(i=0;i<64;i++)printf("%02X",SE_IDENTITY_PUBKEY[i]);return 0;}\n')
            subprocess.check_call(["gcc", "-Wall", "-Werror", "-Wno-unused-variable", "-o",
                                   os.path.join(d, "t"), os.path.join(d, "t.c")])
            out = subprocess.check_output([os.path.join(d, "t")]).decode().split()
        self.assertEqual(out[0], (ENC + MIC).hex().upper())
        self.assertEqual(out[1], ct[1].hex().upper())
        self.assertEqual(out[2], pub.hex().upper())


class Signature(unittest.TestCase):
    def setUp(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.msg = os.urandom(32)
        der = self.priv.sign(self.msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        self.sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")       # chip format R||S

    def text(self, msg=None, sig=None):
        return "x\nSIGN_MSG: %s\nSIGNATURE: %s\n" % ((msg or self.msg).hex(), (sig or self.sig).hex())

    def test_valid(self):
        m, s = sv.parse(self.text())
        self.assertTrue(sv.verify(self.priv.public_key(), m, s))

    def test_changed_challenge_rejected(self):
        m = bytearray(self.msg); m[0] ^= 1
        self.assertFalse(sv.verify(self.priv.public_key(), bytes(m), self.sig))

    def test_changed_signature_rejected(self):
        s = bytearray(self.sig); s[40] ^= 1
        self.assertFalse(sv.verify(self.priv.public_key(), self.msg, bytes(s)))

    def test_other_key_rejected(self):
        other = ec.generate_private_key(ec.SECP256R1()).public_key()
        self.assertFalse(sv.verify(other, self.msg, self.sig))

    def test_main_with_pem(self):
        with tempfile.TemporaryDirectory() as d:
            out, pem = os.path.join(d, "o.txt"), os.path.join(d, "k.pem")
            with open(out, "w") as f:
                f.write(self.text())
            with open(pem, "wb") as f:
                f.write(self.priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo))
            self.assertEqual(quiet(sv.main, [out, pem]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
