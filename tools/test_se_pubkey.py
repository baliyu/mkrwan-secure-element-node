#!/usr/bin/env python3
"""tools/test_se_pubkey.py - PC tests for the identity-key checker.

    python3 tools/test_se_pubkey.py
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import se_pubkey as sp  # noqa: E402


def raw_from_key(pub):
    n = pub.public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


class PubKey(unittest.TestCase):
    def setUp(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.raw = raw_from_key(self.priv.public_key())
        self.text = "noise\nPUBKEY: %s\nmore noise\n" % self.raw.hex().upper()

    def test_parse(self):
        self.assertEqual(sp.parse_pubkey(self.text), self.raw)

    def test_same_line_twice_is_fine(self):
        self.assertEqual(sp.parse_pubkey(self.text + self.text), self.raw)

    def test_two_different_keys_rejected(self):
        other = raw_from_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        with self.assertRaises(ValueError):
            sp.parse_pubkey(self.text + "PUBKEY: %s\n" % other.hex())

    def test_missing_or_short(self):
        with self.assertRaises(ValueError):
            sp.parse_pubkey("no key here")
        with self.assertRaises(ValueError):
            sp.parse_pubkey("PUBKEY: " + self.raw[:63].hex())

    def test_valid_point_round_trip(self):
        key = sp.to_public_key(self.raw)
        self.assertEqual(raw_from_key(key), self.raw)

    def test_point_off_curve_rejected(self):
        bad = bytearray(self.raw)
        bad[63] ^= 0x01                                     # change Y by one bit
        with self.assertRaises(ValueError):
            sp.to_public_key(bytes(bad))

    def test_all_zero_rejected(self):
        with self.assertRaises(ValueError):
            sp.to_public_key(bytes(64))

    def test_pem_verifies_a_signature_from_the_matching_private_key(self):
        # what step 6 will do with a signature from the chip
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.txt")
            with open(out, "w") as f:
                f.write(self.text)
            with contextlib.redirect_stdout(io.StringIO()):     # keep the test log clean
                self.assertEqual(sp.main([out]), 0)
            with open(os.path.join(d, "device_identity_pub.pem"), "rb") as f:
                pub = serialization.load_pem_public_key(f.read())
        msg = b"challenge"
        sig = self.priv.sign(msg, ec.ECDSA(hashes.SHA256()))
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))       # raises if wrong

    def test_fingerprint_is_stable(self):
        self.assertEqual(sp.fingerprint(bytes(64)), "f5a5fd42d16a2030")


if __name__ == "__main__":
    unittest.main(verbosity=2)
