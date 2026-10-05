#!/usr/bin/env python3
"""tools/se_pubkey.py - step 5 (PC side): check and save the device identity
public key that the ATECC608 exported.

    python3 tools/se_pubkey.py docs/step5_identity_key_output.txt

Finds the "PUBKEY: <128 hex>" line printed by firmware/se_identity_key,
checks the 64 bytes (X then Y, big-endian, as the chip outputs them) form a
valid point on NIST P-256, and writes docs/device_identity_pub.pem plus a
short fingerprint (SHA-256 of the 64 raw bytes) to quote in the README.
Needs: pip install cryptography
"""
import argparse
import hashlib
import os
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def parse_pubkey(text):
    keys = re.findall(r"PUBKEY:\s*([0-9A-Fa-f]+)\s*$", text, re.M)
    if not keys:
        raise ValueError("no 'PUBKEY:' line found")
    if len(set(k.upper() for k in keys)) != 1:
        raise ValueError("more than one different PUBKEY line - which run is it?")
    raw = bytes.fromhex(keys[0])
    if len(raw) != 64:
        raise ValueError("public key must be 64 bytes (X||Y), got %d" % len(raw))
    return raw


def to_public_key(raw):
    """Raises ValueError if (X, Y) is not a point on P-256."""
    x = int.from_bytes(raw[:32], "big")
    y = int.from_bytes(raw[32:], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()[:16]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("output", help="saved Serial Monitor output of se_identity_key")
    ap.add_argument("--pem", default=None, help="where to write the PEM (default docs/device_identity_pub.pem)")
    a = ap.parse_args(argv)
    with open(a.output) as f:
        raw = parse_pubkey(f.read())
    try:
        key = to_public_key(raw)
    except ValueError as e:
        print("REJECTED: not a valid P-256 public key (%s)" % e)
        return 1
    pem_path = a.pem or os.path.join(os.path.dirname(a.output) or ".", "device_identity_pub.pem")
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(pem_path, "wb") as f:
        f.write(pem)
    print("Valid P-256 public key (point is on the curve).")
    print("X = %s" % raw[:32].hex().upper())
    print("Y = %s" % raw[32:].hex().upper())
    print("Fingerprint (first 8 bytes of SHA-256 of X||Y): %s" % fingerprint(raw))
    print("Wrote %s" % pem_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
