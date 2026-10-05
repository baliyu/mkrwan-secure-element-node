#!/usr/bin/env python3
"""tools/se_verify_sig.py - step 6c (PC side): verify the ECDSA signature the
ATECC608 made with its identity key (slot 0), using the public key saved in
step 5.

    python3 tools/se_verify_sig.py docs/step6_provision_output.txt docs/device_identity_pub.pem

The chip signs a 32-byte challenge from its own random generator directly
(the 32 bytes are treated as the message digest), so the PC verifies with
Prehashed(SHA-256). Signature format from the chip: R (32 bytes) || S (32 bytes).
Needs: pip install cryptography
"""
import argparse
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def parse(text):
    def one(tag, n):
        vals = set(v.upper() for v in re.findall(tag + r":\s*([0-9A-Fa-f]+)\s*$", text, re.M))
        if len(vals) != 1:
            raise ValueError("expected exactly one %s line, found %d" % (tag, len(vals)))
        b = bytes.fromhex(vals.pop())
        if len(b) != n:
            raise ValueError("%s must be %d bytes" % (tag, n))
        return b
    return one("SIGN_MSG", 32), one("SIGNATURE", 64)


def verify(pub, msg, sig):
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    try:
        pub.verify(utils.encode_dss_signature(r, s), msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("output")
    ap.add_argument("pem")
    a = ap.parse_args(argv)
    with open(a.output) as f:
        msg, sig = parse(f.read())
    with open(a.pem, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    ok = verify(pub, msg, sig)
    print("Challenge: %s" % msg.hex().upper())
    print("Signature: %s" % sig.hex().upper())
    print("VALID: signed by the device identity key" if ok else "INVALID signature")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
