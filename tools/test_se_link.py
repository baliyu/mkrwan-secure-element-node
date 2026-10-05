#!/usr/bin/env python3
"""tools/test_se_link.py - PC tests for firmware/se_lora_node/se_link.c.

    python3 tools/test_se_link.py

Compiles the firmware's se_link.c into a shared library and drives it from
Python, supplying the AES block function (real AES-128 from 'cryptography'),
so the exact C code that runs on the MKR is tested. Checks:
  - CMAC against all four RFC 4493 vectors
  - packets against an independent Python implementation of the STM32
    secure_link format (CTR blocks, little-endian counter, 4-byte MIC)
  - length limits and AES-failure handling
"""
import ctypes
import os
import random
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "firmware", "se_lora_node", "se_link.c")
AES_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint8,
                          ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8))
RFC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
RFC_MSG = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")


def aes_block(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def ref_seal(enc, mic, dev_id, fcnt, payload):
    """Independent Python version of the STM32 secure_link sl_seal()."""
    hdr = bytes([dev_id]) + fcnt.to_bytes(4, "little")
    ct = bytearray()
    for i in range(0, len(payload), 16):
        ctr = bytes([0x01, dev_id]) + fcnt.to_bytes(4, "little") + bytes(9) + bytes([i // 16 + 1])
        ks = aes_block(enc, ctr)
        ct += bytes(a ^ b for a, b in zip(payload[i:i + 16], ks))
    c = cmac.CMAC(algorithms.AES(mic))
    c.update(hdr + bytes(ct))
    return hdr + bytes(ct) + c.finalize()[:4]


class Lib:
    def __init__(self, d):
        so = os.path.join(d, "se_link.so")
        subprocess.check_call(["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2",
                               "-shared", "-fPIC", "-o", so, SRC])
        self.lib = ctypes.CDLL(so)
        self.keys = {}
        self.fail_after = None
        self.calls = 0

        def cb(_ctx, kb, inp, out):
            self.calls += 1
            if self.fail_after is not None and self.calls > self.fail_after:
                return 1
            o = aes_block(self.keys[kb], bytes(inp[:16]))
            for i in range(16):
                out[i] = o[i]
            return 0
        self.cb = AES_FN(cb)

    def cmac(self, key, msg):
        self.keys = {1: key}
        tag = (ctypes.c_uint8 * 16)()
        buf = (ctypes.c_uint8 * max(1, len(msg))).from_buffer_copy(msg or b"\0")
        r = self.lib.se_cmac(self.cb, None, ctypes.c_uint8(1), buf, ctypes.c_size_t(len(msg)), tag)
        return r, bytes(tag)

    def seal(self, enc, mic, dev_id, fcnt, payload, out_max=61):
        self.keys = {0: enc, 1: mic}
        self.calls = 0
        out = (ctypes.c_uint8 * 64)()
        pl = (ctypes.c_uint8 * max(1, len(payload))).from_buffer_copy(payload or b"\0")
        n = self.lib.se_seal(self.cb, None, ctypes.c_uint8(dev_id), ctypes.c_uint32(fcnt), pl,
                             ctypes.c_uint8(len(payload)), out, ctypes.c_uint8(out_max))
        return n, bytes(out[:max(n, 0)])


class SeLink(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.L = Lib(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_cmac_rfc4493(self):
        expect = {0: "bb1d6929e95937287fa37d129b756746", 16: "070a16b46b4d4144f79bdd9dd04a287c",
                  40: "dfa66747de9ae63030ca32611497c827", 64: "51f0bebf7e3b9d92fc49741779363cfe"}
        for n, tag in expect.items():
            r, t = self.L.cmac(RFC_KEY, RFC_MSG[:n])
            self.assertEqual((r, t.hex()), (0, tag), "RFC 4493 example with %d bytes" % n)

    def test_packets_match_reference(self):
        rnd = random.Random(1)
        for _ in range(300):
            enc, mic = bytes(rnd.getrandbits(8) for _ in range(16)), bytes(rnd.getrandbits(8) for _ in range(16))
            payload = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 48)))
            dev, fcnt = rnd.randint(0, 255), rnd.randint(0, 0xFFFFFFFF)
            n, pkt = self.L.seal(enc, mic, dev, fcnt, payload)
            self.assertEqual(pkt, ref_seal(enc, mic, dev, fcnt, payload))
            self.assertEqual(n, 9 + len(payload))

    def test_aes_calls_per_packet(self):
        n, _ = self.L.seal(bytes(16), bytes(range(16)), 2, 1, b"MKR #1")    # 6-byte payload
        self.assertEqual(self.L.calls, 3)          # 1 CTR block + CMAC (L + 1 block)

    def test_too_long_rejected(self):
        n, _ = self.L.seal(bytes(16), bytes(16), 2, 1, bytes(49))
        self.assertEqual(n, -1)
        n, _ = self.L.seal(bytes(16), bytes(16), 2, 1, bytes(10), out_max=18)
        self.assertEqual(n, -1)

    def test_aes_failure_reported(self):
        for k in range(3):
            self.L.fail_after = k
            n, _ = self.L.seal(bytes(16), bytes(range(16)), 2, 1, b"MKR #1")
            self.assertEqual(n, -4, "failure after %d AES calls" % k)
        self.L.fail_after = None


if __name__ == "__main__":
    unittest.main(verbosity=2)
