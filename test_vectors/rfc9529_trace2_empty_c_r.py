#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 or MIT
#
# Copyright (c) 2026 SmartWireless GmbH & Co. KG.
"""EDHOC method 3, cipher suite 2 (RFC 9528) on the inputs of RFC 9529
Section 3, used to derive test vectors that RFC 9529 doesn't contain.

The script first reproduces RFC 9529 trace 2 from the T2_RFC9529__ values in
edhoc_test_vectors_rfc9529.c, then prints the messages and PRK_out of the
same exchange with C_R = h'' as C arrays.

Usage: python3 rfc9529_trace2_empty_c_r.py edhoc_test_vectors_rfc9529.c
Needs the 'cryptography' package.
"""
import hashlib, hmac, re, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def h(b): return hashlib.sha256(b).digest()
def bstr(b):
    n = len(b)
    if n < 24: return bytes([0x40 | n]) + b
    if n < 256: return bytes([0x58, n]) + b
    return bytes([0x59]) + n.to_bytes(2, "big") + b
def uint(n): return bytes([n]) if n < 24 else bytes([0x18, n])
def extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:length]
def kdf(prk, label, context, length):
    return expand(prk, uint(label) + bstr(context) + uint(length), length)
def ecdh(priv, peer_priv):
    sk = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256R1())
    pk = ec.derive_private_key(int.from_bytes(peer_priv, "big"), ec.SECP256R1()).public_key()
    return sk.exchange(ec.ECDH(), pk)
def pub_x(priv):
    return ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256R1()).public_key().public_numbers().x.to_bytes(32, "big")
def enc_id(raw):
    """C_x or kid as in RFC 9528 Section 3.3.2."""
    if len(raw) == 1 and (raw[0] <= 0x17 or 0x20 <= raw[0] <= 0x37):
        return raw
    return bstr(raw)

def run(v, c_r):
    g_x, g_y = pub_x(v["X"]), pub_x(v["Y"])
    m1 = bytes([3]) + bytes([0x82, 6, 2]) + bstr(g_x) + enc_id(v["C_I"])
    th2 = h(bstr(g_y) + bstr(h(m1)))
    prk_2e = extract(th2, ecdh(v["Y"], v["X"]))
    prk_3e2m = extract(kdf(prk_2e, 1, th2, 32), ecdh(v["R"], v["X"]))
    ctx2 = enc_id(c_r) + v["ID_CRED_R"] + bstr(th2) + v["CRED_R"]
    mac2 = kdf(prk_3e2m, 2, ctx2, 8)
    pt2 = enc_id(c_r) + enc_id(v["ID_CRED_R"][3:]) + bstr(mac2)
    ct2 = bytes(a ^ b for a, b in zip(pt2, kdf(prk_2e, 0, th2, len(pt2))))
    m2 = bstr(g_y + ct2)
    th3 = h(bstr(th2) + pt2 + v["CRED_R"])
    prk_4e3m = extract(kdf(prk_3e2m, 5, th3, 32), ecdh(v["I"], v["Y"]))
    mac3 = kdf(prk_4e3m, 6, v["ID_CRED_I"] + bstr(th3) + v["CRED_I"], 8)
    pt3 = enc_id(v["ID_CRED_I"][3:]) + bstr(mac3)
    a3 = bytes([0x83, 0x68]) + b"Encrypt0" + bstr(b"") + bstr(th3)
    m3 = bstr(AESCCM(kdf(prk_3e2m, 3, th3, 16), tag_length=8).encrypt(
        kdf(prk_3e2m, 4, th3, 13), pt3, a3))
    th4 = h(bstr(th3) + pt3 + v["CRED_I"])
    a4 = bytes([0x83, 0x68]) + b"Encrypt0" + bstr(b"") + bstr(th4)
    m4 = bstr(AESCCM(kdf(prk_4e3m, 8, th4, 16), tag_length=8).encrypt(
        kdf(prk_4e3m, 9, th4, 13), b"", a4))
    return dict(MESSAGE_1=m1, MESSAGE_2=m2, MESSAGE_3=m3, MESSAGE_4=m4,
                PRK_out=kdf(prk_4e3m, 7, th4, 32))

def vectors(path, prefix="T2_RFC9529__"):
    s = open(path).read()
    return {m.group(1): bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(2)))
            for m in re.finditer(prefix + r"(\w+)\[\] = \{([^}]*)\}", s)}

if __name__ == "__main__":
    v = vectors(sys.argv[1])
    ref = run(v, v["C_R"])
    for k, val in ref.items():
        assert val == v[k], f"{k} differs from RFC 9529"
    for k, val in run(v, b"").items():
        name = f"T2_EMPTY_C_R__{k}"
        body = ", ".join(f"0x{b:02x}" for b in val)
        print(f"const uint8_t {name}[] = {{ {body} }};")
        print(f"uint32_t {name}_LEN = sizeof({name});")
