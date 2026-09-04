"""Generate Go test vectors and sample files using the `cryptography`
package (same primitives as the original Python code)."""

import base64
import json
import os
import random

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def hx(b: bytes) -> str:
    return b.hex()

# ---------------------------------------------------------------- CCM vectors
rng = random.Random(20260904)
ccm_vecs = []
i = 0
for nonce_len in (7, 8, 12, 13):
    for tag_len in (4, 8, 16):
        for pt_len, aad_len in ((0, 0), (1, 5), (15, 29), (16, 0), (17, 300), (200, 65535)):
            key = bytes(rng.getrandbits(8) for _ in range((16, 24, 32)[i % 3]))
            i += 1
            nonce = bytes(rng.getrandbits(8) for _ in range(nonce_len))
            pt = bytes(rng.getrandbits(8) for _ in range(pt_len))
            aad = bytes(rng.getrandbits(8) for _ in range(aad_len))
            ct = AESCCM(key, tag_length=tag_len).encrypt(nonce, pt, aad)
            ccm_vecs.append({
                "key": hx(key), "nonce": hx(nonce), "pt": hx(pt),
                "aad": hx(aad), "ct": hx(ct), "tagLen": tag_len,
            })

os.makedirs(os.path.join(root, "internal", "ccm", "testdata"), exist_ok=True)
with open(os.path.join(root, "internal", "ccm", "testdata", "vectors.json"), "w") as f:
    json.dump(ccm_vecs, f, indent=1)

# ------------------------------------------------------ RFC 3610-style vectors
# Packet vector #1..#3: key c0c1c2..cecf, nonce 1011121314151617, 8-byte tag,
# AAD = first (2*pt_len + 3)?? per RFC (29/29/56 bytes respectively).
K = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
N = bytes.fromhex("1011121314151617")
packets = [
    (bytes.fromhex("0001020304050607"),
     bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")),
    (bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
     bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")),
    (bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"),
     bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627")),
]
for pt, aad in packets:
    ct = AESCCM(K, tag_length=8).encrypt(N, pt, aad)
    ccm_vecs.append({
        "key": hx(K), "nonce": hx(N), "pt": hx(pt), "aad": hx(aad),
        "ct": hx(ct), "tagLen": 8,
    })

with open(os.path.join(root, "internal", "ccm", "testdata", "vectors.json"), "w") as f:
    json.dump(ccm_vecs, f, indent=1)

# ------------------------------------------------------------------ PBKDF2
pbkdf2_vecs = []
for it, klen, pwd, salt in (
    (1, 32, "password", "salt"),
    (2, 32, "password", "salt"),
    (4096, 32, "password", "salt"),
    (4096, 40, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt"),
    (1, 16, "pass\0word", "sa\0lt"),
    (1000, 20, "пароль", "солёный-salt"),
):
    derived = PBKDF2HMAC(algorithm=hashes.SHA256(), length=klen,
                         salt=salt.encode(), iterations=it).derive(pwd.encode())
    pbkdf2_vecs.append({
        "password": pwd, "salt": hx(salt.encode()), "iter": it,
        "dkLen": klen, "dk": hx(derived),
    })

os.makedirs(os.path.join(root, "internal", "kdf", "testdata"), exist_ok=True)
with open(os.path.join(root, "internal", "kdf", "testdata", "vectors.json"), "w") as f:
    json.dump(pbkdf2_vecs, f, indent=1)

# ------------------------------------------------------------- sample ckz
def make_record(payload, password, iv_len, tag_bytes, it=100000, adata=""):
    salt = os.urandom(16)
    iv = os.urandom(iv_len)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it)
    key = kdf.derive(password.encode())
    ct = AESCCM(key, tag_length=tag_bytes).encrypt(iv[:12], payload, adata.encode())
    return json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
        "adata": adata,
        "iter": it,
        "ks": 256,
        "ts": tag_bytes * 8,
    }, ensure_ascii=False)

pwd = "123"
payload1 = json.dumps({"greeting": "привет", "items": [1, 2, 3],
                       "nested": {"ok": True}}, ensure_ascii=False).encode()
payload2 = json.dumps({"secret": "second-line", "value": 42}).encode()
rec1 = make_record(payload1, pwd, iv_len=16, tag_bytes=16, it=100000, adata="meta:demo")
rec2 = make_record(payload2, pwd, iv_len=12, tag_bytes=8, it=1, adata="")

td = os.path.join(root, "testdata")
os.makedirs(td, exist_ok=True)
with open(os.path.join(td, "sample.ckz"), "w", newline="\n") as f:
    f.write(rec1 + "\n" + rec2 + "\n")

with open(os.path.join(td, "rec1.ckz"), "w", newline="\n") as f:
    f.write(rec1 + "\n")

expected = [json.loads(payload1.decode()), json.loads(payload2.decode())]
with open(os.path.join(td, "expected.json"), "w", newline="\n", encoding="utf-8") as f:
    json.dump(expected, f, ensure_ascii=False, indent=2)

print("ccm vectors:", len(ccm_vecs))
print("pbkdf2 vectors:", len(pbkdf2_vecs))
print("sample files written to", td)
