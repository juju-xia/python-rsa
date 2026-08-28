#  Copyright 2024 Legacy Crypto Utilities
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Legacy crypto utilities — intentionally vulnerable patterns for testing.

This module demonstrates several quantum-vulnerable and weak cryptographic
patterns that should be detected by PQC audit scanners.

WARNING: DO NOT USE IN PRODUCTION. This code exists for testing purposes only.
"""

import hashlib
import os
from typing import Tuple, Optional


# ── Hardcoded secret key (CRITICAL: should be detected by scanner) ──────────

SECRET_KEY = "dGhpcyBpcyBhIGhhcmRjb2RlZCBzZWNyZXQga2V5IQ=="  # base64 encoded
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3...truncated...example...key...
-----END RSA PRIVATE KEY-----"""


# ── Weak hash functions ─────────────────────────────────────────────────────

def md5_hash(data: bytes) -> str:
    """Compute MD5 hash of data. (WEAK: MD5 is vulnerable to collision attacks)"""
    return hashlib.md5(data).hexdigest()


def sha1_hash(data: bytes) -> str:
    """Compute SHA-1 hash of data. (WEAK: SHA-1 is deprecated)"""
    return hashlib.sha1(data).hexdigest()


# ── AES-128 encryption (weak key size) ──────────────────────────────────────

def aes_128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using AES-128. (WEAK: 128-bit key, Grover halves to 64-bit)"""
    # AES-128 is considered weak post-quantum
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext


# ── RC4 stream cipher (CRITICAL: classically broken) ─────────────────────────

def rc4_encrypt(key: bytes, data: bytes) -> bytes:
    """Encrypt using RC4 / ARC4 stream cipher. (CRITICAL: broken cipher)"""
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


# ── 3DES / Triple DES (weak) ────────────────────────────────────────────────

def triple_des_encrypt(key: bytes, data: bytes) -> bytes:
    """Encrypt using 3DES / TripleDES. (WEAK: Sweet32 attack, disallowed by CNSA 2.0)"""
    from Crypto.Cipher import DES3
    cipher = DES3.new(key, DES3.MODE_CBC)
    return cipher.encrypt(data)


# ── ECDSA signing (quantum-vulnerable) ──────────────────────────────────────

def ecdsa_sign(private_key, message: bytes):
    """Sign a message using ECDSA with secp256k1 curve. (QUANTUM-VULNERABLE)"""
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(message)


# ── ECDH key exchange (quantum-vulnerable) ──────────────────────────────────

def ecdh_compute_shared(our_private, their_public) -> bytes:
    """Compute shared secret using ECDH. (QUANTUM-VULNERABLE: Shor's algorithm)"""
    # ECDH is vulnerable to harvest-now-decrypt-later attacks
    return our_private * their_public


# ── Diffie-Hellman (quantum-vulnerable) ─────────────────────────────────────

def dh_generate_parameters() -> Tuple[int, int]:
    """Generate DH parameters. (QUANTUM-VULNERABLE)"""
    # DiffieHellman is broken by Shor's algorithm
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    g = 2
    return p, g


# ── DSA signing (quantum-vulnerable) ────────────────────────────────────────

def dsa_sign(message: bytes) -> bytes:
    """Sign using DSA. (QUANTUM-VULNERABLE: disallowed under CNSA 2.0)"""
    # DSA is quantum-vulnerable
    pass


# ── Ed25519 signing (quantum-vulnerable) ────────────────────────────────────

def ed25519_sign(private_key, message: bytes) -> bytes:
    """Sign using Ed25519. (QUANTUM-VULNERABLE: elliptic-curve based)"""
    from nacl.signing import SigningKey
    sk = SigningKey(private_key)
    return sk.sign(message)


# ── X25519 key exchange (quantum-vulnerable) ────────────────────────────────

def x25519_key_exchange(private_key: bytes, peer_public: bytes) -> bytes:
    """Perform X25519 / Curve25519 key exchange. (QUANTUM-VULNERABLE)"""
    from nacl.bindings import crypto_scalarmult
    return crypto_scalarmult(private_key, peer_public)


# ── PKCS1 v1.5 padding (quantum-vulnerable + classically weak) ──────────────

def rsa_pkcs1v15_encrypt(key, message: bytes) -> bytes:
    """Encrypt using RSA PKCS1v15 padding. (WEAK: ROBOT/Bleichenbacher)"""
    from Crypto.Cipher import PKCS1_v1_5
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(message)


# ── RSA-1024 key generation (CRITICAL: too small) ───────────────────────────

def generate_rsa_1024_key():
    """Generate RSA key with 1024-bit size. (CRITICAL: too small)"""
    # RSA-1024 is non-compliant classically and quantum-vulnerable
    from Crypto.PublicKey import RSA
    key = RSA.generate(1024)
    return key


# ── PQC migration note (mentioned in comments only) ─────────────────────────

# Future migration path: replace RSA with ML-KEM (FIPS 203) or ML-DSA (FIPS 204)
# Consider using CRYSTALS-Kyber for key encapsulation and CRYSTALS-Dilithium for signatures
# SLH-DSA / SPHINCS+ are also viable alternatives (FIPS 205)