"""
RSA cryptographic operations for Aegis-Gate.
Handles key generation, signing, and verification.
"""

import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from config import Config


def generate_rsa_keypair(key_size: int = None):
    """Generate RSA private/public key pair. Returns (private_pem, public_pem)."""
    key_size = key_size or Config.RSA_KEY_SIZE
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_pem, public_pem


def sign_challenge(private_key_pem: str, challenge: str) -> str:
    """Sign a challenge string with a private RSA key. Returns base64 signature."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(
        challenge.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key_pem: str, challenge: str, signature_b64: str) -> bool:
    """Verify a base64-encoded signature against a challenge using a public RSA key."""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
            backend=default_backend()
        )
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            challenge.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception):
        return False


def save_server_keys():
    """Generate and persist server-level RSA keys (used for session token signing)."""
    keys_dir = Config.KEYS_DIR
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = keys_dir / "server_private.pem"
    pub_path = keys_dir / "server_public.pem"

    if not priv_path.exists():
        priv_pem, pub_pem = generate_rsa_keypair()
        priv_path.write_text(priv_pem)
        pub_path.write_text(pub_pem)

    return priv_path.read_text(), pub_path.read_text()


def load_server_private_key():
    priv_path = Config.KEYS_DIR / "server_private.pem"
    if not priv_path.exists():
        save_server_keys()
    return priv_path.read_text()


def load_server_public_key():
    pub_path = Config.KEYS_DIR / "server_public.pem"
    if not pub_path.exists():
        save_server_keys()
    return pub_path.read_text()
