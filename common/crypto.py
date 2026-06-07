"""
Furun VPN - Cryptographic Utilities

Key generation, TLS context creation, and pre-shared key (PSK) management.
"""

import os
import ssl
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def create_client_ssl_context(cert_file: str | None = None,
                              verify: bool = True) -> ssl.SSLContext:
    """Create a TLS client SSL context.

    Parameters
    ----------
    cert_file : str | None
        Optional CA certificate file for server verification.
    verify : bool
        If False, accepts self-signed certificates. PSK authentication
        still ensures tunnel security.
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if cert_file:
            ctx.load_verify_locations(cert_file)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE


    return ctx


def create_server_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """Create a TLS server SSL context."""
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx


def sha256_hex(data: bytes) -> str:
    """Return a hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()
