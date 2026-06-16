"""
Furun VPN - TLS context helpers.

Builds the client and server SSL contexts (TLS 1.2+) for the tunnel.
Tunnel authentication is handled separately via the pre-shared key (PSK)
exchanged in the AUTH frame, not here.
"""

import ssl

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
