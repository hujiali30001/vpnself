"""
Furun VPN - Communication Protocol

Binary frame protocol for client-server communication over TLS.
Frame format (big-endian):
    [0:4]  uint32  Frame total length (including header)
    [4:8]  uint32  Stream ID
    [8]    uint8   Command type
    [9:]   bytes   Payload (command-specific)
"""

import struct
import enum
from common.utils import get_logger

log = get_logger("protocol")

__all__ = [
    "Cmd", "FRAME_HEADER_SIZE", "MAX_FRAME_SIZE",
    "pack_frame", "unpack_frame",
    "pack_auth", "pack_auth_ok",
    "pack_connect", "unpack_connect",
    "pack_connect_ok", "pack_connect_fail",
    "pack_data", "pack_close",
    "pack_ping", "pack_pong",
]

# Protocol constants
FRAME_HEADER_SIZE = 9  # 4 (length) + 4 (stream_id) + 1 (cmd)
MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4 MB -- reject obviously corrupt frames


class Cmd(enum.IntEnum):
    """Frame command types."""
    CONNECT = 1
    DATA = 2
    CLOSE = 3
    CONNECT_OK = 4
    CONNECT_FAIL = 5
    AUTH = 6
    AUTH_OK = 7
    AUTH_FAIL = 8
    PING = 9
    PONG = 10


def pack_frame(stream_id: int, cmd: Cmd, payload: bytes = b"") -> bytes:
    """Encode a protocol frame into bytes."""
    total_len = FRAME_HEADER_SIZE + len(payload)
    header = struct.pack("!IIB", total_len, stream_id, int(cmd))
    frame = header + payload
    return frame


def unpack_frame(data: bytes, offset: int = 0) -> tuple[int, Cmd, bytes] | None:
    """Decode a protocol frame from ``data`` starting at ``offset``.

    Returns (stream_id, cmd, payload) or None if more bytes are needed. Parsing
    is done in place via ``offset`` so read loops never re-slice ``buf[pos:]``
    once per frame (which is O(n^2) when a single read holds many frames).

    IMPORTANT: callers MUST advance their read position by
    ``FRAME_HEADER_SIZE + len(payload)`` after consuming a frame, NOT by the
    raw ``total_len`` field from the header. On the resync path (oversized /
    undersized total_len) the returned payload is empty and the frame is only
    FRAME_HEADER_SIZE bytes wide, so advancing by total_len would skip or
    re-parse valid data.
    """
    if len(data) - offset < FRAME_HEADER_SIZE:
        return None
    total_len, stream_id, cmd_byte = struct.unpack(
        "!IIB", data[offset:offset + FRAME_HEADER_SIZE])
    # Validate the declared length BEFORE the completeness check. An oversized
    # length (up to 4 GB) would otherwise look like "need more bytes" forever,
    # stalling the parser and letting the receive buffer grow unbounded -- a
    # pre-auth OOM DoS from a single hostile/corrupt header. Resync instead by
    # returning a dummy PONG so the caller skips just this 9-byte header.
    if total_len > MAX_FRAME_SIZE or total_len < FRAME_HEADER_SIZE:
        log.warning("Frame size %d out of valid range [%d, %d] -- discarding header", total_len, FRAME_HEADER_SIZE, MAX_FRAME_SIZE)
        return (stream_id, Cmd.PONG, b"")
    if len(data) - offset < total_len:
        return None
    payload = data[offset + FRAME_HEADER_SIZE:offset + total_len]
    try:
        cmd = Cmd(cmd_byte)
    except ValueError:
        log.warning("Unknown command byte 0x%02X, treating as CLOSE", cmd_byte)
        cmd = Cmd.CLOSE
    return stream_id, cmd, payload


def pack_auth(token: str) -> bytes:
    """Pack an AUTH frame."""
    return pack_frame(0, Cmd.AUTH, token.encode("utf-8"))


def pack_connect(stream_id: int, host: str, port: int) -> bytes:
    """Pack a CONNECT frame. Payload: 2-byte host_len + host + 2-byte port."""
    host_bytes = host.encode("utf-8")
    payload = struct.pack("!H", len(host_bytes)) + host_bytes + struct.pack("!H", port)
    return pack_frame(stream_id, Cmd.CONNECT, payload)


def unpack_connect(payload: bytes) -> tuple[str, int] | None:
    """Unpack a CONNECT payload. Returns (host, port) or None."""
    if len(payload) < 4:
        return None
    try:
        host_len = struct.unpack("!H", payload[:2])[0]
        host = payload[2:2 + host_len].decode("utf-8")
        port = struct.unpack("!H", payload[2 + host_len:4 + host_len])[0]
        # Reject a degenerate target here rather than downstream. An empty host
        # resolves to a machine-dependent address (e.g. a private LAN IP), so
        # letting it through would lean entirely on the server's SSRF guard to
        # catch what is plainly a malformed CONNECT. Port 0 is never a real
        # destination either.
        if not host or port == 0:
            log.warning("CONNECT payload has empty host or port 0 -- rejecting")
            return None
        return host, port
    except (struct.error, UnicodeDecodeError) as e:
        log.warning("Failed to unpack CONNECT payload: %s", e)
        return None


def pack_connect_ok(stream_id: int) -> bytes:
    """Pack a CONNECT_OK frame."""
    return pack_frame(stream_id, Cmd.CONNECT_OK)


def pack_connect_fail(stream_id: int, reason: str = "") -> bytes:
    """Pack a CONNECT_FAIL frame."""
    return pack_frame(stream_id, Cmd.CONNECT_FAIL, reason.encode("utf-8"))


def pack_data(stream_id: int, payload: bytes) -> bytes:
    """Pack a DATA frame."""
    return pack_frame(stream_id, Cmd.DATA, payload)


def pack_close(stream_id: int) -> bytes:
    """Pack a CLOSE frame."""
    return pack_frame(stream_id, Cmd.CLOSE)


def pack_ping() -> bytes:
    """Pack a PING frame."""
    return pack_frame(0, Cmd.PING)


def pack_auth_ok() -> bytes:
    """Pack an AUTH_OK frame (stream 0, no payload)."""
    return pack_frame(0, Cmd.AUTH_OK)


def pack_pong() -> bytes:
    """Pack a PONG frame."""
    return pack_frame(0, Cmd.PONG)
