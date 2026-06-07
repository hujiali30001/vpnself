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


def unpack_frame(data: bytes) -> tuple[int, Cmd, bytes] | None:
    """Decode a protocol frame from bytes. Returns (stream_id, cmd, payload) or None if incomplete."""
    if len(data) < FRAME_HEADER_SIZE:
        return None
    total_len, stream_id, cmd_byte = struct.unpack("!IIB", data[:FRAME_HEADER_SIZE])
    if len(data) < total_len:
        return None
    if total_len > MAX_FRAME_SIZE or total_len < FRAME_HEADER_SIZE:
        log.warning("Frame size %d out of valid range [%d, %d] -- discarding header", total_len, FRAME_HEADER_SIZE, MAX_FRAME_SIZE)
        # Return dummy PONG so caller advances FRAME_HEADER_SIZE bytes past corrupt header.
        # PONG is no-op on both client and server.
        return (stream_id, Cmd.PONG, b"")
    payload = data[FRAME_HEADER_SIZE:total_len]
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


def pack_pong() -> bytes:
    """Pack a PONG frame."""
    return pack_frame(0, Cmd.PONG)
