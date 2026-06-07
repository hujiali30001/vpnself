"""
Furun VPN - Client Tunnel with enhanced logging.
"""

import asyncio
import time
import ssl
import socket
from dataclasses import dataclass

from common.protocol import (
    Cmd, FRAME_HEADER_SIZE, pack_frame, unpack_frame, pack_auth, pack_connect,
    pack_close, pack_ping, pack_pong,
)
from common.crypto import create_client_ssl_context
from common.utils import get_logger

log = get_logger("client.tunnel")

AUTH_ACK = Cmd.CONNECT_OK
PING_INTERVAL = 30.0
HEALTH_CHECK_INTERVAL = 10.0  # How often to check connection health
HEALTH_TIMEOUT = 50.0  # Max time without receiving data before considering dead


@dataclass
class TunnelConfig:
    host: str
    port: int = 8443
    psk: str = ""
    tls_cert_file: str | None = None
    verify_cert: bool = False
    connect_timeout: float = 10.0
    auto_reconnect: bool = True


class TunnelStream:
    def __init__(self, stream_id: int, tunnel: "TunnelClient"):
        self.stream_id = stream_id
        self._tunnel = tunnel
        self._buffer: asyncio.Queue = asyncio.Queue()
        self._closed = False
        self._connect_future: asyncio.Future | None = None
        self._bytes_recv = 0
        self._bytes_sent = 0

    @property
    def stats(self) -> dict:
        return {"stream_id": self.stream_id, "bytes_sent": self._bytes_sent,
                "bytes_recv": self._bytes_recv, "closed": self._closed}

    async def read(self, n: int = -1) -> bytes:
        """Read data from this stream. Restored to original two-path version."""
        if self._closed:
            return b""
        try:
            if n < 0:
                # Drain all available chunks, block if empty
                data = b""
                while True:
                    try:
                        chunk = self._buffer.get_nowait()
                        if chunk is None:
                            break
                        data += chunk
                    except asyncio.QueueEmpty:
                        break
                if not data:
                    data = await self._buffer.get()
                    if data is None:
                        self._closed = True
                        return b""
                self._bytes_recv += len(data)
                return data
            else:
                # Read exactly n bytes (or less if EOF)
                data = await self._buffer.get()
                if data is None:
                    self._closed = True
                    return b""
                self._bytes_recv += len(data)
                return data[:n]
        except Exception:
            self._closed = True
            return b""

    def feed_data(self, data: bytes):
        if not self._closed:
            self._buffer.put_nowait(data)

    def close(self):
        if not self._closed:
            self._closed = True
            self._buffer.put_nowait(None)

    @property
    def closed(self) -> bool:
        return self._closed


class TunnelClient:
    def __init__(self, config: TunnelConfig):
        self.config = config
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._authenticated = False
        self._running = False
        self._streams: dict[int, TunnelStream] = {}
        self._next_stream_id = 1
        self._reader_task: asyncio.Task | None = None
        self._health_task: asyncio.Task | None = None
        self._ping_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._on_disconnect: list[callable] = []
        self._frame_rx = 0
        self._last_rx_time = 0.0  # monotonic time of last received frame
        self._frame_tx = 0

    @property
    def connected(self) -> bool:
        return self._connected and self._authenticated

    @property
    def stats(self) -> dict:
        return {"connected": self.connected, "active_streams": len(self._streams),
                "authenticated": self._authenticated}

    def on_disconnect(self, callback):
        self._on_disconnect.append(callback)

    async def connect(self):
        async with self._lock:
            if self._connected:
                return True
            log.debug("TUNNEL: connecting to %s:%d ...", self.config.host, self.config.port)
            try:
                ssl_ctx = create_client_ssl_context(self.config.tls_cert_file,
                                                    verify=self.config.verify_cert)
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(host=self.config.host, port=self.config.port,
                                            ssl=ssl_ctx),
                    timeout=self.config.connect_timeout)
                cipher = self._writer.get_extra_info("cipher")
                log.info("TUNNEL: TLS handshake OK [%s]", cipher[0] if cipher else "?")
                # TCP_NODELAY for low-latency tunnel frames
                sock = self._writer.get_extra_info("socket")
                if sock is not None:
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except (OSError, AttributeError):
                        pass
                auth_frame = pack_auth(self.config.psk)
                self._writer.write(auth_frame)
                await self._writer.drain()
                response = await asyncio.wait_for(self._reader.read(256), timeout=10.0)
                result = unpack_frame(response)
                if result is None or result[1] != AUTH_ACK:
                    log.error("TUNNEL: AUTH FAILED")
                    self._writer.close()
                    return False
                self._authenticated = True
                self._connected = True
                self._running = True
                self._frame_rx = 0
                self._frame_tx = 0
                self._last_rx_time = time.monotonic()
                log.info("TUNNEL: authenticated OK, starting reader+ping loops")
                self._reader_task = asyncio.create_task(self._read_loop())
                self._health_task = asyncio.create_task(self._health_check_loop())
                self._ping_task = asyncio.create_task(self._ping_loop())
                return True
            except asyncio.TimeoutError:
                log.error("TUNNEL: connection timeout (%.1fs)", self.config.connect_timeout)
                return False
            except (ConnectionError, OSError) as e:
                log.error("TUNNEL: connection failed: %s", e)
                return False
            except ssl.SSLError as e:
                log.error("TUNNEL: TLS handshake failed: %s", e)
                return False

    async def disconnect(self):
        self._running = False
        self._connected = False
        self._authenticated = False
        for task in [self._reader_task, self._health_task, self._ping_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        for sid in list(self._streams.keys()):
            self._streams.pop(sid).close()
        if self._writer:
            try:
                self._writer.close()
            except (Exception, AssertionError):
                pass
            self._writer = None
        self._reader = None
        for cb in self._on_disconnect:
            try:
                cb()
            except Exception:
                pass
        log.info("TUNNEL: disconnected (rx=%d frames, tx=%d frames)", self._frame_rx, self._frame_tx)

    async def create_stream(self, target_host: str, target_port: int,
                            timeout: float = 8.0) -> TunnelStream | None:
        if not self.connected:
            log.warning("TUNNEL: cannot create stream -- not connected")
            return None
        if self._writer is None:
            log.warning("TUNNEL: cannot create stream -- writer is None")
            return None
        writer = None
        async with self._lock:
            if not self._connected or self._writer is None:
                log.warning("TUNNEL: cannot create stream -- tunnel disconnected")
                return None
            writer = self._writer
            sid = self._next_stream_id
            self._next_stream_id += 1
            if self._next_stream_id >= 2**32 - 1:
                self._next_stream_id = 1
            stream = TunnelStream(sid, self)
            self._streams[sid] = stream

        log.debug("TUNNEL: [S%d] opening -> %s:%d", sid, target_host, target_port)
        connect_frame = pack_connect(sid, target_host, target_port)
        try:
            writer.write(connect_frame)
            await writer.drain()
            self._frame_tx += 1
        except (ConnectionError, OSError, AssertionError) as e:
            log.error("TUNNEL: [S%d] CONNECT send failed: %s", sid, e)
            self._streams.pop(sid, None)
            return None

        stream._connect_future = asyncio.Future()
        try:
            await asyncio.wait_for(stream._connect_future, timeout=timeout)
            if stream.closed:
                self._streams.pop(sid, None)
                log.warning("TUNNEL: [S%d] CONNECT rejected by server", sid)
                return None
            log.debug("TUNNEL: [S%d] CONNECT OK (%d active streams)", sid, len(self._streams))
            return stream
        except asyncio.TimeoutError:
            log.info("TUNNEL: [S%d] CONNECT timeout %s:%d (%.1fs)",
                        sid, target_host, target_port, timeout)
            self._streams.pop(sid, None)
            stream.close()
            return None

    async def send_data(self, sid: int, data: bytes):
        writer = self._writer
        if not self.connected or writer is None:
            return
        stream = self._streams.get(sid)
        if not stream or stream.closed:
            return
        stream._bytes_sent += len(data)
        frame = pack_frame(sid, Cmd.DATA, data)
        try:
            writer.write(frame)
            await writer.drain()
            self._frame_tx += 1
        except (ConnectionError, OSError, AssertionError):
            pass

    async def close_stream(self, sid: int):
        stream = self._streams.pop(sid, None)
        if stream:
            stream.close()
            log.debug("TUNNEL: [S%d] CLOSE (sent=%d recv=%d)",
                     sid, stream._bytes_sent, stream._bytes_recv)
            writer = self._writer
            if self.connected and writer is not None:
                try:
                    writer.write(pack_close(sid))
                    await writer.drain()
                except (ConnectionError, OSError):
                    pass

    async def _read_loop(self):
        buf = b""
        pos = 0
        try:
            while self._running:
                data = await self._reader.read(65536)
                if not data:
                    log.warning("TUNNEL: read EOF -- server closed connection")
                    break
                if pos > 0:
                    buf = buf[pos:]
                    pos = 0
                buf += data
                while True:
                    result = unpack_frame(buf[pos:])
                    if result is None:
                        break
                    sid, cmd, payload = result
                    consumed = FRAME_HEADER_SIZE + len(payload)
                    pos += consumed
                    self._frame_rx += 1
                    self._last_rx_time = time.monotonic()

                    if cmd in (Cmd.CONNECT_OK, Cmd.CONNECT_FAIL):
                        stream = self._streams.get(sid)
                        if stream and stream._connect_future:
                            if cmd == Cmd.CONNECT_FAIL:
                                reason = payload.decode("utf-8", errors="replace")
                                log.warning("TUNNEL: [S%d] CONNECT FAIL from server: %s", sid, reason)
                                stream.close()
                            stream._connect_future.set_result(None)
                    elif cmd == Cmd.DATA:
                        stream = self._streams.get(sid)
                        if stream:
                            stream.feed_data(payload)
                    elif cmd == Cmd.CLOSE:
                        stream = self._streams.get(sid)
                        if stream:
                            stream.close()
                    elif cmd == Cmd.PING:
                        writer = self._writer
                        if writer:
                            try:
                                writer.write(pack_pong())
                                await writer.drain()
                            except (ConnectionError, OSError):
                                pass
                    elif cmd == Cmd.PONG:
                        pass
        except (ConnectionError, asyncio.IncompleteReadError, OSError) as e:
            log.warning("TUNNEL: read loop error: %s", e)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error("TUNNEL: read loop fatal: %s", e, exc_info=True)
        finally:
            if self._running:
                await self.disconnect()

    async def _health_check_loop(self):
        """Periodically check that we are still receiving data from the server.
        If no data has been received for HEALTH_TIMEOUT seconds, the connection
        is considered dead and we trigger a disconnect (which will fire the
        on_disconnect callback for auto-reconnect)."""
        try:
            while self._running:
                await asyncio.sleep(HEALTH_CHECK_INTERVAL)
                if not self._running:
                    break
                if self._last_rx_time > 0:
                    elapsed = time.monotonic() - self._last_rx_time
                    if elapsed > HEALTH_TIMEOUT:
                        log.warning("TUNNEL: no data received for %.0fs (>%.0fs) -- "
                                    "connection appears dead, disconnecting",
                                    elapsed, HEALTH_TIMEOUT)
                        await self.disconnect()
                        break
        except asyncio.CancelledError:
            pass

    async def _ping_loop(self):
        try:
            while self._running:
                await asyncio.sleep(PING_INTERVAL)
                if self._connected and self._writer:
                    try:
                        self._writer.write(pack_ping())
                        await self._writer.drain()
                    except (ConnectionError, OSError, AssertionError):
                        pass
        except asyncio.CancelledError:
            pass
