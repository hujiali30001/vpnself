"""
Furun VPN - Server Forward Proxy

Handles outbound connections from the server to target hosts.
Uses explicit DNS resolution for consistency with system resolver.
"""

import asyncio
import socket
import ipaddress
from common.utils import get_logger

log = get_logger("server.forward")

# Max seconds to flush a frame into the tunnel before declaring the connection
# dead. A client socket that stops reading (crashed app, frozen NIC) must not be
# able to block the shared tunnel write lock indefinitely -- that would stall
# every other stream's CONNECT_OK/DATA/PONG on the same tunnel.
DRAIN_TIMEOUT = 15.0


async def send_frame_locked(writer: asyncio.StreamWriter,
                            write_lock: "asyncio.Lock | None",
                            frame: bytes,
                            timeout: float = DRAIN_TIMEOUT) -> bool:
    """Write one frame to the shared tunnel writer under the lock, with a
    bounded drain.

    Returns True on success, False if the tunnel is dead or stuck. A drain that
    exceeds ``timeout`` means the peer stopped reading: we close the writer so
    the server read loop sees EOF and the client pool reconnects, rather than
    leaving a zombie tunnel that answers PINGs but relays nothing.

    Concurrent ``drain()`` on one StreamWriter is unsafe, so write+drain stay
    inside the lock; the timeout is what bounds how long the lock is held.
    """
    try:
        if write_lock:
            async with write_lock:
                writer.write(frame)
                await asyncio.wait_for(writer.drain(), timeout=timeout)
        else:
            writer.write(frame)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        return True
    except asyncio.TimeoutError:
        log.warning("tunnel drain stalled >%.0fs -- closing dead tunnel", timeout)
        try:
            writer.close()
        except Exception:
            pass
        return False
    except (ConnectionError, OSError, AssertionError):
        return False


class ForwardRelay:
    """Bidirectional relay between a tunnel stream and a target TCP connection."""

    BUFFER_SIZE = 65536

    def __init__(self, stream_id: int, tunnel_writer: asyncio.StreamWriter,
                 target_reader: asyncio.StreamReader,
                 target_writer: asyncio.StreamWriter,
                 write_lock: asyncio.Lock | None = None):
        self.stream_id = stream_id
        self.tunnel_writer = tunnel_writer
        self.target_reader = target_reader
        self.target_writer = target_writer
        self.write_lock = write_lock
        self._active = True

    async def relay_target_to_tunnel(self, pack_data_func):
        """Relay data from target back to tunnel."""
        bytes_relayed = 0
        try:
            while self._active:
                data = await self.target_reader.read(self.BUFFER_SIZE)
                if not data:
                    break
                frame = pack_data_func(self.stream_id, data)
                if not await send_frame_locked(self.tunnel_writer,
                                               self.write_lock, frame):
                    log.debug("Stream %d: tunnel write failed/stalled", self.stream_id)
                    break
                bytes_relayed += len(data)
        except (ConnectionError, asyncio.IncompleteReadError, OSError) as e:
            log.debug("Stream %d: relay finished: %d bytes (%s)",
                     self.stream_id, bytes_relayed, e)
        finally:
            log.debug("Stream %d: relay closed (%d bytes total)",
                     self.stream_id, bytes_relayed)
            self.close()

    def close(self):
        self._active = False
        try:
            self.target_writer.close()
        except Exception:
            pass


class ForwardProxy:
    """Manages outbound connections from the server to target destinations."""

    CONNECT_TIMEOUT = 5.0
    DNS_TIMEOUT = 3.0

    def __init__(self, max_connections: int = 200):
        self.max_connections = max_connections
        self._semaphore = asyncio.Semaphore(max_connections)
        self._active_relays: dict[int, ForwardRelay] = {}  # key: composite_id = (client_id << 32) | stream_id
        self._total_connections = 0

    @staticmethod
    def _make_key(client_id: int, stream_id: int) -> int:
        """Pack client_id and stream_id into a single integer key."""
        return (client_id << 32) | (stream_id & 0xFFFFFFFF)

    @staticmethod
    def _split_key(key: int) -> tuple[int, int]:
        """Unpack composite key into (client_id, stream_id)."""
        return (key >> 32, key & 0xFFFFFFFF)

    @property
    def stats(self) -> dict:
        return {
            "active_relays": len(self._active_relays),
            "total_connections": self._total_connections,
            "max_connections": self.max_connections,
        }

    def get_relay(self, client_id: int, stream_id: int) -> ForwardRelay | None:
        return self._active_relays.get(self._make_key(client_id, stream_id))

    async def connect_target(self, client_id: int, stream_id: int, host: str, port: int,
                             tunnel_writer: asyncio.StreamWriter,
                             pack_connect_ok_func,
                             pack_connect_fail_func,
                             write_lock: asyncio.Lock | None = None
                             ) -> ForwardRelay | None:
        """Establish a connection to target and return a relay, or None on failure."""
        # Resolve DNS outside the semaphore to avoid blocking other connections.
        # A DNS failure must still send CONNECT_FAIL, otherwise the client stream
        # hangs until its own timeout instead of fast-failing.
        loop = asyncio.get_running_loop()
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, self._resolve, host),
                timeout=self.DNS_TIMEOUT,
            )
        except (asyncio.TimeoutError, OSError) as e:
            log.warning("Stream %d: DNS resolution failed for %s: %s",
                        stream_id, host, e)
            await send_frame_locked(tunnel_writer, write_lock,
                                    pack_connect_fail_func(stream_id, "DNS resolution failed"))
            return None
        log.info("CONNECT %s:%d -> %s", host, port, ip)

        async with self._semaphore:
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.CONNECT_TIMEOUT,
                )
                self._total_connections += 1
                log.info("Stream %d: CONNECT OK %s:%d [relay #%d]",
                         stream_id, host, port, self._total_connections)

                # TCP_NODELAY for low latency
                sock = target_writer.get_extra_info("socket")
                if sock is not None:
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except (OSError, AttributeError):
                        pass

                relay = ForwardRelay(stream_id, tunnel_writer,
                                     target_reader, target_writer,
                                     write_lock=write_lock)
                self._active_relays[self._make_key(client_id, stream_id)] = relay

                ok_frame = pack_connect_ok_func(stream_id)
                await send_frame_locked(tunnel_writer, write_lock, ok_frame)

                return relay
            except asyncio.TimeoutError:
                log.warning("Stream %d: CONNECT TIMEOUT (DNS/TCP) to %s:%d",
                            stream_id, host, port)
                await send_frame_locked(tunnel_writer, write_lock,
                                        pack_connect_fail_func(stream_id, "Connection timeout"))
                return None
            except (ConnectionError, OSError) as e:
                log.warning("Stream %d: CONNECT FAILED to %s:%d: %s",
                            stream_id, host, port, e)
                await send_frame_locked(tunnel_writer, write_lock,
                                        pack_connect_fail_func(stream_id, str(e)))
                return None

    @staticmethod
    def _resolve(host: str) -> str:
        """Resolve hostname using system DNS (same as ping/curl).

        IPv4-only (AF_INET) by design: egress is over IPv4, so IPv6-only
        targets are not reachable.

        Rejects targets that resolve to non-public addresses (loopback,
        private, link-local, reserved). This blocks SSRF: an authenticated
        client must not be able to make the server reach its own internal
        network or cloud metadata endpoints (e.g. 169.254.169.254).
        """
        info = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        if not info:
            raise OSError(f"DNS resolution returned no results for {host}")
        ip = info[0][4][0]
        addr = ipaddress.ip_address(ip)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            raise OSError(f"refusing non-public target {host} -> {ip}")
        return ip

    def remove_relay(self, client_id: int, stream_id: int):
        key = self._make_key(client_id, stream_id)
        relay = self._active_relays.pop(key, None)
        if relay:
            relay.close()
            log.debug("Stream %d: relay removed (active: %d)",
                     stream_id, len(self._active_relays))

    def close_all(self):
        count = len(self._active_relays)
        for key in list(self._active_relays.keys()):
            cid, sid = self._split_key(key)
            self.remove_relay(cid, sid)
        log.info("All %d relays closed", count)
