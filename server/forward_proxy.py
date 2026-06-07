"""
Furun VPN - Server Forward Proxy

Handles outbound connections from the server to target hosts.
Uses explicit DNS resolution for consistency with system resolver.
"""

import asyncio
import socket
from common.utils import get_logger

log = get_logger("server.forward")


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
                if self.write_lock:
                    async with self.write_lock:
                        try:
                            self.tunnel_writer.write(frame)
                            await self.tunnel_writer.drain()
                        except (ConnectionError, OSError, AssertionError):
                            log.debug("Stream %d: tunnel write failed", self.stream_id)
                            break
                else:
                    try:
                        self.tunnel_writer.write(frame)
                        await self.tunnel_writer.drain()
                    except (ConnectionError, OSError, AssertionError):
                        log.debug("Stream %d: tunnel write failed", self.stream_id)
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
            # Resolve DNS outside semaphore to avoid blocking other connections
        loop = asyncio.get_event_loop()
        ip = await asyncio.wait_for(
            loop.run_in_executor(None, self._resolve, host),
            timeout=self.DNS_TIMEOUT,
        )
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
                if write_lock:
                    async with write_lock:
                        tunnel_writer.write(ok_frame)
                        await tunnel_writer.drain()
                else:
                    tunnel_writer.write(ok_frame)
                    await tunnel_writer.drain()

                return relay
            except asyncio.TimeoutError:
                log.warning("Stream %d: CONNECT TIMEOUT (DNS/TCP) to %s:%d",
                            stream_id, host, port)
                fail_frame = pack_connect_fail_func(stream_id, "DNS or connection timeout")
                if write_lock:
                    async with write_lock:
                        tunnel_writer.write(fail_frame)
                        await tunnel_writer.drain()
                else:
                    tunnel_writer.write(fail_frame)
                    await tunnel_writer.drain()
                return None
            except (ConnectionError, OSError) as e:
                log.warning("Stream %d: CONNECT FAILED to %s:%d: %s",
                            stream_id, host, port, e)
                fail_frame = pack_connect_fail_func(stream_id, str(e))
                if write_lock:
                    async with write_lock:
                        tunnel_writer.write(fail_frame)
                        await tunnel_writer.drain()
                else:
                    tunnel_writer.write(fail_frame)
                    await tunnel_writer.drain()
                return None

    @staticmethod
    def _resolve(host: str) -> str:
        """Resolve hostname using system DNS (same as ping/curl)."""
        info = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        if not info:
            raise OSError(f"DNS resolution returned no results for {host}")
        return info[0][4][0]

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
