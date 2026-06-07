"""
Furun VPN - Client Router with automatic Circuit Breaker.

Circuit breaker only applies to DIRECT connections.
PROXY connections are handled by the server, which manages its own failures.
"""

import asyncio
import time

from common.utils import get_logger, resolve_host, is_ip_address
from client.core.tunnel import TunnelClient, TunnelStream
from client.core.rule_engine import RuleEngine, Action
from client.core.geoip import is_china_ip, is_special_ip
from client.core.circuit_breaker import CircuitBreaker

log = get_logger("client.router")


# Module-level stream wrappers (lifted from _wrap_tunnel_stream to avoid
# recreating class objects per stream)

class _TunnelStreamWriter:
    def __init__(self, s: TunnelStream, t: TunnelClient):
        self._stream = s
        self._tunnel = t
        self._closed = False
        self._queue = asyncio.Queue()
        self._drained = asyncio.Event()
        self._drained.set()
        self._sender = asyncio.create_task(self._send_loop())
        self._close_task = None

    async def _send_loop(self):
        try:
            while True:
                data = await self._queue.get()
                if data is None:
                    break
                try:
                    await self._tunnel.send_data(self._stream.stream_id, data)
                except Exception as e:
                    log.warning('TunnelStreamWriter send error: %s (%s)', e, type(e).__name__)
                finally:
                    self._drained.set()
        except asyncio.CancelledError:
            pass

    def write(self, data: bytes):
        if not self._closed and data:
            self._drained.clear()
            self._queue.put_nowait(data)

    async def drain(self):
        await self._drained.wait()

    def close(self):
        if not self._closed:
            self._closed = True
            self._queue.put_nowait(None)
            if not self._sender.done():
                self._sender.cancel()
            self._close_task = asyncio.create_task(
                self._tunnel.close_stream(self._stream.stream_id))

    @property
    def transport(self):
        return None

    def is_closing(self) -> bool:
        return self._closed

    async def wait_closed(self):
        pass

    def get_extra_info(self, name, default=None):
        return default


class _TunnelStreamReader(asyncio.StreamReader):
    def __init__(self, s: TunnelStream):
        super().__init__()
        self._stream = s
        self._feeder_task = asyncio.create_task(self._feed())

    def close(self):
        if self._feeder_task and not self._feeder_task.done():
            self._feeder_task.cancel()
        self.feed_eof()

    async def _feed(self):
        try:
            while not self._stream.closed:
                data = await self._stream.read(65536)
                if not data:
                    break
                self.feed_data(data)
        except Exception as e:
            log.warning('TunnelStreamReader _feed error: %s (%s)', e, type(e).__name__)
        finally:
            self.feed_eof()


DNS_CACHE_TTL = 300  # 5-minute DNS cache

class Router:
    """Orchestrates traffic routing between direct and proxy paths."""

    def __init__(self, tunnel: TunnelClient, rule_engine: RuleEngine):
        self.tunnel = tunnel
        self.rule_engine = rule_engine
        self.circuit_breaker = CircuitBreaker()
        self._dns_cache: dict[str, tuple[float, str]] = {}  # host -> (expires_at, ip)
        self._stats = {
            "direct_connections": 0,
            "proxy_connections": 0,
            "blocked_connections": 0,
            "failed_connections": 0,
            "cb_blocked": 0,
        }

    @property
    def stats(self) -> dict:
        s = dict(self._stats)
        s["cb_blocked"] = self.circuit_breaker.get_blocked_count()
        s["cb_tracked"] = self.circuit_breaker.get_failure_count()
        return s

    async def record_stream_result(self, host: str, bytes_sent: int, bytes_recv: int):
        if bytes_sent == 0 and bytes_recv == 0:
            return
        if is_ip_address(host):
            resolved_ip = host
        else:
            try:
                resolved_ip = await asyncio.get_event_loop().run_in_executor(
                    None, resolve_host, host)
            except Exception:
                return
        if not resolved_ip or not is_ip_address(resolved_ip):
            return
        if bytes_sent > 200 or bytes_recv > 7:
            self.circuit_breaker.record_success(resolved_ip)
        elif bytes_sent <= 200 and bytes_recv <= 7:
            self.circuit_breaker.record_tls_reject(resolved_ip)

    def _cached_resolve(self, host: str) -> str | None:
        now = time.monotonic()
        entry = self._dns_cache.get(host)
        if entry and now < entry[0]:
            return entry[1]
        if entry:
            del self._dns_cache[host]
        return None

    async def route(self, host: str, port: int) -> tuple[asyncio.StreamReader,
                                                               asyncio.StreamWriter] | None:
        log.debug("ROUTE %s:%d", host, port)

        resolved_ip = None
        if is_ip_address(host):
            resolved_ip = host
        else:
            resolved_ip = self._cached_resolve(host)
            if resolved_ip is None:
                try:
                    resolved_ip = await asyncio.get_event_loop().run_in_executor(
                        None, resolve_host, host, port)
                except Exception:
                    resolved_ip = None
                if resolved_ip and is_ip_address(resolved_ip):
                    self._dns_cache[host] = (time.monotonic() + DNS_CACHE_TTL, resolved_ip)

        if resolved_ip and is_special_ip(resolved_ip):
            action = Action.DIRECT
        else:
            action = self.rule_engine.evaluate_with_ip(host, resolved_ip)
            if action == self.rule_engine.default_action and resolved_ip:
                if is_china_ip(resolved_ip):
                    action = Action.DIRECT
                elif self.tunnel.connected:
                    action = Action.PROXY

        if action == Action.DIRECT and resolved_ip and self.circuit_breaker.is_blocked(resolved_ip):
            self._stats["cb_blocked"] += 1
            log.debug("CB-BLOCK %s:%d (IP %s)", host, port, resolved_ip)
            action = Action.BLOCK

        if action == Action.BLOCK:
            self._stats["blocked_connections"] += 1
            log.debug("BLOCK  %s:%d", host, port)
            return None

        elif action == Action.DIRECT:
            self._stats["direct_connections"] += 1
            log.debug("DIRECT %s:%d", host, port)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10.0)
                if resolved_ip:
                    self.circuit_breaker.record_success(resolved_ip)
                return reader, writer
            except asyncio.TimeoutError:
                log.warning("DIRECT timeout: %s:%d", host, port)
                self._stats["failed_connections"] += 1
                if resolved_ip:
                    self.circuit_breaker.record_failure(resolved_ip)
                return None
            except (ConnectionError, OSError) as e:
                log.warning("DIRECT failed %s:%d: %s", host, port, e)
                self._stats["failed_connections"] += 1
                if resolved_ip:
                    self.circuit_breaker.record_failure(resolved_ip)
                return None

        elif action == Action.PROXY:
            self._stats["proxy_connections"] += 1
            log.debug("PROXY  %s:%d", host, port)
            if not self.tunnel.connected:
                log.warning("PROXY: tunnel not connected for %s:%d", host, port)
                self._stats["failed_connections"] += 1
                return None

            try:
                stream = await self.tunnel.create_stream(host, port, timeout=10.0)
                if stream is None:
                    await asyncio.sleep(0.3)
                    stream = await self.tunnel.create_stream(host, port, timeout=10.0)
                if stream is None:
                    self._stats["failed_connections"] += 1
                    return None
            except Exception:
                raise

            return self._wrap_tunnel_stream(stream)

        return None

    def _wrap_tunnel_stream(self, stream: TunnelStream) -> tuple[asyncio.StreamReader,
                                                                   asyncio.StreamWriter]:
        return _TunnelStreamReader(stream), _TunnelStreamWriter(stream, self.tunnel)
