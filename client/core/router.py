"""
Furun VPN - Client Router with automatic Circuit Breaker and connection pool.

Circuit breaker only applies to DIRECT connections.
PROXY connections are handled by the server via a connection pool, which
manages its own failures and parallelism.
"""

import asyncio
import time

from common.utils import get_logger, resolve_host, is_ip_address
from client.core.tunnel import TunnelPool, TunnelClient, TunnelStream, CONNECT_REJECTED
from client.core.rule_engine import RuleEngine, Action
from client.core.geoip import is_china_ip, is_special_ip
from client.core.circuit_breaker import CircuitBreaker

log = get_logger("client.router")


class _TunnelStreamWriter:
    def __init__(self, s: TunnelStream):
        self._stream = s
        self._tunnel = s._tunnel
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
                    log.warning("TunnelStreamWriter send error: %s (%s)", e, type(e).__name__)
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
            log.warning("TunnelStreamReader _feed error: %s (%s)", e, type(e).__name__)
        finally:
            self.feed_eof()


DNS_CACHE_TTL = 300
DNS_CACHE_MAX = 1024

# Heuristic thresholds for the circuit breaker's auto-learning of dead direct
# routes. A real TLS session sends a ClientHello (>~200 B up) and gets a
# ServerHello back (>~7 B down); a GFW reset or silent drop leaves near-zero
# bytes in at least one direction. Tuned to avoid false positives on CDNs.
TLS_OK_MIN_SENT = 200
TLS_OK_MIN_RECV = 7

# How long a proxy host the server reported unreachable is fast-failed locally,
# so a page polling a dead host (NXDOMAIN / refused) doesn't re-probe the tunnel
# on every request. Short enough that a recovering target self-heals quickly.
PROXY_FAIL_TTL = 15.0
PROXY_FAIL_MAX = 512


class Router:
    """Orchestrates traffic routing between direct and proxy paths."""

    def __init__(self, pool: TunnelPool, rule_engine: RuleEngine):
        self.pool = pool
        self.rule_engine = rule_engine
        self.circuit_breaker = CircuitBreaker()
        self._dns_cache: dict[str, tuple[float, str]] = {}
        self._proxy_fail: dict[tuple[str, int], float] = {}  # (host, port) -> expiry_monotonic
        self._stats = {
            "direct_connections": 0,
            "proxy_connections": 0,
            "blocked_connections": 0,
            "failed_connections": 0,
            "cb_blocked": 0,       # attempts denied by the circuit breaker
            "bytes_up": 0,         # cumulative bytes sent to targets this session
            "bytes_down": 0,       # cumulative bytes received from targets
        }

    @property
    def stats(self) -> dict:
        s = dict(self._stats)  # keeps cb_blocked as the attempts-denied counter
        s["cb_blocked_ips"] = self.circuit_breaker.get_blocked_count()  # gauge: IPs currently blocked
        s["cb_tracked"] = self.circuit_breaker.get_failure_count()
        s["cb_tls_rejects"] = self.circuit_breaker.get_tls_reject_count()
        return s

    async def record_stream_result(self, host: str, bytes_sent: int, bytes_recv: int):
        if bytes_sent == 0 and bytes_recv == 0:
            return
        self._stats["bytes_up"] += bytes_sent
        self._stats["bytes_down"] += bytes_recv
        if is_ip_address(host):
            resolved_ip = host
        else:
            # Reuse the DNS answer route() cached. A miss means route() never
            # resolved this host locally -- i.e. it was proxied by an explicit
            # domain rule -- so the circuit breaker (which only gates DIRECT
            # routes) has no interest in it. Skip rather than pay a fresh local
            # lookup per completed proxy stream (the project resolves on the
            # server side by design).
            resolved_ip = self._cached_resolve(host)
            if resolved_ip is None:
                return
        if not resolved_ip or not is_ip_address(resolved_ip):
            return
        if bytes_sent > TLS_OK_MIN_SENT or bytes_recv > TLS_OK_MIN_RECV:
            self.circuit_breaker.record_success(resolved_ip)
        else:
            self.circuit_breaker.record_tls_reject(resolved_ip)

    def _cached_resolve(self, host: str) -> str | None:
        now = time.monotonic()
        entry = self._dns_cache.get(host)
        if entry and now < entry[0]:
            return entry[1]
        if entry:
            del self._dns_cache[host]
        return None

    def _prune_dns_cache(self):
        """Drop expired entries; if still over capacity, evict soonest-to-expire."""
        if len(self._dns_cache) <= DNS_CACHE_MAX:
            return
        now = time.monotonic()
        # First pass: remove anything already expired.
        expired = [h for h, (exp, _) in self._dns_cache.items() if now >= exp]
        for h in expired:
            del self._dns_cache[h]
        if len(self._dns_cache) <= DNS_CACHE_MAX:
            return
        # Still full: evict the entries with the earliest expiry.
        overflow = len(self._dns_cache) - DNS_CACHE_MAX
        for h, _ in sorted(self._dns_cache.items(), key=lambda kv: kv[1][0])[:overflow]:
            del self._dns_cache[h]

    async def route(self, host: str, port: int) -> tuple[asyncio.StreamReader,
                                                               asyncio.StreamWriter] | None:
        log.debug("ROUTE %s:%d", host, port)

        host_is_ip = is_ip_address(host)
        resolved_ip = host if host_is_ip else self._cached_resolve(host)  # cached or None

        # First pass: match explicit domain/IP rules by hostname (+ any cached
        # IP). match_explicit returns None only when NO rule matched, so an
        # explicit rule is honoured even when its action equals default_action.
        action = self.rule_engine.match_explicit(host, resolved_ip)

        # Resolve DNS only when an IP is actually needed: no rule matched (need
        # heuristics), or the matched action is DIRECT (need the IP for the local
        # connect + circuit breaker). PROXY/BLOCK by domain name skip the lookup
        # -- the server resolves for PROXY, and BLOCK needs no IP. This removes a
        # blocking getaddrinfo from the hot path for every proxied domain.
        if (action is None or action == Action.DIRECT) and resolved_ip is None and not host_is_ip:
            try:
                resolved_ip = await asyncio.get_running_loop().run_in_executor(
                    None, resolve_host, host, port)
            except Exception:
                resolved_ip = None
            if resolved_ip and is_ip_address(resolved_ip):
                self._dns_cache[host] = (time.monotonic() + DNS_CACHE_TTL, resolved_ip)
                self._prune_dns_cache()
            else:
                resolved_ip = None
            if action is None:
                # Re-check explicit rules now that we have a resolved IP (IP CIDR
                # rules can match the answer even when the hostname didn't).
                action = self.rule_engine.match_explicit(host, resolved_ip)

        if action is None:
            # No explicit rule matched; fall back to IP-based heuristics.
            if resolved_ip and is_special_ip(resolved_ip):
                action = Action.DIRECT
            elif resolved_ip and is_china_ip(resolved_ip):
                action = Action.DIRECT
            elif self.pool.connected:
                action = Action.PROXY
            else:
                action = self.rule_engine.default_action

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
            # Connect to the exact IP the routing decision was made on, so the
            # circuit-breaker bookkeeping below matches the socket we opened and
            # we avoid a second, independent getaddrinfo inside open_connection.
            connect_host = resolved_ip if (resolved_ip and is_ip_address(resolved_ip)) else host
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_host, port), timeout=10.0)
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
            if not self.pool.connected:
                log.warning("PROXY: tunnel pool not connected for %s:%d", host, port)
                self._stats["failed_connections"] += 1
                return None

            # Fast-fail hosts the server recently reported unreachable, so a page
            # polling a dead host doesn't re-probe the tunnel on every request.
            # Keyed by (host, port): a connection-refused is port-specific, so one
            # dead port must not fast-fail every other port of the same host.
            now = time.monotonic()
            exp = self._proxy_fail.get((host, port))
            if exp is not None and now < exp:
                self._stats["failed_connections"] += 1
                log.debug("PROXY  %s:%d fast-fail (server reported unreachable)", host, port)
                return None

            log.debug("PROXY  %s:%d", host, port)
            stream = await self.pool.create_stream(host, port, timeout=10.0)
            if stream is None:  # no connected tunnel could carry it -- one retry
                await asyncio.sleep(0.3)
                stream = await self.pool.create_stream(host, port, timeout=10.0)

            if stream is CONNECT_REJECTED:
                # Host-level failure: every tunnel rejects this target the same
                # way. Cache it so repeated requests fast-fail above.
                self._proxy_fail[(host, port)] = now + PROXY_FAIL_TTL
                self._prune_proxy_fail()
                self._stats["failed_connections"] += 1
                return None
            if stream is None:
                self._stats["failed_connections"] += 1
                return None

            return self._wrap_tunnel_stream(stream)

        return None

    def _prune_proxy_fail(self):
        """Drop expired entries; if still over capacity, evict soonest-to-expire."""
        if len(self._proxy_fail) <= PROXY_FAIL_MAX:
            return
        now = time.monotonic()
        for h in [h for h, exp in self._proxy_fail.items() if now >= exp]:
            del self._proxy_fail[h]
        if len(self._proxy_fail) <= PROXY_FAIL_MAX:
            return
        overflow = len(self._proxy_fail) - PROXY_FAIL_MAX
        for h, _ in sorted(self._proxy_fail.items(), key=lambda kv: kv[1])[:overflow]:
            del self._proxy_fail[h]

    def _wrap_tunnel_stream(self, stream: TunnelStream) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return _TunnelStreamReader(stream), _TunnelStreamWriter(stream)
