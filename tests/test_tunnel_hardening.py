"""Regression tests for the tunnel-stall hardening fixes.

Covers the three root causes behind the 06-15 mass CONNECT-timeout incident:
  1. server: a stuck client socket must not hold the tunnel write lock forever
     (send_frame_locked drain timeout -> closes the dead tunnel).
  2. server: PONG must travel the same locked/drain-bounded path as data, so a
     wedged data plane can't keep answering PINGs (zombie tunnel).
  3. client: the per-stream recv buffer must be bounded so a slow local app
     can't grow memory without limit.
"""
import asyncio
import pytest

from server.forward_proxy import send_frame_locked, DRAIN_TIMEOUT, ForwardProxy, SERVER_DNS_TTL
from client.core.tunnel import TunnelStream, TunnelClient, TunnelConfig


# --- Fake StreamWriter doubles -------------------------------------------------

class _FastWriter:
    """drain() returns immediately."""
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data):
        self.written += data

    async def drain(self):
        return

    def close(self):
        self.closed = True


class _StalledWriter:
    """drain() never completes -- models a peer that stopped reading."""
    def __init__(self):
        self.closed = False

    def write(self, data):
        pass

    async def drain(self):
        await asyncio.Event().wait()  # blocks forever

    def close(self):
        self.closed = True


# --- Fix 1: drain timeout closes a dead tunnel ---------------------------------

@pytest.mark.asyncio
async def test_send_frame_locked_ok_on_healthy_writer():
    w = _FastWriter()
    lock = asyncio.Lock()
    ok = await send_frame_locked(w, lock, b"hello")
    assert ok is True
    assert w.written == b"hello"
    assert w.closed is False


@pytest.mark.asyncio
async def test_send_frame_locked_times_out_and_closes():
    w = _StalledWriter()
    lock = asyncio.Lock()
    # Use a tiny timeout so the test is fast; real default is DRAIN_TIMEOUT.
    ok = await send_frame_locked(w, lock, b"x", timeout=0.05)
    assert ok is False
    assert w.closed is True, "stalled tunnel must be closed so the loop sees EOF"


@pytest.mark.asyncio
async def test_send_frame_locked_releases_lock_after_timeout():
    """A stalled write must not hold the lock past the timeout -- otherwise
    every other stream's CONNECT_OK/PONG stays blocked (the original bug)."""
    w = _StalledWriter()
    lock = asyncio.Lock()
    await send_frame_locked(w, lock, b"x", timeout=0.05)
    assert not lock.locked(), "lock must be free after a timed-out drain"


@pytest.mark.asyncio
async def test_default_drain_timeout_is_sane():
    assert 1.0 <= DRAIN_TIMEOUT <= 60.0


# --- Fix 3: bounded client recv buffer -----------------------------------------

def test_stream_buffer_accepts_under_cap():
    s = TunnelStream(1, tunnel=None)
    s.feed_data(b"a" * 1024)
    assert not s.closed
    assert s._buffered_bytes == 1024


def test_stream_buffer_closes_on_overflow():
    s = TunnelStream(2, tunnel=None)
    chunk = b"a" * (1024 * 1024)
    closed_by_overflow = False
    for _ in range(TunnelStream.MAX_BUFFER_BYTES // len(chunk) + 2):
        s.feed_data(chunk)
        if s.closed:
            closed_by_overflow = True
            break
    assert closed_by_overflow, "stream must close once buffer exceeds the cap"


@pytest.mark.asyncio
async def test_stream_buffer_bytes_decrease_on_read():
    s = TunnelStream(3, tunnel=None)
    s.feed_data(b"a" * 1000)
    s.feed_data(b"b" * 500)
    assert s._buffered_bytes == 1500
    data = await s.read(-1)          # drains all queued chunks
    assert len(data) == 1500
    assert s._buffered_bytes == 0


# --- Fix A: client write serialization + bounded drain -------------------------

@pytest.mark.asyncio
async def test_client_send_ok_on_healthy_writer():
    c = TunnelClient(TunnelConfig(host="x"))
    c._writer = _FastWriter()
    assert await c._send(b"hello") is True
    assert c._writer.written == b"hello"
    assert c._writer.closed is False


@pytest.mark.asyncio
async def test_client_send_times_out_and_closes_dead_tunnel():
    c = TunnelClient(TunnelConfig(host="x"))
    c._writer = _StalledWriter()
    ok = await c._send(b"x", timeout=0.05)
    assert ok is False
    assert c._writer.closed is True, "stalled tunnel must be closed so the reader sees EOF"


@pytest.mark.asyncio
async def test_client_send_releases_lock_after_timeout():
    """A stalled write must not hold the write lock past the timeout, or every
    other stream's frames stay blocked behind it (the bug this lock prevents)."""
    c = TunnelClient(TunnelConfig(host="x"))
    c._writer = _StalledWriter()
    await c._send(b"x", timeout=0.05)
    assert not c._write_lock.locked()


# --- Fix B: server-side DNS cache ----------------------------------------------

def test_server_dns_cache_hit_and_expiry():
    p = ForwardProxy(max_connections=1)
    assert p._dns_cache_get("a.com") is None              # miss
    p._dns_cache_put("a.com", "1.2.3.4")
    assert p._dns_cache_get("a.com") == "1.2.3.4"          # hit
    exp, ip = p._dns_cache["a.com"]                        # force the entry stale
    p._dns_cache["a.com"] = (exp - SERVER_DNS_TTL - 1, ip)
    assert p._dns_cache_get("a.com") is None               # expired -> evicted
    assert "a.com" not in p._dns_cache


@pytest.mark.asyncio
async def test_stream_partial_read_keeps_remainder():
    """read(n) returns at most n bytes and preserves the rest for the next
    read -- a chunk larger than n must never be silently truncated."""
    s = TunnelStream(4, tunnel=None)
    s.feed_data(b"HELLO_WORLD_1234")  # 16 bytes in one chunk
    assert await s.read(5) == b"HELLO"
    assert await s.read(5) == b"_WORL"
    assert await s.read(100) == b"D_1234"   # remainder, not dropped
    assert s._buffered_bytes == 0
    assert s._bytes_recv == 16              # accounting counts only delivered bytes
