"""
Furun VPN - Server Tunnel Endpoint
Enhanced logging: every frame, every buffer op, every relay lifecycle event.
"""

import asyncio
import ssl
import socket

from common.protocol import (
    Cmd, FRAME_HEADER_SIZE, unpack_frame, pack_connect_ok, pack_connect_fail,
    pack_pong, pack_data, unpack_connect,
)
from common.crypto import create_server_ssl_context
from common.utils import get_logger
from server.forward_proxy import ForwardProxy

log = get_logger("server.tunnel")


class TunnelServer:
    """Accepts encrypted client connections and manages proxy forwarding."""

    def __init__(self, config: dict):
        self.config = config
        self.psk = config["psk"].encode("utf-8") if isinstance(config["psk"], str) else config["psk"]
        self.forward_proxy = ForwardProxy(max_connections=config.get("max_connections", 500))
        self._client_id_counter = 0
        self.ssl_context: ssl.SSLContext | None = None
        self._server: asyncio.AbstractServer | None = None
        self._running = False

    def _setup_ssl(self):
        self.ssl_context = create_server_ssl_context(
            self.config["tls_cert_file"], self.config["tls_key_file"])

    async def start_with_ssl(self):
        self._setup_ssl()
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client, host=self.config["listen_host"],
            port=self.config["listen_port"], ssl=self.ssl_context)
        log.info("=== Tunnel server (TLS) listening on %s:%d ===",
                 self.config["listen_host"], self.config["listen_port"])
        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.forward_proxy.close_all()
        log.info("=== Tunnel server stopped ===")

    async def _handle_connect(self, client_id: int, stream_id: int, target_host: str,
                              target_port: int, writer: asyncio.StreamWriter,
                              active_streams: dict, pending: dict,
                              deferred_close: set, write_lock: asyncio.Lock):
        """Background task: connect to target, flush buffered data, set up relay."""
        log.debug("[C%d S%d] CONNECT task started for %s:%d", client_id, stream_id, target_host, target_port)

        relay = await self.forward_proxy.connect_target(
            client_id, stream_id, target_host, target_port,
            writer, pack_connect_ok, pack_connect_fail,
            write_lock=write_lock)

        if relay:
            buf = pending.pop(stream_id, [])
            if buf:
                total = sum(len(d) for d in buf)
                log.debug("[S%d] Flushing %d buffered DATA frames (%d bytes)",
                         stream_id, len(buf), total)
                for data in buf:
                    relay.target_writer.write(data)
                try:
                    await relay.target_writer.drain()
                except Exception as e:
                    log.warning("[S%d] Drain after buffer flush failed: %s", stream_id, e)

            if stream_id in deferred_close:
                deferred_close.discard(stream_id)
                log.debug("[S%d] Deferred CLOSE after buffered flush", stream_id)
                self.forward_proxy.remove_relay(client_id, stream_id)
                relay.close()
            else:
                task = asyncio.create_task(relay.relay_target_to_tunnel(pack_data))
                active_streams[stream_id] = task
                log.debug("[S%d] Relay task started (active streams: %d)",
                          stream_id, len(active_streams))
        else:
            log.warning("[C%d S%d] CONNECT FAILED for %s:%d", client_id, stream_id, target_host, target_port)
            active_streams.pop(stream_id, None)
            pending.pop(stream_id, None)
            deferred_close.discard(stream_id)

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        self._client_id_counter += 1
        client_id = self._client_id_counter
        log.info("=== CLIENT CONNECTED: %s:%d [CID=%d] ===", peer[0], peer[1], client_id)
        try:
            sock = writer.get_extra_info('socket')
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

        authenticated = False
        active_streams: dict[int, asyncio.Task] = {}
        pending_data: dict[int, list[bytes]] = {}
        deferred_close: set[int] = set()
        write_lock = asyncio.Lock()
        buf = b""
        pos = 0
        frame_count = 0

        try:
            while self._running:
                data = await asyncio.wait_for(reader.read(65536), timeout=self.config.get("idle_timeout", 120))
                if not data:
                    log.info("[CLIENT %s:%d] TCP EOF (read returned empty)", peer[0], peer[1])
                    break
                if pos > 0:
                    buf = buf[pos:]
                    pos = 0
                buf += data
                log.debug("[CLIENT %s:%d] Read %d bytes from socket (buffer: %d bytes)",
                          peer[0], peer[1], len(data), len(buf))

                while True:
                    result = unpack_frame(buf[pos:])
                    if result is None:
                        break
                    stream_id, cmd, payload = result
                    pos += FRAME_HEADER_SIZE + len(payload)
                    frame_count += 1

                    if not authenticated:
                        if cmd == Cmd.AUTH:
                            if payload == self.psk:
                                authenticated = True
                                log.info("[CLIENT %s:%d] AUTH OK (frame #%d)",
                                         peer[0], peer[1], frame_count)
                                try:
                                    writer.write(pack_connect_ok(0))
                                    await writer.drain()
                                except (ConnectionError, OSError):
                                    return
                            else:
                                log.warning("[CLIENT %s:%d] AUTH FAILED (frame #%d)",
                                            peer[0], peer[1], frame_count)
                                writer.write(pack_connect_fail(0, "Auth failed"))
                                await writer.drain()
                                return
                        else:
                            log.warning("[CLIENT %s:%d] Pre-auth frame #%d cmd=%s - rejecting",
                                        peer[0], peer[1], frame_count, cmd.name)
                            writer.write(pack_connect_fail(0, "Not authenticated"))
                            await writer.drain()
                            return
                        continue

                    if cmd == Cmd.PING:
                        log.debug("[CLIENT %s:%d] Frame #%d: PING (stream %d) -> PONG",
                                  peer[0], peer[1], frame_count, stream_id)
                        try:
                            writer.write(pack_pong())
                            await writer.drain()
                        except (ConnectionError, OSError, AssertionError):
                            break

                    elif cmd == Cmd.CONNECT:
                        conn_info = unpack_connect(payload)
                        if conn_info:
                            target_host, target_port = conn_info
                            log.debug("[CLIENT %s:%d] Frame #%d: [S%d] CONNECT %s:%d",
                                     peer[0], peer[1], frame_count,
                                     stream_id, target_host, target_port)
                            task = asyncio.create_task(
                                self._handle_connect(
                                    client_id, stream_id, target_host, target_port,
                                    writer, active_streams,
                                    pending_data, deferred_close, write_lock))
                            active_streams[stream_id] = task
                        else:
                            log.warning("[CLIENT %s:%d] Frame #%d: [S%d] CONNECT payload corrupt",
                                        peer[0], peer[1], frame_count, stream_id)

                    elif cmd == Cmd.DATA:
                        log.debug("[CLIENT %s:%d] Frame #%d: [S%d] DATA %d bytes",
                                  peer[0], peer[1], frame_count, stream_id, len(payload))
                        relay = self.forward_proxy.get_relay(client_id, stream_id)
                        if relay:
                            try:
                                relay.target_writer.write(payload)
                                await relay.target_writer.drain()
                            except (ConnectionError, OSError):
                                pass
                        elif stream_id in active_streams:
                            pending_data.setdefault(stream_id, []).append(payload)
                            log.debug("[S%d] DATA %d bytes BUFFERED (connect still pending, queue: %d)",
                                     stream_id, len(payload),
                                     len(pending_data.get(stream_id, [])))
                        else:
                            log.warning("[S%d] DATA %d bytes DROPPED (no relay, no pending connect)",
                                        stream_id, len(payload))

                    elif cmd == Cmd.CLOSE:
                        relay = self.forward_proxy.get_relay(client_id, stream_id)
                        if relay:
                            log.debug("[CLIENT %s:%d] Frame #%d: [S%d] CLOSE (relay active)",
                                     peer[0], peer[1], frame_count, stream_id)
                            self.forward_proxy.remove_relay(client_id, stream_id)
                            task = active_streams.pop(stream_id, None)
                            if task and not task.done():
                                task.cancel()
                        elif stream_id in active_streams:
                            log.debug("[CLIENT %s:%d] Frame #%d: [S%d] CLOSE DEFERRED (connect pending)",
                                     peer[0], peer[1], frame_count, stream_id)
                            deferred_close.add(stream_id)
                        else:
                            log.debug("[CLIENT %s:%d] Frame #%d: [S%d] CLOSE (no active stream)",
                                      peer[0], peer[1], frame_count, stream_id)
                            active_streams.pop(stream_id, None)

                    else:
                        log.debug("[CLIENT %s:%d] Frame #%d: [S%d] cmd=%s",
                                  peer[0], peer[1], frame_count, stream_id, cmd.name)

        except asyncio.TimeoutError:
            log.info("[CLIENT %s:%d] Idle timeout -- no data for %.0fs, closing",
                     peer[0], peer[1], self.config.get("idle_timeout", 120))
        except (ConnectionError, asyncio.IncompleteReadError, OSError) as e:
            log.info("[CLIENT %s:%d] Connection error: %s", peer[0], peer[1], e)
        except Exception as e:
            log.error("[CLIENT %s:%d] Fatal error: %s", peer[0], peer[1], e, exc_info=True)
        finally:
            active_count = len(active_streams)
            pend_buf = sum(len(v) for v in pending_data.values())
            log.info("[CLIENT %s:%d] Cleaning up: %d active streams, %d pending DATA frames, %d deferred closes",
                     peer[0], peer[1], active_count, pend_buf, len(deferred_close))
            for stream_id in list(active_streams.keys()):
                self.forward_proxy.remove_relay(client_id, stream_id)
                task = active_streams.pop(stream_id, None)
                if task and not task.done():
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass
            pending_data.clear()
            deferred_close.clear()
            try:
                writer.close()
            except Exception:
                pass
            log.info("=== CLIENT DISCONNECTED: %s:%d (processed %d frames) ===",
                     peer[0], peer[1], frame_count)
