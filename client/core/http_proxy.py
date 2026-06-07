"""
Furun VPN - HTTP CONNECT Proxy

Browser sends CONNECT host:port via HTTP proxy protocol.
DNS resolves on server side (Japan), eliminating local-DNS issues.
"""

import asyncio
from common.utils import get_logger
from client.core.router import Router

log = get_logger("client.http_proxy")


class HttpConnectProxy:
    """HTTP CONNECT proxy -- relays browser connections through tunnel."""

    def __init__(self, router: Router, host="127.0.0.1", port=8080):
        self.router = router
        self.host = host
        self.port = port
        self._server = None
        self._running = False
        self._total = 0

    @property
    def stats(self):
        return {"total": self._total, "host": self.host, "port": self.port}

    async def start(self):
        self._running = True
        self._server = await asyncio.start_server(
            self._handle, host=self.host, port=self.port)
        log.debug("HTTP CONNECT proxy on %s:%d", self.host, self.port)

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        log.debug("HTTP CONNECT proxy stopped (%d total)", self._total)

    # --- Request routing ---

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter):
        self._total += 1
        peer = writer.get_extra_info("peername")
        log.debug("HTTP #%d from %s:%d", self._total, peer[0], peer[1])

        target_reader = target_writer = None
        host = port = None
        try:
            request_line = await asyncio.wait_for(reader.readline(), 10.0)
            if not request_line:
                writer.close()
                return
            req = request_line.decode("utf-8", "replace").strip()
            log.debug("HTTP #%d: %s", self._total, req)
            parts = req.split()
            if len(parts) < 2:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            method = parts[0].upper()
            target = parts[1]

            if method == "CONNECT":
                host, port, target_reader, target_writer = await self._handle_connect(
                    reader, writer, target)
            else:
                host, port, target_reader, target_writer = await self._handle_http_get(
                    reader, writer, method, target, req)

            # Bidirectional relay
            if target_reader and target_writer:
                up, down = await self._relay(reader, writer, target_reader, target_writer)
                if host:
                    await self.router.record_stream_result(host, up, down)
                log.debug("HTTP #%d | %s:%d | CLOSED (sent=%d recv=%d)",
                         self._total, host or "?", port or 0, up, down)

        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionError, OSError) as e:
            log.debug("HTTP #%d: %s", self._total, e)
        except Exception as e:
            log.error("HTTP #%d: %s", self._total, e, exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # --- CONNECT handler (HTTPS) ---

    async def _handle_connect(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              target: str) -> tuple[str | None, int | None,
                                                    asyncio.StreamReader | None,
                                                    asyncio.StreamWriter | None]:
        """Handle CONNECT method (HTTPS tunnel)."""
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
        else:
            host, port = target, 443
        log.debug("HTTP CONNECT #%d: %s:%d", self._total, host, port)

        # Discard remaining headers
        while True:
            line = await asyncio.wait_for(reader.readline(), 5.0)
            if not line or line.strip() == b"":
                break

        result = await self.router.route(host, port)
        if result is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return host, port, None, None

        target_reader, target_writer = result
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        return host, port, target_reader, target_writer

    # --- HTTP GET/POST handler ---

    async def _handle_http_get(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter,
                               method: str, target: str, req: str
                               ) -> tuple[str | None, int | None,
                                          asyncio.StreamReader | None,
                                          asyncio.StreamWriter | None]:
        """Handle GET/POST/PUT etc. (plain HTTP)."""
        # Parse the full URL: http://host:port/path
        if "://" in target:
            scheme, rest = target.split("://", 1)
            if "/" in rest:
                hostpart, path = rest.split("/", 1)
                path = "/" + path
            else:
                hostpart, path = rest, "/"
            if ":" in hostpart:
                host, port_str = hostpart.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 80
            else:
                host, port = hostpart, 80
        else:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return None, None, None, None

        log.debug("HTTP GET #%d: %s:%d%s", self._total, host, port, path)

        # Read all headers
        headers = [req + "\r\n"]
        content_length = 0
        while True:
            line = await asyncio.wait_for(reader.readline(), 5.0)
            if not line:
                break
            line_str = line.decode("utf-8", "replace")
            headers.append(line_str)
            if line_str.lower().startswith("content-length:"):
                try:
                    content_length = int(line_str.split(":")[1].strip())
                except ValueError:
                    pass
            if line.strip() == b"":
                break

        # Read body if present
        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(
                reader.readexactly(content_length), 10.0)

        # Rewrite request line to remove scheme/host (relative path)
        headers[0] = "%s %s HTTP/1.1\r\n" % (method, path)

        result = await self.router.route(host, port)
        if result is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return host, port, None, None

        target_reader, target_writer = result

        # Forward the rewritten request
        request_bytes = "".join(headers).encode("utf-8")
        target_writer.write(request_bytes)
        if body:
            target_writer.write(body)
        await target_writer.drain()

        return host, port, target_reader, target_writer

    # --- Bidirectional relay ---

    async def _relay(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
                     tr: asyncio.StreamReader, tw: asyncio.StreamWriter
                     ) -> tuple[int, int]:
        async def r(src: asyncio.StreamReader,
                    dst: asyncio.StreamWriter) -> int:
            total = 0
            try:
                while self._running:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    try:
                        await dst.drain()
                    except (ConnectionError, OSError):
                        break
                    total += len(data)
            except (ConnectionError, asyncio.IncompleteReadError, OSError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass
            return total

        t1 = asyncio.create_task(r(cr, tw))
        t2 = asyncio.create_task(r(tr, cw))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        sp = set()
        if pending:
            _, sp = await asyncio.wait(pending, timeout=10.0)
        up = t1.result() if t1.done() and not t1.exception() else 0
        down = t2.result() if t2.done() and not t2.exception() else 0
        for t in sp:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        return up, down
