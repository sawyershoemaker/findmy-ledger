import asyncio
import unittest

from research.auth_diagnostics import AuthTrace

try:
    from research.auth_transport import AuthenticationSession
    from findmy.util.http import HttpSession
except ImportError:
    AuthenticationSession = None


@unittest.skipIf(AuthenticationSession is None, "Install the auth extra")
class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = 0
        self.connections = 0
        self.writers = []
        self.always_429 = False

        async def receive(reader, writer):
            self.connections += 1
            self.writers.append(writer)
            count = 0
            try:
                while True:
                    await reader.readuntil(b"\r\n\r\n")
                    self.requests += 1
                    count += 1
                    limited = self.always_429 or count > 1
                    code = b"429 Too Many Requests" if limited else b"200 OK"
                    retry = b"Retry-After: 3600\r\n" if limited else b""
                    writer.write(b"HTTP/1.1 " + code + b"\r\nContent-Length: 2\r\n" + retry + b"\r\n{}")
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()

        self.server = await asyncio.start_server(receive, "127.0.0.1", 0)
        self.url = f"http://127.0.0.1:{self.server.sockets[0].getsockname()[1]}/synthetic"

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        for writer in self.writers:
            writer.close()
            await writer.wait_closed()

    async def test_authentication_requests_use_separate_connections(self):
        pooled = HttpSession()
        fixed = AuthenticationSession(AuthTrace())
        try:
            old = [(await pooled.get(self.url)).status_code for _ in range(2)]
            new = [(await fixed.get(self.url)).status_code for _ in range(2)]
            self.assertEqual(old, [200, 429])
            self.assertEqual(new, [200, 200])
            self.assertEqual(self.connections, 3)
        finally:
            await pooled.close()
            await fixed.close()

    async def test_429_is_never_retried_and_delay_is_captured(self):
        self.always_429 = True
        trace = AuthTrace()
        session = AuthenticationSession(trace)
        try:
            response = await session.get(self.url, auto_retry=True)
            self.assertEqual(response.status_code, 429)
            self.assertEqual(self.requests, 1)
            self.assertEqual(trace.retry_after_seconds, 3600)
        finally:
            await session.close()
