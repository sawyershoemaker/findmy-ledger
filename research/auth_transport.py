"""Verified HTTP transport for authentication and authorized Apple services."""
from aiohttp import ClientSession, ClientTimeout, TCPConnector, TraceConfig
from findmy.util.http import HttpSession


class AuthenticationSession(HttpSession):
    def __init__(self, trace):
        super().__init__()  # Retain FindMy.py's verified Apple trust context.
        self.trace = trace

    async def _get_session(self):
        if self._closed:
            raise RuntimeError("Authentication transport is closed")
        if self._session is None:
            hooks = TraceConfig()

            async def received(session, context, parameters):
                response = parameters.response
                self.trace.http_response(response.status, response.headers.get("Retry-After"))

            hooks.on_request_end.append(received)
            # GSA can reject the second SRP request on a reused connection with
            # HTTP 429. These few authentication calls each use a fresh socket.
            self._session = ClientSession(connector=TCPConnector(force_close=True),
                                          timeout=ClientTimeout(total=30), trace_configs=[hooks])
        return self._session

    async def request(self, method, url, **kwargs):
        kwargs["auto_retry"] = False
        return await super().request(method, url, **kwargs)
