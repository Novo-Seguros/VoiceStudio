"""ASGI middlewares for Nexus sign-in (Novo Seguros fork).

Both are pure ASGI, like the other gates in ``main.py``, so streaming bodies
keep streaming, and both are inert unless ``NEXUS_CLIENT_ID`` is set.
"""

from __future__ import annotations

from starlette.requests import HTTPConnection

from core.auth import is_loopback, presented_session_token
from services.nexus_auth import nexus_enabled, refresh_session
from services.nexus_sessions import NEXUS_SESSION_PREFIX, nexus_session_store

_FORWARDING_HEADERS = frozenset({b"cf-connecting-ip", b"x-forwarded-for", b"x-real-ip", b"forwarded"})
#: Any non-loopback address works: it only has to fail every loopback check.
_RELAYED_CLIENT_HOST = "0.0.0.0"


class ProxyLoopbackMiddleware:
    """A loopback peer that carries proxy headers is a relayed remote client.

    Uvicorn already replaces the client with the X-Forwarded-For address for
    a trusted local proxy (cloudflared, Caddy). This is the fail-closed
    backstop for a relay whose forwarded address is missing or itself claims
    loopback: such a request must never inherit the local machine's trust.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and nexus_enabled():
            client = scope.get("client")
            if client and is_loopback(client[0]):
                names = {name.lower() for name, _value in scope.get("headers", ())}
                if names & _FORWARDING_HEADERS:
                    scope = dict(scope, client=(_RELAYED_CLIENT_HOST, client[1]))
        return await self.app(scope, receive, send)


class NexusRefreshMiddleware:
    """Renew an expiring Nexus access token before the auth gates run.

    The gates resolve sessions synchronously and in memory; the network round
    trip to Nexus happens here, at most once per access-token lifetime.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and nexus_enabled():
            token = presented_session_token(HTTPConnection(scope))
            if token.startswith(NEXUS_SESSION_PREFIX):
                record = nexus_session_store.record_for_token(token)
                if record is not None and record.needs_refresh(nexus_session_store.now()):
                    await refresh_session(record)
        return await self.app(scope, receive, send)
