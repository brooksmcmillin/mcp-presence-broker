"""Minimal MCP adapter; authentication is attached to each HTTP request."""

from contextvars import ContextVar

from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from presence_broker.store import CAPABILITY, Denied, Store

_token: ContextVar[str] = ContextVar("broker_session_token")


class AuthenticatedApp:
    def __init__(self, app: ASGIApp, store: Store) -> None:
        self.app = app
        self.store = store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = [value for key, value in scope["headers"] if key.lower() == b"authorization"]
        token = ""
        if len(headers) == 1 and headers[0].startswith(b"Bearer "):
            token = headers[0][7:].decode("ascii", errors="replace")
        try:
            self.store.authenticate(token)
        except Denied:
            await JSONResponse({"error": "invalid_session"}, status_code=401)(scope, receive, send)
            return
        context = _token.set(token)
        try:
            await self.app(scope, receive, send)
        finally:
            _token.reset(context)


def create_app(store: Store) -> ASGIApp:
    mcp = FastMCP(
        "Presence Broker",
        instructions=(
            "counter.increment requires a session-scoped grant. request_access requires a fresh "
            "operator TOTP code; accepting a prompt is not proof. Never seek the enrollment seed."
        ),
        host="127.0.0.1",
        log_level="WARNING",
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool()
    async def request_access(
        code: str | None = None, capability: str = CAPABILITY, ttl: int = 60
    ) -> dict[str, object]:
        """Request a capability using a fresh operator factor, not a client approval boolean."""
        return store.request_grant(_token.get(), code, capability, ttl)

    @mcp.tool()
    async def active_grants() -> dict[str, object]:
        """List this session's currently active grants."""
        return {"grants": store.grants(_token.get())}

    @mcp.tool()
    async def increment_counter() -> dict[str, int]:
        """Increment broker-owned state; an active counter.increment grant is required."""
        return {"value": store.increment(_token.get())}

    @mcp.tool()
    async def revoke_grants() -> dict[str, bool]:
        """Revoke this session's grants. Revocation needs no additional authority."""
        store.revoke(_token.get())
        return {"revoked": True}

    return AuthenticatedApp(mcp.streamable_http_app(), store)
