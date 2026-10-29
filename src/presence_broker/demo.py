"""A real MCP client and loopback server exercise, using synthetic or phone factors."""

import asyncio
import getpass
import json
import logging
import socket
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pyotp
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, TextContent

from presence_broker.server import create_app
from presence_broker.store import Store


@asynccontextmanager
async def running_server(store: Store) -> AsyncIterator[str]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                create_app(store),
                log_level="critical",
                access_log=False,
            )
        )
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if task.done():
                        await task
                        raise RuntimeError("demo server did not start")
                    await asyncio.sleep(0.01)
            yield f"http://127.0.0.1:{port}/mcp"
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, timeout=10)


@asynccontextmanager
async def client(url: str, token: str) -> AsyncIterator[ClientSession]:
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("use an endpoint URL without credentials, query or fragment")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")
    ):
        raise ValueError("plaintext HTTP is permitted only on loopback")
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
        trust_env=False,
    ) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


def text(result: CallToolResult) -> str:
    return "\n".join(part.text for part in result.content if isinstance(part, TextContent))


def expect(result: CallToolResult, *, refusal: str | None = None) -> None:
    if refusal:
        if not result.isError or refusal not in text(result):
            raise RuntimeError(f"expected {refusal}, got {text(result)}")
    elif result.isError:
        raise RuntimeError(text(result))


async def lifecycle(
    url: str, token: str, *, secret: str | None = None, second_token: str | None = None
) -> list[str]:
    checks: list[str] = []
    async with client(url, token) as session:
        # A demo must not silently revoke pre-existing authority.
        initial = await session.call_tool("active_grants")
        expect(initial)
        if json.loads(text(initial))["grants"] != []:
            raise RuntimeError("demo requires a fresh session with no grants")
        try:
            expect(await session.call_tool("increment_counter"), refusal="capability_denied")
            checks.append("ungranted tool denied")
            expect(await session.call_tool("request_access", {}), refusal="presence_check_failed")
            empty = await session.call_tool("active_grants")
            expect(empty)
            if json.loads(text(empty))["grants"] != []:
                raise RuntimeError("missing factor created a grant")
            checks.append("agent approval without factor refused; zero grants")
            code = pyotp.TOTP(secret).now() if secret else getpass.getpass("Fresh phone code: ")
            expect(await session.call_tool("request_access", {"code": code, "ttl": 60}))
            checks.append("fresh factor created scoped grant")
            expect(await session.call_tool("increment_counter"))
            checks.append("protected operation executed")
            if second_token:
                async with client(url, second_token) as other:
                    expect(await other.call_tool("increment_counter"), refusal="capability_denied")
                    expect(
                        await other.call_tool("request_access", {"code": code}),
                        refusal="replayed_code",
                    )
                checks.extend(["other session denied", "same code on other session refused"])
            else:
                expect(
                    await session.call_tool("request_access", {"code": code}),
                    refusal="replayed_code",
                )
                checks.append("same code refused")
        finally:
            expect(await session.call_tool("revoke_grants"))
        expect(await session.call_tool("increment_counter"), refusal="capability_denied")
        final = await session.call_tool("active_grants")
        expect(final)
        if json.loads(text(final))["grants"] != []:
            raise RuntimeError("revocation left active grants")
        checks.append("revocation enforced; zero grants")
    return checks


async def run_demo(url: str | None = None, token_file: Path | None = None) -> None:
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if url:
        if token_file is None:
            raise ValueError("--token-file is required with --url")
        checks = await lifecycle(url, token_file.read_text().strip())
    else:
        if token_file:
            raise ValueError("--token-file requires --url")
        with tempfile.TemporaryDirectory(prefix="presence-demo-") as temp:
            store = Store.initialize(Path(temp) / "state")
            first, second = store.create_session("demo-a"), store.create_session("demo-b")
            async with running_server(store) as endpoint:
                checks = await lifecycle(endpoint, first, secret=store.secret, second_token=second)
            events = store.audit()
            if not any(row["event"] == "grant_issued" for row in events):
                raise RuntimeError("grant audit missing")
            checks.append("attributed audit persisted")
    for check in checks:
        print(f"PASS {check}")
