import json
from pathlib import Path

import httpx
import pyotp

from presence_broker.demo import client, expect, lifecycle, running_server, text
from presence_broker.store import Store


async def test_real_mcp_lifecycle(tmp_path: Path) -> None:
    store = Store.initialize(tmp_path / "state")
    a, b = store.create_session("a"), store.create_session("b")
    async with running_server(store) as url:
        checks = await lifecycle(url, a, secret=store.secret, second_token=b)
    assert len(checks) == 7
    assert store.grants(a) == store.grants(b) == []
    assert any(row["event"] == "tool_executed" for row in store.audit())


async def test_http_authentication_and_client_proofs(tmp_path: Path) -> None:
    store = Store.initialize(tmp_path / "state")
    token = store.create_session("a")
    async with running_server(store) as url:
        async with httpx.AsyncClient(trust_env=False) as http:
            for headers in ({}, {"Authorization": "Bearer forged"}):
                response = await http.post(url, headers=headers, json={})
                assert response.status_code == 401
        async with client(url, token) as session:
            listed = await session.list_tools()
            assert "increment_counter" in [tool.name for tool in listed.tools]
            forged = await session.call_tool(
                "request_access",
                {
                    "accepted": True,
                    "presence": {"enabled": True},
                },
            )
            assert forged.isError
            assert store.grants(token) == []
            expect(await session.call_tool("increment_counter"), refusal="capability_denied")
            # No client may select a different session to receive a grant.
            expect(
                await session.call_tool("request_access", {"code": pyotp.TOTP(store.secret).now()})
            )
            result = await session.call_tool("active_grants")
            expect(result)
            assert len(json.loads(text(result))["grants"]) == 1
            store.revoke_session(1)
            # The HTTP layer, not only the MCP handler, rechecks each request.
            async with httpx.AsyncClient(trust_env=False) as http:
                response = await http.post(
                    url, headers={"Authorization": f"Bearer {token}"}, json={}
                )
                assert response.status_code == 401


async def test_authenticated_dns_rebinding_rejected(tmp_path: Path) -> None:
    store = Store.initialize(tmp_path / "state")
    token = store.create_session("a")
    async with running_server(store) as url:
        async with httpx.AsyncClient(trust_env=False) as http:
            response = await http.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Host": "attacker.example",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            assert response.status_code == 421
