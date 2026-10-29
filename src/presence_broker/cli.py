"""Operator commands must run as the state-owning service identity."""

import argparse
import asyncio
import json
import os
from pathlib import Path

import pyotp
import uvicorn

from presence_broker.demo import run_demo
from presence_broker.server import create_app
from presence_broker.store import Store


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Presence-gated MCP reference broker")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "session", "serve", "audit", "revoke-session"):
        command = commands.add_parser(name)
        command.add_argument("--state", type=Path, required=True)
        if name == "session":
            command.add_argument("--label", required=True)
        elif name == "serve":
            command.add_argument("--port", type=int, default=8765)
        elif name == "revoke-session":
            command.add_argument("--id", type=int, required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--url")
    demo.add_argument("--token-file", type=Path)
    args = parser.parse_args()
    if args.command == "demo":
        asyncio.run(run_demo(args.url, args.token_file))
        return
    if args.command == "init":
        store = Store.initialize(args.state)
        print("SECRET enrollment URI — keep off agent-visible terminals and logs:")
        print(pyotp.TOTP(store.secret).provisioning_uri("operator", issuer_name="Presence Broker"))
        return
    store = Store(args.state)
    if args.command == "session":
        print(store.create_session(args.label))
    elif args.command == "serve":
        uvicorn.run(
            create_app(store),
            host="127.0.0.1",
            port=args.port,
            access_log=False,
            proxy_headers=False,
            log_level="warning",
        )
    elif args.command == "audit":
        for row in store.audit():
            print(json.dumps(row))
    elif args.command == "revoke-session":
        store.revoke_session(args.id)
