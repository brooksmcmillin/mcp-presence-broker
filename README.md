# MCP Presence Broker

A small runnable reference companion to **Approval Is Not Human Presence**.
An MCP client may send its own approval input; only the service-owned broker can
verify a fresh factor and mint a session-scoped, short-lived capability grant.

This is a new, reduced adaptation of Brooks McMillin's infra broker, **not** a
standalone release of the deployed system. Historical evaluation results do not
apply to this implementation. See [provenance](docs/provenance.md) and
[the security model](docs/security.md).

## Quickstart (behavior demo, not an OS security boundary)

Requires Python 3.13+, [uv](https://docs.astral.sh/uv/), and Linux or macOS.

```sh
uv sync --locked
uv run presence-broker demo
```

The automated demo starts a loopback MCP server with temporary state and a
synthetic factor. It checks missing-factor refusal, zero grants, successful
factor approval, actual protected tool execution, session isolation, replay
refusal and revocation. It cleans up its temporary state. **It knows the seed;
this is a protocol/behavior test, not proof of human participation.**

## Try your own authenticator

```sh
umask 077
uv run presence-broker init --state .state
uv run presence-broker session --state .state --label my-client > client.token
uv run presence-broker serve --state .state
```

Enrollment prints a secret `otpauth://` URI once. Enroll it in your phone's TOTP
app using a trusted terminal. Do not paste it into an agent conversation, share
terminal logs, or send it to an online QR generator. The default endpoint is
`http://127.0.0.1:8765/mcp`; supply `Authorization: Bearer <session token>` in your
MCP client. Keep the token file private (`chmod 600 client.token`).

In another terminal, exercise the phone-assisted lifecycle:

```sh
uv run presence-broker demo --url http://127.0.0.1:8765/mcp --token-file client.token
```

This asks for a fresh code without echo. A code is single-use across **all**
sessions; wait for the next 30-second step if needed. No code is put in argv or
logs. Unlike the automated demo, remote mode does not create a second session,
so cross-session isolation is covered by the automated demo/tests instead.
The code passes through the client to the broker: do not interpret this as a
trusted transaction-confirmation channel.

### Tools

| Tool | Behavior |
| --- | --- |
| `request_access(code?, capability="counter.increment", ttl=60)` | Verify the factor and mint a grant; TTL is 1–300 seconds |
| `active_grants()` | Inspect this session's current grants |
| `increment_counter()` | Increment service-owned SQLite state only with an active grant |
| `revoke_grants()` | Revoke all grants belonging to this session |

Tools remain discoverable without a grant. **Hiding tools is not enforcement**;
every protected call checks current session and grant state. The counter is an
intentionally harmless backend inside the broker, with no separate bypass port.

Operator commands (run as the state-owning service user):

```sh
uv run presence-broker audit --state .state
uv run presence-broker revoke-session --state .state --id 1
```

Audit output contains session IDs and outcomes, never codes, seeds or bearer
tokens. Session IDs are recorded by the session-created audit event. Restarting
the broker preserves grants, replay state and lockout. Five failed factor attempts
cause a global 60-second lockout; creating sessions cannot reset it.

## Protected deployment

A same-user quickstart **cannot** protect against an agent running as that user.
Use the separate service-identity recipe in [deployment.md](docs/deployment.md).
The protected boundary includes installed code, Python environment, database,
factor seed, service configuration and the protected operation. An agent with
root, unrestricted sudo, service-account access, or writable service code is
outside this threat model. Filesystem mode checks are helpful but do not prove
that the host is configured securely.

## Development

```sh
uv sync --locked
./scripts/check
uv run presence-broker demo
```

`check` runs the project's small test suite, Ruff and Pyright with a timeout.
Tests use temporary state and synthetic seeds only; they never connect to a live
broker or touch your authenticator. No private infrastructure is required.

## Status

Reference implementation, not a production security product. No upstream OAuth,
remote TLS termination, browser UI, policy editor, Pi integration, or general MCP
proxying. A real upstream adapter must keep its credentials and direct execution
path outside agent authority and re-authorize every dispatch.

The repository is initially private. A redistribution license and public-release
review must be selected before advertising it as open source.
