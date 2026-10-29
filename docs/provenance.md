# Provenance and scope

This project was created as a runnable companion to Brooks McMillin's talk,
**Approval Is Not Human Presence: Building and Breaking an MCP Permission Broker**.

It is a new, reduced adaptation informed by the private infra repository at
revision `ee011f45687dba11a00eea08f00efc45dd17d68b`, particularly:

- `services/mcp-broker/mcp_broker/totp_gate.py`: global TOTP replay state,
  persistent failure accounting and serialized state updates.
- `services/mcp-broker/mcp_broker/policy_store.py`: session-bound TTL grants,
  centralized grant insertion, revocation and attributable audit.
- `services/mcp-broker/mcp_broker/broker_gateway.py`: authorization on every tool
  invocation, rather than relying on visibility or client approval behavior.
- The associated TOTP and permission-lifecycle regression tests.

The implementation deliberately does not copy the complete modules or their
workspace dependency graph. The official MCP Python SDK handles transport; a
small SQLite reference monitor supplies the security-relevant behavior. Factor
verification and grant minting are one atomic transaction here, rather than a
separate in-process presence-proof interface. Administration uses local
service-owned state instead of exposing the deployed broker's admin socket.

The example backend is a counter stored inside the broker, not a browser, database
proxy or shell command. This makes the protected operation runnable without
private services or credentials. It is not a general MCP reverse proxy.

## Evidence boundaries

The talk describes historical deployed negative/positive controls and a historical
SQLite migration defect. None of those evaluation results are evidence that this
new implementation has been exercised under the same workstation threat model.
This project begins at schema version 1 and rejects unknown database versions;
it does not include the private application's historical schema migrations.
Future schema changes need fixtures built from this project's actual prior state.

The demo checks real MCP transport and execution using synthetic factors. Phone
mode additionally supports manual enrollment/code entry but does not establish
that its terminal is trusted or that the OS service boundary is correctly set up.
Do not label synthetic-factor results as measured human participation.

The original broker's profiles, catalogue, private endpoints, OAuth adapters,
Pi integration, browser UI, database/k3s rules and deployed state are omitted.
No history from the private infra repository is imported.

## Publication status

Initially private at the owner's request. No redistribution license has yet been
selected. A public release should add the owner's chosen license, review all
tracked content and publish only results actually measured against a tagged
revision of this project. Lack of a license is intentional at this private stage,
not an assertion that the project is already open source.
