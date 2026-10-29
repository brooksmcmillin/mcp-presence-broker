# Security model

## Claim

Given a protected broker process, code/configuration, SQLite state and TOTP seed,
a client that controls its own MCP messages but lacks the enrolled factor cannot
mint a grant merely by accepting an approval prompt or inventing a presence
object. It must authenticate with a live session and submit a valid, unused factor.
Every counter operation checks that session's current grant under the same
SQLite write transaction as the operation. The client cannot select another
session to receive or exercise the grant.

This is conditional factor possession, **not proof of attention, intent, informed
consent or phishing resistance**. A code is not bound cryptographically to a
capability, request or session. An agent that observes a fresh code can race its
intended use. A compromised authenticator or agent-readable seed defeats the
presence claim. This reference uses an explicit MCP tool parameter for the code,
not a trusted display or protocol elicitation UI.

## Attacker and trusted computing base

The attacker has arbitrary execution as the interactive user, can modify its own
client checkout, knows its session bearer, and can construct MCP requests. It
cannot write installed service code, become the broker user, read the broker's
factor seed/database, access the human authenticator, or control root/systemd.
Being in a group with unrestricted sudo is outside this model. The OS, Python,
dependencies, service installation and operator enrollment channel are trusted.

Only the broker owns the protected counter. A generalized adapter must also own
its upstream credentials and ensure the client cannot call that upstream directly.
The broker cannot make an already agent-accessible capability inaccessible.

## Implementation invariants

- Enrollment is mandatory; startup fails on missing seed, unsafe state-file
  ownership/modes, symlinked state files, or an unsupported database version.
- Session tokens are random 256-bit secrets; only SHA-256 hashes are persisted.
  Tokens are bearer credentials, not proof of a unique process identity. Sharing
  a token shares that session's grants. Sessions persist until operator revocation.
- Capability is fixed to `counter.increment`. TTL is 1–300 seconds.
- Grant insertion and verification occur together in one service-side method;
  no client boolean, serialized presence proof or caller-selected session ID is
  accepted as evidence.
- TOTP uses six digits, 30-second steps and a ±1-step clock window. A matched step
  must be strictly newer than the last consumed step across all sessions.
- `BEGIN IMMEDIATE` serializes verification/consumption/grant creation. Refused
  factor attempts commit their audit/counters before raising an error. Success
  consumes the code and inserts the grant atomically.
- Five failed factor attempts lock the enrollment for 60 seconds. Lockout and
  replay state persist across restarts and newly created sessions. This creates
  a deliberate availability tradeoff: an authenticated attacker can deny approvals
  by provoking repeated lockouts. This is a reference brute-force bound, not a
  claim that unlimited guessing over days is harmless.
- Tool calls revalidate both session and grant, including expiration/revocation.
  Listing a tool conveys no authority. Local counter execution and authorization
  share a transaction; a revocation cannot be interleaved between them.
- HTTP binds only to loopback. Each request authenticates independently; MCP
  transport session IDs are not treated as authorization. SDK DNS-rebinding
  protection remains enabled; proxy headers are ignored by the server CLI.
- Audit records contain identity references, refusal reasons, grant metadata and
  execution outcomes, not factor codes, bearer tokens or seeds.

## Limitations

Quickstart runs everything as one user and is **not** the protected deployment.
Filesystem checks do not inspect ACLs, writable ancestor directories, debugger
permissions, backups, malicious dependencies, sudo rules or host compromise.
The Linux service recipe needs operator review and host-level verification.
Loopback transport is intentionally local; this project does not provide TLS,
OAuth discovery, remote access, or a network perimeter.

No audit rotation, disk quota, broad request-flood protection, hardware-backed
keys or multi-operator enrollment is included. Audit is not tamper-evident against
the service user or root. Clock changes affect TOTP and TTL checks. Enrollment
rotation/recovery requires an explicit operator procedure, not deleting replay
state on a live installation. Backing up/restoring an old database can resurrect
old authorization state. Stop the service for coherent backups and protect them
like live state; do not restore a stale snapshot as an authorization reset.

## Verification

`./scripts/check` covers real MCP HTTP round trips, denial without factor,
forged client presence input, protected operation, scoped grants, expiration,
revocation, session revocation, replay across sessions/restarts, parallel replay,
parallel failure accounting, global lockout, unsafe/missing seed state, unknown
schema version refusal and authenticated DNS-rebinding rejection.

The automated demo uses synthetic factors and checks a functioning positive path,
not just denial. It does not prove physical human presence. No historical 15-case
workstation-boundary evaluation has been rerun against this project. The separate
service-identity recipe has not been live-validated by the automated suite.
