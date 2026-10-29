# Separate-identity deployment (Linux/systemd reference recipe)

This recipe is an operator-reviewed starting point, **not a tested installer**.
It assumes a trusted administrator, system Python 3.13+, and a root-controlled
`uv` executable at `/usr/local/bin/uv`. Adjust those prerequisites to your distro.
Do not grant the agent sudo access to these commands or the service account.
macOS can run the behavior demo; a launchd hardening recipe is not supplied.

## Install reviewed code outside the agent's write authority

Review the source and locked dependencies first. Build/deployment must happen
from trusted operator control; installing from a checkout while the agent can
modify it is not a secure installation procedure. Stage the reviewed repository
content under `/opt/mcp-presence-broker` as root, excluding `.git`, `.venv` and
runtime state. Ensure `/opt` and all relevant ancestor paths are root-owned and
not writable by the agent. Then, from a trusted administrator terminal:

```sh
sudo useradd --system --home-dir /var/lib/mcp-presence-broker --shell /usr/sbin/nologin presence-broker
sudo chown -R root:root /opt/mcp-presence-broker
sudo chmod -R go-w /opt/mcp-presence-broker
sudo /usr/local/bin/uv sync --locked --no-dev --no-editable --python /usr/bin/python3.13 --project /opt/mcp-presence-broker
sudo install -d -o presence-broker -g presence-broker -m 700 /var/lib/mcp-presence-broker
sudo -u presence-broker /opt/mcp-presence-broker/.venv/bin/presence-broker init --state /var/lib/mcp-presence-broker/state
```

The last command displays the enrollment URI. Use a terminal the agent cannot
observe. Enroll with your phone and do not store the URI in an agent-accessible
file, terminal recording or clipboard history. The generated seed and database
are owned by the service account with mode 600 inside mode-700 directories.
Do not install a shared credential-readable group or relax those modes.

Verify installed source, the environment and Python interpreter are not writable
by the interactive user. A root-owned symlink to an agent-writable interpreter
would still break the boundary. Check ACLs as well as Unix mode bits.

## Run the service

Create `/etc/systemd/system/mcp-presence-broker.service` as root:

```ini
[Unit]
Description=Reference MCP presence broker
After=network.target

[Service]
Type=simple
User=presence-broker
Group=presence-broker
WorkingDirectory=/opt/mcp-presence-broker
ExecStart=/opt/mcp-presence-broker/.venv/bin/presence-broker serve --state /var/lib/mcp-presence-broker/state --port 8765
Environment=PYTHONNOUSERSITE=1
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/mcp-presence-broker
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-presence-broker
```

There is no unauthenticated health endpoint and no remote listener. An HTTP 401
from `http://127.0.0.1:8765/mcp` without a token is expected, but does not establish
that the human approval path works.

## Create a client session

In a trusted operator terminal:

```sh
umask 077
sudo -u presence-broker /opt/mcp-presence-broker/.venv/bin/presence-broker session --state /var/lib/mcp-presence-broker/state --label coding-agent > client.token
```

Give this bearer to the intended client only. It can request permission but cannot
read the factor seed. Sharing it with multiple processes intentionally makes them
one authorization session. To revoke the session, read its ID in the operator
`audit` command, then run `revoke-session --id <id>` as the service user.

The CLI directly accesses service-owned state; there is no privileged admin HTTP
endpoint or admin Unix socket in this reduced implementation. No agent-facing
sudo rule should permit invoking the operator CLI as the service account.

## Verify the real boundary before relying on it

From the agent's actual UID and group set:

1. Check that reading the seed/database and writing installed code, environment,
   service unit, interpreter and state directory fail. Check writable ancestors,
   symlinks and ACLs, not just leaf-file modes.
2. Confirm the agent cannot become root or the service user, inspect its process
   memory, or otherwise obtain the service's authority.
3. Use an agent session to call the counter without a grant: expect
   `capability_denied`. Missing/fabricated factors must leave no grants.
4. Run the phone-assisted demo from a trusted client terminal. Confirm actual
   counter execution, replay refusal and post-revocation denial.
5. Create a second session and verify it cannot use the first session's grant.
6. Confirm restart preserves replay/lockout state. Confirm audit attribution and
   absence of seed/code/bearer contents in retained logs.

Keep these host-specific results separate from the automated synthetic demo.
Do not claim successful deployment until these checks have actually run.
