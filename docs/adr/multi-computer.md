# ADR: one switchboard, many computers (v2)

Status: proposed · 2026-10-03 · supersedes the "one VM at a time" rule of v1

## Context

v1 has one slot for the machine with the hands. Whoever attaches last owns it, and the
previous one is closed with `4002` and stops. That was enough to prove the relay, and it
broke the moment there were two computers:

- macmini (instance-mcp 0.8.0, switchboard mode) holds the slot today. Muse's VM attaching
  as a second set of hands would evict it, and the macmini daemon would stop by contract.
- Testing a second Mac's `wss://` path would do the same.
- The only workaround is one switchboard per computer, with its own port, `tailscale serve`
  entry, tokens and, for Muse, its own per-address approval.

The trust model the owner described is two layers, and v1 only has the first:

1. **Who may attach.** Callers are on the tailnet (the `tailscale serve` front) *and*
   present a bearer token. Computers present their own secret.
2. **What each caller may use.** Which computers, and which tools on each.

instance-mcp #27 (hands-node registry) reaches the same conclusion from the other side:
"lend my Mac" must become "lend a hands node", picked from a list. The switchboard is a
natural place for that list, since every computer already dials it.

## Decision

### Computers are configured, named, and identified by their secret

```toml
[[computer]]
name = "macmini"
secret_sha256 = "sha256:…"

[[computer]]
name = "muse-vm"
secret_sha256 = "sha256:…"
max_inflight = 4            # optional; per computer, default 8
```

- A computer still dials `GET /vm/attach` with `Authorization: Bearer <secret>`. **The
  secret alone selects the slot**: verifiers must be unique across computers (`check`
  refuses duplicates, as v1 already does for clients). No URL change, so every v1 daemon
  (instance-mcp 0.8.0, `sb_daemon.py`) works unchanged.
- A name the computer reports about itself (`serverInfo`, hostname) is shown in status and
  never trusted. The configured name is the identity.
- No self-registration. Adding a computer is an operator action: generate a pair, add the
  verifier, `SIGHUP`.
- One live socket per computer. A second attach **with the same secret** replaces the first
  (`4002`, unchanged). An attach with another computer's secret takes *that* computer's slot
  and touches nothing else.
- Removing or rotating a computer's verifier on reload closes only that computer (`4003`).

### Callers get access per computer

```toml
[[client]]
name = "pahud"
token_sha256 = "sha256:…"
computers = { "*" = ["*"] }                     # owner: every computer, every tool

[[client]]
name = "muse"
token_sha256 = "sha256:…"
computers = { macmini = ["sys_info", "screenshot", "browser_navigate", "browser_snapshot",
                         "browser_click", "browser_type", "browser_press_key",
                         "browser_wait_for", "browser_tabs", "browser_take_screenshot"] }

[[client]]
name = "connect"
token_sha256 = "sha256:…"
computers = { macmini = ["sys_info", "screenshot"], muse-vm = ["sys_info"] }
```

- **Deny by default.** A computer missing from `computers` does not exist for that caller:
  it is not listed, and calling it is the same error as calling an unknown computer. No
  enumeration through error differences.
- `"*"` as a computer name means every configured computer. It is meant for the owner and
  is logged at startup when used.
- The tool list per computer is the same allowlist v1 has, including `vm_status` always
  being available. It is still policy, not isolation (see Trust in the README); the
  computer's own profile (instance-mcp `observe`/`desktop`/`owner`) remains the ceiling, and
  the caller gets the intersection.

### Northbound: one MCP endpoint per computer

```
POST /mcp/{computer}     MCP for one computer, tool names unchanged
POST /mcp                the caller's only computer, if it has exactly one; otherwise an
                         `initialize` instruction listing /mcp/{computer} and a tools/list
                         with only `list_computers`
GET  /computers          JSON: the computers this caller may use, with online state
```

Why a path per computer instead of namespaced tools (`macmini__screenshot`) or a
`computer` argument on every tool:

- **Tool names stay exact.** Connect matches `sys_info` and `screenshot` by name; models are
  prompted with instance-mcp's own instructions, which name tools unprefixed.
- **A computer is an MCP server.** MCP clients already know how to hold several servers.
  Adding "macmini" and "muse-vm" as two servers in Kiro, Connect or a Muse skill is the
  existing UX, with the switchboard as the only URL host.
- **Policy is evaluated once per request** from the path, before any frame is sent.

`/mcp` keeps v1 behaviour for callers with exactly one computer, so existing clients do not
change. `GET /computers` is what a node picker (instance-mcp #27, Connect) reads.

### PTY attach names its computer

```toml
[[pty_attach]]
name = "kiro-1040"
computer = "muse-vm"          # required when more than one computer is configured
url = "wss://…/tools/attach/laptop"
secret_file = "…"
tools = ["*"]
```

This is the switchboard half of #27: "lend muse-vm to session `laptop`" is one block.

### Health, status, audit

- `/healthz` is unchanged (switchboard alive).
- `/readyz` is 200 when **every** configured computer is ready; `/readyz/{computer}` is the
  per-computer probe. Monitoring can alert on either.
- `/status` (client token) lists only the computers that caller may use.
- Every audit line about a call or an attach gains `computer`. Takeover and revoke lines are
  per computer.

### Compatibility

A v1 config loads unchanged:

- `[vm]` becomes a computer named `default`.
- A client's `tools = [...]` becomes `computers = { default = [...] }`.
- `[[pty_attach]]` without `computer` targets `default`.

Mixing `[vm]` with `[[computer]]` is a config error, so there is never a question of which
one wins.

## Consequences

- One switchboard, one port, one `tailscale serve` entry and, for Muse, one approved address
  serve every computer.
- macmini and a Muse VM can both be attached; neither evicts the other.
- Muse as a caller keeps its token and adds one URL (`/mcp/macmini`). Muse as a computer
  needs a VM secret and a daemon that dials out.
- The hub becomes a map of slots, each with its own pending table, `max_inflight`, ping
  liveness and generation counter. A slow or dead computer cannot starve another.
- Memory and audit grow with the number of computers. Expected scale is single digits.

## Not in v2

- Routing a call to "any available computer", load balancing, fan-out.
- Computer-to-computer calls through the switchboard.
- Self-registration or enrolment tokens for computers.
- Per-caller rate limits (beyond per-computer `max_inflight`).
- Persisting anything across restarts.

## Alternatives considered

- **One switchboard per computer.** Works today. Rejected as the long-term shape: N ports,
  N configs, N tokens per caller, N approvals for Muse, and no single place to answer "which
  computers exist".
- **Namespaced tool names on one `/mcp`.** One server entry per caller, but tool names
  change, Connect breaks, and a model sees 3× the tool list for three computers.
- **`computer` argument on every tool.** Same single endpoint, but every tool schema is
  rewritten and a forgotten argument is a call to the wrong machine.
- **Computer chosen by URL on attach (`/vm/attach/{name}`).** Redundant with the secret, and
  lets a computer that knows another's name try its secret against it. The secret already
  says who it is.

## Rollout

1. Config model + loader with v1 compatibility (unit tests: v1 config, duplicate verifiers,
   unknown computer in a client, `[vm]` + `[[computer]]` refused).
2. Hub as a map of slots; per-computer takeover, revoke, liveness (e2e: two fake VMs attached
   together; evicting one leaves the other; rotating one leaves the other).
3. `/mcp/{computer}`, `/computers`, `/readyz/{computer}`; `/mcp` single-computer fallback
   (e2e: deny-by-default is indistinguishable from unknown).
4. `[[pty_attach]].computer`.
5. Deploy on macmini with `default` renamed to `macmini`; Muse caller moves to `/mcp/macmini`.
6. **First second computer: Muse's VM.** Needs, on Muse's side: a daemon that dials
   `/vm/attach` through its `:3130` proxy (`sb_daemon.py` today; the Linux instance-mcp port
   has no switchboard mode yet, which is the instance-mcp follow-up), a place for the VM
   secret, and the daemon staying up between conversations. Those are the questions to ask
   Muse before step 6.
