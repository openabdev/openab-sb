# ADR: one switchboard, many computers (v2)

Status: proposed · 2026-10-03 · revision 3 (after two reviews) · supersedes the "one VM at a time"
rule of v1

## Context

v1 has one slot for the machine with the hands. Whoever attaches last owns it, and the
previous one is closed with `4002` and stops. That was enough to prove the relay, and it
broke the moment there were two computers:

- macmini (instance-mcp 0.8.0, switchboard mode) holds the slot today. Muse's VM attaching
  as a second set of hands would evict it, and the macmini daemon would stop by contract.
- Testing a second Mac's `wss://` path would do the same.
- The only workaround is one switchboard per computer, each with its own port,
  `tailscale serve` entry and tokens, and for Muse its own per-address approval.

The owner's trust model is two layers, and v1 only has the first:

1. **Who may attach.** Callers are on the tailnet (the `tailscale serve` front) *and*
   present a bearer token. Computers present their own secret.
2. **What each caller may use.** Which computers, and which tools on each.

instance-mcp #27 (hands-node registry) reaches the same conclusion from the other side:
"lend my Mac" must become "lend a hands node", picked from a list. The switchboard is a
natural place for that list, since every computer already dials it.

## Decision

### Computers are configured; the verifier is the identity, the name is a label

```toml
max_inflight = 8            # default for every computer (unchanged from v1)

[[computer]]
name = "macmini"
secret_sha256 = "sha256:…"

[[computer]]
name = "muse-vm"
secret_sha256 = "sha256:…"
max_inflight = 4            # optional override
```

- A computer still dials `GET /vm/attach` with `Authorization: Bearer <secret>`. **The
  secret alone selects the slot.** The URL does not change, so every v1 daemon
  (instance-mcp 0.8.0, `sb_daemon.py`) works as is.
- **Slot identity is the verifier.** The configured name is the label used in policy,
  routes and audit. A reload that keeps a verifier and changes its name relabels the live
  socket; nothing is closed (see Reload).
- A name attests possession of a secret, not a particular machine. Whoever holds a
  computer's secret answers as that computer, so a leaked secret is replaced, not tolerated.
- Anything a computer reports about itself (`serverInfo`, hostname, forwarded headers) is
  shown, never trusted.
- No self-registration. Adding a computer is an operator action: generate a pair, add the
  verifier, then `SIGHUP`.
- One live socket per computer. A second attach **with the same secret** replaces the first
  (`4002`, unchanged). An attach with another computer's secret takes only *that*
  computer's slot.

Config rules, all enforced by `check` and at load:

- Computer names are 1–64 characters of `[A-Za-z0-9_-]`. **`.` is not allowed**, because a
  bare TOML key `rpi1.local` is a dotted key that makes a nested table. v1 names (`.` allowed,
  `config.rs:332`) keep their rule for clients and pty attaches.
- Verifiers are unique across **all** computers and clients. v1 already refuses reuse
  between the VM secret and a client token (`config.rs:244,248`); v2 extends that to every
  pair.
- `[vm]` and `[[computer]]` in the same file is an error.
- Every computer named anywhere must exist: in `default_computer`, in a client's
  `computers` table, or in `[[pty_attach]].computer`. `default_computer` must also be one
  the caller may reach. Otherwise the config is refused. Without this, a typo such as
  `macmni` would grant nothing today and **pre-grant** access to any computer given that
  name later. A consequence: removing a computer fails the reload, keeping the old config
  (`main.rs:134`), until every block naming it is edited in the same change.
- Computer names are a separate namespace from client and pty-attach names, which stay
  unique among themselves as in v1 (`config.rs:240,263`). Audit lines carry `principal` and
  `computer` as distinct fields, so `macmini` as both a computer and a client name is
  unambiguous.

### Callers get access per computer, deny by default

```toml
[[client]]
name = "pahud"
token_sha256 = "sha256:…"
default_computer = "macmini"                  # required: more than one computer reachable
computers = { "*" = ["*"] }                   # owner: every computer, every tool

[[client]]
name = "muse"
token_sha256 = "sha256:…"
computers = { macmini = ["sys_info", "screenshot", "browser_navigate", "browser_snapshot",
                         "browser_click", "browser_type", "browser_press_key",
                         "browser_wait_for", "browser_tabs", "browser_take_screenshot"] }
max_inflight = 4                              # optional, see Fairness

[[client]]
name = "connect"
token_sha256 = "sha256:…"
default_computer = "macmini"
computers = { macmini = ["sys_info", "screenshot"], muse-vm = ["sys_info"] }
```

- **Deny by default.** A computer missing from `computers` does not exist for that caller,
  on every route. "Not allowed" and "unknown" produce byte-identical responses.
- **`"*"` means every computer, including ones added later.** A `"*"` caller gains access
  to a new computer the moment it is configured, with no change to its own block. It is for
  the owner, and startup logs every client that uses it.
- `"*"` may not be mixed with named computers in one `computers` table, just as v1 refuses
  `"*"` mixed with tool names (`config.rs:89-94`).
- `computers` may not be empty, and each tool list follows the v1 allowlist rules, including
  that `vm_status` is always available.
- The tool list is still policy, not isolation (see Trust in the README). The computer's own
  profile (instance-mcp `observe`/`desktop`/`owner`) remains the ceiling, and the caller
  gets the intersection.
- A client still carrying v1's top-level `tools` alongside `[[computer]]` blocks is an
  error. That combination means a half-migrated config, and guessing which computer it
  meant would be wrong.
- `check` warns about any computer that no client or pty attach may use.

### Northbound: one MCP endpoint per computer

```
POST /mcp/{computer}     MCP for one computer; tool names unchanged
POST /mcp                exactly /mcp/{default_computer}
GET  /computers          JSON: the computers this caller may use, and whether each is online
```

`GET /computers` returns `[{ "name", "default": bool, "attached": bool, "ready": bool }]`,
one entry per computer the caller may use. The `"*"`-only fields of `/status` are not
included.

**`/mcp` never changes meaning when a computer is added.** It is always the caller's
`default_computer`:

- If a caller can reach exactly one computer, that computer is its default and the field
  is optional.
- If it can reach more than one (including any `"*"` caller), `default_computer` is
  required and `check` refuses the config without it.

Adding `muse-vm` therefore leaves `pahud`'s `/mcp` pointing at macmini, and Connect or Kiro
configured on `/mcp` keep working.

Order of checks on every northbound request:

1. The bearer token is checked **before the path is resolved**. A missing or wrong token is
   `401` whatever the path says, so `/mcp/{unknown}` without a token tells nothing.
2. The computer is resolved against the caller's allowlist. Not allowed and unknown give
   the same `404` with the same body.
3. Tool policy and forwarding work as in v1.

Why a path per computer rather than namespaced tool names (`macmini__screenshot`) or a
`computer` argument on every tool:

- **Tool names stay exact.** Connect matches `sys_info` and `screenshot` by name, and models
  are prompted with instance-mcp's instructions, which name tools unprefixed.
- **A computer is an MCP server.** MCP clients already hold several servers. Adding
  "macmini" and "muse-vm" as two servers in Kiro, Connect or a Muse skill is the existing UX.
- **Policy is evaluated once per request** from the path, before any frame is sent.

There is no `list_computers` MCP tool. Pickers (#27, Connect) are HTTP clients and read
`GET /computers`, and a model on `/mcp/{computer}` could not act on such a list anyway.

`initialize` names the computer in its instructions ("…connected through OpenAB Switchboard
as `macmini`…"). The always-available tool keeps the name `vm_status` for compatibility and
gains a `computer` field.

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
Without `computer` and with more than one computer configured, the config is refused.

### Health and status

- `GET /healthz` is unchanged: no auth, the switchboard is alive.
- `GET /readyz` takes no auth and reveals no names:
  - With **one computer** it behaves exactly as in v1: 200 when that computer is attached
    and ready, else 503.
  - With **several**, it returns 200 if any computer is ready, else 503. The bodies are
    v1's (`ok` / `vm offline`), with no counts, so an unauthenticated probe learns neither
    names nor how many computers exist. An intermittent computer such as a Muse VM does not
    make it flap.
- `GET /readyz/{computer}` **requires a client token** and answers only for that caller's
  computers: 200 ready, 503 offline. Unknown and not-allowed give the same 404 as on
  `/mcp/{computer}`, so a tailnet node without a token (an untagged Muse node included)
  cannot learn which computers exist. Monitoring uses a token scoped to the computers it
  watches, for example `computers = { macmini = ["vm_status"] }` (a tool list may not be
  empty, `config.rs:87-89`).
- `GET /status` (client token) lists only the caller's computers.
  - The socket peer (`hub.rs:243-252`, taken from forwarded identity headers,
    `server.rs:104-123`) and the in-flight count are shown only to `"*"` callers.
  - Other callers see each computer's name, `attached`, `ready`, `server`,
    `attached_for_secs` and `max_in_flight` (`hub.rs:243-252`). Only `peer` and `in_flight`
    are hidden.
  - The same filter applies to the `vm_status` tool.

### Hub: a map of slots under one lock

- The hub holds one `Mutex` over the whole table: verifier → (name, slot). There are no
  per-slot locks, so install, takeover and reload never interleave across computers.
- `/vm/attach` compares the presented verifier against **every** computer verifier with no
  early exit, the same way v1 handles client tokens (`config.rs:163-173`). Timing does not
  reveal which computer matched.
- **Install re-resolves under the lock.** v1's protection against an attach authenticated
  just before a reload (`hub.rs:341-346`) generalises as follows: at install, the socket's
  verifier is looked up again in the current table; if it is gone, the socket is refused
  with `4003`, and if it now maps to another name, it installs under that name.
- Each slot has its own pending table, `max_inflight`, ping liveness and close handling.
  A slow or dead computer cannot starve another.
- `generation` is per computer (v1's is hub-wide, `hub.rs:264`). Audit lines carry
  `computer` and that computer's generation.

### Fairness between callers on one computer

`max_inflight` counts per socket (`hub.rs:174-180`). Without more, one caller can occupy
every slot on a shared computer, so a long Muse browsing run would starve Connect's
screenshot poll on macmini.

v2 adds a per-client cap on each computer:

- The cap applies to **every principal**, clients and pty attaches alike. A pod attach is a
  caller too, and its own 64-request ceiling (`pty.rs`, `MAX_CONCURRENT_POD_REQUESTS`) is
  larger than any computer's cap, so without this one pod could starve Connect.
- `[[client]].max_inflight` and `[[pty_attach]].max_inflight` set it, within `1..=64`.
- The default is half of the **live socket's** `max_inflight` (the value it attached with,
  `hub.rs:352`), rounded up. A reload that changes the computer's limit does not move the
  per-caller default until the next attach.
- A caller over its cap gets `-32002` without the call being sent, exactly like the
  computer-wide cap.

### Reload (SIGHUP)

| Change | Effect |
|---|---|
| Client added, removed, token rotated, allowlist or `default_computer` changed | from the next request |
| Computer added | its slot exists at once and accepts an attach |
| Computer removed, or its verifier rotated | that socket closes with `4003`. Its in-flight calls fail with `-32004` and **may have run** (`hub.rs:151-158`). Other computers are untouched |
| Same verifier, new name | the live socket is relabelled, and an audit line `computer_renamed` records it. No close |
| A verifier moved from one name to another | a relabel, not a revoke |
| `max_inflight` (global or per computer) | **new in v2**: reloaded, and applied to that computer's next attach. A live socket keeps the value it attached with (`hub.rs:352`). In v1 limits need a restart (`main.rs:130`) |
| `[[pty_attach]]` added, removed or changed, `listen`, timeouts | need a restart, as in v1 (`server.rs:90-99`, `main.rs:130`) |
| Per-caller `max_inflight` | from that caller's next call |

Reload stays hub-first, as v1's `reload_auth` does (`server.rs:81-90`). The computer table
is swapped before client auth, so a daemon presenting a newly added secret is never
refused with `4003`.

### Compatibility

A v1 config loads unchanged:

- `[vm]` becomes a computer named `default`.
- A client's `tools = [...]` becomes `computers = { default = [...] }`, with
  `default_computer = "default"`.
- `[[pty_attach]]` without `computer` targets `default`.
- Top-level `max_inflight` stays the per-computer default.

Nothing a v1 caller or daemon sees changes: `/mcp`, `/readyz`, `/status` and the close codes
behave as before while there is one computer.

## Consequences

- One switchboard, one port, one `tailscale serve` entry and, for Muse, one approved address
  serve every computer.
- macmini and a Muse VM can both be attached, and neither evicts the other.
- Muse as a caller keeps its token and URL (`/mcp` defaults to macmini). Muse as a computer
  needs a VM secret and a daemon that dials out.
- Moving macmini's config from `default` to `macmini` is a relabel. The attached instance-mcp
  is not closed, which matters because a daemon that gets `4003` stops until someone
  restarts it (instance-mcp `ReverseAttachClient.swift:125`, `sb_daemon.py:35`).
- Memory and audit grow with the number of computers. The expected scale is single digits.

## Not in v2

- Routing a call to "any available computer", load balancing, fan-out.
- Computer-to-computer calls through the switchboard.
- Self-registration or enrolment tokens for computers.
- Rate limits beyond per-computer and per-client in-flight caps.
- Persisting anything across restarts.

## Alternatives considered

- **One switchboard per computer.** Works today. Rejected as the long-term shape: N ports,
  N configs, N tokens per caller, N approvals for Muse, and no single place to answer "which
  computers exist".
- **Namespaced tool names on one `/mcp`.** One server entry per caller, but tool names
  change, Connect breaks, and a model sees three times the tool list for three computers.
- **A `computer` argument on every tool.** Same single endpoint, but every tool schema is
  rewritten, and a forgotten argument becomes a call to the wrong machine.
- **Computer chosen by URL on attach (`/vm/attach/{name}`).** It adds nothing, because the
  secret already identifies the computer, and it would change the URL that instance-mcp
  0.8.0 and `sb_daemon.py` already dial.
- **`/mcp` answering with only a `list_computers` tool for multi-computer callers.**
  Rejected: adding a second computer would silently break every client configured on `/mcp`.

## Rollout and tests

1. **Config model and loader.** Unit tests:
   - a v1 config maps to `default` exactly;
   - `[vm]` together with `[[computer]]` is refused;
   - a duplicate verifier is refused, between computers and between a computer and a client;
   - `"*"` mixed with named computers is refused;
   - an empty `computers` table is refused;
   - a `.` in a computer name is refused with a message;
   - a multi-computer or `"*"` caller without `default_computer` is refused;
   - a client keeping `tools` beside `[[computer]]` is refused;
   - `[[pty_attach]]` without `computer` is refused when there are several computers;
   - a computer name in `default_computer`, `computers` or `[[pty_attach]].computer` that is
     not configured is refused, and a `default_computer` the caller may not reach is refused;
   - a per-caller `max_inflight` outside `1..=64` is refused;
   - `check` warns about a computer no caller may use.
2. **The hub as a map.** End-to-end tests:
   - two fake computers stay attached together;
   - evicting, rotating or removing one leaves the other attached and its calls succeeding;
   - a same-verifier rename keeps the socket;
   - swapping two verifiers between names evicts nothing;
   - an attach authenticated just before its verifier is removed is refused with `4003`;
   - per-computer in-flight isolation: one computer full, the other still answers;
   - the per-caller cap leaves room for a second caller on the same computer, and applies to
     a pty attach as well as a client;
3. **Routes.** End-to-end tests:
   - `/mcp/{computer}`, `/computers` and `/readyz/{computer}` work for allowed computers;
   - `/mcp/{unknown}` and `/readyz/{unknown}` without a token are `401`;
   - `/readyz` bodies carry no names or counts;
   - unknown and not-allowed give identical responses on every route;
   - a `"*"` caller's `/mcp` `tools/list` is identical before and after a computer is added;
   - `/readyz` is unchanged with one computer and gives `ready N/M` with several;
   - `peer` is hidden from non-`"*"` callers.
4. **`[[pty_attach]].computer`.**
5. **Deploy on macmini.** Swapping the binary is a restart: instance-mcp gets `1001` and
   redials (`ReverseAttachClient.swift:126`). After that, relabel `default` to `macmini` by
   reload and confirm instance-mcp stays attached through the reload.
6. **First second computer: Muse's VM.** Open questions for Muse before this step:
   - Can a WebSocket upgrade cross its TCP-only `:3130` HTTP proxy? That needs `CONNECT`, and
     proxy support in the daemon's WebSocket library.
   - Where does the VM secret live? The Secure Credentials Store injects headers into HTTPS
     requests; does it do the same for a WebSocket upgrade?
   - Does the daemon stay up between conversations?
   - Which tools can the VM offer? `sb_daemon.py` needs X11 for `screenshot`, `mouse` and
     `key`.

   On our side: the Linux instance-mcp port has no switchboard mode yet (an instance-mcp
   follow-up), so step 6 starts with `sb_daemon.py`.
