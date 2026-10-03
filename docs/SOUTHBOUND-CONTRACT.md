# Southbound contract — a machine that can only dial out

This is the contract for the **daemon on the dial-out machine** (in practice: a Meta Muse
Secure VM, a box behind NAT, anything with outbound-only networking). Follow it and
`openab-sb` will relay MCP tool calls from OpenAB Connect and OpenAB PTY agents to you over
the one WebSocket you opened.

The daemon is an **MCP server over a WebSocket it dials itself**. There is no custom
envelope: every text frame is one plain MCP JSON-RPC 2.0 message. If you have an MCP server
already, the only new code is "dial instead of listen".

```
 Connect / PTY agent ──MCP──► openab-sb ◄──── WS (you dial) ──── your daemon
                              MCP client      plain MCP JSON-RPC   MCP server
```

## 1. Credentials

The operator runs `openab-sb gen-secret` once. It prints:

- a **secret** (64 hex chars) — give it to the daemon, keep it out of logs and screenshots;
- a **verifier** (`sha256:…`) — goes into `openab-sb.toml` as `[vm].secret_sha256`.

`openab-sb` stores only the verifier, so its config file and memory cannot be used to dial
in. Rotating = generate a new pair, update both sides; the old secret stops working on the
next dial.

## 2. Dial

```
GET wss://<switchboard host>/vm/attach
Authorization: Bearer <secret>
```

- `101` — you are attached. Section 3 begins.
- `401` — wrong or missing secret. **Do not hammer**: retry at most once every 5 minutes
  (an operator has to fix the config; fast retries only fill audit logs).
- anything else / connection refused / TLS error — the switchboard is down or being
  restarted: redial with backoff (section 5).

Transport is whatever fronts the switchboard (`tailscale serve`, Cloudflare Tunnel). The
switchboard itself binds loopback; never send the secret over plain `ws://` across a network
you do not control.

## 3. Session

Once attached, **the switchboard is the MCP client and you are the MCP server.**

1. The switchboard sends `initialize`
   (`protocolVersion` `2025-06-18`, `clientInfo.name` `openab-sb`). Answer it like any MCP
   server would; the `serverInfo` you return is shown to callers in `vm_status`. Answer
   `initialize` **before** any other request.
2. The switchboard then sends `notifications/initialized`. No reply.
3. Every subsequent request (`tools/list`, `tools/call`, `ping`) carries a
   **switchboard-assigned integer `id`**. Reply with exactly that `id`. Ids are rewritten on
   the switchboard; they never match what the end caller sent, and you must not care.
4. Requests may arrive **concurrently** — a screenshot poll and a shell command can be in
   flight at the same time. Either run them concurrently or queue them; replies may be sent
   in any order, matched by `id`.
5. Notifications you send (e.g. `notifications/tools/list_changed`) are accepted and
   dropped. Requests you send are answered `-32601`, except `ping`, which is answered `{}`.

Only three methods reach you: `tools/list`, `tools/call`, `ping` (plus the handshake). Other
MCP methods are refused by the switchboard before they reach you.

### Limits the switchboard enforces (you are not told)

| Limit | Value | Effect |
|---|---|---|
| frame size from you | 16 MiB | larger frames close the socket |
| requests in flight toward you | `max_inflight`, default 8 | extra calls are rejected at the switchboard |
| per-call timeout | per tool, default 60 s, `screenshot` 10 s | caller gets an error; your late reply is dropped |
| liveness | WS ping every 20 s; closed after 60 s with no frame from you | any WS library answers pings for you |

A timed-out or disconnected call is **never retried** by the switchboard. Shell commands are
not idempotent; the caller decides.

## 4. Tools

Expose whatever tools you have through `tools/list`; the switchboard forwards the list,
filtered by each caller's allowlist. Two tools have a fixed shape because OpenAB Connect
calls them directly to show your screen. Match these and Connect works with no changes.

### `sys_info` (no arguments)

```json
{ "content": [{ "type": "text", "text": "<one-line summary>" }],
  "structuredContent": {
    "host": "muse-vm",
    "os": "Debian 13",
    "agent": { "name": "muse-sb-daemon", "version": "0.1.0", "platform": "linux" },
    "permissions": { "screen_recording": true, "accessibility": true },
    "displays": [ { "id": 0, "main": true, "points": { "width": 1280, "height": 800 } } ]
  },
  "isError": false }
```

`displays: []` tells Connect there is no screen to show (headless).

### `screenshot`

Arguments Connect sends: `display` (int, 0), `scale` (0.1–2.0), `quality` (0.1–1.0),
`format` (`"jpeg"`). `region {x,y,width,height}` is optional.

```json
{ "content": [
    { "type": "image", "data": "<base64 JPEG>", "mimeType": "image/jpeg" },
    { "type": "text", "text": "1280x800 jpeg 84213 bytes" } ],
  "structuredContent": {
    "points": { "width": 1280, "height": 800 },
    "image":  { "width": 640, "height": 400, "bytes": 84213 } },
  "isError": false }
```

`points` is the display size in the coordinate space `mouse` uses. Keep frames small:
Connect polls about every 0.5–5 s and gives up on a frame after 8 s.

### Recommended: `mouse`, `key`, `bash`

Same argument names as `oab-instance-mcp`, so agents that know one know the other:

- `mouse`: `action` ∈ `move|click|double_click|right_click|drag|scroll`, `x`, `y`,
  `to_x`, `to_y`, `dx`, `dy`, `display`, `modifiers` (`["ctrl"]`…). Coordinates are display
  points, top-left origin, same space as `screenshot.points`.
- `key`: `action` ∈ `type|press`; `text` for `type`; `keys` (`["ctrl+l","Return"]`) for
  `press`.
- `bash`: `command` (string), optional `timeout_secs`. Return stdout/stderr/exit code as
  text, `isError: true` on non-zero exit. This is an **unrestricted shell**: whoever the
  switchboard lets call it owns the VM.

### Errors

A tool that ran and failed → a normal result with `isError: true` and a text explanation.
A malformed request → JSON-RPC error (`-32602` invalid params, `-32601` unknown tool).
Never crash the socket for one bad call.

## 5. Reconnect

Deployments replace the VM; the daemon must come back on its own (start it from whatever
runs at boot — cron `@reboot`, systemd, a skill hook).

| Close code | Meaning | Do |
|---|---|---|
| `4002` | replaced: another daemon attached with the same secret | **stop**. Two dialers fighting is a bug; the newer one wins |
| `4003` | the operator revoked or rotated the secret | stop until the secret is updated |
| `1001` | switchboard shutting down / restarting | redial with backoff |
| `1000`, abnormal drop, timeout | network blip | redial with backoff |

Backoff: 1 s, doubling to a 60 s cap, ±20 % jitter; reset to 1 s after a connection that
stayed up for 60 s. On `401` see section 2.

`4002` is why exactly one daemon per secret must run. If the old VM might still be alive
when the new one boots, the new one wins and the old one stops — that converges. Two daemons
that both redial on `4002` would evict each other forever.

## 6. What the switchboard does not do

- It does not execute anything, store results, or queue calls across a restart. If the
  switchboard restarts, in-flight calls fail and callers retry.
- It does not inspect your tool output. Screenshots and shell output flow straight to the
  caller — and so does anything a web page on your screen managed to get into them. Treat
  every caller-supplied argument as untrusted, and expect callers to treat your output the
  same way.
- It does not promise end-to-end encryption: TLS ends at whatever fronts the switchboard.

## 7. Minimal daemon

`examples/muse-daemon/sb_daemon.py` is a reference implementation (Python, `websockets`)
with `sys_info`, `screenshot` (Xvfb via `import`/`scrot`), `mouse`/`key` (`xdotool`) and
`bash`. It implements sections 2–5 and is used by the switchboard's own tests as the
behaviour of record.
