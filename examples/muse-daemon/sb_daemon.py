#!/usr/bin/env python3
"""Reference daemon for docs/SOUTHBOUND-CONTRACT.md.

An MCP server that *dials* openab-sb over a WebSocket and serves tools on it:
sys_info, screenshot (X11 via ImageMagick `import`), mouse / key (`xdotool`), bash.

    pip install 'websockets>=12'
    SB_URL=wss://switchboard.example/vm/attach SB_SECRET_FILE=~/.sb-secret python3 sb_daemon.py

Environment:
    SB_URL          switchboard attach URL (required)
    SB_SECRET       the secret from `openab-sb gen-secret`, or
    SB_SECRET_FILE  a file holding it (preferred: keeps it out of `ps`)
    SB_TOOLS        comma list to expose (default: all available)
    DISPLAY         X display for screenshot/mouse/key (e.g. :99 under Xvfb)
"""

import asyncio
import base64
import json
import os
import platform
import random
import shutil
import signal
import socket
import sys
import time

import websockets

VERSION = "0.1.0"
PROTOCOL = "2025-06-18"
MAX_OUTPUT = 256 * 1024
STOP_CODES = {4002, 4003}  # replaced / revoked: another daemon or the operator decided
# 4005 (handshake failed) and everything else: redial with backoff.
UNAUTHORIZED_RETRY = 300   # seconds; a wrong secret needs a human, not a hammer


def log(*parts):
    print(time.strftime("%H:%M:%S"), *parts, file=sys.stderr, flush=True)


class ToolError(Exception):
    """A tool ran and failed: becomes `isError: true`, not a protocol error."""


async def run(*argv, stdin=None, timeout=30):
    # Own process group, so a timeout kills everything the command started
    # (`bash -lc 'sleep 999 &'` must not outlive it).
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout)
    except asyncio.TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.wait()
        raise ToolError(f"{argv[0]} timed out after {timeout}s")
    return proc.returncode, out, err


def text(t):
    return {"type": "text", "text": t}


# --------------------------------------------------------------------------- tools


async def display_points():
    if not shutil.which("xdotool") or not os.environ.get("DISPLAY"):
        return None
    code, out, _ = await run("xdotool", "getdisplaygeometry", timeout=5)
    if code != 0:
        return None
    w, h = (int(v) for v in out.split()[:2])
    return w, h


async def sys_info(_args):
    os_name = platform.platform()
    try:
        with open("/etc/os-release") as f:
            fields = dict(l.rstrip().split("=", 1) for l in f if "=" in l)
            os_name = fields.get("PRETTY_NAME", os_name).strip('"')
    except OSError:
        pass
    pts = await display_points()
    displays = [] if pts is None else [
        {"id": 0, "main": True, "points": {"width": pts[0], "height": pts[1]}}
    ]
    info = {
        "host": socket.gethostname(),
        "os": os_name,
        "agent": {"name": "sb-daemon", "version": VERSION, "platform": sys.platform},
        "permissions": {"screen_recording": pts is not None, "accessibility": pts is not None},
        "displays": displays,
    }
    summary = f"{info['host']} · {os_name} · {len(displays)} display(s)"
    return [text(summary)], info


async def screenshot(args):
    pts = await display_points()
    if pts is None or not shutil.which("import"):
        raise ToolError("no X display (set DISPLAY) or ImageMagick `import` missing")
    scale = min(max(float(args.get("scale", 1.0)), 0.1), 2.0)
    quality = min(max(float(args.get("quality", 0.7)), 0.1), 1.0)
    fmt = "png" if args.get("format") == "png" else "jpeg"
    argv = ["import", "-silent", "-window", "root"]
    region = args.get("region")
    src_w, src_h = pts
    if region:
        x, y, w, h = (int(region[k]) for k in ("x", "y", "width", "height"))
        if w <= 0 or h <= 0 or x < 0 or y < 0:
            raise ToolError("region must have x,y >= 0 and positive width/height")
        argv += ["-crop", f"{w}x{h}+{x}+{y}", "+repage"]
        src_w, src_h = min(w, pts[0] - x), min(h, pts[1] - y)
    argv += ["-resize", f"{scale * 100:.1f}%"]
    if fmt == "jpeg":
        argv += ["-quality", str(int(quality * 100))]
    argv.append(f"{fmt}:-")
    code, data, err = await run(*argv, timeout=10)
    if code != 0 or not data:
        raise ToolError(f"capture failed: {err.decode(errors='replace')[:300]}")
    content = [
        {"type": "image", "data": base64.b64encode(data).decode(), "mimeType": f"image/{fmt}"},
        text(f"{pts[0]}x{pts[1]} {fmt} {len(data)} bytes"),
    ]
    # ImageMagick's percentage resize rounds to the nearest pixel.
    image = {"width": max(1, round(src_w * scale)), "height": max(1, round(src_h * scale)),
             "bytes": len(data)}
    return content, {"points": {"width": pts[0], "height": pts[1]}, "image": image}


MODS = {"cmd": "super", "super": "super", "ctrl": "ctrl", "alt": "alt", "option": "alt", "shift": "shift"}
KEYS = {"return": "Return", "enter": "Return", "tab": "Tab", "space": "space", "escape": "Escape",
        "esc": "Escape", "delete": "BackSpace", "backspace": "BackSpace", "left": "Left",
        "right": "Right", "up": "Up", "down": "Down", "home": "Home", "end": "End",
        "pageup": "Prior", "pagedown": "Next"}


def xkey(combo):
    parts = combo.split("+")
    *mods, key = parts
    out = []
    for m in mods:
        if m.lower() not in MODS:
            raise ToolError(f"unknown modifier {m!r}")
        out.append(MODS[m.lower()])
    k = key.lower()
    out.append(KEYS.get(k, key.upper() if k.startswith("f") and k[1:].isdigit() else key))
    return "+".join(out)


async def xdotool(*argv):
    if not shutil.which("xdotool") or not os.environ.get("DISPLAY"):
        raise ToolError("xdotool missing or DISPLAY unset")
    code, _, err = await run("xdotool", *argv, timeout=30)
    if code != 0:
        raise ToolError(err.decode(errors="replace")[:300])


async def mouse(args):
    action = args.get("action")
    mods = [MODS.get(m.lower()) or "" for m in args.get("modifiers", [])]
    if "" in mods:
        raise ToolError("unknown modifier")

    def at(xk="x", yk="y"):
        if xk not in args or yk not in args:
            raise ToolError(f"{xk} and {yk} are required for {action}")
        return ["mousemove", str(int(args[xk])), str(int(args[yk]))]

    if action == "move":
        steps = at()
    elif action in ("click", "double_click", "right_click"):
        button = "3" if action == "right_click" else "1"
        repeat = ["--repeat", "2"] if action == "double_click" else []
        steps = at() + ["click", *repeat, button]
    elif action == "drag":
        steps = at() + ["mousedown", "1"] + at("to_x", "to_y") + ["mouseup", "1"]
    elif action == "scroll":
        steps = at() if "x" in args else []
        dy, dx = int(args.get("dy", 0)), int(args.get("dx", 0))
        if dy:
            steps += ["click", "--repeat", str(abs(dy)), "4" if dy > 0 else "5"]
        if dx:
            steps += ["click", "--repeat", str(abs(dx)), "7" if dx > 0 else "6"]
    else:
        raise ToolError(f"unknown action {action!r}")
    if mods:
        steps = ["keydown", "+".join(mods)] + steps + ["keyup", "+".join(mods)]
    await xdotool(*steps)
    return [text(f"{action} done")], None


async def key(args):
    action = args.get("action")
    if action == "type":
        t = args.get("text") or ""
        if not t or len(t) > 20000:
            raise ToolError("text is required (max 20000 chars)")
        await xdotool("type", "--delay", str(int(args.get("delay_ms", 10))), "--", t)
        return [text(f"typed {len(t)} chars")], None
    if action == "press":
        keys = [xkey(k) for k in args.get("keys") or []]
        if not keys:
            raise ToolError("keys is required")
        # `--` so a "key" like `--window` is a keysym, never an xdotool option.
        await xdotool("key", "--delay", str(int(args.get("delay_ms", 50))), "--", *keys)
        return [text("pressed " + " ".join(keys))], None
    raise ToolError(f"unknown action {action!r}")


async def bash(args):
    command = args.get("command")
    if not isinstance(command, str) or not command:
        raise ToolError("command is required")
    timeout = min(max(int(args.get("timeout_secs", 60)), 1), 600)
    code, out, err = await run("bash", "-lc", command, timeout=timeout)

    def clip(b):
        s = b.decode(errors="replace")
        return s if len(s) <= MAX_OUTPUT else s[:MAX_OUTPUT] + "\n…[truncated]"

    body = f"exit {code}\n--- stdout\n{clip(out)}\n--- stderr\n{clip(err)}"
    result = {"exit_code": code}
    if code != 0:
        raise ToolError(body)
    return [text(body)], result


OBJ = {"type": "object"}
TOOLS = {
    "sys_info": (sys_info, "Host, OS, and displays of this VM.", {**OBJ, "properties": {}}),
    "screenshot": (screenshot, "Capture the X display as an image. `scale` 0.1–2, `quality` 0.1–1, `format` jpeg|png, optional `region` {x,y,width,height} in points.",
                   {**OBJ, "properties": {"display": {"type": "integer"}, "scale": {"type": "number"},
                    "quality": {"type": "number"}, "format": {"type": "string", "enum": ["jpeg", "png"]},
                    "region": OBJ}}),
    "mouse": (mouse, "Mouse input in display points: move, click, double_click, right_click, drag (to_x,to_y), scroll (dx,dy lines).",
              {**OBJ, "properties": {"action": {"type": "string", "enum": ["move", "click", "double_click", "right_click", "drag", "scroll"]},
               "x": {"type": "number"}, "y": {"type": "number"}, "to_x": {"type": "number"}, "to_y": {"type": "number"},
               "dx": {"type": "integer"}, "dy": {"type": "integer"}, "modifiers": {"type": "array", "items": {"type": "string"}}},
               "required": ["action"]}),
    "key": (key, "Keyboard: `type` text, or `press` combos like [\"ctrl+l\", \"return\"].",
            {**OBJ, "properties": {"action": {"type": "string", "enum": ["type", "press"]}, "text": {"type": "string"},
             "keys": {"type": "array", "items": {"type": "string"}}, "delay_ms": {"type": "integer"}}, "required": ["action"]}),
    "bash": (bash, "Run a command with bash -lc. Unrestricted shell on this VM.",
             {**OBJ, "properties": {"command": {"type": "string"}, "timeout_secs": {"type": "integer"}}, "required": ["command"]}),
}
ENABLED = [t.strip() for t in os.environ.get("SB_TOOLS", ",".join(TOOLS)).split(",") if t.strip() in TOOLS]


# --------------------------------------------------------------------------- MCP


async def answer(msg):
    """One JSON-RPC request → its response (or None for notifications)."""
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        return None
    if method == "initialize":
        result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "sb-daemon", "version": VERSION}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [{"name": n, "description": TOOLS[n][1], "inputSchema": TOOLS[n][2]} for n in ENABLED]}
    elif method == "tools/call":
        params = msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in ENABLED:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown tool {name!r}"}}
        try:
            content, structured = await TOOLS[name][0](args)
            result = {"content": content, "isError": False}
            if structured is not None:
                result["structuredContent"] = structured
        except ToolError as e:
            result = {"content": [text(str(e))], "isError": True}
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"invalid params: {e}"}}
        except Exception as e:  # noqa: BLE001 — answer, never leave the caller to time out
            log("tool", name, "crashed:", type(e).__name__, e)
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": f"internal error in {name}"}}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method {method!r} not found"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


async def session(ws):
    tasks = set()

    async def handle(msg):
        reply = await answer(msg)
        if reply is not None:
            await ws.send(json.dumps(reply))

    async for raw in ws:
        try:
            msg = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
            continue  # responses to requests we never send
        if msg["method"] == "initialize":
            await handle(msg)  # answer the handshake before anything else
            continue
        task = asyncio.create_task(handle(msg))  # requests run concurrently
        tasks.add(task)
        task.add_done_callback(tasks.discard)


def secret():
    if os.environ.get("SB_SECRET_FILE"):
        with open(os.path.expanduser(os.environ["SB_SECRET_FILE"])) as f:
            return f.read().strip()
    return os.environ["SB_SECRET"].strip()


def status_of(exc):
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None) or getattr(exc, "status_code", None)


async def connect(url, headers):
    kwargs = dict(max_size=16 * 1024 * 1024, ping_interval=20, ping_timeout=60)
    try:
        return await websockets.connect(url, additional_headers=headers, **kwargs)
    except TypeError:  # websockets < 14
        return await websockets.connect(url, extra_headers=headers, **kwargs)


async def main():
    url = os.environ["SB_URL"]
    backoff = 1.0
    while True:
        started = time.monotonic()
        code = None
        try:
            ws = await connect(url, {"Authorization": f"Bearer {secret()}"})
            log("attached", url, "tools:", ",".join(ENABLED))
            try:
                await session(ws)
            except websockets.ConnectionClosed:
                pass
            code = ws.close_code
        except Exception as e:  # noqa: BLE001 — every failure means "redial later"
            if status_of(e) == 401:
                log("401: wrong secret; retrying in", UNAUTHORIZED_RETRY, "s")
                await asyncio.sleep(UNAUTHORIZED_RETRY)
                continue
            log("dial failed:", type(e).__name__, e)
        if code in STOP_CODES:
            log("closed with", code, "— stopping (replaced or revoked)")
            return
        if time.monotonic() - started >= 60:
            backoff = 1.0
        wait = backoff * random.uniform(0.8, 1.2)
        log("detached, code", code, f"— redial in {wait:.1f}s")
        await asyncio.sleep(wait)
        backoff = min(backoff * 2, 60.0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
