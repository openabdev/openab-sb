//! End to end: a real switchboard on a loopback port, fake computers dialling in
//! over real WebSockets, northbound calls over real HTTP, and a fake openab-pty
//! pod the switchboard dials.
//!
//! Two config shapes are exercised: `config_text` is v1 (`[vm]` plus clients
//! with `tools`), which must keep behaving as it did, and `multi_config` is v2
//! with two computers.
// tungstenite's handshake callback signature is fixed; its error type is large.
#![allow(clippy::result_large_err)]

use futures_util::{SinkExt, StreamExt};
use openab_sb::audit::Audit;
use openab_sb::auth::Verifier;
use openab_sb::config::Config;
use openab_sb::App;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

const VM_SECRET: &str = "vm-secret-0123456789";
const CONNECT_TOKEN: &str = "connect-token-0123456789";
const PTY_TOKEN: &str = "pty-token-0123456789";

// v2 fixtures: two computers and three callers with different reach.
const M1_SECRET: &str = "m1-secret-0123456789";
const M2_SECRET: &str = "m2-secret-0123456789";
/// `computers = { "*" = ["*"] }`, default `m1`.
const OWNER_TOKEN: &str = "owner-token-0123456789";
/// `computers = { m1 = [...] }`.
const NARROW_TOKEN: &str = "narrow-token-0123456789";
/// A second narrow caller on `m1`, added by tests that need two of them.
const NARROW2_TOKEN: &str = "narrow2-token-0123456789";
/// `computers = { m2 = ["*"] }`, so its default is `m2`.
const M2_ONLY_TOKEN: &str = "m2only-token-0123456789";

fn verifier(secret: &str) -> String {
    Verifier::of_secret(secret).render()
}

/// A v1 config: one `[vm]`, clients with `tools`.
///
/// The `pty` client carries `max_inflight = 64` so that the computer-wide cap,
/// not v2's per-caller share of it, is what these tests measure. Without it the
/// default share (half the socket's `max_inflight`, rounded up) would fire
/// first.
fn config_text(extra_top: &str, extra_tail: &str) -> String {
    format!(
        r#"{extra_top}
[vm]
secret_sha256 = "{vm}"

[timeouts.tools]
slow = 1
hang = 2

[[client]]
name = "connect"
token_sha256 = "{connect}"
tools = ["sys_info", "screenshot"]

[[client]]
name = "pty"
token_sha256 = "{pty}"
tools = ["*"]
max_inflight = 64
{extra_tail}
"#,
        vm = verifier(VM_SECRET),
        connect = verifier(CONNECT_TOKEN),
        pty = verifier(PTY_TOKEN),
    )
}

/// A v2 config: computers `m1` and `m2`, callers `owner` (every computer),
/// `narrow` (only `m1`) and `m2only` (only `m2`, so that is its default).
fn multi_config(extra_top: &str, extra_tail: &str) -> String {
    format!(
        r#"{extra_top}
[[computer]]
name = "m1"
secret_sha256 = "{m1}"

[[computer]]
name = "m2"
secret_sha256 = "{m2}"

[timeouts.tools]
slow = 1
hang = 2

[[client]]
name = "owner"
token_sha256 = "{owner}"
default_computer = "m1"
computers = {{ "*" = ["*"] }}
max_inflight = 64

[[client]]
name = "narrow"
token_sha256 = "{narrow}"
default_computer = "m1"
computers = {{ m1 = ["sys_info", "screenshot", "slow", "hang"] }}

[[client]]
name = "m2only"
token_sha256 = "{m2only}"
computers = {{ m2 = ["*"] }}
{extra_tail}
"#,
        m1 = verifier(M1_SECRET),
        m2 = verifier(M2_SECRET),
        owner = verifier(OWNER_TOKEN),
        narrow = verifier(NARROW_TOKEN),
        m2only = verifier(M2_ONLY_TOKEN),
    )
}

/// `multi_config` with `m2` and the callers that name it taken out: the shape a
/// reload must have before a computer can be removed.
fn only_m1_config() -> String {
    format!(
        r#"
[[computer]]
name = "m1"
secret_sha256 = "{m1}"

[timeouts.tools]
slow = 1
hang = 2

[[client]]
name = "owner"
token_sha256 = "{owner}"
default_computer = "m1"
computers = {{ "*" = ["*"] }}
max_inflight = 64

[[client]]
name = "narrow"
token_sha256 = "{narrow}"
default_computer = "m1"
computers = {{ m1 = ["sys_info", "screenshot", "slow", "hang"] }}
"#,
        m1 = verifier(M1_SECRET),
        owner = verifier(OWNER_TOKEN),
        narrow = verifier(NARROW_TOKEN),
    )
}

/// An extra narrow caller on `m1`, for the per-caller cap tests.
fn second_narrow_client() -> String {
    format!(
        "[[client]]\nname = \"narrow2\"\ntoken_sha256 = \"{}\"\ncomputers = {{ m1 = [\"sys_info\", \"hang\"] }}\n",
        verifier(NARROW2_TOKEN)
    )
}

/// Give computer `m1` its own in-flight limit.
fn with_m1_limit(text: &str, limit: usize) -> String {
    let patched = text.replace(
        "name = \"m1\"\n",
        &format!("name = \"m1\"\nmax_inflight = {limit}\n"),
    );
    assert_ne!(patched, text, "the m1 block moved");
    patched
}

/// Give the `narrow` client its own per-caller in-flight cap.
fn with_narrow_cap(text: &str, cap: usize) -> String {
    let line = "computers = { m1 = [\"sys_info\", \"screenshot\", \"slow\", \"hang\"] }\n";
    let patched = text.replace(line, &format!("{line}max_inflight = {cap}\n"));
    assert_ne!(patched, text, "the narrow client's computers line moved");
    patched
}

struct Sb {
    addr: SocketAddr,
    app: App,
    http: reqwest::Client,
}

async fn start_with(text: &str) -> Sb {
    let config = Config::parse(text).expect("test config");
    let app = App::new(&config, Audit::null());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app.router();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    app.spawn_pty_attachers(config.pty_attach.clone());
    Sb {
        addr,
        app,
        http: reqwest::Client::new(),
    }
}

async fn start() -> Sb {
    start_with(&config_text("", "")).await
}

impl Sb {
    /// SIGHUP: credentials, the computer table and the policy of every running
    /// `[[pty_attach]]`, from the config the operator just wrote.
    fn reload(&self, text: &str) {
        let fresh = Config::parse(text).expect("reload config");
        self.app.reload_auth(fresh.auth, &fresh.pty_attach);
    }

    async fn rpc_at(&self, path: &str, token: &str, body: Value) -> (u16, Value) {
        let response = self
            .http
            .post(format!("http://{}{path}", self.addr))
            .bearer_auth(token)
            .header("accept", "application/json")
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn rpc(&self, token: &str, body: Value) -> (u16, Value) {
        self.rpc_at("/mcp", token, body).await
    }

    async fn call_at(&self, path: &str, token: &str, id: Value, tool: &str, args: Value) -> Value {
        let (status, body) = self
            .rpc_at(
                path,
                token,
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    async fn call(&self, token: &str, id: Value, tool: &str, args: Value) -> Value {
        self.call_at("/mcp", token, id, tool, args).await
    }

    async fn tool_names_at(&self, path: &str, token: &str) -> Vec<String> {
        let (_, body) = self
            .rpc_at(
                path,
                token,
                json!({"jsonrpc":"2.0","id":7,"method":"tools/list"}),
            )
            .await;
        let mut names: Vec<String> = body["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("no tools in {body}"))
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    async fn tool_names(&self, token: &str) -> Vec<String> {
        self.tool_names_at("/mcp", token).await
    }

    /// Status and body of a GET, with no credentials.
    async fn get_body(&self, path: &str) -> (u16, String) {
        let response = self
            .http
            .get(format!("http://{}{path}", self.addr))
            .send()
            .await
            .unwrap();
        (
            response.status().as_u16(),
            response.text().await.unwrap_or_default(),
        )
    }

    /// Status and body of a GET with a bearer token.
    async fn get_body_as(&self, path: &str, token: &str) -> (u16, String) {
        let response = self
            .http
            .get(format!("http://{}{path}", self.addr))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        (
            response.status().as_u16(),
            response.text().await.unwrap_or_default(),
        )
    }

    async fn get(&self, path: &str) -> u16 {
        self.get_body(path).await.0
    }

    async fn readyz(&self) -> u16 {
        self.get("/readyz").await
    }

    async fn status_as(&self, token: &str) -> Value {
        let (status, body) = self.get_body_as("/status", token).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    async fn status(&self) -> Value {
        self.status_as(CONNECT_TOKEN).await
    }

    async fn computers_as(&self, token: &str) -> Vec<Value> {
        let (status, body) = self.get_body_as("/computers", token).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    /// One computer's entry in `/status`, as this caller sees it.
    async fn entry(&self, token: &str, computer: &str) -> Value {
        self.status_as(token).await["computers"]
            .as_array()
            .expect("computers array")
            .iter()
            .find(|e| e["computer"] == json!(computer))
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// Wait until `computer` is attached, initialised and reporting `server`.
    async fn wait_for(&self, token: &str, computer: &str, server: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let entry = self.entry(token, computer).await;
            if entry["ready"] == json!(true) && entry["server"]["name"] == json!(server) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "computer {computer} never became ready as {server}: {entry}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// v1 shape: the one computer is `default`.
    async fn wait_for_vm(&self, name: &str) {
        self.wait_for(CONNECT_TOKEN, "default", name).await;
    }

    async fn wait_for_health(&self, want: u16) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.readyz().await != want {
            assert!(Instant::now() < deadline, "readyz never became {want}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_in_flight(&self, token: &str, computer: &str, want: u64) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let entry = self.entry(token, computer).await;
            if entry["in_flight"] == json!(want) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{computer} never reached {want} in flight: {entry}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Fake computer: an MCP server over a WebSocket it dials.
// ---------------------------------------------------------------------------

struct FakeVm {
    /// tools/call requests that reached the computer.
    calls: Arc<AtomicUsize>,
    /// Close code received from the switchboard (1006 = dropped without one).
    closed: watch::Receiver<Option<u16>>,
}

impl FakeVm {
    async fn close_code(&mut self) -> u16 {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.closed.wait_for(Option::is_some),
        )
        .await
        .expect("VM socket never closed")
        .unwrap()
        .unwrap()
    }

    fn is_closed(&self) -> bool {
        self.closed.borrow().is_some()
    }
}

async fn fake_vm(addr: SocketAddr, secret: &str, name: &str) -> Result<FakeVm, u16> {
    let mut request = format!("ws://{addr}/vm/attach")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
    );
    let socket = match tokio_tungstenite::connect_async(request).await {
        Ok((socket, _)) => socket,
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            return Err(response.status().as_u16())
        }
        Err(error) => panic!("dial failed: {error}"),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let (closed_tx, closed) = watch::channel(None);
    let (mut sink, mut stream) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });
    let name = name.to_owned();
    let counter = calls.clone();
    tokio::spawn(async move {
        let code = loop {
            let Some(Ok(frame)) = stream.next().await else {
                break 1006;
            };
            let request: Value = match frame {
                Message::Text(text) => serde_json::from_str(&text).unwrap(),
                Message::Close(frame) => break frame.map(|f| u16::from(f.code)).unwrap_or(1005),
                _ => continue,
            };
            let Some(id) = request.get("id").cloned() else {
                continue;
            };
            let method = request["method"].as_str().unwrap_or_default().to_owned();
            let tool = request["params"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if method == "tools/call" {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            if tool == "die" {
                // Vanish mid-call, no close frame.
                writer.abort();
                break 1006;
            }
            let out = out_tx.clone();
            let name = name.clone();
            tokio::spawn(async move {
                let result = match method.as_str() {
                    "initialize" => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": name, "version": "0"}
                    }),
                    "tools/list" => {
                        let tools: Vec<Value> = [
                            "sys_info",
                            "screenshot",
                            "bash",
                            "slow",
                            "hang",
                            "vm_status",
                        ]
                        .iter()
                        .map(|n| json!({"name": n, "inputSchema": {"type": "object"}}))
                        .collect();
                        json!({ "tools": tools })
                    }
                    "tools/call" => {
                        let args = request["params"]["arguments"].clone();
                        match tool.as_str() {
                            "hang" => return,
                            "slow" => {
                                let ms = args["ms"].as_u64().unwrap_or(0);
                                tokio::time::sleep(Duration::from_millis(ms)).await;
                            }
                            _ => {}
                        }
                        json!({
                            "content": [{"type": "text", "text": "ok"}],
                            "structuredContent": {"vm": name, "tool": tool, "args": args},
                            "isError": false
                        })
                    }
                    _ => return,
                };
                let reply = json!({"jsonrpc": "2.0", "id": id, "result": result});
                let _ = out.send(Message::Text(reply.to_string().into())).await;
            });
        };
        let _ = closed_tx.send(Some(code));
    });
    Ok(FakeVm { calls, closed })
}

// ---------------------------------------------------------------------------
// v1 behaviour, unchanged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offline_surface_is_honest_and_closed() {
    let sb = start().await;
    assert_eq!(sb.readyz().await, 503);
    // Liveness does not depend on the computer: Connect probes it before
    // sys_info, so "VM offline" must reach Connect as a tool error, not
    // "unreachable".
    assert_eq!(sb.get("/healthz").await, 200);
    let info = sb
        .call(CONNECT_TOKEN, json!(0), "sys_info", json!({}))
        .await;
    assert_eq!(info["result"]["isError"], true);
    assert!(info["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("not connected"));

    // No token / wrong token.
    let response = sb
        .http
        .post(format!("http://{}/mcp", sb.addr))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    assert!(response.headers().get("www-authenticate").is_some());
    let (status, _) = sb
        .rpc(VM_SECRET, json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .await;
    assert_eq!(
        status, 401,
        "the computer secret must not open the northbound side"
    );

    let (status, init) = sb
        .rpc(
            CONNECT_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(init["result"]["serverInfo"]["name"], "openab-sb");
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");

    assert_eq!(sb.tool_names(CONNECT_TOKEN).await, vec!["vm_status"]);
    let shot = sb
        .call(CONNECT_TOKEN, json!(2), "screenshot", json!({}))
        .await;
    assert_eq!(shot["result"]["isError"], true);
    let status_tool = sb
        .call(CONNECT_TOKEN, json!(3), "vm_status", json!({}))
        .await;
    assert_eq!(
        status_tool["result"]["structuredContent"]["attached"],
        false
    );

    // Notifications get 202; other methods are refused, not forwarded.
    let response = sb
        .http
        .post(format!("http://{}/mcp", sb.addr))
        .bearer_auth(CONNECT_TOKEN)
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 202);
    // A JSON-RPC response from the client is accepted the same way.
    let response = sb
        .http
        .post(format!("http://{}/mcp", sb.addr))
        .bearer_auth(CONNECT_TOKEN)
        .json(&json!({"jsonrpc":"2.0","id":99,"result":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 202);
    let (_, other) = sb
        .rpc(
            CONNECT_TOKEN,
            json!({"jsonrpc":"2.0","id":4,"method":"resources/list"}),
        )
        .await;
    assert_eq!(other["error"]["code"], -32601);
    let (status, _) = sb
        .rpc(
            CONNECT_TOKEN,
            json!([{"jsonrpc":"2.0","id":5,"method":"ping"}]),
        )
        .await;
    assert_eq!(status, 400, "batches are refused");

    let get = sb
        .http
        .get(format!("http://{}/mcp", sb.addr))
        .bearer_auth(CONNECT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status().as_u16(), 405);
}

#[tokio::test]
async fn vm_needs_its_own_secret() {
    let sb = start().await;
    assert_eq!(fake_vm(sb.addr, "wrong", "x").await.err(), Some(401));
    assert_eq!(fake_vm(sb.addr, CONNECT_TOKEN, "x").await.err(), Some(401));
    assert_eq!(sb.readyz().await, 503);
}

#[tokio::test]
async fn allowlist_filters_listing_and_blocks_calls_before_the_vm() {
    let sb = start().await;
    let vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;
    assert_eq!(sb.readyz().await, 200);

    // Connect sees only its allowlist; the computer's own `vm_status` is
    // replaced by ours.
    assert_eq!(
        sb.tool_names(CONNECT_TOKEN).await,
        vec!["screenshot", "sys_info", "vm_status"]
    );
    assert_eq!(
        sb.tool_names(PTY_TOKEN).await,
        vec![
            "bash",
            "hang",
            "screenshot",
            "slow",
            "sys_info",
            "vm_status"
        ]
    );

    let denied = sb
        .call(CONNECT_TOKEN, json!(1), "bash", json!({"command": "id"}))
        .await;
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(
        vm.calls.load(Ordering::SeqCst),
        0,
        "a denied call must not reach the computer"
    );

    let allowed = sb
        .call(PTY_TOKEN, json!("abc"), "bash", json!({"command": "id"}))
        .await;
    assert_eq!(allowed["id"], "abc", "caller id restored");
    assert_eq!(
        allowed["result"]["structuredContent"]["args"]["command"],
        "id"
    );

    let shot = sb
        .call(CONNECT_TOKEN, json!(9), "screenshot", json!({"scale": 0.5}))
        .await;
    assert_eq!(shot["result"]["structuredContent"]["tool"], "screenshot");
    assert_eq!(vm.calls.load(Ordering::SeqCst), 2);

    let status = sb
        .call(CONNECT_TOKEN, json!(10), "vm_status", json!({}))
        .await;
    let s = &status["result"]["structuredContent"];
    assert_eq!(s["attached"], true);
    assert_eq!(s["server"]["name"], "fake-vm");
    assert_eq!(s["computer"], "default");
}

#[tokio::test]
async fn concurrent_callers_with_the_same_id_never_cross() {
    let sb = Arc::new(start().await);
    let _vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;

    let mut tasks = Vec::new();
    for n in 0..8u64 {
        let sb = sb.clone();
        tasks.push(tokio::spawn(async move {
            // Everyone uses id 1; later ones answer first.
            let ms = 400 - n * 40;
            let body = sb
                .call(PTY_TOKEN, json!(1), "slow", json!({"ms": ms, "n": n}))
                .await;
            assert_eq!(body["id"], 1);
            assert_eq!(body["result"]["structuredContent"]["args"]["n"], n);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn per_tool_timeout_and_inflight_cap_are_explicit_errors() {
    let sb = start_with(&config_text("max_inflight = 2", "")).await;
    let vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;

    // `slow` has a 1 s budget.
    let started = Instant::now();
    let late = sb
        .call(PTY_TOKEN, json!(1), "slow", json!({"ms": 3000}))
        .await;
    assert_eq!(late["error"]["code"], -32003);
    assert!(started.elapsed() < Duration::from_millis(2500));

    // Two hanging calls fill the cap; the third is refused at once.
    let sb = Arc::new(sb);
    let a = tokio::spawn({
        let sb = sb.clone();
        async move { sb.call(PTY_TOKEN, json!(1), "hang", json!({})).await }
    });
    let b = tokio::spawn({
        let sb = sb.clone();
        async move { sb.call(PTY_TOKEN, json!(2), "hang", json!({})).await }
    });
    // Both hangs have reached the computer, so both are pending. `in_flight`
    // would say so too, but this caller holds a named grant and no longer sees
    // it (ADR Compatibility), and the computer's own count is the same fact.
    let deadline = Instant::now() + Duration::from_secs(2);
    while vm.calls.load(Ordering::SeqCst) < 3 {
        assert!(Instant::now() < deadline, "calls never went in flight");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let third = sb.call(PTY_TOKEN, json!(3), "sys_info", json!({})).await;
    assert_eq!(third["error"]["code"], -32002);
    assert_eq!(a.await.unwrap()["error"]["code"], -32003);
    assert_eq!(b.await.unwrap()["error"]["code"], -32003);
}

#[tokio::test]
async fn takeover_closes_the_old_vm_without_hurting_the_new_one() {
    let sb = Arc::new(start().await);
    let mut old = fake_vm(sb.addr, VM_SECRET, "vm-old").await.unwrap();
    sb.wait_for_vm("vm-old").await;

    // A call in flight on the old socket when the new computer arrives.
    let pending = tokio::spawn({
        let sb = sb.clone();
        async move { sb.call(PTY_TOKEN, json!(1), "hang", json!({})).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let new = fake_vm(sb.addr, VM_SECRET, "vm-new").await.unwrap();
    assert_eq!(old.close_code().await, 4002);
    let failed = pending.await.unwrap();
    assert_eq!(failed["error"]["code"], -32004, "{failed}");

    sb.wait_for_vm("vm-new").await;
    // The old socket's cleanup must not have emptied the slot.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(sb.readyz().await, 200);
    let routed = sb.call(PTY_TOKEN, json!(2), "sys_info", json!({})).await;
    assert_eq!(routed["result"]["structuredContent"]["vm"], "vm-new");
    assert_eq!(new.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn vm_vanishing_mid_call_fails_the_call_and_health() {
    let sb = start().await;
    let _vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;
    let gone = sb.call(PTY_TOKEN, json!(1), "die", json!({})).await;
    assert_eq!(gone["error"]["code"], -32004, "{gone}");
    sb.wait_for_health(503).await;
    let after = sb
        .call(CONNECT_TOKEN, json!(2), "screenshot", json!({}))
        .await;
    assert_eq!(after["result"]["isError"], true);
}

#[tokio::test]
async fn rotating_the_vm_secret_on_reload_evicts_the_attached_vm() {
    let sb = start().await;
    let mut vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;

    // Same secret: nothing happens.
    sb.reload(&config_text("", ""));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sb.readyz().await, 200);

    let rotated = config_text("", "").replace(&verifier(VM_SECRET), &verifier("next-secret"));
    sb.reload(&rotated);
    assert_eq!(vm.close_code().await, 4003);
    assert_eq!(fake_vm(sb.addr, VM_SECRET, "x").await.err(), Some(401));
    let _next = fake_vm(sb.addr, "next-secret", "vm-next").await.unwrap();
    sb.wait_for_vm("vm-next").await;
}

#[tokio::test]
async fn a_pure_v1_config_keeps_its_surface() {
    // No v2 key anywhere: this is what a 0.1.0 file looks like.
    let text = format!(
        "[vm]\nsecret_sha256 = \"{}\"\n\n[[client]]\nname = \"connect\"\ntoken_sha256 = \"{}\"\ntools = [\"sys_info\"]\n",
        verifier(VM_SECRET),
        verifier(CONNECT_TOKEN),
    );
    let sb = start_with(&text).await;
    assert_eq!(sb.get_body("/readyz").await, (503, "vm offline".to_owned()));
    let _vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;
    assert_eq!(sb.get_body("/readyz").await, (200, "ok".to_owned()));

    // v1's `/status` shape.
    let status = sb.status().await;
    assert_eq!(status["vm"]["ready"], true);
    assert_eq!(status["vm"]["server"]["name"], "fake-vm");
    assert!(status["vm"]["attached_for_secs"].is_u64());
    assert!(status["vm"]["max_in_flight"].is_u64());
    // The one documented exception to "nothing a v1 caller sees changes": this
    // client's `tools = ["sys_info"]` is a named grant on `default`, not
    // `computers = { "*" = … }`, so `peer` and `in_flight` are no longer in
    // there. See the ADR's Compatibility section.
    assert!(status["vm"].get("peer").is_none(), "{status}");
    assert!(status["vm"].get("in_flight").is_none(), "{status}");

    // Bare /mcp is the one computer, and so is /mcp/default.
    let bare = sb
        .call(CONNECT_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(bare["result"]["structuredContent"]["vm"], "fake-vm");
    let named = sb
        .call_at(
            "/mcp/default",
            CONNECT_TOKEN,
            json!(2),
            "sys_info",
            json!({}),
        )
        .await;
    assert_eq!(named["result"]["structuredContent"]["vm"], "fake-vm");

    let listed = sb.computers_as(CONNECT_TOKEN).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["name"], "default");
    assert_eq!(listed[0]["default"], true);
    assert_eq!(listed[0]["ready"], true);
}

// ---------------------------------------------------------------------------
// v2: the hub as a map of slots
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_computers_stay_attached_together() {
    let sb = start_with(&multi_config("", "")).await;
    let m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;
    assert!(!m1.is_closed() && !m2.is_closed(), "neither evicted");

    let a = sb
        .call_at("/mcp/m1", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(a["result"]["structuredContent"]["vm"], "vm-m1");
    let b = sb
        .call_at("/mcp/m2", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(b["result"]["structuredContent"]["vm"], "vm-m2");
    assert_eq!(m1.calls.load(Ordering::SeqCst), 1);
    assert_eq!(m2.calls.load(Ordering::SeqCst), 1);

    // Each caller's bare /mcp is its own default.
    let owner_default = sb.call(OWNER_TOKEN, json!(2), "sys_info", json!({})).await;
    assert_eq!(owner_default["result"]["structuredContent"]["vm"], "vm-m1");
    let m2_default = sb
        .call(M2_ONLY_TOKEN, json!(2), "sys_info", json!({}))
        .await;
    assert_eq!(m2_default["result"]["structuredContent"]["vm"], "vm-m2");

    // `vm_status` names the computer it was asked about.
    let status = sb
        .call_at("/mcp/m2", OWNER_TOKEN, json!(3), "vm_status", json!({}))
        .await;
    assert_eq!(status["result"]["structuredContent"]["computer"], "m2");
}

#[tokio::test]
async fn evicting_one_computer_leaves_the_other_attached() {
    let sb = start_with(&multi_config("", "")).await;
    let mut m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    // A second socket with m1's secret takes only m1's slot.
    let m1b = fake_vm(sb.addr, M1_SECRET, "vm-m1b").await.unwrap();
    assert_eq!(m1.close_code().await, 4002);
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1b").await;
    assert!(!m2.is_closed(), "m2 was not touched");

    let routed = sb
        .call_at("/mcp/m2", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(routed["result"]["structuredContent"]["vm"], "vm-m2");
    assert_eq!(m1b.calls.load(Ordering::SeqCst), 0);
    assert_eq!(m2.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rotating_one_computers_secret_leaves_the_other_attached() {
    let sb = start_with(&multi_config("", "")).await;
    let m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let mut m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    let rotated = multi_config("", "").replace(&verifier(M2_SECRET), &verifier("m2-next"));
    sb.reload(&rotated);
    assert_eq!(m2.close_code().await, 4003);
    assert!(!m1.is_closed(), "m1 keeps its socket");

    let still = sb
        .call_at("/mcp/m1", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(still["result"]["structuredContent"]["vm"], "vm-m1");
    assert_eq!(fake_vm(sb.addr, M2_SECRET, "x").await.err(), Some(401));
    let _next = fake_vm(sb.addr, "m2-next", "vm-m2-next").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2-next").await;
}

#[tokio::test]
async fn removing_one_computer_leaves_the_other_attached() {
    let sb = start_with(&multi_config("", "")).await;
    let m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let mut m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    // Removing a computer only loads once nothing names it any more.
    let still_named = multi_config("", "").replace(
        &format!(
            "[[computer]]\nname = \"m2\"\nsecret_sha256 = \"{}\"\n",
            verifier(M2_SECRET)
        ),
        "",
    );
    assert!(
        Config::parse(&still_named).is_err(),
        "a block still names m2"
    );
    sb.reload(&only_m1_config());
    assert_eq!(m2.close_code().await, 4003);
    assert!(!m1.is_closed());
    let still = sb
        .call_at("/mcp/m1", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(still["result"]["structuredContent"]["vm"], "vm-m1");
    // m2 is gone for everyone, including the `"*"` caller.
    let (status, _) = sb
        .rpc_at(
            "/mcp/m2",
            OWNER_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        )
        .await;
    assert_eq!(status, 404);
    assert_eq!(sb.computers_as(OWNER_TOKEN).await.len(), 1);
}

#[tokio::test]
async fn a_same_verifier_rename_keeps_the_socket() {
    let sb = start_with(&multi_config("", "")).await;
    let m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    let before = sb.entry(OWNER_TOKEN, "m1").await;

    // `m1` → `macmini` everywhere it is named, verifier untouched.
    let renamed = multi_config("", "").replace("m1", "macmini");
    sb.reload(&renamed);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!m1.is_closed(), "a relabel must not close the socket");

    let after = sb.entry(OWNER_TOKEN, "macmini").await;
    assert_eq!(after["ready"], true);
    assert_eq!(after["server"]["name"], "vm-m1");
    assert_eq!(
        after["max_in_flight"], before["max_in_flight"],
        "same socket"
    );
    let routed = sb
        .call_at("/mcp/macmini", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(routed["result"]["structuredContent"]["vm"], "vm-m1");
    assert_eq!(m1.calls.load(Ordering::SeqCst), 1, "the same socket served");
    let (status, _) = sb
        .rpc_at(
            "/mcp/m1",
            OWNER_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        )
        .await;
    assert_eq!(status, 404, "the old name is gone");
}

#[tokio::test]
async fn swapping_two_verifiers_between_names_evicts_nothing() {
    let sb = start_with(&multi_config("", "")).await;
    let m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    let (h1, h2) = (verifier(M1_SECRET), verifier(M2_SECRET));
    let swapped = multi_config("", "")
        .replace(&h1, "SWAP")
        .replace(&h2, &h1)
        .replace("SWAP", &h2);
    sb.reload(&swapped);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!m1.is_closed() && !m2.is_closed(), "a swap is two relabels");

    // The sockets kept their secrets, so they changed names.
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m2").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m1").await;
    let routed = sb
        .call_at("/mcp/m1", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(routed["result"]["structuredContent"]["vm"], "vm-m2");
    assert_eq!(m2.calls.load(Ordering::SeqCst), 1);
    assert_eq!(m1.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_new_computer_accepts_an_attach_at_once() {
    let sb = start_with(&only_m1_config()).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    assert_eq!(fake_vm(sb.addr, M2_SECRET, "x").await.err(), Some(401));

    sb.reload(&multi_config("", ""));
    let _m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;
    let routed = sb
        .call_at("/mcp/m2", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(routed["result"]["structuredContent"]["vm"], "vm-m2");
}

#[tokio::test]
async fn one_computer_full_does_not_stop_the_other() {
    let text = with_m1_limit(&multi_config("", ""), 2);
    let sb = Arc::new(start_with(&text).await);
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let _m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    // Fill m1 (the owner's own cap is 64, so only m1's limit of 2 can bite).
    let mut hung = Vec::new();
    for id in 1..=2 {
        let sb = sb.clone();
        hung.push(tokio::spawn(async move {
            sb.call_at("/mcp/m1", OWNER_TOKEN, json!(id), "hang", json!({}))
                .await
        }));
    }
    sb.wait_in_flight(OWNER_TOKEN, "m1", 2).await;

    let refused = sb
        .call_at("/mcp/m1", OWNER_TOKEN, json!(3), "sys_info", json!({}))
        .await;
    assert_eq!(refused["error"]["code"], -32002, "m1 is full");
    let other = sb
        .call_at("/mcp/m2", OWNER_TOKEN, json!(4), "sys_info", json!({}))
        .await;
    assert_eq!(
        other["result"]["structuredContent"]["vm"], "vm-m2",
        "m2 is unaffected"
    );
    for task in hung {
        assert_eq!(task.await.unwrap()["error"]["code"], -32003);
    }
}

#[tokio::test]
async fn the_per_caller_cap_leaves_room_for_a_second_caller() {
    // m1 allows 4 in flight, so a caller without its own limit gets 2.
    let text = with_m1_limit(&multi_config("", &second_narrow_client()), 4);
    let sb = Arc::new(start_with(&text).await);
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;

    let mut hung = Vec::new();
    for id in 1..=2 {
        let sb = sb.clone();
        hung.push(tokio::spawn(async move {
            sb.call_at("/mcp/m1", NARROW_TOKEN, json!(id), "hang", json!({}))
                .await
        }));
    }
    sb.wait_in_flight(OWNER_TOKEN, "m1", 2).await;

    // `narrow` is at its share even though the computer has room.
    let refused = sb
        .call_at("/mcp/m1", NARROW_TOKEN, json!(3), "sys_info", json!({}))
        .await;
    assert_eq!(refused["error"]["code"], -32002);
    // ... and the room is still there for someone else.
    let other = sb
        .call_at("/mcp/m1", NARROW2_TOKEN, json!(4), "sys_info", json!({}))
        .await;
    assert_eq!(other["result"]["structuredContent"]["vm"], "vm-m1");
    for task in hung {
        assert_eq!(task.await.unwrap()["error"]["code"], -32003);
    }
}

#[tokio::test]
async fn an_explicit_per_caller_cap_is_honoured() {
    let narrow = format!(
        "[[client]]\nname = \"narrow2\"\ntoken_sha256 = \"{}\"\ncomputers = {{ m1 = [\"sys_info\", \"hang\"] }}\nmax_inflight = 1\n",
        verifier(NARROW2_TOKEN)
    );
    let sb = Arc::new(start_with(&multi_config("", &narrow)).await);
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;

    let hung = tokio::spawn({
        let sb = sb.clone();
        async move {
            sb.call_at("/mcp/m1", NARROW2_TOKEN, json!(1), "hang", json!({}))
                .await
        }
    });
    sb.wait_in_flight(OWNER_TOKEN, "m1", 1).await;
    let refused = sb
        .call_at("/mcp/m1", NARROW2_TOKEN, json!(2), "sys_info", json!({}))
        .await;
    assert_eq!(refused["error"]["code"], -32002);
    // Another caller is not affected by that one's limit.
    let other = sb
        .call_at("/mcp/m1", NARROW_TOKEN, json!(3), "sys_info", json!({}))
        .await;
    assert_eq!(other["result"]["structuredContent"]["vm"], "vm-m1");
    assert_eq!(hung.await.unwrap()["error"]["code"], -32003);
}

/// Over real HTTP: a caller that gives up mid-call must not keep holding its
/// share. Nothing tells the switchboard that the client went away — the handler
/// future is simply dropped — and `hang` is given a 30 s budget here so that the
/// server-side timeout cannot be what releases the slot.
#[tokio::test]
async fn a_caller_that_disconnects_mid_call_gets_its_share_back() {
    let text = with_narrow_cap(&multi_config("", ""), 1).replace("hang = 2", "hang = 30");
    let sb = start_with(&text).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;

    let gave_up = sb
        .http
        .post(format!("http://{}/mcp/m1", sb.addr))
        .bearer_auth(NARROW_TOKEN)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                      "params":{"name":"hang","arguments":{}}}))
        .timeout(Duration::from_millis(300))
        .send()
        .await;
    assert!(gave_up.is_err(), "`hang` answered; it must not");

    // The computer's slot is free again...
    sb.wait_in_flight(OWNER_TOKEN, "m1", 0).await;
    // ...and so is this caller's share of it: at a cap of 1, a leaked entry
    // would make its own next call -32002 for the next 30 seconds.
    let after = sb
        .call_at("/mcp/m1", NARROW_TOKEN, json!(2), "sys_info", json!({}))
        .await;
    assert_eq!(after["result"]["structuredContent"]["vm"], "vm-m1");
}

/// The ADR's visibility rule keys on the caller's grant, not on how many
/// computers exist, so a one-computer switchboard hides the same fields.
#[tokio::test]
async fn one_computer_does_not_widen_what_a_named_caller_sees() {
    let sb = start_with(&only_m1_config()).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    let narrow = sb.entry(NARROW_TOKEN, "m1").await;
    assert!(narrow.get("peer").is_none(), "{narrow}");
    assert!(narrow.get("in_flight").is_none(), "{narrow}");
    assert_eq!(narrow["ready"], true);
    // The owner sees them with one computer as with two.
    let owner = sb.entry(OWNER_TOKEN, "m1").await;
    assert!(owner["peer"].is_string(), "{owner}");
    assert_eq!(owner["in_flight"], 0);
}

// ---------------------------------------------------------------------------
// v2: routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn per_computer_routes_work_for_allowed_computers() {
    let sb = start_with(&multi_config("", "")).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let _m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    // tools/list is the computer's list, filtered per caller and per computer.
    assert_eq!(
        sb.tool_names_at("/mcp/m1", OWNER_TOKEN).await,
        vec![
            "bash",
            "hang",
            "screenshot",
            "slow",
            "sys_info",
            "vm_status"
        ]
    );
    assert_eq!(
        sb.tool_names_at("/mcp/m1", NARROW_TOKEN).await,
        vec!["hang", "screenshot", "slow", "sys_info", "vm_status"]
    );

    // initialize names the computer, so a model with two servers can tell them apart.
    let (_, init) = sb
        .rpc_at(
            "/mcp/m2",
            OWNER_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        )
        .await;
    let instructions = init["result"]["instructions"].as_str().unwrap();
    assert!(instructions.contains("`m2`"), "{instructions}");

    // /computers: what this caller may use, and whether each is up.
    let owner = sb.computers_as(OWNER_TOKEN).await;
    assert_eq!(owner.len(), 2);
    assert_eq!(owner[0]["name"], "m1");
    assert_eq!(owner[0]["default"], true);
    assert_eq!(owner[0]["attached"], true);
    assert_eq!(owner[0]["ready"], true);
    assert_eq!(owner[1]["name"], "m2");
    assert_eq!(owner[1]["default"], false);
    // The `"*"`-only fields of /status are not in there.
    assert!(owner[0].get("peer").is_none() && owner[0].get("in_flight").is_none());
    let narrow = sb.computers_as(NARROW_TOKEN).await;
    assert_eq!(narrow.len(), 1);
    assert_eq!(narrow[0]["name"], "m1");
    assert_eq!(narrow[0]["default"], true);

    // /readyz/{computer} needs a token and answers only for that caller's.
    assert_eq!(
        sb.get_body_as("/readyz/m1", NARROW_TOKEN).await,
        (200, "ok".to_owned())
    );
    assert_eq!(
        sb.get_body_as("/readyz/m2", OWNER_TOKEN).await,
        (200, "ok".to_owned())
    );
    assert_eq!(
        sb.get_body_as("/readyz/m2", NARROW_TOKEN).await,
        (404, "no such computer".to_owned())
    );
}

#[tokio::test]
async fn every_route_is_401_without_a_token_whatever_the_path_says() {
    let sb = start_with(&multi_config("", "")).await;
    // The token is checked before the path is resolved, so an unknown computer
    // and a real one are the same 401.
    for path in ["/mcp", "/mcp/m1", "/mcp/unknown"] {
        let response = sb
            .http
            .post(format!("http://{}{path}", sb.addr))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 401, "{path}");
        assert!(
            response.headers().get("www-authenticate").is_some(),
            "{path}"
        );
    }
    let reference = sb.get_body("/readyz/m1").await;
    assert_eq!(reference.0, 401);
    assert_eq!(sb.get_body("/readyz/unknown").await, reference);
    assert_eq!(sb.get_body("/computers").await.0, 401);
    assert_eq!(sb.get_body("/status").await.0, 401);
    // A computer secret is not a client token.
    assert_eq!(sb.get_body_as("/computers", M1_SECRET).await.0, 401);
}

#[tokio::test]
async fn unknown_and_not_allowed_are_the_same_answer_on_every_route() {
    let sb = start_with(&multi_config("", "")).await;
    let _m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    // `narrow` may not use m2, which exists and is ready. `nope` does not exist.
    let not_allowed = sb.get_body_as("/readyz/m2", NARROW_TOKEN).await;
    let unknown = sb.get_body_as("/readyz/nope", NARROW_TOKEN).await;
    assert_eq!(not_allowed, unknown);
    assert_eq!(not_allowed.0, 404);

    let denied = post_ping(&sb, "/mcp/m2", NARROW_TOKEN).await;
    assert_eq!(denied, post_ping(&sb, "/mcp/nope", NARROW_TOKEN).await);
    assert_eq!(denied.0, 404);
}

/// A minimal POST, returning status and body verbatim so two refusals can be
/// compared byte for byte.
async fn post_ping(sb: &Sb, path: &str, token: &str) -> (u16, String) {
    let response = sb
        .http
        .post(format!("http://{}{path}", sb.addr))
        .bearer_auth(token)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    (
        response.status().as_u16(),
        response.text().await.unwrap_or_default(),
    )
}

#[tokio::test]
async fn readyz_reveals_no_names_or_counts_and_is_200_when_any_is_ready() {
    let sb = start_with(&multi_config("", "")).await;
    assert_eq!(sb.get_body("/readyz").await, (503, "vm offline".to_owned()));

    // Only the second computer is up: /readyz still says just "ok".
    let _m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;
    let (status, body) = sb.get_body("/readyz").await;
    assert_eq!((status, body.as_str()), (200, "ok"));
    for leak in ["m1", "m2", "1 of", "count"] {
        assert!(!body.contains(leak), "{body} leaks {leak}");
    }
    // ... and the computer that is down is still reported as down, with a token.
    assert_eq!(
        sb.get_body_as("/readyz/m1", OWNER_TOKEN).await,
        (503, "vm offline".to_owned())
    );
}

#[tokio::test]
async fn adding_a_computer_does_not_change_a_wildcard_callers_bare_mcp() {
    let sb = start_with(&only_m1_config()).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    let before = sb.tool_names(OWNER_TOKEN).await;
    let routed_before = sb.call(OWNER_TOKEN, json!(1), "sys_info", json!({})).await;

    sb.reload(&multi_config("", ""));
    let _m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    assert_eq!(sb.tool_names(OWNER_TOKEN).await, before, "/mcp moved");
    let routed_after = sb.call(OWNER_TOKEN, json!(1), "sys_info", json!({})).await;
    assert_eq!(
        routed_after["result"]["structuredContent"]["vm"],
        routed_before["result"]["structuredContent"]["vm"]
    );
    // The new computer is reachable, just not on the bare path.
    assert_eq!(sb.computers_as(OWNER_TOKEN).await.len(), 2);
}

#[tokio::test]
async fn peer_and_in_flight_are_hidden_from_non_wildcard_callers() {
    let sb = start_with(&multi_config("", "")).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;

    let owner = sb.entry(OWNER_TOKEN, "m1").await;
    assert!(owner["peer"].is_string(), "{owner}");
    assert_eq!(owner["in_flight"], 0);

    let narrow = sb.entry(NARROW_TOKEN, "m1").await;
    assert!(narrow.get("peer").is_none(), "{narrow}");
    assert!(narrow.get("in_flight").is_none(), "{narrow}");
    // Everything else is still there.
    assert_eq!(narrow["ready"], true);
    assert_eq!(narrow["server"]["name"], "vm-m1");
    assert!(narrow["attached_for_secs"].is_u64());
    assert!(narrow["max_in_flight"].is_u64());
    // A narrow caller sees only its own computers.
    let listed = sb.status_as(NARROW_TOKEN).await;
    assert_eq!(listed["computers"].as_array().unwrap().len(), 1);
    assert_eq!(listed["vm"]["computer"], "m1");

    // The same filter applies to the vm_status tool.
    let tool = sb
        .call_at("/mcp/m1", NARROW_TOKEN, json!(1), "vm_status", json!({}))
        .await;
    let structured = &tool["result"]["structuredContent"];
    assert!(structured.get("peer").is_none(), "{structured}");
    assert!(structured.get("in_flight").is_none(), "{structured}");
    let owner_tool = sb
        .call_at("/mcp/m1", OWNER_TOKEN, json!(1), "vm_status", json!({}))
        .await;
    assert!(owner_tool["result"]["structuredContent"]["peer"].is_string());
}

// ---------------------------------------------------------------------------
// openab-pty side: the switchboard dials a pod's /tools/attach.
// ---------------------------------------------------------------------------

/// Be openab-pty: accept the dial, check the bearer, then act as MCP client.
async fn pod_handshake(
    pod: &tokio::net::TcpListener,
    expect_secret: &str,
    expect_path: &str,
) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    let (tcp, _) = tokio::time::timeout(Duration::from_secs(5), pod.accept())
        .await
        .expect("switchboard never dialled the pod")
        .unwrap();
    let mut saw_auth = None;
    let ws = tokio_tungstenite::accept_hdr_async(
        tcp,
        |req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
            saw_auth = req
                .headers()
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned());
            assert_eq!(req.uri().path(), expect_path);
            Ok(resp)
        },
    )
    .await
    .unwrap();
    assert_eq!(
        saw_auth.as_deref(),
        Some(format!("Bearer {expect_secret}").as_str())
    );
    ws
}

async fn ask(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    req: Value,
) -> Value {
    ws.send(Message::Text(req.to_string().into()))
        .await
        .unwrap();
    next_frame(ws).await
}

async fn next_frame(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(_)) => continue,
            other => panic!("pod socket ended: {other:?}"),
        }
    }
}

/// A temp dir holding one attach secret; removed on drop.
struct SecretFile {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl SecretFile {
    fn new(tag: &str, secret: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("openab-sb-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pod.secret");
        std::fs::write(&path, format!("{secret}\n")).unwrap();
        Self { dir, path }
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn lends_the_vm_to_an_openab_pty_session_and_honours_stop_codes() {
    const POD_SECRET: &str = "pod-attach-secret";
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pod_addr = pod.local_addr().unwrap();
    let secret = SecretFile::new("pty", POD_SECRET);

    let attach = format!(
        "[[pty_attach]]\nname = \"kiro-pod\"\nurl = \"ws://{pod_addr}/tools/attach/laptop\"\nsecret_file = \"{}\"\ntools = [\"screenshot\", \"sys_info\"]\n",
        secret.path.display()
    );
    let sb = start_with(&config_text("", &attach)).await;
    let _vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;

    let mut ws = pod_handshake(&pod, POD_SECRET, "/tools/attach/laptop").await;
    let init = ask(&mut ws, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"openab-pty"}}})).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "openab-sb");
    ws.send(Message::Text(
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let list = ask(
        &mut ws,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let mut names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["screenshot", "sys_info", "vm_status"]);
    let shot = ask(&mut ws, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"screenshot","arguments":{}}})).await;
    assert_eq!(shot["id"], 3);
    assert_eq!(shot["result"]["structuredContent"]["tool"], "screenshot");
    let bash = ask(&mut ws, json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bash","arguments":{"command":"id"}}})).await;
    assert_eq!(bash["result"]["isError"], true, "attach allowlist applies");

    // Grant revoked: 4010 means stop. The switchboard must not redial.
    ws.close(Some(CloseFrame {
        code: CloseCode::from(4010),
        reason: "revoked".into(),
    }))
    .await
    .unwrap();
    let redial = tokio::time::timeout(Duration::from_secs(3), pod.accept()).await;
    assert!(redial.is_err(), "redialled after a stop code");
}

#[tokio::test]
async fn a_pty_attach_lends_the_computer_it_names() {
    const POD_SECRET: &str = "pod-attach-secret-m2";
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pod_addr = pod.local_addr().unwrap();
    let secret = SecretFile::new("pty-m2", POD_SECRET);

    let attach = format!(
        "[[pty_attach]]\nname = \"kiro-pod\"\ncomputer = \"m2\"\nurl = \"ws://{pod_addr}/tools/attach/laptop\"\nsecret_file = \"{}\"\ntools = [\"sys_info\", \"screenshot\"]\n",
        secret.path.display()
    );
    let sb = start_with(&multi_config("", &attach)).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    let _m2 = fake_vm(sb.addr, M2_SECRET, "vm-m2").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;
    sb.wait_for(OWNER_TOKEN, "m2", "vm-m2").await;

    let mut ws = pod_handshake(&pod, POD_SECRET, "/tools/attach/laptop").await;
    let init = ask(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
    )
    .await;
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("`m2`"),
        "{init}"
    );
    let list = ask(
        &mut ws,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let mut names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["screenshot", "sys_info", "vm_status"]);
    // The call lands on m2, not on the first computer configured.
    let info = ask(&mut ws, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sys_info","arguments":{}}})).await;
    assert_eq!(info["result"]["structuredContent"]["vm"], "vm-m2");
    let status = ask(&mut ws, json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"vm_status","arguments":{}}})).await;
    assert_eq!(status["result"]["structuredContent"]["computer"], "m2");
    // An attach is a named caller, so it does not see the internals either.
    assert!(status["result"]["structuredContent"].get("peer").is_none());
}

/// A computer's name is a label the operator may change by `SIGHUP`, and the
/// verifier keeps the socket. An attach that had resolved its computer once and
/// kept the name would then ask the hub for a slot that no longer exists, and
/// the pod's CLI would be told "the VM is not connected" for ever — with
/// nothing closed and nothing logged.
#[tokio::test]
async fn a_pty_attach_survives_a_same_verifier_rename_of_its_computer() {
    const POD_SECRET: &str = "pod-attach-secret-rename";
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pod_addr = pod.local_addr().unwrap();
    let secret = SecretFile::new("pty-rename", POD_SECRET);

    // Built per computer rather than string-replaced: the secret file lives
    // under a temp path this test must not rewrite.
    let attach_for = |computer: &str| {
        format!(
            "[[pty_attach]]\nname = \"kiro-pod\"\ncomputer = \"{computer}\"\nurl = \"ws://{pod_addr}/tools/attach/laptop\"\nsecret_file = \"{}\"\ntools = [\"*\"]\n",
            secret.path.display()
        )
    };
    let sb = start_with(&multi_config("", &attach_for("m1"))).await;
    let m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;

    let mut ws = pod_handshake(&pod, POD_SECRET, "/tools/attach/laptop").await;
    let before = ask(&mut ws, json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}})).await;
    assert_eq!(before["result"]["structuredContent"]["vm"], "vm-m1");

    // `m1` → `macmini` everywhere, including this attach's `computer` (without
    // that edit the config would not even load). The verifier is untouched, so
    // the computer's socket is relabelled, not closed.
    let renamed = format!(
        "{}{}",
        multi_config("", "").replace("m1", "macmini"),
        attach_for("macmini")
    );
    assert!(renamed.contains("computers = { macmini = ["), "{renamed}");
    sb.reload(&renamed);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!m1.is_closed(), "a relabel must not close the socket");

    // The pod's CLI knows nothing of any of this and calls as before.
    let after = ask(&mut ws, json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sys_info","arguments":{}}})).await;
    assert_eq!(after["id"], 2);
    assert_ne!(
        after["result"]["isError"],
        json!(true),
        "the attach lost its computer: {after}"
    );
    assert_eq!(after["result"]["structuredContent"]["vm"], "vm-m1");
    assert_eq!(m1.calls.load(Ordering::SeqCst), 2, "the same socket served");
    // `vm_status` and `tools/list` follow the new label too.
    let status = ask(&mut ws, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vm_status","arguments":{}}})).await;
    assert_eq!(
        status["result"]["structuredContent"]["computer"], "macmini",
        "{status}"
    );
    let list = ask(
        &mut ws,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}),
    )
    .await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"bash"), "{list}");
}

#[tokio::test]
async fn the_per_caller_cap_applies_to_a_pty_attach() {
    const POD_SECRET: &str = "pod-attach-secret-cap";
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pod_addr = pod.local_addr().unwrap();
    let secret = SecretFile::new("pty-cap", POD_SECRET);

    // One request at a time from this pod, even though the pod's own ceiling is
    // 64 and m1 allows 4.
    let attach = format!(
        "[[pty_attach]]\nname = \"kiro-pod\"\ncomputer = \"m1\"\nurl = \"ws://{pod_addr}/tools/attach/laptop\"\nsecret_file = \"{}\"\ntools = [\"*\"]\nmax_inflight = 1\n",
        secret.path.display()
    );
    let sb = start_with(&with_m1_limit(&multi_config("", &attach), 4)).await;
    let _m1 = fake_vm(sb.addr, M1_SECRET, "vm-m1").await.unwrap();
    sb.wait_for(OWNER_TOKEN, "m1", "vm-m1").await;

    let mut ws = pod_handshake(&pod, POD_SECRET, "/tools/attach/laptop").await;
    // `hang` never answers; the second request is over this attach's share.
    ws.send(Message::Text(
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"hang","arguments":{}}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    sb.wait_in_flight(OWNER_TOKEN, "m1", 1).await;
    let refused = ask(&mut ws, json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"sys_info","arguments":{}}})).await;
    assert_eq!(refused["id"], 11);
    assert_eq!(refused["error"]["code"], -32002, "{refused}");
    // The computer still has room for another caller.
    let other = sb
        .call_at("/mcp/m1", OWNER_TOKEN, json!(1), "sys_info", json!({}))
        .await;
    assert_eq!(other["result"]["structuredContent"]["vm"], "vm-m1");
    // The hung call eventually times out on its own.
    let timed_out = next_frame(&mut ws).await;
    assert_eq!(timed_out["id"], 10);
    assert_eq!(timed_out["error"]["code"], -32003);
}

#[tokio::test]
async fn pty_attach_redials_after_a_plain_drop() {
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pod_addr = pod.local_addr().unwrap();
    let secret = SecretFile::new("redial", "s");
    let attach = format!(
        "[[pty_attach]]\nname = \"kiro-pod\"\nurl = \"ws://{pod_addr}/tools/attach/x\"\nsecret_file = \"{}\"\ntools = [\"*\"]\n",
        secret.path.display()
    );
    let _sb = start_with(&config_text("", &attach)).await;

    let (tcp, _) = tokio::time::timeout(Duration::from_secs(5), pod.accept())
        .await
        .unwrap()
        .unwrap();
    let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    drop(ws); // runtime replaced / network blip
    let again = tokio::time::timeout(Duration::from_secs(5), pod.accept()).await;
    assert!(again.is_ok(), "did not redial after a drop");
}

#[tokio::test]
async fn a_vm_that_refuses_the_handshake_is_closed_not_left_attached() {
    let sb = start().await;
    let mut request = format!("ws://{}/vm/attach", sb.addr)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {VM_SECRET}")).unwrap(),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let code = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(frame)) = ws.next().await {
            match frame {
                Message::Text(text) => {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    if msg["method"] == "initialize" {
                        let refuse = json!({"jsonrpc":"2.0","id":msg["id"],
                            "error":{"code":-32602,"message":"unsupported protocol version"}});
                        ws.send(Message::Text(refuse.to_string().into()))
                            .await
                            .unwrap();
                    }
                }
                Message::Close(frame) => return frame.map(|f| u16::from(f.code)),
                _ => {}
            }
        }
        None
    })
    .await
    .expect("switchboard kept a VM that failed the handshake");
    assert_eq!(code, Some(4005));
    sb.wait_for_health(503).await;
    assert_eq!(sb.status().await["vm"]["attached"], false);
}

/// Accept one dial on `pod` as openab-pty would, then close with `code`.
async fn pod_accept_then_close(pod: &tokio::net::TcpListener, code: u16) {
    let (tcp, _) = tokio::time::timeout(Duration::from_secs(5), pod.accept())
        .await
        .expect("switchboard did not dial the pod")
        .unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    ws.close(Some(CloseFrame {
        code: CloseCode::from(code),
        reason: "".into(),
    }))
    .await
    .unwrap();
    // Let the close handshake finish.
    let _ = tokio::time::timeout(Duration::from_secs(1), ws.next()).await;
}

async fn sb_dialling(pod_addr: SocketAddr, tag: &str) -> (Sb, SecretFile) {
    let secret = SecretFile::new(tag, "s");
    let attach = format!(
        "[[pty_attach]]\nname = \"kiro-pod\"\nurl = \"ws://{pod_addr}/tools/attach/x\"\nsecret_file = \"{}\"\ntools = [\"*\"]\n",
        secret.path.display()
    );
    (start_with(&config_text("", &attach)).await, secret)
}

#[tokio::test]
async fn pty_attach_redials_on_runtime_replaced_and_stops_on_other_4xxx() {
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_sb, _secret) = sb_dialling(pod.local_addr().unwrap(), "codes").await;

    // 4006: the pod was replaced; the switchboard must come back.
    pod_accept_then_close(&pod, 4006).await;
    // 4003 is not a code openab-pty sends today; §9.2 says stop on any 4xxx
    // but 4006, so an unknown one must not be redialled either.
    pod_accept_then_close(&pod, 4003).await;
    let again = tokio::time::timeout(Duration::from_secs(4), pod.accept()).await;
    assert!(again.is_err(), "redialled after 4003");
}

/// Answer one dial with a bare HTTP status, as a proxy in front of the pod does.
async fn pod_refuse(pod: &tokio::net::TcpListener, status: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut tcp, _) = tokio::time::timeout(Duration::from_secs(5), pod.accept())
        .await
        .expect("switchboard did not dial the pod")
        .unwrap();
    let mut buf = [0u8; 4096];
    let _ = tcp.read(&mut buf).await;
    let reply = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    tcp.write_all(reply.as_bytes()).await.unwrap();
    let _ = tcp.shutdown().await;
}

#[tokio::test]
async fn pty_attach_redials_fast_after_a_proxy_error_but_slowly_after_401() {
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_sb, _secret) = sb_dialling(pod.local_addr().unwrap(), "refuse").await;

    // 502 from whatever fronts the pod: a path fault, so the normal 1 s/2 s
    // backoff applies, not the one-minute grant poll.
    pod_refuse(&pod, "502 Bad Gateway").await;
    pod_refuse(&pod, "502 Bad Gateway").await;
    // 401: only a fresh grant helps; nothing for the next several seconds.
    pod_refuse(&pod, "401 Unauthorized").await;
    let again = tokio::time::timeout(Duration::from_secs(6), pod.accept()).await;
    assert!(again.is_err(), "polled fast after a 401");
}
