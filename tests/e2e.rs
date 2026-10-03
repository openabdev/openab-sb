//! End to end: a real switchboard on a loopback port, a fake VM dialling in over
//! a real WebSocket, northbound calls over real HTTP, and a fake openab-pty pod
//! the switchboard dials.
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
{extra_tail}
"#,
        vm = Verifier::of_secret(VM_SECRET).render(),
        connect = Verifier::of_secret(CONNECT_TOKEN).render(),
        pty = Verifier::of_secret(PTY_TOKEN).render(),
    )
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
    async fn rpc(&self, token: &str, body: Value) -> (u16, Value) {
        let response = self
            .http
            .post(format!("http://{}/mcp", self.addr))
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

    async fn call(&self, token: &str, id: Value, tool: &str, args: Value) -> Value {
        let (status, body) = self
            .rpc(
                token,
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    async fn tool_names(&self, token: &str) -> Vec<String> {
        let (_, body) = self
            .rpc(token, json!({"jsonrpc":"2.0","id":7,"method":"tools/list"}))
            .await;
        let mut names: Vec<String> = body["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    async fn healthz(&self) -> u16 {
        self.http
            .get(format!("http://{}/healthz", self.addr))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn status(&self) -> Value {
        self.http
            .get(format!("http://{}/status", self.addr))
            .bearer_auth(CONNECT_TOKEN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// Wait until the VM named `name` is the attached, initialised one.
    async fn wait_for_vm(&self, name: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = self.status().await;
            if status["vm"]["ready"] == json!(true) && status["vm"]["server"]["name"] == json!(name)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "VM {name} never became ready: {status}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_for_health(&self, want: u16) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.healthz().await != want {
            assert!(Instant::now() < deadline, "healthz never became {want}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Fake VM: an MCP server over a WebSocket it dials.
// ---------------------------------------------------------------------------

struct FakeVm {
    /// tools/call requests that reached the VM.
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
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offline_surface_is_honest_and_closed() {
    let sb = start().await;
    assert_eq!(sb.healthz().await, 503);

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
        "the VM secret must not open the northbound side"
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
    assert_eq!(sb.healthz().await, 503);
}

#[tokio::test]
async fn allowlist_filters_listing_and_blocks_calls_before_the_vm() {
    let sb = start().await;
    let vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;
    assert_eq!(sb.healthz().await, 200);

    // Connect sees only its allowlist; the VM's own `vm_status` is replaced by ours.
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
        "a denied call must not reach the VM"
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
    let _vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
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
    let deadline = Instant::now() + Duration::from_secs(2);
    while sb.status().await["vm"]["in_flight"] != json!(2) {
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

    // A call in flight on the old socket when the new VM arrives.
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
    assert_eq!(sb.healthz().await, 200);
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
    sb.app
        .reload_auth(Config::parse(&config_text("", "")).unwrap().auth);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sb.healthz().await, 200);

    let rotated = config_text("", "").replace(
        &Verifier::of_secret(VM_SECRET).render(),
        &Verifier::of_secret("next-secret").render(),
    );
    sb.app.reload_auth(Config::parse(&rotated).unwrap().auth);
    assert_eq!(vm.close_code().await, 4003);
    assert_eq!(fake_vm(sb.addr, VM_SECRET, "x").await.err(), Some(401));
    let _next = fake_vm(sb.addr, "next-secret", "vm-next").await.unwrap();
    sb.wait_for_vm("vm-next").await;
}

// ---------------------------------------------------------------------------
// openab-pty side: the switchboard dials a pod's /tools/attach.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lends_the_vm_to_an_openab_pty_session_and_honours_stop_codes() {
    const POD_SECRET: &str = "pod-attach-secret";
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pod_addr = pod.local_addr().unwrap();
    let dir = std::env::temp_dir().join(format!("openab-sb-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret_file = dir.join("pod.secret");
    std::fs::write(&secret_file, format!("{POD_SECRET}\n")).unwrap();

    let attach = format!(
        "[[pty_attach]]\nname = \"kiro-pod\"\nurl = \"ws://{pod_addr}/tools/attach/laptop\"\nsecret_file = \"{}\"\ntools = [\"screenshot\", \"sys_info\"]\n",
        secret_file.display()
    );
    let sb = start_with(&config_text("", &attach)).await;
    let _vm = fake_vm(sb.addr, VM_SECRET, "fake-vm").await.unwrap();
    sb.wait_for_vm("fake-vm").await;

    // Act as openab-pty: accept, check the bearer, then be the MCP client.
    let (tcp, _) = tokio::time::timeout(Duration::from_secs(5), pod.accept())
        .await
        .expect("switchboard never dialled the pod")
        .unwrap();
    let mut saw_auth = None;
    let mut ws = tokio_tungstenite::accept_hdr_async(
        tcp,
        |req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
            saw_auth = req
                .headers()
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned());
            assert_eq!(req.uri().path(), "/tools/attach/laptop");
            Ok(resp)
        },
    )
    .await
    .unwrap();
    assert_eq!(
        saw_auth.as_deref(),
        Some(format!("Bearer {POD_SECRET}").as_str())
    );

    async fn ask(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        req: Value,
    ) -> Value {
        ws.send(Message::Text(req.to_string().into()))
            .await
            .unwrap();
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pty_attach_redials_after_a_plain_drop() {
    let pod = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pod_addr = pod.local_addr().unwrap();
    let dir = std::env::temp_dir().join(format!("openab-sb-test-redial-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret_file = dir.join("pod.secret");
    std::fs::write(&secret_file, "s").unwrap();
    let attach = format!(
        "[[pty_attach]]\nname = \"kiro-pod\"\nurl = \"ws://{pod_addr}/tools/attach/x\"\nsecret_file = \"{}\"\ntools = [\"*\"]\n",
        secret_file.display()
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
    let _ = std::fs::remove_dir_all(&dir);
}
