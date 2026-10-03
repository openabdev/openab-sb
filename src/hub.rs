//! The switchboard's only stateful part: the VM slot and the pending-request
//! table for the socket the VM dialled in on.
//!
//! Rules enforced here:
//!
//! 1. **One VM, newest wins.** A second attach replaces the first, which is closed
//!    with [`close_code::TAKEOVER`]. The evicted socket's cleanup removes the slot
//!    only if it still holds *that* socket, and fails only *its own* pending calls
//!    — a reconnecting VM never loses calls that were already routed to it.
//! 2. **Ids are ours on the wire.** Every forwarded request gets a fresh integer
//!    id; the caller's id is restored on the way back. Two callers that both send
//!    `id: 1` cannot collide.
//! 3. **Nothing is silent.** Timeout, overload, and disconnect each surface as a
//!    distinct JSON-RPC error; nothing is retried (a shell command is not
//!    idempotent).

use crate::audit::Audit;
use crate::auth::Verifier;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

pub mod close_code {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    /// Another VM attached with a valid secret; the dialer should stop.
    pub const TAKEOVER: u16 = 4002;
    /// The operator rotated or revoked the VM secret.
    pub const REVOKED: u16 = 4003;
}

pub fn close_reason(code: u16) -> &'static str {
    match code {
        close_code::NORMAL => "normal closure",
        close_code::GOING_AWAY => "switchboard shutting down",
        close_code::TAKEOVER => "replaced by a newer attach",
        close_code::REVOKED => "VM secret revoked or rotated",
        _ => "closed",
    }
}

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
/// Largest frame accepted from the VM. Screenshots are base64 images.
pub const MAX_VM_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const PING_INTERVAL: Duration = Duration::from_secs(20);
pub const MAX_MISSED_PINGS: u32 = 3;
const TO_VM_QUEUE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    /// No VM is attached; nothing was sent.
    NotAttached,
    /// The in-flight cap was reached; nothing was sent.
    TooManyInFlight,
    /// Sent, but the VM did not answer in time. Outcome unknown.
    Timeout,
    /// Sent, then the socket went away. Outcome unknown.
    Disconnected,
}

impl CallError {
    pub fn rpc_code(self) -> i64 {
        match self {
            Self::NotAttached => -32001,
            Self::TooManyInFlight => -32002,
            Self::Timeout => -32003,
            Self::Disconnected => -32004,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NotAttached => "the VM is not connected to the switchboard",
            Self::TooManyInFlight => "too many requests in flight toward the VM; retry shortly",
            Self::Timeout => "the VM did not answer in time; the call may or may not have run",
            Self::Disconnected => {
                "the VM disconnected during the call; the call may or may not have run"
            }
        }
    }
}

/// One attached VM socket.
pub struct Vm {
    generation: u64,
    peer: String,
    since: Instant,
    secret: Verifier,
    to_vm: mpsc::Sender<Message>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    close_code: AtomicU64,
    ready: AtomicBool,
    server_info: Mutex<Option<Value>>,
    max_inflight: usize,
}

impl Vm {
    fn close(&self, code: u16) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.close_code.store(u64::from(code), Ordering::Release);
        let _ = self.to_vm.try_send(Message::Close(Some(CloseFrame {
            code,
            reason: close_reason(code).into(),
        })));
        // Dropping the senders wakes every waiter with `Disconnected`.
        self.pending.lock().clear();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn call(&self, mut request: Value, timeout: Duration) -> Result<Value, CallError> {
        if self.is_closed() {
            return Err(CallError::NotAttached);
        }
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut pending = self.pending.lock();
            if pending.len() >= self.max_inflight {
                return Err(CallError::TooManyInFlight);
            }
            let id = self.next_id.fetch_add(1, Ordering::AcqRel);
            pending.insert(id, tx);
            id
        };
        // `close` may have run between the check above and the insert.
        if self.is_closed() {
            self.pending.lock().remove(&id);
            return Err(CallError::NotAttached);
        }
        if let Some(object) = request.as_object_mut() {
            object.insert("id".into(), json!(id));
        }
        let outcome = tokio::time::timeout(timeout, async {
            if self
                .to_vm
                .send(Message::Text(request.to_string().into()))
                .await
                .is_err()
            {
                return Err(CallError::Disconnected);
            }
            rx.await.map_err(|_| CallError::Disconnected)
        })
        .await;
        match outcome {
            Ok(result) => {
                if result.is_err() {
                    self.pending.lock().remove(&id);
                }
                result
            }
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(CallError::Timeout)
            }
        }
    }

    fn on_frame(&self, frame: Value) {
        let is_response = frame.get("result").is_some() || frame.get("error").is_some();
        if is_response {
            let Some(id) = frame.get("id").and_then(Value::as_u64) else {
                return;
            };
            if let Some(waiter) = self.pending.lock().remove(&id) {
                let _ = waiter.send(frame);
            }
            return;
        }
        // A request from the VM: only `ping` is meaningful. Notifications drop.
        let Some(id) = frame.get("id").cloned() else {
            return;
        };
        let reply = match frame.get("method").and_then(Value::as_str) {
            Some("ping") => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            _ => rpc_error(
                id,
                -32601,
                "the switchboard does not serve requests from the VM",
            ),
        };
        let _ = self.to_vm.try_send(Message::Text(reply.to_string().into()));
    }

    fn status(&self) -> Value {
        json!({
            "attached": true,
            "ready": self.ready.load(Ordering::Acquire),
            "peer": self.peer,
            "attached_for_secs": self.since.elapsed().as_secs(),
            "in_flight": self.pending.lock().len(),
            "max_in_flight": self.max_inflight,
            "server": self.server_info.lock().clone(),
        })
    }
}

pub struct Hub {
    slot: Mutex<Option<Arc<Vm>>>,
    generation: AtomicU64,
    max_inflight: usize,
    audit: Audit,
}

impl Hub {
    pub fn new(max_inflight: usize, audit: Audit) -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(None),
            generation: AtomicU64::new(0),
            max_inflight,
            audit,
        })
    }

    fn current(&self) -> Option<Arc<Vm>> {
        self.slot.lock().clone().filter(|vm| !vm.is_closed())
    }

    pub fn is_attached(&self) -> bool {
        self.current().is_some()
    }

    /// Attached and the MCP handshake completed.
    pub fn is_ready(&self) -> bool {
        self.current()
            .is_some_and(|vm| vm.ready.load(Ordering::Acquire))
    }

    pub fn status(&self) -> Value {
        match self.current() {
            Some(vm) => vm.status(),
            None => json!({ "attached": false }),
        }
    }

    /// Forward one JSON-RPC request to the VM; the response carries the VM's
    /// (rewritten) id — callers restore their own. A VM that has not finished
    /// the MCP handshake counts as not attached, so nothing ever reaches it
    /// before `initialize`.
    pub async fn call(&self, request: Value, timeout: Duration) -> Result<Value, CallError> {
        let vm = self
            .current()
            .filter(|vm| vm.ready.load(Ordering::Acquire))
            .ok_or(CallError::NotAttached)?;
        vm.call(request, timeout).await
    }

    /// Close the attached VM if it authenticated with a secret other than
    /// `current` (config reload rotated it).
    pub fn revoke_unless(&self, current: &Verifier) {
        if let Some(vm) = self.current() {
            if !vm.secret.matches(current) {
                self.audit.event(
                    "vm_revoked",
                    json!({ "peer": vm.peer, "generation": vm.generation }),
                );
                vm.close(close_code::REVOKED);
            }
        }
    }

    pub fn close_all(&self, code: u16) {
        if let Some(vm) = self.slot.lock().take() {
            vm.close(code);
        }
    }

    /// Install an authenticated socket as the VM and serve it until it closes.
    pub async fn serve(self: &Arc<Self>, socket: WebSocket, peer: String, secret: Verifier) {
        let (to_vm, mut outbound) = mpsc::channel::<Message>(TO_VM_QUEUE);
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let vm = Arc::new(Vm {
            generation,
            peer: peer.clone(),
            since: Instant::now(),
            secret,
            to_vm,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            close_code: AtomicU64::new(0),
            ready: AtomicBool::new(false),
            server_info: Mutex::new(None),
            max_inflight: self.max_inflight,
        });
        let evicted = self.slot.lock().replace(vm.clone());
        if let Some(old) = evicted {
            self.audit.event(
                "vm_takeover",
                json!({ "old_peer": old.peer, "old_generation": old.generation,
                        "new_peer": peer, "new_generation": generation }),
            );
            old.close(close_code::TAKEOVER);
        }
        self.audit.event(
            "vm_attach",
            json!({ "peer": peer, "generation": generation }),
        );
        tracing::info!(%peer, generation, "VM attached");

        let (mut sink, mut stream) = socket.split();
        let mut writer = tokio::spawn(async move {
            while let Some(message) = outbound.recv().await {
                let closing = matches!(message, Message::Close(_));
                if sink.send(message).await.is_err() || closing {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        // We are the MCP client on this socket: handshake before anything else
        // is sent, so the VM sees `initialize` first.
        let handshake = vm.clone();
        tokio::spawn(async move {
            let init = json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "openab-sb", "version": env!("CARGO_PKG_VERSION") }
                }
            });
            match handshake.call(init, Duration::from_secs(15)).await {
                Ok(response) if response.get("result").is_some() => {
                    *handshake.server_info.lock() = response
                        .get("result")
                        .and_then(|r| r.get("serverInfo"))
                        .cloned();
                    let initialized =
                        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
                    let _ = handshake
                        .to_vm
                        .send(Message::Text(initialized.to_string().into()))
                        .await;
                    handshake.ready.store(true, Ordering::Release);
                }
                Ok(response) => {
                    tracing::warn!(?response, "VM refused initialize");
                }
                Err(error) => {
                    tracing::warn!(?error, "MCP initialize toward the VM failed");
                }
            }
        });

        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping.tick().await;
        let mut missed: u32 = 0;
        loop {
            tokio::select! {
                frame = stream.next() => {
                    let Some(Ok(frame)) = frame else { break };
                    missed = 0;
                    let parsed = match frame {
                        Message::Text(text) => serde_json::from_str::<Value>(&text).ok(),
                        Message::Binary(bytes) => serde_json::from_slice::<Value>(&bytes).ok(),
                        Message::Ping(_) | Message::Pong(_) => None,
                        Message::Close(_) => break,
                    };
                    if let Some(value) = parsed {
                        vm.on_frame(value);
                    }
                }
                _ = ping.tick() => {
                    missed += 1;
                    if missed > MAX_MISSED_PINGS {
                        tracing::info!(%peer, "VM silent past the ping budget");
                        break;
                    }
                    let _ = vm.to_vm.try_send(Message::Ping(Vec::new().into()));
                }
            }
            if vm.is_closed() {
                break;
            }
        }

        vm.close(close_code::NORMAL);
        {
            let mut slot = self.slot.lock();
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &vm))
            {
                *slot = None;
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut writer).await;
        writer.abort();
        let code = vm.close_code.load(Ordering::Acquire) as u16;
        self.audit.event(
            "vm_detach",
            json!({ "peer": peer, "generation": generation, "code": code,
                    "reason": close_reason(code),
                    "attached_for_secs": vm.since.elapsed().as_secs() }),
        );
        tracing::info!(%peer, generation, code, "VM detached");
    }
}

pub fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
