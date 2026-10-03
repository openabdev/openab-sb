//! The switchboard's only stateful part: the VM slot and the pending-request
//! table for the socket the VM dialled in on.
//!
//! Rules enforced here:
//!
//! 1. **One VM, newest wins.** A second attach replaces the first, which is closed
//!    with [`close_code::TAKEOVER`]. The evicted socket's cleanup removes the slot
//!    only if it still holds *that* socket, and fails only *its own* pending calls
//!    — a reconnecting VM never loses calls that were already routed to it.
//! 2. **The secret is checked where the slot is taken.** The VM verifier lives
//!    under the same lock as the slot, so a reload that rotates it and an attach
//!    that was authenticated a moment earlier cannot both miss each other.
//! 3. **Ids are ours on the wire.** Every forwarded request gets a fresh integer
//!    id; the caller's id is restored on the way back. Two callers that both send
//!    `id: 1` cannot collide.
//! 4. **Nothing is silent.** Timeout, overload, disconnect and a failed handshake
//!    each surface as a distinct error or close code; nothing is retried (a shell
//!    command is not idempotent).

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
use tokio::sync::{mpsc, oneshot, watch};

pub mod close_code {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    /// Another VM attached with a valid secret; the dialer should stop.
    pub const TAKEOVER: u16 = 4002;
    /// The operator rotated or revoked the VM secret.
    pub const REVOKED: u16 = 4003;
    /// The VM did not complete the MCP handshake; redial with backoff.
    pub const HANDSHAKE_FAILED: u16 = 4005;
}

pub fn close_reason(code: u16) -> &'static str {
    match code {
        close_code::NORMAL => "normal closure",
        close_code::GOING_AWAY => "switchboard shutting down",
        close_code::TAKEOVER => "replaced by a newer attach",
        close_code::REVOKED => "VM secret revoked or rotated",
        close_code::HANDSHAKE_FAILED => "MCP initialize failed or timed out",
        _ => "closed",
    }
}

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
/// Largest frame accepted from the VM. Screenshots are base64 images.
pub const MAX_VM_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const PING_INTERVAL: Duration = Duration::from_secs(20);
/// Closed once this many ping intervals pass with no frame of any kind from
/// the VM: 3 × 20 s = 60 s.
pub const MAX_SILENT_INTERVALS: u32 = 3;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const TO_VM_QUEUE: usize = 64;
/// How long a closing socket's writer may take to flush before it is dropped.
const WRITER_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    /// No VM is attached (or it has not finished the handshake); nothing was sent.
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
    /// Flips to `true` on close. The writer sends the close frame ahead of
    /// anything queued (a full data queue can never swallow it) and the reader
    /// stops at once, whoever decided to close.
    closed_signal: watch::Sender<bool>,
    ready: AtomicBool,
    server_info: Mutex<Option<Value>>,
    max_inflight: usize,
}

impl Vm {
    fn new(
        generation: u64,
        peer: String,
        secret: Verifier,
        max_inflight: usize,
    ) -> (Arc<Self>, mpsc::Receiver<Message>) {
        let (to_vm, outbound) = mpsc::channel(TO_VM_QUEUE);
        let vm = Arc::new(Self {
            generation,
            peer,
            since: Instant::now(),
            secret,
            to_vm,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            close_code: AtomicU64::new(0),
            closed_signal: watch::channel(false).0,
            ready: AtomicBool::new(false),
            server_info: Mutex::new(None),
            max_inflight,
        });
        (vm, outbound)
    }

    /// Ask the socket to close with `code`. The first code wins.
    fn close(&self, code: u16) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.close_code.store(u64::from(code), Ordering::Release);
        self.closed_signal.send_replace(true);
        // Dropping the senders wakes every waiter with `Disconnected`.
        self.pending.lock().clear();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn code(&self) -> u16 {
        self.close_code.load(Ordering::Acquire) as u16
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

/// The slot and the secret that may occupy it, under one lock.
struct Slot {
    vm: Option<Arc<Vm>>,
    secret: Verifier,
}

pub struct Hub {
    slot: Mutex<Slot>,
    generation: AtomicU64,
    max_inflight: usize,
    audit: Audit,
}

impl Hub {
    pub fn new(max_inflight: usize, vm_secret: Verifier, audit: Audit) -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(Slot {
                vm: None,
                secret: vm_secret,
            }),
            generation: AtomicU64::new(0),
            max_inflight,
            audit,
        })
    }

    fn current(&self) -> Option<Arc<Vm>> {
        self.slot.lock().vm.clone().filter(|vm| !vm.is_closed())
    }

    fn ready_vm(&self) -> Option<Arc<Vm>> {
        self.current().filter(|vm| vm.ready.load(Ordering::Acquire))
    }

    /// A socket is attached (handshake possibly still running).
    pub fn is_attached(&self) -> bool {
        self.current().is_some()
    }

    /// Attached and the MCP handshake completed: calls will be forwarded.
    pub fn is_ready(&self) -> bool {
        self.ready_vm().is_some()
    }

    pub fn status(&self) -> Value {
        match self.current() {
            Some(vm) => vm.status(),
            None => json!({ "attached": false, "ready": false }),
        }
    }

    /// Forward one JSON-RPC request to the VM; the response carries the VM's
    /// (rewritten) id — callers restore their own. A VM that has not finished
    /// the MCP handshake counts as not attached, so nothing ever reaches it
    /// before `initialize`.
    pub async fn call(&self, request: Value, timeout: Duration) -> Result<Value, CallError> {
        let vm = self.ready_vm().ok_or(CallError::NotAttached)?;
        vm.call(request, timeout).await
    }

    /// Install the VM verifier from a reload. An attached VM that presented a
    /// different secret is closed with `4003`.
    pub fn set_vm_secret(&self, secret: Verifier) {
        let mut slot = self.slot.lock();
        slot.secret = secret;
        if let Some(vm) = slot.vm.as_ref().filter(|vm| !vm.is_closed()) {
            if !vm.secret.matches(&slot.secret) {
                self.audit.event(
                    "vm_revoked",
                    json!({ "peer": vm.peer, "generation": vm.generation }),
                );
                vm.close(close_code::REVOKED);
            }
        }
    }

    pub fn close_all(&self, code: u16) {
        if let Some(vm) = self.slot.lock().vm.take() {
            vm.close(code);
        }
    }

    /// Take the slot for `vm`, evicting any incumbent, unless the secret it
    /// authenticated with was rotated out after the upgrade check. Returns the
    /// evicted VM.
    fn install(&self, vm: &Arc<Vm>) -> Result<Option<Arc<Vm>>, ()> {
        let mut slot = self.slot.lock();
        if !vm.secret.matches(&slot.secret) {
            return Err(());
        }
        Ok(slot.vm.replace(vm.clone()))
    }

    /// Install an authenticated socket as the VM and serve it until it closes.
    pub async fn serve(self: &Arc<Self>, socket: WebSocket, peer: String, secret: Verifier) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let (vm, mut outbound) = Vm::new(generation, peer.clone(), secret, self.max_inflight);

        let (mut sink, mut stream) = socket.split();
        match self.install(&vm) {
            Ok(Some(old)) => {
                self.audit.event(
                    "vm_takeover",
                    json!({ "old_peer": old.peer, "old_generation": old.generation,
                            "new_peer": peer, "new_generation": generation }),
                );
                old.close(close_code::TAKEOVER);
            }
            Ok(None) => {}
            Err(()) => {
                // Authenticated against a secret that a reload has since rotated.
                self.audit.event(
                    "vm_revoked",
                    json!({ "peer": peer, "generation": generation, "at": "attach" }),
                );
                let _ = sink
                    .send(Message::Close(Some(CloseFrame {
                        code: close_code::REVOKED,
                        reason: close_reason(close_code::REVOKED).into(),
                    })))
                    .await;
                return;
            }
        }
        self.audit.event(
            "vm_attach",
            json!({ "peer": peer, "generation": generation }),
        );
        tracing::info!(%peer, generation, "VM attached");

        let writer_vm = vm.clone();
        let mut writer_closed = vm.closed_signal.subscribe();
        let mut writer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = async { let _ = writer_closed.wait_for(|closed| *closed).await; } => {
                        let code = writer_vm.code();
                        let _ = sink
                            .send(Message::Close(Some(CloseFrame {
                                code,
                                reason: close_reason(code).into(),
                            })))
                            .await;
                        break;
                    }
                    message = outbound.recv() => {
                        let Some(message) = message else { break };
                        if sink.send(message).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = sink.close().await;
        });

        // We are the MCP client on this socket: handshake before anything else
        // is forwarded (`call` refuses until `ready`). A VM that will not
        // handshake is closed, so its daemon logs it and redials instead of
        // sitting attached and useless.
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
            match handshake.call(init, HANDSHAKE_TIMEOUT).await {
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
                    tracing::warn!(peer = %handshake.peer, ?response, "VM refused initialize");
                    handshake.close(close_code::HANDSHAKE_FAILED);
                }
                Err(error) => {
                    tracing::warn!(peer = %handshake.peer, ?error, "MCP initialize toward the VM failed");
                    handshake.close(close_code::HANDSHAKE_FAILED);
                }
            }
        });

        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping.tick().await;
        let mut silent: u32 = 0;
        let mut reader_closed = vm.closed_signal.subscribe();
        loop {
            tokio::select! {
                frame = stream.next() => {
                    let Some(Ok(frame)) = frame else { break };
                    silent = 0;
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
                    silent += 1;
                    if silent >= MAX_SILENT_INTERVALS {
                        tracing::info!(%peer, "VM silent past the ping budget");
                        break;
                    }
                    let _ = vm.to_vm.try_send(Message::Ping(Vec::new().into()));
                }
                _ = async { let _ = reader_closed.wait_for(|closed| *closed).await; } => break,
            }
            if vm.is_closed() {
                break;
            }
        }

        vm.close(close_code::NORMAL);
        {
            let mut slot = self.slot.lock();
            if slot
                .vm
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &vm))
            {
                slot.vm = None;
            }
        }
        let _ = tokio::time::timeout(WRITER_GRACE, &mut writer).await;
        writer.abort();
        let code = vm.code();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(secret: &str) -> Arc<Vm> {
        Vm::new(1, "test".into(), Verifier::of_secret(secret), 8).0
    }

    #[test]
    fn install_refuses_a_secret_rotated_out_after_the_upgrade_check() {
        let hub = Hub::new(8, Verifier::of_secret("old"), Audit::null());
        // Upgrade authenticated with "old" ...
        let late = vm("old");
        // ... then SIGHUP rotates before the socket takes the slot.
        hub.set_vm_secret(Verifier::of_secret("new"));
        assert!(hub.install(&late).is_err());
        assert!(!hub.is_attached());
        assert!(hub.install(&vm("new")).is_ok());
    }

    #[test]
    fn rotation_closes_an_installed_vm_on_a_stale_secret_only() {
        let hub = Hub::new(8, Verifier::of_secret("a"), Audit::null());
        let attached = vm("a");
        hub.install(&attached).unwrap();
        hub.set_vm_secret(Verifier::of_secret("a"));
        assert!(!attached.is_closed(), "same secret must not evict");
        hub.set_vm_secret(Verifier::of_secret("b"));
        assert!(attached.is_closed());
        assert_eq!(attached.code(), close_code::REVOKED);
    }

    #[test]
    fn first_close_code_wins_and_pending_calls_are_failed() {
        let v = vm("a");
        let (tx, rx) = oneshot::channel();
        v.pending.lock().insert(1, tx);
        v.close(close_code::TAKEOVER);
        v.close(close_code::NORMAL);
        assert_eq!(v.code(), close_code::TAKEOVER);
        assert!(v.pending.lock().is_empty());
        drop(rx);
    }
}
