//! The switchboard's only stateful part: one slot per configured computer, each
//! with the pending-request table for the socket that computer dialled in on.
//!
//! Rules enforced here:
//!
//! 1. **The verifier is the identity; the name is a label.** A dialler presents
//!    a secret and nothing else, and that secret alone selects the slot. A
//!    reload that keeps a verifier and changes its name relabels the live
//!    socket and closes nothing.
//! 2. **One lock over the whole table.** Install, takeover and reload never
//!    interleave across computers, and a slow or dead computer cannot starve
//!    another: pending table, `max_inflight`, ping liveness and close handling
//!    are per slot.
//! 3. **One socket per computer, newest wins.** A second attach *with the same
//!    secret* replaces the first, which is closed with [`close_code::TAKEOVER`].
//!    The evicted socket's cleanup clears the slot only if it still holds *that*
//!    socket, and fails only *its own* pending calls.
//! 4. **The secret is re-resolved where the slot is taken.** A socket
//!    authenticated just before a reload is refused with `4003` if its verifier
//!    is gone, and installs under the new name if the verifier was relabelled.
//! 5. **Ids are ours on the wire.** Every forwarded request gets a fresh integer
//!    id; the caller's id is restored on the way back. Two callers that both send
//!    `id: 1` cannot collide.
//! 6. **Nothing is silent.** Timeout, overload, disconnect and a failed handshake
//!    each surface as a distinct error or close code; nothing is retried (a shell
//!    command is not idempotent).

use crate::audit::Audit;
use crate::auth::Verifier;
use crate::config::Computer;
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
    /// Another socket attached with this computer's secret; the dialer should stop.
    pub const TAKEOVER: u16 = 4002;
    /// The operator rotated or removed this computer's secret.
    pub const REVOKED: u16 = 4003;
    /// The computer did not complete the MCP handshake; redial with backoff.
    pub const HANDSHAKE_FAILED: u16 = 4005;
    /// Internal: the computer sent nothing for the whole liveness budget.
    /// Recorded in the audit line; the socket is dead, so nothing reaches the peer.
    pub const SILENT: u16 = 1011;
}

pub fn close_reason(code: u16) -> &'static str {
    match code {
        close_code::NORMAL => "normal closure",
        close_code::GOING_AWAY => "switchboard shutting down",
        close_code::TAKEOVER => "replaced by a newer attach",
        close_code::REVOKED => "VM secret revoked or rotated",
        close_code::HANDSHAKE_FAILED => "MCP initialize failed or timed out",
        close_code::SILENT => "no frame from the VM within the liveness budget",
        _ => "closed",
    }
}

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
/// Largest frame accepted from a computer. Screenshots are base64 images.
pub const MAX_VM_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const PING_INTERVAL: Duration = Duration::from_secs(20);
/// Closed once this many ping intervals pass with no frame of any kind from
/// the computer: 3 × 20 s = 60 s.
pub const MAX_SILENT_INTERVALS: u32 = 3;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const TO_VM_QUEUE: usize = 64;
/// How long a closing socket's writer may take to flush before it is dropped.
const WRITER_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    /// The computer is not attached (or has not finished the handshake);
    /// nothing was sent.
    NotAttached,
    /// An in-flight cap was reached — this computer's or this caller's share of
    /// it; nothing was sent.
    TooManyInFlight,
    /// Sent, but the computer did not answer in time. Outcome unknown.
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

/// One caller's outstanding calls on one socket, so that one caller filling the
/// socket cannot starve another.
struct Waiter {
    caller: String,
    reply: oneshot::Sender<Value>,
}

#[derive(Default)]
struct Pending {
    waiters: HashMap<u64, Waiter>,
    per_caller: HashMap<String, usize>,
}

impl Pending {
    fn len(&self) -> usize {
        self.waiters.len()
    }

    fn caller_len(&self, caller: &str) -> usize {
        self.per_caller.get(caller).copied().unwrap_or(0)
    }

    fn insert(&mut self, id: u64, caller: &str, reply: oneshot::Sender<Value>) {
        self.waiters.insert(
            id,
            Waiter {
                caller: caller.to_owned(),
                reply,
            },
        );
        *self.per_caller.entry(caller.to_owned()).or_insert(0) += 1;
    }

    fn remove(&mut self, id: u64) -> Option<oneshot::Sender<Value>> {
        let waiter = self.waiters.remove(&id)?;
        if let Some(count) = self.per_caller.get_mut(&waiter.caller) {
            *count -= 1;
            if *count == 0 {
                self.per_caller.remove(&waiter.caller);
            }
        }
        Some(waiter.reply)
    }

    /// Drop every waiter, waking each with `Disconnected`.
    fn clear(&mut self) {
        self.waiters.clear();
        self.per_caller.clear();
    }
}

/// Removes one id from a socket's pending table unless it is disarmed.
///
/// Every exit from [`Vm::call`] must give the caller its share back, and one of
/// those exits is not a `return` at all: when an HTTP caller goes away mid-call,
/// hyper drops the handler future while it awaits the reply. Without this guard
/// the [`Waiter`] would sit in `pending` — and in `per_caller` — until the
/// computer answered or the socket closed, so a caller could lock itself out of
/// its own `max_inflight` by cancelling.
///
/// Ids come from a monotonic counter and are never reused, so a late drop can
/// only ever remove its own entry; and [`Pending::remove`] on an id another
/// path already took is a no-op, so nothing is decremented twice.
struct PendingGuard<'a> {
    pending: &'a Mutex<Pending>,
    id: Option<u64>,
}

impl PendingGuard<'_> {
    /// The entry is gone already (the reply arrived and `on_frame` took it).
    fn disarm(&mut self) {
        self.id = None;
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.pending.lock().remove(id);
        }
    }
}

/// One attached computer socket.
pub struct Vm {
    /// The computer's current label. A reload can rename it under us.
    computer: Mutex<String>,
    generation: u64,
    peer: String,
    since: Instant,
    to_vm: mpsc::Sender<Message>,
    pending: Mutex<Pending>,
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
        computer: String,
        generation: u64,
        peer: String,
        max_inflight: usize,
    ) -> (Arc<Self>, mpsc::Receiver<Message>) {
        let (to_vm, outbound) = mpsc::channel(TO_VM_QUEUE);
        let vm = Arc::new(Self {
            computer: Mutex::new(computer),
            generation,
            peer,
            since: Instant::now(),
            to_vm,
            pending: Mutex::new(Pending::default()),
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

    fn name(&self) -> String {
        self.computer.lock().clone()
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

    /// This caller's share of the socket: its own `max_inflight` if it set one,
    /// else half of what the socket attached with, rounded up. A reload that
    /// changes the computer's limit does not move this until the next attach.
    fn caller_cap(&self, asked: Option<usize>) -> usize {
        asked.unwrap_or_else(|| self.max_inflight.div_ceil(2))
    }

    async fn call(
        &self,
        caller: &str,
        caller_cap: Option<usize>,
        mut request: Value,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        if self.is_closed() {
            return Err(CallError::NotAttached);
        }
        let cap = self.caller_cap(caller_cap);
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut pending = self.pending.lock();
            if pending.len() >= self.max_inflight || pending.caller_len(caller) >= cap {
                return Err(CallError::TooManyInFlight);
            }
            let id = self.next_id.fetch_add(1, Ordering::AcqRel);
            pending.insert(id, caller, tx);
            id
        };
        // From here every exit — including this future being dropped by a
        // caller that went away — returns the id and the caller's share.
        let mut guard = PendingGuard {
            pending: &self.pending,
            id: Some(id),
        };
        // `close` may have run between the check above and the insert.
        if self.is_closed() {
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
            Ok(Ok(response)) => {
                // `on_frame` removed the entry when it handed the reply over.
                guard.disarm();
                Ok(response)
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(CallError::Timeout),
        }
    }

    fn on_frame(&self, frame: Value) {
        let is_response = frame.get("result").is_some() || frame.get("error").is_some();
        if is_response {
            let Some(id) = frame.get("id").and_then(Value::as_u64) else {
                return;
            };
            if let Some(waiter) = self.pending.lock().remove(id) {
                let _ = waiter.send(frame);
            }
            return;
        }
        // A request from the computer: only `ping` is meaningful. Notifications drop.
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

    /// `show_internals` adds the socket peer and the in-flight count: another
    /// caller's activity and a forwarded identity header are not everyone's
    /// business.
    fn status(&self, show_internals: bool) -> Value {
        let mut status = json!({
            "computer": self.name(),
            "attached": true,
            "ready": self.ready.load(Ordering::Acquire),
            "attached_for_secs": self.since.elapsed().as_secs(),
            "max_in_flight": self.max_inflight,
            "server": self.server_info.lock().clone(),
        });
        if show_internals {
            let object = status.as_object_mut().expect("object");
            object.insert("peer".into(), json!(self.peer));
            object.insert("in_flight".into(), json!(self.pending.lock().len()));
        }
        status
    }
}

/// One computer: its label, the verifier that may occupy it, and the socket
/// currently in it.
struct Slot {
    name: String,
    secret: Verifier,
    max_inflight: usize,
    /// Per computer, unlike v1's hub-wide counter.
    generation: u64,
    vm: Option<Arc<Vm>>,
}

/// Every slot under one lock: install, takeover and reload are serialised
/// across computers, so no pair of them can interleave.
pub struct Hub {
    slots: Mutex<Vec<Slot>>,
    audit: Audit,
}

impl Hub {
    pub fn new(computers: &[Computer], audit: Audit) -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(
                computers
                    .iter()
                    .map(|c| Slot {
                        name: c.name.clone(),
                        secret: c.secret.clone(),
                        max_inflight: c.max_inflight,
                        generation: 0,
                        vm: None,
                    })
                    .collect(),
            ),
            audit,
        })
    }

    /// Does any configured computer accept this secret? Every verifier is
    /// compared with no early exit, so timing does not reveal which matched.
    pub fn accepts(&self, presented: &Verifier) -> bool {
        let slots = self.slots.lock();
        let mut found = false;
        for slot in slots.iter() {
            if slot.secret.matches(presented) {
                found = true;
            }
        }
        found
    }

    /// Configured computers, in config order.
    pub fn computer_names(&self) -> Vec<String> {
        self.slots.lock().iter().map(|s| s.name.clone()).collect()
    }

    pub fn computer_count(&self) -> usize {
        self.slots.lock().len()
    }

    pub fn exists(&self, computer: &str) -> bool {
        self.slots.lock().iter().any(|s| s.name == computer)
    }

    fn live(&self, computer: &str) -> Option<Arc<Vm>> {
        self.slots
            .lock()
            .iter()
            .find(|s| s.name == computer)
            .and_then(|s| s.vm.clone())
            .filter(|vm| !vm.is_closed())
    }

    fn ready_vm(&self, computer: &str) -> Option<Arc<Vm>> {
        self.live(computer)
            .filter(|vm| vm.ready.load(Ordering::Acquire))
    }

    /// A socket is attached (handshake possibly still running).
    pub fn is_attached(&self, computer: &str) -> bool {
        self.live(computer).is_some()
    }

    /// Attached and the MCP handshake completed: calls will be forwarded.
    pub fn is_ready(&self, computer: &str) -> bool {
        self.ready_vm(computer).is_some()
    }

    /// Unauthenticated `/readyz`: with one computer this is v1's answer, and
    /// with several it says only that *something* can serve — no names, no
    /// counts, and an intermittent computer does not make it flap.
    pub fn any_ready(&self) -> bool {
        let slots = self.slots.lock();
        slots.iter().any(|s| {
            s.vm.as_ref()
                .is_some_and(|vm| !vm.is_closed() && vm.ready.load(Ordering::Acquire))
        })
    }

    /// Peer and in-flight count are internals: only a `"*"` caller sees them,
    /// whatever the number of computers.
    ///
    /// This is the one exception to "nothing a v1 caller sees changes": a v1
    /// client's `tools = ["*"]` maps to `computers = { default = ["*"] }`, which
    /// is a named grant, not `"*"`, so `/status` and `vm_status` no longer carry
    /// another caller's activity or a forwarded identity header to it. See the
    /// ADR's Compatibility section.
    pub fn shows_internals(&self, wildcard: bool) -> bool {
        wildcard
    }

    pub fn status(&self, computer: &str, show_internals: bool) -> Value {
        match self.live(computer) {
            Some(vm) => vm.status(show_internals),
            None => json!({ "computer": computer, "attached": false, "ready": false }),
        }
    }

    /// Forward one JSON-RPC request to `computer`; the response carries the
    /// rewritten id — callers restore their own. A computer that has not
    /// finished the MCP handshake counts as not attached, so nothing ever
    /// reaches it before `initialize`.
    pub async fn call(
        &self,
        computer: &str,
        caller: &str,
        caller_cap: Option<usize>,
        request: Value,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        let vm = self.ready_vm(computer).ok_or(CallError::NotAttached)?;
        vm.call(caller, caller_cap, request, timeout).await
    }

    /// Install the computer table from a reload. Matching is by verifier:
    ///
    /// - same verifier, new name → the live socket is relabelled, nothing closes;
    /// - a verifier moved between names → the same relabel, not a revoke;
    /// - verifier gone (computer removed or rotated) → that socket closes with
    ///   `4003` and only its own in-flight calls fail;
    /// - new verifier → an empty slot that accepts an attach at once.
    ///
    /// `max_inflight` applies to the next attach; a live socket keeps the value
    /// it attached with.
    pub fn set_computers(&self, computers: &[Computer]) {
        let mut renamed = Vec::new();
        let gone = {
            let mut slots = self.slots.lock();
            let mut old = std::mem::take(&mut *slots);
            let mut fresh = Vec::with_capacity(computers.len());
            for computer in computers {
                match old.iter().position(|s| s.secret == computer.secret) {
                    Some(index) => {
                        let mut slot = old.remove(index);
                        if slot.name != computer.name {
                            let live = slot.vm.as_ref().filter(|vm| !vm.is_closed());
                            if let Some(vm) = live {
                                *vm.computer.lock() = computer.name.clone();
                            }
                            renamed.push(json!({
                                "from": slot.name,
                                "to": computer.name,
                                "attached": live.is_some(),
                                "generation": slot.generation,
                            }));
                            slot.name = computer.name.clone();
                        }
                        slot.max_inflight = computer.max_inflight;
                        fresh.push(slot);
                    }
                    None => fresh.push(Slot {
                        name: computer.name.clone(),
                        secret: computer.secret.clone(),
                        max_inflight: computer.max_inflight,
                        generation: 0,
                        vm: None,
                    }),
                }
            }
            *slots = fresh;
            old
        };
        for fields in renamed {
            self.audit.event("computer_renamed", fields);
        }
        for slot in gone {
            if let Some(vm) = slot.vm.filter(|vm| !vm.is_closed()) {
                self.audit.event(
                    "vm_revoked",
                    json!({ "computer": slot.name, "peer": vm.peer,
                            "generation": vm.generation }),
                );
                vm.close(close_code::REVOKED);
            }
        }
    }

    pub fn close_all(&self, code: u16) {
        let mut slots = self.slots.lock();
        for slot in slots.iter_mut() {
            if let Some(vm) = slot.vm.take() {
                vm.close(code);
            }
        }
    }

    /// Take the slot whose verifier matches, re-resolving the secret under the
    /// lock: an upgrade authenticated a moment before a reload lands here, and
    /// `None` means its verifier is gone (`4003`). The slot's current name and
    /// `max_inflight` are read here too, so a relabel before install is picked
    /// up rather than racing it.
    #[allow(clippy::type_complexity)]
    fn install(
        &self,
        peer: String,
        secret: Verifier,
    ) -> Option<(Arc<Vm>, mpsc::Receiver<Message>, Option<Arc<Vm>>)> {
        let mut slots = self.slots.lock();
        let mut matched = None;
        for (index, slot) in slots.iter().enumerate() {
            if slot.secret.matches(&secret) && matched.is_none() {
                matched = Some(index);
            }
        }
        let slot = &mut slots[matched?];
        slot.generation += 1;
        let (vm, outbound) = Vm::new(slot.name.clone(), slot.generation, peer, slot.max_inflight);
        let evicted = slot.vm.replace(vm.clone()).filter(|old| !old.is_closed());
        Some((vm, outbound, evicted))
    }

    /// Install an authenticated socket as its computer and serve it until it
    /// closes.
    pub async fn serve(self: &Arc<Self>, socket: WebSocket, peer: String, secret: Verifier) {
        let (mut sink, mut stream) = socket.split();
        let Some((vm, mut outbound, evicted)) = self.install(peer.clone(), secret) else {
            // Authenticated against a secret that a reload has since removed.
            self.audit
                .event("vm_revoked", json!({ "peer": peer, "at": "attach" }));
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: close_code::REVOKED,
                    reason: close_reason(close_code::REVOKED).into(),
                })))
                .await;
            return;
        };
        let computer = vm.name();
        let generation = vm.generation;
        if let Some(old) = evicted {
            self.audit.event(
                "vm_takeover",
                json!({ "computer": computer, "old_peer": old.peer,
                        "old_generation": old.generation, "new_peer": peer,
                        "new_generation": generation }),
            );
            old.close(close_code::TAKEOVER);
        }
        self.audit.event(
            "vm_attach",
            json!({ "computer": computer, "peer": peer, "generation": generation }),
        );
        tracing::info!(%computer, %peer, generation, "computer attached");

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
        // is forwarded (`call` refuses until `ready`). A computer that will not
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
            // `/` cannot occur in a configured name, so the handshake's slot in
            // the per-caller table can never be confused with a caller's.
            match handshake
                .call("openab-sb/handshake", Some(1), init, HANDSHAKE_TIMEOUT)
                .await
            {
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
                    tracing::warn!(peer = %handshake.peer, ?response, "computer refused initialize");
                    handshake.close(close_code::HANDSHAKE_FAILED);
                }
                // Already closed (takeover, drop, revoke): not a handshake fault.
                Err(_) if handshake.is_closed() => {}
                Err(error) => {
                    tracing::warn!(peer = %handshake.peer, ?error, "MCP initialize toward the computer failed");
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
                        tracing::info!(%peer, "computer silent past the ping budget");
                        vm.close(close_code::SILENT);
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
            // Only this socket's slot, and only if it still holds this socket:
            // a successor must never be cleared by its predecessor's cleanup.
            let mut slots = self.slots.lock();
            for slot in slots.iter_mut() {
                if slot
                    .vm
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &vm))
                {
                    slot.vm = None;
                }
            }
        }
        let _ = tokio::time::timeout(WRITER_GRACE, &mut writer).await;
        writer.abort();
        let code = vm.code();
        // The name as it stands now: a reload may have relabelled it while attached.
        let computer = vm.name();
        self.audit.event(
            "vm_detach",
            json!({ "computer": computer, "peer": peer, "generation": generation,
                    "code": code, "reason": close_reason(code),
                    "attached_for_secs": vm.since.elapsed().as_secs() }),
        );
        tracing::info!(%computer, %peer, generation, code, "computer detached");
    }
}

pub fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn computer(name: &str, secret: &str) -> Computer {
        Computer {
            name: name.to_owned(),
            secret: Verifier::of_secret(secret),
            max_inflight: 8,
        }
    }

    fn hub(computers: &[Computer]) -> Arc<Hub> {
        Hub::new(computers, Audit::null())
    }

    fn attach(hub: &Arc<Hub>, secret: &str) -> Option<Arc<Vm>> {
        hub.install("test".into(), Verifier::of_secret(secret))
            .map(|(vm, _outbound, _evicted)| vm)
    }

    #[test]
    fn install_refuses_a_secret_rotated_out_after_the_upgrade_check() {
        let hub = hub(&[computer("m1", "old")]);
        // SIGHUP rotates between the upgrade check and the install.
        hub.set_computers(&[computer("m1", "new")]);
        assert!(hub
            .install("late".into(), Verifier::of_secret("old"))
            .is_none());
        assert!(!hub.is_attached("m1"));
        assert!(attach(&hub, "new").is_some());
        assert!(hub.is_attached("m1"));
    }

    #[test]
    fn install_follows_a_relabel_that_landed_first() {
        let hub = hub(&[computer("default", "s")]);
        hub.set_computers(&[computer("macmini", "s")]);
        let vm = attach(&hub, "s").expect("the verifier is still configured");
        assert_eq!(vm.name(), "macmini");
        assert!(hub.is_attached("macmini"));
        assert!(!hub.exists("default"));
    }

    #[test]
    fn a_rename_keeps_the_socket_and_a_removal_revokes_only_its_own() {
        let hub = hub(&[computer("m1", "a"), computer("m2", "b")]);
        let one = attach(&hub, "a").unwrap();
        let two = attach(&hub, "b").unwrap();
        // Same verifier, new name: relabel, no close.
        hub.set_computers(&[computer("renamed", "a"), computer("m2", "b")]);
        assert!(!one.is_closed());
        assert_eq!(one.name(), "renamed");
        assert!(hub.is_attached("renamed"));
        // Verifiers swapped between the two names: still only relabels.
        hub.set_computers(&[computer("renamed", "b"), computer("m2", "a")]);
        assert!(!one.is_closed() && !two.is_closed());
        assert_eq!(one.name(), "m2");
        assert_eq!(two.name(), "renamed");
        // m2's verifier rotated: only that socket closes.
        hub.set_computers(&[computer("renamed", "b"), computer("m2", "c")]);
        assert!(one.is_closed());
        assert_eq!(one.code(), close_code::REVOKED);
        assert!(!two.is_closed());
        assert!(hub.is_attached("renamed"));
    }

    #[test]
    fn generation_is_per_computer_and_survives_a_rename() {
        let hub = hub(&[computer("m1", "a"), computer("m2", "b")]);
        assert_eq!(attach(&hub, "a").unwrap().generation, 1);
        assert_eq!(attach(&hub, "b").unwrap().generation, 1);
        assert_eq!(attach(&hub, "a").unwrap().generation, 2);
        hub.set_computers(&[computer("renamed", "a"), computer("m2", "b")]);
        assert_eq!(attach(&hub, "a").unwrap().generation, 3);
    }

    /// This covers [`Hub::install`] only: that taking a slot hands back *that*
    /// slot's incumbent and nothing else, which is why the close below is the
    /// test's own doing rather than the hub's. The production path — `serve`
    /// closing the evicted socket with `4002` while another computer keeps
    /// serving — is the e2e test `evicting_one_computer_leaves_the_other_attached`.
    #[test]
    fn install_returns_only_its_own_computers_incumbent() {
        let hub = hub(&[computer("m1", "a"), computer("m2", "b")]);
        let first = attach(&hub, "a").unwrap();
        let other = attach(&hub, "b").unwrap();
        let (_second, _out, evicted) = hub.install("new".into(), Verifier::of_secret("a")).unwrap();
        evicted
            .expect("the incumbent on m1")
            .close(close_code::TAKEOVER);
        assert!(first.is_closed());
        assert_eq!(first.code(), close_code::TAKEOVER);
        assert!(!other.is_closed(), "m2 is untouched");
        assert!(hub.is_attached("m1") && hub.is_attached("m2"));
    }

    #[test]
    fn accepts_any_configured_secret_and_nothing_else() {
        let hub = hub(&[computer("m1", "a"), computer("m2", "b")]);
        assert!(hub.accepts(&Verifier::of_secret("a")));
        assert!(hub.accepts(&Verifier::of_secret("b")));
        assert!(!hub.accepts(&Verifier::of_secret("c")));
        assert_eq!(hub.computer_names(), vec!["m1", "m2"]);
        assert_eq!(hub.computer_count(), 2);
    }

    #[test]
    fn a_new_computer_gets_its_slot_at_once() {
        let hub = hub(&[computer("m1", "a")]);
        assert!(attach(&hub, "b").is_none());
        hub.set_computers(&[computer("m1", "a"), computer("m2", "b")]);
        assert!(attach(&hub, "b").is_some());
        assert!(hub.is_attached("m2"));
    }

    #[test]
    fn first_close_code_wins_and_pending_calls_are_failed() {
        let hub = hub(&[computer("m1", "a")]);
        let vm = attach(&hub, "a").unwrap();
        let (tx, mut rx) = oneshot::channel::<Value>();
        vm.pending.lock().insert(1, "someone", tx);
        vm.close(close_code::TAKEOVER);
        vm.close(close_code::NORMAL);
        assert_eq!(vm.code(), close_code::TAKEOVER);
        assert_eq!(vm.pending.lock().len(), 0);
        // The waiter is not merely forgotten: its sender was dropped, which is
        // what `Vm::call` turns into `-32004` for the caller.
        assert!(
            matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)),
            "the pending waiter was never woken"
        );
    }

    /// An HTTP caller that goes away mid-call has its future dropped by hyper,
    /// and nothing else ever tells the switchboard. If the id stayed in
    /// `pending`, that caller would be locked out of its own share until the
    /// computer answered or the socket closed.
    #[tokio::test]
    async fn a_dropped_call_future_gives_the_caller_its_share_back() {
        let hub = hub(&[computer("m1", "a")]);
        // Keep the outbound receiver alive, or the send fails before the await.
        let (vm, _outbound, _) = hub
            .install("test".into(), Verifier::of_secret("a"))
            .expect("a slot");
        vm.ready.store(true, Ordering::Release);

        let call = vm.clone();
        let task = tokio::spawn(async move {
            call.call(
                "muse",
                Some(1),
                json!({ "jsonrpc": "2.0", "method": "tools/call" }),
                Duration::from_secs(600),
            )
            .await
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while vm.pending.lock().caller_len("muse") == 0 {
            assert!(Instant::now() < deadline, "the call never went in flight");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(vm.pending.lock().len(), 1);

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            vm.pending.lock().caller_len("muse"),
            0,
            "the caller's share leaked"
        );
        assert_eq!(vm.pending.lock().len(), 0, "the pending entry leaked");

        // And the cap is usable again: at `Some(1)` a leaked entry would have
        // made this second call `TooManyInFlight` instead.
        let again = vm.call(
            "muse",
            Some(1),
            json!({ "jsonrpc": "2.0", "method": "ping" }),
            Duration::from_millis(50),
        );
        assert_eq!(again.await, Err(CallError::Timeout));
    }

    #[test]
    fn per_caller_counts_are_released_with_their_waiter() {
        let mut pending = Pending::default();
        let (a, _ra) = oneshot::channel();
        let (b, _rb) = oneshot::channel();
        pending.insert(1, "muse", a);
        pending.insert(2, "muse", b);
        assert_eq!(pending.caller_len("muse"), 2);
        pending.remove(1);
        assert_eq!(pending.caller_len("muse"), 1);
        pending.remove(2);
        assert_eq!(pending.caller_len("muse"), 0);
        assert!(pending.per_caller.is_empty(), "no leak per caller name");
    }

    #[test]
    fn the_default_caller_cap_is_half_the_socket_rounded_up() {
        let (vm, _out) = Vm::new("m1".into(), 1, "p".into(), 8);
        assert_eq!(vm.caller_cap(None), 4);
        assert_eq!(vm.caller_cap(Some(7)), 7);
        let (odd, _out) = Vm::new("m1".into(), 1, "p".into(), 1);
        assert_eq!(odd.caller_cap(None), 1, "never zero");
        let (three, _out) = Vm::new("m1".into(), 1, "p".into(), 3);
        assert_eq!(three.caller_cap(None), 2, "rounded up");
    }

    #[test]
    fn status_hides_internals_unless_the_caller_is_the_owner() {
        let hub = hub(&[computer("m1", "a"), computer("m2", "b")]);
        let open = hub.status("m1", true);
        assert_eq!(open["attached"], false);
        assert_eq!(open["computer"], "m1");
        let vm = attach(&hub, "a").unwrap();
        let shown = vm.status(true);
        assert!(shown.get("peer").is_some() && shown.get("in_flight").is_some());
        let hidden = vm.status(false);
        assert!(hidden.get("peer").is_none() && hidden.get("in_flight").is_none());
        assert_eq!(hidden["max_in_flight"], 8);
        assert_eq!(hidden["computer"], "m1");
        // Only a `"*"` caller sees internals.
        assert!(hub.shows_internals(true));
        assert!(!hub.shows_internals(false));
    }

    /// The ADR's rule is the caller's grant, not the fleet size: a lone
    /// computer does not turn a named grant into the owner's view. This is the
    /// documented exception to v1 compatibility.
    #[test]
    fn one_computer_still_hides_internals_from_a_named_caller() {
        let hub = hub(&[computer("default", "a")]);
        assert!(!hub.shows_internals(false));
        assert!(hub.shows_internals(true));
    }

    #[test]
    fn a_reloaded_max_inflight_applies_to_the_next_attach_only() {
        let hub = hub(&[computer("m1", "a")]);
        let live = attach(&hub, "a").unwrap();
        assert_eq!(live.max_inflight, 8);
        let mut tighter = computer("m1", "a");
        tighter.max_inflight = 2;
        hub.set_computers(&[tighter]);
        assert!(!live.is_closed(), "a limit change closes nothing");
        assert_eq!(live.max_inflight, 8, "the live socket keeps its value");
        // The next attach picks the new one up.
        let next = attach(&hub, "a").unwrap();
        assert_eq!(next.max_inflight, 2);
        assert_eq!(next.caller_cap(None), 1);
    }

    /// The audit is the only record that a relabel happened rather than a
    /// revoke, so the line itself is part of the contract.
    #[test]
    fn a_rename_is_audited_as_computer_renamed() {
        let path = std::env::temp_dir().join(format!(
            "openab-sb-hub-audit-{}-{:?}.jsonl",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        let hub = Hub::new(
            &[computer("default", "a")],
            Audit::open(Some(&path), false).unwrap(),
        );
        let vm = attach(&hub, "a").unwrap();
        hub.set_computers(&[computer("macmini", "a")]);
        assert!(!vm.is_closed());
        let lines: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let _ = std::fs::remove_file(&path);
        let renamed = lines
            .iter()
            .find(|l| l["event"] == "computer_renamed")
            .unwrap_or_else(|| panic!("no computer_renamed in {lines:?}"));
        assert_eq!(renamed["from"], "default");
        assert_eq!(renamed["to"], "macmini");
        assert_eq!(renamed["attached"], true);
        assert!(
            !lines.iter().any(|l| l["event"] == "vm_revoked"),
            "a relabel must not read as a revoke: {lines:?}"
        );
    }
}
