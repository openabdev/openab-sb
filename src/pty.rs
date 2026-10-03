//! Lend the VM to an openab-pty session, with no change to openab-pty.
//!
//! openab-pty's tools plane (`CLIENT-CONTRACT.md` §9) expects the machine with
//! the hands to dial `WS /tools/attach/{session}` and act as an MCP server on
//! that socket. The switchboard plays that part: it dials the pod, answers the
//! pod's MCP requests through the same [`Mcp`] surface Connect uses, under this
//! attach's own allowlist. The coding CLI in the session then reaches the VM via
//! its usual `$OPENAB_TOOLS_MCP_URL`.
//!
//! ```text
//!   CLI ─► openab-pty ◄── WS /tools/attach/S ── openab-sb ◄── WS ── VM
//!          (MCP client)     we dial, Bearer      (MCP server)
//! ```

use crate::audit::Audit;
use crate::config::PtyAttach;
use crate::mcp::Mcp;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// The one application close code after which openab-pty wants a redial
/// (`4006`, runtime replaced). Every other `4xxx` means stop (§9.2): grant
/// expired or revoked, replaced by another dialer, session ended, or a code
/// this build does not know yet — guessing "retry" there would fight the pod.
const REDIAL_CODE: u16 = 4006;
/// Requests from one pod handled concurrently; past this the pod gets
/// `-32002` at once. Matches openab-pty's own per-session cap.
const MAX_CONCURRENT_POD_REQUESTS: usize = 64;
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A session that stayed up this long resets the backoff.
const STABLE_AFTER: Duration = Duration::from_secs(60);
/// The pod pings every 20 s; hearing nothing for this long means the path is dead.
const IDLE_LIMIT: Duration = Duration::from_secs(70);
const KEEPALIVE: Duration = Duration::from_secs(20);
const MAX_POD_FRAME_BYTES: usize = 4 * 1024 * 1024;

enum Ended {
    /// Closed by the pod with this code (or `None` for a plain drop).
    Closed(Option<u16>),
    /// The upgrade was refused with this HTTP status.
    Refused(u16),
    /// Could not connect at all.
    Failed(String),
}

pub fn spawn(mcp: Mcp, attach: PtyAttach, audit: Audit) -> tokio::task::JoinHandle<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::spawn(run(mcp, attach, audit))
}

async fn run(mcp: Mcp, attach: PtyAttach, audit: Audit) {
    let name = attach.principal.name.clone();
    let mut backoff = BACKOFF_START;
    loop {
        let started = Instant::now();
        let ended = dial_once(&mcp, &attach, &audit).await;
        let wait = match &ended {
            Ended::Closed(Some(code)) if is_stop_code(*code) => {
                tracing::info!(attach = %name, code, "openab-pty ended the attach; not redialling");
                audit.event(
                    "pty_attach_stopped",
                    json!({ "attach": name, "code": code }),
                );
                return;
            }
            Ended::Closed(code) => {
                if started.elapsed() >= STABLE_AFTER {
                    backoff = BACKOFF_START;
                }
                tracing::info!(attach = %name, ?code, "openab-pty attach closed; redialling");
                backoff
            }
            // 401 = no grant, wrong secret, or the pod was replaced. A human
            // re-mints and rewrites `secret_file`; poll slowly (the pod throttles
            // at five failed upgrades a minute).
            Ended::Refused(status) => {
                tracing::warn!(attach = %name, status, "openab-pty refused the attach; waiting for a fresh grant");
                audit.event(
                    "pty_attach_refused",
                    json!({ "attach": name, "status": status }),
                );
                BACKOFF_MAX
            }
            // Backoff caps at a minute, so warning each time stays bounded and a
            // wrong URL or a missing secret_file is visible at the default level.
            Ended::Failed(error) => {
                tracing::warn!(attach = %name, %error, "openab-pty dial failed");
                backoff
            }
        };
        tokio::time::sleep(jitter(wait)).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

async fn dial_once(mcp: &Mcp, attach: &PtyAttach, audit: &Audit) -> Ended {
    // Re-read every dial so a rotated secret heals without a restart.
    let secret = match std::fs::read_to_string(&attach.secret_file) {
        Ok(text) => text.trim().to_owned(),
        Err(error) => return Ended::Failed(format!("{}: {error}", attach.secret_file.display())),
    };
    let mut request = match attach.url.as_str().into_client_request() {
        Ok(request) => request,
        Err(error) => return Ended::Failed(error.to_string()),
    };
    let Ok(value) = HeaderValue::from_str(&format!("Bearer {secret}")) else {
        return Ended::Failed("secret_file holds characters invalid in a header".into());
    };
    request.headers_mut().insert("authorization", value);

    let mut ws_config = WebSocketConfig::default();
    ws_config.max_message_size = Some(MAX_POD_FRAME_BYTES);
    ws_config.max_frame_size = Some(MAX_POD_FRAME_BYTES);
    let socket =
        match tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false).await {
            Ok((socket, _)) => socket,
            Err(WsError::Http(response)) => return Ended::Refused(response.status().as_u16()),
            Err(error) => return Ended::Failed(error.to_string()),
        };

    let name = attach.principal.name.clone();
    audit.event("pty_attach", json!({ "attach": name }));
    tracing::info!(attach = %name, "lent the VM to an openab-pty session");

    let (mut sink, mut stream) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_POD_REQUESTS));
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await;
    let mut last_heard = Instant::now();
    let ended = loop {
        tokio::select! {
            frame = stream.next() => {
                let frame = match frame {
                    Some(Ok(frame)) => frame,
                    Some(Err(_)) | None => break Ended::Closed(None),
                };
                last_heard = Instant::now();
                let value = match frame {
                    Message::Text(text) => serde_json::from_str::<Value>(&text).ok(),
                    Message::Binary(bytes) => serde_json::from_slice::<Value>(&bytes).ok(),
                    Message::Close(frame) => break Ended::Closed(frame.map(|f| u16::from(f.code))),
                    _ => None,
                };
                // Requests from the pod run concurrently: a slow screenshot must
                // not hold up a quick `tools/list`.
                if let Some(request) = value.filter(|v| v.get("method").is_some()) {
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        if let Some(id) = request.get("id").cloned() {
                            let busy = crate::hub::rpc_error(id, -32002, "too many requests in flight on this attach");
                            let _ = out_tx.try_send(Message::Text(busy.to_string().into()));
                        }
                        continue;
                    };
                    let mcp = mcp.clone();
                    let principal = attach.principal.clone();
                    let out = out_tx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Some(response) = mcp.handle(&principal, request).await {
                            let _ = out.send(Message::Text(response.to_string().into())).await;
                        }
                    });
                }
            }
            _ = keepalive.tick() => {
                if last_heard.elapsed() > IDLE_LIMIT {
                    break Ended::Closed(None);
                }
                // Also flushes any pong tungstenite queued while reading. Never
                // block the read loop on a full queue: skip this ping instead.
                let _ = out_tx.try_send(Message::Ping(Vec::new().into()));
            }
        }
    };
    drop(out_tx);
    writer.abort();
    audit.event(
        "pty_detach",
        json!({ "attach": name, "code": match &ended { Ended::Closed(c) => *c, _ => None } }),
    );
    ended
}

fn is_stop_code(code: u16) -> bool {
    (4000..5000).contains(&code) && code != REDIAL_CODE
}

fn jitter(base: Duration) -> Duration {
    let mut raw = [0u8; 2];
    let spread = if getrandom::fill(&mut raw).is_ok() {
        u16::from_le_bytes(raw) as f64 / u16::MAX as f64
    } else {
        0.5
    };
    // ±20 %
    base.mul_f64(0.8 + 0.4 * spread)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_on_every_4xxx_except_runtime_replaced() {
        for code in [4001, 4002, 4003, 4004, 4005, 4010, 4999] {
            assert!(is_stop_code(code), "{code}");
        }
        for code in [4006, 1000, 1001, 1006, 1011] {
            assert!(!is_stop_code(code), "{code}");
        }
    }
}
