//! Lend one computer to an openab-pty session, with no change to openab-pty.
//!
//! openab-pty's tools plane (`CLIENT-CONTRACT.md` §9) expects the machine with
//! the hands to dial `WS /tools/attach/{session}` and act as an MCP server on
//! that socket. The switchboard plays that part: it dials the pod, answers the
//! pod's MCP requests through the same [`Mcp`] surface Connect uses, under this
//! attach's own allowlist on the computer named in `[[pty_attach]].computer`.
//! The coding CLI in the session then reaches that computer via its usual
//! `$OPENAB_TOOLS_MCP_URL`.
//!
//! ```text
//!   CLI ─► openab-pty ◄── WS /tools/attach/S ── openab-sb ◄── WS ── computer
//!          (MCP client)     we dial, Bearer      (MCP server)
//! ```

use crate::audit::Audit;
use crate::config::{Caller, PtyAttach};
use crate::mcp::Mcp;
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::path::PathBuf;
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

/// One running `[[pty_attach]]`: what it dials, and the policy it serves the
/// pod with.
///
/// The policy is behind a lock and read **per request**, not once per process.
/// A computer's name is a label the operator may change by `SIGHUP` (the
/// verifier is the identity), and the slot is looked up by name on every call —
/// so an attacher that cached its [`Caller`] would keep asking for a computer
/// that no longer exists and answer the pod's CLI "the VM is not connected"
/// for ever.
pub struct Attacher {
    /// The attach's name, which is what a reloaded block is matched by.
    pub name: String,
    /// Fixed for the life of the process: a live socket is dialled, so
    /// repointing it needs a restart (ADR Reload).
    url: String,
    secret_file: PathBuf,
    caller: RwLock<Caller>,
}

impl Attacher {
    fn new(attach: &PtyAttach) -> Option<Self> {
        // The attach names exactly one computer (the loader enforces it), so
        // `None` here is a config the loader should have refused.
        let caller = attach.principal.resolve(None)?;
        Some(Self {
            name: attach.principal.name.clone(),
            url: attach.url.clone(),
            secret_file: attach.secret_file.clone(),
            caller: RwLock::new(caller),
        })
    }

    /// The policy for one request. A reload may swap it between two frames on
    /// the same socket, which is the point.
    fn caller(&self) -> Caller {
        self.caller.read().clone()
    }
}

/// Apply a reloaded `[[pty_attach]]` list to the attachers already running.
///
/// Names are unique across a config, so one block matches at most one
/// attacher. What a reload can and cannot do, per the ADR's Reload table:
///
/// - `computer`, `tools`, `max_inflight` changed → swapped here, in force from
///   that attach's next request. This is what keeps a same-verifier rename from
///   cutting a pod off its computer.
/// - `url` or `secret_file` changed, a block added, a block removed → the live
///   socket is already dialled at the old URL with the old secret, so these
///   still need a restart. Each one is reported at `warn`, because nothing else
///   would show that the file on disk and the running attach disagree.
pub fn relabel(attachers: &[Arc<Attacher>], fresh: &[PtyAttach]) {
    for attacher in attachers {
        let Some(block) = fresh.iter().find(|p| p.principal.name == attacher.name) else {
            tracing::warn!(attach = %attacher.name,
                               "[[pty_attach]] is gone from the config but still dialling under \
                                its old policy; restart to stop it");
            continue;
        };
        // The socket was dialled with the old url and secret, so those wait for a
        // restart. The policy still follows the reload: skipping it would leave
        // a renamed computer unreachable from this pod until then.
        if block.url != attacher.url || block.secret_file != attacher.secret_file {
            tracing::warn!(attach = %attacher.name,
                           "[[pty_attach]] `url` or `secret_file` changed; the live attach keeps \
                            dialling the old one until a restart (its computer and tools are \
                            updated now)");
        }
        let Some(caller) = block.principal.resolve(None) else {
            tracing::warn!(attach = %attacher.name,
                           "reloaded [[pty_attach]] reaches no computer; keeping its old policy");
            continue;
        };
        let mut live = attacher.caller.write();
        if live.computer != caller.computer {
            tracing::info!(attach = %attacher.name, from = %live.computer, to = %caller.computer,
                           "[[pty_attach]] now lends another computer");
        }
        *live = caller;
    }
    for block in fresh {
        if !attachers.iter().any(|a| a.name == block.principal.name) {
            tracing::warn!(attach = %block.principal.name,
                           "new [[pty_attach]] needs a restart before it is dialled");
        }
    }
}

/// Start dialling for one `[[pty_attach]]`. `None` means the block reaches no
/// computer, which the loader should already have refused.
pub fn spawn(
    mcp: Mcp,
    attach: PtyAttach,
    audit: Audit,
) -> Option<(Arc<Attacher>, tokio::task::JoinHandle<()>)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(attacher) = Attacher::new(&attach) else {
        tracing::error!(attach = %attach.principal.name,
                        "pty attach reaches no computer; not dialling");
        return None;
    };
    let attacher = Arc::new(attacher);
    let handle = tokio::spawn(run(mcp, attacher.clone(), audit));
    Some((attacher, handle))
}

async fn run(mcp: Mcp, attacher: Arc<Attacher>, audit: Audit) {
    let name = attacher.name.clone();
    let mut backoff = BACKOFF_START;
    loop {
        let started = Instant::now();
        let ended = dial_once(&mcp, &attacher, &audit).await;
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
            Ended::Refused(status) if is_credential_refusal(*status) => {
                tracing::warn!(attach = %name, status, "openab-pty refused the attach; waiting for a fresh grant");
                audit.event(
                    "pty_attach_refused",
                    json!({ "attach": name, "status": status }),
                );
                BACKOFF_MAX
            }
            // Any other status came from whatever fronts the pod (a 502 from
            // `tailscale serve` while the pod restarts): a path fault, not a
            // missing grant, so redial on the normal backoff.
            Ended::Refused(status) => {
                tracing::warn!(attach = %name, status, "openab-pty upgrade failed; redialling");
                backoff
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

async fn dial_once(mcp: &Mcp, attacher: &Arc<Attacher>, audit: &Audit) -> Ended {
    // Re-read every dial so a rotated secret heals without a restart.
    let secret = match std::fs::read_to_string(&attacher.secret_file) {
        Ok(text) => text.trim().to_owned(),
        Err(error) => return Ended::Failed(format!("{}: {error}", attacher.secret_file.display())),
    };
    let mut request = match attacher.url.as_str().into_client_request() {
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

    let name = attacher.name.clone();
    // Only a label for the audit line: the policy this socket serves is read
    // again for every request below.
    let lent = attacher.caller().computer;
    audit.event("pty_attach", json!({ "attach": name, "computer": lent }));
    tracing::info!(attach = %name, computer = %lent,
                   "lent a computer to an openab-pty session");

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
                    // Per request, not per socket: a SIGHUP between two frames
                    // moves this call onto the computer the config now names.
                    let caller = attacher.caller();
                    let out = out_tx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Some(response) = mcp.handle(&caller, request).await {
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
        json!({ "attach": name, "computer": attacher.caller().computer,
                "code": match &ended { Ended::Closed(c) => *c, _ => None } }),
    );
    ended
}

fn is_stop_code(code: u16) -> bool {
    (4000..5000).contains(&code) && code != REDIAL_CODE
}

/// Upgrade refusals that only a fresh grant can fix: 401/403 (no grant, wrong
/// or expired secret) and 429 (the pod's upgrade throttle). Polling these fast
/// cannot help and keeps the throttle tripped.
fn is_credential_refusal(status: u16) -> bool {
    matches!(status, 401 | 403 | 429)
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
    use crate::auth::Verifier;
    use crate::config::Config;

    /// One `[[pty_attach]]` block as the loader produces it. Two computers are
    /// configured so that `computer` is meaningful and must be written out.
    fn block(computer: &str, url: &str, tools: &str) -> PtyAttach {
        let text = format!(
            r#"
[[computer]]
name = "m1"
secret_sha256 = "{a}"

[[computer]]
name = "macmini"
secret_sha256 = "{b}"

[[pty_attach]]
name = "kiro-1040"
computer = "{computer}"
url = "{url}"
secret_file = "/tmp/openab-sb-relabel-test.secret"
tools = {tools}
"#,
            a = Verifier::of_secret("secret-a").render(),
            b = Verifier::of_secret("secret-b").render(),
        );
        let mut parsed = Config::parse(&text).expect("test config");
        parsed.pty_attach.remove(0)
    }

    const URL: &str = "ws://127.0.0.1:9100/tools/attach/laptop";

    fn running(attach: &PtyAttach) -> Vec<Arc<Attacher>> {
        vec![Arc::new(Attacher::new(attach).expect("resolves"))]
    }

    /// Renaming a computer by `SIGHUP` keeps its verifier and its socket, so
    /// the attach lending it must follow the label.
    #[test]
    fn a_reload_points_a_running_attach_at_the_renamed_computer() {
        let live = running(&block("m1", URL, r#"["*"]"#));
        assert_eq!(live[0].caller().computer, "m1");
        relabel(&live, &[block("macmini", URL, r#"["*"]"#)]);
        assert_eq!(live[0].caller().computer, "macmini");
    }

    #[test]
    fn a_reload_swaps_the_allowlist_and_the_per_caller_cap_too() {
        let live = running(&block("m1", URL, r#"["*"]"#));
        assert!(live[0].caller().tools.allows("bash"));
        relabel(&live, &[block("m1", URL, r#"["sys_info"]"#)]);
        let caller = live[0].caller();
        assert!(caller.tools.allows("sys_info"));
        assert!(!caller.tools.allows("bash"));
    }

    /// `url` and `secret_file` belong to the socket that is already dialled, so
    /// they wait for a restart. The policy (computer and tools) is not tied to
    /// the socket and still follows the reload: otherwise a computer renamed in
    /// the same edit would leave this pod asking for a name that no longer exists.
    #[test]
    fn a_changed_url_still_takes_the_new_policy() {
        let live = running(&block("m1", URL, r#"["*"]"#));
        relabel(
            &live,
            &[block(
                "macmini",
                "ws://127.0.0.1:9101/tools/attach/laptop",
                r#"["sys_info"]"#,
            )],
        );
        let caller = live[0].caller();
        assert_eq!(caller.computer, "macmini");
        assert!(!caller.tools.allows("bash"));
        assert_eq!(live[0].url, URL, "the dial target is not swapped live");
    }

    #[test]
    fn a_block_that_is_gone_leaves_its_running_attach_as_it_was() {
        let live = running(&block("m1", URL, r#"["*"]"#));
        relabel(&live, &[]);
        assert_eq!(live[0].caller().computer, "m1");
    }

    #[test]
    fn stops_on_every_4xxx_except_runtime_replaced() {
        for code in [4001, 4002, 4003, 4004, 4005, 4010, 4999] {
            assert!(is_stop_code(code), "{code}");
        }
        for code in [4006, 1000, 1001, 1006, 1011] {
            assert!(!is_stop_code(code), "{code}");
        }
    }

    #[test]
    fn only_credential_refusals_wait_for_a_fresh_grant() {
        for status in [401, 403, 429] {
            assert!(is_credential_refusal(status), "{status}");
        }
        // A proxy in front of the pod answering while it restarts is a path
        // fault: normal backoff, not the one-minute grant poll.
        for status in [400, 404, 500, 502, 503, 504] {
            assert!(!is_credential_refusal(status), "{status}");
        }
    }
}
