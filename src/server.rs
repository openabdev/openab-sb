//! HTTP surface: one listener, one endpoint per computer.
//!
//! ```text
//!   POST /mcp              MCP for the caller's default_computer            Bearer <client token>
//!   POST /mcp/{computer}   MCP for one computer                            Bearer <client token>
//!   GET  /computers        the computers this caller may use, and liveness  Bearer <client token>
//!   GET  /vm/attach        southbound WebSocket, a computer dials in        Bearer <computer secret>
//!   GET  /healthz          200 while the switchboard runs (no auth). Connect probes this
//!                          before calling `sys_info`, so it must not depend on a computer
//!   GET  /readyz           200 when any computer is ready, else 503 (no auth, no names)
//!   GET  /readyz/{computer} 200 when that computer is ready, else 503       Bearer <client token>
//!   GET  /status           switchboard + per-computer state as JSON         Bearer <client token>
//! ```
//!
//! Order of checks on every northbound request: the bearer token first, so
//! `/mcp/{unknown}` without a token tells nothing; then the computer against
//! the caller's allowlist, where "not allowed" and "unknown" are the same
//! answer; then tool policy.

use crate::audit::Audit;
use crate::auth::{bearer, Verifier};
use crate::config::{Auth, Caller, Config, Principal, PtyAttach};
use crate::hub::{rpc_error, Hub, MAX_VM_FRAME_BYTES};
use crate::mcp::Mcp;
use crate::pty::Attacher;
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

/// Largest northbound request body. Tool arguments are small; screenshots flow
/// the other way.
pub const MAX_MCP_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct App {
    mcp: Mcp,
    auth: Arc<RwLock<Auth>>,
    /// The `[[pty_attach]]` dialers running in this process. A reload re-points
    /// each one at the computer its block now names, so a renamed computer does
    /// not silently cut a pod off.
    attachers: Arc<RwLock<Vec<Arc<Attacher>>>>,
    audit: Audit,
}

impl App {
    pub fn new(config: &Config, audit: Audit) -> Self {
        let hub = Hub::new(&config.auth.computers, audit.clone());
        Self {
            mcp: Mcp {
                hub,
                timeouts: config.timeouts.clone(),
                audit: audit.clone(),
            },
            auth: Arc::new(RwLock::new(config.auth.clone())),
            attachers: Arc::new(RwLock::new(Vec::new())),
            audit,
        }
    }

    pub fn hub(&self) -> Arc<Hub> {
        self.mcp.hub.clone()
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/mcp",
                post(post_mcp)
                    .get(mcp_method_not_allowed)
                    .delete(mcp_method_not_allowed),
            )
            .route(
                "/mcp/{computer}",
                post(post_mcp_for)
                    .get(mcp_method_not_allowed)
                    .delete(mcp_method_not_allowed),
            )
            .route("/computers", get(computers))
            .route("/vm/attach", get(vm_attach))
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz", get(readyz))
            .route("/readyz/{computer}", get(readyz_for))
            .route("/status", get(status))
            .layer(DefaultBodyLimit::max(MAX_MCP_BODY_BYTES))
            .with_state(self.clone())
    }

    /// Swap credentials (SIGHUP): clients, their allowlists, the computer
    /// table, and the policy each running `[[pty_attach]]` serves. A socket
    /// whose secret is no longer configured is closed with `4003`; a renamed one
    /// is relabelled and stays. Northbound tokens apply from the next request.
    ///
    /// `pty_attach` is the reloaded list, not a new set of dialers: a block that
    /// appeared, vanished, or changed its `url`/`secret_file` still needs a
    /// restart, and is reported by [`crate::pty::relabel`].
    pub fn reload_auth(&self, auth: Auth, pty_attach: &[PtyAttach]) {
        // Hub first: an upgrade that passes the new check below must find the
        // new verifier at install, not be refused with 4003 (which tells the
        // daemon to stop).
        self.mcp.hub.set_computers(&auth.computers);
        *self.auth.write() = auth;
        // A running attacher holds an attach name, not a computer, so follow
        // the label: otherwise a same-verifier rename leaves the pod's CLI
        // asking for a computer that no longer exists.
        // Not atomic with the hub swap: a pod request that read its policy just
        // before this line can meet the renamed hub once and get one -32001.
        crate::pty::relabel(&self.attachers.read(), pty_attach);
        self.audit.event("config_reloaded", json!({}));
    }

    pub fn spawn_pty_attachers(
        &self,
        attaches: Vec<PtyAttach>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut running = self.attachers.write();
        let mut handles = Vec::new();
        for attach in attaches {
            if let Some((attacher, handle)) =
                crate::pty::spawn(self.mcp.clone(), attach, self.audit.clone())
            {
                running.push(attacher);
                handles.push(handle);
            }
        }
        handles
    }

    /// The caller behind a bearer token, or `None`.
    fn principal(&self, headers: &HeaderMap) -> Option<Principal> {
        let auth = self.auth.read();
        authorization(headers)
            .and_then(|token| auth.client_for(token))
            .map(|client| client.principal.clone())
    }

    /// Resolve one request's computer. A computer the caller may not use and
    /// one that does not exist are the same answer, so a token cannot be used
    /// to enumerate computers.
    fn resolve(&self, principal: &Principal, computer: Option<&str>) -> Option<Caller> {
        let caller = principal.resolve(computer)?;
        self.mcp.hub.exists(&caller.computer).then_some(caller)
    }

    /// The computers this caller may use, in config order. A `"*"` caller gets
    /// whatever is configured now, including computers added after it.
    fn reachable(&self, principal: &Principal) -> Vec<String> {
        match principal.computers.names() {
            None => self.mcp.hub.computer_names(),
            Some(names) => names
                .into_iter()
                .filter(|name| self.mcp.hub.exists(name))
                .map(str::to_owned)
                .collect(),
        }
    }
}

/// Longest forwarded-identity header copied into an audit line.
const MAX_PEER_HEADER_CHARS: usize = 128;

/// Peer for audit lines. A forwarded-identity header (set by `tailscale serve`
/// or a tunnel) is recorded next to the socket address, truncated, and never
/// trusted for anything: a direct caller can send any value.
fn peer_label(addr: SocketAddr, headers: &HeaderMap) -> String {
    let forwarded = headers
        .get("tailscale-user-login")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok());
    match forwarded {
        Some(f) => {
            let f: String = f
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_PEER_HEADER_CHARS)
                .collect();
            format!("{f} via {addr}")
        }
        None => addr.to_string(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer realm=\"openab-sb\"")],
        "unauthorized",
    )
        .into_response()
}

/// The one answer for "no such computer" and "not yours": byte-identical, on
/// every route.
fn no_such_computer() -> Response {
    (StatusCode::NOT_FOUND, "no such computer").into_response()
}

fn authorization(headers: &HeaderMap) -> Option<&str> {
    bearer(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
    )
}

async fn post_mcp(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    mcp_request(app, addr, headers, None, body).await
}

async fn post_mcp_for(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(computer): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    mcp_request(app, addr, headers, Some(computer), body).await
}

async fn mcp_request(
    app: App,
    addr: SocketAddr,
    headers: HeaderMap,
    computer: Option<String>,
    body: Bytes,
) -> Response {
    // 1. The token, before the path is even looked at.
    let Some(principal) = app.principal(&headers) else {
        app.audit.auth_failure(
            "client_auth_fail",
            json!({ "peer": peer_label(addr, &headers) }),
        );
        return unauthorized();
    };
    // 2. The computer, against this caller's allowlist.
    let Some(caller) = app.resolve(&principal, computer.as_deref()) else {
        return no_such_computer();
    };
    // 3. Tool policy and forwarding, as in v1.
    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(rpc_error(Value::Null, -32700, "parse error")),
            )
                .into_response()
        }
    };
    if request.is_array() {
        return (
            StatusCode::BAD_REQUEST,
            Json(rpc_error(
                Value::Null,
                -32600,
                "JSON-RPC batches are not supported",
            )),
        )
            .into_response();
    }
    match app.mcp.handle(&caller, request).await {
        Some(response) => Json(response).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// There is no server-to-client stream; saying so beats an SSE stream that never
/// carries a frame.
async fn mcp_method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        "POST only",
    )
        .into_response()
}

/// No auth and no names: an unauthenticated probe learns that something can
/// serve, not which computers exist or how many.
async fn readyz(State(app): State<App>) -> Response {
    if app.mcp.hub.any_ready() {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "vm offline").into_response()
    }
}

/// Per-computer readiness, for monitoring that holds a token scoped to the
/// computers it watches.
async fn readyz_for(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(computer): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(principal) = app.principal(&headers) else {
        app.audit.auth_failure(
            "client_auth_fail",
            json!({ "peer": peer_label(addr, &headers) }),
        );
        return unauthorized();
    };
    let Some(caller) = app.resolve(&principal, Some(&computer)) else {
        return no_such_computer();
    };
    if app.mcp.hub.is_ready(&caller.computer) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "vm offline").into_response()
    }
}

/// The picker's list. Pickers are HTTP clients, not models, which is why there
/// is no `list_computers` MCP tool.
async fn computers(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(principal) = app.principal(&headers) else {
        app.audit.auth_failure(
            "client_auth_fail",
            json!({ "peer": peer_label(addr, &headers) }),
        );
        return unauthorized();
    };
    let hub = &app.mcp.hub;
    let list: Vec<Value> = app
        .reachable(&principal)
        .into_iter()
        .map(|name| {
            json!({
                "name": name,
                "default": name == principal.default_computer,
                "attached": hub.is_attached(&name),
                "ready": hub.is_ready(&name),
            })
        })
        .collect();
    Json(list).into_response()
}

async fn status(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(principal) = app.principal(&headers) else {
        app.audit.auth_failure(
            "client_auth_fail",
            json!({ "peer": peer_label(addr, &headers) }),
        );
        return unauthorized();
    };
    let hub = &app.mcp.hub;
    let show = hub.shows_internals(principal.computers.is_any());
    let computers: Vec<Value> = app
        .reachable(&principal)
        .into_iter()
        .map(|name| hub.status(&name, show))
        .collect();
    Json(json!({
        "switchboard": { "name": "openab-sb", "version": env!("CARGO_PKG_VERSION") },
        // v1's key, kept: the caller's default computer, which is the one its
        // bare /mcp talks to.
        "vm": hub.status(&principal.default_computer, show),
        "computers": computers,
    }))
    .into_response()
}

async fn vm_attach(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let peer = peer_label(addr, &headers);
    // The secret alone selects the computer, and the hub owns that table, so a
    // reload cannot leave this check and the install disagreeing.
    let presented = authorization(&headers).map(Verifier::of_secret);
    let verified = presented.as_ref().is_some_and(|p| app.mcp.hub.accepts(p));
    let (true, Some(secret)) = (verified, presented) else {
        app.audit
            .auth_failure("vm_auth_fail", json!({ "peer": peer }));
        return unauthorized();
    };
    let hub = app.mcp.hub.clone();
    ws.max_message_size(MAX_VM_FRAME_BYTES)
        .max_frame_size(MAX_VM_FRAME_BYTES)
        .on_upgrade(move |socket| async move { hub.serve(socket, peer, secret).await })
}
