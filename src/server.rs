//! HTTP surface: one listener, four routes.
//!
//! ```text
//!   POST /mcp        northbound MCP (Streamable HTTP, JSON responses)  Bearer <client token>
//!   GET  /vm/attach  southbound WebSocket, the VM dials in            Bearer <VM secret>
//!   GET  /healthz    200 when the VM is attached and initialised, else 503 (no auth)
//!   GET  /livez      200 while the process runs (no auth)
//!   GET  /status     switchboard + VM state as JSON                   Bearer <client token>
//! ```

use crate::audit::Audit;
use crate::auth::{bearer, Verifier};
use crate::config::{Auth, Config, PtyAttach};
use crate::hub::{rpc_error, Hub, MAX_VM_FRAME_BYTES};
use crate::mcp::Mcp;
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
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
    audit: Audit,
}

impl App {
    pub fn new(config: &Config, audit: Audit) -> Self {
        let hub = Hub::new(config.max_inflight, audit.clone());
        Self {
            mcp: Mcp {
                hub,
                timeouts: config.timeouts.clone(),
                audit: audit.clone(),
            },
            auth: Arc::new(RwLock::new(config.auth.clone())),
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
            .route("/vm/attach", get(vm_attach))
            .route("/healthz", get(healthz))
            .route("/livez", get(|| async { "ok" }))
            .route("/status", get(status))
            .layer(DefaultBodyLimit::max(MAX_MCP_BODY_BYTES))
            .with_state(self.clone())
    }

    /// Swap credentials (SIGHUP). A VM attached with a secret that is no longer
    /// configured is closed with `4003`; northbound tokens apply from the next
    /// request.
    pub fn reload_auth(&self, auth: Auth) {
        let vm_secret = auth.vm_secret.clone();
        *self.auth.write() = auth;
        self.mcp.hub.revoke_unless(&vm_secret);
        self.audit.event("config_reloaded", json!({}));
    }

    pub fn spawn_pty_attachers(
        &self,
        attaches: Vec<PtyAttach>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        attaches
            .into_iter()
            .map(|attach| crate::pty::spawn(self.mcp.clone(), attach, self.audit.clone()))
            .collect()
    }
}

/// Peer for audit lines. A forwarded-for header is recorded next to the socket
/// address but never trusted for anything.
fn peer_label(addr: SocketAddr, headers: &HeaderMap) -> String {
    let forwarded = headers
        .get("tailscale-user-login")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok());
    match forwarded {
        Some(f) => format!("{f} via {addr}"),
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
    let principal = {
        let auth = app.auth.read();
        authorization(&headers)
            .and_then(|token| auth.client_for(token))
            .map(|client| client.principal.clone())
    };
    let Some(principal) = principal else {
        app.audit.event(
            "client_auth_fail",
            json!({ "peer": peer_label(addr, &headers) }),
        );
        return unauthorized();
    };
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
    match app.mcp.handle(&principal, request).await {
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

async fn healthz(State(app): State<App>) -> Response {
    if app.mcp.hub.is_ready() {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "vm offline").into_response()
    }
}

async fn status(State(app): State<App>, headers: HeaderMap) -> Response {
    let allowed = {
        let auth = app.auth.read();
        authorization(&headers).is_some_and(|token| auth.client_for(token).is_some())
    };
    if !allowed {
        return unauthorized();
    }
    Json(json!({
        "switchboard": { "name": "openab-sb", "version": env!("CARGO_PKG_VERSION") },
        "vm": app.mcp.hub.status(),
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
    let presented = authorization(&headers).map(Verifier::of_secret);
    let verified = {
        let auth = app.auth.read();
        presented
            .as_ref()
            .is_some_and(|p| auth.vm_secret.matches(p))
    };
    let (true, Some(secret)) = (verified, presented) else {
        app.audit.event("vm_auth_fail", json!({ "peer": peer }));
        return unauthorized();
    };
    let hub = app.mcp.hub.clone();
    ws.max_message_size(MAX_VM_FRAME_BYTES)
        .max_frame_size(MAX_VM_FRAME_BYTES)
        .on_upgrade(move |socket| async move { hub.serve(socket, peer, secret).await })
}
