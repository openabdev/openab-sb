//! The MCP surface callers see, shared by every northbound adapter (HTTP for
//! Connect, the reverse attach toward openab-pty). The switchboard answers the
//! handshake itself, filters `tools/list` by the caller's allowlist, refuses
//! disallowed calls before they reach the VM, and forwards the rest.
//!
//! Only `initialize`, `ping`, `tools/list` and `tools/call` are served. Every
//! other method is refused here rather than forwarded: the switchboard is a
//! closed relay for tools, not a generic MCP proxy.

use crate::audit::Audit;
use crate::config::{Principal, Timeouts};
use crate::hub::{rpc_error, CallError, Hub, MCP_PROTOCOL_VERSION};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

/// Tool the switchboard answers itself, attached or not.
pub const STATUS_TOOL: &str = "vm_status";
/// Longest tool name accepted; names land in audit lines.
pub const MAX_TOOL_NAME_CHARS: usize = 128;

#[derive(Clone)]
pub struct Mcp {
    pub hub: Arc<Hub>,
    pub timeouts: Timeouts,
    pub audit: Audit,
}

impl Mcp {
    /// Answer one JSON-RPC message. `None` = it was a notification.
    pub async fn handle(&self, who: &Principal, request: Value) -> Option<Value> {
        let Some(object) = request.as_object() else {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "expected one JSON-RPC object",
            ));
        };
        let id = object.get("id").cloned();
        let method = object.get("method").and_then(Value::as_str);
        let (Some(id), Some(method)) = (id, method) else {
            // A response a client sends us (it has `result`/`error`) is accepted
            // like a notification; nothing here ever asked it anything.
            let is_response = object.contains_key("result") || object.contains_key("error");
            return match (object.get("id"), method) {
                (Some(id), None) if !is_response => {
                    Some(rpc_error(id.clone(), -32600, "missing method"))
                }
                _ => None,
            };
        };
        let method = method.to_owned();
        match method.as_str() {
            "initialize" => Some(self.initialize(id, &request)),
            "ping" => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
            "tools/list" => Some(self.tools_list(who, id, request).await),
            "tools/call" => Some(self.tools_call(who, id, request).await),
            _ => Some(rpc_error(
                id,
                -32601,
                "method not served by the switchboard",
            )),
        }
    }

    fn initialize(&self, id: Value, request: &Value) -> Value {
        let offered = request
            .pointer("/params/protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(MCP_PROTOCOL_VERSION);
        let version = match offered {
            "2025-06-18" | "2025-03-26" => offered,
            _ => MCP_PROTOCOL_VERSION,
        };
        let instructions = if self.hub.is_ready() {
            "A remote VM is connected through OpenAB Switchboard. Its tools are listed under tools/list alongside vm_status. Calls are relayed over the network: expect latency of a second or more, and never assume a timed-out call did not run."
        } else {
            "The remote VM is not connected right now. Only vm_status is available; call it, or tools/list again later."
        };
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "openab-sb", "version": env!("CARGO_PKG_VERSION") },
                "instructions": instructions
            }
        })
    }

    fn status_tool() -> Value {
        json!({
            "name": STATUS_TOOL,
            "description": "Whether the remote VM is connected to OpenAB Switchboard, since when, and what it reported about itself. Answered by the switchboard; works when the VM is offline.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        })
    }

    async fn tools_list(&self, who: &Principal, id: Value, request: Value) -> Value {
        let only_status = || json!({ "jsonrpc": "2.0", "id": id.clone(), "result": { "tools": [Self::status_tool()] } });
        let forwarded = json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": request.get("params").cloned().unwrap_or_else(|| json!({}))
        });
        let mut response = match self.hub.call(forwarded, self.timeouts.control).await {
            Ok(response) => response,
            Err(CallError::NotAttached) => return only_status(),
            Err(error) => return rpc_error(id, error.rpc_code(), error.message()),
        };
        if let Some(error) = response.get("error") {
            // Not an error to the caller: an MCP client may drop a server whose
            // tools/list fails. `vm_status` stays callable to explain.
            tracing::warn!(%error, "VM answered tools/list with an error");
            return only_status();
        }
        let Some(tools) = response
            .get_mut("result")
            .and_then(|r| r.get_mut("tools"))
            .and_then(Value::as_array_mut)
        else {
            return only_status();
        };
        tools.retain(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name != STATUS_TOOL && who.tools.allows(name))
        });
        tools.push(Self::status_tool());
        // Pagination stays the VM's business; the cursor passes through.
        if let Some(object) = response.as_object_mut() {
            object.insert("id".into(), id);
        }
        response
    }

    async fn tools_call(&self, who: &Principal, id: Value, request: Value) -> Value {
        let params = request.get("params");
        let Some(name) = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return rpc_error(id, -32602, "tools/call needs params.name");
        };
        if name.is_empty() || name.chars().count() > MAX_TOOL_NAME_CHARS {
            return rpc_error(id, -32602, "params.name must be 1-128 characters");
        }
        let arguments = params.and_then(|p| p.get("arguments"));
        if arguments.is_some_and(|a| !a.is_object()) {
            return rpc_error(id, -32602, "params.arguments must be an object");
        }

        let started = Instant::now();
        let audit_args = self.audit.args(arguments);
        let record = |outcome: &str, code: Option<i64>, bytes: usize| {
            self.audit.event(
                "call",
                json!({
                    "principal": who.name,
                    "tool": name,
                    "outcome": outcome,
                    "error_code": code,
                    "ms": started.elapsed().as_millis() as u64,
                    "response_bytes": bytes,
                    "args": audit_args.clone(),
                }),
            );
        };

        if name == STATUS_TOOL {
            let status = self.hub.status();
            record("ok", None, 0);
            return tool_result(id, status.to_string(), Some(status), false);
        }

        if !who.tools.allows(&name) {
            record("denied", None, 0);
            return tool_result(
                id,
                format!(
                    "tool `{name}` is not allowed for `{}` by the switchboard's policy",
                    who.name
                ),
                None,
                true,
            );
        }

        let forwarded = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": params.cloned().unwrap_or_else(|| json!({}))
        });
        match self
            .hub
            .call(forwarded, self.timeouts.for_tool(&name))
            .await
        {
            Ok(mut response) => {
                let bytes = response.to_string().len();
                let outcome = if response.get("error").is_some() {
                    "rpc_error"
                } else if response.pointer("/result/isError") == Some(&Value::Bool(true)) {
                    "tool_error"
                } else {
                    "ok"
                };
                let code = response.pointer("/error/code").and_then(Value::as_i64);
                record(outcome, code, bytes);
                if let Some(object) = response.as_object_mut() {
                    object.insert("id".into(), id);
                }
                response
            }
            // Offline is a tool result, not a protocol error, so an MCP client
            // keeps the server and the agent can read why.
            Err(CallError::NotAttached) => {
                record("not_attached", Some(CallError::NotAttached.rpc_code()), 0);
                tool_result(id, CallError::NotAttached.message().into(), None, true)
            }
            Err(error) => {
                let outcome = match error {
                    CallError::Timeout => "timeout",
                    CallError::TooManyInFlight => "overloaded",
                    _ => "disconnected",
                };
                record(outcome, Some(error.rpc_code()), 0);
                rpc_error(id, error.rpc_code(), error.message())
            }
        }
    }
}

fn tool_result(id: Value, text: String, structured: Option<Value>, is_error: bool) -> Value {
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    });
    if let Some(structured) = structured {
        result["structuredContent"] = structured;
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}
