//! Audit log: one JSON object per line — who, when, what, outcome. Results are
//! never logged (they pass through, they do not land); only their size.
//!
//! With `audit_args` on, call arguments are recorded after [`redact`]: any
//! argument, at any depth, whose name is secret-bearing ([`DEFAULT_REDACT_KEYS`],
//! [`DEFAULT_REDACT_FRAGMENTS`], plus the operator's `audit_redact_keys`) is
//! replaced with a marker. That covers `ui_action`'s `value` (which may go into
//! a password field) and the `text` typed through `key`. Free-form arguments
//! such as a `bash` `command` are not inspected, so the file is still created
//! `0600`. Authentication failures come from
//! unauthenticated callers, so they are rate-limited: a flood costs a summary
//! line, not the disk.

use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Longest rendering of call arguments kept in an audit line.
pub const MAX_AUDIT_ARGS_CHARS: usize = 512;
/// Argument names (compared case-insensitively, `-` read as `_`) whose value is
/// never recorded: `value` is what `ui_action` `set_value` writes, `text` what
/// `key` and browser typing tools type.
pub const DEFAULT_REDACT_KEYS: &[&str] = &[
    "value",
    "values",
    "text",
    "password",
    "passphrase",
    "secret",
    "token",
    "pin",
    "otp",
];
/// A name containing any of these is redacted too (`api_token`, `db_password`,
/// `client_secret`, `Authorization`, …).
pub const DEFAULT_REDACT_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "cookie",
    "authorization",
    "private_key",
];
/// Authentication-failure lines written per window; the rest are counted.
pub const AUTH_FAILURES_PER_WINDOW: u32 = 20;
pub const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);

struct FailureWindow {
    started: Instant,
    written: u32,
    suppressed: u64,
}

#[derive(Clone)]
pub struct Audit {
    sink: Arc<Mutex<Box<dyn Write + Send>>>,
    failures: Arc<Mutex<FailureWindow>>,
    log_args: bool,
    /// Operator additions to [`DEFAULT_REDACT_KEYS`], already normalised.
    extra_redact: Arc<[String]>,
}

impl Audit {
    fn with_sink(sink: Box<dyn Write + Send>, log_args: bool) -> Self {
        Self {
            sink: Arc::new(Mutex::new(sink)),
            failures: Arc::new(Mutex::new(FailureWindow {
                started: Instant::now(),
                written: 0,
                suppressed: 0,
            })),
            log_args,
            extra_redact: Arc::from(Vec::new()),
        }
    }

    /// Also redact arguments with these names (`audit_redact_keys`), on top of
    /// the defaults, which cannot be removed.
    pub fn with_redact_keys(mut self, keys: &[String]) -> Self {
        self.extra_redact = keys.iter().map(|k| normalise(k)).collect();
        self
    }

    /// Append to `path` (created `0600`), or write to stdout when `None`.
    pub fn open(path: Option<&Path>, log_args: bool) -> anyhow::Result<Self> {
        let sink: Box<dyn Write + Send> = match path {
            Some(path) => {
                let mut options = std::fs::OpenOptions::new();
                options.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                Box::new(options.open(path)?)
            }
            None => Box::new(std::io::stdout()),
        };
        Ok(Self::with_sink(sink, log_args))
    }

    /// Discard everything (tests).
    pub fn null() -> Self {
        Self::with_sink(Box::new(std::io::sink()), false)
    }

    pub fn event(&self, kind: &str, fields: Value) {
        let mut line = Map::new();
        line.insert(
            "ts".into(),
            json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        );
        line.insert("event".into(), json!(kind));
        if let Value::Object(fields) = fields {
            line.extend(fields);
        }
        let mut sink = self.sink.lock();
        let _ = writeln!(sink, "{}", Value::Object(line));
        let _ = sink.flush();
    }

    /// An authentication failure, rate-limited per [`AUTH_FAILURE_WINDOW`].
    pub fn auth_failure(&self, kind: &str, fields: Value) {
        let (summary, write) = {
            let mut window = self.failures.lock();
            let mut summary = None;
            if window.started.elapsed() >= AUTH_FAILURE_WINDOW {
                summary = (window.suppressed > 0).then_some(window.suppressed);
                *window = FailureWindow {
                    started: Instant::now(),
                    written: 0,
                    suppressed: 0,
                };
            }
            let write = window.written < AUTH_FAILURES_PER_WINDOW;
            if write {
                window.written += 1;
            } else {
                window.suppressed += 1;
            }
            (summary, write)
        };
        if let Some(count) = summary {
            self.event(
                "auth_failures_suppressed",
                json!({ "count": count, "window_secs": AUTH_FAILURE_WINDOW.as_secs() }),
            );
        }
        if write {
            self.event(kind, fields);
        }
    }

    /// Render call arguments for the audit line, or `None` when disabled.
    pub fn args(&self, arguments: Option<&Value>) -> Option<String> {
        if !self.log_args {
            return None;
        }
        let text = arguments
            .map(|a| redact(a, &self.extra_redact).to_string())
            .unwrap_or_default();
        if text.chars().count() <= MAX_AUDIT_ARGS_CHARS {
            Some(text)
        } else {
            let cut: String = text.chars().take(MAX_AUDIT_ARGS_CHARS).collect();
            Some(format!("{cut}…"))
        }
    }
}

fn normalise(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}

fn is_secret_name(name: &str, extra: &[String]) -> bool {
    let name = normalise(name);
    DEFAULT_REDACT_KEYS.contains(&name.as_str())
        || DEFAULT_REDACT_FRAGMENTS.iter().any(|f| name.contains(f))
        || extra.contains(&name)
}

/// What a redacted argument is recorded as: its length for a string (so an
/// empty or truncated value is still visible), nothing for anything else.
fn marker(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(format!("<redacted:{} chars>", s.chars().count())),
        _ => Value::String("<redacted>".into()),
    }
}

/// Copy of `value` with every secret-bearing field replaced, at any depth and
/// inside arrays, so the rest of the call (`snapshot_id`, `ref`, `action`)
/// stays in the trail. A secret-named object or array is replaced whole.
pub fn redact(value: &Value, extra: &[String]) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if is_secret_name(k, extra) {
                        marker(v)
                    } else {
                        redact(v, extra)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| redact(v, extra)).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn lines(buf: &Shared) -> Vec<Value> {
        String::from_utf8(buf.0.lock().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn auth_failures_are_capped_per_window() {
        let buf = Shared::default();
        let audit = Audit::with_sink(Box::new(buf.clone()), false);
        for _ in 0..(AUTH_FAILURES_PER_WINDOW + 50) {
            audit.auth_failure("vm_auth_fail", json!({ "peer": "x" }));
        }
        assert_eq!(lines(&buf).len(), AUTH_FAILURES_PER_WINDOW as usize);
        // Next window: one summary for the 50, then the new line.
        audit.failures.lock().started -= AUTH_FAILURE_WINDOW;
        audit.auth_failure("vm_auth_fail", json!({ "peer": "y" }));
        let all = lines(&buf);
        let summary = &all[AUTH_FAILURES_PER_WINDOW as usize];
        assert_eq!(summary["event"], "auth_failures_suppressed");
        assert_eq!(summary["count"], 50);
        assert_eq!(all.last().unwrap()["peer"], "y");
    }

    #[test]
    fn args_are_truncated_or_omitted() {
        let off = Audit::null();
        assert_eq!(off.args(Some(&json!({"a": 1}))), None);
        let on = Audit::with_sink(Box::new(std::io::sink()), true);
        let long = json!({ "command": "x".repeat(2000) });
        let rendered = on.args(Some(&long)).unwrap();
        assert_eq!(rendered.chars().count(), MAX_AUDIT_ARGS_CHARS + 1);
    }

    #[test]
    fn secret_arguments_are_redacted_at_any_depth() {
        let canary = "hunter2-canary-6f1d";
        let on = Audit::with_sink(Box::new(std::io::sink()), true)
            .with_redact_keys(&["One-Time-Code".to_owned()]);
        let call = json!({
            "snapshot_id": "s1", "ref": "e7", "action": "set_value", "value": canary,
            "fields": [{ "name": "pw", "ref": "e9", "value": canary }],
            "nested": { "deeper": { "Client_Secret": canary, "API-KEY": canary } },
            "one_time_code": canary,
            "auth": { "password": { "raw": canary } },
            "number": { "value": 42 },
        });
        let rendered = on.args(Some(&call)).unwrap();
        assert!(!rendered.contains(canary), "{rendered}");
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        let len = format!("<redacted:{} chars>", canary.chars().count());
        assert_eq!(parsed["value"], json!(len));
        assert_eq!(parsed["fields"][0]["value"], json!(len));
        assert_eq!(parsed["fields"][0]["ref"], "e9");
        assert_eq!(parsed["nested"]["deeper"]["Client_Secret"], json!(len));
        assert_eq!(parsed["nested"]["deeper"]["API-KEY"], json!(len));
        assert_eq!(parsed["one_time_code"], json!(len));
        assert_eq!(parsed["auth"]["password"], "<redacted>");
        assert_eq!(parsed["number"]["value"], "<redacted>");
        assert_eq!(parsed["snapshot_id"], "s1");
        assert_eq!(parsed["ref"], "e7");
        assert_eq!(parsed["action"], "set_value");
    }

    #[test]
    fn typed_text_is_redacted_and_other_arguments_are_kept() {
        let on = Audit::with_sink(Box::new(std::io::sink()), true);
        let typed = on
            .args(Some(&json!({ "action": "type", "text": "correct horse" })))
            .unwrap();
        assert_eq!(typed, r#"{"action":"type","text":"<redacted:13 chars>"}"#);
        let press = on
            .args(Some(&json!({ "action": "press", "keys": ["ctrl+l"] })))
            .unwrap();
        assert_eq!(press, r#"{"action":"press","keys":["ctrl+l"]}"#);
        // Redaction runs before truncation, so a long secret cannot survive a cut.
        let long = on
            .args(Some(&json!({ "value": "s".repeat(5000) })))
            .unwrap();
        assert_eq!(long, r#"{"value":"<redacted:5000 chars>"}"#);
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("openab-sb-audit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let audit = Audit::open(Some(&path), true).unwrap();
        audit.event("probe", json!({}));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600);
    }
}
