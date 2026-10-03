//! Audit log: one JSON object per line — who, when, what, outcome. Results are
//! never logged (they pass through, they do not land); only their size.

use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

/// Longest rendering of call arguments kept in an audit line.
pub const MAX_AUDIT_ARGS_CHARS: usize = 512;

#[derive(Clone)]
pub struct Audit {
    sink: Arc<Mutex<Box<dyn Write + Send>>>,
    log_args: bool,
}

impl Audit {
    /// Append to `path`, or write to stdout when `None`.
    pub fn open(path: Option<&Path>, log_args: bool) -> anyhow::Result<Self> {
        let sink: Box<dyn Write + Send> = match path {
            Some(path) => Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            ),
            None => Box::new(std::io::stdout()),
        };
        Ok(Self {
            sink: Arc::new(Mutex::new(sink)),
            log_args,
        })
    }

    /// Discard everything (tests).
    pub fn null() -> Self {
        Self {
            sink: Arc::new(Mutex::new(Box::new(std::io::sink()))),
            log_args: false,
        }
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

    /// Render call arguments for the audit line, or `None` when disabled.
    pub fn args(&self, arguments: Option<&Value>) -> Option<String> {
        if !self.log_args {
            return None;
        }
        let text = arguments.map(Value::to_string).unwrap_or_default();
        if text.chars().count() <= MAX_AUDIT_ARGS_CHARS {
            Some(text)
        } else {
            let cut: String = text.chars().take(MAX_AUDIT_ARGS_CHARS).collect();
            Some(format!("{cut}…"))
        }
    }
}
