//! `openab-sb.toml`: parsed, then validated into [`Config`]. Anything that would
//! widen exposure (a non-loopback bind, plaintext toward a pod) must be asked for
//! by name; the defaults are the narrow choice.

use crate::auth::Verifier;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8790";
pub const DEFAULT_MAX_INFLIGHT: usize = 8;
pub const MAX_MAX_INFLIGHT: usize = 64;
pub const DEFAULT_TOOL_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_SCREENSHOT_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: Option<String>,
    #[serde(default)]
    allow_insecure_bind: bool,
    max_inflight: Option<usize>,
    #[serde(default = "default_true")]
    audit_args: bool,
    audit_path: Option<String>,
    vm: RawVm,
    #[serde(default)]
    timeouts: RawTimeouts,
    #[serde(default, rename = "client")]
    clients: Vec<RawClient>,
    #[serde(default, rename = "pty_attach")]
    pty_attach: Vec<RawPtyAttach>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVm {
    secret_sha256: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTimeouts {
    default_secs: Option<u64>,
    control_secs: Option<u64>,
    #[serde(default)]
    tools: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    name: String,
    token_sha256: String,
    tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPtyAttach {
    name: String,
    url: String,
    secret_file: String,
    tools: Vec<String>,
    #[serde(default)]
    allow_insecure_transport: bool,
}

/// Which VM tools a caller may see and call. `vm_status` is always allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolAllow {
    All,
    Only(BTreeSet<String>),
}

impl ToolAllow {
    fn parse(tools: &[String], owner: &str) -> Result<Self> {
        if tools.is_empty() {
            bail!("{owner}: `tools` is empty; list tool names or use [\"*\"]");
        }
        if tools.iter().any(|t| t == "*") {
            if tools.len() > 1 {
                bail!("{owner}: `tools` mixes \"*\" with names");
            }
            return Ok(Self::All);
        }
        Ok(Self::Only(
            tools.iter().map(|t| t.trim().to_owned()).collect(),
        ))
    }

    pub fn allows(&self, tool: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(set) => set.contains(tool),
        }
    }
}

/// A northbound caller: who it is and what it may do.
#[derive(Debug, Clone)]
pub struct Principal {
    pub name: String,
    pub tools: ToolAllow,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub principal: Principal,
    pub token: Verifier,
}

#[derive(Debug, Clone)]
pub struct PtyAttach {
    pub principal: Principal,
    pub url: String,
    pub secret_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Timeouts {
    pub default: Duration,
    pub control: Duration,
    pub tools: BTreeMap<String, Duration>,
}

impl Timeouts {
    pub fn for_tool(&self, tool: &str) -> Duration {
        self.tools.get(tool).copied().unwrap_or(self.default)
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        let mut tools = BTreeMap::new();
        tools.insert("screenshot".to_owned(), DEFAULT_SCREENSHOT_TIMEOUT);
        Self {
            default: DEFAULT_TOOL_TIMEOUT,
            control: DEFAULT_CONTROL_TIMEOUT,
            tools,
        }
    }
}

/// The credentials part of the config: everything that SIGHUP reloads.
#[derive(Debug, Clone)]
pub struct Auth {
    pub vm_secret: Verifier,
    pub clients: Vec<Client>,
}

impl Auth {
    /// Constant-time lookup of a presented northbound bearer.
    pub fn client_for(&self, token: &str) -> Option<&Client> {
        let presented = Verifier::of_secret(token);
        // Compare against every entry so timing does not reveal the position.
        let mut found = None;
        for client in &self.clients {
            if client.token.matches(&presented) && found.is_none() {
                found = Some(client);
            }
        }
        found
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub max_inflight: usize,
    pub audit_args: bool,
    pub audit_path: Option<PathBuf>,
    pub timeouts: Timeouts,
    pub auth: Auth,
    pub pty_attach: Vec<PtyAttach>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text)?;

        let listen: SocketAddr = raw
            .listen
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN)
            .parse()
            .context("`listen` must be ip:port")?;
        if !listen.ip().is_loopback() && !raw.allow_insecure_bind {
            bail!(
                "`listen = \"{listen}\"` is not loopback. Front the switchboard with \
                 `tailscale serve` or a tunnel, or set `allow_insecure_bind = true` if \
                 this network is private and you accept bearer tokens in clear"
            );
        }

        let max_inflight = raw.max_inflight.unwrap_or(DEFAULT_MAX_INFLIGHT);
        if !(1..=MAX_MAX_INFLIGHT).contains(&max_inflight) {
            bail!("`max_inflight` must be 1..={MAX_MAX_INFLIGHT}");
        }

        let secs = |name: &str, value: u64| -> Result<Duration> {
            if value == 0 || value > MAX_TIMEOUT_SECS {
                bail!("timeout `{name}` must be 1..={MAX_TIMEOUT_SECS} seconds");
            }
            Ok(Duration::from_secs(value))
        };
        let mut timeouts = Timeouts::default();
        if let Some(v) = raw.timeouts.default_secs {
            timeouts.default = secs("default_secs", v)?;
        }
        if let Some(v) = raw.timeouts.control_secs {
            timeouts.control = secs("control_secs", v)?;
        }
        for (tool, v) in &raw.timeouts.tools {
            timeouts.tools.insert(tool.clone(), secs(tool, *v)?);
        }

        let vm_secret = Verifier::parse(&raw.vm.secret_sha256).context("[vm].secret_sha256")?;

        let mut names = HashSet::new();
        let mut clients = Vec::new();
        for c in raw.clients {
            let owner = format!("[[client]] {:?}", c.name);
            check_name(&c.name, &owner)?;
            if !names.insert(c.name.clone()) {
                bail!("{owner}: duplicate name");
            }
            let token = Verifier::parse(&c.token_sha256).with_context(|| owner.clone())?;
            if token == vm_secret {
                bail!("{owner}: token equals the VM secret; they must differ");
            }
            if clients.iter().any(|other: &Client| other.token == token) {
                bail!("{owner}: token is shared with another client");
            }
            clients.push(Client {
                principal: Principal {
                    tools: ToolAllow::parse(&c.tools, &owner)?,
                    name: c.name,
                },
                token,
            });
        }

        let mut pty_attach = Vec::new();
        for p in raw.pty_attach {
            let owner = format!("[[pty_attach]] {:?}", p.name);
            check_name(&p.name, &owner)?;
            if !names.insert(p.name.clone()) {
                bail!("{owner}: name is already used by a client or attach");
            }
            let insecure_ok = p.allow_insecure_transport;
            let uri: tokio_tungstenite::tungstenite::http::Uri = p
                .url
                .parse()
                .with_context(|| format!("{owner}: `url` is not a valid URL"))?;
            let host = uri
                .host()
                .with_context(|| format!("{owner}: `url` has no host"))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            match uri.scheme_str() {
                Some("wss") => {}
                Some("ws") => {
                    let loopback = host == "localhost"
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback());
                    if !loopback && !insecure_ok {
                        bail!(
                            "{owner}: `ws://` to a non-loopback host sends the attach secret in \
                             clear; use `wss://` or set `allow_insecure_transport = true` \
                             (acceptable over a tailnet IP)"
                        );
                    }
                }
                _ => bail!("{owner}: `url` must be ws:// or wss://"),
            }
            if pty_attach
                .iter()
                .any(|other: &PtyAttach| other.url == p.url)
            {
                bail!(
                    "{owner}: another [[pty_attach]] already dials this url; \
                     two dialers on one session evict each other"
                );
            }
            pty_attach.push(PtyAttach {
                principal: Principal {
                    tools: ToolAllow::parse(&p.tools, &owner)?,
                    name: p.name,
                },
                url: p.url,
                secret_file: expand_home(&p.secret_file),
            });
        }

        if clients.is_empty() && pty_attach.is_empty() {
            bail!("no [[client]] and no [[pty_attach]]: nothing could ever call the VM");
        }

        Ok(Self {
            listen,
            max_inflight,
            audit_args: raw.audit_args,
            audit_path: raw.audit_path.as_deref().map(expand_home),
            timeouts,
            auth: Auth { vm_secret, clients },
            pty_attach,
        })
    }
}

fn check_name(name: &str, owner: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        bail!("{owner}: name must be 1-64 chars of [A-Za-z0-9._-]");
    }
    Ok(())
}

pub fn expand_home(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(rest),
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(secret: &str) -> String {
        Verifier::of_secret(secret).render()
    }

    fn base(extra: &str) -> String {
        format!(
            "[vm]\nsecret_sha256 = \"{}\"\n\n[[client]]\nname = \"connect\"\ntoken_sha256 = \"{}\"\ntools = [\"screenshot\", \"sys_info\"]\n{extra}",
            v("vm"),
            v("c1")
        )
    }

    #[test]
    fn minimal_config_has_narrow_defaults() {
        let c = Config::parse(&base("")).unwrap();
        assert_eq!(c.listen.to_string(), DEFAULT_LISTEN);
        assert_eq!(c.max_inflight, DEFAULT_MAX_INFLIGHT);
        assert_eq!(
            c.timeouts.for_tool("screenshot"),
            DEFAULT_SCREENSHOT_TIMEOUT
        );
        assert_eq!(c.timeouts.for_tool("bash"), DEFAULT_TOOL_TIMEOUT);
        let client = c.auth.client_for("c1").unwrap();
        assert!(client.principal.tools.allows("screenshot"));
        assert!(!client.principal.tools.allows("bash"));
        assert!(c.auth.client_for("vm").is_none());
    }

    #[test]
    fn refuses_public_bind_unless_asked() {
        let text = format!("listen = \"0.0.0.0:8790\"\n{}", base(""));
        assert!(Config::parse(&text).is_err());
        let text = format!(
            "listen = \"0.0.0.0:8790\"\nallow_insecure_bind = true\n{}",
            base("")
        );
        assert!(Config::parse(&text).is_ok());
    }

    #[test]
    fn refuses_plaintext_to_a_remote_pod_unless_asked() {
        let attach = "[[pty_attach]]\nname = \"pod\"\nurl = \"ws://100.67.90.88:8091/tools/attach/s\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n";
        assert!(Config::parse(&base(attach)).is_err());
        let attach_ok = format!("{attach}allow_insecure_transport = true\n");
        assert!(Config::parse(&base(&attach_ok)).is_ok());
        let local = "[[pty_attach]]\nname = \"pod\"\nurl = \"ws://127.0.0.1:8091/tools/attach/s\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n";
        assert!(Config::parse(&base(local)).is_ok());
        let v6 = "[[pty_attach]]\nname = \"pod\"\nurl = \"ws://[::1]:8091/tools/attach/s\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n";
        assert!(Config::parse(&base(v6)).is_ok(), "[::1] is loopback");
        let dup = format!("{local}[[pty_attach]]\nname = \"pod2\"\nurl = \"ws://127.0.0.1:8091/tools/attach/s\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n");
        assert!(
            Config::parse(&base(&dup)).is_err(),
            "two dialers on one session"
        );
        let http = "[[pty_attach]]\nname = \"pod\"\nurl = \"https://x/tools/attach/s\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n";
        assert!(Config::parse(&base(http)).is_err());
    }

    #[test]
    fn refuses_shared_or_reused_credentials_and_bad_lists() {
        let dup = format!(
            "[[client]]\nname = \"pty\"\ntoken_sha256 = \"{}\"\ntools = [\"*\"]\n",
            v("c1")
        );
        assert!(Config::parse(&base(&dup)).is_err());
        let vm_reuse = format!(
            "[[client]]\nname = \"pty\"\ntoken_sha256 = \"{}\"\ntools = [\"*\"]\n",
            v("vm")
        );
        assert!(Config::parse(&base(&vm_reuse)).is_err());
        let mixed = format!(
            "[[client]]\nname = \"pty\"\ntoken_sha256 = \"{}\"\ntools = [\"*\", \"bash\"]\n",
            v("c2")
        );
        assert!(Config::parse(&base(&mixed)).is_err());
        assert!(Config::parse(&format!("max_inflight = 0\n{}", base(""))).is_err());
        assert!(Config::parse(&format!("max_inflight = 65\n{}", base(""))).is_err());
    }

    #[test]
    fn shipped_example_parses_once_filled_in() {
        let example = include_str!("../openab-sb.toml.example");
        let parts: Vec<&str> = example.split("sha256:REPLACE_ME").collect();
        let mut filled = parts[0].to_owned();
        for (i, part) in parts[1..].iter().enumerate() {
            filled.push_str(&v(&format!("secret-{i}")));
            filled.push_str(part);
        }
        let c = Config::parse(&filled).unwrap();
        assert_eq!(c.auth.clients.len(), 2);
        assert_eq!(c.timeouts.for_tool("bash"), Duration::from_secs(60));
    }

    #[test]
    fn rejects_unknown_keys() {
        let text = format!("lisen = \"127.0.0.1:1\"\n{}", base(""));
        assert!(Config::parse(&text).is_err());
    }
}
