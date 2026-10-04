//! `openab-sb.toml`: parsed, then validated into [`Config`]. Anything that would
//! widen exposure (a non-loopback bind, plaintext toward a pod, a computer a
//! caller never asked for) must be asked for by name; the defaults are the
//! narrow choice.
//!
//! v2 shape: computers are configured as `[[computer]]` blocks and callers are
//! granted access per computer. A v1 file still loads — `[vm]` becomes a
//! computer named [`DEFAULT_COMPUTER`] and a client's `tools` becomes
//! `computers = { default = [...] }`.

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
/// The name a v1 `[vm]` block takes in v2.
pub const DEFAULT_COMPUTER: &str = "default";
/// `computers` key meaning "every computer, including ones configured later".
pub const ANY_COMPUTER: &str = "*";

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
    /// v1: one computer, named [`DEFAULT_COMPUTER`].
    vm: Option<RawVm>,
    #[serde(default, rename = "computer")]
    computers: Vec<RawComputer>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawComputer {
    name: String,
    secret_sha256: String,
    max_inflight: Option<usize>,
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
    /// v1 form: one computer's tools.
    tools: Option<Vec<String>>,
    /// v2 form: computer name (or `"*"`) → tool allowlist.
    computers: Option<BTreeMap<String, Vec<String>>>,
    default_computer: Option<String>,
    max_inflight: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPtyAttach {
    name: String,
    url: String,
    secret_file: String,
    tools: Vec<String>,
    computer: Option<String>,
    max_inflight: Option<usize>,
    #[serde(default)]
    allow_insecure_transport: bool,
}

/// Which of a computer's tools a caller may see and call. `vm_status` is always
/// allowed.
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

/// Which computers a caller may reach, and with which tools on each. Deny by
/// default: a computer that is not named here does not exist for that caller.
#[derive(Debug, Clone)]
pub enum ComputerAccess {
    /// `computers = { "*" = [...] }`: every computer, including ones configured
    /// later. For the owner.
    Any(ToolAllow),
    /// Only these computers, by name.
    Named(BTreeMap<String, ToolAllow>),
}

impl ComputerAccess {
    fn parse(raw: &BTreeMap<String, Vec<String>>, owner: &str) -> Result<Self> {
        if raw.is_empty() {
            bail!(
                "{owner}: `computers` is empty; name a computer, or use \
                 {{ \"*\" = [\"*\"] }} for every computer"
            );
        }
        if let Some(tools) = raw.get(ANY_COMPUTER) {
            if raw.len() > 1 {
                bail!("{owner}: `computers` mixes \"*\" with computer names");
            }
            return Ok(Self::Any(ToolAllow::parse(
                tools,
                &format!("{owner} `computers.\"*\"`"),
            )?));
        }
        let mut named = BTreeMap::new();
        for (name, tools) in raw {
            let inner = format!("{owner} `computers.{name}`");
            check_computer_name(name, &inner)?;
            named.insert(name.clone(), ToolAllow::parse(tools, &inner)?);
        }
        Ok(Self::Named(named))
    }

    /// One computer, one tool list (the v1 shape, and a pty attach).
    fn one(computer: &str, tools: ToolAllow) -> Self {
        Self::Named(BTreeMap::from([(computer.to_owned(), tools)]))
    }

    /// The tools this caller may use on `computer`, or `None` when it may not
    /// reach it at all.
    pub fn tools_on(&self, computer: &str) -> Option<&ToolAllow> {
        match self {
            Self::Any(tools) => Some(tools),
            Self::Named(named) => named.get(computer),
        }
    }

    /// Is this the `"*"` form? Such a caller is the owner: it reaches computers
    /// added later, and sees `/status` internals.
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any(_))
    }

    /// The names written in the config, or `None` for `"*"`.
    pub fn names(&self) -> Option<Vec<&str>> {
        match self {
            Self::Any(_) => None,
            Self::Named(named) => Some(named.keys().map(String::as_str).collect()),
        }
    }
}

/// A northbound caller: who it is, which computers it may reach, and what
/// `POST /mcp` without a path means for it.
#[derive(Debug, Clone)]
pub struct Principal {
    pub name: String,
    pub computers: ComputerAccess,
    /// What bare `POST /mcp` resolves to. Never changes when a computer is
    /// added, which is the point of requiring it.
    pub default_computer: String,
    /// This caller's in-flight cap on one computer. `None` = half the live
    /// socket's `max_inflight`, rounded up.
    pub max_inflight: Option<usize>,
}

impl Principal {
    /// Resolve one request's computer against this caller's allowlist. `None`
    /// means not allowed — the caller is told the same thing as for a computer
    /// that does not exist.
    pub fn resolve(&self, computer: Option<&str>) -> Option<Caller> {
        let computer = computer.unwrap_or(&self.default_computer);
        let tools = self.computers.tools_on(computer)?;
        Some(Caller {
            principal: self.name.clone(),
            computer: computer.to_owned(),
            tools: tools.clone(),
            max_inflight: self.max_inflight,
            wildcard: self.computers.is_any(),
        })
    }
}

/// One request's resolved identity: who, which computer, what it may call.
/// Policy is evaluated once, here, before any frame is sent.
#[derive(Debug, Clone)]
pub struct Caller {
    pub principal: String,
    pub computer: String,
    pub tools: ToolAllow,
    pub max_inflight: Option<usize>,
    /// The principal's `computers` is `"*"`.
    pub wildcard: bool,
}

#[derive(Debug, Clone)]
pub struct Computer {
    pub name: String,
    pub secret: Verifier,
    pub max_inflight: usize,
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
    pub computers: Vec<Computer>,
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
    /// Per-computer default for `max_inflight`.
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

        // ---- computers -------------------------------------------------
        if raw.vm.is_some() && !raw.computers.is_empty() {
            bail!(
                "[vm] and [[computer]] are both present. [vm] is the v1 form of a single \
                 computer named `{DEFAULT_COMPUTER}`; write every computer as a \
                 [[computer]] block instead"
            );
        }
        let v2_blocks = !raw.computers.is_empty();
        let mut computers: Vec<Computer> = Vec::new();
        if let Some(vm) = &raw.vm {
            computers.push(Computer {
                name: DEFAULT_COMPUTER.to_owned(),
                secret: Verifier::parse(&vm.secret_sha256).context("[vm].secret_sha256")?,
                max_inflight,
            });
        }
        for c in &raw.computers {
            let owner = format!("[[computer]] {:?}", c.name);
            check_computer_name(&c.name, &owner)?;
            if computers.iter().any(|other| other.name == c.name) {
                bail!("{owner}: duplicate name");
            }
            let secret = Verifier::parse(&c.secret_sha256).with_context(|| owner.clone())?;
            if computers.iter().any(|other| other.secret == secret) {
                bail!(
                    "{owner}: `secret_sha256` is already another computer's. The secret \
                     alone selects the slot, so one verifier is one computer"
                );
            }
            computers.push(Computer {
                name: c.name.clone(),
                secret,
                max_inflight: in_flight_cap(c.max_inflight, &owner)?.unwrap_or(max_inflight),
            });
        }
        if computers.is_empty() {
            bail!("no [[computer]] (and no v1 [vm]): there is nothing to relay to");
        }
        let configured: Vec<&str> = computers.iter().map(|c| c.name.as_str()).collect();

        // ---- clients ---------------------------------------------------
        let mut names = HashSet::new();
        let mut clients: Vec<Client> = Vec::new();
        for c in raw.clients {
            let owner = format!("[[client]] {:?}", c.name);
            check_name(&c.name, &owner)?;
            if !names.insert(c.name.clone()) {
                bail!("{owner}: duplicate name");
            }
            let token = Verifier::parse(&c.token_sha256).with_context(|| owner.clone())?;
            if let Some(computer) = computers.iter().find(|m| m.secret == token) {
                bail!(
                    "{owner}: token equals computer {:?}'s secret; they must differ",
                    computer.name
                );
            }
            if clients.iter().any(|other| other.token == token) {
                bail!("{owner}: token is shared with another client");
            }
            let access = match (c.tools.as_deref(), c.computers.as_ref()) {
                (Some(_), Some(_)) => bail!(
                    "{owner}: `tools` and `computers` are both set. `tools` is the v1 form \
                     (one computer); keep `computers` only"
                ),
                (Some(tools), None) => {
                    if v2_blocks {
                        bail!(
                            "{owner}: `tools` is the v1 form and names no computer, but this \
                             config has [[computer]] blocks. Write \
                             `computers = {{ <name> = [...] }}`"
                        );
                    }
                    ComputerAccess::one(DEFAULT_COMPUTER, ToolAllow::parse(tools, &owner)?)
                }
                (None, Some(map)) => ComputerAccess::parse(map, &owner)?,
                (None, None) => bail!(
                    "{owner}: no `computers`; name at least one computer and its tools, or \
                     use {{ \"*\" = [\"*\"] }}"
                ),
            };
            check_names_exist(&access, &configured, &owner)?;
            let default_computer =
                resolve_default(c.default_computer.as_deref(), &access, &configured, &owner)?;
            clients.push(Client {
                principal: Principal {
                    name: c.name,
                    computers: access,
                    default_computer,
                    max_inflight: in_flight_cap(c.max_inflight, &owner)?,
                },
                token,
            });
        }

        // ---- pty attaches ----------------------------------------------
        let mut pty_attach: Vec<PtyAttach> = Vec::new();
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
            let computer = match p.computer.as_deref() {
                Some(name) => {
                    if !configured.contains(&name) {
                        bail!("{owner}: `computer = {name:?}` is not a configured computer");
                    }
                    name.to_owned()
                }
                None if configured.len() == 1 => configured[0].to_owned(),
                None => bail!(
                    "{owner}: `computer` is required: {} computers are configured, so which \
                     one is lent to this session cannot be guessed",
                    configured.len()
                ),
            };
            let tools = ToolAllow::parse(&p.tools, &owner)?;
            pty_attach.push(PtyAttach {
                principal: Principal {
                    name: p.name,
                    computers: ComputerAccess::one(&computer, tools),
                    default_computer: computer,
                    max_inflight: in_flight_cap(p.max_inflight, &owner)?,
                },
                url: p.url,
                secret_file: expand_home(&p.secret_file),
            });
        }

        if clients.is_empty() && pty_attach.is_empty() {
            bail!("no [[client]] and no [[pty_attach]]: nothing could ever call a computer");
        }

        Ok(Self {
            listen,
            max_inflight,
            audit_args: raw.audit_args,
            audit_path: raw.audit_path.as_deref().map(expand_home),
            timeouts,
            auth: Auth { computers, clients },
            pty_attach,
        })
    }

    /// Every caller that may reach every computer, now and later. Startup and
    /// `check` name these, because adding a computer widens them silently.
    pub fn wildcard_clients(&self) -> Vec<&str> {
        self.auth
            .clients
            .iter()
            .filter(|c| c.principal.computers.is_any())
            .map(|c| c.principal.name.as_str())
            .collect()
    }

    /// Computers no client and no pty attach may use. `check` warns about them:
    /// a configured computer nobody can reach is either a typo or dead config.
    pub fn unused_computers(&self) -> Vec<&str> {
        let principals = || {
            self.auth
                .clients
                .iter()
                .map(|c| &c.principal)
                .chain(self.pty_attach.iter().map(|p| &p.principal))
        };
        if principals().any(|p| p.computers.is_any()) {
            return Vec::new();
        }
        let mut used: BTreeSet<&str> = BTreeSet::new();
        for principal in principals() {
            if let Some(names) = principal.computers.names() {
                used.extend(names);
            }
        }
        self.auth
            .computers
            .iter()
            .map(|c| c.name.as_str())
            .filter(|name| !used.contains(name))
            .collect()
    }
}

/// `default_computer`, or the only reachable computer when there is exactly one.
fn resolve_default(
    wanted: Option<&str>,
    access: &ComputerAccess,
    configured: &[&str],
    owner: &str,
) -> Result<String> {
    if let Some(name) = wanted {
        if !configured.contains(&name) {
            bail!("{owner}: `default_computer = {name:?}` is not a configured computer");
        }
        if access.tools_on(name).is_none() {
            bail!(
                "{owner}: `default_computer = {name:?}` is not in this caller's `computers`, \
                 so POST /mcp would resolve to a computer it may not use"
            );
        }
        return Ok(name.to_owned());
    }
    match access {
        // `"*"` reaches computers that do not exist yet, so bare /mcp must be
        // pinned by hand or its meaning would depend on the config order.
        ComputerAccess::Any(_) => bail!(
            "{owner}: `computers = {{ \"*\" = … }}` reaches every computer, so \
             `default_computer` is required to fix what POST /mcp means"
        ),
        ComputerAccess::Named(named) if named.len() == 1 => {
            Ok(named.keys().next().expect("len == 1").clone())
        }
        ComputerAccess::Named(named) => bail!(
            "{owner}: {} computers are reachable, so `default_computer` is required to fix \
             what POST /mcp means",
            named.len()
        ),
    }
}

/// Every computer a caller names must already be configured. Without this a
/// typo grants nothing today and pre-grants access to whatever takes that name
/// later.
fn check_names_exist(access: &ComputerAccess, configured: &[&str], owner: &str) -> Result<()> {
    let Some(names) = access.names() else {
        return Ok(());
    };
    for name in names {
        if !configured.contains(&name) {
            bail!(
                "{owner}: `computers` names {name:?}, which is not a configured [[computer]]. \
                 A name that exists later would inherit this grant"
            );
        }
    }
    Ok(())
}

fn in_flight_cap(value: Option<usize>, owner: &str) -> Result<Option<usize>> {
    if let Some(n) = value {
        if !(1..=MAX_MAX_INFLIGHT).contains(&n) {
            bail!("{owner}: `max_inflight` must be 1..={MAX_MAX_INFLIGHT}");
        }
    }
    Ok(value)
}

/// Client and pty-attach names. v1's rule, `.` included.
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

/// Computer names. Stricter than [`check_name`]: no `.`, because a bare TOML
/// key such as `rpi1.local` is a dotted key and would make a nested table.
fn check_computer_name(name: &str, owner: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if !ok {
        if name.contains('.') {
            bail!(
                "{owner}: a computer name may not contain `.`: as a bare TOML key \
                 `{name}` is a dotted key and would make a nested table. Use \
                 `{}` instead",
                name.replace('.', "-")
            );
        }
        bail!("{owner}: a computer name must be 1-64 chars of [A-Za-z0-9_-]");
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

    /// A v1 file: `[vm]` plus a client with `tools`.
    fn base(extra: &str) -> String {
        format!(
            "[vm]\nsecret_sha256 = \"{}\"\n\n[[client]]\nname = \"connect\"\ntoken_sha256 = \"{}\"\ntools = [\"screenshot\", \"sys_info\"]\n{extra}",
            v("vm"),
            v("c1")
        )
    }

    /// A v2 file with `n` computers (`m1`, `m2`, …) and no clients.
    fn computers(n: usize) -> String {
        (1..=n)
            .map(|i| {
                format!(
                    "[[computer]]\nname = \"m{i}\"\nsecret_sha256 = \"{}\"\n\n",
                    v(&format!("m{i}"))
                )
            })
            .collect()
    }

    fn client(extra: &str) -> String {
        format!(
            "[[client]]\nname = \"c\"\ntoken_sha256 = \"{}\"\n{extra}",
            v("ct")
        )
    }

    fn err(text: &str) -> String {
        format!("{:#}", Config::parse(text).unwrap_err())
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
        let caller = client.principal.resolve(None).unwrap();
        assert!(caller.tools.allows("screenshot"));
        assert!(!caller.tools.allows("bash"));
        assert!(c.auth.client_for("vm").is_none());
    }

    // ---- v1 compatibility -------------------------------------------------

    #[test]
    fn a_v1_config_maps_to_the_default_computer_exactly() {
        let attach = "[[pty_attach]]\nname = \"pod\"\nurl = \"ws://127.0.0.1:8091/tools/attach/s\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n";
        let c = Config::parse(&base(attach)).unwrap();
        // [vm] became one computer named `default`, with the global max_inflight.
        assert_eq!(c.auth.computers.len(), 1);
        assert_eq!(c.auth.computers[0].name, DEFAULT_COMPUTER);
        assert_eq!(c.auth.computers[0].max_inflight, DEFAULT_MAX_INFLIGHT);
        assert!(c.auth.computers[0].secret == Verifier::of_secret("vm"));
        // `tools` became computers = { default = [...] }, default_computer = default.
        let p = &c.auth.client_for("c1").unwrap().principal;
        assert_eq!(p.default_computer, DEFAULT_COMPUTER);
        assert!(!p.computers.is_any());
        assert!(p.computers.tools_on(DEFAULT_COMPUTER).is_some());
        assert!(p.computers.tools_on("macmini").is_none());
        assert_eq!(p.max_inflight, None);
        // [[pty_attach]] without `computer` targets `default`.
        assert_eq!(c.pty_attach[0].principal.default_computer, DEFAULT_COMPUTER);
        assert!(c.unused_computers().is_empty());
    }

    #[test]
    fn refuses_vm_together_with_computer_blocks() {
        let block = format!(
            "\n[[computer]]\nname = \"m1\"\nsecret_sha256 = \"{}\"\n",
            v("m1")
        );
        let text = format!("{}{block}", base(""));
        assert!(err(&text).contains("[vm] and [[computer]]"));
    }

    #[test]
    fn refuses_v1_tools_beside_computer_blocks() {
        let text = format!("{}{}", computers(1), client("tools = [\"*\"]\n"));
        assert!(err(&text).contains("v1 form"));
        // ... and `tools` beside `computers` on one client.
        let both = format!(
            "{}{}",
            computers(1),
            client("tools = [\"*\"]\ncomputers = { m1 = [\"*\"] }\n")
        );
        assert!(err(&both).contains("both set"));
        // ... and neither.
        assert!(err(&format!("{}{}", computers(1), client(""))).contains("no `computers`"));
    }

    // ---- computer identity ------------------------------------------------

    #[test]
    fn refuses_a_duplicate_verifier_anywhere() {
        // computer against computer
        let dup = format!(
            "{}[[computer]]\nname = \"m2\"\nsecret_sha256 = \"{}\"\n{}",
            computers(1),
            v("m1"),
            client("computers = { m1 = [\"*\"] }\n")
        );
        assert!(err(&dup).contains("already another computer's"));
        // computer against client
        let shared = format!(
            "{}[[client]]\nname = \"c\"\ntoken_sha256 = \"{}\"\ncomputers = {{ m1 = [\"*\"] }}\n",
            computers(1),
            v("m1")
        );
        assert!(err(&shared).contains("must differ"));
        // client against client (v1 rule kept)
        let twice = format!(
            "{}{}[[client]]\nname = \"d\"\ntoken_sha256 = \"{}\"\ncomputers = {{ m1 = [\"*\"] }}\n",
            computers(1),
            client("computers = { m1 = [\"*\"] }\n"),
            v("ct")
        );
        assert!(err(&twice).contains("shared with another client"));
        // duplicate computer name
        let same_name = format!(
            "{}[[computer]]\nname = \"m1\"\nsecret_sha256 = \"{}\"\n{}",
            computers(1),
            v("other"),
            client("computers = { m1 = [\"*\"] }\n")
        );
        assert!(err(&same_name).contains("duplicate name"));
    }

    #[test]
    fn refuses_a_dot_in_a_computer_name() {
        let text = format!(
            "[[computer]]\nname = \"rpi1.local\"\nsecret_sha256 = \"{}\"\n{}",
            v("m1"),
            client("computers = { m1 = [\"*\"] }\n")
        );
        let message = err(&text);
        assert!(message.contains("may not contain `.`"), "{message}");
        assert!(message.contains("rpi1-local"), "{message}");
        // The same rule applies to a `computers` key.
        let key = format!(
            "{}{}",
            computers(1),
            client("computers = { \"m1.local\" = [\"*\"] }\n")
        );
        assert!(err(&key).contains("may not contain `.`"));
        // Clients keep v1's rule, `.` included.
        let dotted = format!(
            "{}[[client]]\nname = \"a.b\"\ntoken_sha256 = \"{}\"\ncomputers = {{ m1 = [\"*\"] }}\n",
            computers(1),
            v("ct")
        );
        assert!(Config::parse(&dotted).is_ok());
    }

    #[test]
    fn per_computer_max_inflight_overrides_the_global_default() {
        let text = format!(
            "max_inflight = 8\n[[computer]]\nname = \"m1\"\nsecret_sha256 = \"{}\"\nmax_inflight = 4\n{}",
            v("m1"),
            client("computers = { m1 = [\"*\"] }\n")
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.auth.computers[0].max_inflight, 4);
        let bad = text.replace("max_inflight = 4", "max_inflight = 65");
        assert!(err(&bad).contains("must be 1..=64"));
    }

    // ---- per-caller access ------------------------------------------------

    #[test]
    fn refuses_wildcard_mixed_with_named_computers() {
        let text = format!(
            "{}{}",
            computers(1),
            client("default_computer = \"m1\"\ncomputers = { \"*\" = [\"*\"], m1 = [\"*\"] }\n")
        );
        assert!(err(&text).contains("mixes \"*\" with computer names"));
    }

    #[test]
    fn refuses_an_empty_computers_table() {
        let text = format!("{}{}", computers(1), client("computers = {}\n"));
        assert!(err(&text).contains("`computers` is empty"));
        // An empty tool list on a named computer is v1's rule.
        let empty_tools = format!("{}{}", computers(1), client("computers = { m1 = [] }\n"));
        assert!(err(&empty_tools).contains("`tools` is empty"));
        let mixed = format!(
            "{}{}",
            computers(1),
            client("computers = { m1 = [\"*\", \"bash\"] }\n")
        );
        assert!(err(&mixed).contains("mixes \"*\" with names"));
    }

    #[test]
    fn requires_default_computer_when_more_than_one_is_reachable() {
        // One named computer: optional, and it is the default.
        let one = format!(
            "{}{}",
            computers(2),
            client("computers = { m1 = [\"*\"] }\n")
        );
        let c = Config::parse(&one).unwrap();
        assert_eq!(c.auth.clients[0].principal.default_computer, "m1");
        // Two named: required.
        let two = format!(
            "{}{}",
            computers(2),
            client("computers = { m1 = [\"*\"], m2 = [\"*\"] }\n")
        );
        assert!(err(&two).contains("`default_computer` is required"));
        let fixed = format!(
            "{}{}",
            computers(2),
            client("default_computer = \"m2\"\ncomputers = { m1 = [\"*\"], m2 = [\"*\"] }\n")
        );
        assert_eq!(
            Config::parse(&fixed).unwrap().auth.clients[0]
                .principal
                .default_computer,
            "m2"
        );
        // `"*"` reaches computers added later, so it always needs one.
        let any = format!(
            "{}{}",
            computers(1),
            client("computers = { \"*\" = [\"*\"] }\n")
        );
        assert!(err(&any).contains("`default_computer` is required"));
        let any_ok = format!(
            "{}{}",
            computers(1),
            client("default_computer = \"m1\"\ncomputers = { \"*\" = [\"*\"] }\n")
        );
        let c = Config::parse(&any_ok).unwrap();
        assert!(c.auth.clients[0].principal.computers.is_any());
        assert_eq!(c.wildcard_clients(), vec!["c"]);
    }

    #[test]
    fn refuses_a_computer_name_that_is_not_configured() {
        let typo = format!(
            "{}{}",
            computers(1),
            client("computers = { macmni = [\"*\"] }\n")
        );
        assert!(err(&typo).contains("not a configured [[computer]]"));
        let default_typo = format!(
            "{}{}",
            computers(1),
            client("default_computer = \"nope\"\ncomputers = { m1 = [\"*\"] }\n")
        );
        assert!(err(&default_typo).contains("not a configured computer"));
        // Configured, but not this caller's.
        let unreachable = format!(
            "{}{}",
            computers(2),
            client("default_computer = \"m2\"\ncomputers = { m1 = [\"*\"] }\n")
        );
        assert!(err(&unreachable).contains("not in this caller's `computers`"));
        let attach_typo = format!(
            "{}{}{}",
            computers(1),
            client("computers = { m1 = [\"*\"] }\n"),
            "[[pty_attach]]\nname = \"pod\"\ncomputer = \"nope\"\nurl = \"ws://127.0.0.1:1/t\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n"
        );
        assert!(err(&attach_typo).contains("is not a configured computer"));
    }

    #[test]
    fn refuses_a_per_caller_max_inflight_out_of_range() {
        for bad in ["0", "65"] {
            let text = format!(
                "{}{}",
                computers(1),
                client(&format!(
                    "computers = {{ m1 = [\"*\"] }}\nmax_inflight = {bad}\n"
                ))
            );
            assert!(err(&text).contains("must be 1..=64"), "{bad}");
        }
        let ok = format!(
            "{}{}",
            computers(1),
            client("computers = { m1 = [\"*\"] }\nmax_inflight = 4\n")
        );
        assert_eq!(
            Config::parse(&ok).unwrap().auth.clients[0]
                .principal
                .max_inflight,
            Some(4)
        );
    }

    // ---- pty attaches -----------------------------------------------------

    #[test]
    fn pty_attach_names_its_computer_when_there_are_several() {
        let attach = |extra: &str| {
            format!(
                "{}{}[[pty_attach]]\nname = \"pod\"\n{extra}url = \"ws://127.0.0.1:8091/tools/attach/s\"\nsecret_file = \"/tmp/x\"\ntools = [\"screenshot\"]\n",
                computers(2),
                client("computers = { m1 = [\"*\"] }\n"),
            )
        };
        assert!(err(&attach("")).contains("`computer` is required"));
        let c = Config::parse(&attach("computer = \"m2\"\n")).unwrap();
        let p = &c.pty_attach[0].principal;
        assert_eq!(p.default_computer, "m2");
        assert!(p.computers.tools_on("m2").unwrap().allows("screenshot"));
        assert!(p.computers.tools_on("m1").is_none());
        // One computer: `computer` may be left out.
        let single = format!(
            "{}{}[[pty_attach]]\nname = \"pod\"\nurl = \"ws://127.0.0.1:8091/t\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\nmax_inflight = 3\n",
            computers(1),
            client("computers = { m1 = [\"*\"] }\n"),
        );
        let c = Config::parse(&single).unwrap();
        assert_eq!(c.pty_attach[0].principal.default_computer, "m1");
        assert_eq!(c.pty_attach[0].principal.max_inflight, Some(3));
    }

    #[test]
    fn check_warns_about_a_computer_no_caller_may_use() {
        let text = format!(
            "{}{}",
            computers(2),
            client("computers = { m1 = [\"*\"] }\n")
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.unused_computers(), vec!["m2"]);
        // A pty attach counts as a caller.
        let lent = format!(
            "{}{}[[pty_attach]]\nname = \"pod\"\ncomputer = \"m2\"\nurl = \"ws://127.0.0.1:1/t\"\nsecret_file = \"/tmp/x\"\ntools = [\"*\"]\n",
            computers(2),
            client("computers = { m1 = [\"*\"] }\n"),
        );
        assert!(Config::parse(&lent).unwrap().unused_computers().is_empty());
        // So does a `"*"` client, including for computers added later.
        let any = format!(
            "{}{}",
            computers(2),
            client("default_computer = \"m1\"\ncomputers = { \"*\" = [\"*\"] }\n")
        );
        assert!(Config::parse(&any).unwrap().unused_computers().is_empty());
    }

    // ---- unchanged v1 rules ----------------------------------------------

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
    fn refuses_a_config_with_no_computer() {
        let text = client("computers = { m1 = [\"*\"] }\n");
        assert!(err(&text).contains("nothing to relay to"));
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
        assert_eq!(c.auth.computers.len(), 2);
        assert_eq!(c.auth.clients.len(), 2);
        assert_eq!(c.timeouts.for_tool("bash"), Duration::from_secs(60));
        assert!(c.unused_computers().is_empty());
        assert_eq!(c.wildcard_clients(), vec!["agent"]);
    }

    #[test]
    fn rejects_unknown_keys() {
        let text = format!("lisen = \"127.0.0.1:1\"\n{}", base(""));
        assert!(Config::parse(&text).is_err());
    }
}
