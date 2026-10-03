//! Secrets and verifiers.
//!
//! The switchboard never stores a usable credential: config holds `sha256:<hex>`
//! verifiers, and a presented bearer is hashed once and compared in constant
//! time. A leaked config file or core dump connects to nothing.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// SHA-256 of a secret, parsed from or rendered as `sha256:<64 hex>`.
#[derive(Clone, PartialEq, Eq)]
pub struct Verifier([u8; 32]);

impl Verifier {
    pub fn parse(text: &str) -> Result<Self> {
        let hex_part = text
            .trim()
            .strip_prefix("sha256:")
            .context("verifier must start with `sha256:` (run `openab-sb hash` to make one)")?;
        let bytes = hex::decode(hex_part).context("verifier is not hex")?;
        let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            bail!("verifier must be 32 bytes (64 hex chars)");
        };
        Ok(Self(array))
    }

    pub fn of_secret(secret: &str) -> Self {
        Self(Sha256::digest(secret.as_bytes()).into())
    }

    /// Constant-time check of an already-hashed presentation.
    pub fn matches(&self, presented: &Verifier) -> bool {
        bool::from(self.0.ct_eq(&presented.0))
    }

    pub fn render(&self) -> String {
        format!("sha256:{}", hex::encode(self.0))
    }

    /// Short, non-reversible tag for audit lines (first 8 hex of the verifier).
    pub fn tag(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Verifier({}…)", self.tag())
    }
}

/// 32 random bytes from the OS, hex-encoded.
pub fn generate_secret() -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("OS entropy unavailable: {e}"))?;
    Ok(hex::encode(raw))
}

/// Extract the token from an `Authorization: Bearer <token>` header value.
pub fn bearer(header: Option<&str>) -> Option<&str> {
    let value = header?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_match() {
        let secret = generate_secret().unwrap();
        assert_eq!(secret.len(), 64);
        let v = Verifier::of_secret(&secret);
        let parsed = Verifier::parse(&v.render()).unwrap();
        assert!(parsed.matches(&Verifier::of_secret(&secret)));
        assert!(!parsed.matches(&Verifier::of_secret("nope")));
    }

    #[test]
    fn rejects_malformed_verifiers() {
        assert!(Verifier::parse("abcd").is_err());
        assert!(Verifier::parse("sha256:zz").is_err());
        assert!(Verifier::parse("sha256:abcd").is_err());
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer(Some("Bearer abc")), Some("abc"));
        assert_eq!(bearer(Some("bearer  abc ")), Some("abc"));
        assert_eq!(bearer(Some("Basic abc")), None);
        assert_eq!(bearer(Some("Bearer ")), None);
        assert_eq!(bearer(None), None);
    }
}
