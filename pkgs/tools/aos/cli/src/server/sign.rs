use std::path::Path;

use anyhow::{Context as _, Result};
use base64::Engine;

/// Optional narinfo signer using an ed25519 secret key.
pub struct NarInfoSigner {
    /// Key name and base64-encoded secret (if configured).
    key_data: Option<(String, Vec<u8>)>,
}

impl NarInfoSigner {
    /// Load the signing key from a file, or return a no-op signer.
    pub fn load(key_file: Option<&Path>) -> Result<Self> {
        let key_data = match key_file {
            Some(path) => {
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("reading signing key from {}", path.display()))?;
                let content = content.trim();
                let (name, b64) = content
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("signing key must be name:base64"))?;
                let secret = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .context("decoding signing key base64")?;
                Some((name.to_string(), secret))
            }
            None => None,
        };
        Ok(Self { key_data })
    }

    /// Return the key name, if configured.
    pub fn key_name(&self) -> Option<&str> {
        self.key_data.as_ref().map(|(name, _)| name.as_str())
    }

    /// Check if signing is configured.
    pub fn is_configured(&self) -> bool {
        self.key_data.is_some()
    }

    /// Compute the narinfo fingerprint for signing.
    pub fn fingerprint(store_path: &str, nar_hash: &str, nar_size: i64, refs: &[String]) -> String {
        let refs_str = refs.join(",");
        format!("1;{store_path};{nar_hash};{nar_size};{refs_str}")
    }
}
