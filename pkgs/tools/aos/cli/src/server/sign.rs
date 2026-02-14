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

    /// Sign a narinfo fingerprint. Returns `name:base64_sig` or None if no key.
    pub fn sign(&self, fingerprint: &str) -> Option<String> {
        let (name, secret) = self.key_data.as_ref()?;
        // The Nix key format stores 64 bytes: first 32 = ed25519 secret, last 32 = public
        // ed25519_dalek::SigningKey takes the 32-byte secret seed
        use ed25519_dalek::{Signer, SigningKey};
        let key_bytes: [u8; 32] = secret[..32].try_into().ok()?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(fingerprint.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        Some(format!("{name}:{sig_b64}"))
    }

    /// Compute the narinfo fingerprint for signing.
    pub fn fingerprint(store_path: &str, nar_hash: &str, nar_size: i64, refs: &[String]) -> String {
        let refs_str = refs.join(",");
        format!("1;{store_path};{nar_hash};{nar_size};{refs_str}")
    }
}
