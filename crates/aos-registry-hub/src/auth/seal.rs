//! AEAD-backed secret sealing for the hub's at-rest secrets.
//!
//! The hub holds two classes of long-lived secrets in its database: per-org
//! OIDC client secrets and hosted-key Ed25519 signing seeds. Both are stored
//! **sealed** and unsealed only at the instant they are used. This module
//! provides [`AesGcmSealer`], the production [`SecretSealer`], and
//! [`instance_sealer`], which loads (or creates) the per-instance key and
//! returns a sealer bound to it.
//!
//! # Sealed wire format
//!
//! A sealed value is base64url (no padding) over the concatenation of a fresh
//! 96-bit random nonce and the AES-256-GCM ciphertext (which carries the
//! 128-bit authentication tag as its suffix):
//!
//! ```text
//! sealed = base64url( nonce[12] || ciphertext || tag[16] )
//! ```
//!
//! A fresh nonce is drawn per seal, so two seals of the same plaintext differ.
//! Unsealing splits off the nonce, then AES-256-GCM decrypts and verifies the
//! tag; any tampering with the ciphertext, tag, or nonce makes unsealing fail.
//!
//! # Instance key
//!
//! The 256-bit instance key is sourced, in order:
//!
//! 1. from the file named by the `AOS_HUB_SECRET_KEY_FILE` environment
//!    variable (32 raw bytes, or 64 hex characters), if set; otherwise
//! 2. from `{root}/secret.key`, generated with `0600` permissions on first
//!    `serve` if absent and reloaded verbatim thereafter.
//!
//! Because the key is persisted, secrets sealed by one process unseal in the
//! next, and the CLI subcommands that seal ([`idp set`], [`hosted-key
//! create`]) use the same [`instance_sealer`] as `serve` so values round-trip.
//!
//! [`idp set`]: crate::auth::oidc
//! [`SecretSealer`]: crate::auth::oidc::SecretSealer
//! [`hosted-key create`]: crate::auth::oidc

use std::fs;
use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use rand::Rng as _;

use crate::auth::oidc::SecretSealer;

/// Size of the AES-256 instance key, in bytes.
const KEY_LEN: usize = 32;

/// Size of the AES-GCM nonce, in bytes (96 bits).
const NONCE_LEN: usize = 12;

/// A production [`SecretSealer`] using AES-256-GCM with a per-instance key.
///
/// Each seal draws a fresh 96-bit nonce, so the scheme is randomized and
/// integrity-protected: unsealing a tampered or truncated value fails rather
/// than returning corrupt plaintext. See the [module docs](self) for the
/// on-disk wire format.
pub struct AesGcmSealer {
    cipher: Aes256Gcm,
}

impl AesGcmSealer {
    /// Builds a sealer from a 256-bit instance key.
    ///
    /// # Errors
    ///
    /// Returns an error if `key` is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<AesGcmSealer> {
        if key.len() != KEY_LEN {
            bail!(
                "AES-256 instance key must be {KEY_LEN} bytes, got {}",
                key.len()
            );
        }
        let key = Key::<Aes256Gcm>::from_slice(key);
        Ok(AesGcmSealer {
            cipher: Aes256Gcm::new(key),
        })
    }
}

impl SecretSealer for AesGcmSealer {
    fn seal(&self, plaintext: &str) -> Result<String> {
        let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("AES-GCM seal failed: {e}"))?;
        let mut framed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        framed.extend_from_slice(&nonce_bytes);
        framed.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(framed))
    }

    fn unseal(&self, sealed: &str) -> Result<String> {
        let framed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sealed)
            .context("decoding sealed secret")?;
        if framed.len() < NONCE_LEN {
            bail!("sealed secret is too short to contain a nonce");
        }
        let (nonce_bytes, ciphertext) = framed.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("AES-GCM unseal failed: authentication tag mismatch"))?;
        String::from_utf8(plaintext).context("unsealed secret is not valid UTF-8")
    }
}

/// Loads or creates the per-instance key and returns an [`AesGcmSealer`].
///
/// The key is read from `AOS_HUB_SECRET_KEY_FILE` if that environment variable
/// is set, otherwise from `{root}/secret.key`, which is generated with `0600`
/// permissions on first call when absent. See the [module docs](self) for the
/// key-sourcing rules.
///
/// # Errors
///
/// Returns an error if the configured key file cannot be read or parsed, if a
/// new key cannot be written, or if the loaded key is not exactly 32 bytes
/// (or 64 hex characters).
pub fn instance_sealer(root: &Path) -> Result<Box<dyn SecretSealer>> {
    let key = load_or_create_key(root)?;
    Ok(Box::new(AesGcmSealer::new(&key)?))
}

/// Resolves the 32-byte instance key per the [module docs](self) ordering.
fn load_or_create_key(root: &Path) -> Result<Vec<u8>> {
    if let Some(path) = std::env::var_os("AOS_HUB_SECRET_KEY_FILE") {
        let path = Path::new(&path);
        let raw = fs::read(path)
            .with_context(|| format!("reading AOS_HUB_SECRET_KEY_FILE at {}", path.display()))?;
        return parse_key(&raw)
            .with_context(|| format!("parsing instance key at {}", path.display()));
    }

    let path = root.join("secret.key");
    if path.exists() {
        let raw = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        parse_key(&raw).with_context(|| format!("parsing instance key at {}", path.display()))
    } else {
        let key: [u8; KEY_LEN] = rand::rng().random();
        write_key_0600(&path, &key)?;
        Ok(key.to_vec())
    }
}

/// Interprets a key file's bytes as either 32 raw bytes or 64 hex characters.
///
/// Surrounding ASCII whitespace (so a trailing newline on a hex file is fine)
/// is trimmed before the hex interpretation is attempted.
///
/// # Errors
///
/// Returns an error if the input is neither 32 raw bytes nor a 64-character
/// hex string.
fn parse_key(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() == KEY_LEN {
        return Ok(raw.to_vec());
    }
    let trimmed = std::str::from_utf8(raw).map(str::trim).unwrap_or_default();
    if trimmed.len() == KEY_LEN * 2 {
        if let Ok(bytes) = hex::decode(trimmed) {
            return Ok(bytes);
        }
    }
    bail!(
        "instance key must be {KEY_LEN} raw bytes or {} hex chars",
        KEY_LEN * 2
    );
}

/// Writes `key` to `path` with `0600` permissions, creating parent dirs.
///
/// # Errors
///
/// Returns an error if the parent directory or the file cannot be created or
/// its permissions cannot be set.
fn write_key_0600(path: &Path, key: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    fs::write(path, key).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    #[test]
    fn seal_unseal_roundtrip() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let sealed = sealer.seal("super-secret").unwrap();
        assert_eq!(sealer.unseal(&sealed).unwrap(), "super-secret");
    }

    #[test]
    fn nonce_makes_repeated_seals_differ() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let a = sealer.seal("same").unwrap();
        let b = sealer.seal("same").unwrap();
        assert_ne!(a, b, "fresh nonce must randomize the ciphertext");
        assert_eq!(sealer.unseal(&a).unwrap(), "same");
        assert_eq!(sealer.unseal(&b).unwrap(), "same");
    }

    #[test]
    fn tampering_is_detected() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let sealed = sealer.seal("integrity").unwrap();
        let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&sealed)
            .unwrap();
        // Flip a byte in the ciphertext region (past the 12-byte nonce).
        let idx = bytes.len() - 1;
        bytes[idx] ^= 0x01;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        assert!(sealer.unseal(&tampered).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let sealed = sealer.seal("for-key-a").unwrap();
        let other = AesGcmSealer::new(&[9u8; KEY_LEN]).unwrap();
        assert!(other.unseal(&sealed).is_err());
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(AesGcmSealer::new(b"too-short").is_err());
    }

    #[test]
    fn parse_key_accepts_raw_and_hex() {
        let raw = vec![3u8; KEY_LEN];
        assert_eq!(parse_key(&raw).unwrap(), raw);
        let hexed = hex::encode(&raw);
        assert_eq!(parse_key(hexed.as_bytes()).unwrap(), raw);
        // Trailing newline on the hex form is tolerated.
        let with_nl = format!("{hexed}\n");
        assert_eq!(parse_key(with_nl.as_bytes()).unwrap(), raw);
        assert!(parse_key(b"nope").is_err());
    }

    #[test]
    fn instance_sealer_creates_and_reloads_persistent_key() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // No env override for this test.
        std::env::remove_var("AOS_HUB_SECRET_KEY_FILE");

        let first = instance_sealer(root).unwrap();
        let sealed = first.seal("persisted").unwrap();
        assert!(root.join("secret.key").exists());

        // A second sealer over the same root loads the same key and unseals.
        let second = instance_sealer(root).unwrap();
        assert_eq!(second.unseal(&sealed).unwrap(), "persisted");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(root.join("secret.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be 0600");
        }
    }
}
