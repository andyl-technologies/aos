//! AEAD secret sealing: the [`SecretSealer`] seam and its implementations.
//!
//! The hub holds two classes of long-lived secrets in its database — per-org
//! OIDC client secrets and hosted-key Ed25519 signing seeds — stored **sealed**
//! and unsealed only at the instant they are used. This module owns the pure,
//! runtime-agnostic sealing crypto shared by the native hub and the Cloudflare
//! Worker (RFC-0004 Phase 5): the [`SecretSealer`] trait, the production
//! [`AesGcmSealer`], the dev/test placeholder [`XorSealer`], and the
//! [`parse_key`] instance-key decoder.
//!
//! The IO-bound key *loading* (read/create `secret.key` on disk, or honor the
//! `AOS_HUB_SECRET_KEY_FILE` env var) stays in the native hub's `auth::seal`
//! module; on the Worker the instance key is supplied from a binding. The
//! crypto here touches neither the filesystem nor the environment.
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

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use rand::Rng as _;

/// Size of the AES-256 instance key, in bytes.
pub const KEY_LEN: usize = 32;

/// Size of the AES-GCM nonce, in bytes (96 bits).
const NONCE_LEN: usize = 12;

/// Seals and unseals client secrets at rest.
///
/// The hub stores OIDC client secrets *sealed* and unseals them only at the
/// instant of the token exchange. Production uses [`AesGcmSealer`]; the
/// placeholder [`XorSealer`] is reachable only under `--dev` and in tests.
pub trait SecretSealer: Send + Sync {
    /// Seals a plaintext secret into the at-rest form stored in
    /// `org_idp_configs.client_secret_enc`.
    ///
    /// # Errors
    ///
    /// Returns an error if sealing fails (never, for [`XorSealer`]).
    fn seal(&self, plaintext: &str) -> Result<String>;

    /// Unseals an at-rest secret back to plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if the sealed value is malformed or cannot be
    /// unsealed.
    fn unseal(&self, sealed: &str) -> Result<String>;
}

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

/// A **placeholder** [`SecretSealer`]: XOR with an instance key, base64url.
///
/// # ⚠️ Not real encryption
///
/// This is **not** confidentiality-grade. XOR with a repeating key is trivially
/// reversible by anyone who can read both the database and the instance key,
/// and offers no integrity. It exists only so client secrets can be stored in a
/// *non-plaintext* form behind the [`SecretSealer`] seam. It is **test/dev-only**:
/// production `serve` uses [`AesGcmSealer`] instead, and `XorSealer` is reachable
/// only under `--dev` (where reproducibility, not confidentiality, is the goal)
/// and in tests via [`dev_sealer`].
#[derive(Debug, Clone)]
pub struct XorSealer {
    key: Vec<u8>,
}

impl XorSealer {
    /// Builds a placeholder sealer from an instance key.
    ///
    /// The key should be high-entropy and at least a few bytes; an empty key
    /// is rejected so a misconfiguration cannot produce a no-op "seal".
    ///
    /// # Errors
    ///
    /// Returns an error when `key` is empty.
    pub fn new(key: &[u8]) -> Result<XorSealer> {
        if key.is_empty() {
            bail!("XorSealer instance key must not be empty");
        }
        Ok(XorSealer { key: key.to_vec() })
    }

    fn xor(&self, bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.key[i % self.key.len()])
            .collect()
    }
}

impl SecretSealer for XorSealer {
    fn seal(&self, plaintext: &str) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.xor(plaintext.as_bytes())))
    }

    fn unseal(&self, sealed: &str) -> Result<String> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sealed)
            .context("decoding sealed client secret")?;
        String::from_utf8(self.xor(&bytes)).context("unsealed client secret is not valid UTF-8")
    }
}

/// The fixed instance key the dev/test placeholder sealer uses.
const DEV_SEALER_KEY: &[u8] = b"aos-hub-dev-instance-key";

/// Builds the placeholder [`XorSealer`] used in dev mode and tests.
///
/// Uses a fixed non-empty instance key, so construction is infallible and no
/// panic path is introduced. **Never** use this in production — see
/// [`XorSealer`] for the (large) caveat.
#[must_use]
pub fn dev_sealer() -> std::sync::Arc<dyn SecretSealer> {
    std::sync::Arc::new(XorSealer {
        key: DEV_SEALER_KEY.to_vec(),
    })
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
pub fn parse_key(raw: &[u8]) -> Result<Vec<u8>> {
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
    fn xor_sealer_roundtrips() {
        let sealer = XorSealer::new(b"instance-key-0123456789").unwrap();
        let sealed = sealer.seal("super-secret-client-secret").unwrap();
        assert_ne!(sealed, "super-secret-client-secret");
        assert_eq!(
            sealer.unseal(&sealed).unwrap(),
            "super-secret-client-secret"
        );
    }

    #[test]
    fn xor_sealer_rejects_empty_key() {
        assert!(XorSealer::new(b"").is_err());
    }
}
