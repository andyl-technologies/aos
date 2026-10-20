//! Pure bounded encryption framing for a future logical Hub archive.
//!
//! This layer authenticates arbitrary bytes, not rows, JSONL record grammar,
//! SQL/application/object closure, source provenance, import, or activation.
//! Callers supply the expected archive identity/role and external key custody.
//! Typed records and their end/count validation belong to a later layer.
//!
//! The fixed v1 binary grammar is:
//!
//! ```text
//! Header (36 bytes): "AOSHSTRM", version:u16=1, suite:u8=1,
//!     role:u8, archive_id:[u8;16], frame_cap:u32=262144, reserved:[0;4]
//! DATA: sequence:u64, kind:u8=0, reserved:[0;3], ciphertext_len:u32,
//!     ciphertext (nonempty plaintext plus 16-byte AES-256-GCM tag)
//! END: sequence:u64, kind:u8=1, reserved:[0;3], ciphertext_len:u32=16,
//!     data_frames:u64, plaintext_bytes:u64, prior_ciphertext_sha256:[u8;32],
//!     tag:[u8;16] (empty authenticated plaintext)
//! All integers are big-endian. END must be followed by EOF.
//! ```
//!
//! Each nonce is `AOSH || sequence_u64_be`. AAD includes a fixed domain,
//! the entire header and frame prefix; END also binds its complete commitment.
//! The prior digest covers the exact header and all preceding DATA prefixes and
//! ciphertexts, excluding END. No caller-selected algorithm, AAD or nonce exists.
//!
//! A writer consumes a fresh non-Clone encryption key. Its RNG must be an
//! unpredictable CSPRNG with fresh state; repeating a seeded generator violates
//! the trusted caller contract. The API cannot prove external entropy quality.
//! Reader-key import cannot construct a writer key. Streams are not resumable.
//! Owned key/plaintext buffers are zeroizing; cipher/library copies do not have
//! a perfect-erasure guarantee. Private callbacks remain explicit disclosure
//! boundaries. No filesystem, provider, SQL, network or runtime initialization
//! occurs here; blocking/liveness and immutable input custody are caller-owned.

use std::fmt;

use anyhow::Result;
use rand::TryCryptoRng;
use zeroize::Zeroizing;

mod frames;

pub mod root;

pub mod records;

pub use frames::{PrivateStreamChunk, StreamDecoder, StreamEncoder, StreamLimits, StreamSummary};

#[cfg(test)]
mod tests;

/// The only supported logical stream roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    /// Classified metadata and its future typed reports.
    Metadata,
    /// Exact private originals and their future provenance records.
    Private,
}

impl StreamRole {
    fn tag(self) -> u8 {
        match self {
            Self::Metadata => 1,
            Self::Private => 2,
        }
    }
}

/// Externally expected archive identity and fixed stream role.
///
/// A fresh archive ID is supplied by the capture owner. This is context binding,
/// not authenticated deployment identity, a signature or activation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamContext {
    archive_id: [u8; 16],
    role: StreamRole,
}

impl StreamContext {
    /// Creates the externally selected expected stream context.
    pub fn new(archive_id: [u8; 16], role: StreamRole) -> Self {
        Self { archive_id, role }
    }
}

/// A fresh one-use stream encryption key, consumed by an encoder.
///
/// It has no raw-byte import, Clone, or automatic serialization. The trusted
/// caller must provide fresh unpredictable RNG state for every stream/retry and
/// must not reuse this key for another purpose, stream or capture.
pub struct FreshStreamKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for FreshStreamKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshStreamKey { <redacted> }")
    }
}

impl FreshStreamKey {
    /// Generates fresh key material from an explicitly supplied trusted CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the RNG fails. RNG freshness and entropy
    /// quality are trusted caller obligations, not assertions proved by the API.
    pub fn generate(rng: &mut impl TryCryptoRng) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut bytes[..])
            .map_err(|_| anyhow::anyhow!("snapshot stream key generation failed"))?;
        Ok(Self(bytes))
    }

    /// Runs an explicitly private callback for key wrapping/custody.
    ///
    /// Copies and output made by the callback are sensitive and caller-owned.
    pub fn with_private_key_bytes<T>(&self, callback: impl FnOnce(&[u8; 32]) -> T) -> T {
        callback(&self.0)
    }
}

/// Externally unwrapped stream key material admitted only for decryption.
///
/// This type cannot be converted into a writer key. It has no automatic
/// serialization or Clone, and its Debug output is redacted.
pub struct StreamDecryptionKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for StreamDecryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamDecryptionKey { <redacted> }")
    }
}

impl StreamDecryptionKey {
    /// Accepts externally authenticated/unwrapped decryption material.
    ///
    /// The caller remains responsible for external wrapping/signature trust.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}
