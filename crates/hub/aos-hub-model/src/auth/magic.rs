//! Single-use magic-link secret generation and expiration policy.

use rand::Rng;

/// How long a magic link stays valid, in seconds (15 minutes).
pub const MAGIC_LINK_TTL_SECS: i64 = 15 * 60;

/// Generates a fresh magic-link secret (256 bits as lowercase hex).
///
/// Only its SHA-256 hash is persisted; the plaintext is embedded in the
/// emailed URL.
#[must_use]
pub fn new_magic_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}
