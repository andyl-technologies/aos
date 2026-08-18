//! Access and refresh-token secret generation and hashing.
//!
//! A provisioning token is the long-lived machine credential at the bottom
//! of the auth chain. Its plaintext secret is shown exactly once — at
//! creation or rotation — and only its SHA-256 hash is persisted, so a
//! database leak never yields a usable credential.
//!
//! The secret wire format is an `aos_`-prefixed, 40-hex-character string:
//!
//! ```text
//! aos_3f9a1c0b7e5d2648fa01bc93de77105a6b4c8d2e
//! └┬─┘└──────────────────┬───────────────────┘
//!  │                     └ 20 random bytes, lowercase hex (40 chars)
//!  └ fixed "aos_" prefix that marks an AOS provisioning secret
//! ```
//!
//! The hash stored in `tokens.hash` is the lowercase hex SHA-256 of the
//! whole plaintext (prefix included). Both `Database` token
//! and session/device/magic methods funnel their hashing through
//! [`sha256_hex`] so the on-disk hash format is defined in exactly one
//! place.

use rand::Rng;
use sha2::{Digest, Sha256};

/// Idle lifetime of a CLI refresh credential.
pub const REFRESH_TOKEN_IDLE_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Absolute lifetime of a CLI refresh-token family.
pub const REFRESH_TOKEN_ABSOLUTE_TTL_SECS: i64 = 90 * 24 * 60 * 60;

/// Generates a fresh provisioning-token secret and its storage hash.
///
/// Returns `(secret, hash)`: the `secret` is the `aos_`-prefixed plaintext
/// to hand to the client once, and `hash` is the lowercase hex SHA-256 of
/// that plaintext to persist in `tokens.hash`. The random portion is 20
/// bytes (160 bits) of CSPRNG output.
///
/// # Examples
///
/// ```no_run
/// use aos_hub_core::auth::token::{generate_token, sha256_hex};
///
/// let (secret, hash) = generate_token();
/// assert!(secret.starts_with("aos_"));
/// assert_eq!(hash, sha256_hex(&secret));
/// ```
#[must_use]
pub fn generate_token() -> (String, String) {
    let random_bytes: [u8; 20] = rand::rng().random();
    let secret = format!("aos_{}", hex::encode(random_bytes));
    let hash = sha256_hex(&secret);
    (secret, hash)
}

/// Generates a fresh opaque refresh credential and its storage hash.
///
/// The `aosr_` prefix distinguishes a refresh credential from an ordinary
/// scoped access-token secret. The random portion contains 256 bits from the
/// process CSPRNG. Only the returned hash may be persisted.
#[must_use]
pub fn generate_refresh_token() -> (String, String) {
    let random_bytes: [u8; 32] = rand::rng().random();
    let secret = format!("aosr_{}", hex::encode(random_bytes));
    let hash = sha256_hex(&secret);
    (secret, hash)
}

/// Generates a fresh invitation-acceptance secret and its storage hash.
///
/// The `aosi_` prefix distinguishes the one-time human invitation ceremony
/// from access and refresh credentials. The random portion contains 256 bits
/// from the process CSPRNG. The plaintext must never be stored directly; the
/// invitation lifecycle may retain a copy only after sealing it with the
/// runtime's durable at-rest key so an exact apply retry can recover it.
#[must_use]
pub fn generate_invitation_token() -> (String, String) {
    let random_bytes: [u8; 32] = rand::rng().random();
    let secret = format!("aosi_{}", hex::encode(random_bytes));
    let hash = sha256_hex(&secret);
    (secret, hash)
}

/// Returns whether `secret` has the canonical invitation-token wire shape.
///
/// This structural check is suitable before placing an invitation credential
/// in an HTTP cookie. It does not authenticate the token; callers must still
/// compare its hash through the database acceptance ceremony.
#[must_use]
pub fn is_invitation_token(secret: &str) -> bool {
    secret.len() == 69
        && secret.strip_prefix("aosi_").is_some_and(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

/// Computes the lowercase hex SHA-256 digest of `input`.
///
/// This is the one hashing primitive shared by every credential store in
/// the hub's db layer: tokens, sessions, device codes, and magic links all hash
/// their secrets this way before they touch the database.
#[must_use]
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_has_prefix_and_length() {
        let (secret, hash) = generate_token();
        assert!(secret.starts_with("aos_"));
        // "aos_" (4) + 20 bytes as hex (40) = 44 chars.
        assert_eq!(secret.len(), 44);
        assert!(secret["aos_".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(hash, sha256_hex(&secret));
        // The hash is 32 bytes as hex.
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn generate_is_unique() {
        let (a, _) = generate_token();
        let (b, _) = generate_token();
        assert_ne!(a, b, "two secrets must not collide");
    }

    #[test]
    fn refresh_token_has_distinct_prefix_and_full_entropy() {
        let (secret, hash) = generate_refresh_token();
        assert!(secret.starts_with("aosr_"));
        assert_eq!(secret.len(), 69);
        assert_eq!(hash, sha256_hex(&secret));
    }

    #[test]
    fn invitation_token_has_distinct_prefix_and_full_entropy() {
        let (secret, hash) = generate_invitation_token();
        assert!(secret.starts_with("aosi_"));
        assert_eq!(secret.len(), 69);
        assert_eq!(hash, sha256_hex(&secret));
        assert!(is_invitation_token(&secret));
        assert!(!is_invitation_token("aosi_bad; SameSite=None"));
        assert!(!is_invitation_token(&format!("aosi_{}", "A".repeat(64))));
    }

    #[test]
    fn sha256_hex_is_stable() {
        // A known SHA-256 vector ("abc").
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
