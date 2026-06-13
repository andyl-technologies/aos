//! Opaque human cookie sessions.
//!
//! Humans authenticate with a session cookie rather than a bearer token.
//! The cookie value is a 256-bit opaque random secret; only its SHA-256
//! hash is stored (the `sessions.id_hash` column), the same
//! high-entropy-secret rationale as provisioning tokens. The cookie is
//! named [`COOKIE_NAME`] (`__Host-aos_session`) and the hub sets it
//! `Secure; HttpOnly; SameSite=Lax; Path=/` — the `__Host-` prefix binds
//! it to the exact origin with no `Domain` attribute.
//!
//! Sessions carry an `auth_level`: `1` marks a **sudo-capable** session
//! whose owner re-authenticated recently, gating destructive operations.
//! The session lifecycle (create, validate-and-bump, revoke, revoke-all,
//! elevate) lives on [`crate::db::Database`]; this module owns only the
//! secret format and the cookie name.

use rand::Rng;

/// The session cookie name, with the `__Host-` prefix that pins it to the
/// exact origin (`Secure`, `Path=/`, no `Domain`).
pub const COOKIE_NAME: &str = "__Host-aos_session";

/// The default idle timeout for a session, in seconds (7 days).
pub const IDLE_TIMEOUT_SECS: i64 = 7 * 24 * 60 * 60;

/// The default absolute session lifetime, in seconds (30 days).
pub const ABSOLUTE_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

/// Generates a fresh opaque session secret (256 bits as lowercase hex).
///
/// The returned value is the cookie value handed to the browser; only its
/// SHA-256 hash (via [`crate::auth::token::sha256_hex`]) is persisted.
#[must_use]
pub fn new_session_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Returns the `Set-Cookie` attribute string for a session cookie.
///
/// Produces `__Host-aos_session=<secret>; Secure; HttpOnly; SameSite=Lax;
/// Path=/; Max-Age=<max_age_secs>`. Pass the value returned by
/// [`crate::db::Database::create_session`] as `secret`.
#[must_use]
pub fn set_cookie_header(secret: &str, max_age_secs: i64) -> String {
    format!(
        "{COOKIE_NAME}={secret}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_256_bits_hex() {
        let s = new_session_secret();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(s, new_session_secret());
    }

    #[test]
    fn cookie_header_has_host_prefix_and_flags() {
        let h = set_cookie_header("abc", 3600);
        assert!(h.starts_with("__Host-aos_session=abc;"));
        assert!(h.contains("Secure"));
        assert!(h.contains("HttpOnly"));
        assert!(h.contains("SameSite=Lax"));
        assert!(h.contains("Path=/"));
        assert!(h.contains("Max-Age=3600"));
    }
}
