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
//! whose owner re-authenticated recently. Sudo is *time-bounded*: a session
//! counts as sudo only while `auth_level == 1` **and** the re-authentication
//! is within [`SUDO_WINDOW_SECS`] of now (see
//! `SessionAuth::is_sudo`). The most destructive operations
//! (password change, registry/org deletion) require a sudo session.
//!
//! Sessions also enforce two independent lifetime bounds, both checked in
//! `Database::validate_session`:
//!
//! - an **idle timeout** of [`IDLE_TIMEOUT_SECS`]: a session dies once
//!   `now - last_seen_at` exceeds it. Each successful validation bumps
//!   `last_seen_at`, so the idle window slides with activity.
//! - an **absolute lifetime** of [`ABSOLUTE_LIFETIME_SECS`]: a session dies
//!   once `now - created_at` exceeds it, regardless of activity. The
//!   session row's `expires_at` is set to this absolute cap at creation.
//!
//! The session lifecycle (create, validate-and-bump, revoke, revoke-all,
//! elevate) lives on `Database`; this module owns only the
//! secret format, the cookie name, and the lifetime/sudo constants.

use rand::Rng;

/// The session cookie name, with the `__Host-` prefix that pins it to the
/// exact origin (`Secure`, `Path=/`, no `Domain`).
pub const COOKIE_NAME: &str = "__Host-aos_session";

/// The idle timeout for a session, in seconds (7 days).
///
/// A session is rejected once `now - last_seen_at` exceeds this; each
/// successful validation bumps `last_seen_at`, sliding the window forward.
pub const IDLE_TIMEOUT_SECS: i64 = 7 * 24 * 60 * 60;

/// The absolute session lifetime, in seconds (30 days).
///
/// A session is rejected once `now - created_at` exceeds this, regardless of
/// activity. The session row's `expires_at` is stamped to this cap at
/// creation.
pub const ABSOLUTE_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

/// The re-authentication (sudo) window, in seconds (15 minutes).
///
/// A sudo-capable session (`auth_level == 1`) only *counts* as sudo while its
/// last re-authentication is within this window; past it, destructive
/// operations require the user to re-authenticate.
pub const SUDO_WINDOW_SECS: i64 = 15 * 60;

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
/// `Database::create_session` as `secret`.
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
