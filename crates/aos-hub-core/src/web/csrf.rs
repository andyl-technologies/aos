//! Cross-site request forgery (CSRF) defenses for the cookie-authenticated
//! producer console.
//!
//! A cookie-authenticated mutation is reachable with the browser's ambient
//! session cookie, so it is forgeable from another origin unless it carries
//! proof the request originated from the hub's own pages. This module is that
//! proof: a per-session **synchronizer token** derived from the session secret.
//! Because the token is the SHA-256 of the session secret (with a fixed domain
//! separator), it is unforgeable without the secret yet safe to embed in a
//! server-rendered form, and it requires no server-side token store.
//!
//! The functions here are pure and runtime-neutral — they take an axum
//! [`HeaderMap`] (a type, not a server) and a session secret, so they compile
//! to `wasm32-unknown-unknown` and are shared by the native hub and the
//! Cloudflare Worker (RFC-0004 Phase 5).
//!
//! - [`mint_csrf_token`] derives the token an SSR form embeds.
//! - [`verify_csrf_token`] checks a submitted token against the session secret.
//! - [`connect_or_csrf_ok`] is the request gate: a Connect-protocol header (a
//!   no-JS form cannot send it; a cross-origin XHR that does triggers a CORS
//!   preflight) *or* a valid `x-aos-csrf` header lets the request proceed.

use axum::http::HeaderMap;

/// Returns `true` if the request may proceed past CSRF defenses.
///
/// For a cookie-authenticated Connect-JSON call, either the
/// `connect-protocol-version` header is present (a no-JS form cannot send it,
/// and a cross-origin XHR that does triggers a preflight blocked by strict
/// CORS), or the SSR form path supplies a valid per-session synchronizer token
/// via the `x-aos-csrf` header. Bearer requests carry no ambient credential and
/// should not be routed through this check.
#[must_use]
pub fn connect_or_csrf_ok(headers: &HeaderMap, session_secret: Option<&str>) -> bool {
    if headers.contains_key("connect-protocol-version") {
        return true;
    }
    match (
        headers.get("x-aos-csrf").and_then(|v| v.to_str().ok()),
        session_secret,
    ) {
        (Some(token), Some(secret)) => verify_csrf_token(secret, token),
        _ => false,
    }
}

/// Mints a per-session CSRF synchronizer token bound to `session_secret`.
///
/// The token is the SHA-256 of the session secret prefixed with a fixed
/// domain separator, so it is unforgeable without the session secret yet
/// safe to embed in an SSR form. Verify with [`verify_csrf_token`].
#[must_use]
pub fn mint_csrf_token(session_secret: &str) -> String {
    crate::auth::token::sha256_hex(&format!("aos-csrf:{session_secret}"))
}

/// Verifies a CSRF synchronizer token against a session secret.
#[must_use]
pub fn verify_csrf_token(session_secret: &str, token: &str) -> bool {
    mint_csrf_token(session_secret) == token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_roundtrips() {
        let token = mint_csrf_token("session-secret");
        assert!(verify_csrf_token("session-secret", &token));
        assert!(!verify_csrf_token("other-secret", &token));
        assert!(!verify_csrf_token("session-secret", "garbage"));
    }

    #[test]
    fn connect_or_csrf_ok_paths() {
        // Connect-protocol header alone passes.
        let mut headers = HeaderMap::new();
        headers.insert("connect-protocol-version", "1".parse().unwrap());
        assert!(connect_or_csrf_ok(&headers, None));

        // Valid synchronizer token passes.
        let secret = "sess";
        let csrf = mint_csrf_token(secret);
        let mut headers = HeaderMap::new();
        headers.insert("x-aos-csrf", csrf.parse().unwrap());
        assert!(connect_or_csrf_ok(&headers, Some(secret)));

        // Neither: blocked.
        assert!(!connect_or_csrf_ok(&HeaderMap::new(), Some(secret)));
        // Wrong token: blocked.
        let mut headers = HeaderMap::new();
        headers.insert("x-aos-csrf", "nope".parse().unwrap());
        assert!(!connect_or_csrf_ok(&headers, Some(secret)));
    }
}
