//! Runtime-neutral session extraction for the cookie-authenticated console.
//!
//! Humans reach the producer console with a `__Host-aos_session` cookie (see
//! [`crate::auth::session`]). This module turns that cookie into a resolved,
//! already-validated identity a handler can trust, independent of any specific
//! HTTP server or async runtime: it takes a raw `Cookie` header value (or an
//! [`axum::http::HeaderMap`]) plus a [`Database`], and returns the authenticated
//! [`Principal`], the session row, the session secret (for CSRF minting), and
//! the user's email.
//!
//! It is the single place the cookie format and the validate-then-resolve-email
//! sequence live, so the native hub and the Cloudflare Worker share one
//! implementation. The functions touch only the [`Database`] (whose backend is
//! itself runtime-selected) and `axum` *types*, so the module compiles to
//! `wasm32-unknown-unknown` (RFC-0004 Phase 5).

use axum::http::{header, HeaderMap};

use crate::auth::session::COOKIE_NAME;
use crate::db::{Database, SessionAuth};
use crate::domain::Principal;

/// A resolved, validated console session.
///
/// Produced by [`resolve_session`] (or [`resolve_session_from_headers`]) when a
/// request's session cookie checks out: it bundles everything a console handler
/// needs without re-reading the database. The session secret is retained so the
/// handler can mint the per-session CSRF token
/// ([`mint_csrf_token`](crate::web::csrf::mint_csrf_token)).
#[derive(Debug, Clone)]
pub struct ResolvedSession {
    /// The opaque session cookie secret, used to mint the CSRF synchronizer
    /// token bound to this session.
    pub secret: String,
    /// The validated session row (user id, sudo `auth_level`, expiry).
    pub auth: SessionAuth,
    /// The signed-in user's email.
    pub email: String,
}

impl ResolvedSession {
    /// This session user's [`Principal`].
    #[must_use]
    pub fn principal(&self) -> Principal {
        Principal::user(self.auth.user_id)
    }
}

/// Extracts the `__Host-aos_session` value from a raw `Cookie` header value.
///
/// `cookie_header` is the full value of the request's `Cookie` header (a
/// `;`-separated list of `name=value` pairs); returns the session secret when
/// the named cookie is present, or `None` otherwise.
#[must_use]
pub fn session_secret_from_cookie_header(cookie_header: &str) -> Option<String> {
    let prefix = format!("{COOKIE_NAME}=");
    cookie_header
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(&prefix).map(str::to_string))
}

/// Extracts the `__Host-aos_session` value from a request's headers.
///
/// Reads the `Cookie` header and delegates to
/// [`session_secret_from_cookie_header`]; returns `None` when the header is
/// absent, not valid UTF-8, or carries no session cookie.
#[must_use]
pub fn session_secret_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    session_secret_from_cookie_header(cookies)
}

/// Validates a session cookie secret and resolves the signed-in identity.
///
/// Validates `secret` against `db` (hash match and unexpired), bumping
/// `last_seen_at`, then loads the user's email. Returns `Ok(None)` when the
/// secret is absent from the store, expired, or its user has been deleted — the
/// caller decides how to handle an anonymous/invalid session (the console
/// bounces to `/login`).
///
/// # Errors
///
/// Returns an error on a database failure while validating the session or
/// loading the user's email.
pub async fn resolve_session(
    db: &Database,
    secret: &str,
) -> anyhow::Result<Option<ResolvedSession>> {
    let Some(auth) = db.validate_session(secret).await? else {
        return Ok(None);
    };
    let Some(email) = db.user_email(auth.user_id).await? else {
        return Ok(None);
    };
    Ok(Some(ResolvedSession {
        secret: secret.to_string(),
        auth,
        email,
    }))
}

/// Resolves the session for a request from its headers.
///
/// Pulls the session cookie via [`session_secret_from_headers`] and resolves it
/// with [`resolve_session`]. Returns `Ok(None)` when no session cookie is
/// present or the cookie does not resolve to a live, non-deleted user.
///
/// # Errors
///
/// Returns an error on a database failure while validating the session or
/// loading the user's email.
pub async fn resolve_session_from_headers(
    db: &Database,
    headers: &HeaderMap,
) -> anyhow::Result<Option<ResolvedSession>> {
    let Some(secret) = session_secret_from_headers(headers) else {
        return Ok(None);
    };
    resolve_session(db, &secret).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_named_cookie_among_others() {
        let header = format!("foo=bar; {COOKIE_NAME}=sekret; baz=qux");
        assert_eq!(
            session_secret_from_cookie_header(&header).as_deref(),
            Some("sekret")
        );
    }

    #[test]
    fn missing_cookie_is_none() {
        assert!(session_secret_from_cookie_header("foo=bar; baz=qux").is_none());
        assert!(session_secret_from_headers(&HeaderMap::new()).is_none());
    }

    #[tokio::test]
    async fn resolves_a_live_session() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("dev@acme.com", None).await.unwrap();
        let secret = db.create_session(user, 3600, 1).await.unwrap();
        let resolved = resolve_session(&db, &secret).await.unwrap().unwrap();
        assert_eq!(resolved.email, "dev@acme.com");
        assert_eq!(resolved.principal(), Principal::user(user));
        // An unknown secret resolves to None, not an error.
        assert!(resolve_session(&db, "nope").await.unwrap().is_none());
    }
}
