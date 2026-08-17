//! Authentication: the credentials principals present and the machinery
//! that verifies them.
//!
//! This module owns RFC-0004's "Authentication: sessions, tokens, SSO"
//! plane — *who you are*, as distinct from the pure *what you may do*
//! authorization kernel in [`crate::domain::iam`], which it reuses for
//! every access decision. Two principal planes that never cross:
//!
//! - **Machines** use the shared OAuth device/refresh flow or present an
//!   `aos_`-prefixed [provisioning token](token) through the explicit bootstrap
//!   grant at `POST /oauth2/token`; both produce short-TTL [HS256 JWTs](jwt).
//!   The hub generalizes the `aos-server` token from a set of *views* to a
//!   `{scope-path, permissions[]}` grant, and *honors* the rotation grace
//!   window that `aos-server` recorded but ignored.
//! - **Humans** carry opaque [cookie sessions](session)
//!   (`__Host-aos_session`) with a sudo `auth_level`, obtained through the
//!   [device-authorization flow](device) (RFC 8628) for the CLI, [email magic
//!   links](magic) for the browser, [email + password](password) (Argon2id,
//!   an operator-requested reversal of the original "no passwords" stance),
//!   [passkeys / WebAuthn](webauthn) (an in-house relying-party verifier,
//!   `attestation: none` only), or — per org — [OIDC single sign-on](oidc)
//!   (authorization-code + PKCE, domain-captured email-first routing).
//!
//! # Module map
//!
//! - [`token`] — provisioning-token secret generation and hashing.
//! - [`jwt`] — HS256 JWT minting and verification ([`jwt::Claims`]).
//! - [`session`] — opaque human session secrets.
//! - [`device`] — RFC 8628 device-code and user-code minting.
//! - [`magic`] — single-use email magic-link secrets and the [`magic::Mailer`]
//!   delivery trait.
//! - [`password`] — Argon2id password hashing and constant-time verification
//!   for the email + password login path.
//! - [`webauthn`] — the in-house WebAuthn relying-party verifier
//!   (`attestation: none` only): `clientDataJSON`/`authenticatorData` checks,
//!   COSE key decode, ES256/Ed25519/RS256 signature verification, and the
//!   registration/assertion ceremonies.
//! - [`oidc`] — per-org OIDC SSO: the authorization-code + PKCE flow, JWKS-backed
//!   RS256 id_token verification, and the [`oidc::SecretSealer`] seam. The flow
//!   itself moved to [`aos_hub_core::auth::oidc`] (RFC-0004 Phase 5,
//!   console-dedup stage F); this `oidc` module is a re-export shim so existing
//!   `crate::auth::oidc::…` paths are unchanged.
//! - [`extract`] — the axum extractors and middleware that gate requests:
//!   [`extract::BearerAuth`], [`extract::SessionAuth`],
//!   [`extract::MaybeSession`]. The runtime-neutral OAuth HTTP handlers live in
//!   [`aos_hub_core::web::console`].
//!
//! The on-disk system of record for every credential lives in
//! [`crate::db`]: the `tokens`, `sessions`, `device_codes`, `refresh_tokens`,
//! and `magic_links` tables. Only secret *hashes* are stored, so a database leak
//! never yields a usable credential.

pub mod extract;
pub mod oidc;
pub mod seal;

// The runtime-agnostic auth primitives moved to aos-hub-core (RFC-0004
// Phase 5) so the Worker shares them; re-exported here so every
// `crate::auth::{token,session,magic,device,password,permission_from_str,
// webauthn,jwt}::…` path is unchanged. (jwt's HS256 is now hmac/sha2-based —
// no jsonwebtoken/ring — so it builds for wasm32.)
pub use aos_hub_core::auth::{
    device, jwt, magic, password, permission_from_str, session, token, webauthn,
};
