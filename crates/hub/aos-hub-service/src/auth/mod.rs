//! Runtime-agnostic authentication primitives shared by the hub and Worker.
//!
//! These are the deployment-independent halves of the hub's auth stack — the
//! credential operations that depend on neither a specific HTTP server, a
//! database driver, nor an async runtime. They are gathered here (RFC-0004
//! Phase 5) so the native `aos-hub` binary and the Cloudflare Worker
//! run the *same* credential code rather than two divergent implementations.
//!
//! - [`token`] — provisioning-token secret generation and SHA-256 hashing.
//! - [`session`] — opaque human session secrets and the cookie header.
//! - [`magic`] — single-use email magic-link secrets and the [`magic::Mailer`]
//!   delivery trait.
//! - [`device`] — RFC 8628 device-code and user-code minting.
//! - [`oidc`] — per-org OIDC SSO: the authorization-code + PKCE flow and
//!   JWKS-backed RS256 id_token verification, over the
//!   [`HttpClient`](crate::web::console::ports::HttpClient) port.
//! - [`password`] — Argon2id password hashing and constant-time verification.
//! - [`seal`] — the [`SecretSealer`](seal::SecretSealer) seam (AES-256-GCM
//!   production sealer + the dev/test XOR placeholder) for at-rest secrets.
//! - [`webauthn`] — the in-house WebAuthn relying-party verifier
//!   (`attestation: none`): COSE key decode and ES256/Ed25519/RS256 assertion
//!   verification, over [`Database`](crate::db::Database) credential rows.
//! - [`permission_from_str`] — the inverse of `Permission::as_str`.
//!
//! The HTTP-bound and database-bound halves (axum extractors, JWT minting, the
//! sealed-secret envelope, the WebAuthn verifier, and the
//! session/token row queries) currently stay in the deployment crates; later
//! phases move the runtime-agnostic ones here too. The on-disk system of record
//! for every credential is the hub's `db` layer; only secret *hashes* are
//! stored, so a database leak never yields a usable credential.

// jwt: HS256 access-token mint/verify (hmac/sha2-based; no jsonwebtoken/ring).
pub use aos_hub_model::auth::device;
pub use aos_hub_model::auth::jwt;
pub mod magic;
pub mod oidc;
pub use aos_hub_model::auth::password;
pub use aos_hub_model::auth::seal;
pub use aos_hub_model::auth::session;
pub use aos_hub_model::auth::token;
pub mod webauthn;

pub use aos_hub_model::auth::permission_from_str;
