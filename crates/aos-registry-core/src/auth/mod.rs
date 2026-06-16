//! Runtime-agnostic authentication primitives shared by the hub and Worker.
//!
//! These are the deployment-independent halves of the hub's auth stack — the
//! cryptographic credential operations that do not depend on a specific HTTP
//! server, database driver, or async runtime. They are gathered here (RFC-0004
//! Phase 5) so the native `aos-registry-hub` binary and the Cloudflare Worker
//! run the *same* credential code rather than two divergent implementations.
//!
//! - [`password`] — Argon2id password hashing and constant-time verification.
//!
//! Later phases add the random secret/token generators, the OIDC/PKCE flow
//! types, the sealed-secret envelope, and the WebAuthn verifier here too. The
//! HTTP-bound and database-bound halves (axum extractors, session/token row
//! queries) stay in the deployment crates.

pub mod password;
