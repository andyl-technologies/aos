//! Per-org OIDC single sign-on — re-export shim over the shared core module.
//!
//! The OIDC authorization-code + PKCE flow moved to
//! [`aos_hub_core::auth::oidc`] (RFC-0004 Phase 5, console-dedup stage F)
//! so the native hub and the Cloudflare Worker run the *same* SSO code: a
//! toolchain change lets `jsonwebtoken` (via `ring`) compile to
//! `wasm32-unknown-unknown`, so the RS256 id_token verifier did not need
//! reimplementing — the module moved unchanged in its crypto. Its two network
//! calls now go through the
//! [`HttpClient`](aos_hub_core::web::console::ports::HttpClient) port
//! instead of a concrete `reqwest::Client`.
//!
//! Everything is re-exported here so existing `crate::auth::oidc::…` paths
//! across the hub (and the `tests/oidc.rs` integration suite) are unchanged.
//! The sealer re-export (`SecretSealer`, `XorSealer`, `dev_sealer`) continues to
//! come from [`aos_hub_core::auth::seal`].

pub use aos_hub_core::auth::oidc::*;
pub use aos_hub_core::auth::seal::{dev_sealer, SecretSealer, XorSealer};
