//! The shared producer console (RFC-0004 Phase 5, console-dedup stage B/C).
//!
//! The console's request handlers are transport- and runtime-neutral `axum`
//! handlers that run on the shared [`Database`](crate::db::Database) and reach
//! every platform-specific capability through a *port* (see [`ports`]), so the
//! native hub and the Cloudflare Worker mount the same console router. This
//! module owns the [`ports::ConsoleDeps`] bundle and the ported wasm-clean
//! handlers ([`handlers`]) mounted by [`console_router`]. The routes that stay
//! native (the OIDC flow and the git-backed config/change-request flows) are
//! mounted by the hub alongside this router.
//!
//! The pre-auth `/login`, `/login/password` (stage D), `/auth/passkey/begin`,
//! and `/activate` (stage E) paths are shared: they meter on the
//! [`CLIENT_IP_HEADER`] each shell stamps on ingress rather than on a native
//! peer socket.

pub mod handlers;
pub mod ports;
pub mod router;

pub use handlers::CLIENT_IP_HEADER;
pub use ports::{AdvanceOutcome, ChannelAdvancer, ConsoleDeps, HttpClient};
pub use router::console_router;
