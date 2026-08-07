//! The shared producer console (RFC-0004 Phase 5, console-dedup stage B/C).
//!
//! The console's request handlers are transport- and runtime-neutral `axum`
//! handlers that run on the shared [`Database`](crate::db::Database) and reach
//! every platform-specific capability through a *port* (see [`ports`]), so the
//! native hub and the Cloudflare Worker mount the same console router. This
//! module owns the [`ports::ConsoleDeps`] bundle and the wasm-clean handlers
//! ([`handlers`]) mounted by [`console_router`]. Registry configuration and
//! change-request reads and writes use storage-neutral ports as well, so every
//! management route has the same implementation on the native hub and Worker.
//!
//! The pre-auth `/login`, `/login/password` (stage D), `/auth/passkey/begin`,
//! and `/activate` (stage E) paths are shared: they meter on the
//! [`CLIENT_IP_HEADER`] each shell stamps on ingress rather than on a native
//! peer socket. The OIDC flow (`/auth/sso`, `/auth/oidc/start`,
//! `/auth/oidc/callback`, stage F) is shared too: its token exchange and JWKS
//! fetch go through the [`HttpClient`](ports::HttpClient) port.

pub mod handlers;
pub mod ia;
pub mod manifest;
pub mod nested;
pub mod ports;
pub mod router;

pub use handlers::CLIENT_IP_HEADER;
pub use manifest::{route_manifest, ConsoleRouteMatched, RouteMethods, RouteSpec};
pub use nested::dispatch_nested;
pub use ports::{ConsoleDeps, HttpClient, TopologyConsole};
pub use router::console_router;
