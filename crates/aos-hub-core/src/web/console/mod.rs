//! Shared authentication routes and browser-console shell.
//!
//! Native Hub and Cloudflare Worker deployments mount the same login/account
//! ceremonies and the same authenticated application shell. Management data
//! and mutations do not have a second Web-only server implementation: the
//! browser application invokes the generated Connect API used by the CLI.
//!
//! The pre-auth `/login`, `/login/password` (stage D), `/auth/passkey/begin`,
//! and `/activate` (stage E) paths are shared: they meter on the
//! [`CLIENT_IP_HEADER`] each shell stamps on ingress rather than on a native
//! peer socket. The OIDC flow (`/auth/sso`, `/auth/oidc/start`,
//! `/auth/oidc/callback`, stage F) is shared too: its token exchange and JWKS
//! fetch go through the [`HttpClient`](ports::HttpClient) port.

pub mod handlers;
pub mod manifest;
pub mod nested;
pub mod ports;
pub mod router;

pub use handlers::CLIENT_IP_HEADER;
pub use manifest::{route_manifest, ConsoleRouteMatched, RouteMethods, RouteSpec};
pub use nested::dispatch_nested;
pub use ports::{ConsoleDeps, HttpClient};
pub use router::console_router;
