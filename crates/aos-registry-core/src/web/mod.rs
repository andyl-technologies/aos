//! The shared no-JS browse UI: one renderer and one set of handlers.
//!
//! RFC-0004 Phase 5 unifies the human browse surface (the no-JS HTML pages and
//! the JSON read API) on a single code path so the native hub and the
//! Cloudflare Worker render it identically:
//!
//! - [`render`] — the transport- and task-local-free HTML builders. The
//!   masthead brand and the signed-in email ride in an explicit [`PageChrome`]
//!   rather than a global/task-local, and every page renders from the
//!   `aos.registry.v1` read shapes, so the module is wasm-clean.
//! - [`browse`] — the handler functions that call the
//!   [`RpcService`](crate::service::RpcService) read methods and render via
//!   [`render`], returning a [`Rendered`](browse::Rendered) the transport layer
//!   ([`crate::connect`]) turns into an HTTP response. Browse reads
//!   anonymously, so only `public` registries resolve.
//!
//! The shared Connect-JSON router ([`crate::connect`]) mounts the browse routes
//! under the reserved `/` and `/{slug}/-/…` paths, more specific than the
//! machine-surface facade wildcard, so the two never collide.

pub mod browse;
pub mod render;

pub use render::PageChrome;
