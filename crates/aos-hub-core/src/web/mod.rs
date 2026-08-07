//! The shared no-JS browse UI: one renderer and one set of handlers.
//!
//! RFC-0004 Phase 5 unifies the human browse surface (the no-JS HTML pages and
//! the JSON read API) on a single code path so the native hub and the
//! Cloudflare Worker render it identically:
//!
//! - [`render`] — the transport- and task-local-free HTML builders. The
//!   masthead brand and the signed-in email ride in an explicit [`PageChrome`]
//!   rather than a global/task-local, and every page renders from the
//!   `aos.hub.v1` read shapes, so the module is wasm-clean.
//! - [`browse`] — the handler functions that call the
//!   [`RpcService`](crate::service::RpcService) read methods and render via
//!   [`render`], returning a [`Rendered`](browse::Rendered) the transport layer
//!   ([`crate::connect`]) turns into an HTTP response. Browse reads
//!   anonymously, so only `public` registries resolve.
//! - [`browse_pages`] — the *rich*, session-aware browse renderer lifted from
//!   the native hub (console-dedup stage G): the searchable/sortable package
//!   index, the data-rich package detail with closure resolution, the channel
//!   partition grid and bucket calculator, and the per-registry health page.
//!   It renders from the [`db`](crate::db) record types (richer than the proto
//!   read shapes) and threads the signed-in identity via an explicit
//!   [`SessionIndicator`](console_render::SessionIndicator), superseding the
//!   anonymous proto-shaped builders in [`render`].
//!
//! The producer console's foundation is shared the same way (RFC-0004 Phase 5,
//! console-dedup stage A):
//!
//! - [`session`] — runtime-neutral session extraction: turn a request's
//!   `Cookie` header plus a [`Database`](crate::db::Database) into a resolved,
//!   validated [`ResolvedSession`](session::ResolvedSession).
//! - [`csrf`] — the per-session synchronizer-token CSRF defenses
//!   ([`mint_csrf_token`](csrf::mint_csrf_token),
//!   [`connect_or_csrf_ok`](csrf::connect_or_csrf_ok)).
//! - [`console_render`] — the console page chrome
//!   ([`page_with_session`](console_render::page_with_session),
//!   [`StateLine`](console_render::StateLine),
//!   [`SessionIndicator`](console_render::SessionIndicator),
//!   [`Pager`](console_render::Pager)) and every console page builder, made
//!   transport- and task-local-free (session email, brand, and CSRF token are
//!   parameters).
//!
//! The shared Connect-JSON router ([`crate::connect`]) mounts the browse routes
//! under the reserved `/` and `/{slug}/-/…` paths, more specific than the
//! machine-surface facade wildcard, so the two never collide.

pub mod assets;
pub mod browse;
pub mod browse_pages;
pub mod config_form;
pub mod console;
pub mod console_render;
pub mod csrf;
pub mod help;
pub mod render;
pub mod session;
pub mod toml_highlight;

pub use render::PageChrome;
