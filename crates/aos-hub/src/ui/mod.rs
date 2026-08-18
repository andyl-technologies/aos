//! Server-rendered browse pages: the no-JS tier of RFC-0004's design.
//!
//! - [`render`] — escaping, the shared layout (masthead, crumbs, footer
//!   state line), relative ages, key fingerprints, and table/size
//!   primitives.
//! - [`pages`] — the page set: instance home, registry home, package
//!   index/detail (with search and pagination), channels (with the
//!   16×16 partition grid and bucket calculator), releases, and the
//!   per-registry health page.
//!
//! Authentication and account ceremonies are served by the shared
//! `aos_hub_core::web::console` router. The authenticated management console is
//! a Leptos client over the canonical Connect API, packaged identically for the
//! native Hub and Worker.
//!
//! The stylesheet (`style.css`, served at `/_assets/style.css`) carries
//! the "release-engineering paper" language: one monospace face, ink on
//! paper with a phosphor dark scheme, tables and rules as layout, color
//! strictly semantic. Pages never reference a third-party origin.

pub mod pages;
pub mod render;

// The first-party static assets (stylesheet, app.js, fonts) moved to the shared
// `aos_hub_core::web::assets` module and are served by the shared browse router,
// so both the native hub and the Cloudflare Worker expose `/_assets/*`.
