//! Server-rendered browse pages: the no-JS tier of RFC-0004's design.
//!
//! - [`render`] — escaping, the shared layout (masthead, crumbs, footer
//!   state line), and table/size primitives.
//! - [`pages`] — the page set: instance home, registry home, package
//!   index/detail, channels (with the 16×16 partition grid), releases.
//!
//! The stylesheet (`style.css`, served at `/_assets/style.css`) carries
//! the "release-engineering paper" language: one monospace face, ink on
//! paper with a phosphor dark scheme, tables and rules as layout, color
//! strictly semantic. Pages never reference a third-party origin.

pub mod pages;
pub mod render;

/// The single first-party stylesheet, embedded at build time.
pub const STYLESHEET: &str = include_str!("style.css");
