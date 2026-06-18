//! Server-rendered browse pages: the no-JS tier of RFC-0004's design.
//!
//! - [`render`] — escaping, the shared layout (masthead, crumbs, footer
//!   state line), relative ages, key fingerprints, and table/size
//!   primitives.
//! - [`pages`] — the page set: instance home, registry home, package
//!   index/detail (with search and pagination), channels (with the
//!   16×16 partition grid and bucket calculator), releases, and the
//!   per-registry health page.
//! - [`console`] — the authenticated producer console pages: login,
//!   account, device approval, org dashboards, token management, the
//!   channel rollout console, key roster, and the publish-pipeline view.
//!
//! The stylesheet (`style.css`, served at `/_assets/style.css`) carries
//! the "release-engineering paper" language: one monospace face, ink on
//! paper with a phosphor dark scheme, tables and rules as layout, color
//! strictly semantic. Pages never reference a third-party origin.

pub mod console;
pub mod pages;
pub mod render;

/// The single first-party stylesheet, embedded at build time.
pub const STYLESHEET: &str = include_str!("style.css");

/// First-party progressive-enhancement bundle (live search + the TOML
/// config editor), served at `/_assets/app.js`. Same-origin, so it loads
/// under the strict `default-src 'self'` CSP with no nonce; every behavior
/// is an enhancement over a form/textarea that already works without JS.
pub const APP_JS: &str = include_str!("app.js");

/// JetBrains Mono Regular (OFL), self-hosted per the first-party asset
/// policy — no font CDNs, ever. License: `assets/OFL.txt`.
pub const FONT_REGULAR: &[u8] = include_bytes!("assets/JetBrainsMono-Regular.woff2");
/// JetBrains Mono Bold (OFL), self-hosted.
pub const FONT_BOLD: &[u8] = include_bytes!("assets/JetBrainsMono-Bold.woff2");
/// The SIL Open Font License text for the embedded fonts.
pub const FONT_LICENSE: &str = include_str!("assets/OFL.txt");
