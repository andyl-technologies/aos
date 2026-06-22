//! First-party static assets served under `/_assets/` — the stylesheet, the
//! progressive-enhancement JS bundle, and the self-hosted fonts.
//!
//! These are embedded at build time and served by the *shared* browse router
//! ([`crate::connect`]) so **both** shells expose them: the no-JS browse pages
//! and the producer console (rendered by [`crate::web`]) link
//! `/_assets/style.css` + `/_assets/app.js`, and `style.css` `@font-face`s the
//! woff2 fonts. They live in core (not the native crate) precisely so the
//! Cloudflare Worker serves them too — otherwise its pages 404 their CSS/JS.
//!
//! Every asset is first-party and same-origin: it loads under the strict
//! `default-src 'self'` CSP with no third-party origin, and there are no font
//! CDNs. URLs are stable (not content-hashed), so the cache lifetime is a
//! conservative hour (CSS/JS) / day (fonts) rather than `immutable`, letting a
//! hub upgrade reship them.

use axum::http::header;
use axum::response::{IntoResponse, Response};

/// The single first-party stylesheet (`/_assets/style.css`).
pub const STYLESHEET: &str = include_str!("static_assets/style.css");

/// The progressive-enhancement JS bundle (`/_assets/app.js`): live search and
/// the TOML config editor, each an enhancement over a form/textarea that works
/// without JS.
pub const APP_JS: &str = include_str!("static_assets/app.js");

/// A short content hash of the CSS + JS bundle, for cache-busting asset URLs.
///
/// `/_assets/style.css` and `/_assets/app.js` are served at stable paths by the
/// deployment's static-asset layer with a multi-hour/day cache, so a browser
/// would keep the old CSS/JS for up to a day after a hub upgrade. Linking them
/// as `…/style.css?v=<version>` makes the URL change whenever the asset's bytes
/// change, so a deploy's new styles/scripts reach browsers immediately (the
/// query is ignored for asset matching but is part of the browser cache key).
///
/// Computed once from the embedded bytes; stable for a given build.
#[must_use]
pub fn asset_version() -> &'static str {
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let mut hasher = Sha256::new();
        hasher.update(STYLESHEET.as_bytes());
        hasher.update(APP_JS.as_bytes());
        hex::encode(hasher.finalize())[..8].to_string()
    })
}

/// JetBrains Mono Regular (OFL), self-hosted — no font CDNs, ever.
pub const FONT_REGULAR: &[u8] = include_bytes!("static_assets/JetBrainsMono-Regular.woff2");

/// JetBrains Mono Bold (OFL), self-hosted.
pub const FONT_BOLD: &[u8] = include_bytes!("static_assets/JetBrainsMono-Bold.woff2");

/// The SIL Open Font License text for the embedded fonts.
pub const FONT_LICENSE: &str = include_str!("static_assets/OFL.txt");

/// Serve the stylesheet (`text/css`, 1-hour cache).
pub async fn stylesheet() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        STYLESHEET,
    )
        .into_response()
}

/// Serve the JS bundle (`text/javascript`, 1-hour cache).
pub async fn app_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        APP_JS,
    )
        .into_response()
}

/// Serve the regular-weight font.
pub async fn font_regular() -> Response {
    font_response(FONT_REGULAR)
}

/// Serve the bold-weight font.
pub async fn font_bold() -> Response {
    font_response(FONT_BOLD)
}

/// Serve the font license text.
pub async fn font_license() -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        FONT_LICENSE,
    )
        .into_response()
}

/// Build a `woff2` font response with a one-day cache (stable, non-hashed URLs,
/// so not `immutable` — a hub upgrade that reships fonts must take effect).
fn font_response(bytes: &'static [u8]) -> Response {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
        .into_response()
}
