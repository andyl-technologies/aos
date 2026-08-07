//! First-party static assets served under `/_assets/` — the stylesheet, the
//! progressive-enhancement JS bundle, and the self-hosted fonts.
//!
//! These are embedded at build time and served by the shared router
//! ([`crate::connect`]) so both runtimes expose the public browse assets and
//! the hermetic browser-console JavaScript, WebAssembly, and CSS bundle.
//!
//! Every asset is first-party and same-origin: it loads under the strict
//! `default-src 'self'` CSP with no third-party origin, and there are no font
//! CDNs. Browse-asset URLs are stable and use bounded caching. Browser-console
//! filenames contain the bundle's content identity and use immutable caching.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

/// The single first-party stylesheet (`/_assets/style.css`).
pub const STYLESHEET: &str = include_str!("static_assets/style.css");

/// The progressive-enhancement JS bundle (`/_assets/app.js`): live search and
/// the TOML config editor, each an enhancement over a form/textarea that works
/// without JS.
pub const APP_JS: &str = include_str!("static_assets/app.js");

/// The generated browser-console ES module.
pub const CONSOLE_JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hub-console.js"));

/// The generated browser-console WebAssembly module.
pub const CONSOLE_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hub-console_bg.wasm"));

/// The browser-console stylesheet.
pub const CONSOLE_CSS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hub-console.css"));

/// Returns the short content identity used in every console asset filename.
#[must_use]
pub fn asset_version() -> &'static str {
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let mut hasher = Sha256::new();
        hasher.update(STYLESHEET.as_bytes());
        hasher.update(APP_JS.as_bytes());
        hasher.update(CONSOLE_JS);
        hasher.update(CONSOLE_WASM);
        hasher.update(CONSOLE_CSS);
        hex::encode(hasher.finalize())[..8].to_string()
    })
}

/// Returns the content-addressed console JavaScript filename.
#[must_use]
pub fn console_js_name() -> String {
    format!("hub-console-{}.js", asset_version())
}

/// Returns the content-addressed console WebAssembly filename.
#[must_use]
pub fn console_wasm_name() -> String {
    format!("hub-console-{}_bg.wasm", asset_version())
}

/// Returns the content-addressed console stylesheet filename.
#[must_use]
pub fn console_css_name() -> String {
    format!("hub-console-{}.css", asset_version())
}

/// Returns the content-addressed console bootstrap filename.
#[must_use]
pub fn console_bootstrap_name() -> String {
    format!("hub-console-bootstrap-{}.js", asset_version())
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

/// Serves one exact content-addressed browser-console asset.
///
/// Unknown and stable legacy filenames return `404`; this keeps the immutable
/// cache contract honest across both native and Worker deployments.
pub async fn console_asset(Path(asset): Path<String>) -> Response {
    if asset == console_js_name() {
        return immutable_asset("text/javascript; charset=utf-8", CONSOLE_JS);
    }
    if asset == console_wasm_name() {
        return immutable_asset("application/wasm", CONSOLE_WASM);
    }
    if asset == console_css_name() {
        return immutable_asset("text/css; charset=utf-8", CONSOLE_CSS);
    }
    if asset == console_bootstrap_name() {
        let source = format!(
            "import init from './{}';\n\nawait init(new URL('./{}', import.meta.url));\n",
            console_js_name(),
            console_wasm_name(),
        );
        return (
            [
                (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            source,
        )
            .into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

fn immutable_asset(content_type: &'static str, bytes: &'static [u8]) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
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
