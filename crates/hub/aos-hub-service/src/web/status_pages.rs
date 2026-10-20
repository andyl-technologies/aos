//! Browser status pages for disabled features and unavailable page data.
//!
//! A browser can render an explanation even when its requested content cannot
//! be loaded. These responses never pretend that an unavailable catalog is
//! empty, and are not cached. Machine APIs retain their own error statuses.

use axum::http::header;
use axum::response::{IntoResponse, Response};

use super::console_render::{page_with_session, SessionIndicator, StateLine};
use super::render::escape;

/// Renders an uncached, successful HTML response explaining unavailable content.
///
/// The message must describe a safe user-facing state, never a raw database,
/// provider, or credential error. The page needs no database or storage access,
/// so it also works when loading the normal page has failed.
#[must_use]
pub fn unavailable(message: &str) -> Response {
    let body = format!(
        "<h1>This page is unavailable</h1><p>{}</p>\
         <p>You can reload this page or <a href=\"/\">return to the Hub</a>.</p>",
        escape(message),
    );
    let page = page_with_session(
        "Page unavailable",
        &[(String::new(), "Page unavailable".to_string())],
        &body,
        &StateLine::default(),
        &SessionIndicator::default(),
    );

    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "private, no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; frame-ancestors 'none'",
            ),
        ],
        page,
    )
        .into_response()
}
