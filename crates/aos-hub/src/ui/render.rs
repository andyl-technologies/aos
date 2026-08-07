//! HTML rendering primitives for the no-JS tier.
//!
//! Plain string-building with strict escaping — no client-side framework
//! is required for any page this module renders, which is the design
//! floor RFC-0004 commits to.
//!
//! The pure primitives (`escape`, `table`, `human_size`, `key_fingerprint`)
//! and the retained identity-page foundation — the page chrome (`page_with_session`,
//! `StateLine`, `SessionIndicator`, `Pager`, `csrf_field`, `brand`, `ago`, the
//! small table/`meter`/`datalist`/`urlencode` helpers) — are single-sourced in
//! the shared, wasm-clean [`aos_hub_core::web`] (RFC-0004 Phase 5,
//! console-dedup stage A) so the hub and Worker render byte-identically. They
//! are re-exported here so every
//! `crate::ui::render::…` call site is unchanged.
//!
//! What stays native to the hub is the *task-local* session middleware seam:
//! [`with_session_email`] scopes the signed-in identity per request and [`page`]
//! reads it via [`current_session_indicator`], so the anonymous browse pages
//! reflect the session in their masthead without threading the identity through
//! every renderer. The shared chrome takes the indicator explicitly instead
//! (its `wasm32` builds have no task-locals).

// The pure rendering primitives and the console chrome live in the shared,
// wasm-clean core crate; re-export them so the hub's richer page builders, the
// retained identity pages and shared browse surface render byte-identically.
pub use aos_hub_core::web::console_render::{
    ago, brand, csrf_field, datalist, live_table, meter, page_with_session, set_app_version,
    set_brand, table_raw_headers, urlencode, Pager, SessionIndicator, StateLine,
};
pub use aos_hub_core::web::render::{escape, human_size, key_fingerprint, table};

tokio::task_local! {
    /// The signed-in user's email for the current request, set per-request
    /// by the session-resolving middleware. `None` for anonymous requests.
    ///
    /// Lets every page reflect the session in its masthead without threading
    /// the identity through every handler and renderer signature.
    static SESSION_EMAIL: Option<String>;
}

/// Run `fut` with the current request's session email in scope.
///
/// The session-resolving middleware wraps each request in this so [`page`]
/// can read the identity via [`current_session_indicator`].
pub async fn with_session_email<F: std::future::Future>(
    email: Option<String>,
    fut: F,
) -> F::Output {
    SESSION_EMAIL.scope(email, fut).await
}

/// The session indicator for the current request, from the task-local set by
/// the middleware; anonymous when unset (e.g. in unit tests calling [`page`]).
#[must_use]
pub fn current_session_indicator() -> SessionIndicator {
    SESSION_EMAIL
        .try_with(|email| email.clone())
        .ok()
        .flatten()
        .map(SessionIndicator::signed_in)
        .unwrap_or_default()
}

/// Render a complete page in the shared layout.
///
/// `crumbs` is the masthead trail as `(href, label)` pairs; the final
/// crumb should be the current page (empty href renders unlinked). The
/// masthead reflects the current request's session (from the task-local set
/// by the session middleware), so browse pages show the signed-in identity
/// and navigation automatically; use [`page_with_session`] to pass an
/// explicit indicator.
#[must_use]
pub fn page(title: &str, crumbs: &[(String, String)], body: &str, state: &StateLine) -> String {
    page_with_session(title, crumbs, body, state, &current_session_indicator())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_covers_html_metacharacters() {
        assert_eq!(
            escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn page_contains_title_crumbs_and_statline() {
        let html = page(
            "demo",
            &[
                ("/".into(), "registries".into()),
                (String::new(), "demo".into()),
            ],
            "<p>body</p>",
            &StateLine {
                surface_commit: Some("ab".repeat(32)),
                indexed_at: Some(1),
                state: Some("fresh".into()),
                started: Some(std::time::Instant::now()),
            },
        );
        // No brand configured in tests -> the neutral default title.
        assert!(html.contains("demo — Registry Hub"));
        assert!(html.contains("surface abababababab"));
        assert!(html.contains("<p>body</p>"));
        assert!(html.contains("registries</a>"));
        assert!(html.contains("rendered"), "footer carries render time");
    }

    #[test]
    fn ago_picks_units() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(ago(now - 38), "38s ago");
        assert_eq!(ago(now - 4 * 60), "4m ago");
        assert_eq!(ago(now - 3 * 3600), "3h ago");
        assert_eq!(ago(now - 2 * 86400), "2d ago");
        assert_eq!(ago(now + 500), "0s ago", "future timestamps clamp");
    }

    #[test]
    fn key_fingerprint_is_sha256_base64_no_pad() {
        // sha256("") = 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU (no pad).
        assert_eq!(
            key_fingerprint(""),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
        // A valid base64 blob is decoded before hashing: "AAAA" = 3 zero
        // bytes, not the 4 ASCII characters.
        assert_ne!(key_fingerprint("AAAA"), key_fingerprint("\0\0\0\0"));
        assert!(key_fingerprint("AAAA").starts_with("SHA256:"));
        // Invalid base64 falls back to hashing the raw string, stably.
        assert_eq!(key_fingerprint("!!"), key_fingerprint("!!"));
    }

    #[test]
    fn human_size_picks_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }
}
