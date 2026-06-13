//! HTML rendering primitives for the no-JS tier.
//!
//! Plain string-building with strict escaping — no client-side framework
//! is required for any page this module renders, which is the design
//! floor RFC-0004 commits to. The SSR-framework decision (Leptos vs
//! Dioxus) is an explicit open question; everything here sits behind the
//! `ui` module boundary so that spike can replace the renderer without
//! touching handlers.

use std::fmt::Write as _;
use std::sync::OnceLock;

/// The operator-configurable masthead brand (company/instance name).
///
/// Set once at server startup via [`set_brand`]; defaults to empty. When
/// empty the masthead shows only the page crumbs (e.g. "log in"); when set,
/// the name leads the masthead and titles every page.
static BRAND: OnceLock<String> = OnceLock::new();

/// Set the masthead brand once, at startup.
///
/// A no-op if called more than once (the first value wins), so it is safe
/// to call unconditionally from `serve`.
pub fn set_brand(name: impl Into<String>) {
    let _ = BRAND.set(name.into());
}

/// The configured brand, or `""` when unset.
#[must_use]
pub fn brand() -> &'static str {
    BRAND.get().map(String::as_str).unwrap_or("")
}

/// The masthead brand element for `brand`: a home link, or empty when unset.
fn brand_span(brand: &str) -> String {
    if brand.is_empty() {
        String::new()
    } else {
        format!("<a class=\"brand\" href=\"/\">{}</a>", escape(brand))
    }
}

/// The `<title>` text: `"<page> — <brand>"`, or `"<page> — Registry Hub"`
/// when no brand is configured.
fn page_title(brand: &str, title: &str) -> String {
    if brand.is_empty() {
        format!("{} — Registry Hub", escape(title))
    } else {
        format!("{} — {}", escape(title), escape(brand))
    }
}

/// Escape text for HTML element and attribute contexts.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Data for the footer state line ("expose state" — every page carries
/// the surface commit, index freshness, render time, and hub version).
#[derive(Debug, Default, Clone)]
pub struct StateLine {
    /// Indexed surface commit (short form is rendered).
    pub surface_commit: Option<String>,
    /// Unix time of the last successful index.
    pub indexed_at: Option<i64>,
    /// Index state when not `fresh`.
    pub state: Option<String>,
    /// Handler entry time; when set, the footer shows "rendered NNms".
    pub started: Option<std::time::Instant>,
}

impl StateLine {
    /// A state line that only carries the render-time clock.
    pub fn timed(started: std::time::Instant) -> Self {
        Self {
            started: Some(started),
            ..Self::default()
        }
    }
}

/// The masthead session indicator: the logged-in email plus a logout link,
/// or a "log in" link for an anonymous visitor.
///
/// Passed to [`page_with_session`] so every authenticated producer-console
/// page shows who is signed in (RFC-0004's masthead "[log in]" affordance).
/// `None` renders the anonymous indicator; the browse pages pass `None` and
/// remain unchanged.
#[derive(Debug, Default, Clone)]
pub struct SessionIndicator {
    /// The signed-in user's email, or `None` when anonymous.
    pub email: Option<String>,
}

impl SessionIndicator {
    /// A session indicator for the signed-in user `email`.
    #[must_use]
    pub fn signed_in(email: impl Into<String>) -> Self {
        Self {
            email: Some(email.into()),
        }
    }

    /// Renders the indicator as the right-hand masthead HTML fragment.
    fn render(&self) -> String {
        match &self.email {
            Some(email) => format!(
                "<span class=\"session\">{} · <a href=\"/logout\">log out</a></span>",
                escape(email),
            ),
            None => "<span class=\"session\"><a href=\"/login\">log in</a></span>".to_string(),
        }
    }
}

/// Render a complete page in the shared layout.
///
/// `crumbs` is the masthead trail as `(href, label)` pairs; the final
/// crumb should be the current page (empty href renders unlinked). The
/// masthead carries the anonymous session indicator; use
/// [`page_with_session`] to show the signed-in identity.
pub fn page(title: &str, crumbs: &[(String, String)], body: &str, state: &StateLine) -> String {
    page_with_session(title, crumbs, body, state, &SessionIndicator::default())
}

/// Render a complete page, threading a masthead session indicator.
///
/// Identical to [`page`] but renders `session` on the right of the masthead
/// — the signed-in email and a logout link, or the anonymous "log in" link.
pub fn page_with_session(
    title: &str,
    crumbs: &[(String, String)],
    body: &str,
    state: &StateLine,
    session: &SessionIndicator,
) -> String {
    let mut crumb_html = String::new();
    for (i, (href, label)) in crumbs.iter().enumerate() {
        if i > 0 {
            crumb_html.push_str(" / ");
        }
        if href.is_empty() {
            let _ = write!(crumb_html, "{}", escape(label));
        } else {
            let _ = write!(
                crumb_html,
                "<a href=\"{}\">{}</a>",
                escape(href),
                escape(label)
            );
        }
    }

    let mut statline = String::new();
    if let Some(commit) = &state.surface_commit {
        let _ = write!(
            statline,
            "surface {}",
            escape(&commit[..commit.len().min(12)])
        );
    }
    if let Some(at) = state.indexed_at {
        if !statline.is_empty() {
            statline.push_str(" · ");
        }
        let _ = write!(statline, "indexed at unix {at}");
    }
    if let Some(s) = &state.state {
        if s != "fresh" {
            if !statline.is_empty() {
                statline.push_str(" · ");
            }
            let _ = write!(statline, "index state: {}", escape(s));
        }
    }
    if !statline.is_empty() {
        statline.push_str(" · ");
    }
    let _ = write!(statline, "aos-registry-hub {}", env!("CARGO_PKG_VERSION"));
    if let Some(started) = state.started {
        let _ = write!(statline, " · rendered {}ms", started.elapsed().as_millis());
    }

    // The brand is operator-configurable (default empty): when set it
    // leads the masthead and titles every page; when empty the crumbs lead.
    let brand_span = brand_span(brand());
    let page_title = page_title(brand(), title);

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{page_title}</title>\n\
         <link rel=\"stylesheet\" href=\"/_assets/style.css\">\n</head>\n<body>\n\
         <header class=\"masthead\">{brand_span}\
         <span class=\"crumbs\">{crumb_html}</span>{session}</header>\n\
         <main>\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}</footer>\n</body>\n</html>\n",
        session = session.render(),
    )
}

/// Render a table from a header row and pre-escaped body rows.
///
/// Cells in `rows` are inserted as-is so callers can embed links; callers
/// must escape all dynamic text via [`escape`].
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = String::from("<table>\n<thead><tr>");
    for header in headers {
        let _ = write!(out, "<th>{}</th>", escape(header));
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for cell in row {
            let _ = write!(out, "<td>{cell}</td>");
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table>\n");
    out
}

/// Format a Unix timestamp as a coarse relative age ("38s ago",
/// "4m ago", "3h ago", "2d ago").
///
/// Timestamps in the future (clock skew) render as "0s ago".
pub fn ago(unix: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let delta = (now - unix).max(0);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

/// The ssh-keygen-style SHA-256 fingerprint of a base64 key blob.
///
/// Decodes `b64`, hashes the raw blob, and renders the digest as
/// `SHA256:<base64-no-pad>` — the same form `ssh-keygen -lf` prints. When
/// `b64` is not valid base64, the raw string bytes are hashed instead so
/// every anchor still gets a stable fingerprint.
pub fn key_fingerprint(b64: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .unwrap_or_else(|_| b64.as_bytes().to_vec());
    let digest = sha2::Sha256::digest(&blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// Format a byte count for humans (binary units, one decimal).
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
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
    fn brand_span_and_title_reflect_the_configured_brand() {
        // Empty brand: no masthead brand element, neutral page title.
        assert_eq!(brand_span(""), "");
        assert_eq!(page_title("", "log in"), "log in — Registry Hub");
        // Configured brand: a home-linked element + branded title, escaped.
        assert_eq!(
            brand_span("Acme <Co>"),
            "<a class=\"brand\" href=\"/\">Acme &lt;Co&gt;</a>"
        );
        assert_eq!(page_title("Acme", "log in"), "log in — Acme");
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
