//! HTML rendering primitives for the no-JS tier.
//!
//! Plain string-building with strict escaping — no client-side framework
//! is required for any page this module renders, which is the design
//! floor RFC-0004 commits to. The SSR-framework decision (Leptos vs
//! Dioxus) is an explicit open question; everything here sits behind the
//! `ui` module boundary so that spike can replace the renderer without
//! touching handlers.

use std::fmt::Write as _;

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
/// the surface commit, index freshness, and hub version).
#[derive(Debug, Default, Clone)]
pub struct StateLine {
    /// Indexed surface commit (short form is rendered).
    pub surface_commit: Option<String>,
    /// Unix time of the last successful index.
    pub indexed_at: Option<i64>,
    /// Index state when not `fresh`.
    pub state: Option<String>,
}

/// Render a complete page in the shared layout.
///
/// `crumbs` is the masthead trail as `(href, label)` pairs; the final
/// crumb should be the current page (empty href renders unlinked).
pub fn page(title: &str, crumbs: &[(String, String)], body: &str, state: &StateLine) -> String {
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

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title} — AOS Registry Hub</title>\n\
         <link rel=\"stylesheet\" href=\"/_assets/style.css\">\n</head>\n<body>\n\
         <header class=\"masthead\"><span class=\"brand\">AOS REGISTRY HUB</span>\
         <span class=\"crumbs\">{crumb_html}</span></header>\n\
         <main>\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}</footer>\n</body>\n</html>\n",
        title = escape(title),
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
            },
        );
        assert!(html.contains("demo — AOS Registry Hub"));
        assert!(html.contains("surface abababababab"));
        assert!(html.contains("<p>body</p>"));
        assert!(html.contains("registries</a>"));
    }

    #[test]
    fn human_size_picks_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }
}
