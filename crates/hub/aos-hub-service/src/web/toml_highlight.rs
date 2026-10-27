//! Server-side TOML syntax highlighting and diff rendering.
//!
//! This is the Rust twin of the line-oriented TOML highlighter in
//! `static_assets/app.js`: one grammar, two runtimes. The client highlighter
//! enhances the live config editor; this module renders the *committed* diffs on
//! the change-request review surface so syntax color survives with JavaScript
//! disabled (the no-JS floor) and under the strict `default-src 'self'` CSP.
//!
//! Both emit the same CSS token classes, bound to theme variables in
//! `style.css`:
//!
//! ```text
//! t-c  comment        t-h  [table] header   t-k  key
//! t-s  string value   t-n  number value     t-b  boolean value   t-a  array/inline-table
//! ```
//!
//! Highlighting is deliberately approximate and line-local: it covers the
//! `registry.toml` schema and lets anything it does not recognize fall through
//! as plain escaped ink, so malformed input never panics or mis-renders
//! structurally — it just loses color.

use std::fmt::Write as _;

use super::render::escape;

/// Highlights one line of TOML into escaped HTML with `t-*` token spans.
///
/// Splits off a trailing `#` comment (honoring `#` inside string literals),
/// then classifies the code portion as a `[table]` header, a `key = value`
/// pair (highlighting the value by type), or plain text. The returned string is
/// already HTML-escaped and safe to embed in element content.
#[must_use]
pub fn highlight_toml_line(line: &str) -> String {
    // Split off a trailing comment, skipping any `#` inside a string literal.
    let mut in_str: Option<char> = None;
    let mut cut: Option<usize> = None;
    for (i, c) in line.char_indices() {
        match in_str {
            Some(q) => {
                if c == q {
                    in_str = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    in_str = Some(c);
                } else if c == '#' {
                    cut = Some(i);
                    break;
                }
            }
        }
    }

    let (code, comment) = match cut {
        Some(i) => (
            &line[..i],
            format!("<span class=\"t-c\">{}</span>", escape(&line[i..])),
        ),
        None => (line, String::new()),
    };

    let trimmed = code.trim();
    let body = if trimmed.is_empty() {
        escape(code)
    } else if trimmed.starts_with('[') {
        format!("<span class=\"t-h\">{}</span>", escape(code))
    } else if let Some(eq) = code.find('=') {
        format!(
            "<span class=\"t-k\">{}</span>={}",
            escape(&code[..eq]),
            highlight_toml_value(&code[eq + 1..]),
        )
    } else {
        escape(code)
    };

    format!("{body}{comment}")
}

/// Highlights the value side of a `key = value` pair by inferred type.
///
/// Recognizes string, boolean, number, and array/inline-table cores, preserving
/// surrounding whitespace; an unrecognized value renders as plain escaped text.
fn highlight_toml_value(v: &str) -> String {
    let core = v.trim();
    if core.is_empty() {
        return escape(v);
    }
    let lead = &v[..v.len() - v.trim_start().len()];
    let trail = &v[v.trim_end().len()..];

    let class = if is_quoted(core) {
        "t-s"
    } else if core == "true" || core == "false" {
        "t-b"
    } else if is_number(core) {
        "t-n"
    } else if core.starts_with('[') || core.starts_with('{') {
        "t-a"
    } else {
        return escape(v);
    };

    format!(
        "{}<span class=\"{class}\">{}</span>{}",
        escape(lead),
        escape(core),
        escape(trail),
    )
}

/// Whether `s` is a single double- or single-quoted string literal.
fn is_quoted(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
}

/// Whether `s` looks like a TOML number/date core (`[-+]?[0-9][0-9_.:eE+-]*`).
fn is_number(s: &str) -> bool {
    let rest = s.strip_prefix(['-', '+']).unwrap_or(s);
    let mut chars = rest.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => {}
        _ => return false,
    }
    rest.chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | 'e' | 'E' | '+' | '-'))
}

/// Renders a unified-diff string (from [`crate::git::unified_diff`]) as a
/// syntax-highlighted, no-JS HTML diff block.
///
/// Each source line becomes a block `<span class="dl …">` carrying its `+`/`-`/
/// ` ` marker and TOML-highlighted content; `--- a/` / `+++ b/` banners and
/// `@@` hunk markers render as dimmed meta lines. The result is a complete
/// `<div class="diff">` whose text stays selectable and copy-pasteable.
#[must_use]
pub fn render_toml_diff(unified: &str) -> String {
    let mut out = String::from("<div class=\"diff\">");
    for line in unified.lines() {
        let (class, content) =
            if line.starts_with("--- ") || line.starts_with("+++ ") || line.starts_with("@@") {
                ("dl dl-meta", escape(line))
            } else if let Some(rest) = line.strip_prefix('-') {
                ("dl dl-del", format!("-{}", highlight_toml_line(rest)))
            } else if let Some(rest) = line.strip_prefix('+') {
                ("dl dl-add", format!("+{}", highlight_toml_line(rest)))
            } else {
                let rest = line.strip_prefix(' ').unwrap_or(line);
                ("dl dl-ctx", format!(" {}", highlight_toml_line(rest)))
            };
        let _ = write!(out, "<span class=\"{class}\">{content}</span>");
    }
    out.push_str("</div>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlights_table_key_and_value_kinds() {
        assert_eq!(
            highlight_toml_line("[registry]"),
            "<span class=\"t-h\">[registry]</span>"
        );
        assert!(highlight_toml_line("name = \"acme\"")
            .contains("<span class=\"t-s\">&quot;acme&quot;</span>"));
        assert!(highlight_toml_line("priority = 40").contains("<span class=\"t-n\">40</span>"));
        assert!(highlight_toml_line("content_addressed = true")
            .contains("<span class=\"t-b\">true</span>"));
    }

    #[test]
    fn comment_is_split_off_and_strings_protect_hash() {
        assert!(
            highlight_toml_line("# a comment").contains("<span class=\"t-c\"># a comment</span>")
        );
        // A `#` inside a string is not a comment.
        let line = highlight_toml_line("url = \"https://x/#frag\"");
        assert!(!line.contains("t-c"));
    }

    #[test]
    fn diff_classifies_lines_and_skips_banner_as_meta() {
        let unified =
            crate::git::unified_diff("registry.toml", "priority = 10\n", "priority = 40\n");
        let html = render_toml_diff(&unified);
        assert!(html.contains("dl-meta")); // the --- / +++ banner
        assert!(html.contains("dl-del"));
        assert!(html.contains("dl-add"));
        assert!(html.contains("<span class=\"t-n\">40</span>"));
    }

    #[test]
    fn malformed_input_never_panics() {
        let _ = highlight_toml_line("=== not really toml [[[ \"unterminated");
        let _ = render_toml_diff("garbage\nwith no markers");
    }
}
