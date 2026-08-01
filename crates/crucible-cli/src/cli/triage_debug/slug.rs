//! Short digest and filesystem-safe slug rendering.

use super::*;

pub(crate) fn short_digest(digest: &str) -> &str {
    digest
        .strip_prefix(CONTENT_ADDRESS_PREFIX)
        .and_then(|hex| hex.get(..12))
        .unwrap_or("unknown")
}

pub(crate) fn sanitize_slug(slug: &str) -> String {
    let mut sanitized = slug
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }
    sanitized = sanitized.trim_matches('-').to_string();
    if sanitized.is_empty() {
        String::from("failure")
    } else {
        sanitized
    }
}
