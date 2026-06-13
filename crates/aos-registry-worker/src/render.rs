//! No-JS HTML rendering for the Worker's browse pages.
//!
//! Pure string-building with strict escaping — the same no-JS floor the native
//! hub commits to (RFC-0004 "UI surface map"). These helpers are ported from
//! the native `ui::render` module rather than reused directly: that module
//! lives inside the hub crate, which pulls in axum/tokio/rusqlite and so cannot
//! link into the wasm32 Worker. The ports are byte-compatible in behavior
//! ([`escape`], [`table`], [`human_size`], [`key_fingerprint`]) so the two
//! surfaces render identically.
//!
//! Each page is a complete document built by [`page`]: a masthead with a
//! breadcrumb trail, the body, and a footer state line carrying the surface
//! commit and index freshness. No stylesheet link to a third-party CDN — every
//! asset is first-party (RFC-0004 asset policy); the Worker serves a minimal
//! inline-free layout that curl and lynx render as real content.

use std::fmt::Write as _;

use crate::model::{ChannelSummary, IndexInfo, PackageDetail, PackageRow, Registry, ReleaseRow};

/// Truncate a string to at most `n` characters on a char boundary.
///
/// Object ids are ASCII hex in practice, but D1 is stored data and a hostile
/// or corrupt oid could be non-ASCII; a byte slice such as `&s[..12]` would
/// then panic mid-codepoint and 500 the page. Taking `n` *chars* is
/// panic-free for any input.
fn truncate_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// Escape text for HTML element and attribute contexts.
///
/// A faithful copy of the native `ui::render::escape`.
#[must_use]
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

/// Format a byte count for humans (binary units, one decimal).
///
/// A faithful copy of the native `ui::render::human_size`.
#[must_use]
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

/// The ssh-keygen-style SHA-256 fingerprint of a base64 key blob.
///
/// A faithful copy of the native `ui::render::key_fingerprint`: decodes `b64`,
/// hashes the raw blob, and renders `SHA256:<base64-no-pad>` (the form
/// `ssh-keygen -lf` prints). Invalid base64 falls back to hashing the raw
/// string so every anchor still gets a stable fingerprint.
#[must_use]
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

/// Render a table from a header row and pre-escaped body rows.
///
/// Cells in `rows` are inserted as-is so callers can embed links; callers must
/// escape all dynamic text via [`escape`]. A faithful copy of the native
/// `ui::render::table`.
#[must_use]
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

/// Render a complete page in the shared layout.
///
/// `crumbs` is the masthead trail as `(href, label)` pairs; the final crumb is
/// the current page (an empty href renders unlinked). The footer carries the
/// surface commit and index freshness from `index`.
#[must_use]
pub fn page(title: &str, crumbs: &[(String, String)], body: &str, index: &IndexInfo) -> String {
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
    if let Some(commit) = &index.last_indexed_commit {
        let _ = write!(statline, "surface {}", escape(&truncate_chars(commit, 12)));
    }
    if let Some(at) = index.indexed_at {
        if !statline.is_empty() {
            statline.push_str(" · ");
        }
        let _ = write!(statline, "indexed at unix {at}");
    }
    if !index.state.is_empty() && index.state != "fresh" {
        if !statline.is_empty() {
            statline.push_str(" · ");
        }
        let _ = write!(statline, "index state: {}", escape(&index.state));
    }
    if !statline.is_empty() {
        statline.push_str(" · ");
    }
    let _ = write!(
        statline,
        "aos-registry-worker {}",
        env!("CARGO_PKG_VERSION")
    );

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title} — AOS Registry Hub</title>\n</head>\n<body>\n\
         <header class=\"masthead\"><span class=\"brand\">AOS REGISTRY HUB</span> \
         <span class=\"crumbs\">{crumb_html}</span></header>\n\
         <main>\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}</footer>\n</body>\n</html>\n",
        title = escape(title),
    )
}

/// The hub home page: a table of every public registry.
#[must_use]
pub fn home_page(registries: &[Registry]) -> String {
    let rows: Vec<Vec<String>> = registries
        .iter()
        .map(|r| {
            vec![
                format!("<a href=\"/{slug}/-/\">{slug}</a>", slug = escape(&r.slug)),
                escape(&r.source_url),
            ]
        })
        .collect();
    let body = if rows.is_empty() {
        "<p>No public registries.</p>".to_string()
    } else {
        table(&["registry", "source"], &rows)
    };
    page(
        "registries",
        &[(String::new(), "registries".into())],
        &body,
        &IndexInfo::default(),
    )
}

/// The registry home page: trust anchors, channels, packages, setup snippet.
#[must_use]
pub fn registry_home(
    registry: &Registry,
    index: &IndexInfo,
    roster: &[(String, String, String)],
    channels: &[ChannelSummary],
    packages: &[PackageRow],
) -> String {
    let mut body = String::new();
    if let Some(desc) = &index.description {
        let _ = writeln!(body, "<p>{}</p>", escape(desc));
    }

    // Trust anchors with fingerprints (public data on a public registry).
    body.push_str("<h2>Trust anchors</h2>\n");
    if roster.is_empty() {
        body.push_str("<p>No roster keys indexed.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = roster
            .iter()
            .map(|(key_id, public_key, status)| {
                vec![
                    escape(key_id),
                    escape(&key_fingerprint(public_key)),
                    escape(status),
                ]
            })
            .collect();
        body.push_str(&table(&["key id", "fingerprint", "status"], &rows));
    }

    // Channels and their frontier.
    body.push_str("<h2>Channels</h2>\n");
    if channels.is_empty() {
        body.push_str("<p>No channels indexed.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = channels
            .iter()
            .map(|c| {
                let mapped = c.partitions.iter().filter(|p| p.is_some()).count();
                vec![
                    format!(
                        "<a href=\"/{slug}/-/channels/{name}\">{name}</a>",
                        slug = escape(&registry.slug),
                        name = escape(&c.name)
                    ),
                    escape(c.frontier.as_deref().unwrap_or("—")),
                    format!("{mapped}/256"),
                ]
            })
            .collect();
        body.push_str(&table(&["channel", "frontier", "partitions"], &rows));
    }

    // Packages.
    body.push_str("<h2>Packages</h2>\n");
    body.push_str(&package_table(&registry.slug, packages));

    page(
        &registry.slug,
        &[
            ("/".into(), "registries".into()),
            (String::new(), registry.slug.clone()),
        ],
        &body,
        index,
    )
}

/// The package index table for one registry.
#[must_use]
pub fn package_table(slug: &str, packages: &[PackageRow]) -> String {
    if packages.is_empty() {
        return "<p>No packages indexed.</p>\n".to_string();
    }
    let rows: Vec<Vec<String>> = packages
        .iter()
        .map(|p| {
            vec![
                format!(
                    "<a href=\"/{slug}/-/packages/{name}\">{name}</a>",
                    slug = escape(slug),
                    name = escape(&p.name)
                ),
                escape(p.latest.as_deref().unwrap_or("—")),
                escape(&p.license),
                escape(&p.description),
            ]
        })
        .collect();
    table(&["package", "latest", "license", "description"], &rows)
}

/// One package's detail page: versions × platforms with sizes and store paths.
#[must_use]
pub fn package_page(slug: &str, index: &IndexInfo, detail: &PackageDetail) -> String {
    let mut body = format!(
        "<h1>{}</h1>\n<p>{}</p>\n",
        escape(&detail.name),
        escape(&detail.description)
    );
    let _ = write!(
        body,
        "<dl><dt>license</dt><dd>{}</dd><dt>maintainer</dt><dd>{}</dd>",
        escape(&detail.license),
        escape(&detail.maintainer)
    );
    if let Some(home) = &detail.homepage {
        // Only http(s) homepages become links; anything else (javascript:,
        // data:, …) renders as escaped text (mirrors the native hub's
        // `pages.rs`). The homepage is stored content the native hub may have
        // populated from a package TOML, so it cannot be trusted to be a safe
        // scheme.
        let cell = if crate::indexlogic::is_safe_href(home) {
            format!("<a href=\"{h}\">{h}</a>", h = escape(home))
        } else {
            escape(home)
        };
        let _ = write!(body, "<dt>homepage</dt><dd>{cell}</dd>");
    }
    body.push_str("</dl>\n");

    for version in &detail.versions {
        let _ = writeln!(body, "<h2>{}</h2>", escape(&version.version));
        let rows: Vec<Vec<String>> = version
            .platforms
            .iter()
            .map(|p| {
                vec![
                    escape(&p.platform),
                    escape(&p.store_path),
                    escape(&human_size(p.nar_size.max(0) as u64)),
                    escape(&human_size(p.closure_size.max(0) as u64)),
                ]
            })
            .collect();
        body.push_str(&table(
            &["platform", "store path", "nar size", "closure size"],
            &rows,
        ));
    }

    page(
        &format!("{} — {slug}", detail.name),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/-/"), slug.to_string()),
            (String::new(), detail.name.clone()),
        ],
        &body,
        index,
    )
}

/// One channel's 256-partition grid page.
#[must_use]
pub fn channel_page(slug: &str, index: &IndexInfo, channel: &ChannelSummary) -> String {
    let mut body = format!(
        "<h1>channel {}</h1>\n<p>frontier: {}</p>\n",
        escape(&channel.name),
        escape(channel.frontier.as_deref().unwrap_or("—"))
    );
    body.push_str("<pre class=\"grid\">\n");
    for (bucket, slot) in channel.partitions.iter().enumerate() {
        let cell = slot.as_deref().unwrap_or("·");
        let _ = writeln!(body, "{bucket:02x} {}", escape(cell));
    }
    body.push_str("</pre>\n");
    page(
        &format!("channel {} — {slug}", channel.name),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/-/"), slug.to_string()),
            (String::new(), format!("channel {}", channel.name)),
        ],
        &body,
        index,
    )
}

/// The releases page: signed tags with signature/pack status.
#[must_use]
pub fn releases_page(slug: &str, index: &IndexInfo, releases: &[ReleaseRow]) -> String {
    let body = if releases.is_empty() {
        "<p>No releases indexed.</p>\n".to_string()
    } else {
        let rows: Vec<Vec<String>> = releases
            .iter()
            .map(|r| {
                vec![
                    escape(&r.semver),
                    escape(&truncate_chars(&r.commit_oid, 12)),
                    escape(r.signer.as_deref().unwrap_or("—")),
                    if r.pack_present != 0 {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                ]
            })
            .collect();
        table(&["version", "commit", "signer", "pack"], &rows)
    };
    page(
        &format!("releases — {slug}"),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/-/"), slug.to_string()),
            (String::new(), "releases".into()),
        ],
        &body,
        index,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PlatformDetail, VersionDetail};

    #[test]
    fn escape_covers_html_metacharacters() {
        assert_eq!(
            escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn human_size_picks_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn key_fingerprint_matches_native() {
        // sha256("") = 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU (no pad) —
        // identical to the native ui::render::key_fingerprint.
        assert_eq!(
            key_fingerprint(""),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    fn demo_registry() -> Registry {
        Registry {
            id: 1,
            slug: "demo".into(),
            source_url: "https://cdn.example/demo".into(),
            trust_keys: "[]".into(),
            require_signatures: 1,
            visibility: "public".into(),
            prefix: "demo/".into(),
        }
    }

    fn demo_index() -> IndexInfo {
        IndexInfo {
            state: "fresh".into(),
            error: None,
            last_indexed_commit: Some("ab".repeat(32)),
            name: Some("Demo".into()),
            description: Some("A demo registry".into()),
            indexed_at: Some(200),
        }
    }

    #[test]
    fn registry_home_renders_anchors_channels_packages() {
        let channels = vec![ChannelSummary {
            name: "stable".into(),
            frontier: Some("8.0.0".into()),
            partitions: {
                let mut p = vec![None; 256];
                p[0] = Some("8.0.0".into());
                p
            },
        }];
        let packages = vec![PackageRow {
            name: "curl".into(),
            description: "A client".into(),
            license: "MIT".into(),
            latest: Some("8.0.0".into()),
        }];
        let roster = vec![("k1".to_string(), "AAAA".to_string(), "active".to_string())];
        let html = registry_home(
            &demo_registry(),
            &demo_index(),
            &roster,
            &channels,
            &packages,
        );
        assert!(html.contains("Trust anchors"));
        assert!(html.contains("SHA256:"), "fingerprint rendered");
        assert!(html.contains("/demo/-/channels/stable"));
        assert!(html.contains("1/256"), "mapped partition count");
        assert!(html.contains("/demo/-/packages/curl"));
        assert!(html.contains("surface abababababab"), "footer state line");
    }

    #[test]
    fn package_page_renders_versions_and_sizes() {
        let detail = PackageDetail {
            name: "curl".into(),
            description: "A client".into(),
            homepage: Some("https://curl.se".into()),
            license: "MIT".into(),
            maintainer: "alice".into(),
            sysroot: false,
            versions: vec![VersionDetail {
                version: "8.0.0".into(),
                previous: None,
                platforms: vec![PlatformDetail {
                    platform: "x86_64-linux".into(),
                    store_path: "/nix/store/x-curl".into(),
                    nar_hash: "sha256:ab".into(),
                    nar_size: 3 * 1024 * 1024,
                    closure_size: 10 * 1024 * 1024,
                }],
            }],
        };
        let html = package_page("demo", &demo_index(), &detail);
        assert!(html.contains("x86_64-linux"));
        assert!(html.contains("/nix/store/x-curl"));
        assert!(html.contains("3.0 MiB"));
        assert!(html.contains("https://curl.se"));
    }

    #[test]
    fn channel_page_renders_256_buckets() {
        let mut partitions = vec![None; 256];
        partitions[0] = Some("8.0.0".into());
        partitions[255] = Some("7.9.0".into());
        let channel = ChannelSummary {
            name: "stable".into(),
            frontier: Some("8.0.0".into()),
            partitions,
        };
        let html = channel_page("demo", &demo_index(), &channel);
        assert!(html.contains("00 8.0.0"));
        assert!(html.contains("ff 7.9.0"));
        // Unmapped buckets render the placeholder.
        assert!(html.contains("01 ·"));
    }

    #[test]
    fn releases_page_renders_signature_and_pack_status() {
        let releases = vec![ReleaseRow {
            semver: "8.0.0".into(),
            tag_oid: "tag1".into(),
            commit_oid: "commit1deadbeef".into(),
            signer: Some("alice".into()),
            tagged_at: Some(300),
            pack_present: 1,
        }];
        let html = releases_page("demo", &demo_index(), &releases);
        assert!(html.contains("8.0.0"));
        assert!(html.contains("alice"));
        assert!(html.contains("<td>yes</td>"), "pack present");
    }

    #[test]
    fn home_page_lists_registries() {
        let html = home_page(&[demo_registry()]);
        assert!(html.contains("/demo/-/"));
        assert!(html.contains("https://cdn.example/demo"));
    }

    #[test]
    fn package_homepage_requires_http_scheme() {
        // A `javascript:` homepage (stored content the native hub may populate)
        // must never become a live href; it renders as escaped text instead.
        let detail = PackageDetail {
            name: "evil".into(),
            description: "x".into(),
            homepage: Some("javascript:alert(1)".into()),
            license: "MIT".into(),
            maintainer: "alice".into(),
            sysroot: false,
            versions: vec![],
        };
        let html = package_page("demo", &demo_index(), &detail);
        assert!(
            !html.contains("href=\"javascript:"),
            "javascript: homepage must not become a link: {html}"
        );
        assert!(html.contains("javascript:alert(1)"), "still shown as text");
    }

    #[test]
    fn package_homepage_http_becomes_link() {
        let detail = PackageDetail {
            name: "curl".into(),
            description: "x".into(),
            homepage: Some("https://curl.se".into()),
            license: "MIT".into(),
            maintainer: "alice".into(),
            sysroot: false,
            versions: vec![],
        };
        let html = package_page("demo", &demo_index(), &detail);
        assert!(html.contains("href=\"https://curl.se\""));
    }

    #[test]
    fn non_ascii_commit_oid_does_not_panic() {
        // A corrupt/hostile multibyte oid must truncate on a char boundary, not
        // panic mid-codepoint (which would 500 the page).
        let releases = vec![ReleaseRow {
            semver: "1.0.0".into(),
            tag_oid: "t".into(),
            commit_oid: "café—deadbeef—oid".into(),
            signer: None,
            tagged_at: None,
            pack_present: 0,
        }];
        let html = releases_page("demo", &demo_index(), &releases);
        assert!(html.contains("1.0.0"));
    }

    #[test]
    fn non_ascii_surface_commit_does_not_panic() {
        let mut index = demo_index();
        index.last_indexed_commit = Some("café—surface—commit".into());
        let html = home_page(&[demo_registry()]);
        // The statline only appears on pages that take an index; render one.
        let _ = html;
        let detail = PackageDetail {
            name: "p".into(),
            description: "x".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "a".into(),
            sysroot: false,
            versions: vec![],
        };
        let page = package_page("demo", &index, &detail);
        assert!(page.contains("surface"));
    }
}
