//! No-JS HTML rendering for the shared browse pages.
//!
//! RFC-0004 Phase 5 unifies the browse UI on one renderer so the native hub
//! and the Cloudflare Worker render it from a single code path. These builders
//! are **transport- and task-local-free**: the masthead brand and the
//! signed-in email (the login indicator) are passed explicitly via
//! [`PageChrome`] rather than read from a task-local, so the module compiles to
//! `wasm32-unknown-unknown` (no `axum`, no `tokio`, no `std::fs`).
//!
//! Every page renders from the `aos.hub.v1` read shapes the
//! [`RpcService`](crate::service::RpcService) returns
//! ([`aos_proto_types`] structs) — the same data the JSON read API serializes —
//! and is a complete document built by [`page`]: a masthead with the brand, a
//! breadcrumb trail, and the optional session indicator; the body; and a footer
//! state line carrying the surface commit and index freshness. No stylesheet
//! link to a third-party CDN — every asset is first-party (RFC-0004 asset
//! policy); the layout is one that `curl` and `lynx` render as real content.
//!
//! The pure primitives — [`escape`], [`table`], [`human_size`],
//! [`key_fingerprint`] — are byte-compatible with the native hub's richer
//! `ui::render` so the two surfaces render identically.

use std::fmt::Write as _;

use aos_hub_console_contract::{HashPresentation, AUTHENTICATED_PRIMARY_NAVIGATION};
use aos_proto_types as pb;

/// Renders the canonical signed-in masthead links.
pub(crate) fn authenticated_navigation() -> String {
    AUTHENTICATED_PRIMARY_NAVIGATION
        .iter()
        .map(|item| {
            format!(
                "<a href=\"{}\">{}</a>",
                escape(item.href),
                escape(item.label)
            )
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The masthead chrome threaded into every page by the deploying shell.
///
/// Replaces the native hub's task-local session lookup and global brand
/// `OnceLock`: the shell (native hub or Worker) supplies the per-request
/// signed-in email and the operator-configured brand explicitly, keeping the
/// renderer a pure function of its inputs and wasm-clean. The Worker passes
/// `session_email: None` (anonymous public browse only); the native hub threads
/// the email resolved by its session middleware.
#[derive(Debug, Default, Clone)]
pub struct PageChrome {
    /// The signed-in user's email, or `None` for an anonymous visitor.
    ///
    /// When set, the masthead shows the email and a log-out link; when `None`
    /// it shows a "log in" link.
    pub session_email: Option<String>,
    /// The operator-configured masthead brand (company/instance name).
    ///
    /// When empty, the masthead shows only the page crumbs and titles default
    /// to `"<page> — AOS Registry Hub"`; when set, the brand leads the masthead
    /// and titles every page.
    pub brand: String,
}

impl PageChrome {
    /// An anonymous chrome with no brand (the Worker's default).
    #[must_use]
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// The masthead brand element: a home link, or empty when the brand is unset.
    fn brand_span(&self) -> String {
        if self.brand.is_empty() {
            String::new()
        } else {
            format!("<a class=\"brand\" href=\"/\">{}</a>", escape(&self.brand))
        }
    }

    /// The `<title>` text: `"<page> — <brand>"`, or `"<page> — AOS Registry
    /// Hub"` when no brand is configured.
    fn page_title(&self, title: &str) -> String {
        if self.brand.is_empty() {
            format!("{} — AOS Registry Hub", escape(title))
        } else {
            format!("{} — {}", escape(title), escape(&self.brand))
        }
    }

    /// The right-hand masthead session indicator.
    ///
    /// Renders the signed-in email plus a log-out link, or a "log in" link for
    /// an anonymous visitor. Always leads with a "registries" home link.
    fn session_span(&self) -> String {
        match &self.session_email {
            Some(email) => format!(
                "<span class=\"session\">\
                 {} · \
                 <span class=\"who\">{}</span> · \
                 <a href=\"/logout\">log out</a></span>",
                authenticated_navigation(),
                escape(email),
            ),
            None => "<span class=\"session\">\
                     <a href=\"/\">registries</a> · \
                     <a href=\"/login\">log in</a></span>"
                .to_string(),
        }
    }
}

/// Index freshness and surface metadata for the footer state line.
///
/// Projected from one [`pb::Registry`] (its `index_*`/`last_indexed_commit`/
/// `indexed_at` fields); a `default` value renders an empty state line (the hub
/// home, which has no single registry context).
#[derive(Debug, Clone, Default)]
pub struct IndexInfo {
    /// `fresh` | `indexing` | `stale` | `failed` | `partial`.
    pub state: String,
    /// The registry's description from its committed `registry.toml`.
    pub description: Option<String>,
    /// The surface commit the index was built from.
    pub last_indexed_commit: Option<String>,
    /// Unix time of the last successful index.
    pub indexed_at: Option<i64>,
}

impl IndexInfo {
    /// Project the index-freshness fields of a [`pb::Registry`] for the footer.
    #[must_use]
    pub fn from_registry(registry: &pb::Registry) -> Self {
        Self {
            state: registry.index_state.clone(),
            description: non_empty(&registry.description),
            last_indexed_commit: non_empty(&registry.last_indexed_commit),
            indexed_at: (registry.indexed_at != 0).then_some(registry.indexed_at),
        }
    }
}

/// `Some(s.to_owned())` when `s` is non-empty, else `None`.
///
/// The proto types use empty strings for absent optional fields; this restores
/// the `Option` the renderer's "—" fallbacks expect.
fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

/// Truncate a string to at most `n` characters on a char boundary.
///
/// Object ids are ASCII hex in practice, but stored data could carry a hostile
/// or corrupt non-ASCII oid; a byte slice such as `&s[..12]` would then panic
/// mid-codepoint and 500 the page. Taking `n` *chars* is panic-free for any
/// input.
fn truncate_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// Whether an href is safe to emit as a link target.
///
/// Only `http`/`https` URLs become links; anything else (`javascript:`,
/// `data:`, …) must render as escaped plain text so a stored hostile URL cannot
/// become an active sink in the no-JS browse UI.
#[must_use]
fn is_safe_href(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Escape text for HTML element and attribute contexts.
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
/// Decodes `b64`, hashes the raw blob, and renders `SHA256:<base64-no-pad>`
/// (the form `ssh-keygen -lf` prints). Invalid base64 falls back to hashing the
/// raw string so every anchor still gets a stable fingerprint.
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
/// escape all dynamic text via [`escape`].
#[must_use]
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let subject = headers.first().copied().unwrap_or("Data");
    let label = format!("{subject} table");
    let mut out = format!(
        "<div class=\"table-scroll\" role=\"region\" aria-label=\"{}\" tabindex=\"0\">\
         <table>\n<caption class=\"visually-hidden\">{}</caption><thead><tr>",
        escape(&format!("Scrollable {label}")),
        escape(&label),
    );
    for header in headers {
        let _ = write!(out, "<th scope=\"col\">{}</th>", escape(header));
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for cell in row {
            let _ = write!(out, "<td>{cell}</td>");
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table></div>\n");
    out
}

/// Renders one hash using the shared compact, tooltip, and copy treatment.
///
/// The complete value remains in the document and is exposed by the
/// progressive-enhancement bundle on hover, focus, and copy.
#[must_use]
pub fn hash_value(value: &str) -> String {
    hash_value_with_link(value, None)
}

/// Renders one compact hash whose pill links to `href` while copy stays local.
#[must_use]
pub fn hash_value_link(value: &str, href: &str) -> String {
    hash_value_with_link(value, Some(href))
}

fn hash_value_with_link(value: &str, href: Option<&str>) -> String {
    let presentation = HashPresentation::new(value);
    compact_value(presentation.full, &presentation.compact, "hash", href)
}

/// Renders a trust key as a compact, copyable pill that emphasizes its tail.
///
/// Trust-key names and algorithms are usually identical within one roster, so
/// the trailing key material is more useful for distinguishing adjacent rows.
#[must_use]
pub fn trust_key_value(value: &str) -> String {
    const VISIBLE_TAIL_CHARACTERS: usize = 12;

    let character_count = value.chars().count();
    let compact = if character_count > VISIBLE_TAIL_CHARACTERS {
        let tail = value
            .chars()
            .skip(character_count - VISIBLE_TAIL_CHARACTERS)
            .collect::<String>();
        format!("…{tail}")
    } else {
        value.to_string()
    };

    compact_value(value, &compact, "trust key", None)
}

fn compact_value(full: &str, compact: &str, kind: &str, href: Option<&str>) -> String {
    let content = format!(
        "<code aria-label=\"{}\">{}</code>\
         <span class=\"hash-tooltip\" role=\"tooltip\">{}</span>",
        escape(full),
        escape(compact),
        escape(full),
    );
    let identity = match href {
        Some(href) => format!(
            "<a class=\"hash-value\" data-hash-value=\"{}\" href=\"{}\">{content}</a>",
            escape(full),
            escape(href),
        ),
        None => format!(
            "<span class=\"hash-value\" data-hash-value=\"{}\" tabindex=\"0\">\
             {content}</span>",
            escape(full),
        ),
    };
    format!(
        "<span class=\"hash-control\">{}\
         <button type=\"button\" class=\"hash-copy\" data-copy-value=\"{}\" \
         aria-label=\"Copy full {}\" title=\"Copy full {}\">\
         <svg class=\"hash-copy-icon\" aria-hidden=\"true\" viewBox=\"0 0 16 16\">\
         <rect x=\"5.5\" y=\"5.5\" width=\"7\" height=\"7\" rx=\"1\"/>\
         <path d=\"M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2\"/>\
         </svg><svg class=\"hash-copy-done\" aria-hidden=\"true\" viewBox=\"0 0 16 16\">\
         <path d=\"m3 8 3 3 7-7\"/></svg></button></span>",
        identity,
        escape(full),
        escape(kind),
        escape(kind),
    )
}

/// Render a complete page in the shared layout.
///
/// `crumbs` is the masthead trail as `(href, label)` pairs; the final crumb is
/// the current page (an empty href renders unlinked). `chrome` carries the
/// masthead brand and the session indicator; the footer carries the surface
/// commit and index freshness from `index`.
#[must_use]
pub fn page(
    chrome: &PageChrome,
    title: &str,
    crumbs: &[(String, String)],
    body: &str,
    index: &IndexInfo,
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
    let _ = write!(statline, "aos-registry {}", env!("CARGO_PKG_VERSION"));

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{page_title}</title>\n</head>\n<body>\n\
         <header class=\"masthead\">{brand_span}\
         <span class=\"crumbs\">{crumb_html}</span>{session}</header>\n\
         <main>\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}</footer>\n</body>\n</html>\n",
        page_title = chrome.page_title(title),
        brand_span = chrome.brand_span(),
        session = chrome.session_span(),
    )
}

/// The hub home page: a table of every public registry.
#[must_use]
pub fn home_page(chrome: &PageChrome, registries: &[pb::Registry]) -> String {
    let rows: Vec<Vec<String>> = registries
        .iter()
        .map(|r| {
            vec![format!(
                "<a href=\"/{slug}/-/\">{slug}</a>",
                slug = escape(&r.slug)
            )]
        })
        .collect();
    let body = if rows.is_empty() {
        "<p>No public registries.</p>".to_string()
    } else {
        table(&["registry"], &rows)
    };
    page(
        chrome,
        "registries",
        &[(String::new(), "registries".into())],
        &body,
        &IndexInfo::default(),
    )
}

/// The registry home page: trust anchors, channels, packages, setup snippet.
///
/// Renders entirely from the `aos.hub.v1` read shapes: trust anchors from
/// the registry's `roster`, plus the channel and package lists.
#[must_use]
pub fn registry_home(
    chrome: &PageChrome,
    registry: &pb::Registry,
    channels: &[pb::Channel],
    packages: &[pb::PackageSummary],
) -> String {
    let index = IndexInfo::from_registry(registry);
    let mut body = String::new();
    if let Some(desc) = &index.description {
        let _ = writeln!(body, "<p>{}</p>", escape(desc));
    }

    // Trust anchors with fingerprints (public data on a public registry).
    body.push_str("<h2>Trust anchors</h2>\n");
    if registry.roster.is_empty() {
        body.push_str("<p>No roster keys indexed.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = registry
            .roster
            .iter()
            .map(|k| {
                vec![
                    escape(&k.id),
                    hash_value(&key_fingerprint(&k.key)),
                    escape(&k.status),
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
                let mapped = c.partitions.len();
                vec![
                    format!(
                        "<a href=\"/{slug}/-/channels/{name}\">{name}</a>",
                        slug = escape(&registry.slug),
                        name = escape(&c.name)
                    ),
                    escape(if c.frontier.is_empty() {
                        "—"
                    } else {
                        &c.frontier
                    }),
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
        chrome,
        &registry.slug,
        &[
            ("/".into(), "registries".into()),
            (String::new(), registry.slug.clone()),
        ],
        &body,
        &index,
    )
}

/// The package index table for one registry.
#[must_use]
pub fn package_table(slug: &str, packages: &[pb::PackageSummary]) -> String {
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
                escape(if p.latest_version.is_empty() {
                    "—"
                } else {
                    &p.latest_version
                }),
                escape(&p.license),
                escape(&p.description),
            ]
        })
        .collect();
    table(&["package", "latest", "license", "description"], &rows)
}

/// The package index page: the registry's package table under the `/-/`
/// namespace.
#[must_use]
pub fn package_index(
    chrome: &PageChrome,
    registry: &pb::Registry,
    packages: &[pb::PackageSummary],
) -> String {
    let index = IndexInfo::from_registry(registry);
    let body = package_table(&registry.slug, packages);
    page(
        chrome,
        &format!("packages — {}", registry.slug),
        &[
            ("/".into(), "registries".into()),
            (format!("/{}/-/", registry.slug), registry.slug.clone()),
            (String::new(), "packages".into()),
        ],
        &body,
        &index,
    )
}

/// One package's detail page: versions × platforms with sizes and store paths.
#[must_use]
pub fn package_page(chrome: &PageChrome, registry: &pb::Registry, package: &pb::Package) -> String {
    let slug = &registry.slug;
    let index = IndexInfo::from_registry(registry);
    let mut body = format!(
        "<h1>{}</h1>\n<p>{}</p>\n",
        escape(&package.name),
        escape(&package.description)
    );
    let _ = write!(
        body,
        "<dl><dt>license</dt><dd>{}</dd><dt>maintainer</dt><dd>{}</dd>",
        escape(&package.license),
        escape(&package.maintainer)
    );
    if !package.homepage.is_empty() {
        // Only http(s) homepages become links; anything else (javascript:,
        // data:, …) renders as escaped text. The homepage is stored content
        // that cannot be trusted to be a safe scheme.
        let cell = if is_safe_href(&package.homepage) {
            format!("<a href=\"{h}\">{h}</a>", h = escape(&package.homepage))
        } else {
            escape(&package.homepage)
        };
        let _ = write!(body, "<dt>homepage</dt><dd>{cell}</dd>");
    }
    body.push_str("</dl>\n");

    for version in &package.versions {
        let _ = writeln!(body, "<h2>{}</h2>", escape(&version.version));
        let rows: Vec<Vec<String>> = version
            .platforms
            .iter()
            .map(|p| {
                vec![
                    escape(&p.platform),
                    escape(&p.store_path),
                    escape(&human_size(p.nar_size)),
                    escape(&human_size(p.closure_size)),
                ]
            })
            .collect();
        body.push_str(&table(
            &["platform", "store path", "nar size", "closure size"],
            &rows,
        ));
    }

    page(
        chrome,
        &format!("{} — {slug}", package.name),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/-/"), slug.to_string()),
            (String::new(), package.name.clone()),
        ],
        &body,
        &index,
    )
}

/// Expand a [`pb::Channel`]'s sparse partition list into a dense 256-bucket map.
///
/// The wire shape carries only assigned buckets (`Partition { bucket, release
/// }`); the grid renders all 256, so unassigned buckets become `None`.
fn dense_partitions(channel: &pb::Channel) -> Vec<Option<&str>> {
    let mut buckets: Vec<Option<&str>> = vec![None; 256];
    for partition in &channel.partitions {
        if let Some(slot) = buckets.get_mut(partition.bucket as usize) {
            *slot = Some(partition.release.as_str());
        }
    }
    buckets
}

/// One channel's 256-partition grid page.
#[must_use]
pub fn channel_page(chrome: &PageChrome, registry: &pb::Registry, channel: &pb::Channel) -> String {
    let slug = &registry.slug;
    let index = IndexInfo::from_registry(registry);
    let mut body = format!(
        "<h1>channel {}</h1>\n<p>frontier: {}</p>\n",
        escape(&channel.name),
        escape(if channel.frontier.is_empty() {
            "—"
        } else {
            &channel.frontier
        })
    );
    body.push_str("<pre class=\"grid\">\n");
    for (bucket, slot) in dense_partitions(channel).iter().enumerate() {
        let cell = slot.unwrap_or("·");
        let _ = writeln!(body, "{bucket:02x} {}", escape(cell));
    }
    body.push_str("</pre>\n");
    page(
        chrome,
        &format!("channel {} — {slug}", channel.name),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/-/"), slug.to_string()),
            (String::new(), format!("channel {}", channel.name)),
        ],
        &body,
        &index,
    )
}

/// The channels index page: every channel with its frontier and assignment.
#[must_use]
pub fn channels_index(
    chrome: &PageChrome,
    registry: &pb::Registry,
    channels: &[pb::Channel],
) -> String {
    let slug = &registry.slug;
    let index = IndexInfo::from_registry(registry);
    let body = if channels.is_empty() {
        "<p>No channels indexed.</p>\n".to_string()
    } else {
        let rows: Vec<Vec<String>> = channels
            .iter()
            .map(|c| {
                vec![
                    format!(
                        "<a href=\"/{slug}/-/channels/{name}\">{name}</a>",
                        slug = escape(slug),
                        name = escape(&c.name)
                    ),
                    escape(if c.frontier.is_empty() {
                        "—"
                    } else {
                        &c.frontier
                    }),
                    format!("{}/256", c.partitions.len()),
                ]
            })
            .collect();
        table(&["channel", "frontier", "partitions"], &rows)
    };
    page(
        chrome,
        &format!("channels — {slug}"),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/-/"), slug.to_string()),
            (String::new(), "channels".into()),
        ],
        &body,
        &index,
    )
}

/// The releases page: signed tags with signature/pack status.
#[must_use]
pub fn releases_page(
    chrome: &PageChrome,
    registry: &pb::Registry,
    releases: &[pb::Release],
) -> String {
    let slug = &registry.slug;
    let index = IndexInfo::from_registry(registry);
    let body = if releases.is_empty() {
        "<p>No releases indexed.</p>\n".to_string()
    } else {
        let rows: Vec<Vec<String>> = releases
            .iter()
            .map(|r| {
                vec![
                    escape(&r.semver),
                    hash_value(&r.commit_oid),
                    escape(if r.signer.is_empty() {
                        "—"
                    } else {
                        &r.signer
                    }),
                ]
            })
            .collect();
        table(&["version", "commit", "signer"], &rows)
    };
    page(
        chrome,
        &format!("releases — {slug}"),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/-/"), slug.to_string()),
            (String::new(), "releases".into()),
        ],
        &body,
        &index,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_registry() -> pb::Registry {
        pb::Registry {
            slug: "demo".into(),
            name: "Demo".into(),
            description: "A demo registry".into(),
            index_state: "fresh".into(),
            index_error: String::new(),
            last_indexed_commit: "ab".repeat(32),
            indexed_at: 200,
            trust_keys: vec![],
            roster: vec![pb::RosterKey {
                id: "k1".into(),
                key: "AAAA".into(),
                status: "active".into(),
            }],
            crawl_policy: "allow_all".into(),
            llms_txt_body: String::new(),
            ..Default::default()
        }
    }

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
        // sha256("") = 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU (no pad).
        assert_eq!(
            key_fingerprint(""),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    #[test]
    fn brand_and_session_chrome_render() {
        // Anonymous, no brand: neutral title, no brand element, log-in link.
        let anon = PageChrome::anonymous();
        assert_eq!(anon.brand_span(), "");
        assert_eq!(anon.page_title("log in"), "log in — AOS Registry Hub");
        assert!(anon.session_span().contains("log in"));
        // Branded + signed in: home-linked brand, branded title, email + logout.
        let signed = PageChrome {
            session_email: Some("a@b.example".into()),
            brand: "Acme <Co>".into(),
        };
        assert_eq!(
            signed.brand_span(),
            "<a class=\"brand\" href=\"/\">Acme &lt;Co&gt;</a>"
        );
        assert_eq!(signed.page_title("log in"), "log in — Acme &lt;Co&gt;");
        assert!(signed.session_span().contains("a@b.example"));
        assert!(signed
            .session_span()
            .contains("<a href=\"/-/instance\">settings</a>"));
        assert!(signed.session_span().contains("log out"));
    }

    #[test]
    fn hash_value_is_compact_and_retains_the_complete_value() {
        let hash = "sha256:0123456789abcdef";
        let html = hash_value(hash);
        assert!(html.contains(">sha256:01234…</code>"));
        assert!(html.contains(&format!("data-hash-value=\"{hash}\"")));
        assert!(html.contains(&format!("data-copy-value=\"{hash}\"")));
        assert!(html.contains("class=\"hash-copy-icon\""));
        assert!(!html.contains(">copy</button>"));
    }

    #[test]
    fn trust_key_value_emphasizes_the_distinguishing_tail() {
        let key = "cache.andyl.org-1:Ed25519:ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let html = trust_key_value(key);
        assert!(html.contains("…OPQRSTUVWXYZ</code>"));
        assert!(html.contains(&format!("data-copy-value=\"{key}\"")));
        assert!(html.contains("aria-label=\"Copy full trust key\""));
    }

    #[test]
    fn tables_render_inside_bounded_scroll_regions() {
        let html = table(&["very long heading"], &[vec!["value".to_string()]]);
        assert!(html.starts_with("<div class=\"table-scroll\""));
        assert!(html.contains("<th scope=\"col\">very long heading</th>"));
        assert!(html.ends_with("</table></div>\n"));
    }

    #[test]
    fn registry_home_renders_anchors_channels_packages() {
        let channels = vec![pb::Channel {
            name: "stable".into(),
            frontier: "8.0.0".into(),
            partitions: vec![pb::Partition {
                bucket: 0,
                release: "8.0.0".into(),
            }],
        }];
        let packages = vec![pb::PackageSummary {
            name: "curl".into(),
            description: "A client".into(),
            license: "MIT".into(),
            latest_version: "8.0.0".into(),
        }];
        let html = registry_home(
            &PageChrome::anonymous(),
            &demo_registry(),
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
        let package = pb::Package {
            name: "curl".into(),
            description: "A client".into(),
            homepage: "https://curl.se".into(),
            license: "MIT".into(),
            maintainer: "alice".into(),
            sysroot: false,
            versions: vec![pb::Version {
                version: "8.0.0".into(),
                previous: String::new(),
                platforms: vec![pb::Platform {
                    platform: "x86_64-linux".into(),
                    store_path: "/nix/store/x-curl".into(),
                    nar_hash: "sha256:ab".into(),
                    nar_size: 3 * 1024 * 1024,
                    closure_size: 10 * 1024 * 1024,
                }],
            }],
        };
        let html = package_page(&PageChrome::anonymous(), &demo_registry(), &package);
        assert!(html.contains("x86_64-linux"));
        assert!(html.contains("/nix/store/x-curl"));
        assert!(html.contains("3.0 MiB"));
        assert!(html.contains("https://curl.se"));
    }

    #[test]
    fn package_homepage_requires_http_scheme() {
        let package = pb::Package {
            name: "evil".into(),
            description: "x".into(),
            homepage: "javascript:alert(1)".into(),
            license: "MIT".into(),
            maintainer: "alice".into(),
            sysroot: false,
            versions: vec![],
        };
        let html = package_page(&PageChrome::anonymous(), &demo_registry(), &package);
        assert!(
            !html.contains("href=\"javascript:"),
            "javascript: homepage must not become a link: {html}"
        );
        assert!(html.contains("javascript:alert(1)"), "still shown as text");
    }

    #[test]
    fn channel_page_renders_256_buckets() {
        let channel = pb::Channel {
            name: "stable".into(),
            frontier: "8.0.0".into(),
            partitions: vec![
                pb::Partition {
                    bucket: 0,
                    release: "8.0.0".into(),
                },
                pb::Partition {
                    bucket: 255,
                    release: "7.9.0".into(),
                },
            ],
        };
        let html = channel_page(&PageChrome::anonymous(), &demo_registry(), &channel);
        assert!(html.contains("00 8.0.0"));
        assert!(html.contains("ff 7.9.0"));
        assert!(html.contains("01 ·"), "unmapped bucket placeholder");
    }

    #[test]
    fn releases_page_renders_signer() {
        let releases = vec![pb::Release {
            semver: "8.0.0".into(),
            tag_oid: "tag1".into(),
            commit_oid: "commit1deadbeef".into(),
            signer: "alice".into(),
            tagged_at: 300,
        }];
        let html = releases_page(&PageChrome::anonymous(), &demo_registry(), &releases);
        assert!(html.contains("8.0.0"));
        assert!(html.contains("alice"));
    }

    #[test]
    fn home_page_lists_registries() {
        let html = home_page(&PageChrome::anonymous(), &[demo_registry()]);
        assert!(html.contains("/demo/-/"));
        assert!(!html.contains("cdn.example"));
    }

    #[test]
    fn non_ascii_commit_oid_does_not_panic() {
        let releases = vec![pb::Release {
            semver: "1.0.0".into(),
            tag_oid: "t".into(),
            commit_oid: "café—deadbeef—oid".into(),
            signer: String::new(),
            tagged_at: 0,
        }];
        let html = releases_page(&PageChrome::anonymous(), &demo_registry(), &releases);
        assert!(html.contains("1.0.0"));
    }
}
