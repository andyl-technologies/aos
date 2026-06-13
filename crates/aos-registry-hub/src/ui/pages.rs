//! Page composition: data in, complete HTML documents out.
//!
//! Every page here renders from index data alone (no live surface reads),
//! works without JavaScript, and carries the footer state line. URL space
//! (RFC-0004 "Sitemap"): the registry home lives at `/{slug}/`, all other
//! human pages under `/{slug}/-/…` — the reserved namespace that can never
//! collide with machine paths.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::db::{
    ChannelSummary, IndexStatus, PackageDetail, PackageRow, RegistryRecord, ReleaseRow,
};
use crate::ui::render::{escape, human_size, page, table, StateLine};

/// Glyph palette for the partition grid: one glyph per release, assigned
/// in frontier-first order, so the encoding survives without color.
const GRID_GLYPHS: [char; 6] = ['■', '▣', '▥', '▤', '▧', '▢'];

fn state_line(status: Option<&IndexStatus>) -> StateLine {
    match status {
        Some(status) => StateLine {
            surface_commit: status.last_indexed_commit.clone(),
            indexed_at: status.indexed_at,
            state: Some(status.state.clone()),
        },
        None => StateLine::default(),
    }
}

fn registry_crumbs(slug: &str, tail: &[(String, String)]) -> Vec<(String, String)> {
    let mut crumbs = vec![
        ("/".to_string(), "registries".to_string()),
        (format!("/{slug}/"), slug.to_string()),
    ];
    crumbs.extend_from_slice(tail);
    crumbs
}

/// The instance home: every registered registry and its index state.
pub fn instance_home(rows: &[(RegistryRecord, Option<IndexStatus>)]) -> String {
    let body_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|(reg, status)| {
            let (state, class) = match status.as_ref().map(|s| s.state.as_str()) {
                Some("fresh") => ("fresh", "ok"),
                Some("failed") => ("failed", "bad"),
                Some(other) => (other, "warn"),
                None => ("unregistered", "dim"),
            };
            vec![
                format!("<a href=\"/{0}/\">{0}</a>", escape(&reg.slug)),
                escape(
                    status
                        .as_ref()
                        .and_then(|s| s.name.as_deref())
                        .unwrap_or("—"),
                ),
                escape(&reg.source_url),
                format!("<span class=\"{class}\">{state}</span>"),
            ]
        })
        .collect();
    let mut body = String::from("<h1>Registries</h1>\n");
    if body_rows.is_empty() {
        body.push_str(
            "<p class=\"dim\">No registries registered. Add one with \
             <code>aos-registry-hub registry add &lt;slug&gt; &lt;url&gt;</code>.</p>",
        );
    } else {
        body.push_str(&table(&["slug", "name", "source", "index"], &body_rows));
    }
    page(
        "registries",
        &[(String::new(), "registries".into())],
        &body,
        &StateLine::default(),
    )
}

/// The registry home: trust anchors, channels, setup, and package count.
#[allow(clippy::too_many_arguments)]
pub fn registry_home(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
    packages: &[PackageRow],
    caches: &[(String, u32)],
    roster: &[(String, String, String)],
    external_url: &str,
) -> String {
    let slug = &registry.slug;
    let mut body = String::new();

    let display_name = status
        .and_then(|s| s.name.as_deref())
        .unwrap_or(slug.as_str());
    let _ = write!(body, "<h1>Registry {}</h1>", escape(display_name));
    if let Some(desc) = status.and_then(|s| s.description.as_deref()) {
        let _ = write!(body, "<p>{}</p>", escape(desc));
    }
    if let Some(status) = status {
        if status.state == "failed" {
            let _ = write!(
                body,
                "<p class=\"bad\">index failed: {}</p>",
                escape(status.error.as_deref().unwrap_or("unknown error")),
            );
        }
    }

    body.push_str("<h2>Trust</h2>\n");
    if registry.trust_keys.is_empty() && roster.is_empty() {
        body.push_str(
            "<p class=\"warn\">No trust anchors pinned — content is displayed unverified.</p>\n",
        );
    } else {
        let rows: Vec<Vec<String>> = registry
            .trust_keys
            .iter()
            .map(|key| {
                vec![
                    "pinned".to_string(),
                    format!("<code>{}</code>", escape(key)),
                ]
            })
            .chain(roster.iter().map(|(id, key, status)| {
                let label = if key.is_empty() {
                    String::from("—")
                } else {
                    format!("<code>{}</code>", escape(key))
                };
                vec![format!("roster {} ({})", escape(id), escape(status)), label]
            }))
            .collect();
        body.push_str(&table(&["anchor", "key"], &rows));
    }

    body.push_str("<h2>Channels</h2>\n");
    if channels.is_empty() {
        body.push_str("<p class=\"dim\">No channels resolved.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = channels
            .iter()
            .map(|channel| {
                let assigned = channel.partitions.iter().flatten().count();
                let at_frontier = channel
                    .frontier
                    .as_ref()
                    .map(|f| {
                        channel
                            .partitions
                            .iter()
                            .flatten()
                            .filter(|r| *r == f)
                            .count()
                    })
                    .unwrap_or(0);
                let percent = at_frontier * 100 / 256;
                vec![
                    format!(
                        "<a href=\"/{}/-/channels/{}\">{}</a>",
                        escape(slug),
                        escape(&channel.name),
                        escape(&channel.name),
                    ),
                    escape(channel.frontier.as_deref().unwrap_or("—")),
                    format!(
                        "<span class=\"rollout-bar\">{}</span><span class=\"dim\">{}</span> {percent}%",
                        "█".repeat(percent / 8),
                        "░".repeat(12usize.saturating_sub(percent / 8)),
                    ),
                    format!("{assigned}/256 assigned"),
                ]
            })
            .collect();
        body.push_str(&table(
            &["channel", "frontier", "rollout", "partitions"],
            &rows,
        ));
    }

    let _ = write!(
        body,
        "<h2>Packages ({count})</h2>\n<p><a href=\"/{slug}/-/packages\">Browse the package index →</a></p>\n",
        count = packages.len(),
        slug = escape(slug),
    );

    body.push_str("<h2>Caches</h2>\n");
    if caches.is_empty() {
        body.push_str("<p class=\"dim\">No committed caches.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = caches
            .iter()
            .map(|(url, priority)| {
                vec![
                    format!("<code>{}</code>", escape(url)),
                    priority.to_string(),
                ]
            })
            .collect();
        body.push_str(&table(&["url", "priority"], &rows));
    }

    body.push_str("<h2>Setup</h2>\n");
    let _ = write!(
        body,
        "<pre>apr add {url}/ --name {slug}\n# or as a plain Nix substituter:\n# substituters = {url}/</pre>\n",
        url = escape(external_url.trim_end_matches('/')),
        slug = escape(slug),
    );

    page(
        display_name,
        &registry_crumbs(slug, &[]),
        &body,
        &state_line(status),
    )
}

/// The package index page.
pub fn package_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    packages: &[PackageRow],
) -> String {
    let slug = &registry.slug;
    let rows: Vec<Vec<String>> = packages
        .iter()
        .map(|p| {
            vec![
                format!(
                    "<a href=\"/{}/-/packages/{}\">{}</a>",
                    escape(slug),
                    escape(&p.name),
                    escape(&p.name),
                ),
                escape(p.latest_version.as_deref().unwrap_or("—")),
                escape(&p.license),
                escape(&p.description),
            ]
        })
        .collect();
    let mut body = format!("<h1>Packages ({})</h1>\n", packages.len());
    body.push_str(&table(&["name", "latest", "license", "description"], &rows));
    page(
        &format!("{slug} packages"),
        &registry_crumbs(slug, &[(String::new(), "packages".into())]),
        &body,
        &state_line(status),
    )
}

/// One package's detail page.
pub fn package_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    detail: &PackageDetail,
) -> String {
    let slug = &registry.slug;
    let mut body = format!(
        "<h1>{}</h1>\n<p>{}</p>\n",
        escape(&detail.name),
        escape(&detail.description)
    );

    let mut meta_rows = vec![
        vec!["license".to_string(), escape(&detail.license)],
        vec!["maintainer".to_string(), escape(&detail.maintainer)],
    ];
    if let Some(homepage) = &detail.homepage {
        meta_rows.push(vec![
            "homepage".to_string(),
            format!("<a href=\"{0}\">{0}</a>", escape(homepage)),
        ]);
    }
    if detail.sysroot {
        meta_rows.push(vec![
            "sysroot".to_string(),
            "yes (system toplevel)".to_string(),
        ]);
    }
    body.push_str(&table(&["field", "value"], &meta_rows));

    body.push_str("<h2>Versions</h2>\n");
    for version in &detail.versions {
        let _ = write!(body, "<h2>{}", escape(&version.version));
        if let Some(previous) = &version.previous {
            let _ = write!(
                body,
                " <span class=\"dim\">(upgrades {})</span>",
                escape(previous)
            );
        }
        body.push_str("</h2>\n");
        let rows: Vec<Vec<String>> = version
            .platforms
            .iter()
            .map(|p| {
                vec![
                    escape(&p.platform),
                    format!("<code>{}</code>", escape(&p.store_path)),
                    human_size(p.nar_size),
                    human_size(p.closure_size),
                    format!("<code>{}</code>", escape(&p.nar_hash)),
                ]
            })
            .collect();
        body.push_str(&table(
            &["platform", "store path", "nar", "closure", "nar hash"],
            &rows,
        ));
    }

    page(
        &detail.name,
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/packages"), "packages".into()),
                (String::new(), detail.name.clone()),
            ],
        ),
        &body,
        &state_line(status),
    )
}

/// The channel page with the 16×16 partition grid.
pub fn channel_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channel: &ChannelSummary,
) -> String {
    let slug = &registry.slug;

    // Assign glyphs frontier-first so the newest release is always '■'.
    let mut release_order: Vec<String> = Vec::new();
    if let Some(frontier) = &channel.frontier {
        release_order.push(frontier.clone());
    }
    for release in channel.partitions.iter().flatten() {
        if !release_order.contains(release) {
            release_order.push(release.clone());
        }
    }
    let glyph_for: BTreeMap<&str, char> = release_order
        .iter()
        .enumerate()
        .map(|(i, release)| (release.as_str(), GRID_GLYPHS[i.min(GRID_GLYPHS.len() - 1)]))
        .collect();

    let mut grid = String::new();
    for row in 0..16 {
        for col in 0..16 {
            let bucket = row * 16 + col;
            let glyph = channel.partitions[bucket]
                .as_deref()
                .and_then(|release| glyph_for.get(release))
                .copied()
                .unwrap_or('·');
            grid.push(glyph);
        }
        grid.push('\n');
    }

    let mut body = format!("<h1>Channel {}</h1>\n", escape(&channel.name));
    let _ = writeln!(
        body,
        "<p>frontier <strong>{}</strong> · {} of 256 partitions assigned</p>",
        escape(channel.frontier.as_deref().unwrap_or("—")),
        channel.partitions.iter().flatten().count(),
    );
    let _ = writeln!(body, "<pre class=\"partition-grid\">{grid}</pre>");

    let legend_rows: Vec<Vec<String>> = release_order
        .iter()
        .map(|release| {
            let count = channel
                .partitions
                .iter()
                .flatten()
                .filter(|r| *r == release)
                .count();
            vec![
                glyph_for[release.as_str()].to_string(),
                escape(release),
                format!("{count} partitions ({}%)", count * 100 / 256),
            ]
        })
        .collect();
    body.push_str(&table(&["glyph", "release", "coverage"], &legend_rows));
    body.push_str(
        "<p class=\"dim\">Which version will my host get? Your bucket is the low byte of \
         sha256(registry‑name \\0 salt) — see <code>[registry.state] bucket</code> in your \
         registries.d entry, then find it above (row = bucket / 16, column = bucket % 16).</p>\n",
    );

    page(
        &format!("{} channel", channel.name),
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/channels"), "channels".into()),
                (String::new(), channel.name.clone()),
            ],
        ),
        &body,
        &state_line(status),
    )
}

/// The channels index page.
pub fn channels_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
) -> String {
    let slug = &registry.slug;
    let rows: Vec<Vec<String>> = channels
        .iter()
        .map(|channel| {
            vec![
                format!(
                    "<a href=\"/{}/-/channels/{}\">{}</a>",
                    escape(slug),
                    escape(&channel.name),
                    escape(&channel.name),
                ),
                escape(channel.frontier.as_deref().unwrap_or("—")),
                format!("{}/256", channel.partitions.iter().flatten().count()),
            ]
        })
        .collect();
    let mut body = String::from("<h1>Channels</h1>\n");
    body.push_str(&table(&["channel", "frontier", "assigned"], &rows));
    page(
        &format!("{slug} channels"),
        &registry_crumbs(slug, &[(String::new(), "channels".into())]),
        &body,
        &state_line(status),
    )
}

/// The releases page: every verified signed tag.
pub fn releases_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    releases: &[ReleaseRow],
) -> String {
    let slug = &registry.slug;
    let rows: Vec<Vec<String>> = releases
        .iter()
        .map(|release| {
            vec![
                escape(&release.semver),
                format!("<code>{}</code>", escape(&release.commit_oid[..12])),
                match &release.signer {
                    Some(signer) => format!(
                        "<span class=\"ok\">✓ signed</span> <span class=\"dim\">{}…</span>",
                        escape(&signer[..signer.len().min(20)]),
                    ),
                    None => "<span class=\"dim\">unverified</span>".to_string(),
                },
                release
                    .tagged_at
                    .map(|t| format!("unix {t}"))
                    .unwrap_or_else(|| "—".to_string()),
            ]
        })
        .collect();
    let mut body = String::from("<h1>Releases</h1>\n");
    body.push_str(&table(&["release", "commit", "signature", "tagged"], &rows));
    page(
        &format!("{slug} releases"),
        &registry_crumbs(slug, &[(String::new(), "releases".into())]),
        &body,
        &state_line(status),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> RegistryRecord {
        RegistryRecord {
            id: 1,
            slug: "demo".into(),
            source_url: "/srv/demo".into(),
            trust_keys: vec!["demo:Ed25519:AAAA".into()],
            require_signatures: true,
        }
    }

    #[test]
    fn channel_grid_is_16_by_16() {
        let channel = ChannelSummary {
            name: "stable".into(),
            frontier: Some("1.2.0".into()),
            partitions: {
                let mut p = vec![Some("1.1.0".to_string()); 256];
                for slot in p.iter_mut().take(64) {
                    *slot = Some("1.2.0".to_string());
                }
                p
            },
        };
        let html = channel_page(&registry(), None, &channel);
        let grid = html
            .split("partition-grid\">")
            .nth(1)
            .unwrap()
            .split("</pre>")
            .next()
            .unwrap();
        assert_eq!(grid.lines().count(), 16);
        assert!(grid.lines().all(|l| l.chars().count() == 16));
        // Frontier glyph appears exactly 64 times.
        assert_eq!(grid.chars().filter(|c| *c == '■').count(), 64);
        assert!(html.contains("frontier <strong>1.2.0</strong>"));
    }

    #[test]
    fn registry_home_escapes_and_links() {
        let html = registry_home(
            &registry(),
            None,
            &[],
            &[],
            &[("https://cache.example".into(), 40)],
            &[("alice".into(), "demo:Ed25519:<k>".into(), "active".into())],
            "http://127.0.0.1:8420/demo",
        );
        assert!(html.contains("&lt;k&gt;"));
        assert!(html.contains("apr add http://127.0.0.1:8420/demo/"));
        assert!(!html.contains("<k>"));
    }
}
