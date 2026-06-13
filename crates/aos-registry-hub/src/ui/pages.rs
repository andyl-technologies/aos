//! Page composition: data in, complete HTML documents out.
//!
//! Every page here renders from index data alone (no live surface reads),
//! works without JavaScript — search, the channel-bucket calculator, and
//! pagination are plain GET forms and links — and carries the footer
//! state line. URL space (RFC-0004 "Sitemap"): the registry home lives at
//! `/{slug}/`, all other human pages (packages, channels, releases,
//! health) under `/{slug}/-/…` — the reserved namespace that can never
//! collide with machine paths.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Instant;

use crate::db::{
    ChannelSummary, IndexStatus, PackageDetail, PackageRow, RegistryRecord, ReleaseRow,
    ValidationRunRow,
};
use crate::ui::render::{ago, escape, human_size, key_fingerprint, page, table, StateLine};

/// Glyph palette for the partition grid: one glyph per release, assigned
/// in frontier-first order, so the encoding survives without color.
const GRID_GLYPHS: [char; 6] = ['■', '▣', '▥', '▤', '▧', '▢'];

/// Rows per page on the HTML package index.
pub const PACKAGES_PER_PAGE: usize = 100;

fn state_line(status: Option<&IndexStatus>, started: Instant) -> StateLine {
    match status {
        Some(status) => StateLine {
            surface_commit: status.last_indexed_commit.clone(),
            indexed_at: status.indexed_at,
            state: Some(status.state.clone()),
            started: Some(started),
        },
        None => StateLine::timed(started),
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

/// Percent-encode a string for use in a query component.
fn urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// Split a `name:Ed25519:<base64>` trust anchor into `(name, base64)`.
///
/// Tolerates other shapes by returning the whole string for both parts.
fn key_name_and_blob(key: &str) -> (&str, &str) {
    let name = key.split(':').next().unwrap_or(key);
    let blob = key.rsplit(':').next().unwrap_or(key);
    (name, blob)
}

/// The store hash of a store path: the basename text before the first `-`.
fn store_hash(store_path: &str) -> Option<&str> {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    basename.split_once('-').map(|(hash, _)| hash)
}

/// Parse a partition bucket from user input: decimal first, then hex
/// (with or without a `0x` prefix), 0..=255.
fn parse_bucket(text: &str) -> Option<u8> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).ok();
    }
    text.parse::<u8>()
        .ok()
        .or_else(|| u8::from_str_radix(text, 16).ok())
}

/// A narinfo permalink for one store hash on this registry's facade.
fn narinfo_link(slug: &str, hash: &str) -> String {
    format!(
        "<a href=\"/{}/{}.narinfo\"><code>{}</code></a>",
        escape(slug),
        escape(hash),
        escape(hash),
    )
}

/// The status / coverage / checked / probed cells for one cache row.
fn validation_cells(run: Option<&ValidationRunRow>) -> [String; 4] {
    let Some(run) = run else {
        return [
            "<span class=\"dim\">not yet validated</span>".to_string(),
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
        ];
    };
    let status = if !run.reachable {
        "<span class=\"bad\">✗ unreachable</span>".to_string()
    } else if run.missing == 0 {
        "<span class=\"ok\">✓ ok</span>".to_string()
    } else {
        format!("<span class=\"warn\">⚠ {} missing</span>", run.missing)
    };
    let coverage = if run.checked > 0 {
        format!(
            "{}%",
            run.checked.saturating_sub(run.missing) * 100 / run.checked
        )
    } else {
        "—".to_string()
    };
    [
        status,
        coverage,
        run.checked.to_string(),
        ago(run.finished_at),
    ]
}

/// The instance home: every registered registry and its index state, with
/// an optional `?q=` substring filter over slugs, names, and descriptions.
pub fn instance_home(
    rows: &[(RegistryRecord, Option<IndexStatus>)],
    query: Option<&str>,
    started: Instant,
) -> String {
    let needle = query.map(str::to_lowercase);
    let matches: Vec<&(RegistryRecord, Option<IndexStatus>)> = rows
        .iter()
        .filter(|(reg, status)| match &needle {
            None => true,
            Some(needle) => {
                let name = status
                    .as_ref()
                    .and_then(|s| s.name.as_deref())
                    .unwrap_or("");
                let desc = status
                    .as_ref()
                    .and_then(|s| s.description.as_deref())
                    .unwrap_or("");
                reg.slug.to_lowercase().contains(needle)
                    || name.to_lowercase().contains(needle)
                    || desc.to_lowercase().contains(needle)
            }
        })
        .collect();

    let body_rows: Vec<Vec<String>> = matches
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
                format!("<span class=\"{class}\">{}</span>", escape(state)),
            ]
        })
        .collect();

    let mut body = String::from("<h1>Registries</h1>\n");
    let _ = writeln!(
        body,
        "<form method=\"get\"><input name=\"q\" value=\"{}\" placeholder=\"search registries\"> \
         <button>search</button></form>",
        escape(query.unwrap_or("")),
    );
    if let Some(query) = query {
        let _ = writeln!(
            body,
            "<p class=\"dim\">{} of {} registries match \"{}\"</p>",
            matches.len(),
            rows.len(),
            escape(query),
        );
    }
    if rows.is_empty() {
        body.push_str(
            "<p class=\"dim\">No registries registered. Add one with \
             <code>aos-registry-hub registry add &lt;slug&gt; &lt;url&gt;</code>.</p>",
        );
    } else if body_rows.is_empty() {
        body.push_str("<p class=\"dim\">No registries match.</p>");
    } else {
        body.push_str(&table(&["slug", "name", "source", "index"], &body_rows));
    }
    page(
        "registries",
        &[(String::new(), "registries".into())],
        &body,
        &StateLine::timed(started),
    )
}

/// The registry home: trust anchors with fingerprints, channels, cache
/// validation health, package count, and the three setup snippets.
#[allow(clippy::too_many_arguments)]
pub fn registry_home(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
    packages: &[PackageRow],
    caches: &[(String, u32)],
    roster: &[(String, String, String)],
    validations: &[ValidationRunRow],
    external_url: &str,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = String::new();

    let display_name = status
        .and_then(|s| s.name.as_deref())
        .unwrap_or(slug.as_str());
    let _ = write!(body, "<h1>Registry {}</h1>", escape(display_name));
    if let Some(at) = status.and_then(|s| s.indexed_at) {
        let _ = write!(body, "\n<p class=\"dim\">indexed {}</p>", ago(at));
    }
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
                let (name, blob) = key_name_and_blob(key);
                vec![
                    format!("pinned {}", escape(name)),
                    format!("<code>{}</code>", escape(&key_fingerprint(blob))),
                    format!("<code>{}</code>", escape(key)),
                ]
            })
            .chain(roster.iter().map(|(id, key, status)| {
                let (fingerprint, label) = if key.is_empty() {
                    ("—".to_string(), "—".to_string())
                } else {
                    let (_, blob) = key_name_and_blob(key);
                    (
                        format!("<code>{}</code>", escape(&key_fingerprint(blob))),
                        format!("<code>{}</code>", escape(key)),
                    )
                };
                vec![
                    format!("roster {} ({})", escape(id), escape(status)),
                    fingerprint,
                    label,
                ]
            }))
            .collect();
        body.push_str(&table(&["anchor", "fingerprint", "key"], &rows));
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
        let runs_by_url: BTreeMap<&str, &ValidationRunRow> = validations
            .iter()
            .map(|run| (run.cache_url.as_str(), run))
            .collect();
        let rows: Vec<Vec<String>> = caches
            .iter()
            .map(|(url, priority)| {
                let [status, coverage, checked, probed] =
                    validation_cells(runs_by_url.get(url.as_str()).copied());
                vec![
                    format!("<code>{}</code>", escape(url)),
                    priority.to_string(),
                    status,
                    coverage,
                    checked,
                    probed,
                ]
            })
            .collect();
        body.push_str(&table(
            &["url", "priority", "status", "coverage", "checked", "probed"],
            &rows,
        ));
    }
    let _ = writeln!(
        body,
        "<p><a href=\"/{}/-/health\">health →</a></p>",
        escape(slug),
    );

    body.push_str("<h2>Setup</h2>\n");
    let url = external_url.trim_end_matches('/');
    let _ = write!(
        body,
        "<p class=\"dim\">apm:</p>\n<pre>apr add {url}/ --name {slug}</pre>\n",
        url = escape(url),
        slug = escape(slug),
    );
    let mut stanza =
        format!("aos.apm.registries.{slug} = {{\n  url = \"{url}/\";\n  trustKeys = [\n");
    for key in &registry.trust_keys {
        let _ = writeln!(stanza, "    \"{key}\"");
    }
    stanza.push_str("  ];\n};");
    let _ = write!(
        body,
        "<p class=\"dim\">AOS module:</p>\n<pre>{}</pre>\n",
        escape(&stanza),
    );
    let mut plain = format!("substituters = {url}/");
    if !registry.trust_keys.is_empty() {
        let _ = write!(
            plain,
            "\ntrusted-public-keys = {}",
            registry.trust_keys.join(" ")
        );
    }
    let _ = write!(
        body,
        "<p class=\"dim\">plain Nix:</p>\n<pre>{}</pre>\n",
        escape(&plain),
    );

    page(
        display_name,
        &registry_crumbs(slug, &[]),
        &body,
        &state_line(status, started),
    )
}

/// The package index page: one pre-filtered, pre-sliced page of rows.
///
/// `rows` is the current page after the handler applies the `?q=` filter
/// and `?page=` slice; `total_matches` and `total_all` carry the counts
/// for the result line, and pagination links render only when the match
/// set spans multiple pages.
#[allow(clippy::too_many_arguments)]
pub fn package_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    rows: &[PackageRow],
    query: Option<&str>,
    page_number: usize,
    total_matches: usize,
    total_all: usize,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let body_rows: Vec<Vec<String>> = rows
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

    let mut body = format!("<h1>Packages ({total_all})</h1>\n");
    let _ = writeln!(
        body,
        "<form method=\"get\"><input name=\"q\" value=\"{}\" placeholder=\"search packages\"> \
         <button>search</button></form>",
        escape(query.unwrap_or("")),
    );
    if let Some(query) = query {
        let _ = writeln!(
            body,
            "<p class=\"dim\">{total_matches} of {total_all} packages match \"{}\"</p>",
            escape(query),
        );
    }
    if body_rows.is_empty() {
        body.push_str("<p class=\"dim\">No packages.</p>\n");
    } else {
        body.push_str(&table(
            &["name", "latest", "license", "description"],
            &body_rows,
        ));
    }

    let pages = total_matches.div_ceil(PACKAGES_PER_PAGE).max(1);
    if pages > 1 {
        let query_suffix = query
            .map(|q| format!("&q={}", urlencode(q)))
            .unwrap_or_default();
        body.push_str("<p class=\"pager\">");
        if page_number > 1 {
            let _ = write!(
                body,
                "<a href=\"/{}/-/packages?page={}{query_suffix}\">← prev</a> ",
                escape(slug),
                page_number - 1,
            );
        }
        let _ = write!(body, "page {page_number} of {pages}");
        if page_number < pages {
            let _ = write!(
                body,
                " <a href=\"/{}/-/packages?page={}{query_suffix}\">next →</a>",
                escape(slug),
                page_number + 1,
            );
        }
        body.push_str("</p>\n");
    }

    page(
        &format!("{slug} packages"),
        &registry_crumbs(slug, &[(String::new(), "packages".into())]),
        &body,
        &state_line(status, started),
    )
}

/// One package's detail page.
pub fn package_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    detail: &PackageDetail,
    started: Instant,
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
        // Only http(s) homepages become links; anything else (javascript:,
        // data:, …) renders as escaped text.
        let cell = if homepage.starts_with("http://") || homepage.starts_with("https://") {
            format!("<a href=\"{0}\">{0}</a>", escape(homepage))
        } else {
            escape(homepage)
        };
        meta_rows.push(vec!["homepage".to_string(), cell]);
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
                let narinfo = match store_hash(&p.store_path) {
                    Some(hash) => narinfo_link(slug, hash),
                    None => "—".to_string(),
                };
                vec![
                    escape(&p.platform),
                    format!("<code>{}</code>", escape(&p.store_path)),
                    human_size(p.nar_size),
                    human_size(p.closure_size),
                    format!("<code>{}</code>", escape(&p.nar_hash)),
                    narinfo,
                ]
            })
            .collect();
        body.push_str(&table(
            &[
                "platform",
                "store path",
                "nar",
                "closure",
                "nar hash",
                "narinfo",
            ],
            &rows,
        ));

        for platform in &version.platforms {
            if platform.refs.is_empty() {
                continue;
            }
            let _ = write!(
                body,
                "<p class=\"dim\">references ({}):</p>\n<p>",
                escape(&platform.platform),
            );
            for (i, reference) in platform.refs.iter().enumerate() {
                if i > 0 {
                    body.push(' ');
                }
                body.push_str(&narinfo_link(slug, reference));
            }
            body.push_str("</p>\n");
        }

        let image_rows: Vec<Vec<String>> = version
            .platforms
            .iter()
            .flat_map(|p| {
                p.images.iter().map(|image| {
                    vec![
                        escape(&p.platform),
                        escape(&image.format),
                        format!("<code>{}</code>", escape(&image.store_path)),
                        human_size(image.nar_size),
                    ]
                })
            })
            .collect();
        if !image_rows.is_empty() {
            body.push_str("<p class=\"dim\">sysroot images:</p>\n");
            body.push_str(&table(
                &["platform", "format", "store path", "size"],
                &image_rows,
            ));
        }
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
        &state_line(status, started),
    )
}

/// The channel page with the 16×16 partition grid, the anti-rollback
/// floor, and the no-JS `?bucket=` calculator.
pub fn channel_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channel: &ChannelSummary,
    floor: Option<&str>,
    bucket_query: Option<&str>,
    started: Instant,
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
    let class_for: BTreeMap<&str, usize> = release_order
        .iter()
        .enumerate()
        .map(|(i, release)| (release.as_str(), i.min(GRID_GLYPHS.len() - 1)))
        .collect();

    let hit = bucket_query.and_then(parse_bucket);
    let mut grid = String::new();
    for row in 0..16 {
        for col in 0..16 {
            let bucket = row * 16 + col;
            let cell = match channel.partitions[bucket].as_deref() {
                Some(release) => {
                    let i = class_for
                        .get(release)
                        .copied()
                        .unwrap_or(GRID_GLYPHS.len() - 1);
                    format!("<span class=\"r{i}\">{}</span>", GRID_GLYPHS[i])
                }
                None => "<span class=\"dim\">·</span>".to_string(),
            };
            if hit == Some(bucket as u8) {
                let _ = write!(grid, "<strong class=\"hit\">{cell}</strong>");
            } else {
                grid.push_str(&cell);
            }
        }
        grid.push('\n');
    }

    let mut body = format!("<h1>Channel {}</h1>\n", escape(&channel.name));
    let _ = writeln!(
        body,
        "<p>frontier <strong>{}</strong> · floor {} · {} of 256 partitions assigned</p>",
        escape(channel.frontier.as_deref().unwrap_or("—")),
        match floor {
            Some(floor) => format!("<strong>{}</strong>", escape(floor)),
            None => "<span class=\"dim\">—</span>".to_string(),
        },
        channel.partitions.iter().flatten().count(),
    );

    let _ = writeln!(
        body,
        "<form method=\"get\"><label>which version will my host get? bucket \
         <input name=\"bucket\" value=\"{}\" size=\"6\"></label> <button>resolve</button></form>",
        escape(bucket_query.unwrap_or("")),
    );
    if let Some(raw) = bucket_query {
        match parse_bucket(raw) {
            Some(bucket) => {
                let target = match channel.partitions[bucket as usize].as_deref() {
                    Some(release) => format!("release <strong>{}</strong>", escape(release)),
                    None => "<span class=\"dim\">unassigned</span>".to_string(),
                };
                let _ = writeln!(
                    body,
                    "<p>bucket <strong>0x{bucket:02X}</strong> ({bucket}) → {target}</p>",
                );
            }
            None => {
                let _ = writeln!(
                    body,
                    "<p class=\"bad\">unrecognized bucket \"{}\" (decimal or hex, 0..255)</p>",
                    escape(raw),
                );
            }
        }
    }

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
            let i = class_for
                .get(release.as_str())
                .copied()
                .unwrap_or(GRID_GLYPHS.len() - 1);
            vec![
                format!("<span class=\"r{i}\">{}</span>", GRID_GLYPHS[i]),
                escape(release),
                format!("{count} partitions ({}%)", count * 100 / 256),
            ]
        })
        .collect();
    body.push_str(&table(&["glyph", "release", "coverage"], &legend_rows));
    body.push_str(
        "<p class=\"dim\">Your bucket is the low byte of sha256(registry‑name \\0 salt) — see \
         <code>[registry.state] bucket</code> in your registries.d entry, or resolve it with the \
         form above (row = bucket / 16, column = bucket % 16).</p>\n",
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
        &state_line(status, started),
    )
}

/// The channels index page.
pub fn channels_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
    started: Instant,
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
        &state_line(status, started),
    )
}

/// The releases page: every verified signed tag, newest first by semver.
pub fn releases_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    releases: &[ReleaseRow],
    started: Instant,
) -> String {
    let slug = &registry.slug;

    // Sort newest-first by parsed semver (ties by tag time); rows whose
    // version does not parse sort last, ordered lexically.
    let mut sorted: Vec<&ReleaseRow> = releases.iter().collect();
    sorted.sort_by(|a, b| {
        match (
            semver::Version::parse(&a.semver),
            semver::Version::parse(&b.semver),
        ) {
            (Ok(va), Ok(vb)) => vb.cmp(&va).then_with(|| b.tagged_at.cmp(&a.tagged_at)),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => b.semver.cmp(&a.semver),
        }
    });

    let rows: Vec<Vec<String>> = sorted
        .iter()
        .map(|release| {
            vec![
                escape(&release.semver),
                format!(
                    "<code>{}</code>",
                    escape(&release.commit_oid[..release.commit_oid.len().min(12)])
                ),
                match &release.signer {
                    Some(signer) => format!(
                        "<span class=\"ok\">✓ signed</span> <span class=\"dim\">{}…</span>",
                        escape(&signer[..signer.len().min(20)]),
                    ),
                    None => "<span class=\"dim\">unverified</span>".to_string(),
                },
                if release.pack_present {
                    "<span class=\"ok\">✓ pack</span>".to_string()
                } else {
                    "<span class=\"dim\">— none</span>".to_string()
                },
                release
                    .tagged_at
                    .map(|t| format!("{} <span class=\"dim\">(unix {t})</span>", ago(t)))
                    .unwrap_or_else(|| "—".to_string()),
            ]
        })
        .collect();
    let mut body = String::from("<h1>Releases</h1>\n");
    body.push_str(&table(
        &["release", "commit", "signature", "pack", "tagged"],
        &rows,
    ));
    page(
        &format!("{slug} releases"),
        &registry_crumbs(slug, &[(String::new(), "releases".into())]),
        &body,
        &state_line(status, started),
    )
}

/// The health page: the cache × coverage validation matrix plus the
/// missing-hash drill-down for each cache with gaps.
pub fn health_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    runs: &[(ValidationRunRow, Vec<String>)],
    started: Instant,
) -> String {
    /// Missing hashes shown per cache before collapsing to "and N more".
    const MISSING_DISPLAY_CAP: usize = 100;

    let slug = &registry.slug;
    let mut body = String::from("<h1>Health</h1>\n");
    if runs.is_empty() {
        body.push_str("<p class=\"dim\">No validation runs recorded yet.</p>\n");
    } else {
        body.push_str("<h2>Cache validation</h2>\n");
        let rows: Vec<Vec<String>> = runs
            .iter()
            .map(|(run, _)| {
                let [status, coverage, checked, probed] = validation_cells(Some(run));
                vec![
                    format!("<code>{}</code>", escape(&run.cache_url)),
                    escape(&run.depth),
                    checked,
                    run.missing.to_string(),
                    coverage,
                    status,
                    probed,
                ]
            })
            .collect();
        body.push_str(&table(
            &[
                "cache", "depth", "checked", "missing", "coverage", "status", "finished",
            ],
            &rows,
        ));

        for (run, missing) in runs {
            if missing.is_empty() {
                continue;
            }
            let _ = write!(
                body,
                "<h2>Missing from {}</h2>\n<pre>",
                escape(&run.cache_url),
            );
            for hash in missing.iter().take(MISSING_DISPLAY_CAP) {
                let _ = writeln!(body, "{}", escape(hash));
            }
            if missing.len() > MISSING_DISPLAY_CAP {
                let _ = writeln!(body, "… and {} more", missing.len() - MISSING_DISPLAY_CAP);
            }
            body.push_str("</pre>\n");
        }
    }

    page(
        &format!("{slug} health"),
        &registry_crumbs(slug, &[(String::new(), "health".into())]),
        &body,
        &state_line(status, started),
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
            org_id: None,
            project_path: String::new(),
            visibility: "public".into(),
            storage_binding_id: None,
            prefix: String::new(),
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
        let html = channel_page(&registry(), None, &channel, None, None, Instant::now());
        let grid = html
            .split("partition-grid\">")
            .nth(1)
            .unwrap()
            .split("</pre>")
            .next()
            .unwrap();
        assert_eq!(grid.lines().count(), 16);
        assert!(grid.lines().all(|l| l.matches("</span>").count() == 16));
        // Frontier glyph appears exactly 64 times, in the frontier class.
        assert_eq!(grid.matches('■').count(), 64);
        assert_eq!(grid.matches("<span class=\"r0\">■</span>").count(), 64);
        assert!(html.contains("frontier <strong>1.2.0</strong>"));
    }

    #[test]
    fn channel_calculator_resolves_hex_and_decimal_buckets() {
        let channel = ChannelSummary {
            name: "stable".into(),
            frontier: Some("1.2.0".into()),
            partitions: vec![Some("1.2.0".to_string()); 256],
        };
        let html = channel_page(
            &registry(),
            None,
            &channel,
            Some("1.1.0"),
            Some("0a"),
            Instant::now(),
        );
        assert!(html.contains("bucket <strong>0x0A</strong> (10)"), "{html}");
        assert!(html.contains("release <strong>1.2.0</strong>"));
        assert!(html.contains("<strong class=\"hit\">"));
        assert!(html.contains("floor <strong>1.1.0</strong>"));

        assert_eq!(parse_bucket("10"), Some(10), "decimal wins when both parse");
        assert_eq!(parse_bucket("0x10"), Some(16));
        assert_eq!(parse_bucket("ff"), Some(255));
        assert_eq!(parse_bucket("zz"), None);
        assert_eq!(parse_bucket("256"), None);

        let html = channel_page(
            &registry(),
            None,
            &channel,
            None,
            Some("zz"),
            Instant::now(),
        );
        assert!(html.contains("unrecognized bucket"));
        assert!(!html.contains("<strong class=\"hit\">"));
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
            &[],
            "http://127.0.0.1:8420/demo",
            Instant::now(),
        );
        assert!(html.contains("&lt;k&gt;"));
        assert!(html.contains("apr add http://127.0.0.1:8420/demo/"));
        assert!(!html.contains("<k>"));
        // Fingerprints, the module stanza, and the plain-Nix snippet.
        assert!(html.contains("SHA256:"));
        assert!(html.contains("aos.apm.registries.demo"));
        assert!(html.contains("trustKeys"));
        assert!(html.contains("substituters = http://127.0.0.1:8420/demo/"));
        assert!(html.contains("trusted-public-keys = demo:Ed25519:AAAA"));
        // Unvalidated caches say so; the health page is linked.
        assert!(html.contains("not yet validated"));
        assert!(html.contains("/demo/-/health"));
    }

    #[test]
    fn package_homepage_requires_http_scheme() {
        let mut detail = PackageDetail {
            name: "curl".into(),
            description: "URL transfers".into(),
            homepage: Some("javascript:alert(1)".into()),
            license: "MIT".into(),
            maintainer: "aos".into(),
            sysroot: false,
            versions: Vec::new(),
        };
        let html = package_page(&registry(), None, &detail, Instant::now());
        assert!(
            !html.contains("href=\"javascript:"),
            "javascript: homepage must not become a link: {html}"
        );
        assert!(html.contains("javascript:alert(1)"), "still shown as text");

        detail.homepage = Some("https://curl.se".into());
        let html = package_page(&registry(), None, &detail, Instant::now());
        assert!(html.contains("<a href=\"https://curl.se\">"));
    }

    #[test]
    fn releases_sort_by_semver_with_pack_column() {
        let release = |semver: &str, tagged_at: i64, pack: bool| ReleaseRow {
            semver: semver.into(),
            tag_oid: "t".repeat(64),
            commit_oid: "c".repeat(64),
            signer: None,
            tagged_at: Some(tagged_at),
            pack_present: pack,
        };
        // String order would put 1.10.0 before 1.9.0; semver order must not.
        let releases = vec![
            release("1.9.0", 300, false),
            release("1.10.0", 100, true),
            release("0.9.0", 200, false),
        ];
        let html = releases_page(&registry(), None, &releases, Instant::now());
        let first = html.find("1.10.0").unwrap();
        let second = html.find("1.9.0").unwrap();
        let third = html.find("0.9.0").unwrap();
        assert!(first < second && second < third, "{html}");
        assert!(html.contains("✓ pack"));
        assert!(html.contains("— none"));
        assert!(html.contains("(unix 100)"));
    }

    #[test]
    fn short_commit_oids_do_not_panic() {
        let releases = vec![ReleaseRow {
            semver: "1.0.0".into(),
            tag_oid: "t".into(),
            commit_oid: "abc".into(), // shorter than the 12-char display slice
            signer: None,
            tagged_at: None,
            pack_present: false,
        }];
        let html = releases_page(&registry(), None, &releases, Instant::now());
        assert!(html.contains("<code>abc</code>"));
    }

    #[test]
    fn instance_home_filters_and_escapes_state() {
        let rows = vec![(
            registry(),
            Some(IndexStatus {
                state: "<bad&state>".into(),
                error: None,
                last_indexed_commit: None,
                name: Some("Demo".into()),
                description: Some("Fixture registry".into()),
                indexed_at: None,
            }),
        )];
        let html = instance_home(&rows, None, Instant::now());
        assert!(html.contains("&lt;bad&amp;state&gt;"));
        assert!(!html.contains("<bad&state>"));

        let html = instance_home(&rows, Some("fixture"), Instant::now());
        assert!(html.contains("1 of 1 registries match"));
        let html = instance_home(&rows, Some("zzz"), Instant::now());
        assert!(html.contains("0 of 1 registries match"));
        assert!(html.contains("No registries match."));
    }

    #[test]
    fn package_index_paginates_and_counts() {
        let rows: Vec<PackageRow> = (0..3)
            .map(|i| PackageRow {
                name: format!("pkg{i}"),
                description: "desc".into(),
                license: "MIT".into(),
                latest_version: None,
            })
            .collect();
        // 250 matches across 3 pages; this is page 2.
        let html = package_index(
            &registry(),
            None,
            &rows,
            Some("pkg"),
            2,
            250,
            300,
            Instant::now(),
        );
        assert!(html.contains("250 of 300 packages match"));
        assert!(html.contains("page 2 of 3"));
        assert!(html.contains("?page=1&q=pkg"));
        assert!(html.contains("?page=3&q=pkg"));

        // A single page renders no pager.
        let html = package_index(&registry(), None, &rows, None, 1, 3, 3, Instant::now());
        assert!(!html.contains("class=\"pager\""));
    }

    #[test]
    fn health_page_caps_missing_drilldown() {
        let run = ValidationRunRow {
            id: 1,
            cache_url: "https://cache.example".into(),
            depth: "presence".into(),
            checked: 200,
            missing: 150,
            reachable: true,
            finished_at: 0,
        };
        let missing: Vec<String> = (0..150).map(|i| format!("hash{i:03}")).collect();
        let html = health_page(&registry(), None, &[(run, missing)], Instant::now());
        assert!(html.contains("Missing from https://cache.example"));
        assert!(html.contains("hash000"));
        assert!(html.contains("hash099"));
        assert!(!html.contains("hash100"), "capped at 100 entries");
        assert!(html.contains("… and 50 more"));
        assert!(html.contains("⚠ 150 missing"));
    }
}
