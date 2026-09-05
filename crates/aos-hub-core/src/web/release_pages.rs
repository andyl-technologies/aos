//! Publication pages and shared, live channel rollout summaries.
//!
//! Release contents and tag prose come from immutable publication identities.
//! Channel participation is explicitly current state; percentages describe the
//! protocol's 256 rollout buckets, never observed host installation rates.

use crate::clock::Instant;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::browse_pages::{registry_crumbs, state_line};
use super::console_render::{ago, page_with_session, urlencode, Pager, SessionIndicator};
use super::release_browse::{
    is_prerelease, release_href, release_order, unavailable_page, verification, ReleaseContext,
};
use super::render::{escape, hash_value, table};
use crate::db::{ChannelSummary, Database, IndexStatus, RegistryRecord};

/// Published content counts, distinguishing incomplete projections from empty sets.
#[derive(Debug, Clone, Default)]
pub struct ReleaseContents {
    /// Number of packages, absent while the catalog is still indexing.
    pub packages: Option<usize>,
    /// Number of exact documentation objects, absent while still indexing.
    pub documentation: Option<usize>,
    /// Number of signed system images.
    pub images: usize,
    /// Number of signed container roots.
    pub containers: usize,
}

/// Loads counts without reading full historical package catalogs.
pub(crate) async fn content_counts(
    db: &Database,
    registry_id: i64,
) -> anyhow::Result<BTreeMap<String, ReleaseContents>> {
    let (catalogs, images, containers) = futures_util::future::join3(
        db.release_browse_counts(registry_id),
        db.list_system_images(registry_id),
        db.list_release_browse_containers(registry_id),
    )
    .await;
    let mut result = BTreeMap::<String, ReleaseContents>::new();
    for (release, packages, documentation) in catalogs? {
        let counts = result.entry(release).or_default();
        counts.packages = Some(packages);
        counts.documentation = Some(documentation);
    }
    for image in images? {
        result.entry(image.release).or_default().images += 1;
    }
    for container in containers? {
        result.entry(container.release).or_default().containers += 1;
    }
    Ok(result)
}

const CONTENT_SECTIONS: [(&str, &str); 4] = [
    ("packages", "Packages"),
    ("docs", "Docs"),
    ("images", "Images"),
    ("containers", "Containers"),
];

fn content_counts_of(counts: &ReleaseContents) -> [Option<usize>; 4] {
    [
        counts.packages,
        counts.documentation,
        Some(counts.images),
        Some(counts.containers),
    ]
}

/// Renders the release's content counts as linked tiles for its detail page.
fn contents_links(slug: &str, version: &str, counts: &ReleaseContents) -> String {
    let mut body = String::from("<div class=\"release-contents\">");
    for ((section, label), count) in CONTENT_SECTIONS.iter().zip(content_counts_of(counts)) {
        let _ = write!(
            body,
            "<a href=\"/{}/-/{}?release={}\"><span>{}</span><strong>{}</strong></a>",
            escape(slug),
            section,
            urlencode(version),
            label,
            count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "Indexing".into())
        );
    }
    body.push_str("</div>");
    body
}

/// Renders the same counts as a compact two-by-two grid for the release
/// directory, where tiles would force the table wider than the page.
fn contents_line(slug: &str, version: &str, counts: &ReleaseContents) -> String {
    let mut parts = Vec::with_capacity(CONTENT_SECTIONS.len());
    for ((section, label), count) in CONTENT_SECTIONS.iter().zip(content_counts_of(counts)) {
        parts.push(format!(
            "<a href=\"/{}/-/{}?release={}\">{} {}</a>",
            escape(slug),
            section,
            urlencode(version),
            count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "indexing".into()),
            label.to_lowercase()
        ));
    }
    format!(
        "<span class=\"release-contents-line\">{}</span>",
        parts.concat()
    )
}

/// Renders the registry-wide release directory.
pub(crate) fn releases_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    contents: &BTreeMap<String, ReleaseContents>,
    channels: &[ChannelSummary],
    page_number: usize,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let mut body = context.nav(slug, "releases");
    body.push_str("<h1>Releases</h1>");
    let pager = Pager::new(page_number, 50, context.releases().len());
    let rows = pager
        .slice(context.releases())
        .iter()
        .map(|release| {
            let version = &release.semver;
            vec![
                format!(
                    "<a class=\"release-version\" id=\"release-{}\" href=\"{}\">{}</a>{}",
                    urlencode(version),
                    escape(&release_href(slug, version)),
                    escape(version),
                    if is_prerelease(version) {
                        "<div class=\"subline\">Prerelease</div>"
                    } else {
                        ""
                    }
                ),
                release.tagged_at.map(ago).unwrap_or_else(|| "—".into()),
                contents_line(
                    slug,
                    version,
                    &contents.get(version).cloned().unwrap_or_default(),
                ),
                verification(release).to_string(),
                channel_participation(slug, version, channels),
            ]
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        body.push_str("<p>No releases have been published yet.</p>");
    } else {
        // The directory must fit the page: wrapped cells beat a hidden
        // horizontal scroll that clips the channel column.
        body.push_str("<div class=\"release-directory\">");
        body.push_str(&table(
            &[
                "release",
                "published",
                "contents",
                "verification",
                "current channels",
            ],
            &rows,
        ));
        body.push_str("</div>");
    }
    body.push_str(&pager.nav(&format!("/{slug}/-/releases"), ""));
    page_with_session(
        "Releases",
        &registry_crumbs(slug, &[(String::new(), "releases".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Renders an individual release's contents and publication details.
pub(crate) fn release_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    contents: &ReleaseContents,
    notes: Option<&str>,
    channels: &[ChannelSummary],
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let Some(release) = context.release() else {
        return unavailable_page(
            registry,
            status,
            context,
            "releases",
            "This release is unavailable.",
            started,
            session,
        );
    };
    let version = &release.semver;
    let mut body = context.nav(slug, "releases");
    body.push_str(&context.selector(slug, &format!("/{slug}/-/releases"), &[]));
    let _ = write!(
        body,
        "<h1>Release {}</h1><p>{} {}</p>",
        escape(version),
        if is_prerelease(version) {
            "Prerelease ·"
        } else {
            ""
        },
        release
            .tagged_at
            .map(|at| format!("Published {}", ago(at)))
            .unwrap_or_default()
    );
    body.push_str(&contents_links(slug, version, contents));
    if let Some(notes) = notes.map(str::trim).filter(|notes| !notes.is_empty()) {
        body.push_str("<section class=\"release-notes\"><h2>Release notes</h2>");
        for paragraph in notes.split("\n\n") {
            let _ = write!(body, "<p>{}</p>", escape(paragraph));
        }
        body.push_str("</section>");
    }
    body.push_str("<h2>Current rollout</h2>");
    body.push_str(&channel_participation(slug, version, channels));
    body.push_str("<details><summary>Details</summary>");
    body.push_str(&table(
        &["field", "value"],
        &[
            vec!["Commit".into(), hash_value(&release.commit_oid)],
            vec!["Tag".into(), hash_value(&release.tag_oid)],
            vec![
                "Published".into(),
                release
                    .tagged_at
                    .map(|at| format!("unix {at}"))
                    .unwrap_or_else(|| "Unknown".into()),
            ],
            vec![
                "Git pack".into(),
                if release.pack_present {
                    "Available"
                } else {
                    "Not advertised"
                }
                .into(),
            ],
            vec![
                "Signing key".into(),
                release
                    .signer
                    .as_deref()
                    .map(hash_value)
                    .unwrap_or_else(|| "Unverified".into()),
            ],
        ],
    ));
    body.push_str("</details>");
    page_with_session(
        &format!("Release {version}"),
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/releases"), "releases".into()),
                (String::new(), version.clone()),
            ],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

fn channel_participation(slug: &str, version: &str, channels: &[ChannelSummary]) -> String {
    let mut entries = Vec::new();
    for channel in channels {
        let count = channel
            .partitions
            .iter()
            .filter(|assigned| assigned.as_deref() == Some(version))
            .count();
        if count > 0 || channel.frontier.as_deref() == Some(version) {
            entries.push(format!(
                "<a href=\"/{}/-/channels/{}\">{}</a> · {}% of rollout buckets{}",
                escape(slug),
                urlencode(&channel.name),
                escape(&channel.name),
                percentage(count),
                if channel.frontier.as_deref() == Some(version) {
                    " · target"
                } else {
                    ""
                }
            ));
        }
    }
    if entries.is_empty() {
        "<span class=\"dim\">No current channel assignments</span>".into()
    } else {
        entries.join("<br>")
    }
}

/// Formats a percentage of the protocol's 256 rollout buckets.
pub(crate) fn percentage(count: usize) -> String {
    let value = count as f64 * 100.0 / 256.0;
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

/// Number of distinct swatch colours available to a channel's releases.
pub(crate) const ROLLOUT_PALETTE: usize = 6;

/// Lists a channel's assigned releases with their bucket counts, newest first,
/// followed by the unassigned remainder.
///
/// Every channel rendering derives its colour from a release's position in
/// this list, so the rollout bar, its labels, and the bucket map agree.
pub(crate) fn rollout_shares(channel: &ChannelSummary) -> Vec<(Option<&str>, usize)> {
    let mut counts = BTreeMap::<Option<&str>, usize>::new();
    for bucket in 0..256 {
        *counts
            .entry(
                channel
                    .partitions
                    .get(bucket)
                    .and_then(|value| value.as_deref()),
            )
            .or_default() += 1;
    }
    let mut releases = counts.into_iter().collect::<Vec<_>>();
    releases.sort_by(|(a, _), (b, _)| match (a, b) {
        (Some(a), Some(b)) => release_order(a, b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    releases
}

/// Renders the complete channel distribution, including unassigned buckets.
pub(crate) fn rollout_distribution(slug: &str, channel: &ChannelSummary) -> String {
    let releases = rollout_shares(channel);
    let mut body = String::from("<div class=\"rollout-distribution\"><svg class=\"rollout-bar\" viewBox=\"0 0 256 8\" preserveAspectRatio=\"none\" aria-hidden=\"true\">");
    let mut offset = 0;
    for (index, (release, count)) in releases.iter().enumerate() {
        let _ = write!(body, "<rect class=\"rollout-segment r{}{}\" x=\"{offset}\" y=\"0\" width=\"{count}\" height=\"8\"/>",
            index % ROLLOUT_PALETTE, if release.is_none() { " unassigned" } else { "" });
        offset += count;
    }
    body.push_str("</svg><ul class=\"rollout-labels\">");
    for (index, (release, count)) in releases.into_iter().enumerate() {
        let label = release
            .map(|release| {
                format!(
                    "<a href=\"{}\">{}</a>",
                    escape(&release_href(slug, release)),
                    escape(release)
                )
            })
            .unwrap_or_else(|| "Unassigned".into());
        let _ = write!(
            body,
            "<li><span class=\"rollout-swatch r{}{}\" aria-hidden=\"true\"></span>{label}: <strong>{}%</strong> <span class=\"dim\">({count}/256 buckets)</span></li>",
            index % ROLLOUT_PALETTE,
            if release.is_none() { " unassigned" } else { "" },
            percentage(count)
        );
    }
    body.push_str("</ul></div>");
    body
}
