//! Publication pages and shared, live channel rollout summaries.
//!
//! Release contents and tag prose come from immutable publication identities.
//! Channel participation is explicitly current state; percentages describe the
//! protocol's 256 rollout buckets, never observed host installation rates.

use crate::clock::Instant;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::browse::BrowseQuery;
use super::browse_pages::{registry_crumbs, state_line};
use super::console_render::{ago, page_with_session, urlencode, Pager, SessionIndicator};
use super::release_browse::{
    is_prerelease, release_href, release_order, unavailable_page, verification, ReleaseContext,
};
use super::render::{escape, hash_value, table};
use crate::db::{ChannelSummary, Database, IndexStatus, RegistryRecord, ReleaseRow};

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

/// Maturity of one release version, read from its semantic-version suffix.
///
/// The registry's calendar trains use `-rc.N` for candidates and `-dev.…` for
/// edge snapshots; any other prerelease suffix is reported as a plain
/// prerelease so unfamiliar tags are never mislabelled as stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseStatus {
    /// A final release with no prerelease suffix.
    Stable,
    /// A release candidate (`-rc.N`).
    Candidate,
    /// An edge snapshot (`-dev.…`).
    Edge,
    /// Any other prerelease suffix.
    Prerelease,
}

impl ReleaseStatus {
    /// Classifies a version string.
    pub(crate) fn of(version: &str) -> Self {
        match semver::Version::parse(version) {
            Ok(parsed) if parsed.pre.is_empty() => Self::Stable,
            Ok(parsed) => {
                let first = parsed.pre.as_str().split('.').next().unwrap_or_default();
                match first {
                    "rc" => Self::Candidate,
                    "dev" => Self::Edge,
                    _ => Self::Prerelease,
                }
            }
            Err(_) => Self::Prerelease,
        }
    }

    /// The query value and label pair used by the filter form.
    pub(crate) const ALL: [(Self, &'static str, &'static str); 4] = [
        (Self::Stable, "stable", "Stable"),
        (Self::Candidate, "candidate", "Candidate"),
        (Self::Edge, "edge", "Edge"),
        (Self::Prerelease, "prerelease", "Other prerelease"),
    ];

    fn token(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(status, _, _)| *status == self)
            .map(|(_, token, _)| *token)
            .unwrap_or("prerelease")
    }

    fn label(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(status, _, _)| *status == self)
            .map(|(_, _, label)| *label)
            .unwrap_or("Prerelease")
    }

    fn parse(token: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(_, candidate, _)| *candidate == token)
            .map(|(status, _, _)| *status)
    }
}

/// The `major.minor` train a version belongs to, when it parses.
fn train_of(version: &str) -> Option<(u64, u64)> {
    semver::Version::parse(version)
        .ok()
        .map(|parsed| (parsed.major, parsed.minor))
}

/// One stable train and the newest release inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrainSummary {
    /// First two version fields.
    pub train: (u64, u64),
    /// Newest stable version in the train.
    pub latest: String,
    /// Whether the registry still treats this train as supported.
    pub supported: bool,
    /// Channels whose frontier currently names a release in this train.
    pub channels: Vec<String>,
}

/// Number of newest stable trains that count as supported without an explicit
/// policy: the current train and the one before it, matching the retention
/// floor in the release model.
pub(crate) const DEFAULT_SUPPORTED_TRAINS: usize = 2;

/// Groups stable releases into trains, newest first, and marks support.
///
/// Until the registry publishes an explicit support policy, the newest
/// [`DEFAULT_SUPPORTED_TRAINS`] trains and any train a channel currently
/// targets count as supported; everything older is end of life.
pub(crate) fn stable_trains(
    releases: &[ReleaseRow],
    channels: &[ChannelSummary],
) -> Vec<TrainSummary> {
    let mut trains: Vec<TrainSummary> = Vec::new();
    for release in releases {
        if ReleaseStatus::of(&release.semver) != ReleaseStatus::Stable {
            continue;
        }
        let Some(train) = train_of(&release.semver) else {
            continue;
        };
        if trains.iter().any(|summary| summary.train == train) {
            continue;
        }
        trains.push(TrainSummary {
            train,
            latest: release.semver.clone(),
            supported: false,
            channels: Vec::new(),
        });
    }
    for (index, summary) in trains.iter_mut().enumerate() {
        summary.channels = channels
            .iter()
            .filter(|channel| {
                channel
                    .frontier
                    .as_deref()
                    .and_then(train_of)
                    .is_some_and(|train| train == summary.train)
            })
            .map(|channel| channel.name.clone())
            .collect();
        summary.supported = index < DEFAULT_SUPPORTED_TRAINS || !summary.channels.is_empty();
    }
    trains
}

/// Renders the support board: one tile per supported stable train plus the
/// newest candidate and edge snapshots, so a reader can tell at a glance
/// whether their train still receives updates and which release is newest.
fn support_board(slug: &str, releases: &[ReleaseRow], channels: &[ChannelSummary]) -> String {
    let trains = stable_trains(releases, channels);
    let newest = |status: ReleaseStatus| {
        releases
            .iter()
            .find(|release| ReleaseStatus::of(&release.semver) == status)
    };
    let mut body =
        String::from("<section class=\"support-board\" aria-label=\"Supported releases\">");
    for summary in trains.iter().filter(|summary| summary.supported) {
        let (major, minor) = summary.train;
        let _ = write!(
            body,
            "<a class=\"support-tile supported\" href=\"{}\"><span class=\"support-train\">{major}.{minor}</span><strong>{}</strong><span class=\"support-state\">Supported</span>{}</a>",
            escape(&release_href(slug, &summary.latest)),
            escape(&summary.latest),
            if summary.channels.is_empty() {
                String::new()
            } else {
                format!(
                    "<span class=\"support-channels\">{}</span>",
                    summary
                        .channels
                        .iter()
                        .map(|name| escape(name))
                        .collect::<Vec<_>>()
                        .join(" · ")
                )
            }
        );
    }
    for (status, class) in [
        (ReleaseStatus::Candidate, "candidate"),
        (ReleaseStatus::Edge, "edge"),
    ] {
        if let Some(release) = newest(status) {
            let _ = write!(
                body,
                "<a class=\"support-tile {class}\" href=\"{}\"><span class=\"support-train\">{}</span><strong>{}</strong><span class=\"support-state\">No support promise</span></a>",
                escape(&release_href(slug, &release.semver)),
                status.label(),
                escape(&release.semver)
            );
        }
    }
    let eol = trains.iter().filter(|summary| !summary.supported).count();
    if eol > 0 {
        let _ = write!(
            body,
            "<a class=\"support-tile eol\" href=\"/{}/-/releases?status=stable\"><span class=\"support-train\">End of life</span><strong>{eol} older {}</strong><span class=\"support-state\">No updates</span></a>",
            escape(slug),
            if eol == 1 { "train" } else { "trains" }
        );
    }
    if trains.is_empty()
        && newest(ReleaseStatus::Candidate).is_none()
        && newest(ReleaseStatus::Edge).is_none()
    {
        body.push_str("<p class=\"dim\">No releases have been published yet.</p>");
    }
    body.push_str("</section>");
    body
}

/// Renders the major, minor, and status filter form for the directory.
fn filter_form(slug: &str, releases: &[ReleaseRow], query: &BrowseQuery) -> String {
    let mut majors = releases
        .iter()
        .filter_map(|release| train_of(&release.semver).map(|(major, _)| major))
        .collect::<Vec<_>>();
    majors.sort_unstable_by(|a, b| b.cmp(a));
    majors.dedup();
    let selected_major = query
        .major
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    let mut minors = releases
        .iter()
        .filter_map(|release| train_of(&release.semver))
        .filter(|(major, _)| selected_major.is_none_or(|selected| selected == *major))
        .map(|(_, minor)| minor)
        .collect::<Vec<_>>();
    minors.sort_unstable_by(|a, b| b.cmp(a));
    minors.dedup();
    let selected_minor = query
        .minor
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    let selected_status = query.status.as_deref().and_then(ReleaseStatus::parse);

    let mut body = format!(
        "<form method=\"get\" action=\"/{}/-/releases\" class=\"release-filter\"><label>Major <select name=\"major\"><option value=\"\">All</option>",
        escape(slug)
    );
    for major in majors {
        let _ = write!(
            body,
            "<option value=\"{major}\"{}>{major}</option>",
            if Some(major) == selected_major {
                " selected"
            } else {
                ""
            }
        );
    }
    body.push_str(
        "</select></label><label>Minor <select name=\"minor\"><option value=\"\">All</option>",
    );
    for minor in minors {
        let _ = write!(
            body,
            "<option value=\"{minor}\"{}>{minor}</option>",
            if Some(minor) == selected_minor {
                " selected"
            } else {
                ""
            }
        );
    }
    body.push_str(
        "</select></label><label>Status <select name=\"status\"><option value=\"\">All</option>",
    );
    for (status, token, label) in ReleaseStatus::ALL {
        let _ = write!(
            body,
            "<option value=\"{token}\"{}>{label}</option>",
            if Some(status) == selected_status {
                " selected"
            } else {
                ""
            }
        );
    }
    body.push_str("</select></label><button type=\"submit\">Filter</button>");
    if selected_major.is_some() || selected_minor.is_some() || selected_status.is_some() {
        let _ = write!(body, "<a href=\"/{}/-/releases\">Clear</a>", escape(slug));
    }
    body.push_str("</form>");
    body
}

/// Applies the directory filters to the release list.
pub(crate) fn filter_releases<'a>(
    releases: &'a [ReleaseRow],
    query: &BrowseQuery,
) -> Vec<&'a ReleaseRow> {
    let major = query
        .major
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    let minor = query
        .minor
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    let status = query.status.as_deref().and_then(ReleaseStatus::parse);
    releases
        .iter()
        .filter(|release| {
            let train = train_of(&release.semver);
            major.is_none_or(|major| train.is_some_and(|(actual, _)| actual == major))
                && minor.is_none_or(|minor| train.is_some_and(|(_, actual)| actual == minor))
                && status.is_none_or(|status| ReleaseStatus::of(&release.semver) == status)
        })
        .collect()
}

/// Encodes the active filters for pager links.
fn filter_query(query: &BrowseQuery) -> String {
    let mut pairs = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in [
        ("major", &query.major),
        ("minor", &query.minor),
        ("status", &query.status),
    ] {
        if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
            pairs.append_pair(key, value);
        }
    }
    pairs.finish()
}

/// Renders the registry-wide release directory.
pub(crate) fn releases_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    contents: &BTreeMap<String, ReleaseContents>,
    channels: &[ChannelSummary],
    query: &BrowseQuery,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let mut body = context.nav(slug, "releases");
    body.push_str("<h1>Releases</h1>");
    body.push_str(&support_board(slug, context.releases(), channels));
    body.push_str(&filter_form(slug, context.releases(), query));
    let filtered = filter_releases(context.releases(), query);
    if filtered.len() != context.releases().len() {
        let _ = write!(
            body,
            "<p class=\"dim\">{} of {} releases match.</p>",
            filtered.len(),
            context.releases().len()
        );
    }
    let pager = Pager::new(query.page_number(), 50, filtered.len());
    let rows = pager
        .slice(&filtered)
        .iter()
        .map(|release| {
            let version = &release.semver;
            let status = ReleaseStatus::of(version);
            vec![
                format!(
                    "<a class=\"release-version\" id=\"release-{}\" href=\"{}\">{}</a>{}",
                    urlencode(version),
                    escape(&release_href(slug, version)),
                    escape(version),
                    if status == ReleaseStatus::Stable {
                        String::new()
                    } else {
                        format!("<div class=\"subline\">{}</div>", status.label())
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
        body.push_str(if context.releases().is_empty() {
            "<p>No releases have been published yet.</p>"
        } else {
            "<p>No releases match these filters.</p>"
        });
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
    body.push_str(&pager.nav(&format!("/{slug}/-/releases"), &filter_query(query)));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str) -> ReleaseRow {
        ReleaseRow {
            semver: version.into(),
            tag_oid: format!("tag-{version}"),
            commit_oid: format!("commit-{version}"),
            signer: Some("signer".into()),
            tagged_at: Some(1),
            pack_present: true,
        }
    }

    fn channel(name: &str, frontier: &str) -> ChannelSummary {
        ChannelSummary {
            name: name.into(),
            frontier: Some(frontier.into()),
            partitions: vec![Some(frontier.to_string()); 256],
        }
    }

    #[test]
    fn status_reads_the_calendar_train_suffixes() {
        assert_eq!(ReleaseStatus::of("2026.9.1"), ReleaseStatus::Stable);
        assert_eq!(
            ReleaseStatus::of("2026.10.0-rc.2"),
            ReleaseStatus::Candidate
        );
        assert_eq!(
            ReleaseStatus::of("2026.10.0-dev.20260902.1"),
            ReleaseStatus::Edge
        );
        assert_eq!(
            ReleaseStatus::of("2026.10.0-beta.1"),
            ReleaseStatus::Prerelease
        );
        assert_eq!(
            ReleaseStatus::of("not-a-version"),
            ReleaseStatus::Prerelease
        );
        assert_eq!(ReleaseStatus::parse("edge"), Some(ReleaseStatus::Edge));
        assert_eq!(ReleaseStatus::parse("nope"), None);
    }

    #[test]
    fn trains_group_stable_releases_and_mark_support() {
        let releases = [
            "2026.9.2",
            "2026.9.1",
            "2026.10.0-rc.1",
            "2026.8.3",
            "2026.7.0",
            "2025.12.4",
        ]
        .iter()
        .map(|version| release(version))
        .collect::<Vec<_>>();
        let channels = vec![channel("stable", "2026.9.2"), channel("lts", "2025.12.4")];
        let trains = stable_trains(&releases, &channels);
        assert_eq!(
            trains
                .iter()
                .map(|train| train.latest.as_str())
                .collect::<Vec<_>>(),
            vec!["2026.9.2", "2026.8.3", "2026.7.0", "2025.12.4"]
        );
        assert!(trains[0].supported && trains[0].channels == vec!["stable"]);
        assert!(trains[1].supported && trains[1].channels.is_empty());
        assert!(
            !trains[2].supported,
            "third train is end of life by default"
        );
        assert!(
            trains[3].supported,
            "a channel target keeps an old train supported"
        );
    }

    #[test]
    fn filters_select_by_train_and_status() {
        let releases = ["2026.9.2", "2026.9.0-rc.1", "2026.8.3", "2025.12.4"]
            .iter()
            .map(|version| release(version))
            .collect::<Vec<_>>();
        let query = BrowseQuery {
            major: Some("2026".into()),
            status: Some("stable".into()),
            ..BrowseQuery::default()
        };
        let matched = filter_releases(&releases, &query)
            .into_iter()
            .map(|release| release.semver.as_str())
            .collect::<Vec<_>>();
        assert_eq!(matched, vec!["2026.9.2", "2026.8.3"]);
        let query = BrowseQuery {
            minor: Some("9".into()),
            ..BrowseQuery::default()
        };
        assert_eq!(filter_releases(&releases, &query).len(), 2);
        assert_eq!(filter_query(&query), "minor=9");
        let board = support_board("org/main", &releases, &[channel("stable", "2026.9.2")]);
        assert!(
            board.contains("<span class=\"support-train\">2026.9</span><strong>2026.9.2</strong>")
        );
        assert!(board.contains("<span class=\"support-channels\">stable</span>"));
        assert!(board.contains("class=\"support-tile candidate\""));
        assert!(board.contains("1 older train"));
    }
}
