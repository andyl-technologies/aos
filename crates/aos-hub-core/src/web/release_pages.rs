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
use aos_registry_surface::support::{Date, SupportKind, SupportPolicy, SupportState};

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

    /// Query value for the policy-dependent long-term-support filter, which
    /// selects stable releases whose train the registry marks as LTS.
    pub(crate) const LTS_TOKEN: &'static str = "lts";

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
    /// Support class under the registry's policy.
    pub kind: SupportKind,
    /// Where the train stands today.
    pub state: SupportState,
    /// Channels whose frontier currently names a release in this train.
    pub channels: Vec<String>,
}

impl TrainSummary {
    /// Whether the train still receives updates.
    pub(crate) fn supported(&self) -> bool {
        self.state.is_supported()
    }
}

/// Groups releases into trains, newest first, keeping each train's newest
/// release (a candidate counts for its train), and classifies each one.
///
/// The registry's committed policy decides; without one, the default policy
/// applies (the newest two trains are supported, matching the retention floor
/// in the release model). A train a channel currently targets stays supported
/// regardless, because hosts are still being moved onto it.
pub(crate) fn release_trains(
    releases: &[ReleaseRow],
    channels: &[ChannelSummary],
    policy: Option<&SupportPolicy>,
    today: Date,
) -> Vec<TrainSummary> {
    let fallback = SupportPolicy::default();
    let policy = policy.unwrap_or(&fallback);
    let mut trains: Vec<TrainSummary> = Vec::new();
    for release in releases {
        let Some(train) = train_of(&release.semver) else {
            continue;
        };
        if trains.iter().any(|summary| summary.train == train) {
            continue;
        }
        trains.push(TrainSummary {
            train,
            latest: release.semver.clone(),
            kind: policy.kind(train),
            state: SupportState::EndOfLife { until: None },
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
        summary.state = match policy.classify(summary.train, index, today) {
            SupportState::EndOfLife { until } if !summary.channels.is_empty() => {
                SupportState::Supported { until }
            }
            state => state,
        };
    }
    trains
}

/// Renders the support board: one tile per supported train, newest train
/// first, showing that train's newest release and the channels targeting it.
/// Trains that no longer receive updates are not listed.
fn support_board(
    slug: &str,
    releases: &[ReleaseRow],
    channels: &[ChannelSummary],
    policy: Option<&SupportPolicy>,
    today: Date,
) -> String {
    let trains = release_trains(releases, channels, policy, today);
    let mut body =
        String::from("<section class=\"support-board\" aria-label=\"Supported releases\">");
    for summary in trains.iter().filter(|summary| summary.supported()) {
        let (major, minor) = summary.train;
        // Only a stated end date earns a line; an open-ended train says nothing
        // and the release page carries the full policy.
        let (class, state) = match &summary.state {
            SupportState::EndingSoon { until } => (
                "supported ending",
                format!("<span class=\"support-state\">Until {until}</span>"),
            ),
            SupportState::Supported { until: Some(until) } => (
                "supported",
                format!("<span class=\"support-state\">Until {until}</span>"),
            ),
            _ => ("supported", String::new()),
        };
        let _ = write!(
            body,
            "<a class=\"support-tile {class}\" href=\"{}\"><span class=\"support-train\">{major}.{minor}{}</span><strong>{}</strong>{state}{}</a>",
            escape(&release_href(slug, &summary.latest)),
            if summary.kind == SupportKind::Lts {
                " · LTS"
            } else {
                ""
            },
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
    if releases.is_empty() {
        body.push_str("<p class=\"dim\">No releases have been published yet.</p>");
    }
    body.push_str("</section>");
    body
}

/// Renders the major, minor, and status filter form for the directory.
fn filter_form(
    slug: &str,
    releases: &[ReleaseRow],
    query: &BrowseQuery,
    policy: Option<&SupportPolicy>,
) -> String {
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
    let lts_selected = query.status.as_deref() == Some(ReleaseStatus::LTS_TOKEN);
    let has_lts = policy.is_some_and(SupportPolicy::has_lts);
    if has_lts || lts_selected {
        let _ = write!(
            body,
            "<option value=\"{}\"{}>Long-term support</option>",
            ReleaseStatus::LTS_TOKEN,
            if lts_selected { " selected" } else { "" }
        );
    }
    body.push_str("</select></label><button type=\"submit\">Filter</button>");
    if selected_major.is_some()
        || selected_minor.is_some()
        || selected_status.is_some()
        || lts_selected
    {
        let _ = write!(body, "<a href=\"/{}/-/releases\">Clear</a>", escape(slug));
    }
    body.push_str("</form>");
    body
}

/// Applies the directory filters to the release list.
///
/// The `lts` status selects stable releases whose train the policy marks as
/// long-term support; it matches nothing when the registry has no policy.
pub(crate) fn filter_releases<'a>(
    releases: &'a [ReleaseRow],
    query: &BrowseQuery,
    policy: Option<&SupportPolicy>,
) -> Vec<&'a ReleaseRow> {
    let major = query
        .major
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    let minor = query
        .minor
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    let lts = query.status.as_deref() == Some(ReleaseStatus::LTS_TOKEN);
    let status = query.status.as_deref().and_then(ReleaseStatus::parse);
    releases
        .iter()
        .filter(|release| {
            let train = train_of(&release.semver);
            let is_lts = train.is_some_and(|train| {
                policy.is_some_and(|policy| policy.kind(train) == SupportKind::Lts)
            });
            major.is_none_or(|major| train.is_some_and(|(actual, _)| actual == major))
                && minor.is_none_or(|minor| train.is_some_and(|(_, actual)| actual == minor))
                && status.is_none_or(|status| ReleaseStatus::of(&release.semver) == status)
                && (!lts || (ReleaseStatus::of(&release.semver) == ReleaseStatus::Stable && is_lts))
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
    let policy = status.and_then(|status| status.support.as_ref());
    let today = Date::from_unix(crate::clock::now_unix_secs());
    let mut body = context.nav(slug, "releases");
    body.push_str("<h1>Releases</h1>");
    body.push_str(&support_board(
        slug,
        context.releases(),
        channels,
        policy,
        today,
    ));
    body.push_str(&filter_form(slug, context.releases(), query, policy));
    let filtered = filter_releases(context.releases(), query, policy);
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
    record: Option<&aos_release::record::ReleaseRecordV1>,
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
    if let Some(record) = record {
        body.push_str(&qualification_section(slug, record));
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

/// Renders the verified public release record: the qualification outcome,
/// per-claim assurance, the train's support promise, and provenance digests.
///
/// Assurance describes the evidence at admission time, so the admission date
/// sits beside the result rather than implying a standing guarantee.
fn qualification_section(slug: &str, record: &aos_release::record::ReleaseRecordV1) -> String {
    use aos_release::evidence::GateResult;
    use aos_release::qualification::claims::ClaimDisposition;

    let summary = &record.qualification;
    let (result_class, result_label) = match summary.result {
        GateResult::Passed => ("ok", "Qualified"),
        GateResult::Failed => ("bad", "Failed qualification"),
    };
    let mut body = String::from("<h2>Qualification</h2><div class=\"release-facts\">");
    let _ = write!(
        body,
        "<div class=\"release-fact\"><span>Result</span><strong class=\"{result_class}\">{result_label}</strong><small class=\"dim\">{}</small></div>",
        escape(&summary.qualified_at)
    );
    let _ = write!(
        body,
        "<div class=\"release-fact\"><span>Class</span><strong>{:?}</strong>{}</div>",
        record.release_class,
        summary
            .phase
            .map(|phase| format!("<small class=\"dim\">{phase:?} hold point</small>"))
            .unwrap_or_default()
    );
    let _ = write!(
        body,
        "<div class=\"release-fact\"><span>Policy</span><strong>{}</strong><small class=\"dim\">{}</small></div>",
        escape(&summary.policy_id),
        hash_value(&summary.policy_digest.to_string())
    );
    let _ = write!(
        body,
        "<div class=\"release-fact\"><span>Authority</span><strong>{}</strong></div>",
        escape(&summary.authority_id)
    );
    if let Some(support) = &record.support {
        let _ = write!(
            body,
            "<div class=\"release-fact\"><span>Support at release</span><strong>{} {}</strong>{}</div>",
            escape(&record.train),
            support.kind.label(),
            support
                .supported_until
                .as_deref()
                .map(|until| format!("<small class=\"dim\">Until {}</small>", escape(until)))
                .unwrap_or_default()
        );
    }
    body.push_str("</div>");

    if !summary.claims.is_empty() {
        let rows = summary
            .claims
            .iter()
            .map(|claim| {
                let (class, label) = match claim.disposition {
                    ClaimDisposition::Passed => ("ok", "Passed"),
                    ClaimDisposition::Failed => ("bad", "Failed"),
                    ClaimDisposition::Missing => ("warn", "Missing"),
                    ClaimDisposition::Stale => ("warn", "Stale"),
                };
                vec![
                    escape(&claim.claim_id),
                    format!("{:?}", claim.required_assurance),
                    format!("<strong>{:?}</strong>", claim.achieved_assurance),
                    format!("<span class=\"{class}\">{label}</span>"),
                    if claim.blocks_release {
                        "Blocks release".into()
                    } else {
                        "<span class=\"dim\">Informational</span>".into()
                    },
                ]
            })
            .collect::<Vec<_>>();
        body.push_str(&table(
            &["claim", "required", "achieved", "result", "obligation"],
            &rows,
        ));
    }
    let _ = write!(
        body,
        "<details><summary>Provenance</summary>{}</details>",
        table(
            &["field", "value"],
            &[
                vec!["Source commit".into(), hash_value(&record.source_commit)],
                vec!["Plan".into(), hash_value(&record.plan_digest.to_string())],
                vec![
                    "Manifest".into(),
                    hash_value(&record.manifest_digest.to_string())
                ],
                vec![
                    "Qualification receipt".into(),
                    hash_value(&summary.receipt_digest.to_string())
                ],
                vec![
                    "Report".into(),
                    hash_value(&summary.report_digest.to_string())
                ],
                vec![
                    "Record".into(),
                    format!(
                        "<code>{}</code>",
                        escape(&aos_release::record::record_path(
                            record.release_class,
                            &record.version
                        ))
                    )
                ],
            ],
        )
    );
    let _ = slug;
    body
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
    fn release_record_renders_result_claims_support_and_provenance() {
        use aos_release::digest::Sha256Digest;
        use aos_release::evidence::GateResult;
        use aos_release::qualification::claims::{AssuranceLevel, ClaimDisposition, ClaimOutcome};
        use aos_release::record::{QualificationSummaryV1, ReleaseRecordV1, ReleaseSupportV1};
        let record = ReleaseRecordV1 {
            schema_version: aos_release::record::RECORD_V1.into(),
            registry: "andyl/main".into(),
            release_id: "release-2026.9.1".into(),
            version: "2026.9.1".into(),
            train: "2026.9".into(),
            release_class: aos_release::plan::ReleaseClass::Stable,
            source_commit: "a".repeat(64),
            plan_digest: Sha256Digest::of_bytes(b"plan"),
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            qualification: QualificationSummaryV1 {
                policy_id: "full-release-qualification".into(),
                policy_digest: Sha256Digest::of_bytes(b"policy"),
                result: GateResult::Passed,
                qualified_at: "2026-09-05T12:00:00Z".into(),
                authority_id: "qualification-authority".into(),
                receipt_digest: Sha256Digest::of_bytes(b"receipt"),
                report_digest: Sha256Digest::of_bytes(b"report"),
                phase: None,
                claims: vec![ClaimOutcome {
                    case_id: "disk-x86_64-linux".into(),
                    claim_id: "disk-x86_64-linux-qualified".into(),
                    required_assurance: AssuranceLevel::A3,
                    achieved_assurance: AssuranceLevel::A2,
                    disposition: ClaimDisposition::Passed,
                    blocks_release: true,
                    environment_digest: None,
                }],
            },
            support: Some(ReleaseSupportV1 {
                kind: SupportKind::Lts,
                supported_until: Some("2028-09-30".into()),
            }),
            signed_qualification: "{}".into(),
        };
        let html = qualification_section("org/main", &record);
        assert!(html.contains("<strong class=\"ok\">Qualified</strong>"));
        assert!(html.contains("2026-09-05T12:00:00Z"));
        assert!(html.contains("<strong>2026.9 LTS</strong>"));
        assert!(html.contains("Until 2028-09-30"));
        assert!(html.contains("disk-x86_64-linux-qualified"));
        assert!(html.contains("<strong>A2</strong>"));
        assert!(html.contains("Blocks release"));
        assert!(html.contains("releases/stable/2026.9.1/release-record.json"));
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
        let releases = ["2026.9.2", "2026.9.1", "2026.8.3", "2026.7.0", "2025.12.4"]
            .iter()
            .map(|version| release(version))
            .collect::<Vec<_>>();
        let channels = vec![channel("stable", "2026.9.2"), channel("lts", "2025.12.4")];
        let today = Date::parse("2026-09-05").unwrap();
        let trains = release_trains(&releases, &channels, None, today);
        assert_eq!(
            trains
                .iter()
                .map(|train| train.latest.as_str())
                .collect::<Vec<_>>(),
            vec!["2026.9.2", "2026.8.3", "2026.7.0", "2025.12.4"]
        );
        assert!(trains[0].supported() && trains[0].channels == vec!["stable"]);
        assert!(trains[1].supported() && trains[1].channels.is_empty());
        assert!(
            !trains[2].supported(),
            "third train is end of life by default"
        );
        assert!(
            trains[3].supported(),
            "a channel target keeps an old train supported"
        );
        assert!(trains
            .iter()
            .all(|train| train.kind == SupportKind::Standard));
    }

    #[test]
    fn policy_dates_and_kinds_override_the_rolling_default() {
        let releases = ["2026.9.2", "2026.8.3", "2026.7.0", "2025.12.4"]
            .iter()
            .map(|version| release(version))
            .collect::<Vec<_>>();
        let policy: SupportPolicy = serde_json::from_str(
            r#"{"default":{"kind":"standard","superseded_after_trains":1},
                "trains":{"2025.12":{"kind":"lts","supported_until":"2027-12-31"},
                          "2026.8":{"supported_until":"2026-09-30"}}}"#,
        )
        .unwrap();
        let today = Date::parse("2026-09-05").unwrap();
        let trains = release_trains(&releases, &[], Some(&policy), today);
        assert_eq!(
            trains[0].state,
            SupportState::Supported { until: None },
            "newest train is implicit and supported"
        );
        assert_eq!(
            trains[1].state,
            SupportState::EndingSoon {
                until: Date::parse("2026-09-30").unwrap()
            }
        );
        assert_eq!(trains[2].state, SupportState::EndOfLife { until: None });
        assert_eq!(trains[3].kind, SupportKind::Lts);
        assert!(trains[3].supported());

        let board = support_board("org/main", &releases, &[], Some(&policy), today);
        assert!(board.contains("<span class=\"support-train\">2025.12 · LTS</span>"));
        assert!(board.contains("class=\"support-tile supported ending\""));
        assert!(board.contains("<span class=\"support-state\">Until 2026-09-30</span>"));
        assert!(!board.contains(">Supported<"));
        assert!(
            !board.contains("2026.7"),
            "end-of-life trains are not listed"
        );

        let query = BrowseQuery {
            status: Some("lts".into()),
            ..BrowseQuery::default()
        };
        let matched = filter_releases(&releases, &query, Some(&policy))
            .into_iter()
            .map(|release| release.semver.as_str())
            .collect::<Vec<_>>();
        assert_eq!(matched, vec!["2025.12.4"]);
        assert!(filter_releases(&releases, &query, None).is_empty());
        let form = filter_form("org/main", &releases, &query, Some(&policy));
        assert!(form.contains("<option value=\"lts\" selected>Long-term support</option>"));
        let plain = filter_form("org/main", &releases, &BrowseQuery::default(), None);
        assert!(!plain.contains("value=\"lts\""));
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
        let matched = filter_releases(&releases, &query, None)
            .into_iter()
            .map(|release| release.semver.as_str())
            .collect::<Vec<_>>();
        assert_eq!(matched, vec!["2026.9.2", "2026.8.3"]);
        let query = BrowseQuery {
            minor: Some("9".into()),
            ..BrowseQuery::default()
        };
        assert_eq!(filter_releases(&releases, &query, None).len(), 2);
        assert_eq!(filter_query(&query), "minor=9");
        let today = Date::parse("2026-09-05").unwrap();
        let board = support_board(
            "org/main",
            &releases,
            &[channel("stable", "2026.9.2")],
            None,
            today,
        );
        assert!(
            board.contains("<span class=\"support-train\">2026.9</span><strong>2026.9.2</strong>")
        );
        assert!(board.contains("<span class=\"support-channels\">stable</span>"));
        assert!(
            !board.contains("2026.9.0-rc.1"),
            "candidates join their train"
        );
        assert!(
            !board.contains("2025.12"),
            "end-of-life trains are not listed"
        );
        assert!(board.find("2026.9").unwrap() < board.find("2026.8").unwrap());
    }
}
