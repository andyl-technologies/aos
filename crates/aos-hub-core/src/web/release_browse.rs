//! Release selection and exact package metadata for the public browser.
//!
//! Content links carry `?release=1.2.3`; Images and Containers also accept an
//! explicit `?release=all`. Overview, the release directory, and Channels are
//! registry-wide. An unavailable selection never falls back to live content.
//!
//! A request may name a channel (`?release=stable`) or a commit; both resolve
//! to the exact published version and redirect to it, so shared links always
//! carry an immutable identity. The selector shows channels, the newest
//! releases, and the current selection rather than every historical tag; the
//! Releases directory lists the rest.

use crate::clock::Instant;
use std::cmp::Ordering;
use std::fmt::Write as _;

use super::browse::Rendered;
use super::browse_pages::{registry_crumbs, registry_nav_at_release, state_line};
use super::console_render::{page_with_session, urlencode, SessionIndicator};
use super::render::escape;
use crate::db::{
    ChannelSummary, Database, IndexStatus, PackageDetail, PackageRow, PlatformDetail,
    RegistryRecord, ReleaseRow, VersionDetail,
};
use aos_registry_surface::manifest::PackageToml;

/// Number of newest releases offered directly in the selector.
const RECENT_RELEASES: usize = 10;

/// Exact content selection and available registry release versions.
#[derive(Debug, Clone, Default)]
pub struct ReleaseContext {
    releases: Vec<ReleaseRow>,
    channels: Vec<ChannelSummary>,
    selected: Option<String>,
    all_releases: bool,
    allow_all: bool,
}

impl ReleaseContext {
    /// Loads a selection from published releases and the indexed preference.
    ///
    /// # Errors
    /// Returns service-unavailable for database failures and not-found for an
    /// unknown explicit or configured release.
    pub async fn load(
        db: &Database,
        registry_id: i64,
        requested: Option<&str>,
        allow_all: bool,
    ) -> Result<Self, Rendered> {
        let (releases, channels, default) = futures_util::future::join3(
            db.list_releases(registry_id),
            db.list_channels(registry_id),
            db.default_browse_release(registry_id),
        )
        .await;
        Self::select_among(
            releases.map_err(|_| Rendered::ServiceUnavailable)?,
            channels.map_err(|_| Rendered::ServiceUnavailable)?,
            default
                .map_err(|_| Rendered::ServiceUnavailable)?
                .as_deref(),
            requested,
            allow_all,
        )
        .ok_or(Rendered::NotFound)
    }

    /// Selects a release without I/O, resolving commit aliases to version names.
    ///
    /// Returns `None` for unknown selections or unsupported all-release views.
    #[must_use]
    pub fn select(
        releases: Vec<ReleaseRow>,
        default: Option<&str>,
        requested: Option<&str>,
        allow_all: bool,
    ) -> Option<Self> {
        Self::select_among(releases, Vec::new(), default, requested, allow_all)
    }

    /// Selects a release, also resolving channel names to their current target.
    ///
    /// A channel alias resolves to the release its frontier names; a channel
    /// without a frontier is unknown. Returns `None` for unknown selections or
    /// unsupported all-release views.
    #[must_use]
    pub fn select_among(
        mut releases: Vec<ReleaseRow>,
        channels: Vec<ChannelSummary>,
        default: Option<&str>,
        requested: Option<&str>,
        allow_all: bool,
    ) -> Option<Self> {
        releases.sort_by(|a, b| {
            release_order(&a.semver, &b.semver).then_with(|| b.tagged_at.cmp(&a.tagged_at))
        });
        let requested = requested.map(str::trim).filter(|value| !value.is_empty());
        let all_releases = requested == Some("all");
        if all_releases && !allow_all {
            return None;
        }
        let selected = if all_releases {
            None
        } else if let Some(value) = requested.or(default) {
            let value = channels
                .iter()
                .find(|channel| channel.name == value)
                .map(|channel| channel.frontier.as_deref())
                .unwrap_or(Some(value))?;
            Some(
                releases
                    .iter()
                    .find(|release| release.semver == value || release.commit_oid == value)?
                    .semver
                    .clone(),
            )
        } else {
            releases
                .iter()
                .filter(|release| release.signer.is_some())
                .find(|release| {
                    semver::Version::parse(&release.semver)
                        .is_ok_and(|version| version.pre.is_empty())
                })
                .or_else(|| releases.iter().find(|release| release.signer.is_some()))
                .map(|release| release.semver.clone())
        };
        Some(Self {
            releases,
            channels,
            selected,
            all_releases,
            allow_all,
        })
    }

    /// Returns the selected exact version, absent for empty or all-release views.
    #[must_use]
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Returns whether the user explicitly selected all releases.
    #[must_use]
    pub fn is_all(&self) -> bool {
        self.all_releases
    }

    /// Returns the selection's URL query value.
    #[must_use]
    pub fn query_value(&self) -> Option<&str> {
        if self.all_releases {
            Some("all")
        } else {
            self.selected()
        }
    }

    /// Returns releases in semantic-version order, newest first.
    #[must_use]
    pub fn releases(&self) -> &[ReleaseRow] {
        &self.releases
    }

    /// Returns the selected publication metadata.
    #[must_use]
    pub fn release(&self) -> Option<&ReleaseRow> {
        self.releases
            .iter()
            .find(|release| Some(release.semver.as_str()) == self.selected())
    }

    /// Builds navigation preserving the selected content version.
    #[must_use]
    pub fn nav(&self, slug: &str, active: &str) -> String {
        registry_nav_at_release(slug, active, self.query_value())
    }

    /// Returns each channel paired with the release its frontier currently names.
    ///
    /// Channels whose frontier is not a published release are omitted: the
    /// selector only offers destinations that resolve.
    #[must_use]
    pub fn channel_targets(&self) -> Vec<(&str, &str)> {
        self.channels
            .iter()
            .filter_map(|channel| {
                let frontier = channel.frontier.as_deref()?;
                self.releases
                    .iter()
                    .any(|release| release.semver == frontier)
                    .then_some((channel.name.as_str(), frontier))
            })
            .collect()
    }

    /// Builds the shared selector with page-specific filters preserved.
    ///
    /// The selector stays small at any release count: channel targets, the
    /// newest releases, and the current selection are offered directly, a
    /// typed jump resolves any version, commit, or channel name, and the
    /// Releases directory lists everything else. An explicit action lets
    /// detail pages resolve the package in the newly selected release.
    /// Pagination and digests belong to the old selection and must not be
    /// included in `filters`.
    #[must_use]
    pub fn selector(&self, slug: &str, action: &str, filters: &[(&str, &str)]) -> String {
        let mut hidden = String::new();
        for (key, value) in filters {
            let _ = write!(
                hidden,
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape(key),
                escape(value)
            );
        }
        let channel_targets = self.channel_targets();

        let mut body = String::from("<div class=\"release-selector\" data-release-picker>");
        if !channel_targets.is_empty() {
            body.push_str("<div class=\"release-rail\" role=\"group\" aria-label=\"Channels\">");
            for (name, version) in &channel_targets {
                let mut href = format!("{}?release={}", escape(action), urlencode(version));
                for (key, value) in filters {
                    let _ = write!(href, "&amp;{}={}", urlencode(key), urlencode(value));
                }
                let _ = write!(
                    body,
                    "<a class=\"release-pill\" href=\"{href}\"{}>{} <strong>{}</strong></a>",
                    if Some(*version) == self.selected() {
                        " aria-current=\"true\""
                    } else {
                        ""
                    },
                    escape(name),
                    escape(version)
                );
            }
            body.push_str("</div>");
        }

        let _ = write!(
            body,
            "<form method=\"get\" action=\"{}\" class=\"release-choice\">{hidden}<label>Release <select name=\"release\">",
            escape(action)
        );
        if self.allow_all {
            let _ = write!(
                body,
                "<option value=\"all\"{}>All releases</option>",
                if self.all_releases { " selected" } else { "" }
            );
        }
        if self.selected.is_none() && !self.all_releases {
            body.push_str("<option value=\"\" selected disabled>Choose a release</option>");
        }
        let option = |body: &mut String, release: &ReleaseRow, prefix: &str| {
            let _ = write!(
                body,
                "<option value=\"{}\"{}>{prefix}{}{}</option>",
                escape(&release.semver),
                if Some(release.semver.as_str()) == self.selected() {
                    " selected"
                } else {
                    ""
                },
                escape(&release.semver),
                if is_prerelease(&release.semver) {
                    " · prerelease"
                } else {
                    ""
                }
            );
        };
        let mut offered = std::collections::BTreeSet::new();
        if !channel_targets.is_empty() {
            body.push_str("<optgroup label=\"Channels\">");
            for (name, version) in &channel_targets {
                if let Some(release) = self.releases.iter().find(|r| r.semver == *version) {
                    option(&mut body, release, &format!("{} → ", escape(name)));
                    offered.insert(release.semver.as_str());
                }
            }
            body.push_str("</optgroup>");
        }
        let recent = self
            .releases
            .iter()
            .filter(|release| !offered.contains(release.semver.as_str()))
            .take(RECENT_RELEASES)
            .collect::<Vec<_>>();
        if !recent.is_empty() {
            body.push_str("<optgroup label=\"Recent\">");
            for release in recent {
                option(&mut body, release, "");
                offered.insert(release.semver.as_str());
            }
            body.push_str("</optgroup>");
        }
        if let Some(release) = self
            .release()
            .filter(|release| !offered.contains(release.semver.as_str()))
        {
            body.push_str("<optgroup label=\"Selected\">");
            option(&mut body, release, "");
            body.push_str("</optgroup>");
        }
        body.push_str("</select></label><button type=\"submit\">Show release</button></form>");

        // A second form keeps the typed value out of the select's field name;
        // the server resolves versions, commits, and channel names alike.
        let _ = write!(
            body,
            "<form method=\"get\" action=\"{}\" class=\"release-jump\" role=\"search\">{hidden}<label><span class=\"visually-hidden\">Jump to release</span><input type=\"search\" name=\"release\" data-release-jump placeholder=\"Jump to version, commit, or channel\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\"></label><button type=\"submit\">Go</button><div class=\"filter-suggest release-suggest\" hidden></div></form>",
            escape(action)
        );
        let _ = write!(
            body,
            "<a class=\"release-directory-link\" href=\"/{}/-/releases\">All {} releases →</a>",
            escape(slug),
            self.releases.len()
        );
        if let Some(release) = self.release() {
            let _ = write!(
                body,
                "<a href=\"{}\">View release →</a>",
                escape(&release_href(slug, &release.semver))
            );
        }
        body.push_str(&self.index_json());
        body.push_str("</div>");
        if self.releases.is_empty() {
            body.push_str("<p class=\"dim\">No releases have been published yet.</p>");
        } else if self.selected.is_none() && !self.all_releases {
            body.push_str("<p class=\"dim\">No verified release is available. Choose a release to inspect its contents and verification status.</p>");
        }
        body
    }

    /// Embeds the compact release index that powers the typed jump's typeahead.
    ///
    /// Versions only, plus channel names: a few bytes per release rather than
    /// a rendered option each, and inert data under the strict script policy.
    fn index_json(&self) -> String {
        let channels = self
            .channel_targets()
            .into_iter()
            .map(|(name, version)| serde_json::json!({"name": name, "release": version}))
            .collect::<Vec<_>>();
        let releases = self
            .releases
            .iter()
            .map(|release| {
                serde_json::json!({
                    "version": release.semver,
                    "verified": release.signer.is_some(),
                    "prerelease": is_prerelease(&release.semver),
                })
            })
            .collect::<Vec<_>>();
        let json = serde_json::json!({"channels": channels, "releases": releases})
            .to_string()
            .replace('<', "\\u003c");
        format!("<script type=\"application/json\" data-release-index>{json}</script>")
    }
}

/// Orders releases by semantic precedence, newest first.
pub(crate) fn release_order(left: &str, right: &str) -> Ordering {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(a), Ok(b)) => b.cmp(&a).then_with(|| right.cmp(left)),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => right.cmp(left),
    }
}

pub(crate) fn is_prerelease(version: &str) -> bool {
    semver::Version::parse(version).is_ok_and(|version| !version.pre.is_empty())
}

/// Builds an individual release's stable public URL.
pub(crate) fn release_href(slug: &str, version: &str) -> String {
    format!("/{slug}/-/releases/{}", urlencode(version))
}

pub(crate) fn verification(release: &ReleaseRow) -> &'static str {
    if release.signer.is_some() {
        "<span class=\"ok release-verification\">Verified</span>"
    } else {
        "<span class=\"warn release-verification\">Unverified</span>"
    }
}

/// Renders missing content without substituting a different release.
pub(crate) fn unavailable_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    section: &str,
    message: &str,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let mut body = context.nav(slug, section);
    body.push_str(&context.selector(slug, &format!("/{slug}/-/{section}"), &[]));
    let _ = write!(
        body,
        "<h1>Content unavailable</h1><p>{}</p>",
        escape(message)
    );
    page_with_session(
        "Content unavailable",
        &registry_crumbs(slug, &[]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Converts a retained package catalog into searchable list rows.
pub(crate) fn package_rows(packages: &[PackageToml]) -> Vec<PackageRow> {
    let mut rows = packages
        .iter()
        .map(|package| {
            let version = package.versions.iter().max_by(|a, b| {
                crate::filter::version_key(Some(&a.version))
                    .cmp(&crate::filter::version_key(Some(&b.version)))
            });
            let mut platforms = version
                .map(|version| version.platforms.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            platforms.sort();
            PackageRow {
                name: package.package.name.clone(),
                description: package.package.description.clone(),
                license: package.package.license.clone(),
                latest_version: version.map(|version| version.version.clone()),
                closure_size: version
                    .and_then(|version| {
                        platforms
                            .first()
                            .and_then(|platform| version.platforms.get(platform))
                    })
                    .map(|platform| platform.closure_size),
                platforms,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

/// Builds details entirely from the selected release's package manifest.
pub(crate) fn package_detail(package: &PackageToml) -> PackageDetail {
    let header = &package.package;
    let mut versions = package
        .versions
        .iter()
        .map(|version| {
            let mut platforms = version
                .platforms
                .iter()
                .map(|(name, entry)| PlatformDetail {
                    platform: name.clone(),
                    store_path: entry.store_path.clone(),
                    nar_hash: entry.nar_hash.clone(),
                    nar_size: entry.nar_size,
                    closure_size: entry.closure_size,
                    source_drv: entry.source_drv.clone(),
                    refs: entry.references.hashes().to_vec(),
                    images: entry
                        .images
                        .iter()
                        .map(|image| crate::db::ImageDetail {
                            format: image.format.clone(),
                            store_path: image.store_path.clone(),
                            nar_hash: image.nar_hash.clone(),
                            nar_size: image.nar_size,
                            delivery: image.delivery.clone(),
                        })
                        .collect(),
                })
                .collect::<Vec<_>>();
            platforms.sort_by(|a, b| a.platform.cmp(&b.platform));
            VersionDetail {
                version: version.version.clone(),
                previous: version.previous.clone(),
                platforms,
            }
        })
        .collect::<Vec<_>>();
    versions.sort_by(|a, b| {
        crate::filter::version_key(Some(&b.version))
            .cmp(&crate::filter::version_key(Some(&a.version)))
    });
    PackageDetail {
        name: header.name.clone(),
        description: header.description.clone(),
        homepage: header.homepage.clone(),
        license: header.license.clone(),
        maintainer: header.maintainer.clone(),
        sysroot: header.sysroot,
        versions,
    }
}

/// Resolves both dependency directions inside the selected release catalog.
pub(crate) fn package_closure(
    catalog: &[PackageToml],
    detail: &PackageDetail,
    reverse_limit: usize,
) -> super::browse_pages::PackageClosure {
    use super::browse_pages::{PackageClosure, ResolvedDependency};
    use std::collections::{BTreeMap, BTreeSet};

    let Some(primary) = detail
        .versions
        .first()
        .and_then(|version| version.platforms.first())
    else {
        return PackageClosure::default();
    };
    let hash = |path: &str| {
        path.rsplit('/')
            .next()
            .and_then(|name| name.split_once('-'))
            .map(|(hash, _)| hash.to_string())
    };
    let mut owners = BTreeMap::new();
    let mut reverse = BTreeSet::new();
    let primary_hash = hash(&primary.store_path);
    for package in catalog {
        for version in &package.versions {
            if let Some(platform) = version.platforms.get(&primary.platform) {
                if let Some(hash) = hash(&platform.store_path) {
                    owners.insert(hash, (&package.package.name, &version.version));
                }
                if primary_hash
                    .as_ref()
                    .is_some_and(|hash| platform.references.hashes().contains(hash))
                {
                    reverse.insert((package.package.name.clone(), version.version.clone()));
                }
            }
        }
    }
    let dependencies = primary
        .refs
        .iter()
        .map(|hash| {
            let owner = owners.get(hash);
            ResolvedDependency {
                hash: hash.clone(),
                name: owner.map(|(name, _)| (*name).clone()),
                version: owner.map(|(_, version)| (*version).clone()),
            }
        })
        .collect();
    PackageClosure {
        platform: Some(primary.platform.clone()),
        dependencies,
        reverse_total: reverse.len(),
        reverse: reverse.into_iter().take(reverse_limit).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release(version: &str, commit: &str, verified: bool) -> ReleaseRow {
        ReleaseRow {
            semver: version.into(),
            tag_oid: format!("tag-{version}"),
            commit_oid: commit.into(),
            signer: verified.then(|| "signer".into()),
            tagged_at: Some(1),
            pack_present: true,
        }
    }

    #[test]
    fn initial_selection_uses_all_published_versions_and_respects_explicit_context() {
        let releases = vec![
            release("1.9.0", "main", true),
            release("1.10.0", "maintenance-branch", true),
            release("2.0.0-rc.1", "preview", true),
            release("9.0.0", "unverified", false),
        ];
        let selected = ReleaseContext::select(releases.clone(), None, None, false).unwrap();
        assert_eq!(selected.selected(), Some("1.10.0"));
        assert_eq!(
            selected
                .releases()
                .iter()
                .map(|release| release.semver.as_str())
                .collect::<Vec<_>>(),
            vec!["9.0.0", "2.0.0-rc.1", "1.10.0", "1.9.0"]
        );
        assert_eq!(
            ReleaseContext::select(releases.clone(), Some("1.9.0"), None, false)
                .unwrap()
                .selected(),
            Some("1.9.0")
        );
        assert_eq!(
            ReleaseContext::select(releases.clone(), Some("1.9.0"), Some("preview"), false)
                .unwrap()
                .selected(),
            Some("2.0.0-rc.1")
        );
        assert!(ReleaseContext::select(releases.clone(), Some("missing"), None, false).is_none());
        assert!(ReleaseContext::select(releases.clone(), None, Some("HEAD"), false).is_none());
        assert!(ReleaseContext::select(releases.clone(), None, Some("all"), false).is_none());
        assert!(ReleaseContext::select(releases, None, Some("all"), true)
            .unwrap()
            .is_all());
        let preview = ReleaseContext::select(
            vec![release("2.0.0-rc.1", "preview", true)],
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(preview.selected(), Some("2.0.0-rc.1"));
    }

    fn channel(name: &str, frontier: Option<&str>) -> ChannelSummary {
        ChannelSummary {
            name: name.into(),
            frontier: frontier.map(str::to_string),
            partitions: vec![None; 256],
        }
    }

    #[test]
    fn channel_names_resolve_to_their_current_target_or_nothing() {
        let releases = vec![
            release("1.9.0", "main", true),
            release("1.10.0", "maintenance-branch", true),
            release("2.0.0-rc.1", "preview", true),
        ];
        let channels = vec![
            channel("stable", Some("1.9.0")),
            channel("beta", Some("2.0.0-rc.1")),
            channel("staged", None),
            channel("dangling", Some("3.0.0")),
        ];
        let stable = ReleaseContext::select_among(
            releases.clone(),
            channels.clone(),
            None,
            Some("stable"),
            false,
        )
        .unwrap();
        assert_eq!(stable.selected(), Some("1.9.0"));
        assert_eq!(
            stable.channel_targets(),
            vec![("stable", "1.9.0"), ("beta", "2.0.0-rc.1")]
        );
        assert!(ReleaseContext::select_among(
            releases.clone(),
            channels.clone(),
            None,
            Some("staged"),
            false
        )
        .is_none());
        assert!(ReleaseContext::select_among(
            releases.clone(),
            channels.clone(),
            None,
            Some("dangling"),
            false
        )
        .is_none());
        assert_eq!(
            ReleaseContext::select_among(releases, channels, Some("beta"), None, false)
                .unwrap()
                .selected(),
            Some("2.0.0-rc.1")
        );
    }

    #[test]
    fn selector_offers_channels_and_recent_releases_instead_of_every_tag() {
        let mut releases = (0..120)
            .map(|index| release(&format!("1.{index}.0"), &format!("commit-{index}"), true))
            .collect::<Vec<_>>();
        releases.push(release("0.1.0", "ancient", true));
        let channels = vec![channel("stable", Some("1.100.0"))];
        let context = ReleaseContext::select_among(
            releases.clone(),
            channels.clone(),
            None,
            Some("0.1.0"),
            false,
        )
        .unwrap();
        let html = context.selector("org/main", "/org/main/-/docs", &[("root", "abc")]);
        assert_eq!(html.matches("<option ").count(), 12, "{html}");
        assert!(html.contains(
            "<optgroup label=\"Channels\"><option value=\"1.100.0\">stable → 1.100.0</option>"
        ));
        assert!(
            html.contains("<optgroup label=\"Recent\"><option value=\"1.119.0\">1.119.0</option>")
        );
        assert!(html.contains(
            "<optgroup label=\"Selected\"><option value=\"0.1.0\" selected>0.1.0</option>"
        ));
        assert!(html.contains(
            "class=\"release-pill\" href=\"/org/main/-/docs?release=1.100.0&amp;root=abc\""
        ));
        assert!(html.contains("name=\"release\" data-release-jump"));
        assert!(html.contains("All 121 releases →"));
        assert!(html.contains("\"channels\":[{\"name\":\"stable\",\"release\":\"1.100.0\"}]"));
        assert!(html.contains("<input type=\"hidden\" name=\"root\" value=\"abc\">"));
        assert_eq!(html.matches("name=\"root\" value=\"abc\"").count(), 2);

        let current = ReleaseContext::select_among(releases, channels, None, Some("stable"), false)
            .unwrap()
            .selector("org/main", "/org/main/-/docs", &[]);
        assert!(current.contains("aria-current=\"true\">stable <strong>1.100.0</strong>"));
        assert!(!current.contains("<optgroup label=\"Selected\">"));
    }

    #[test]
    fn navigation_and_initial_redirect_preserve_exact_release_and_filters() {
        let context =
            ReleaseContext::select(vec![release("1.2.3", "branch", true)], None, None, false)
                .unwrap();
        let query = super::super::browse::BrowseQuery::parse(Some(
            "filter=license%20%3D%3D%20MIT&sort=name&dir=asc&page=2",
        ));
        let Some(Rendered::TemporaryRedirect(location)) =
            query.pin_release("/org/main/-/packages", &context)
        else {
            panic!("pin initial release");
        };
        assert!(location.contains("release=1.2.3"));
        assert!(location.contains("page=2"));
        assert!(location.contains("filter=license+%3D%3D+MIT"));
        let nav = context.nav("org/main", "docs");
        for tab in ["packages", "docs", "images", "containers"] {
            assert!(nav.contains(&format!("/{tab}?release=1.2.3")));
        }
        assert!(nav.contains("/-/releases\""));
        assert!(!nav.contains("HEAD"));
    }
}
