//! Release selection and exact package metadata for the public browser.
//!
//! Content links carry `?release=1.2.3`; Images and Containers also accept an
//! explicit `?release=all`. Overview, the release directory, and Channels are
//! registry-wide. An unavailable selection never falls back to live content.

use crate::clock::Instant;
use std::cmp::Ordering;
use std::fmt::Write as _;

use super::browse::Rendered;
use super::browse_pages::{registry_crumbs, registry_nav_at_release, state_line};
use super::console_render::{page_with_session, urlencode, SessionIndicator};
use super::render::escape;
use crate::db::{
    Database, IndexStatus, PackageDetail, PackageRow, PlatformDetail, RegistryRecord, ReleaseRow,
    VersionDetail,
};
use aos_registry_surface::manifest::PackageToml;

/// Exact content selection and available registry release versions.
#[derive(Debug, Clone, Default)]
pub struct ReleaseContext {
    releases: Vec<ReleaseRow>,
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
        let (releases, default) = futures_util::future::join(
            db.list_releases(registry_id),
            db.default_browse_release(registry_id),
        )
        .await;
        Self::select(
            releases.map_err(|_| Rendered::ServiceUnavailable)?,
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
        mut releases: Vec<ReleaseRow>,
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

    /// Builds the shared selector with page-specific filters preserved.
    ///
    /// An explicit action lets detail pages resolve the package in the newly
    /// selected release. Pagination and digests belong to the old selection
    /// and must not be included in `filters`.
    #[must_use]
    pub fn selector(&self, slug: &str, action: &str, filters: &[(&str, &str)]) -> String {
        let mut body = format!(
            "<form method=\"get\" action=\"{}\" class=\"release-selector\">",
            escape(action)
        );
        for (key, value) in filters {
            let _ = write!(
                body,
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape(key),
                escape(value)
            );
        }
        body.push_str("<label>Release <select name=\"release\">");
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
        for release in &self.releases {
            let _ = write!(
                body,
                "<option value=\"{}\"{}>{}{}</option>",
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
        }
        body.push_str("</select></label><button type=\"submit\">Show release</button>");
        if let Some(release) = self.release() {
            let _ = write!(
                body,
                "<a href=\"{}\">View release →</a>{}",
                escape(&release_href(slug, &release.semver)),
                verification(release)
            );
        }
        body.push_str("</form>");
        if self.releases.is_empty() {
            body.push_str("<p class=\"dim\">No releases have been published yet.</p>");
        } else if self.selected.is_none() && !self.all_releases {
            body.push_str("<p class=\"dim\">No verified release is available. Choose a release to inspect its contents and verification status.</p>");
        }
        body
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
