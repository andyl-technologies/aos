//! Public, no-JavaScript OCI repository browsing pages.
//!
//! These renderers expose only delivery-safe repository, tag, manifest, and
//! platform projections. Publication sessions, retention policy, garbage
//! collection, and mutation controls remain confined to the authenticated
//! management console.

use std::fmt::Write as _;

use crate::clock::Instant;
use crate::db::{
    IndexStatus, OciAdminManifestRecord, OciAdminPlatformRecord, OciAdminRepositoryRecord,
    OciAdminTagRecord, RegistryRecord,
};
use crate::web::browse_pages::{registry_crumbs, registry_nav, state_line};
use crate::web::console_render::{page_with_session, urlencode, Pager, SessionIndicator};
use crate::web::release_browse::ReleaseContext;
use crate::web::render::{escape, human_size, table};
use aos_oci_types::RepositoryName;

fn repository_href(slug: &str, repository: &RepositoryName) -> String {
    format!(
        "/{}/-/containers/repository?repository={}",
        slug,
        urlencode(repository.as_str())
    )
}

fn manifest_href(slug: &str, repository: &RepositoryName, digest: &str) -> String {
    format!(
        "/{}/-/containers/manifest?repository={}&digest={}",
        slug,
        urlencode(repository.as_str()),
        urlencode(digest)
    )
}

fn tag_href(slug: &str, repository: &RepositoryName, tag: &str) -> String {
    format!(
        "/{}/-/containers/tag?repository={}&tag={}",
        slug,
        urlencode(repository.as_str()),
        urlencode(tag)
    )
}

/// Renders containers from signed release roots, independently of mutable tags.
pub(crate) fn release_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    containers: &[crate::db::ReleaseContainerRow],
    authority: Option<&str>,
    query: Option<&str>,
    page_number: usize,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let mut body = context.nav(slug, "containers");
    let filters = query.map(|value| vec![("q", value)]).unwrap_or_default();
    body.push_str(&context.selector(slug, &format!("/{slug}/-/containers"), &filters));
    body.push_str("<h1>Containers</h1>");
    let needle = query.unwrap_or_default().to_lowercase();
    let mut containers = containers
        .iter()
        .filter(|container| {
            (context.is_all() || context.selected() == Some(container.release.as_str()))
                && (container
                    .repository
                    .as_str()
                    .to_lowercase()
                    .contains(&needle)
                    || container.package.to_lowercase().contains(&needle))
        })
        .collect::<Vec<_>>();
    containers.sort_by(|a, b| {
        crate::web::release_browse::release_order(&a.release, &b.release)
            .then_with(|| a.repository.as_str().cmp(b.repository.as_str()))
            .then_with(|| a.package.cmp(&b.package))
    });
    let release = context.query_value().unwrap_or_default();
    let _ = write!(body, "<form method=\"get\" class=\"filter-form\"><input type=\"hidden\" name=\"release\" value=\"{}\"><label>Search containers <input type=\"search\" name=\"q\" value=\"{}\"></label><button>Search</button></form>",
        escape(release), escape(query.unwrap_or_default()));
    let pager = Pager::new(page_number, 25, containers.len());
    let rows = pager
        .slice(&containers)
        .iter()
        .map(|container| {
            let href = format!(
                "{}&release={}",
                manifest_href(slug, &container.repository, &container.digest.to_string()),
                urlencode(&container.release)
            );
            let reference = distribution_reference(authority, &container.repository)
                .map(|base| format!("{base}@{}", container.digest));
            vec![
                format!(
                    "<a href=\"{}\">{}</a>",
                    escape(&crate::web::release_browse::release_href(
                        slug,
                        &container.release
                    )),
                    escape(&container.release)
                ),
                format!(
                    "<a href=\"{}\">{}</a>",
                    escape(&href),
                    escape(&container.package)
                ),
                escape(container.repository.as_str()),
                pull_commands(reference.as_deref()),
                format!("<a href=\"{}\">Platforms and details →</a>", escape(&href)),
            ]
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        body.push_str("<p class=\"dim\">No containers match this release and search.</p>");
    } else {
        let headers = ["release", "container", "repository", "pull", "details"];
        if context.is_all() {
            let page = pager.slice(&containers);
            let mut start = 0;
            while start < page.len() {
                let release = &page[start].release;
                let end = start
                    + page[start..]
                        .iter()
                        .take_while(|row| &row.release == release)
                        .count();
                let _ = write!(
                    body,
                    "<section class=\"release-group\"><h2><a href=\"{}\">Release {}</a></h2>",
                    escape(&crate::web::release_browse::release_href(slug, release)),
                    escape(release)
                );
                body.push_str(&table(&headers, &rows[start..end]));
                body.push_str("</section>");
                start = end;
            }
        } else {
            body.push_str(&table(&headers, &rows));
        }
        body.push_str(&pager.nav(
            &format!("/{slug}/-/containers"),
            &format!(
                "release={}&q={}",
                urlencode(release),
                urlencode(query.unwrap_or_default())
            ),
        ));
    }
    let _ = write!(body, "<details><summary>Repository inventory</summary><p><a href=\"/{}/-/containers/repositories\">Browse repositories and current tags</a></p></details>", escape(slug));
    page_with_session(
        "Containers",
        &registry_crumbs(slug, &[(String::new(), "containers".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

fn distribution_reference(authority: Option<&str>, repository: &RepositoryName) -> Option<String> {
    authority.map(|authority| format!("{authority}/{}", repository.as_str()))
}

fn next_page(href: &str, cursor: Option<&str>) -> String {
    let Some(cursor) = cursor else {
        return String::new();
    };
    let separator = if href.contains('?') { "&amp;" } else { "?" };
    format!(
        "<nav class=\"pagination\" aria-label=\"pagination\"><a rel=\"next\" href=\"{}{}cursor={}\">Next page</a></nav>",
        escape(href),
        separator,
        escape(&urlencode(cursor))
    )
}

fn pull_commands(reference: Option<&str>) -> String {
    let Some(reference) = reference else {
        return "<p class=\"dim\">No ready OCI delivery route is available.</p>".to_string();
    };
    let mut html = String::from("<div class=\"command-list\">");
    for (label, command) in [
        ("Docker", format!("docker pull {reference}")),
        ("nerdctl", format!("nerdctl pull {reference}")),
        ("AOS", format!("aos container pull {reference}")),
    ] {
        let _ = write!(
            html,
            "<div class=\"copy-row container-pull-command\"><strong>{}</strong><code class=\"merge-cmd\">{}</code><button type=\"button\" class=\"hash-copy copy-btn\" data-copy-value=\"{}\" aria-label=\"Copy {} pull command\">copy</button></div>",
            escape(label),
            escape(&command),
            escape(&command),
            escape(label)
        );
    }
    html.push_str("</div>");
    html
}

fn platform_rows(platforms: &[OciAdminPlatformRecord]) -> Vec<Vec<String>> {
    platforms
        .iter()
        .map(|platform| {
            let variant = platform
                .platform
                .variant
                .as_deref()
                .map(|value| format!("/{value}"))
                .unwrap_or_default();
            vec![
                escape(&format!(
                    "{}/{}{variant}",
                    platform.platform.os, platform.platform.architecture
                )),
                escape(&platform.aos_system),
                format!(
                    "<code>{}</code>",
                    escape(&platform.manifest_digest.to_string())
                ),
                platform.layer_count.to_string(),
                escape(&human_size(platform.compressed_byte_size)),
                escape(&human_size(platform.unpacked_byte_size)),
            ]
        })
        .collect()
}

fn manifest_summary(manifest: &OciAdminManifestRecord) -> String {
    let rows = vec![
        vec![
            "Digest".to_string(),
            format!("<code>{}</code>", escape(&manifest.digest.to_string())),
        ],
        vec![
            "Media type".to_string(),
            escape(manifest.media_type.as_str()),
        ],
        vec!["Size".to_string(), escape(&human_size(manifest.byte_size))],
        vec!["Layers".to_string(), manifest.layer_count.to_string()],
        vec![
            "Child manifests".to_string(),
            manifest.child_count.to_string(),
        ],
        vec![
            "Config".to_string(),
            manifest
                .config_digest
                .map(|digest| format!("<code>{}</code>", escape(&digest.to_string())))
                .unwrap_or_else(|| "—".to_string()),
        ],
    ];
    table(&["field", "value"], &rows)
}

/// Renders the public OCI repository index for one visible registry.
#[must_use]
pub fn repository_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    repositories: &[OciAdminRepositoryRecord],
    authority: Option<&str>,
    query: Option<&str>,
    next_cursor: Option<&str>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let mut body = registry_nav(slug, "containers");
    body.push_str(
        "<h1>Containers</h1>\n<p>OCI repositories available through this registry.</p>\n",
    );
    let _ = write!(
        body,
        "<form method=\"get\" action=\"/{}/-/containers/repositories\" class=\"filter-form\"><label>Repository prefix <input name=\"q\" value=\"{}\" autocomplete=\"off\"></label><button type=\"submit\">Filter</button></form>",
        escape(slug),
        escape(query.unwrap_or_default())
    );
    if repositories.is_empty() {
        body.push_str(if query.is_some_and(|value| !value.trim().is_empty()) {
            "<p class=\"dim\">No container repositories match this prefix.</p>"
        } else {
            "<p class=\"dim\">No container repositories have been published yet.</p>"
        });
    } else {
        let rows = repositories
            .iter()
            .map(|repository| {
                let reference = distribution_reference(authority, &repository.name)
                    .unwrap_or_else(|| "route unavailable".to_string());
                vec![
                    format!(
                        "<a href=\"{}\">{}</a>",
                        escape(&repository_href(slug, &repository.name)),
                        escape(repository.name.as_str())
                    ),
                    escape(&repository.description),
                    repository.tag_count.to_string(),
                    repository.manifest_count.to_string(),
                    escape(&human_size(repository.compressed_byte_size)),
                    format!("<code>{}</code>", escape(&reference)),
                ]
            })
            .collect::<Vec<_>>();
        body.push_str(&table(
            &[
                "repository",
                "description",
                "tags",
                "manifests",
                "size",
                "pull reference",
            ],
            &rows,
        ));
    }
    let next_href = query.map_or_else(
        || format!("/{slug}/-/containers/repositories"),
        |query| format!("/{slug}/-/containers/repositories?q={}", urlencode(query)),
    );
    body.push_str(&next_page(&next_href, next_cursor));
    page_with_session(
        &format!("{slug} containers"),
        &registry_crumbs(slug, &[(String::new(), "containers".to_string())]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Renders one public OCI repository and all current tag pointers.
#[must_use]
pub fn repository(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    repository: &OciAdminRepositoryRecord,
    tags: &[OciAdminTagRecord],
    authority: Option<&str>,
    next_cursor: Option<&str>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let base = distribution_reference(authority, &repository.name);
    let mut body = registry_nav(slug, "containers");
    let _ = write!(
        body,
        "<h1>Container repository {}</h1><p>{}</p><p>{} tags · {} manifests · {}</p>",
        escape(repository.name.as_str()),
        escape(&repository.description),
        repository.tag_count,
        repository.manifest_count,
        escape(&human_size(repository.compressed_byte_size))
    );
    body.push_str("<h2>Tags</h2>");
    if tags.is_empty() {
        body.push_str("<p class=\"dim\">No tags are published. Pull commands appear when a published tag identifies an available manifest.</p>");
    } else {
        let rows = tags
            .iter()
            .map(|tag| {
                let digest = tag.digest.to_string();
                vec![
                    format!(
                        "<a href=\"{}\">{}</a>",
                        escape(&tag_href(slug, &repository.name, tag.name.as_str())),
                        escape(tag.name.as_str())
                    ),
                    format!(
                        "<a href=\"{}\"><code>{}</code></a>",
                        escape(&manifest_href(slug, &repository.name, &digest)),
                        escape(&digest)
                    ),
                    escape(tag.media_type.as_str()),
                    escape(&tag.ownership_kind),
                ]
            })
            .collect::<Vec<_>>();
        body.push_str(&table(&["tag", "digest", "media type", "owner"], &rows));
    }
    body.push_str(&next_page(
        &repository_href(slug, &repository.name),
        next_cursor,
    ));
    if let Some(tag) = tags.first() {
        let _ = write!(
            body,
            "<h2>Pull a published image</h2><p>This command pins the current digest of tag <a href=\"{}\">{}</a>. Select another tag above for a different version.</p>",
            escape(&tag_href(slug, &repository.name, tag.name.as_str())),
            escape(tag.name.as_str()),
        );
        let reference = base.map(|base| format!("{base}@{}", tag.digest));
        body.push_str(&pull_commands(reference.as_deref()));
    }
    page_with_session(
        repository.name.as_str(),
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/containers"), "containers".to_string()),
                (String::new(), repository.name.to_string()),
            ],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Renders one public tag with an immutable digest pull and platform matrix.
#[must_use]
pub fn tag(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    repository: &RepositoryName,
    tag: &OciAdminTagRecord,
    manifest: &OciAdminManifestRecord,
    platforms: &[OciAdminPlatformRecord],
    authority: Option<&str>,
    next_cursor: Option<&str>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let base = distribution_reference(authority, repository);
    let tag_reference = base.as_ref().map(|base| format!("{base}:{}", tag.name));
    let digest_reference = base.as_ref().map(|base| format!("{base}@{}", tag.digest));
    let mut body = registry_nav(slug, "containers");
    let _ = write!(
        body,
        "<h1>{}:{}</h1><p>Current <strong>{}</strong> tag owned by {}.</p>",
        escape(repository.as_str()),
        escape(tag.name.as_str()),
        escape(tag.name.as_str()),
        escape(&tag.ownership_kind)
    );
    body.push_str("<h2>Pull by tag</h2>");
    body.push_str(&pull_commands(tag_reference.as_deref()));
    body.push_str("<h2>Pull immutably</h2>");
    body.push_str(&pull_commands(digest_reference.as_deref()));
    body.push_str("<h2>Manifest</h2>");
    body.push_str(&manifest_summary(manifest));
    body.push_str("<h2>Runnable platforms</h2>");
    body.push_str(&table(
        &[
            "platform",
            "AOS system",
            "manifest",
            "layers",
            "compressed",
            "unpacked",
        ],
        &platform_rows(platforms),
    ));
    body.push_str(&next_page(
        &tag_href(slug, repository, tag.name.as_str()),
        next_cursor,
    ));
    page_with_session(
        &format!("{}:{}", repository, tag.name),
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/containers"), "containers".to_string()),
                (repository_href(slug, repository), repository.to_string()),
                (String::new(), tag.name.to_string()),
            ],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Renders one immutable public manifest and its runnable platform matrix.
#[must_use]
pub fn manifest(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    repository: &RepositoryName,
    manifest: &OciAdminManifestRecord,
    platforms: &[OciAdminPlatformRecord],
    authority: Option<&str>,
    next_cursor: Option<&str>,
    context: Option<&ReleaseContext>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let reference = distribution_reference(authority, repository)
        .map(|base| format!("{base}@{}", manifest.digest));
    let mut body = context
        .map(|context| context.nav(slug, "containers"))
        .unwrap_or_else(|| registry_nav(slug, "containers"));
    if let Some(context) = context {
        body.push_str(&context.selector(
            slug,
            &format!("/{slug}/-/containers/repository"),
            &[("repository", repository.as_str())],
        ));
    }
    let _ = write!(body, "<h1>{}</h1>", escape(repository.as_str()));
    body.push_str("<h2>Pull</h2>");
    body.push_str(&pull_commands(reference.as_deref()));
    body.push_str("<details><summary>Details</summary>");
    body.push_str(&manifest_summary(manifest));
    body.push_str("</details>");
    body.push_str("<h2>Runnable platforms</h2>");
    body.push_str(&table(
        &[
            "platform",
            "AOS system",
            "manifest",
            "layers",
            "compressed",
            "unpacked",
        ],
        &platform_rows(platforms),
    ));
    body.push_str(&next_page(
        &format!(
            "{}{}",
            manifest_href(slug, repository, &manifest.digest.to_string()),
            context
                .and_then(ReleaseContext::selected)
                .map(|release| format!("&release={}", urlencode(release)))
                .unwrap_or_default()
        ),
        next_cursor,
    ));
    page_with_session(
        "container manifest",
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/containers"), "containers".to_string()),
                (repository_href(slug, repository), repository.to_string()),
                (String::new(), manifest.digest.to_string()),
            ],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_oci_types::{MediaType, Sha256Digest, Tag};

    #[test]
    fn repository_pull_uses_a_published_digest_and_never_assumes_latest() {
        let registry = RegistryRecord {
            id: 1,
            stable_id: "registry:test".into(),
            scope_key: "registry:test".into(),
            owner_scope_key: "instance".into(),
            slug: "demo".into(),
            trust_keys: vec![],
            require_signatures: true,
            org_id: None,
            project_path: String::new(),
            visibility: "public".into(),
            crawl_policy: "allow_all".into(),
            llms_txt_body: None,
            resource_version: 1,
            updated_at: 0,
        };
        let record = OciAdminRepositoryRecord {
            id: 1,
            registry_id: 1,
            name: RepositoryName::parse("systems/minimal").unwrap(),
            description: String::new(),
            inherited_visibility: "public".into(),
            lifecycle_state: "active".into(),
            resource_version: 1,
            metadata_resource_version: 1,
            manifest_count: 1,
            compressed_byte_size: 1,
            unique_byte_size: 1,
            tag_count: 1,
            created_at: 0,
            updated_at: 0,
        };
        let digest = format!("sha256:{}", "a".repeat(64));
        let tags = [OciAdminTagRecord {
            name: Tag::parse("2026.09").unwrap(),
            digest: Sha256Digest::parse(&digest).unwrap(),
            media_type: MediaType::OciImageManifest,
            ownership_kind: "release".into(),
            release: Some("2026.09".into()),
            channel: None,
            resource_version: 1,
            created_at: 0,
            updated_at: 0,
        }];
        let render = |tags: &[OciAdminTagRecord], authority| {
            repository(
                &registry,
                None,
                &record,
                tags,
                authority,
                None,
                Instant::now(),
                &SessionIndicator::default(),
            )
        };
        let html = render(&tags, Some("oci.example"));
        for client in ["docker", "nerdctl", "aos container"] {
            assert!(html.contains(&format!(
                "{client} pull oci.example/systems/minimal@{digest}"
            )));
        }
        assert!(!html.contains("pull oci.example/systems/minimal</code>"));
        assert!(!html.contains(":latest"));
        assert!(
            html.find("<h2>Tags</h2>").unwrap()
                < html.find("<h2>Pull a published image</h2>").unwrap()
        );
        let empty = render(&[], Some("oci.example"));
        assert!(empty.contains("No tags are published"));
        assert!(!empty.contains("docker pull"));
        let unavailable = render(&tags, None);
        assert!(unavailable.contains("No ready OCI delivery route"));
        assert!(!unavailable.contains("docker pull"));
    }
}
