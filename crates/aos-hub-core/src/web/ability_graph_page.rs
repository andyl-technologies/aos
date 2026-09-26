//! Release-wide ability graph rendering for the shared Hub browser.

use std::fmt::Write as _;

use crate::clock::Instant;
use crate::db::{IndexStatus, RegistryRecord};

use super::browse_pages::{registry_crumbs, state_line};
use super::console_render::{SessionIndicator, page_with_session, urlencode};
use super::release_browse::ReleaseContext;
use super::render::{escape, hash_value};

/// Renders the release-wide provider, consumer, and interface contract graph.
#[must_use]
pub fn page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    graph: &aos_doc_model::ReleaseAbilityGraph,
    platforms: &[String],
    digest: &str,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let release = context.selected().unwrap_or_default();
    let mut body = context.nav(slug, "abilities");
    body.push_str("<h1>Abilities</h1>");
    body.push_str(&context.selector(slug, &format!("/{slug}/-/abilities"), &[]));
    if platforms.len() > 1 {
        body.push_str("<nav class=\"chips\" aria-label=\"Ability graph platforms\">");
        for platform in platforms {
            let current = (platform == &graph.platform)
                .then_some(" aria-current=\"page\"")
                .unwrap_or_default();
            let _ = write!(
                body,
                "<a class=\"chip\"{} href=\"/{}/-/abilities?release={}&amp;platform={}\">{}</a> ",
                current,
                escape(slug),
                urlencode(release),
                urlencode(platform),
                escape(platform),
            );
        }
        body.push_str("</nav>");
    }
    let _ = write!(
        body,
        "<p class=\"lede\">Shared contracts and package relationships for release <strong>{}</strong> on <code>{}</code>.</p>",
        escape(release),
        escape(&graph.platform),
    );
    let _ = write!(
        body,
        "<p><a href=\"/{}/-/api/v1/abilities?release={}&amp;platform={}\">Canonical release ability graph JSON</a></p>",
        escape(slug),
        urlencode(release),
        urlencode(&graph.platform),
    );
    let _ = write!(
        body,
        "<dl class=\"meta\"><dt>Packages</dt><dd>{}</dd><dt>Interfaces</dt><dd>{}</dd><dt>Providers</dt><dd>{}</dd><dt>Requirements</dt><dd>{}</dd><dt>Graph digest</dt><dd>{}</dd></dl>",
        graph.packages.len(),
        graph.interfaces.len(),
        graph.providers.len(),
        graph.requirements.len(),
        hash_value(digest),
    );

    body.push_str("<h2>Packages</h2><table><thead><tr><th>package</th><th>version</th><th>provides</th><th>consumes</th></tr></thead><tbody>");
    for package in &graph.packages {
        let provider_count = graph
            .providers
            .iter()
            .filter(|provider| provider.id.package == package.id)
            .count();
        let requirement_count = graph
            .requirements
            .iter()
            .filter(|requirement| requirement.id.package == package.id)
            .count();
        let _ = write!(
            body,
            "<tr id=\"{}\"><td><a href=\"{}\">{}</a></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape(&package_anchor(
                package.id.name.as_str(),
                &package.id.version
            )),
            escape(&package_href(slug, release, package.id.name.as_str())),
            escape(package.id.name.as_str()),
            escape(&package.id.version),
            provider_count,
            requirement_count,
        );
    }
    body.push_str("</tbody></table>");

    body.push_str("<h2>Shared interface contracts</h2>");
    if graph.interfaces.is_empty() {
        body.push_str("<p class=\"dim\">This release publishes no ability interfaces.</p>");
    }
    for interface in &graph.interfaces {
        let anchor = interface_anchor(&interface.key);
        let providers = graph
            .providers
            .iter()
            .filter(|provider| provider.interface == interface.key)
            .collect::<Vec<_>>();
        let consumers = graph
            .requirements
            .iter()
            .filter(|requirement| requirement.matching_interfaces.contains(&interface.key))
            .collect::<Vec<_>>();
        let _ = write!(
            body,
            "<article class=\"ability-interface\"><h3 id=\"{}\">{} <span class=\"dim\">ABI {}</span></h3><p>{}</p><dl class=\"meta\"><dt>Descriptor</dt><dd>{}</dd><dt>Providers</dt><dd>{}</dd><dt>Consumers</dt><dd>{}</dd></dl>",
            escape(&anchor),
            escape(interface.key.name.as_str()),
            interface.key.abi,
            escape(&interface.document.interface.description),
            hash_value(&interface.key.descriptor.to_string()),
            providers.len(),
            consumers.len(),
        );
        if interface.document.interface.methods.is_empty() {
            body.push_str("<p class=\"dim\">This interface declares no callable methods.</p>");
        } else {
            body.push_str("<h4>Methods</h4><dl>");
            for (name, method) in &interface.document.interface.methods {
                let _ = write!(
                    body,
                    "<dt><code>{}</code></dt><dd>{}</dd>",
                    escape(name.as_str()),
                    escape(&method.description),
                );
            }
            body.push_str("</dl>");
        }
        if interface.document.interface.configuration.is_some() {
            body.push_str(
                "<p><strong>Operator configuration:</strong> supported by this interface.</p>",
            );
        }
        if !interface.document.interface.guarantees.is_empty() {
            body.push_str("<h4>Interface guarantees</h4><ul>");
            for guarantee in &interface.document.interface.guarantees {
                let _ = write!(
                    body,
                    "<li>{} v{} · {}</li>",
                    escape(guarantee.name.as_str()),
                    guarantee.version,
                    hash_value(&guarantee.descriptor.to_string()),
                );
            }
            body.push_str("</ul>");
        }
        body.push_str("<h4>Provided by</h4>");
        if providers.is_empty() {
            body.push_str("<p class=\"warn\">No public provider is published in this release.</p>");
        } else {
            body.push_str("<ul>");
            for provider in providers {
                let _ = write!(
                    body,
                    "<li><a href=\"{}\">{} <code>{}</code></a> via implementation <code>{}</code></li>",
                    escape(&package_href(
                        slug,
                        release,
                        provider.id.package.name.as_str()
                    )),
                    escape(provider.id.package.name.as_str()),
                    escape(provider.id.export.as_str()),
                    escape(provider.implementation.as_str()),
                );
            }
            body.push_str("</ul>");
        }
        body.push_str("<h4>Consumed by</h4>");
        if consumers.is_empty() {
            body.push_str(
                "<p class=\"dim\">No package in this release consumes this contract.</p>",
            );
        } else {
            body.push_str("<ul>");
            for requirement in consumers {
                let scope = requirement
                    .id
                    .implementation
                    .as_ref()
                    .map_or("package", aos_ability_model::LocalKey::as_str);
                let resolution = match requirement.matching_providers.len() {
                    0 => "unresolved",
                    1 => "one matching provider",
                    _ => "multiple matching providers",
                };
                let provider_links = requirement
                    .matching_providers
                    .iter()
                    .map(|provider| {
                        format!(
                            "<a href=\"{}\">{} <code>{}</code></a>",
                            escape(&package_href(slug, release, provider.package.name.as_str())),
                            escape(provider.package.name.as_str()),
                            escape(provider.export.as_str()),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = write!(
                    body,
                    "<li><a href=\"{}\">{}</a> <code>{}/{}</code> — {}{}</li>",
                    escape(&package_href(
                        slug,
                        release,
                        requirement.id.package.name.as_str()
                    )),
                    escape(requirement.id.package.name.as_str()),
                    escape(scope),
                    escape(requirement.id.alias.as_str()),
                    resolution,
                    if provider_links.is_empty() {
                        String::new()
                    } else {
                        format!(" · {provider_links}")
                    },
                );
            }
            body.push_str("</ul>");
        }
        body.push_str("</article>");
    }

    let unresolved = graph
        .requirements
        .iter()
        .filter(|requirement| requirement.matching_providers.is_empty())
        .collect::<Vec<_>>();
    let ambiguous = graph
        .requirements
        .iter()
        .filter(|requirement| requirement.matching_providers.len() > 1)
        .collect::<Vec<_>>();
    body.push_str("<h2>Resolution status</h2>");
    render_requirement_status(&mut body, slug, release, "Unresolved", &unresolved);
    render_requirement_status(&mut body, slug, release, "Multiple providers", &ambiguous);

    page_with_session(
        "Abilities",
        &registry_crumbs(
            slug,
            &[(
                format!("/{slug}/-/abilities?release={}", urlencode(release)),
                "abilities".to_string(),
            )],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

fn render_requirement_status(
    body: &mut String,
    slug: &str,
    release: &str,
    title: &str,
    requirements: &[&aos_doc_model::ReleaseAbilityRequirement],
) {
    let _ = write!(body, "<h3>{} ({})</h3>", escape(title), requirements.len());
    if requirements.is_empty() {
        body.push_str("<p class=\"dim\">None.</p>");
        return;
    }
    body.push_str("<ul>");
    for requirement in requirements {
        let _ = write!(
            body,
            "<li><a href=\"{}\">{}</a> <code>{}</code> — {}</li>",
            escape(&package_href(
                slug,
                release,
                requirement.id.package.name.as_str()
            )),
            escape(requirement.id.package.name.as_str()),
            escape(requirement.id.alias.as_str()),
            escape(&requirement.declaration.description),
        );
    }
    body.push_str("</ul>");
}

fn package_href(slug: &str, release: &str, package: &str) -> String {
    format!(
        "/{slug}/-/packages/{}?release={}#abilities",
        urlencode(package),
        urlencode(release),
    )
}

fn interface_anchor(interface: &aos_ability_model::InterfaceKey) -> String {
    format!(
        "interface-{}-{}-{}",
        interface.name.as_str().replace('.', "-"),
        interface.abi,
        interface.descriptor,
    )
}

fn package_anchor(package: &str, version: &str) -> String {
    format!(
        "package-{}-{}",
        package.replace('.', "-"),
        version.replace('.', "-")
    )
}

#[cfg(test)]
mod tests {
    use aos_ability_model::LocalKey;
    use aos_contract::Sha256Digest;

    use super::*;
    use crate::db::{RegistryRecord, ReleaseRow};

    fn registry() -> RegistryRecord {
        RegistryRecord {
            id: 1,
            stable_id: "registry:00000000000000000000000000000001".into(),
            scope_key: "registry:00000000000000000000000000000001".into(),
            owner_scope_key: "instance".into(),
            slug: "core".into(),
            trust_keys: vec!["core:Ed25519:AAAA".into()],
            require_signatures: true,
            org_id: None,
            project_path: String::new(),
            visibility: "public".into(),
            crawl_policy: "allow_all".into(),
            llms_txt_body: None,
            resource_version: 1,
            updated_at: 0,
        }
    }

    #[test]
    fn release_graph_page_links_packages_and_canonical_bytes() {
        let release = ReleaseRow {
            semver: "1.2.3".into(),
            tag_oid: "tag".into(),
            commit_oid: "commit".into(),
            signer: Some("signer".into()),
            tagged_at: Some(1),
            pack_present: true,
        };
        let context = ReleaseContext::select(vec![release], None, Some("1.2.3"), false)
            .expect("release context");
        let graph = aos_doc_model::ReleaseAbilityGraph {
            schema: aos_doc_model::RELEASE_ABILITY_GRAPH_SCHEMA.into(),
            platform: "x86_64-linux".into(),
            packages: vec![aos_doc_model::ReleaseAbilityPackage {
                id: aos_doc_model::ReleaseAbilityPackageId {
                    name: LocalKey::new("demo-service").expect("package name"),
                    version: "1.2.3".into(),
                },
                manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
                package_digest: Sha256Digest::of_bytes(b"package"),
            }],
            interfaces: Vec::new(),
            providers: Vec::new(),
            requirements: Vec::new(),
        };

        let html = page(
            &registry(),
            None,
            &context,
            &graph,
            &["x86_64-linux".into()],
            &"a".repeat(64),
            Instant::now(),
            &SessionIndicator::default(),
        );

        assert!(html.contains("aria-current=\"page\">Abilities</a>"));
        assert!(
            html.contains(
                "href=\"/core/-/api/v1/abilities?release=1.2.3&amp;platform=x86_64-linux\""
            )
        );
        assert!(html.contains("id=\"package-demo-service-1-2-3\""));
        assert!(html.contains("href=\"/core/-/packages/demo-service?release=1.2.3#abilities\""));
    }
}
