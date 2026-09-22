//! Handles hub documentation commands and their domain-specific request validation.

use crate::cli::{HubAccessArgs, HubDocumentationCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use crate::commands::hub::output::print_hub_json;
use anyhow::{Context as _, Result};
use aos_core::output::{OutputMode, Printer};
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};
use sha2::{Digest as _, Sha256};

/// Handles the hub documentation command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn documentation(printer: &Printer, command: &HubDocumentationCmd) -> Result<()> {
    match command {
        HubDocumentationCmd::Abilities {
            access,
            registry,
            release,
            platform,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response: hub_types::GetReleaseAbilityGraphResponse = client
                .call_topology(
                    HubTopologyMethod::GetReleaseAbilityGraph,
                    &hub_types::GetReleaseAbilityGraphRequest {
                        registry: registry.clone(),
                        release: release.clone().unwrap_or_default(),
                        platform: platform.clone().unwrap_or_default(),
                    },
                )
                .await?;
            let graph = verify_ability_graph_response(&response)?;
            let identity = response
                .identity
                .as_ref()
                .context("Hub omitted release ability graph identity")?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "identity": {
                        "registry_commit": identity.registry_commit,
                        "release": identity.release,
                        "platform": identity.platform,
                        "graph_sha256": identity.graph_sha256,
                    },
                    "graph": graph,
                }));
            } else {
                print_ability_graph(&graph, identity);
            }
            Ok(())
        }
        HubDocumentationCmd::Search {
            access,
            query,
            registry,
            kind,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::SearchPackageDocumentationResponse>(
                printer,
                &client,
                HubTopologyMethod::SearchPackageDocumentation,
                &hub_types::SearchPackageDocumentationRequest {
                    registry: registry.clone(),
                    query: query.clone(),
                    kind: kind.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubDocumentationCmd::Package {
            access,
            package,
            registry,
            version,
            platform,
        } => {
            let response = fetch_documentation(
                access,
                registry,
                package,
                version.as_deref(),
                platform.as_deref(),
            )
            .await?;
            print_documentation_response(printer, &response)
        }
        HubDocumentationCmd::Option {
            access,
            package,
            registry,
            version,
            platform,
            prefix,
            owner,
            option_type,
            contributable,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListPackageOptionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPackageOptions,
                &hub_types::ListPackageOptionsRequest {
                    registry: registry.clone(),
                    package: package.clone(),
                    version: version.clone().unwrap_or_default(),
                    platform: platform.clone().unwrap_or_default(),
                    prefix: prefix.clone().unwrap_or_default(),
                    owner: owner.clone().unwrap_or_default(),
                    r#type: option_type.clone().unwrap_or_default(),
                    contributable: *contributable,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubDocumentationCmd::Compare {
            access,
            package,
            registry,
            from,
            to,
            platform,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response: hub_types::ComparePackageDocumentationResponse = client
                .call_topology(
                    HubTopologyMethod::ComparePackageDocumentation,
                    &hub_types::ComparePackageDocumentationRequest {
                        registry: registry.clone(),
                        package: package.clone(),
                        from_version: from.clone(),
                        to_version: to.clone(),
                        platform: platform.clone(),
                    },
                )
                .await?;
            let comparison: serde_json::Value =
                serde_json::from_slice(&response.canonical_comparison_json)
                    .context("Hub returned invalid canonical comparison JSON")?;
            if print_hub_json(printer, "documentation_comparison", comparison.clone()) {
                return Ok(());
            }
            println!("{}", serde_json::to_string_pretty(&comparison)?);
            Ok(())
        }
        HubDocumentationCmd::Fetch {
            access,
            package,
            registry,
            version,
            platform,
            output,
        } => {
            let response = fetch_documentation(
                access,
                registry,
                package,
                version.as_deref(),
                platform.as_deref(),
            )
            .await?;
            verify_documentation_response(&response)?;
            std::fs::write(output, &response.canonical_json)
                .with_context(|| format!("writing {}", output.display()))?;
            printer.success(&format!(
                "Wrote verified documentation to {}",
                output.display()
            ));
            Ok(())
        }
        HubDocumentationCmd::Open {
            access,
            package,
            registry,
            version,
            platform,
        } => {
            let response = fetch_documentation(
                access,
                registry,
                package,
                version.as_deref(),
                platform.as_deref(),
            )
            .await?;
            let identity = response
                .identity
                .as_ref()
                .context("Hub omitted package documentation identity")?;
            let (origin, _) = crate::commands::hub_auth::resolve_access(
                access.hub.as_deref(),
                access.token.as_deref(),
            )?;
            let url = documentation_browser_url(
                &origin,
                registry,
                &identity.package,
                &identity.version,
                &identity.platform,
            )?;
            if print_hub_json(
                printer,
                "documentation_url",
                serde_json::json!({ "url": url.as_str() }),
            ) {
                return Ok(());
            }
            println!("{url}");
            Ok(())
        }
    }
}

fn verify_ability_graph_response(
    response: &hub_types::GetReleaseAbilityGraphResponse,
) -> Result<aos_doc_model::ReleaseAbilityGraph> {
    let identity = response
        .identity
        .as_ref()
        .context("Hub omitted release ability graph identity")?;
    let graph = aos_doc_model::ReleaseAbilityGraph::from_canonical_json(&response.canonical_json)
        .context("Hub returned an invalid canonical release ability graph")?;
    let digest = hex::encode(Sha256::digest(&response.canonical_json));
    anyhow::ensure!(
        graph.platform == identity.platform
            && digest == identity.graph_sha256
            && response.etag == identity.graph_sha256,
        "Hub release ability graph identity does not match canonical bytes"
    );
    Ok(graph)
}

fn print_ability_graph(
    graph: &aos_doc_model::ReleaseAbilityGraph,
    identity: &hub_types::ReleaseAbilityGraphIdentity,
) {
    println!(
        "Ability graph for release {} on {}",
        identity.release, graph.platform
    );
    println!("Registry commit: {}", identity.registry_commit);
    println!(
        "{} packages, {} interfaces, {} providers, {} requirements",
        graph.packages.len(),
        graph.interfaces.len(),
        graph.providers.len(),
        graph.requirements.len()
    );

    for interface in &graph.interfaces {
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
        println!(
            "\n{} ABI {} ({} providers, {} consumers)",
            interface.key.name,
            interface.key.abi,
            providers.len(),
            consumers.len()
        );
        for provider in providers {
            println!(
                "  provides: {}@{}/{}",
                provider.id.package.name, provider.id.package.version, provider.id.export
            );
        }
        for consumer in consumers {
            let scope = consumer
                .id
                .implementation
                .as_ref()
                .map_or_else(|| "package".to_string(), ToString::to_string);
            println!(
                "  consumes: {}@{} ({scope})/{}",
                consumer.id.package.name, consumer.id.package.version, consumer.id.alias
            );
        }
    }

    let unresolved = graph
        .requirements
        .iter()
        .filter(|requirement| requirement.matching_providers.is_empty())
        .collect::<Vec<_>>();
    if !unresolved.is_empty() {
        println!("\nUnresolved requirements");
        for requirement in unresolved {
            println!(
                "  {}@{}/{}",
                requirement.id.package.name, requirement.id.package.version, requirement.id.alias
            );
        }
    }
}

fn documentation_browser_url(
    origin: &str,
    registry: &str,
    package: &str,
    version: &str,
    platform: &str,
) -> Result<url::Url> {
    let registry_segments = registry.split('/').collect::<Vec<_>>();
    anyhow::ensure!(
        !registry_segments.is_empty()
            && registry_segments
                .iter()
                .all(|segment| !segment.is_empty() && *segment != "." && *segment != ".."),
        "registry refs contain non-empty canonical path segments"
    );

    let mut url = url::Url::parse(origin).context("parsing Hub URL")?;
    let mut path = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Hub URL cannot carry path segments"))?;
    path.extend(registry_segments);
    path.extend(["-", "docs", package, version, platform]);
    drop(path);

    Ok(url)
}

async fn fetch_documentation(
    access: &HubAccessArgs,
    registry: &str,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
) -> Result<hub_types::GetPackageDocumentationResponse> {
    hub_client(&access.hub, access.token.as_deref())
        .await?
        .call_topology(
            HubTopologyMethod::GetPackageDocumentation,
            &hub_types::GetPackageDocumentationRequest {
                registry: registry.to_string(),
                package: package.to_string(),
                version: version.unwrap_or_default().to_string(),
                platform: platform.unwrap_or_default().to_string(),
            },
        )
        .await
}

fn verify_documentation_response(
    response: &hub_types::GetPackageDocumentationResponse,
) -> Result<aos_doc_model::PackageDocumentationProjection> {
    let identity = response
        .identity
        .as_ref()
        .context("Hub omitted package documentation identity")?;
    let projection = aos_doc_model::PackageDocumentationProjection::from_canonical_json(
        &response.canonical_json,
    )
    .context("Hub returned an invalid canonical package reference")?;
    let document = &projection.document;
    anyhow::ensure!(
        document.package.name == identity.package
            && document.package.version == identity.version
            && document.package.platform == identity.platform
            && projection.document_sha256()? == identity.document_sha256
            && response.etag == identity.document_sha256,
        "Hub documentation identity does not match canonical bytes"
    );
    Ok(projection)
}

fn print_documentation_response(
    printer: &Printer,
    response: &hub_types::GetPackageDocumentationResponse,
) -> Result<()> {
    let projection = verify_documentation_response(response)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::from_slice(&response.canonical_json)?);
    } else {
        print!("{}", projection.render_plain());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documentation_browser_urls_preserve_registry_path_segments() {
        let url = documentation_browser_url(
            "https://hub.example.test",
            "acme/platform/production",
            "nginx",
            "1.30.4",
            "x86_64-linux",
        )
        .unwrap();

        assert_eq!(
            url.as_str(),
            "https://hub.example.test/acme/platform/production/-/docs/nginx/1.30.4/x86_64-linux"
        );
        assert!(
            documentation_browser_url(
                "https://hub.example.test",
                "acme//production",
                "nginx",
                "1.30.4",
                "x86_64-linux",
            )
            .is_err()
        );
    }

    #[test]
    fn release_ability_graph_response_binds_identity_to_canonical_bytes() {
        let graph = aos_doc_model::ReleaseAbilityGraph {
            schema: aos_doc_model::RELEASE_ABILITY_GRAPH_SCHEMA.to_string(),
            platform: "x86_64-linux".to_string(),
            packages: Vec::new(),
            interfaces: Vec::new(),
            providers: Vec::new(),
            requirements: Vec::new(),
        };
        let canonical_json = graph.canonical_json().expect("canonical graph");
        let digest = hex::encode(Sha256::digest(&canonical_json));
        let mut response = hub_types::GetReleaseAbilityGraphResponse {
            identity: Some(hub_types::ReleaseAbilityGraphIdentity {
                registry_commit: "commit".to_string(),
                release: "1.0.0".to_string(),
                platform: graph.platform.clone(),
                graph_sha256: digest.clone(),
            }),
            canonical_json,
            etag: digest,
        };

        assert_eq!(
            verify_ability_graph_response(&response).expect("verified graph"),
            graph
        );
        response.etag = "tampered".to_string();
        assert!(verify_ability_graph_response(&response).is_err());
    }
}
