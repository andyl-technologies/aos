//! Handles hub documentation commands and their domain-specific request validation.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{HubAccessArgs, HubDocumentationCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use crate::commands::hub::output::print_hub_json;
use crate::commands::input::read_bounded_file;
use anyhow::{Context as _, Result};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use aos_doc_model::runtime::deployment::{
    NativeDeploymentReport, NativePackageIdentity, NativeReleaseGraph, ReleasedReference,
};
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};
#[cfg(test)]
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
                print_ability_graph(&graph, identity)?;
            }
            Ok(())
        }
        HubDocumentationCmd::Report {
            access,
            transaction,
            outputs,
            expected_digest,
            registry,
            release,
            package,
            version,
            platform,
            deployment,
            sequence,
            reporter_resource_version,
            valid_for_seconds,
        } => {
            let bytes = read_bounded_file(
                transaction,
                aos_doc_model::runtime::MAX_RUNTIME_DOCUMENT_BYTES as u64,
                "native desired transaction",
            )?;
            if let Some(expected) = expected_digest {
                anyhow::ensure!(
                    Sha256Digest::of_bytes(&bytes) == Sha256Digest::parse(expected)?,
                    "native transaction differs from its independent digest"
                );
            }
            let document = aos_doc_model::runtime::RuntimeDocument::from_json(&bytes)?;
            let graph = document
                .transaction_graph()
                .context("report requires a native desired package transaction")?;
            anyhow::ensure!(
                document.value()["system"] == platform.as_str(),
                "transaction platform differs from reporter selection"
            );
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response: hub_types::GetPackageAbilityReferenceResponse = client
                .call_topology(
                    HubTopologyMethod::GetPackageAbilityReference,
                    &hub_types::GetPackageAbilityReferenceRequest {
                        registry: registry.clone(),
                        package: package.clone(),
                        version: version.clone(),
                        platform: platform.clone(),
                        release: release.clone().unwrap_or_default(),
                    },
                )
                .await?;
            let identity = response
                .identity
                .as_ref()
                .context("Hub omitted native reference identity")?;
            anyhow::ensure!(
                identity.package == *package
                    && identity.version == *version
                    && identity.platform == *platform
                    && release
                        .as_ref()
                        .is_none_or(|release| *release == identity.release)
                    && !identity.release_snapshot_id.is_empty()
                    && Sha256Digest::of_bytes(&response.canonical_json)
                        == Sha256Digest::parse(&identity.document_sha256)?
                    && response.etag == identity.document_sha256,
                "Hub native reference differs from selected signed identity"
            );
            let reference = ReleasedReference {
                identity: NativePackageIdentity {
                    registry_commit: identity.registry_commit.clone(),
                    package: identity.package.clone(),
                    version: identity.version.clone(),
                    platform: identity.platform.clone(),
                    document_sha256: Sha256Digest::parse(&identity.document_sha256)?,
                },
                reference_json: String::from_utf8(response.canonical_json)?,
            };
            let reported_outputs = match outputs {
                Some(path) => serde_json::from_slice(&read_bounded_file(
                    path,
                    aos_doc_model::runtime::MAX_RUNTIME_DOCUMENT_BYTES as u64,
                    "reported native outputs",
                )?)?,
                None => Default::default(),
            };
            let report = NativeDeploymentReport {
                schema: "aos.module.deployment-report".into(),
                deployment: deployment.clone(),
                sequence: *sequence,
                package: reference.identity.clone(),
                graph: serde_json::to_value(graph.graph())?,
                reported_outputs,
                reported_at_unix_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .context("system clock precedes Unix epoch")?
                    .as_secs(),
                valid_for_seconds: *valid_for_seconds,
            };
            report.validate_reference(&reference)?;
            let canonical_json = report.canonical_bytes()?;
            let accepted: hub_types::PackageAbilityDeploymentResponse = client
                .call_topology(
                    HubTopologyMethod::ReportPackageAbilityDeployment,
                    &hub_types::ReportPackageAbilityDeploymentRequest {
                        registry: registry.clone(),
                        deployment: deployment.clone(),
                        reporter_resource_version: *reporter_resource_version,
                        canonical_json: canonical_json.clone(),
                    },
                )
                .await?;
            anyhow::ensure!(
                accepted.canonical_json == canonical_json,
                "Hub changed native reporter assertion bytes"
            );
            printer.json(&serde_json::json!({"report":report,"authority":accepted.authority,"receivedAt":accepted.received_at,"expiresAt":accepted.expires_at,"liveStateVerified":false}));
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
            extensible,
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
                    extensible: *extensible,
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
            let comparison: aos_doc_model::runtime::NativeComparison =
                serde_json::from_slice(&response.canonical_comparison_json)
                    .context("Hub returned invalid native comparison JSON")?;
            anyhow::ensure!(
                comparison.schema == "aos.module.documentation.comparison"
                    && comparison.package == *package
                    && comparison.from_version == *from
                    && comparison.to_version == *to
                    && comparison.platform == *platform,
                "Hub comparison differs from the selected native coordinates"
            );
            let comparison = serde_json::to_value(comparison)?;
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
            verify_documentation_response(&response)?;
            let mut url = documentation_browser_url(
                &origin,
                registry,
                &identity.package,
                &identity.version,
                &identity.platform,
            )?;
            url.query_pairs_mut()
                .append_pair("release", &identity.release)
                .append_pair("digest", &identity.document_sha256);
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
) -> Result<NativeReleaseGraph> {
    let identity = response
        .identity
        .as_ref()
        .context("Hub omitted native release reference identity")?;
    let graph = NativeReleaseGraph::decode(&response.canonical_json)?;
    anyhow::ensure!(
        graph.platform == identity.platform
            && graph.registry_commit == identity.registry_commit
            && graph.release == identity.release
            && Sha256Digest::of_bytes(&response.canonical_json)
                == Sha256Digest::parse(&identity.graph_sha256)?
            && response.etag == identity.graph_sha256,
        "Hub native release graph identity differs from its exact bytes"
    );
    Ok(graph)
}

fn print_ability_graph(
    graph: &NativeReleaseGraph,
    identity: &hub_types::ReleaseAbilityGraphIdentity,
) -> Result<()> {
    println!(
        "Native declarations for release {} on {} (commit {})",
        identity.release, graph.platform, identity.registry_commit
    );
    for reference in &graph.references {
        println!(
            "\n{} {}",
            reference.identity.package, reference.identity.version
        );
        let document = reference.check()?;
        print!("{}", document.render_plain());
    }
    Ok(())
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
    let response: hub_types::GetPackageDocumentationResponse =
        hub_client(&access.hub, access.token.as_deref())
            .await?
            .call_topology(
                HubTopologyMethod::GetPackageDocumentation,
                &hub_types::GetPackageDocumentationRequest {
                    registry: registry.to_string(),
                    package: package.to_string(),
                    version: version.unwrap_or_default().to_string(),
                    platform: platform.unwrap_or_default().to_string(),
                    release: String::new(),
                },
            )
            .await?;
    verify_documentation_response(&response)?;
    let identity = response
        .identity
        .as_ref()
        .context("Hub omitted package documentation identity")?;
    anyhow::ensure!(
        identity.package == package
            && version.is_none_or(|selected| selected == identity.version)
            && platform.is_none_or(|selected| selected == identity.platform),
        "Hub returned a different package documentation selection"
    );
    Ok(response)
}

fn verify_documentation_response(
    response: &hub_types::GetPackageDocumentationResponse,
) -> Result<aos_doc_model::runtime::RuntimeDocument> {
    let identity = response
        .identity
        .as_ref()
        .context("Hub omitted package documentation identity")?;
    anyhow::ensure!(
        identity.format == aos_doc_model::runtime::MODULE_DOCUMENTATION_SCHEMA
            && !identity.release.is_empty()
            && !identity.release_snapshot_id.is_empty()
            && matches!(identity.registry_commit.len(), 40 | 64)
            && identity
                .registry_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && matches!(identity.verified_tag_oid.len(), 40 | 64)
            && identity
                .verified_tag_oid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && response.canonical_json.len() as u64 == identity.document_size
            && Sha256Digest::of_bytes(&response.canonical_json)
                == Sha256Digest::parse(&identity.document_sha256)?
            && response.etag == identity.document_sha256,
        "Hub documentation identity does not match exact native bytes"
    );
    let document = aos_doc_model::runtime::RuntimeDocument::from_json(&response.canonical_json)?;
    document.verify_package_identity(&identity.package, &identity.version, &identity.platform)?;
    Ok(document)
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
    fn native_documentation_verification_preserves_exact_signed_bytes() {
        let bytes = br#"{"schema":"aos.module.documentation","scope":["package","sample"],"system":"x86_64-linux","packages":[{"name":"sample","version":"1"}],"options":[],"abilities":{}}"#.to_vec();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        let mut response = hub_types::GetPackageDocumentationResponse {
            identity: Some(hub_types::PackageDocumentationIdentity {
                registry_commit: "a".repeat(40),
                package: "sample".into(),
                version: "1".into(),
                platform: "x86_64-linux".into(),
                format: aos_doc_model::runtime::MODULE_DOCUMENTATION_SCHEMA.into(),
                document_sha256: digest.clone(),
                document_size: bytes.len() as u64,
                release: "1.0.0".into(),
                verified_tag_oid: "b".repeat(40),
                release_snapshot_id: "verified".into(),
                ..Default::default()
            }),
            canonical_json: bytes,
            etag: digest,
        };

        assert!(verify_documentation_response(&response).is_ok());
        response.canonical_json.push(b' ');
        assert!(verify_documentation_response(&response).is_err());
        response.canonical_json.pop();
        response.identity.as_mut().unwrap().platform = "aarch64-linux".into();
        assert!(verify_documentation_response(&response).is_err());
    }

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
        let graph = NativeReleaseGraph {
            schema: "aos.module.release-graph".into(),
            release: "1.0.0".into(),
            registry_commit: "a".repeat(40),
            platform: "x86_64-linux".into(),
            references: Vec::new(),
        };
        let canonical_json = graph.canonical_bytes().expect("native graph");
        let digest = Sha256Digest::of_bytes(&canonical_json).to_string();
        let mut response = hub_types::GetReleaseAbilityGraphResponse {
            identity: Some(hub_types::ReleaseAbilityGraphIdentity {
                registry_commit: graph.registry_commit.clone(),
                release: "1.0.0".to_string(),
                platform: graph.platform.clone(),
                graph_sha256: digest.clone(),
            }),
            canonical_json: canonical_json.clone(),
            etag: digest,
        };

        assert_eq!(
            verify_ability_graph_response(&response)
                .expect("verified graph")
                .canonical_bytes()
                .unwrap(),
            canonical_json
        );
        response.etag = "tampered".to_string();
        assert!(verify_ability_graph_response(&response).is_err());
    }
}
