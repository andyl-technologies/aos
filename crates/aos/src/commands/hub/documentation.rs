//! Handles hub documentation commands and their domain-specific request validation.

use crate::cli::{HubAccessArgs, HubDocumentationCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use crate::commands::hub::output::print_hub_json;
use anyhow::{Context as _, Result};
use aos_core::output::{OutputMode, Printer};
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub documentation command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn documentation(printer: &Printer, command: &HubDocumentationCmd) -> Result<()> {
    match command {
        HubDocumentationCmd::Search {
            access,
            query,
            registry,
            kind,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
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
            let client = hub_client(&access.hub, access.token.as_deref())?;
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
            let client = hub_client(&access.hub, access.token.as_deref())?;
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
    hub_client(&access.hub, access.token.as_deref())?
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
) -> Result<aos_doc_model::PackageDocumentation> {
    let identity = response
        .identity
        .as_ref()
        .context("Hub omitted package documentation identity")?;
    let document =
        aos_doc_model::PackageDocumentation::from_canonical_json(&response.canonical_json)
            .context("Hub returned invalid canonical package documentation")?;
    anyhow::ensure!(
        document.package.name == identity.package
            && document.package.version == identity.version
            && document.package.platform == identity.platform
            && document.document_sha256()? == identity.document_sha256
            && response.etag == identity.document_sha256,
        "Hub documentation identity does not match canonical bytes"
    );
    Ok(document)
}

fn print_documentation_response(
    printer: &Printer,
    response: &hub_types::GetPackageDocumentationResponse,
) -> Result<()> {
    let document = verify_documentation_response(response)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::from_slice(&response.canonical_json)?);
    } else {
        print!("{}", document.render_plain());
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
}
