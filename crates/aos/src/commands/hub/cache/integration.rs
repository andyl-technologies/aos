//! Handles hub cache integration commands and their domain-specific request validation.

use crate::cli::{HubCacheIntegrationCmd, HubMutationArgs, HubRegistryCacheStackCmd};
use crate::commands::hub::cache::retention::retention_spec;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::{
    new_idempotency_key, topology_mutation, topology_read, topology_stable_id,
};
use crate::commands::hub::output::print_topology_message;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

fn external_consumer_cache(url: &str) -> Result<hub_types::ExternalConsumerCache> {
    let parsed = reqwest::Url::parse(url).context("parsing external cache URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("external cache URLs use http or https");
    }
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("external cache URLs cannot contain credentials, query, or fragment");
    }
    Ok(hub_types::ExternalConsumerCache {
        url: parsed.to_string(),
    })
}

/// Handles the hub registry cache stack command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn registry_cache_stack(
    printer: &Printer,
    command: &HubRegistryCacheStackCmd,
) -> Result<()> {
    match command {
        HubRegistryCacheStackCmd::Show { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ConsumerCacheStackResponse>(
                printer,
                &client,
                HubTopologyMethod::GetConsumerCacheStack,
                &hub_types::GetConsumerCacheStackRequest {
                    registry_id: registry.clone(),
                },
            )
            .await
        }
        HubRegistryCacheStackCmd::Validate { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ConsumerCacheStackValidationResponse>(
                printer,
                &client,
                HubTopologyMethod::ValidateConsumerCacheStack,
                &hub_types::GetConsumerCacheStackRequest {
                    registry_id: registry.clone(),
                },
            )
            .await
        }
        HubRegistryCacheStackCmd::Add {
            access,
            registry,
            cache,
            url,
            before,
            mirror_with,
            mutation,
        } => {
            let source = match (cache, url) {
                (Some(cache), None) => {
                    hub_types::consumer_cache_stack_entry::Source::BinaryCacheId(cache.clone())
                }
                (None, Some(url)) => hub_types::consumer_cache_stack_entry::Source::External(
                    external_consumer_cache(url)?,
                ),
                _ => anyhow::bail!("exactly one of --cache or --url is required"),
            };
            let entry_id = topology_stable_id(None, "cache-stack-entry");
            registry_cache_stack_mutation(
                printer,
                access,
                registry,
                hub_types::ConsumerCacheChange {
                    operation: "add".into(),
                    entry_id: String::new(),
                    desired: Some(hub_types::ConsumerCacheStackEntry {
                        entry_id,
                        source: Some(source),
                        priority: 0,
                        mirror_group_id: String::new(),
                    }),
                    before_entry_id: before.clone().unwrap_or_default(),
                    mirror_with_entry_id: mirror_with.clone().unwrap_or_default(),
                },
                mutation,
            )
            .await
        }
        HubRegistryCacheStackCmd::Move {
            access,
            registry,
            entry,
            before,
            mutation,
        } => {
            registry_cache_stack_mutation(
                printer,
                access,
                registry,
                hub_types::ConsumerCacheChange {
                    operation: "move".into(),
                    entry_id: entry.clone(),
                    desired: None,
                    before_entry_id: before.clone(),
                    mirror_with_entry_id: String::new(),
                },
                mutation,
            )
            .await
        }
        HubRegistryCacheStackCmd::Remove {
            access,
            registry,
            entry,
            mutation,
        } => {
            registry_cache_stack_mutation(
                printer,
                access,
                registry,
                hub_types::ConsumerCacheChange {
                    operation: "remove".into(),
                    entry_id: entry.clone(),
                    desired: None,
                    before_entry_id: String::new(),
                    mirror_with_entry_id: String::new(),
                },
                mutation,
            )
            .await
        }
    }
}

async fn registry_cache_stack_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    registry: &str,
    change: hub_types::ConsumerCacheChange,
    mutation: &HubMutationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_mutation::<
        _,
        hub_types::ApplyTopologyPlanRequest,
        hub_types::ConsumerCacheChangesetResponse,
        _,
    >(
        printer,
        &client,
        HubTopologyMethod::PlanCreateConsumerCacheChangeset,
        HubTopologyMethod::CreateConsumerCacheChangeset,
        &hub_types::PlanCreateConsumerCacheChangesetRequest {
            registry_id: registry.into(),
            change: Some(change),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyTopologyPlanRequest {
            plan_id: plan_id.into(),
            confirmation_hash: confirmation_hash.into(),
            idempotency_key: idempotency_key.into(),
        },
    )
    .await
}

/// Handles the hub cache integration command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn cache_integration(
    printer: &Printer,
    command: &HubCacheIntegrationCmd,
) -> Result<()> {
    match command {
        HubCacheIntegrationCmd::List {
            access,
            cache,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            match registry {
                Some(registry) => {
                    let response: hub_types::CacheIntegrationResponse = client
                        .call_topology(
                            HubTopologyMethod::GetCacheRegistryIntegration,
                            &hub_types::GetCacheRegistryIntegrationRequest {
                                cache_id: cache.clone(),
                                registry_id: registry.clone(),
                            },
                        )
                        .await?;
                    print_topology_message(
                        printer,
                        &hub_types::ListCacheIntegrationsResponse {
                            integrations: response.integration.into_iter().collect(),
                            next_page_token: String::new(),
                        },
                    )
                }
                None => {
                    topology_read::<_, hub_types::ListCacheIntegrationsResponse>(
                        printer,
                        &client,
                        HubTopologyMethod::ListCacheRegistryIntegrations,
                        &hub_types::ListCacheRegistryIntegrationsRequest {
                            cache_id: cache.clone(),
                            page_size: pagination.page_size.unwrap_or_default(),
                            page_token: pagination.page_token.clone().unwrap_or_default(),
                        },
                    )
                    .await
                }
            }
        }
        HubCacheIntegrationCmd::Show {
            access,
            cache,
            registry,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::CacheIntegrationResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheRegistryIntegration,
                &hub_types::GetCacheRegistryIntegrationRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                },
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Previews cache integration settings without applying the resulting plan.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn preview_cache_integration(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    cache: &str,
    registry: &str,
    use_for_clients: bool,
    retain_current_catalog: bool,
    retain_channels: &[String],
    retain_recent_releases: Option<u32>,
    recent_include_prereleases: bool,
    retain_releases: &[String],
    retain_semver: Option<&str>,
    semver_include_prereleases: bool,
    retain_all_releases: bool,
    populate: Option<&str>,
    population_trigger: Option<&str>,
) -> Result<()> {
    let has_retention = retain_current_catalog
        || !retain_channels.is_empty()
        || retain_recent_releases.is_some()
        || !retain_releases.is_empty()
        || retain_semver.is_some()
        || retain_all_releases;
    if !use_for_clients && !has_retention && populate.is_none() {
        anyhow::bail!("integrate requires publication, retention, or population preview options");
    }
    if population_trigger.is_some() && populate.is_none() {
        anyhow::bail!("--population-trigger requires --populate");
    }
    let publication = use_for_clients.then(|| {
        let entry_id = topology_stable_id(None, "cache-stack-entry");
        hub_types::ConsumerCacheChange {
            operation: "add".into(),
            entry_id: String::new(),
            desired: Some(hub_types::ConsumerCacheStackEntry {
                entry_id,
                source: Some(
                    hub_types::consumer_cache_stack_entry::Source::BinaryCacheId(cache.into()),
                ),
                priority: 0,
                mirror_group_id: String::new(),
            }),
            before_entry_id: String::new(),
            mirror_with_entry_id: String::new(),
        }
    });
    let retention = has_retention
        .then(|| {
            retention_spec(
                retain_current_catalog,
                retain_channels,
                false,
                retain_recent_releases,
                recent_include_prereleases,
                retain_releases,
                retain_semver,
                semver_include_prereleases,
                retain_all_releases,
                None,
            )
        })
        .transpose()?;
    let population = populate.map(|mode| hub_types::PopulationTargetSpec {
        trigger: population_trigger.unwrap_or("release").into(),
        required: mode == "required",
        placement_policy_revision_id: String::new(),
        validation_gate: "integrity".into(),
    });
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_read::<_, hub_types::PreviewCacheIntegrationResponse>(
        printer,
        &client,
        HubTopologyMethod::PreviewCacheIntegration,
        &hub_types::PreviewCacheIntegrationRequest {
            cache_id: cache.into(),
            registry_id: registry.into(),
            publication,
            retention,
            population,
        },
    )
    .await
}
