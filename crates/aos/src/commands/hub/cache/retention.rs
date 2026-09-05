//! Handles hub cache retention commands and their domain-specific request validation.

use crate::cli::HubCacheRetentionCmd;
use crate::commands::hub::cache::mutation::cache_plan_mutation;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::{parse_duration_seconds, sorted_unique};
use crate::commands::hub::mutation::{
    new_idempotency_key, required_plan_version, topology_operation_mutation, topology_read,
};
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Builds a retention policy from the selected CLI roots and history limits.
///
/// # Errors
///
/// Returns an error if no selector is supplied or the removal-grace duration is invalid.
pub(super) fn retention_spec(
    current_catalog: bool,
    channels: &[String],
    all_channel_targets: bool,
    recent_releases: Option<u32>,
    recent_include_prereleases: bool,
    releases: &[String],
    semver: Option<&str>,
    semver_include_prereleases: bool,
    all_releases: bool,
    removal_grace: Option<&str>,
) -> Result<hub_types::RetentionSubscriptionSpec> {
    if !current_catalog
        && channels.is_empty()
        && !all_channel_targets
        && recent_releases.is_none()
        && releases.is_empty()
        && semver.is_none()
        && !all_releases
    {
        anyhow::bail!("retention set requires at least one retention selector");
    }
    let channel_targets = if all_channel_targets || !channels.is_empty() {
        Some(hub_types::ChannelTargetSelector {
            all: all_channel_targets,
            names: sorted_unique(channels.to_vec()),
        })
    } else {
        None
    };
    Ok(hub_types::RetentionSubscriptionSpec {
        selector: Some(hub_types::RetentionSelector {
            current_catalog,
            channel_targets,
            recent_releases: recent_releases.map(|count| hub_types::RecentReleaseSelector {
                count,
                include_prereleases: recent_include_prereleases,
            }),
            release_tags: sorted_unique(releases.to_vec()),
            semver: semver.map(|requirement| hub_types::SemverRetentionSelector {
                requirement: requirement.into(),
                include_prereleases: semver_include_prereleases,
            }),
            all_releases,
        }),
        removal_grace_seconds: removal_grace
            .map(|value| parse_duration_seconds(value, "--removal-grace"))
            .transpose()?
            .unwrap_or_default(),
    })
}

/// Handles the hub cache retention command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn cache_retention(
    printer: &Printer,
    command: &HubCacheRetentionCmd,
) -> Result<()> {
    match command {
        HubCacheRetentionCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRetentionSubscriptionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRetentionSubscriptions,
                &hub_types::ListRetentionSubscriptionsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheRetentionCmd::Set {
            access,
            cache,
            registry,
            current_catalog,
            channels,
            all_channel_targets,
            recent_releases,
            recent_include_prereleases,
            releases,
            semver,
            semver_include_prereleases,
            all_releases,
            removal_grace,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return cache_plan_mutation::<_, hub_types::RetentionSubscriptionResponse>(
                    printer,
                    access,
                    cache,
                    HubTopologyMethod::PlanSetRetentionSubscription,
                    HubTopologyMethod::SetRetentionSubscription,
                    &hub_types::PlanRetentionSubscriptionRequest::default(),
                    mutation,
                )
                .await;
            }
            let registry = registry
                .as_ref()
                .context("retention set requires --registry when creating a plan")?;
            let desired = retention_spec(
                *current_catalog,
                channels,
                *all_channel_targets,
                *recent_releases,
                *recent_include_prereleases,
                releases,
                semver.as_deref(),
                *semver_include_prereleases,
                *all_releases,
                removal_grace.as_deref(),
            )?;
            cache_plan_mutation::<_, hub_types::RetentionSubscriptionResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanSetRetentionSubscription,
                HubTopologyMethod::SetRetentionSubscription,
                &hub_types::PlanRetentionSubscriptionRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    desired: Some(desired),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCacheRetentionCmd::Remove {
            access,
            cache,
            registry,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::DeleteTopologyResourceResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanDeleteRetentionSubscription,
                HubTopologyMethod::DeleteRetentionSubscription,
                &hub_types::PlanDeleteRetentionSubscriptionRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCacheRetentionCmd::Refresh {
            access,
            cache,
            registry,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "retention refresh")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            match registry {
                Some(registry) => {
                    topology_operation_mutation(
                        printer,
                        &client,
                        HubTopologyMethod::PlanRefreshRetentionSubscription,
                        HubTopologyMethod::RefreshRetentionSubscription,
                        &hub_types::PlanRefreshRetentionSubscriptionRequest {
                            cache_id: cache.clone(),
                            registry_id: registry.clone(),
                            expected_resource_version: mutation
                                .if_version
                                .clone()
                                .unwrap_or_default(),
                            idempotency_key: new_idempotency_key(),
                        },
                        mutation,
                        operation,
                    )
                    .await
                }
                None => {
                    topology_operation_mutation(
                        printer,
                        &client,
                        HubTopologyMethod::PlanRefreshAllRetention,
                        HubTopologyMethod::RefreshAllRetention,
                        &hub_types::PlanRefreshAllRetentionRequest {
                            cache_id: cache.clone(),
                            expected_resource_version: mutation
                                .if_version
                                .clone()
                                .unwrap_or_default(),
                            idempotency_key: new_idempotency_key(),
                        },
                        mutation,
                        operation,
                    )
                    .await
                }
            }
        }
        HubCacheRetentionCmd::Explain {
            access,
            cache,
            store_hash,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ExplainRetentionResponse>(
                printer,
                &client,
                HubTopologyMethod::ExplainRetention,
                &hub_types::ExplainRetentionRequest {
                    cache_id: cache.clone(),
                    store_hash: store_hash.clone(),
                },
            )
            .await
        }
        HubCacheRetentionCmd::Roots {
            access,
            cache,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRootReasonsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRootReasons,
                &hub_types::ListRootReasonsRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone().unwrap_or_default(),
                    store_hash: String::new(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
    }
}
