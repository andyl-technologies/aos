//! Handles hub cache commands and their domain-specific request validation.

use crate::cli::HubCacheCmd;
use crate::commands::hub::cache::gc::cache_gc;
use crate::commands::hub::cache::integration::{cache_integration, preview_cache_integration};
use crate::commands::hub::cache::population::{cache_coverage, cache_population};
use crate::commands::hub::cache::retention::cache_retention;
use crate::commands::hub::cache::roots::{cache_lease, cache_root};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::{
    delete_topology_resource, new_idempotency_key, topology_mutation, topology_read,
};
use crate::commands::hub::organization::organization_scope_key;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub cache command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn cache(
    printer: &Printer,
    command: &HubCacheCmd,
) -> Result<()> {
    match command {
        HubCacheCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListBinaryCachesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListBinaryCaches,
                &hub_types::ListBinaryCachesRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheCmd::Show { access, cache } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::BinaryCacheResponse>(
                printer,
                &client,
                HubTopologyMethod::GetBinaryCache,
                &hub_types::GetBinaryCacheRequest {
                    cache_id: cache.clone(),
                },
            )
            .await
        }
        HubCacheCmd::Create {
            access,
            cache,
            name,
            visibility,
            nix_priority,
            compression,
            mass_query,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateBinaryCache,
                    HubTopologyMethod::CreateBinaryCache,
                    &hub_types::PlanBinaryCacheMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyBinaryCacheMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let owner = qualified_cache_owner(cache)?;
            let owner_scope_key = organization_scope_key(&client, Some(owner)).await?;
            let name = name
                .as_ref()
                .context("cache create requires --name when creating a plan")?;
            let visibility = visibility
                .as_ref()
                .context("cache create requires --visibility when creating a plan")?;
            topology_mutation::<
                _,
                hub_types::ApplyBinaryCacheMutationRequest,
                hub_types::BinaryCacheResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateBinaryCache,
                HubTopologyMethod::CreateBinaryCache,
                &hub_types::PlanBinaryCacheMutationRequest {
                    stable_id: cache.clone(),
                    desired: Some(hub_types::BinaryCacheSpec {
                        slug: cache.clone(),
                        name: name.clone(),
                        owner_scope_key,
                        visibility: visibility.clone(),
                        nix_priority: *nix_priority,
                        compression: compression.clone(),
                        want_mass_query: mass_query == "enabled",
                    }),
                    update_mask: vec![
                        "slug".into(),
                        "name".into(),
                        "owner_scope_key".into(),
                        "visibility".into(),
                        "nix_priority".into(),
                        "compression".into(),
                        "want_mass_query".into(),
                    ],
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyBinaryCacheMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubCacheCmd::Update {
            access,
            cache,
            name,
            visibility,
            nix_priority,
            compression,
            mass_query,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                return topology_mutation::<
                    _,
                    hub_types::ApplyBinaryCacheMutationRequest,
                    hub_types::BinaryCacheResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateBinaryCache,
                    HubTopologyMethod::UpdateBinaryCache,
                    &hub_types::PlanBinaryCacheMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyBinaryCacheMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            if name.is_none()
                && visibility.is_none()
                && nix_priority.is_none()
                && compression.is_none()
                && mass_query.is_none()
            {
                anyhow::bail!(
                    "cache update requires --name, --visibility, --nix-priority, --compression, or --mass-query"
                );
            }
            let mut update_mask = Vec::new();
            if name.is_some() {
                update_mask.push("name".into());
            }
            if visibility.is_some() {
                update_mask.push("visibility".into());
            }
            if nix_priority.is_some() {
                update_mask.push("nix_priority".into());
            }
            if compression.is_some() {
                update_mask.push("compression".into());
            }
            if mass_query.is_some() {
                update_mask.push("want_mass_query".into());
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyBinaryCacheMutationRequest,
                hub_types::BinaryCacheResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdateBinaryCache,
                HubTopologyMethod::UpdateBinaryCache,
                &hub_types::PlanBinaryCacheMutationRequest {
                    stable_id: cache.clone(),
                    desired: Some(hub_types::BinaryCacheSpec {
                        slug: String::new(),
                        name: name.clone().unwrap_or_default(),
                        owner_scope_key: String::new(),
                        visibility: visibility.clone().unwrap_or_default(),
                        nix_priority: nix_priority.unwrap_or_default(),
                        compression: compression.clone().unwrap_or_default(),
                        want_mass_query: mass_query.as_deref() == Some("enabled"),
                    }),
                    update_mask,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyBinaryCacheMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubCacheCmd::Delete {
            access,
            cache,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                cache,
                mutation,
                HubTopologyMethod::PlanDeleteBinaryCache,
                HubTopologyMethod::DeleteBinaryCache,
            )
            .await
        }
        HubCacheCmd::Retention { command } => cache_retention(printer, command).await,
        HubCacheCmd::Root { command } => cache_root(printer, command).await,
        HubCacheCmd::Lease { command } => cache_lease(printer, command).await,
        HubCacheCmd::Population { command } => cache_population(printer, command).await,
        HubCacheCmd::Coverage { command } => cache_coverage(printer, command).await,
        HubCacheCmd::Gc { command } => cache_gc(printer, command).await,
        HubCacheCmd::Integration { command } => cache_integration(printer, command).await,
        HubCacheCmd::Integrate {
            access,
            cache,
            registry,
            use_for_clients,
            retain_current_catalog,
            retain_channels,
            retain_recent_releases,
            recent_include_prereleases,
            retain_releases,
            retain_semver,
            semver_include_prereleases,
            retain_all_releases,
            populate,
            population_trigger,
        } => {
            preview_cache_integration(
                printer,
                access,
                cache,
                registry,
                *use_for_clients,
                *retain_current_catalog,
                retain_channels,
                *retain_recent_releases,
                *recent_include_prereleases,
                retain_releases,
                retain_semver.as_deref(),
                *semver_include_prereleases,
                *retain_all_releases,
                populate.as_deref(),
                population_trigger.as_deref(),
            )
            .await
        }
    }
}

fn qualified_cache_owner(cache: &str) -> Result<&str> {
    let (org, name) = cache
        .split_once('/')
        .context("cache refs are qualified as <org>/<cache>")?;
    if org.is_empty() || name.is_empty() || name.contains('/') {
        anyhow::bail!("cache refs are qualified as <org>/<cache>");
    }
    Ok(org)
}

mod gc;
pub(super) mod integration;
mod mutation;
mod population;
mod retention;
mod roots;
