//! Handles hub registry commands and their domain-specific request validation.

use crate::cli::{HubRegistryCmd, HubRegistryMirrorCmd};
use crate::commands::hub::cache::integration::registry_cache_stack;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::config::config;
use crate::commands::hub::input::parse_duration_seconds;
use crate::commands::hub::mutation::{apply_registry_plan, apply_topology_plan};
use crate::commands::hub::mutation::{
    delete_topology_resource, new_idempotency_key, required_plan_version, topology_mutation,
    topology_operation_mutation, topology_read,
};
use crate::commands::hub::package::{channel, package};
use crate::commands::hub::publication::publish;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles `aos hub registry …`.
async fn registry_mirror(printer: &Printer, command: &HubRegistryMirrorCmd) -> Result<()> {
    match command {
        HubRegistryMirrorCmd::Show { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::RegistryMirrorResponse>(
                printer,
                &client,
                HubTopologyMethod::GetRegistryMirror,
                &hub_types::GetRegistryMirrorRequest {
                    registry_id: registry.clone(),
                },
            )
            .await
        }
        HubRegistryMirrorCmd::Set {
            access,
            registry,
            source,
            refspec,
            auth_secret_ref,
            interval,
            signature_policy,
            mode,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetRegistryMirror,
                    HubTopologyMethod::SetRegistryMirror,
                    &hub_types::PlanRegistryMirrorMutationRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let source = source
                .as_ref()
                .context("registry mirror set requires --source when creating a plan")?;
            let source_url =
                url::Url::parse(source).context("--source must be an absolute HTTPS URL")?;
            if source_url.scheme() != "https" {
                anyhow::bail!("--source must use HTTPS");
            }
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::RegistryMirrorResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanSetRegistryMirror,
                HubTopologyMethod::SetRegistryMirror,
                &hub_types::PlanRegistryMirrorMutationRequest {
                    registry_id: registry.clone(),
                    desired: Some(hub_types::RegistryMirrorSpec {
                        source_url: source.clone(),
                        refspec: refspec.clone().unwrap_or_default(),
                        auth_secret_ref: auth_secret_ref.clone().unwrap_or_default(),
                        interval_seconds: interval
                            .as_deref()
                            .map(|value| parse_duration_seconds(value, "--interval"))
                            .transpose()?
                            .unwrap_or_default(),
                        signature_policy: signature_policy.clone().unwrap_or_default(),
                        mode: match mode.as_str() {
                            "full" => hub_types::RegistryMirrorMode::Full as i32,
                            "pull-through" => hub_types::RegistryMirrorMode::PullThrough as i32,
                            other => anyhow::bail!("unsupported registry mirror mode '{other}'"),
                        },
                    }),
                    expected_resource_version: mutation.if_version.clone(),
                    update_mask: vec!["desired".into()],
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubRegistryMirrorCmd::Remove {
            access,
            registry,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                registry,
                mutation,
                HubTopologyMethod::PlanDeleteRegistryMirror,
                HubTopologyMethod::DeleteRegistryMirror,
            )
            .await
        }
        HubRegistryMirrorCmd::Sync {
            access,
            registry,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "registry mirror synchronization")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanSyncRegistryMirror,
                HubTopologyMethod::SyncRegistryMirror,
                &hub_types::PlanSyncRegistryMirrorRequest {
                    registry_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
    }
}

/// Handles the hub registry command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn registry(printer: &Printer, command: &HubRegistryCmd) -> Result<()> {
    match command {
        HubRegistryCmd::List { access, pagination } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRegistriesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRegistries,
                &hub_types::ListRegistriesRequest {
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubRegistryCmd::Show { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetRegistryResponse>(
                printer,
                &client,
                HubTopologyMethod::GetRegistry,
                &hub_types::GetRegistryRequest {
                    slug: registry.clone(),
                },
            )
            .await
        }
        HubRegistryCmd::Releases {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListReleasesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListReleases,
                &hub_types::ListReleasesRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubRegistryCmd::Create {
            access,
            org,
            project,
            name,
            visibility,
            trust_keys,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateRegistry,
                    HubTopologyMethod::CreateRegistry,
                    &hub_types::PlanCreateRegistryRequest::default(),
                    mutation,
                    apply_registry_plan,
                )
                .await;
            }
            topology_mutation::<
                _,
                hub_types::ApplyRegistryMutationRequest,
                hub_types::RegistryResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateRegistry,
                HubTopologyMethod::CreateRegistry,
                &hub_types::PlanCreateRegistryRequest {
                    org_slug: org
                        .clone()
                        .context("registry create requires --org when creating a plan")?,
                    project_path: project.clone().unwrap_or_default(),
                    name: name
                        .clone()
                        .context("registry create requires --name when creating a plan")?,
                    visibility: visibility.clone().unwrap_or_else(|| "private".into()),
                    trust_keys: trust_keys.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_registry_plan,
            )
            .await
        }
        HubRegistryCmd::Update {
            access,
            registry,
            visibility,
            crawl_policy,
            llms_txt_body,
            clear_llms_txt,
            trust_keys,
            clear_trust_keys,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateRegistry,
                    HubTopologyMethod::UpdateRegistry,
                    &hub_types::PlanUpdateRegistryRequest::default(),
                    mutation,
                    apply_registry_plan,
                )
                .await;
            }
            let update_mask = [
                visibility.as_ref().map(|_| "visibility"),
                crawl_policy.as_ref().map(|_| "crawl_policy"),
                (llms_txt_body.is_some() || *clear_llms_txt).then_some("llms_txt_body"),
                (!trust_keys.is_empty() || *clear_trust_keys).then_some("trust_keys"),
            ]
            .into_iter()
            .flatten()
            .map(str::to_string)
            .collect::<Vec<_>>();
            if update_mask.is_empty() {
                anyhow::bail!("registry update requires at least one changed field");
            }
            topology_mutation::<
                _,
                hub_types::ApplyRegistryMutationRequest,
                hub_types::RegistryResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdateRegistry,
                HubTopologyMethod::UpdateRegistry,
                &hub_types::PlanUpdateRegistryRequest {
                    slug: registry.clone(),
                    visibility: visibility.clone().unwrap_or_default(),
                    crawl_policy: crawl_policy.clone().unwrap_or_default(),
                    llms_txt_body: llms_txt_body.clone().unwrap_or_default(),
                    trust_keys: if *clear_trust_keys {
                        Vec::new()
                    } else {
                        trust_keys.clone()
                    },
                    update_mask,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_registry_plan,
            )
            .await
        }
        HubRegistryCmd::Delete {
            access,
            registry,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyDeleteTopologyResourceRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteRegistry,
                HubTopologyMethod::DeleteRegistry,
                &hub_types::PlanDeleteTopologyResourceRequest {
                    stable_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyDeleteTopologyResourceRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubRegistryCmd::CacheStack { command } => registry_cache_stack(printer, command).await,
        HubRegistryCmd::Mirror { command } => registry_mirror(printer, command).await,
        HubRegistryCmd::Package { command } => package(printer, command).await,
        HubRegistryCmd::Channel { command } => channel(printer, command).await,
        HubRegistryCmd::Publish { command } => publish(printer, command).await,
        HubRegistryCmd::Configuration { command } => config(printer, command).await,
        HubRegistryCmd::Container { command } => {
            crate::commands::hub_container::run(printer, command).await
        }
    }
}
