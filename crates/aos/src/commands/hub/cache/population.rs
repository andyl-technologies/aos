//! Handles hub cache population commands and their domain-specific request validation.

use crate::cli::{HubCacheCoverageCmd, HubCachePopulationCmd, HubMutationArgs, HubOperationArgs};
use crate::commands::hub::cache::mutation::cache_plan_mutation;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::{
    new_idempotency_key, required_plan_version, topology_operation_mutation, topology_read,
};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{HubRpc, hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub cache population command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn cache_population(
    printer: &Printer,
    command: &HubCachePopulationCmd,
) -> Result<()> {
    match command {
        HubCachePopulationCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListPopulationTargetsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPopulationTargets,
                &hub_types::ListPopulationTargetsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCachePopulationCmd::Set {
            access,
            cache,
            registry,
            trigger,
            required,
            best_effort: _,
            placement_policy,
            validation_gate,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::PopulationTargetResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanSetPopulationTarget,
                HubTopologyMethod::SetPopulationTarget,
                &hub_types::PlanPopulationTargetRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    desired: Some(hub_types::PopulationTargetSpec {
                        trigger: trigger.clone(),
                        required: *required,
                        placement_policy_revision_id: placement_policy.clone().unwrap_or_default(),
                        validation_gate: validation_gate
                            .clone()
                            .unwrap_or_else(|| "integrity".into()),
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCachePopulationCmd::Run {
            access,
            cache,
            registry,
            release,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "population run")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanRunPopulation,
                HubTopologyMethod::RunPopulation,
                &hub_types::PlanRunPopulationRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    release_tag: release.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubCachePopulationCmd::Remove {
            access,
            cache,
            registry,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::DeleteTopologyResourceResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanDeletePopulationTarget,
                HubTopologyMethod::DeletePopulationTarget,
                &hub_types::PlanDeletePopulationTargetRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

/// Handles the hub cache coverage command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn cache_coverage(printer: &Printer, command: &HubCacheCoverageCmd) -> Result<()> {
    match command {
        HubCacheCoverageCmd::Show {
            access,
            cache,
            registry,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::CoverageResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCoverage,
                &hub_types::GetPopulationTargetRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheCoverageCmd::Validate {
            access,
            cache,
            registry,
            mutation,
            operation,
        } => {
            run_coverage_operation(
                printer,
                access,
                cache,
                registry.as_deref(),
                HubTopologyMethod::PlanRunCoverageValidation,
                HubTopologyMethod::RunCoverageValidation,
                mutation,
                operation,
            )
            .await
        }
        HubCacheCoverageCmd::Repair {
            access,
            cache,
            registry,
            mutation,
            operation,
        } => {
            run_coverage_operation(
                printer,
                access,
                cache,
                registry.as_deref(),
                HubTopologyMethod::PlanRunCoverageRepair,
                HubTopologyMethod::RunCoverageRepair,
                mutation,
                operation,
            )
            .await
        }
    }
}

async fn run_coverage_operation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    cache: &str,
    registry: Option<&str>,
    plan_method: impl HubRpc<
        Request = hub_types::PlanCoverageOperationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyTopologyPlanRequest,
        Response = hub_types::OperationResponse,
    > + Copy,
    mutation: &HubMutationArgs,
    operation: &HubOperationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    if mutation.plan_id.is_none() {
        required_plan_version(mutation, "coverage operation")?;
    }
    topology_operation_mutation(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanCoverageOperationRequest {
            cache_id: cache.into(),
            registry_id: registry.unwrap_or_default().into(),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        operation,
    )
    .await
}
