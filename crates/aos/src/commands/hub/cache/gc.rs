//! Handles hub cache gc commands and their domain-specific request validation.

use crate::cli::{
    HubCacheGcCmd, HubCacheGcFirstSweepCmd, HubCacheGcJobsCmd, HubCacheGcPlanCmd,
    HubCacheGcPolicyCmd, HubCacheGcRunsCmd,
};
use crate::commands::hub::cache::mutation::{apply_reviewed_cache_plan, cache_plan_mutation};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_duration_seconds;
use crate::commands::hub::mutation::{
    confirm_destructive, new_idempotency_key, required_plan_version, topology_operation_mutation,
    topology_read,
};
use crate::commands::hub::operation::{print_or_wait_operation, watch_hub_operation};
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

async fn cache_gc_policy(printer: &Printer, command: &HubCacheGcPolicyCmd) -> Result<()> {
    match command {
        HubCacheGcPolicyCmd::Show { access, cache } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetCacheGcPolicyResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcPolicy,
                &hub_types::GetCacheGcPolicyRequest {
                    cache_id: cache.clone(),
                },
            )
            .await
        }
        HubCacheGcPolicyCmd::Set {
            access,
            cache,
            unreferenced_grace,
            soft_max_bytes,
            clear_soft_max_bytes,
            soft_max_objects,
            clear_soft_max_objects,
            schedule,
            deletion_concurrency,
            retry_initial,
            retry_max,
            retry_max_attempts,
            tombstone_retention,
            mutation,
        } => {
            let mut update_mask = vec![
                "unreferenced_grace_seconds".into(),
                "schedule".into(),
                "deletion_concurrency".into(),
                "retry_initial_seconds".into(),
                "retry_max_seconds".into(),
                "retry_max_attempts".into(),
                "tombstone_retention_seconds".into(),
            ];
            if soft_max_bytes.is_some() || *clear_soft_max_bytes {
                update_mask.push("soft_max_bytes".into());
            }
            if soft_max_objects.is_some() || *clear_soft_max_objects {
                update_mask.push("soft_max_objects".into());
            }
            let desired = hub_types::CacheGcPolicy {
                unreferenced_grace_seconds: parse_duration_seconds(
                    unreferenced_grace,
                    "--unreferenced-grace",
                )?,
                soft_max_bytes: if *clear_soft_max_bytes {
                    None
                } else {
                    *soft_max_bytes
                },
                soft_max_objects: if *clear_soft_max_objects {
                    None
                } else {
                    *soft_max_objects
                },
                schedule: schedule.clone(),
                deletion_concurrency: *deletion_concurrency,
                retry_initial_seconds: parse_duration_seconds(retry_initial, "--retry-initial")?,
                retry_max_seconds: parse_duration_seconds(retry_max, "--retry-max")?,
                retry_max_attempts: *retry_max_attempts,
                tombstone_retention_seconds: parse_duration_seconds(
                    tombstone_retention,
                    "--tombstone-retention",
                )?,
                policy_version: 0,
                resource_version: String::new(),
            };
            cache_plan_mutation::<_, hub_types::GetCacheGcPolicyResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanSetCacheGcPolicy,
                HubTopologyMethod::SetCacheGcPolicy,
                &hub_types::PlanSetCacheGcPolicyRequest {
                    cache_id: cache.clone(),
                    desired: Some(desired),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask,
                },
                mutation,
            )
            .await
        }
    }
}

async fn cache_gc_plan(printer: &Printer, command: &HubCacheGcPlanCmd) -> Result<()> {
    match command {
        HubCacheGcPlanCmd::Create { access, cache } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let current: hub_types::GetCacheGcPolicyResponse = client
                .call_topology(
                    HubTopologyMethod::GetCacheGcPolicy,
                    &hub_types::GetCacheGcPolicyRequest {
                        cache_id: cache.clone(),
                    },
                )
                .await?;
            let expected_resource_version = current
                .generation
                .context("the Hub returned cache GC policy without a generation")?
                .resource_version;
            topology_read::<_, hub_types::TopologyPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::PlanRunCacheGc,
                &hub_types::PlanRunCacheGcRequest {
                    cache_id: cache.clone(),
                    expected_resource_version,
                    idempotency_key: new_idempotency_key(),
                },
            )
            .await
        }
        HubCacheGcPlanCmd::Show {
            access,
            cache,
            plan_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CacheGcPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcPlan,
                &hub_types::GetCacheGcPlanRequest {
                    cache_id: cache.clone(),
                    plan_id: plan_id.clone(),
                },
            )
            .await
        }
    }
}

async fn cache_gc_first_sweep(printer: &Printer, command: &HubCacheGcFirstSweepCmd) -> Result<()> {
    match command {
        HubCacheGcFirstSweepCmd::PlanAcknowledgement {
            access,
            cache,
            gc_plan_id,
            idempotency_key,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let current: hub_types::GetCacheGcPolicyResponse = client
                .call_topology(
                    HubTopologyMethod::GetCacheGcPolicy,
                    &hub_types::GetCacheGcPolicyRequest {
                        cache_id: cache.clone(),
                    },
                )
                .await?;
            let expected_resource_version = current
                .generation
                .context("the Hub returned cache GC policy without a generation")?
                .resource_version;
            topology_read::<_, hub_types::TopologyPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::PlanAcknowledgeCacheGcFirstSweep,
                &hub_types::PlanAcknowledgeCacheGcFirstSweepRequest {
                    cache_id: cache.clone(),
                    gc_plan_id: gc_plan_id.clone(),
                    expected_resource_version,
                    idempotency_key: idempotency_key.clone(),
                },
            )
            .await
        }
        HubCacheGcFirstSweepCmd::Acknowledge {
            access,
            cache,
            ack_plan_id,
            confirm_hash,
            idempotency_key,
            yes,
        } => {
            apply_reviewed_cache_plan::<hub_types::CacheGcGenerationResponse>(
                printer,
                access,
                cache,
                ack_plan_id,
                confirm_hash,
                idempotency_key,
                *yes,
                HubTopologyMethod::AcknowledgeCacheGcFirstSweep,
                "first-sweep acknowledgement",
            )
            .await
        }
    }
}

async fn cache_gc_runs(printer: &Printer, command: &HubCacheGcRunsCmd) -> Result<()> {
    match command {
        HubCacheGcRunsCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListCacheGcRunsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListCacheGcRuns,
                &hub_types::ListCacheGcRunsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheGcRunsCmd::Show {
            access,
            cache,
            operation_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CacheGcRunResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcRun,
                &hub_types::GetCacheOperationRequest {
                    cache_id: cache.clone(),
                    operation_id: operation_id.clone(),
                },
            )
            .await
        }
        HubCacheGcRunsCmd::Watch {
            access,
            cache: _,
            operation_id,
            timeout,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            watch_hub_operation(printer, &client, operation_id, timeout.as_deref()).await
        }
    }
}

async fn cache_gc_jobs(printer: &Printer, command: &HubCacheGcJobsCmd) -> Result<()> {
    match command {
        HubCacheGcJobsCmd::List {
            access,
            cache,
            operation_id,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListCacheGcDeletionJobsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListCacheGcDeletionJobs,
                &hub_types::ListCacheGcDeletionJobsRequest {
                    cache_id: cache.clone(),
                    operation_id: operation_id.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheGcJobsCmd::Show {
            access,
            cache,
            job_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CacheGcDeletionJobResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcDeletionJob,
                &hub_types::GetCacheGcDeletionJobRequest {
                    cache_id: cache.clone(),
                    job_id: job_id.clone(),
                },
            )
            .await
        }
        HubCacheGcJobsCmd::Retry {
            access,
            cache,
            job_id,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "cache GC deletion retry")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanRetryCacheGcDeletionJob,
                HubTopologyMethod::RetryCacheGcDeletionJob,
                &hub_types::PlanRetryCacheGcDeletionJobRequest {
                    cache_id: cache.clone(),
                    job_id: job_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubCacheGcJobsCmd::Abandon {
            access,
            cache,
            job_id,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::CacheGcDeletionJobResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanAbandonCacheGcDeletionJob,
                HubTopologyMethod::AbandonCacheGcDeletionJob,
                &hub_types::PlanAbandonCacheGcDeletionJobRequest {
                    cache_id: cache.clone(),
                    job_id: job_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

/// Handles the hub cache gc command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn cache_gc(printer: &Printer, command: &HubCacheGcCmd) -> Result<()> {
    match command {
        HubCacheGcCmd::Policy { command } => cache_gc_policy(printer, command).await,
        HubCacheGcCmd::Plan { command } => cache_gc_plan(printer, command).await,
        HubCacheGcCmd::FirstSweep { command } => cache_gc_first_sweep(printer, command).await,
        HubCacheGcCmd::Run {
            access,
            cache: _,
            plan_id,
            confirm_hash,
            idempotency_key,
            yes,
            operation,
        } => {
            if !confirm_destructive(*yes, "logical cache GC")? {
                printer.info("logical cache GC cancelled");
                return Ok(());
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::OperationResponse = client
                .call_topology(
                    HubTopologyMethod::RunCacheGc,
                    &hub_types::ApplyCachePlanRequest {
                        plan_id: plan_id.clone(),
                        confirmation_hash: confirm_hash.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                )
                .await?;
            print_or_wait_operation(printer, &client, &response, operation).await
        }
        HubCacheGcCmd::Runs { command } => cache_gc_runs(printer, command).await,
        HubCacheGcCmd::Jobs { command } => cache_gc_jobs(printer, command).await,
    }
}
