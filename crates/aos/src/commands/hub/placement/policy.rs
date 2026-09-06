//! Handles hub placement policy commands and their domain-specific request validation.

use crate::cli::HubPlacementPolicyCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_generation_ref;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    new_idempotency_key, required_plan_version, topology_mutation, topology_read,
};
use crate::commands::hub::route::surface_message;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

fn placement_policy_spec(
    kind: &str,
    members: &[String],
    local_boundary: Option<&String>,
    local: &[String],
    remote: &[String],
    ranges: &[String],
    complete_fallback: &[String],
    allow_remote_fallback: bool,
    retry_on: &[String],
) -> Result<hub_types::PlacementPolicyRevisionSpec> {
    let selector = match kind {
        "ordered-failover" => {
            if members.is_empty() {
                anyhow::bail!("ordered-failover requires at least one --member");
            }
            hub_types::placement_policy_revision_spec::Selector::OrderedFailover(
                hub_types::OrderedFailoverPlacementPolicy {
                    replica_groups: members
                        .iter()
                        .map(|placement| hub_types::PlacementPolicyReplicaGroup {
                            placement_names: vec![placement.clone()],
                            access_class: hub_types::AccessClass::Unspecified as i32,
                            hash_range: None,
                        })
                        .collect(),
                },
            )
        }
        "local-then-remote" => {
            if local.is_empty() || remote.is_empty() {
                anyhow::bail!("local-then-remote requires --local and --remote members");
            }
            let (boundary_id, revision) = parse_generation_ref(
                local_boundary
                    .context("local-then-remote requires --local-boundary name@revision")?,
                "local boundary",
            )?;
            let local_groups =
                local
                    .iter()
                    .map(|placement| hub_types::PlacementPolicyReplicaGroup {
                        placement_names: vec![placement.clone()],
                        access_class: hub_types::AccessClass::Local as i32,
                        hash_range: None,
                    });
            let remote_groups =
                remote
                    .iter()
                    .map(|placement| hub_types::PlacementPolicyReplicaGroup {
                        placement_names: vec![placement.clone()],
                        access_class: hub_types::AccessClass::Remote as i32,
                        hash_range: None,
                    });
            hub_types::placement_policy_revision_spec::Selector::LocalThenRemote(
                hub_types::LocalThenRemotePlacementPolicy {
                    replica_groups: local_groups.chain(remote_groups).collect(),
                    local_boundary: Some(hub_types::NetworkPolicyRevisionRef {
                        boundary_id,
                        revision,
                    }),
                    allow_remote_fallback,
                },
            )
        }
        "hash-partition" => {
            if ranges.is_empty() {
                anyhow::bail!("hash-partition requires at least one --range");
            }
            let mut replica_groups = Vec::new();
            for raw in ranges {
                let (bounds, placements) = raw
                    .split_once('=')
                    .context("--range must be <start>-<end>=<placement>[,<replica>...]")?;
                let (start, end) = bounds
                    .split_once('-')
                    .context("--range bounds must be <start>-<end>")?;
                let start: u32 = start.parse()?;
                let end: u32 = end.parse()?;
                if start >= end || end > 65_536 {
                    anyhow::bail!("hash range must satisfy 0 <= start < end <= 65536");
                }
                let placement_names = placements
                    .split(',')
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                if placement_names.iter().any(String::is_empty) {
                    anyhow::bail!("hash range placement names cannot be empty");
                }
                replica_groups.push(hub_types::PlacementPolicyReplicaGroup {
                    placement_names,
                    access_class: hub_types::AccessClass::Unspecified as i32,
                    hash_range: Some(hub_types::HashRangeV1 { start, end }),
                });
            }
            hub_types::placement_policy_revision_spec::Selector::HashPartition(
                hub_types::HashPartitionPlacementPolicy {
                    ranges: replica_groups,
                    complete_fallback_placements: complete_fallback.to_vec(),
                },
            )
        }
        _ => anyhow::bail!("unsupported placement-policy kind '{kind}'"),
    };
    let retry_on = retry_on
        .iter()
        .map(|condition| match condition.as_str() {
            "connect-failure" => Ok(hub_types::PolicyRetryCondition::ConnectFailure as i32),
            "timeout-before-headers" => {
                Ok(hub_types::PolicyRetryCondition::TimeoutBeforeHeaders as i32)
            }
            "origin-429" => Ok(hub_types::PolicyRetryCondition::Origin429 as i32),
            "origin-502" => Ok(hub_types::PolicyRetryCondition::Origin502 as i32),
            "origin-503" => Ok(hub_types::PolicyRetryCondition::Origin503 as i32),
            "origin-504" => Ok(hub_types::PolicyRetryCondition::Origin504 as i32),
            "presence-mismatch" => Ok(hub_types::PolicyRetryCondition::PresenceMismatch as i32),
            "verified-corruption" => Ok(hub_types::PolicyRetryCondition::VerifiedCorruption as i32),
            other => anyhow::bail!("unsupported policy retry condition '{other}'"),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(hub_types::PlacementPolicyRevisionSpec {
        selector: Some(selector),
        failure_contract: Some(hub_types::PolicyFailureContract { retry_on }),
    })
}

/// Handles the hub placement policy command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn placement_policy(
    printer: &Printer,
    command: &HubPlacementPolicyCmd,
) -> Result<()> {
    match command {
        HubPlacementPolicyCmd::List {
            access,
            surface,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListPlacementPoliciesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPlacementPolicies,
                &hub_types::SurfaceListRequest {
                    surface: Some(surface_message(surface)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementPolicyCmd::Show {
            access,
            surface,
            policy,
            revision,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if let Some(revision) = revision {
                topology_read::<_, hub_types::PlacementPolicyRevisionResponse>(
                    printer,
                    &client,
                    HubTopologyMethod::GetPlacementPolicyRevision,
                    &hub_types::GetPlacementPolicyRevisionRequest {
                        surface: Some(surface_message(surface)?),
                        policy_id: policy.clone(),
                        revision: *revision,
                    },
                )
                .await
            } else {
                topology_read::<_, hub_types::PlacementPolicyResponse>(
                    printer,
                    &client,
                    HubTopologyMethod::GetPlacementPolicy,
                    &hub_types::GetPlacementPolicyRequest {
                        surface: Some(surface_message(surface)?),
                        policy_id: policy.clone(),
                    },
                )
                .await
            }
        }
        HubPlacementPolicyCmd::Revisions {
            access,
            surface,
            policy,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListPlacementPolicyRevisionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPlacementPolicyRevisions,
                &hub_types::ListPlacementPolicyRevisionsRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementPolicyCmd::Create {
            access,
            surface,
            policy,
            kind,
            members,
            local_boundary,
            local,
            remote,
            ranges,
            complete_fallback,
            allow_remote_fallback,
            retry_on,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreatePlacementPolicy,
                    HubTopologyMethod::CreatePlacementPolicy,
                    &hub_types::PlanPlacementPolicyMutationRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let kind = kind
                .as_deref()
                .context("placement-policy create requires --kind when creating a plan")?;
            let expected_resource_version =
                required_plan_version(mutation, "placement-policy creation")?.to_string();
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementPolicyResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreatePlacementPolicy,
                HubTopologyMethod::CreatePlacementPolicy,
                &hub_types::PlanPlacementPolicyMutationRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    name: policy.clone(),
                    desired: Some(placement_policy_spec(
                        kind,
                        members,
                        local_boundary.as_ref(),
                        local,
                        remote,
                        ranges,
                        complete_fallback,
                        *allow_remote_fallback,
                        retry_on,
                    )?),
                    expected_resource_version: Some(expected_resource_version),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementPolicyCmd::Revise {
            access,
            surface,
            policy,
            kind,
            members,
            local_boundary,
            local,
            remote,
            ranges,
            complete_fallback,
            allow_remote_fallback,
            retry_on,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRevisePlacementPolicy,
                    HubTopologyMethod::RevisePlacementPolicy,
                    &hub_types::PlanPlacementPolicyMutationRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let kind = kind
                .as_deref()
                .context("placement-policy revise requires --kind when creating a plan")?;
            let expected_resource_version =
                required_plan_version(mutation, "placement-policy revision")?.to_string();
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementPolicyRevisionResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanRevisePlacementPolicy,
                HubTopologyMethod::RevisePlacementPolicy,
                &hub_types::PlanPlacementPolicyMutationRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    name: String::new(),
                    desired: Some(placement_policy_spec(
                        kind,
                        members,
                        local_boundary.as_ref(),
                        local,
                        remote,
                        ranges,
                        complete_fallback,
                        *allow_remote_fallback,
                        retry_on,
                    )?),
                    expected_resource_version: Some(expected_resource_version),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementPolicyCmd::Test {
            access,
            surface,
            policy,
            revision,
            object,
            access_class,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::TestPlacementPolicyRevisionResponse>(
                printer,
                &client,
                HubTopologyMethod::TestPlacementPolicyRevision,
                &hub_types::TestPlacementPolicyRevisionRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    revision: *revision,
                    object_ref: object.clone(),
                    access_class: match access_class.as_deref() {
                        Some("local") => hub_types::AccessClass::Local as i32,
                        Some("remote") => hub_types::AccessClass::Remote as i32,
                        Some(value) => anyhow::bail!("unsupported access class '{value}'"),
                        None => hub_types::AccessClass::Unspecified as i32,
                    },
                },
            )
            .await
        }
    }
}
