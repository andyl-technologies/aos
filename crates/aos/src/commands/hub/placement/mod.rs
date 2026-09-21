//! Handles hub placement commands and their domain-specific request validation.

use crate::cli::{
    HubPlacementCmd, HubPlacementDrainCmd, HubPlacementEvictionCmd, HubPlacementPromotionCmd,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    confirm_destructive, new_idempotency_key, required_plan_version, topology_mutation,
    topology_operation_mutation, topology_read,
};
use crate::commands::hub::operation::print_or_wait_operation;
use crate::commands::hub::output::print_hub_json;
use crate::commands::hub::route::surface_message;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubSurfaceRef, Placement, hub_rpc as HubTopologyMethod, hub_types};

/// Renders one placement as a stable public JSON object.
fn placement_json(placement: &Placement) -> Result<serde_json::Value> {
    let spec = placement
        .spec
        .as_ref()
        .context("the hub returned a placement without desired spec")?;
    let observation = placement
        .observation
        .as_ref()
        .context("the hub returned a placement without observation")?;
    let status = placement
        .status
        .as_ref()
        .context("the hub returned a placement without status projection")?;
    let hash_range = spec.hash_range.as_ref().map(|range| {
        serde_json::json!({
            "start": range.start,
            "end": range.end,
        })
    });
    Ok(serde_json::json!({
        "name": placement.name,
        "binding_name": placement.binding_name,
        "prefix": placement.prefix,
        "spec": {
            "kind": spec.kind,
            "desired_state": spec.desired_state,
            "desired_read_enabled": spec.desired_read_enabled,
            "read_order": spec.read_order,
            "write_spec_version": spec.write_spec_version,
            "requires_conditional_writes": spec.requires_conditional_writes,
            "hash_range": hash_range,
        },
        "observation": {
            "state": observation.state,
            "completeness": observation.completeness,
            "observed_at": observation.observed_at,
            "observation_version": observation.observation_version,
            "mutable_publication_id": observation.mutable_publication_id,
            "pending_publication_id": observation.pending_publication_id,
            "watermark_resource_version": observation.watermark_resource_version,
        },
        "status": {
            "derived_role": status.derived_role,
            "desired_writer": status.desired_writer,
            "observed_writer": status.observed_writer,
            "promotion_pending": status.promotion_pending,
            "effective_read_enabled": status.effective_read_enabled,
            "effective_write_enabled": status.effective_write_enabled,
        },
        "created_at": placement.created_at,
        "updated_at": placement.updated_at,
        "resource_version": placement.resource_version,
    }))
}

/// Handles `aos hub placement …` inventory and lifecycle operations.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn placement(
    printer: &Printer,
    command: &HubPlacementCmd,
) -> Result<()> {
    match command {
        HubPlacementCmd::List {
            access,
            surface,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let surface: HubSurfaceRef = surface.parse()?;
            let response: hub_types::ListPlacementsResponse = client
                .call_topology(
                    HubTopologyMethod::ListPlacements,
                    &hub_types::ListPlacementsRequest {
                        surface: Some(surface.to_message()),
                        page_size: pagination.page_size.unwrap_or_default(),
                        page_token: pagination.page_token.clone().unwrap_or_default(),
                    },
                )
                .await?;
            let placements = response.placements;
            let placements_json = placements
                .iter()
                .map(placement_json)
                .collect::<Result<Vec<_>>>()?;
            if print_hub_json(
                printer,
                "placement_list",
                serde_json::json!({
                    "surface": surface.to_string(),
                    "placements": placements_json,
                    "next_page_token": response.next_page_token,
                }),
            ) {
                return Ok(());
            }
            if placements.is_empty() {
                printer.info(&format!("no placements on {surface}"));
                return Ok(());
            }
            printer.header(&format!("{} placement(s) on {surface}", placements.len()));
            for placement in &placements {
                let spec = placement
                    .spec
                    .as_ref()
                    .context("the hub returned a placement without desired spec")?;
                let observation = placement
                    .observation
                    .as_ref()
                    .context("the hub returned a placement without observation")?;
                let status = placement
                    .status
                    .as_ref()
                    .context("the hub returned a placement without status projection")?;
                printer.plain(&format!(
                    "  {}  [{} / {} / {} / {}]  {}:{}  read-order={}",
                    placement.name,
                    status.derived_role,
                    spec.kind,
                    observation.state,
                    observation.completeness,
                    placement.binding_name,
                    placement.prefix,
                    spec.read_order,
                ));
            }
            Ok(())
        }
        HubPlacementCmd::Show {
            access,
            surface,
            name,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response: hub_types::GetPlacementResponse = client
                .call_topology(
                    HubTopologyMethod::GetPlacement,
                    &hub_types::GetPlacementRequest {
                        surface: Some(surface.to_message()),
                        name: name.clone(),
                    },
                )
                .await?;
            let placement = response
                .placement
                .context("the Hub returned GetPlacement without a placement")?;
            if print_hub_json(
                printer,
                "placement_show",
                serde_json::json!({
                    "surface": surface.to_string(),
                    "placement": placement_json(&placement)?,
                }),
            ) {
                return Ok(());
            }
            printer.header(&format!("{} on {surface}", placement.name));
            printer.kv("binding", &placement.binding_name);
            printer.kv("prefix", &placement.prefix);
            let spec = placement
                .spec
                .as_ref()
                .context("the hub returned a placement without desired spec")?;
            let observation = placement
                .observation
                .as_ref()
                .context("the hub returned a placement without observation")?;
            let status = placement
                .status
                .as_ref()
                .context("the hub returned a placement without status projection")?;
            printer.kv("kind", &spec.kind);
            printer.kv("desired state", &spec.desired_state);
            printer.kv("observed state", &observation.state);
            printer.kv("completeness", &observation.completeness);
            printer.kv("derived role", &status.derived_role);
            printer.kv(
                "desired read enabled",
                &spec.desired_read_enabled.to_string(),
            );
            printer.kv(
                "effective read enabled",
                &status.effective_read_enabled.to_string(),
            );
            printer.kv(
                "effective write enabled",
                &status.effective_write_enabled.to_string(),
            );
            printer.kv("read order", &spec.read_order.to_string());
            printer.kv("created at", &placement.created_at.to_string());
            printer.kv("updated at", &placement.updated_at.to_string());
            printer.kv("resource version", &placement.resource_version);
            Ok(())
        }
        HubPlacementCmd::Presence {
            access,
            surface,
            object,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListObjectPresenceResponse>(
                printer,
                &client,
                HubTopologyMethod::ListObjectPresence,
                &hub_types::ListObjectPresenceRequest {
                    surface: Some(surface_message(surface)?),
                    object_ref: object.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementCmd::Add {
            access,
            surface,
            name,
            binding,
            prefix,
            kind,
            desired_state,
            read,
            read_order,
            hash_range,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreatePlacement,
                    HubTopologyMethod::CreatePlacement,
                    &hub_types::PlanCreatePlacementRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let surface: HubSurfaceRef = surface
                .as_deref()
                .context("placement add requires <surface> when creating a plan")?
                .parse()?;
            let name = name
                .as_ref()
                .context("placement add requires <name> when creating a plan")?;
            let binding = binding
                .as_ref()
                .context("placement add requires --binding when creating a plan")?;
            let prefix = prefix
                .as_ref()
                .context("placement add requires --prefix when creating a plan")?;
            let kind = kind.as_deref().unwrap_or("complete");
            let hash_range = hash_range
                .as_deref()
                .map(|raw| {
                    let (start, end) = raw
                        .split_once('-')
                        .context("--hash-range must be <start>-<end>")?;
                    let start: u32 = start.parse()?;
                    let end: u32 = end.parse()?;
                    if start >= end || end > 65_536 {
                        anyhow::bail!("hash range must satisfy 0 <= start < end <= 65536");
                    }
                    Ok(hub_types::HashRangeV1 { start, end })
                })
                .transpose()?;
            if kind == "shard" && hash_range.is_none() {
                anyhow::bail!("shard placements require a hash range");
            }
            if kind != "shard" && hash_range.is_some() {
                anyhow::bail!("only shard placements accept a hash range");
            }
            if kind == "archive" && read.as_deref() == Some("enabled") {
                anyhow::bail!("archive placements cannot enable reads");
            }
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreatePlacement,
                HubTopologyMethod::CreatePlacement,
                &hub_types::PlanCreatePlacementRequest {
                    surface: Some(surface.to_message()),
                    name: name.clone(),
                    binding_id: binding.to_string(),
                    prefix: prefix.to_string(),
                    kind: kind.into(),
                    desired_state: desired_state.clone(),
                    desired_read_enabled: Some(
                        read.as_deref()
                            .map(|value| value == "enabled")
                            .unwrap_or(kind != "archive"),
                    ),
                    read_order: Some(*read_order),
                    hash_range,
                    requires_conditional_writes: false,
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
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
        HubPlacementCmd::Update {
            access,
            surface,
            name,
            desired_state,
            read,
            read_order,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref()).await?;
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdatePlacement,
                    HubTopologyMethod::UpdatePlacement,
                    &hub_types::PlanUpdatePlacementRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            required_plan_version(mutation, "placement update")?;
            let mut update_mask = Vec::new();
            if desired_state.is_some() {
                update_mask.push("desired_state".into());
            }
            if read.is_some() {
                update_mask.push("desired_read_enabled".into());
            }
            if read_order.is_some() {
                update_mask.push("read_order".into());
            }
            if update_mask.is_empty() {
                anyhow::bail!("placement update requires at least one changed field");
            }
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdatePlacement,
                HubTopologyMethod::UpdatePlacement,
                &hub_types::PlanUpdatePlacementRequest {
                    surface: Some(surface.to_message()),
                    name: name.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    desired_state: desired_state.clone().unwrap_or_default(),
                    desired_read_enabled: read.as_deref().map(|value| value == "enabled"),
                    read_order: *read_order,
                    update_mask,
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
        HubPlacementCmd::Scan {
            access,
            surface,
            name,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement scan")?;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanScanPlacement,
                HubTopologyMethod::ScanPlacement,
                &hub_types::PlanScanPlacementRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Replicate {
            access,
            surface,
            source,
            destination,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement replication")?;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanReplicatePlacement,
                HubTopologyMethod::ReplicatePlacement,
                &hub_types::PlanReplicatePlacementRequest {
                    surface: Some(surface.to_message()),
                    source_placement_name: source.clone(),
                    destination_placement_name: destination.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Repair {
            access,
            surface,
            name,
            source,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement repair")?;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanRepairPlacement,
                HubTopologyMethod::RepairPlacement,
                &hub_types::PlanRepairPlacementRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    source_placement_name: source.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Promote {
            access,
            surface,
            name,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement promotion")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::GetWriteAuthorityResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanPromotePlacement,
                HubTopologyMethod::PromotePlacement,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementCmd::Promotion { command } => placement_promotion(printer, command).await,
        HubPlacementCmd::Drain {
            access,
            surface,
            name,
            mutation,
            operation,
            command,
        } => {
            if let Some(command) = command {
                return placement_drain(printer, command).await;
            }
            let hub = access
                .hub
                .as_deref()
                .context("placement drain requires --hub")?;
            let surface: HubSurfaceRef = surface
                .as_deref()
                .context("placement drain requires <surface-ref>")?
                .parse()?;
            let name = name
                .as_ref()
                .context("placement drain requires <placement>")?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement drain")?;
            }
            let client = hub_client(hub, access.token.as_deref()).await?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanDrainPlacement,
                HubTopologyMethod::DrainPlacement,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Remove {
            access,
            surface,
            name,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement promotion cancellation")?;
            }
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement removal")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeletePlacement,
                HubTopologyMethod::DeletePlacement,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
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
        HubPlacementCmd::Eviction { command } => placement_eviction(printer, command).await,
    }
}

async fn placement_promotion(printer: &Printer, command: &HubPlacementPromotionCmd) -> Result<()> {
    match command {
        HubPlacementPromotionCmd::Cancel {
            access,
            surface,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::GetWriteAuthorityResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCancelPlacementPromotion,
                HubTopologyMethod::CancelPlacementPromotion,
                &hub_types::SurfaceMutationRequest {
                    surface: Some(surface.to_message()),
                    expected_resource_version: mutation.if_version.clone(),
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
    }
}

async fn placement_drain(printer: &Printer, command: &HubPlacementDrainCmd) -> Result<()> {
    match command {
        HubPlacementDrainCmd::Cancel {
            access,
            surface,
            name,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement drain cancellation")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCancelPlacementDrain,
                HubTopologyMethod::CancelPlacementDrain,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
    }
}

async fn placement_eviction(printer: &Printer, command: &HubPlacementEvictionCmd) -> Result<()> {
    match command {
        HubPlacementEvictionCmd::Plan {
            access,
            surface_ref,
            placement,
            if_version,
            idempotency_key,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let surface: HubSurfaceRef = surface_ref.parse()?;
            topology_read::<_, hub_types::TopologyPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::PlanRunPlacementEviction,
                &hub_types::PlanRunPlacementEvictionRequest {
                    surface: Some(surface.to_message()),
                    placement_name: placement.clone(),
                    expected_resource_version: Some(if_version.clone()),
                    idempotency_key: idempotency_key.clone(),
                },
            )
            .await
        }
        HubPlacementEvictionCmd::Run {
            access,
            plan_id,
            confirm_hash,
            yes,
            idempotency_key,
            operation,
        } => {
            if !confirm_destructive(*yes, "placement eviction")? {
                printer.info("placement eviction cancelled");
                return Ok(());
            }
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response: hub_types::OperationResponse = client
                .call_topology(
                    HubTopologyMethod::RunPlacementEviction,
                    &hub_types::ApplyTopologyPlanRequest {
                        plan_id: plan_id.clone(),
                        confirmation_hash: confirm_hash.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                )
                .await?;
            print_or_wait_operation(printer, &client, &response, operation).await
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use aos_remote::{HashRangeV1, PlacementObservation, PlacementSpec, PlacementStatus};

    #[test]
    fn placement_json_keeps_the_normalized_snake_case_contract() {
        let placement = Placement {
            name: "west".to_string(),
            binding_name: "origin".to_string(),
            prefix: "registry/west".to_string(),
            spec: Some(PlacementSpec {
                kind: "shard".to_string(),
                desired_state: "active".to_string(),
                desired_read_enabled: true,
                read_order: 20,
                write_spec_version: 3,
                requires_conditional_writes: true,
                hash_range: Some(HashRangeV1 {
                    start: 0,
                    end: 32_768,
                }),
            }),
            observation: Some(PlacementObservation {
                state: "ready".to_string(),
                completeness: "partial".to_string(),
                observed_at: 100,
                observation_version: "4".to_string(),
                mutable_publication_id: "pub-1".to_string(),
                pending_publication_id: "pub-2".to_string(),
                watermark_resource_version: "9".to_string(),
            }),
            status: Some(PlacementStatus {
                derived_role: "replica".to_string(),
                desired_writer: false,
                observed_writer: false,
                promotion_pending: false,
                effective_read_enabled: true,
                effective_write_enabled: false,
            }),
            created_at: 90,
            updated_at: 100,
            resource_version: "5".to_string(),
        };

        assert_eq!(
            placement_json(&placement).unwrap(),
            serde_json::json!({
                "name": "west",
                "binding_name": "origin",
                "prefix": "registry/west",
                "spec": {
                    "kind": "shard",
                    "desired_state": "active",
                    "desired_read_enabled": true,
                    "read_order": 20,
                    "write_spec_version": 3,
                    "requires_conditional_writes": true,
                    "hash_range": { "start": 0, "end": 32768 },
                },
                "observation": {
                    "state": "ready",
                    "completeness": "partial",
                    "observed_at": 100,
                    "observation_version": "4",
                    "mutable_publication_id": "pub-1",
                    "pending_publication_id": "pub-2",
                    "watermark_resource_version": "9",
                },
                "status": {
                    "derived_role": "replica",
                    "desired_writer": false,
                    "observed_writer": false,
                    "promotion_pending": false,
                    "effective_read_enabled": true,
                    "effective_write_enabled": false,
                },
                "created_at": 90,
                "updated_at": 100,
                "resource_version": "5",
            })
        );
    }
}

pub(super) mod equivalence;
pub(super) mod policy;
