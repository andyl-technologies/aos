//! Original opaque admission extraction for the output-only packet dialect.

use crucible_node_contract::{Direction, U64, canonical};
use serde::Serialize;

use crate::{
    node_contract::{ExactBoundaryPolicy, OperationAdmission, OperationFailure, OperationRequest},
    node_scheduling::InputPayload,
};

use super::{CnpSemanticInstallation, budget, refused, unknown};

#[derive(Serialize)]
struct OriginalActivation<'a> {
    generation: U64,
    activation_id: &'a crucible_node_contract::Id,
    world_binding_hash: &'a crucible_node_contract::HashRef,
    owners: &'a [crate::node_contract::OwnerIdentity],
    boundary: crucible_node_contract::Position,
}

#[derive(Serialize)]
struct OriginalGrant<'a> {
    schema: &'static str,
    operation: &'a crucible_node_contract::Id,
    route: &'a crate::node_contract::NodeRoute,
    activation: OriginalActivation<'a>,
    request: &'a OperationRequest,
    input_batch: Option<()>,
    input_watermark: U64,
}

/// Extracts complete original no-ingress correlation from an opaque common admission.
///
/// This helper is used by the independently installed packet source callback.
/// The result is portable correlation data, never a permission or qualification
/// token. The native dispatcher also authenticates the actual original peer,
/// current installed world and matching original baseline Begin before effects.
/// Every referenced common authority remains owned by the caller's original
/// admission. No empty queue or finite horizon is interpreted as producer EOF.
///
/// # Errors
/// Refuses non-output source ports, staged ingress, changed owner/world/route,
/// unsupported request or stop semantics, and complete encoded association
/// exceeding the unchanged source-selected 8 KiB ceiling. The borrowed size
/// pass precedes all report, JSON value and byte copies.
pub fn packet_common_grant_authorization(
    installation: &CnpSemanticInstallation,
    original: &OperationAdmission,
    watermark: U64,
) -> Result<InputPayload, OperationFailure> {
    let token = original.token();
    let record = original.activation().record();
    let authority = &installation.binding.authority;
    let route = token.route();
    if route.node != installation.descriptor.id
        || route.owners.len() != 1
        || route.owners[0].owner != installation.owner.owner.id
        || route.owners[0].incarnation != authority.incarnation_id
        || route.owners[0].generation != authority.owner_generation
        || record.owners != route.owners
        || record.world_binding_hash != installation.world_binding_hash
        || original.inputs().is_some()
        || watermark.get() != 0
        || installation.descriptor.ports.is_empty()
        || installation.descriptor.ports.iter().any(|port| {
            port.lanes.is_empty()
                || port
                    .lanes
                    .iter()
                    .any(|lane| lane.direction != Direction::Output)
        })
    {
        return Err(refused(
            "packet original common no-ingress owner association",
        ));
    }
    match original.request() {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        } if start <= limit
            && limit.microstep.get() == 0
            && limit.phase == crucible_node_contract::Phase::BoundaryControl => {}
        OperationRequest::BoundarySettle { start, limit }
            if start <= limit && start.time_ps == limit.time_ps => {}
        _ => return Err(refused("packet unsupported original common grant")),
    }
    let body = OriginalGrant {
        schema: "source-owned.packet-common-grant.v1",
        operation: token.operation(),
        route,
        activation: OriginalActivation {
            generation: record.generation,
            activation_id: &record.activation_id,
            world_binding_hash: &record.world_binding_hash,
            owners: &record.owners,
            boundary: record.boundary,
        },
        request: original.request(),
        input_batch: None,
        input_watermark: watermark,
    };
    let ceiling = installation.maximum_authorization_bytes.min(8192);
    budget::serialized_size(&body, ceiling)?;
    let bytes = canonical::canonical_json(&serde_json::to_value(&body).map_err(unknown)?)
        .map_err(unknown)?;
    if bytes.len() > ceiling {
        return Err(refused("packet whole original common authorization bytes"));
    }
    Ok(InputPayload {
        reference: canonical::content_ref(&bytes, "application/json").map_err(unknown)?,
        bytes,
    })
}
