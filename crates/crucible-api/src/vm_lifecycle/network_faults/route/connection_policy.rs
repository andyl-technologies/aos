//! Applies bounded connection-state mutations and packet-key extraction.

use super::*;

// crucible-lint: allow rust-allow -- connection-state evaluation preserves the complete authenticated frame context.
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_connection_state(
    payload: &[u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    state: &mut NetworkEffectRuntimeState,
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    table_bound: u32,
    flow_key: &FaultObjectId,
    state_machine: &FaultObjectId,
    transition_event: &FaultObjectId,
    overflow: &crucible::model::NetworkConnectionOverflow,
    typed_response: &mut Option<FaultObjectId>,
    resource_limits: FaultResourceLimits,
) -> Result<Option<u64>, SchedulerError> {
    let flow = network_packet_key(payload, topology, flow_key, action)?;
    let owner = NetworkEffectStateKey::from_action(action);
    let initial = network_state_machine_initial(topology, state_machine, action)?;
    admit_network_connection_entry(state, &owner, &flow, table_bound, resource_limits)?;
    let table = state.connection_tables.entry(owner).or_default();
    if !table.contains_key(&flow)
        && u32::try_from(table.len()).map_or(true, |length| length >= table_bound)
    {
        use crucible::model::NetworkConnectionOverflow as Overflow;
        match overflow {
            Overflow::DropNewest => {
                effects.mark_drop();
                return Ok(None);
            }
            Overflow::TypedError { response } => {
                request_typed_response(typed_response, response, action)?;
                effects.mark_drop();
                return Ok(None);
            }
            Overflow::EvictOldest => {
                let victim = table
                    .iter()
                    .min_by_key(|(identity, entry)| {
                        (entry.last_used_nanos, entry.created_by, **identity)
                    })
                    .map(|(identity, _entry)| *identity)
                    .ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "connection table reached its bound without an eviction candidate",
                        )
                    })?;
                table.remove(&victim);
            }
            Overflow::KeyedEviction => {
                let count = u64::try_from(table.len()).map_err(|_error| {
                    network_effect_application_error(
                        action,
                        "connection table candidate count exceeds u64",
                    )
                })?;
                let index = usize::try_from(
                    network_effect_draw(
                        scenario_seed,
                        opportunity,
                        action,
                        "connection-eviction",
                        0,
                    ) % count,
                )
                .map_err(|_error| {
                    network_effect_application_error(
                        action,
                        "connection eviction index exceeds host width",
                    )
                })?;
                let victim = table.keys().nth(index).copied().ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "connection eviction candidate disappeared",
                    )
                })?;
                table.remove(&victim);
            }
        }
    }
    let entry = table.entry(flow).or_insert_with(|| NetworkConnectionEntry {
        machine: NetworkStateMachineRuntime {
            current: initial,
            pending: Vec::new(),
            transition_sequence: action.transition_sequence,
        },
        created_by: opportunity.id(),
        last_used_nanos: opportunity.coordinate().virtual_nanos,
    });
    entry.last_used_nanos = opportunity.coordinate().virtual_nanos;
    advance_network_state_machine(
        &mut entry.machine,
        topology,
        state_machine,
        transition_event,
        action,
        opportunity.coordinate().virtual_nanos,
    )
}

pub(in super::super) fn network_packet_key(
    payload: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    key: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<ContentHash, SchedulerError> {
    Ok(ContentHash::from_bytes(&network_packet_key_bytes(
        payload, topology, key, action,
    )?))
}

pub(in super::super) fn network_packet_key_bytes(
    payload: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    key: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<Vec<u8>, SchedulerError> {
    let declaration = topology.network_policy_artifact(key).ok_or_else(|| {
        network_effect_application_error(action, "network packet key disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::PacketKey { ranges } = &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "network packet key changed type after admission",
        ));
    };
    let mut material = Vec::new();
    for range in ranges {
        let start = usize::try_from(range.start()).map_err(|_error| {
            network_effect_application_error(action, "packet key offset exceeds host width")
        })?;
        let end = usize::try_from(range.end()).map_err(|_error| {
            network_effect_application_error(action, "packet key end exceeds host width")
        })?;
        let bytes = payload.get(start..end).ok_or_else(|| {
            network_effect_application_error(action, "packet key range is outside the frame")
        })?;
        material.extend_from_slice(&range.length().to_be_bytes());
        material.extend_from_slice(bytes);
    }
    Ok(material)
}
