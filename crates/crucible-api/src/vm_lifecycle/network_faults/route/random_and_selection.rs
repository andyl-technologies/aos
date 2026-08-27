//! Computes deterministic network draws, recipient selection, and mapped inputs.

use super::*;

pub(in super::super) fn network_effect_application_error(
    action: &impl NetworkEffectContext,
    reason: &str,
) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: format!(
            "apply network effect `{}` from binding `{}`: {reason}",
            action.effect_kind().as_str(),
            action.binding()
        ),
    }
}

pub(in super::super) fn network_effect_draw(
    scenario_seed: ContentHash,
    opportunity: &FaultOpportunity,
    action: &ResolvedBindingAction,
    axis: &str,
    ordinal: u64,
) -> u64 {
    let mut material = Vec::new();
    material.extend_from_slice(&scenario_seed.bytes);
    material.extend_from_slice(&opportunity.id().bytes);
    material.extend_from_slice(&action.committed_state_id().bytes);
    material.extend_from_slice(axis.as_bytes());
    material.extend_from_slice(&ordinal.to_be_bytes());
    let digest = ContentHash::from_bytes(&material);
    let mut draw = [0_u8; 8];
    draw.copy_from_slice(&digest.bytes[..8]);
    u64::from_be_bytes(draw)
}

pub(in super::super) fn probability_fires(
    probability: crucible::model::ProbabilityMillionths,
    draw: u64,
) -> bool {
    draw % 1_000_000 < u64::from(probability.get())
}

pub(in super::super) fn uniform_inclusive(draw: u64, maximum: u64) -> u64 {
    let range = u128::from(maximum) + 1;
    ((u128::from(draw) * range) >> 64) as u64
}

// crucible-lint: allow rust-allow -- recipient selection authenticates action, opportunity, seed, topology, and membership version together.
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_recipient_subset(
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    topology: &crucible::model::WorldFaultTopology,
    membership_version: &FaultObjectId,
    drop_members: Option<&crucible::model::ObjectIdSet>,
    selection: Option<&crucible::model::NetworkSelection>,
    retain_count: Option<&crucible::model::BoundedCount>,
) -> Result<(), SchedulerError> {
    let declaration = topology
        .network_policy_artifact(membership_version)
        .ok_or_else(|| {
            network_effect_application_error(action, "recipient membership disappeared")
        })?;
    let crucible::model::NetworkPolicyArtifactKind::RecipientMembership { members } =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "recipient membership changed type after admission",
        ));
    };
    let OpportunityPayload::NetworkFrame {
        producer,
        destination,
        producer_sequence,
        ..
    } = opportunity.payload()
    else {
        return Err(network_effect_application_error(
            action,
            "recipient subset received a non-frame opportunity",
        ));
    };
    if members
        .binary_search_by(|candidate| candidate.member.cmp(destination))
        .is_err()
    {
        return Err(network_effect_application_error(
            action,
            "frame destination is absent from the admitted membership version",
        ));
    }
    if let Some(drop_members) = drop_members {
        if drop_members.as_slice().binary_search(destination).is_ok() {
            effects.mark_drop();
        }
        return Ok(());
    }
    let selection = selection
        .ok_or_else(|| network_effect_application_error(action, "recipient selection is absent"))?;
    let retain = retain_count
        .and_then(|count| usize::try_from(count.get()).ok())
        .ok_or_else(|| {
            network_effect_application_error(action, "recipient retain count exceeds host width")
        })?;
    let mut selected = members.iter().collect::<Vec<_>>();
    match selection {
        crucible::model::NetworkSelection::Oldest => selected.sort_by(|left, right| {
            left.joined_sequence
                .cmp(&right.joined_sequence)
                .then_with(|| left.member.cmp(&right.member))
        }),
        crucible::model::NetworkSelection::Newest => selected.sort_by(|left, right| {
            right
                .joined_sequence
                .cmp(&left.joined_sequence)
                .then_with(|| left.member.cmp(&right.member))
        }),
        crucible::model::NetworkSelection::CanonicalOrder => {}
        crucible::model::NetworkSelection::KeyedUniform => {
            selected.sort_by(|left, right| {
                network_recipient_rank(
                    scenario_seed,
                    action,
                    membership_version,
                    producer,
                    *producer_sequence,
                    &left.member,
                )
                .bytes
                .cmp(
                    &network_recipient_rank(
                        scenario_seed,
                        action,
                        membership_version,
                        producer,
                        *producer_sequence,
                        &right.member,
                    )
                    .bytes,
                )
                .then_with(|| left.member.cmp(&right.member))
            });
        }
    }
    if !selected
        .iter()
        .take(retain)
        .any(|candidate| &candidate.member == destination)
    {
        effects.mark_drop();
    }
    Ok(())
}

pub(in super::super) fn network_recipient_rank(
    scenario_seed: ContentHash,
    action: &ResolvedBindingAction,
    membership_version: &FaultObjectId,
    producer: &FaultObjectId,
    producer_sequence: u64,
    recipient: &FaultObjectId,
) -> ContentHash {
    let mut material = b"crucible.network-recipient-rank.v1\0".to_vec();
    material.extend_from_slice(&scenario_seed.bytes);
    material.extend_from_slice(action.binding.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(membership_version.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(producer.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(&producer_sequence.to_be_bytes());
    material.extend_from_slice(recipient.as_str().as_bytes());
    ContentHash::from_bytes(&material)
}

pub(in super::super) fn mapped_network_integer(
    action: &ResolvedBindingAction,
) -> Result<i64, SchedulerError> {
    mapped_network_integers(action)?
        .into_iter()
        .next()
        .ok_or_else(|| network_effect_application_error(action, "network lookup has no input"))
}

pub(in super::super) fn mapped_network_service_input(
    action: &ResolvedBindingAction,
    role: &str,
    expected: &crucible::model::SignalShape,
) -> Result<i64, SchedulerError> {
    let crucible::model::ResolvedMappingOutput::ServiceProfile {
        input_contracts,
        inputs,
        ..
    } = action.mapping_output.as_ref()
    else {
        return Err(network_effect_application_error(
            action,
            "network service effect requires a service-profile mapping",
        ));
    };
    if input_contracts.len() != inputs.len() {
        return Err(network_effect_application_error(
            action,
            "network service input shapes and values differ in length",
        ));
    }
    let mut matches = input_contracts
        .iter()
        .zip(inputs)
        .filter(|(contract, _value)| contract.role.as_str() == role && &contract.shape == expected);
    let (_contract, value) = matches.next().ok_or_else(|| {
        network_effect_application_error(action, "network service omitted a physical input")
    })?;
    if matches.next().is_some() {
        return Err(network_effect_application_error(
            action,
            "network service repeated a physical input shape",
        ));
    }
    mapped_network_scalar(action, value)
}

pub(in super::super) fn mapped_network_service_u64(
    action: &ResolvedBindingAction,
    role: &str,
    expected: &crucible::model::SignalShape,
) -> Result<u64, SchedulerError> {
    let crucible::model::ResolvedMappingOutput::ServiceProfile {
        input_contracts,
        inputs,
        ..
    } = action.mapping_output.as_ref()
    else {
        return Err(network_effect_application_error(
            action,
            "network service effect requires a service-profile mapping",
        ));
    };
    if input_contracts.len() != inputs.len() {
        return Err(network_effect_application_error(
            action,
            "network service input shapes and values differ in length",
        ));
    }
    let mut matches = input_contracts
        .iter()
        .zip(inputs)
        .filter(|(contract, _value)| contract.role.as_str() == role && &contract.shape == expected);
    let (_contract, value) = matches.next().ok_or_else(|| {
        network_effect_application_error(action, "network service omitted a physical input")
    })?;
    if matches.next().is_some() {
        return Err(network_effect_application_error(
            action,
            "network service repeated a physical input shape",
        ));
    }
    let crucible::model::SignalValue::U64(value) = value else {
        return Err(network_effect_application_error(
            action,
            "network service input is not an unsigned integer",
        ));
    };
    Ok(*value)
}
