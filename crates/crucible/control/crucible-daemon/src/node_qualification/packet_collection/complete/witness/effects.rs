//! Reads independent actual datagrams without borrowing source outcome projections.

use crucible_node_transport::reference_packet::connected::{
    PacketConnectedPublication, PacketDeliveredInput, PacketReaction,
};
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReactiveEffect {
    Delivery {
        delivery: PacketDeliveredInput,
    },
    Reaction {
        operation: Id,
        reaction: PacketReaction,
    },
    Publication {
        publication: PacketConnectedPublication,
    },
}

// crucible-lint: allow rust-allow -- Inline effects occupy the complete table reserved before Child; boxing would introduce a new allocation per received effect.
#[allow(clippy::large_enum_variant)]
pub(super) enum Effect {
    Producer { bytes: [u8; 33], length: usize },
    Reactive(ReactiveEffect),
}

pub(super) fn drain(
    oracle: &PacketCompleteNativeOracle,
    member: usize,
    observed: &mut Observed,
) -> Result<(), QualificationError> {
    loop {
        // A complete source trace is bounded before parsing. The extra byte
        // detects oversized/truncated datagrams without accepting a prefix.
        let mut buffer = [0u8; 65_537];
        oracle
            .receiver_reader
            .authenticate_original_group(&oracle.receiver_group)
            .map_err(native_failure)?;
        let Some(length) = oracle
            .receiver_reader
            .receive(member, &mut buffer)
            .map_err(native_failure)?
        else {
            break;
        };
        if length > 65_536 || observed.effects[member].len() == MAXIMUM_EFFECTS {
            return Err(refused());
        }
        let credit = length
            .checked_mul(4)
            .and_then(|bytes| observed.bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= oracle.maximum_bytes)
            .ok_or_else(refused)?;
        let effect = match &oracle.programmes[member] {
            PacketConnectedSourceProgram::Producer { program } => {
                let index = observed.effects[member].len();
                let event = program.events.get(index).ok_or_else(refused)?;
                let valid = match &event.payload {
                    None => length == 1 && buffer[0] == 0,
                    Some(payload) => {
                        length == payload.as_slice().len() + 1
                            && buffer[0] == 1
                            && &buffer[1..length] == payload.as_slice()
                    }
                };
                if !valid || length > 33 {
                    return Err(refused());
                }
                let mut bytes = [0; 33];
                bytes[..length].copy_from_slice(&buffer[..length]);
                Effect::Producer { bytes, length }
            }
            PacketConnectedSourceProgram::Reactive { .. } => {
                let value = canonical::parse_json(&buffer[..length], 65_536)?;
                if canonical::canonical_json(&value)? != buffer[..length] {
                    return Err(refused());
                }
                let effect: ReactiveEffect = serde_json::from_value(value)
                    .map_err(crucible_node_format::ContractError::from)?;
                Effect::Reactive(effect)
            }
        };
        observed.effects[member].push(effect);
        observed.bytes = credit;
    }
    Ok(())
}

pub(super) fn verify_prefix(
    oracle: &PacketCompleteNativeOracle,
    member: usize,
    observed: &Observed,
) -> Result<(), QualificationError> {
    for seal in observed.seals.iter().filter(|seal| seal.member == member) {
        match &seal.body {
            NativeBody::Producer(record) => {
                let completed = record
                    .inventory
                    .private_mutations
                    .get()
                    .checked_add(record.inventory.packet_effects.get())
                    .ok_or_else(refused)?;
                if completed > observed.effects[member].len() as u64 {
                    return Err(refused());
                }
                for effect in &observed.effects[member] {
                    let Effect::Producer { bytes, length } = effect else {
                        return Err(refused());
                    };
                    if *length == 0 || bytes[0] > 1 {
                        return Err(refused());
                    }
                }
            }
            NativeBody::Reactive(record) => {
                let mut deliveries = Vec::new();
                let mut reactions = 0u64;
                let mut publications = 0u64;
                for effect in &observed.effects[member] {
                    let Effect::Reactive(effect) = effect else {
                        return Err(refused());
                    };
                    match effect {
                        ReactiveEffect::Delivery { delivery } => deliveries.push(delivery),
                        ReactiveEffect::Reaction { .. } => reactions += 1,
                        ReactiveEffect::Publication { .. } => publications += 1,
                    }
                }
                if record.inventory.delivered_inputs.len() > deliveries.len()
                    || !record
                        .inventory
                        .delivered_inputs
                        .iter()
                        .zip(deliveries)
                        .all(|(a, b)| a == b)
                    || record.inventory.reactions_completed.get() > reactions
                    || record.inventory.packet_effects.get() > publications
                {
                    return Err(refused());
                }
            }
            NativeBody::Stage(_) | NativeBody::Commit(_) => {}
        }
    }
    // This check permits an independently observed effect to arrive before its
    // original Poll. Final grant authentication requires complete equality.
    oracle.roster.sources[member]
        .authenticate_current_native()
        .map_err(native_failure)
}
