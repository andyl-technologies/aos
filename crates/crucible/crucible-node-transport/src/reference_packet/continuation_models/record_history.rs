//! Checks original native proof records against the full captured model history.
//!
//! These predicates borrow decoded data only. Source archive verification still
//! binds each proof to its actual host original, causal order and common grant.

use super::*;
use crate::bodies::{BeginArguments, RequestBody, decode_request};
use crate::envelope::{Envelope, Method};
use crate::reference_packet::control::PacketNative5UnderlyingRecord;

/// Selects the precise historical relationship a Source verifier must establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketModelRecordExpectation {
    /// Requires a complete grant identical to its retained original grant row.
    CompletedGrant,
    /// Requires an Observe without a grant and the exact final full inventory.
    ///
    /// Source separately proves this original's position in the Capture history;
    /// an older observation with different inventory cannot satisfy this case.
    FinalObservation,
}

impl PacketDecodedModelSnapshot {
    /// Checks a full original native record against retained captured model data.
    ///
    /// This creates no source, kernel, socket, native installer or Core rights.
    /// The caller must separately admit simultaneous typed history scratch and
    /// bind the record's complete bytes and original host request to its archive.
    ///
    /// # Errors
    /// Refuses another kind/PID/original, malformed full model history, missing
    /// or changed saved grant, incompatible exact interval or a final inventory
    /// that omits, changes or reorders any callback, output or input association.
    pub fn authenticate_original_record_history_data(
        &self,
        record: &PacketNative5UnderlyingRecord,
        original: &Envelope,
        expectation: PacketModelRecordExpectation,
        maximum_bytes: usize,
    ) -> Result<(), ProviderError> {
        let maximum = checked_limit(maximum_bytes)?;
        crate::connection::serialized_credit(&self.record.state, maximum)?;
        original.validate()?;
        match (self.record.kind, record) {
            (PacketModelKind::Producer, PacketNative5UnderlyingRecord::Producer(record)) => {
                if record.schema != "source-owned.packet-native/2"
                    || record.native_pid != self.record.captured_process
                    || &record.original != original
                {
                    return Err(refused());
                }
                let state =
                    ProducerState::deserialize(&self.record.state).map_err(ContractError::from)?;
                authenticate_producer_data(&self.record, &state)?;
                super::super::validate_packet_program_definition(&state.events)?;
                match expectation {
                    PacketModelRecordExpectation::CompletedGrant => {
                        let grant = record.grant.as_ref().ok_or_else(refused)?;
                        authenticate_grant_request(
                            original,
                            &grant.operation,
                            grant.start,
                            grant.limit,
                        )?;
                        if !grant.complete
                            || state.grants.get(&grant.operation) != Some(grant)
                            || record.inventory != grant.inventory
                        {
                            return Err(refused());
                        }
                    }
                    PacketModelRecordExpectation::FinalObservation => {
                        let inventory = &record.inventory;
                        if original.method != Method::Observe
                            || record.grant.is_some()
                            || inventory.reached != state.reached
                            || inventory.gate_closed != state.gate_closed
                            || inventory.pending.as_slice() != &state.events[state.next_event..]
                            || inventory.retained_outputs != state.outputs
                            || inventory.private_mutations != U64::new(state.private_mutations)
                            || inventory.packet_effects != U64::new(state.packet_effects)
                        {
                            return Err(refused());
                        }
                        decode_request(original.method, &original.body)?;
                    }
                }
                Ok(())
            }
            (PacketModelKind::Reactive, PacketNative5UnderlyingRecord::Reactive(record)) => {
                super::super::connected::continuation::authenticate_record_history_data(
                    &self.record,
                    record,
                    original,
                    expectation,
                )
            }
            _ => Err(refused()),
        }
    }
}

pub(in crate::reference_packet) fn authenticate_grant_request(
    original: &Envelope,
    operation: &Id,
    start: Position,
    limit: Position,
) -> Result<(), ProviderError> {
    if original.method != Method::Begin || original.operation_id.0.as_ref() != Some(operation) {
        return Err(refused());
    }
    let RequestBody::Begin(begin) = decode_request(original.method, &original.body)? else {
        return Err(refused());
    };
    let arguments = match begin.decoded_arguments()? {
        BeginArguments::ExactRun(arguments) | BeginArguments::BoundarySettle(arguments) => {
            arguments
        }
        _ => return Err(refused()),
    };
    if arguments.grant_id != *operation || arguments.start != start || arguments.limit != limit {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("packet archived native record differs from model history")
}
