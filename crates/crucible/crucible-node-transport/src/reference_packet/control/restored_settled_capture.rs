//! Authenticates the settled Capture checkpoint against the actual live model.
//!
//! The native17 spent request owner calls this only after its independent action
//! debit and Source-MAC/current Connection checks. Raw content remains owned by
//! Control; each completed decoded proof is installed in the same attempt before
//! later correspondence checks. No checkpoint, equality or decoded model issues
//! a Capture permit, opens a physical gate or replaces the administrative ticket.

use super::*;
use crate::reference_packet::service::{
    complete_restore::PacketNativeRestoredRecord,
    restored_settled_capture::PacketRestoredSettledCaptureRequest,
};
use crate::retained_metadata::MetadataObserver;

/// Retains independently decoded native checkpoint and actual lineage projection.
#[derive(serde::Serialize)]
pub(crate) struct NativeRestoredSettledCheckpointAttempt {
    restored: Option<PacketNativeRestoredRecord>,
    #[serde(serialize_with = "serialize_capture_underlying17")]
    underlying: Option<PacketNative5UnderlyingRecord>,
    expected_lineage: Option<PacketNativeRestoredRecord>,
    validated: bool,
}

impl PacketControl {
    /// Retains and checks the exact current proof before native17 Capture output.
    ///
    /// Its caller separately prepays two bounded proof decodes plus the actual
    /// lineage clone and all error/partial owners in the new native action row.
    /// This method never borrows unused old suffix credit or selects a route.
    ///
    /// # Errors
    /// Refuses a reused slot, noncurrent/fenced/held Control, unretained or changed
    /// proof, old model grant, changed full inventory, incomplete current model,
    /// changed genuine Commit ancestry, or an ineligible administrative cut.
    pub(crate) fn authenticate_restored_settled_checkpoint_into(
        &self,
        request: &PacketRestoredSettledCaptureRequest,
        destination: &mut Option<NativeRestoredSettledCheckpointAttempt>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(refused());
        }
        *destination = Some(NativeRestoredSettledCheckpointAttempt {
            restored: None,
            underlying: None,
            expected_lineage: None,
            validated: false,
        });
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || !self.restoration_activation_required
            || self.current_operation.is_some()
            || self.original_physical_gate_held()?
        {
            return Err(refused());
        }
        request.validate_data()?;
        let attempt = destination.as_mut().ok_or_else(refused)?;
        let raw = self
            .content
            .get(&request.current_record)
            .ok_or_else(refused)?;
        request.current_record.verify(raw)?;
        // Retain the bounded strict decode before validating its local grammar,
        // so later correspondence refusal preserves this actual decoded child.
        attempt.restored = Some(
            serde_json::from_value(canonical::parse_json(raw, 65_536)?)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let restored = attempt.restored.as_ref().ok_or_else(refused)?;
        restored.validate_data()?;
        if restored.physical_gate_held
            || restored.native_receipt.native_record != request.current_model
        {
            return Err(refused());
        }
        let original = &restored.native_receipt.original;
        if original.method != Method::Observe {
            return Err(refused());
        }
        let (hash, reply) = self
            .originals
            .get(original.request_id.0.as_ref().ok_or_else(refused)?)
            .ok_or_else(refused)?;
        if *hash != original.request_hash(crate::envelope::RequestOrigin::Controller)?
            || !reply
                .evidence
                .iter()
                .any(|(reference, bytes)| reference == &request.current_record && bytes == raw)
        {
            return Err(refused());
        }
        let model_raw = self
            .content
            .get(&request.current_model)
            .ok_or_else(refused)?;
        request.current_model.verify(model_raw)?;
        attempt.underlying = Some(restored.native_receipt.verify_original_record_data(
            &self.selection,
            std::process::id(),
            original,
            model_raw,
        )?);
        // The actual native evidence owner supplies immutable ancestry. A
        // caller's checkpoint cannot manufacture or select a Commit/Hold edge.
        attempt.expected_lineage = Some(
            self.complete_restored_evidence
                .as_ref()
                .ok_or_else(refused)?
                .wrap(restored.native_receipt.clone(), false)?,
        );
        let expected = attempt.expected_lineage.as_ref().ok_or_else(refused)?;
        if restored.schema != expected.schema
            || restored.captured_owner_state != expected.captured_owner_state
            || restored.captured_journal != expected.captured_journal
            || restored.mapping != expected.mapping
            || restored.restore_commit != expected.restore_commit
            || restored.restore_response != expected.restore_response
            || restored.context_digest != expected.context_digest
            || restored.physical_gate_held != expected.physical_gate_held
        {
            return Err(refused());
        }
        let lineage = &request.scope.restoration;
        let target = &request.scope.target;
        let receipt = &restored.native_receipt;
        if lineage.captured_owner_state != restored.captured_owner_state
            || lineage.captured_journal != restored.captured_journal
            || lineage.mapping != restored.mapping
            || lineage.commit_request != restored.restore_commit
            || lineage.commit_response != restored.restore_response
            || lineage.context_digest != restored.context_digest
            || target.native_pid != receipt.native_pid
            || target.session != receipt.session
            || target.incarnation != receipt.incarnation
            || target.node != receipt.node
            || target.owner != receipt.owner
            || target.owner_generation != receipt.owner_generation
            || target.binding_hash != receipt.binding_hash
            || target.world != receipt.world
        {
            return Err(refused());
        }
        match (
            &self.program,
            attempt.underlying.as_ref().ok_or_else(refused)?,
        ) {
            (
                NativeProgram::OutputOnly(program),
                PacketNative5UnderlyingRecord::Producer(record),
            ) => {
                if record.grant.is_some() {
                    return Err(refused());
                }
                authenticate_producer_inventory(program, &record.inventory)?;
                program.authenticate_original_capture_cut(request.capture.cut)?;
            }
            (
                NativeProgram::Connected(program),
                PacketNative5UnderlyingRecord::Reactive(record),
            ) => {
                if record.grant.is_some() {
                    return Err(refused());
                }
                program.authenticate_original_settled_inventory_data(&record.inventory)?;
                program.authenticate_original_capture_cut(request.capture.cut)?;
            }
            _ => return Err(refused()),
        }
        attempt.validated = true;
        Ok(())
    }
}

fn authenticate_producer_inventory(
    program: &super::super::PacketProgram,
    inventory: &PacketInventory,
) -> Result<(), ProviderError> {
    program.observe_original_live_capture_metadata(&mut MetadataObserver::new())?;
    let pending = program
        .events
        .get(program.next_event..)
        .ok_or_else(refused)?;
    if inventory.reached != program.reached
        || inventory.gate_closed != program.gate_closed
        || inventory.pending.as_slice() != pending
        || inventory.retained_outputs != program.outputs
        || inventory.private_mutations.get() != program.private_mutations
        || inventory.packet_effects.get() != program.packet_effects
    {
        return Err(refused());
    }
    Ok(())
}

impl NativeRestoredSettledCheckpointAttempt {
    /// Appends all completed proof owners without clearing any caller bank.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        for record in [&self.restored, &self.expected_lineage]
            .into_iter()
            .flatten()
        {
            let PacketNativeRestoredRecord {
                schema,
                native_receipt,
                captured_owner_state,
                captured_journal,
                mapping,
                restore_commit,
                restore_response,
                context_digest,
                physical_gate_held,
            } = record;
            observer.observe(schema)?;
            observer.observe(native_receipt)?;
            observer.observe(captured_owner_state)?;
            observer.observe(captured_journal)?;
            observer.observe(mapping)?;
            observer.observe(restore_commit)?;
            observer.observe(restore_response)?;
            observer.observe(context_digest)?;
            observer.observe(physical_gate_held)?;
        }
        if let Some(record) = &self.underlying {
            match record {
                PacketNative5UnderlyingRecord::Producer(record) => {
                    observer.observe(record.as_ref())?;
                    // Box's inline payload remains an independent allocation.
                    observer.vector::<PacketNativeRecord>(1)?;
                }
                PacketNative5UnderlyingRecord::Reactive(record) => {
                    observer.observe(record.as_ref())?;
                    observer.vector::<super::super::connected::PacketConnectedNativeRecord>(1)?;
                }
            }
        }
        observer.observe(&self.validated)
    }

    pub(crate) fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()+size_of::<Option<Self>>()
            +size_of::<&Self>()+size_of::<&mut Option<Self>>()
            +size_of::<PacketNativeRestoredRecord>()*2
            +size_of::<Result<PacketNativeRestoredRecord,ProviderError>>()
            +size_of::<PacketNative5UnderlyingRecord>()
            +size_of::<Result<PacketNative5UnderlyingRecord,ProviderError>>()
            +size_of::<Option<&PacketNativeRestoredRecord>>()
            +size_of::<[&Option<PacketNativeRestoredRecord>;2]>()
            +size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<PacketNativeRestoredRecord>,2>>>()
            +size_of::<&PacketNative5UnderlyingRecord>()
            +size_of::<MetadataObserver<'static>>()
            +size_of::<Result<(),ProviderError>>()
            +super::super::connected::PacketConnectedProgram::original_settled_inventory_counter_scratch_data()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native17 Capture checkpoint differs from live restored model")
}

// crucible-lint: allow panic-shortcut -- actual model and negative current eligibility are observations.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::{PacketEvent, PacketProgram};

    #[test]
    fn actual_producer_inventory_match_rejects_changed_or_failed_current_model()
    -> Result<(), Box<dyn std::error::Error>> {
        let (effect, _peer) = std::os::unix::net::UnixDatagram::pair()?;
        let event = PacketEvent {
            id: Id::new("capture17-current-event")?,
            evaluation: Position::new(U64::new(2), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(3), U64::new(0), Phase::Publication),
            payload: Some(Bytes::new(b"still pending".to_vec())),
        };
        let mut model = PacketProgram::new(vec![event], effect)?;
        model.open_gate()?;
        let actual = model.inventory();
        authenticate_producer_inventory(&model, &actual)?;

        let mut changed = actual.clone();
        changed.packet_effects = U64::new(actual.packet_effects.get() + 1);
        assert!(authenticate_producer_inventory(&model, &changed).is_err());
        model.failed = true;
        assert!(authenticate_producer_inventory(&model, &actual).is_err());
        assert_eq!(model.events.len(), 1);
        assert!(model.failed);
        Ok(())
    }
}

fn serialize_capture_underlying17<S: serde::Serializer>(
    value: &Option<PacketNative5UnderlyingRecord>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    enum Underlying<'a> {
        Producer(&'a PacketNativeRecord),
        Reactive(&'a super::super::connected::PacketConnectedNativeRecord),
    }
    value
        .as_ref()
        .map(|value| match value {
            PacketNative5UnderlyingRecord::Producer(record) => {
                Underlying::Producer(record.as_ref())
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                Underlying::Reactive(record.as_ref())
            }
        })
        .serialize(serializer)
}
