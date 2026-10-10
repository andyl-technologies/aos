//! Borrows the public measurement's exact original accepted-input custody rows.
//!
//! Only the explicitly selected source codecs are enumerated. Prior public
//! receipts and upstream producer proofs remain unresolved original references;
//! their shapes or hashes never establish a source class or a dependency leaf.

use super::*;

const MAXIMUM_OBJECTS: usize = 80;
const MAXIMUM_BYTES: usize = 1024 * 1024;

impl OriginalLineageWindow<'_> {
    /// Borrows original public measurement and native consumption dependencies.
    ///
    /// The owning controller has already authenticated this window's actual
    /// Realize/Input/Begin replies and native Close. This inventory additionally
    /// binds the measurement to the exact accepted-input receipt and its frozen
    /// pending batch. The controller borrow prevents ACK or replacement while
    /// the returned bodies are in use. Installed source adoption is separate.
    ///
    /// Cumulative checksum ancestry remains an explicit preceding public chain;
    /// it does not become an event's same-time `causal_parent_ids`.
    ///
    /// # Errors
    /// Refuses invalid or excessive credits, absent or changed original bodies,
    /// unsupported custody/pending geometry, conflicting rows, or aggregate
    /// byte exhaustion. It performs no native effects, upload, or ACK.
    pub fn measurement_evidence(
        &self,
        maximum_objects: usize,
        maximum_bytes: usize,
    ) -> Result<OriginalLineageEvidence<'_>, ProviderError> {
        if maximum_objects == 0
            || maximum_objects > MAXIMUM_OBJECTS
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_BYTES
        {
            return Err(credit());
        }

        let control: ControlReceipt =
            validated(self.controller, &self.measurement.accepted_input_custody)?;
        let custody: InputCustodyRecord = validated(self.controller, &control.record_ref)?;
        let pending: PendingInventory = validated(self.controller, &custody.pending_inventory)?;
        self.validate_input_inventory(&control, &custody, &pending)?;

        let native = self.native_evidence(72, 600 * 1024)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(native.objects().len() + 4)
            .map_err(|_| credit())?;
        rows.extend(
            native
                .objects()
                .iter()
                .map(|object| (object.reference().clone(), object.dependencies().to_vec())),
        );

        rows.push((
            self.measurement.accepted_input_custody.clone(),
            vec![control.record_ref.clone()],
        ));
        rows.push((control.record_ref, vec![custody.pending_inventory.clone()]));
        rows.push((
            custody.pending_inventory,
            vec![self.relation.input_batch.clone()],
        ));

        let mut dependencies = vec![
            self.measurement.consumption_relation.clone(),
            self.measurement.accepted_input_custody.clone(),
        ];
        if let Some(previous) = &self.measurement.previous_publication {
            dependencies.extend([
                previous.measurement.clone(),
                previous.stop_receipt.clone(),
                previous.observation_batch.clone(),
                previous.publication_consumption.clone(),
                previous.committed_observation.clone(),
            ]);
        }
        rows.push((self.measurement_ref.clone(), dependencies));

        rows::collect(
            self.controller,
            self.measurement_ref.clone(),
            rows,
            maximum_objects,
            maximum_bytes,
        )
    }

    fn validate_input_inventory(
        &self,
        control: &ControlReceipt,
        custody: &InputCustodyRecord,
        pending: &PendingInventory,
    ) -> Result<(), ProviderError> {
        let [entry] = pending.entries.as_slice() else {
            return Err(invalid());
        };
        // This selected package creates exactly the accepted batch row. A
        // future pending-state codec must be explicitly selected before adding
        // timers, outputs or extra evidence; unknown rows are never omitted.
        if !control.extensions.is_empty()
            || !custody.extensions.is_empty()
            || !custody.evidence_refs.is_empty()
            || !pending.extensions.is_empty()
            || !entry.extensions.is_empty()
            || entry.id.as_str() != "accepted-input"
            || entry.kind != PendingKind::Input
            || entry.owner_id != self.origin.owner
            || entry.state_ref != self.relation.input_batch
            || entry.deadline.kind != BoundKind::Unknown
            || entry.deadline.position.is_some()
            || entry.deadline.evidence.is_some()
            || !pending.complete
            || pending.execution_owner_id != self.origin.owner
            || pending.owner_generation != self.origin.owner_generation
            || pending.owner_binding_hash != self.stop.owner_binding_hash
            || pending.world_binding_hash != self.stop.world_binding_hash
            || pending.activation_id.as_ref() != Some(&self.stop.activation_id)
            || pending.world_generation != self.stop.world_generation
            || pending.input_watermark != self.input.batch_sequence
            || pending.input_epoch != self.input.input_epoch
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original lineage public evidence inventory credit")
}
