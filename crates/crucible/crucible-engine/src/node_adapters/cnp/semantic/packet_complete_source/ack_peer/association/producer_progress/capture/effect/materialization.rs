//! Materializes only genuine completed Source output into its Core destination.
//!
//! A nested Source-owned cell keeps every initialized copy and spent/failure
//! flag while the outer Completion remains immutably borrowed. No decoded DATA,
//! callback limits or standalone constructor can produce this materialization.

use super::super::materialization_storage::{
    CaptureMaterializationStorage, EVIDENCE_COUNT, OUTPUT_COUNT, media_types, output_metadata_data,
};
use super::*;
use crate::node_contract::{
    InstalledNativeCapture, InstalledOriginalLineageCapture, NativeCaptureLimits, NativeStateKey,
};
use std::{
    cell::{Ref, RefMut},
    mem::size_of,
};

struct PayloadCopy {
    started: bool,
    completed: bool,
    reference: Option<ContentRef>,
    bytes: Vec<u8>,
}

impl PayloadCopy {
    const fn empty() -> Self {
        Self {
            started: false,
            completed: false,
            reference: None,
            bytes: Vec::new(),
        }
    }

    fn copy_data(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
        media: &str,
        bound: usize,
    ) -> Result<(), RuntimeError> {
        if self.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        reference
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if reference.media_type != media || bytes.is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
        if bytes.len() > bound {
            return Err(RuntimeError::ResourceLimit);
        }
        self.reference = Some(reference.clone());
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.bytes.capacity() > bound {
            return Err(RuntimeError::ResourceLimit);
        }
        self.bytes.extend_from_slice(bytes);
        reference
            .verify(&self.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.completed = true;
        Ok(())
    }

    fn take_data(&mut self) -> Option<crate::node_scheduling::InputPayload> {
        if !self.completed {
            return None;
        }
        Some(crate::node_scheduling::InputPayload {
            reference: self.reference.take()?,
            bytes: std::mem::take(&mut self.bytes),
        })
    }

    fn restore_data(&mut self, value: Option<crate::node_scheduling::InputPayload>) {
        if let Some(value) = value {
            self.reference = Some(value.reference);
            self.bytes = value.bytes;
        }
    }

    fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            completed: _,
            reference,
            bytes,
        } = self;
        let reference = reference
            .as_ref()
            .map_or(Ok(0), NodeRuntime::capture_reference_storage)?;
        super::super::construction_quote::sum(&[reference, bytes.capacity()], maximum)
    }
}

/// Keeps every partial output copy inside the actual Source once owner.
pub(crate) struct CaptureMaterializationOwner {
    started: bool,
    failed: bool,
    transferred: bool,
    owner: Option<Id>,
    participants: Vec<Id>,
    key: Option<NativeStateKey>,
    slots: [PayloadCopy; OUTPUT_COUNT],
    evidence: Vec<crate::node_scheduling::InputPayload>,
    born: CaptureBornOwner,
}

impl CaptureMaterializationOwner {
    pub(crate) fn empty() -> Self {
        Self {
            started: false,
            failed: false,
            transferred: false,
            owner: None,
            participants: Vec::new(),
            key: None,
            slots: std::array::from_fn(|_| PayloadCopy::empty()),
            evidence: Vec::new(),
            born: CaptureBornOwner::empty(),
        }
    }

    /// Counts actual backing; its enclosing Source already owns this inline root.
    pub(crate) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            failed: _,
            transferred: _,
            owner,
            participants,
            key,
            slots,
            evidence,
            born,
        } = self;
        let mut total = participants
            .capacity()
            .checked_mul(size_of::<Id>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for participant in participants {
            total = super::super::construction_quote::sum(
                &[total, participant.allocated_capacity()],
                maximum,
            )?;
        }
        if let Some(owner) = owner {
            total = super::super::construction_quote::sum(
                &[total, owner.allocated_capacity()],
                maximum,
            )?;
        }
        if let Some(key) = key {
            total = super::super::construction_quote::sum(
                &[total, NodeRuntime::capture_native_key_storage(key)?],
                maximum,
            )?;
        }
        for slot in slots {
            total = super::super::construction_quote::sum(
                &[total, slot.retained_storage_data(maximum)?],
                maximum,
            )?;
        }
        total = super::super::construction_quote::sum(
            &[
                total,
                evidence
                    .capacity()
                    .checked_mul(size_of::<crate::node_scheduling::InputPayload>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        for value in evidence {
            total = super::super::construction_quote::sum(
                &[
                    total,
                    value.bytes.capacity(),
                    NodeRuntime::capture_reference_storage(&value.reference)?,
                ],
                maximum,
            )?;
        }
        super::super::construction_quote::sum(
            &[total, born.retained_storage_data(maximum)?],
            maximum,
        )
    }

    fn copy_metadata_data(
        &mut self,
        source: &PacketCompleteSemanticSource,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let metadata = output_metadata_data(source)?;
        self.owner = Some(metadata.0.clone());
        self.retained_storage_data(maximum)?;
        self.participants
            .try_reserve_exact(metadata.1.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.participants.capacity() > metadata.1.len() {
            return Err(RuntimeError::ResourceLimit);
        }
        for participant in metadata.1 {
            self.participants.push(participant.clone());
            self.retained_storage_data(maximum)?;
        }
        self.key = Some(NativeStateKey {
            implementation: metadata.2.clone(),
            profile: metadata.3.clone(),
            schema: metadata.4.clone(),
        });
        self.retained_storage_data(maximum)?;
        self.evidence
            .try_reserve_exact(EVIDENCE_COUNT)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.evidence.capacity() > EVIDENCE_COUNT {
            return Err(RuntimeError::ResourceLimit);
        }
        self.retained_storage_data(maximum)?;
        Ok(())
    }

    // No allocation or fallible fence follows the first successful owner move.
    // If an internal field is absent, restore every taken object before refusal.
    fn move_into_data(
        &mut self,
        cut: crucible_node_format::Position,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), RuntimeError> {
        let values =
            std::array::from_fn::<_, OUTPUT_COUNT, _>(|index| self.slots[index].take_data());
        let owner = self.owner.take();
        let key = self.key.take();
        let index = self.born.take_index_payload_data();
        match (owner, key, values, index) {
            (
                Some(owner),
                Some(key),
                [
                    Some(snapshot),
                    Some(control),
                    Some(before),
                    Some(anchor),
                    Some(after),
                    Some(controller),
                    Some(semantic),
                    Some(node),
                    Some(scope),
                    Some(prefix),
                    Some(journal),
                ],
                Some(index),
            ) => {
                self.evidence.push(control);
                self.evidence.push(before);
                self.evidence.push(anchor);
                self.evidence.push(after);
                self.evidence.push(controller);
                self.evidence.push(semantic);
                self.evidence.push(node);
                self.evidence.push(scope);
                self.evidence.push(prefix);
                // The imported Index3 is an independently funded twelfth body.
                // Its complete bank was checked before this atomic move.
                self.evidence.push(index);
                *completed = Some(InstalledOriginalLineageCapture {
                    native: InstalledNativeCapture {
                        owner,
                        participants: std::mem::take(&mut self.participants),
                        key,
                        cut,
                        state: snapshot,
                        evidence: std::mem::take(&mut self.evidence),
                        artifacts: Vec::new(),
                    },
                    journal,
                });
                self.transferred = true;
                self.failed = false;
                Ok(())
            }
            (owner, key, values, index) => {
                self.born.restore_index_payload_data(index);
                self.owner = owner;
                self.key = key;
                for (slot, value) in self.slots.iter_mut().zip(values) {
                    slot.restore_data(value);
                }
                Err(RuntimeError::InvalidReceipt)
            }
        }
    }

    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<PayloadCopy>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&mut PayloadCopy>()
            + size_of::<&CaptureMaterializationStorage>()
            + size_of::<InstalledOriginalLineageCapture>()
            + size_of::<Option<InstalledOriginalLineageCapture>>()
            + size_of::<&mut Option<InstalledOriginalLineageCapture>>()
            + size_of::<(
                Option<Id>,
                Option<NativeStateKey>,
                [Option<crate::node_scheduling::InputPayload>; OUTPUT_COUNT],
                Option<crate::node_scheduling::InputPayload>,
            )>()
            + size_of::<crucible_node_format::HashRef>()
            + size_of::<Ref<'static, Self>>()
            + size_of::<RefMut<'static, Self>>()
            + size_of::<Result<Ref<'static, Self>, std::cell::BorrowError>>()
            + size_of::<Result<RefMut<'static, Self>, std::cell::BorrowMutError>>()
            + size_of::<[(&ContentRef, &[u8]); OUTPUT_COUNT]>()
            + size_of::<[Option<crate::node_scheduling::InputPayload>; OUTPUT_COUNT]>()
            + size_of::<
                std::array::IntoIter<Option<crate::node_scheduling::InputPayload>, OUTPUT_COUNT>,
            >()
            + size_of::<std::slice::Iter<'static, PayloadCopy>>()
            + size_of::<std::slice::IterMut<'static, PayloadCopy>>()
            + size_of::<
                std::iter::Zip<
                    std::slice::IterMut<'static, PayloadCopy>,
                    std::array::IntoIter<
                        Option<crate::node_scheduling::InputPayload>,
                        OUTPUT_COUNT,
                    >,
                >,
            >()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<std::slice::Iter<'static, crate::node_scheduling::InputPayload>>()
            + size_of::<NativeCaptureLimits>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + returned_header(|| blake3::Hash::from_bytes([0; 32]).to_hex())
            + CaptureMaterializationStorage::counter_scratch_data()
            + CaptureBornOwner::counter_scratch_data()
    }
}

fn returned_header<T>(_: impl FnOnce() -> T) -> usize {
    size_of::<T>()
}

impl OriginalSourceRestoredCaptureCompletion<'_> {
    fn materialization_payloads_data(
        &self,
    ) -> Result<[(&ContentRef, &[u8]); OUTPUT_COUNT], RuntimeError> {
        let objects = self
            .finalization
            .objects
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        objects
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let transferred = |reference| {
            self.sdk
                .transferred_object_data(reference)
                .map_err(|_| RuntimeError::InvalidReceipt)
        };
        let before = self
            .native
            .before_protocol_bytes_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok([
            (&objects.snapshot, transferred(&objects.snapshot)?),
            (&objects.control, transferred(&objects.control)?),
            (&objects.before, before),
            (&objects.anchor, transferred(&objects.anchor)?),
            (&objects.after, transferred(&objects.after)?),
            self.host_protocol_data()?,
            self.semantic_data(),
            self.node_data(),
            self.scope_proof_data()?,
            self.history_prefix_data(),
            self.journal_data()?,
        ])
    }

    /// Copies completed native17 output once into its actual Core destination.
    ///
    /// The same opaque Completion, Source and claim supply original row, World,
    /// ticket, Runtime and native/SDK finalizer conjunctions. Callback ceilings
    /// only constrain the already funded output row. Full ticket validation is
    /// performed by the owning Node before and after the enclosing Source effect.
    /// Each initialized copy remains in the Source's nested cell on refusal.
    ///
    /// # Errors
    /// Refuses foreign or repeated custody, an occupied destination, a stale
    /// actual claim, incomplete SDK/native evidence, changed key/roster/bytes,
    /// duplicate output roles or any independent native/output-copy ceiling.
    pub(crate) fn materialize_installed_capture_into_data(
        &self,
        source: &PacketCompleteSemanticSource,
        claim: &OriginalRestoredCaptureClaim<'_>,
        limits: NativeCaptureLimits,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        let mut owner = self
            .materialization
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owner.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        owner.started = true;
        owner.failed = true;
        if completed.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.authenticate_claim_data(
            claim.row_data(),
            claim.world_data(),
            claim.ticket_data(),
            claim.runtime_record_data(),
            claim.runtime_object_data(),
        )?;
        claim.authenticate_current_data(source, self.row.controller)?;
        self.row.authenticate_capture_output_limits_data(limits)?;
        let row = &self.row.materialization;
        let maximum = row.retained.min(self.row.maximum);
        let metadata = output_metadata_data(source)?;
        if metadata.0 != &claim.ticket_data().owner().owner
            || metadata.1.as_slice() != claim.ticket_data().participants()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        owner.copy_metadata_data(source, maximum)?;
        owner.born.prepare_data(self, source, maximum)?;
        owner.retained_storage_data(maximum)?;

        let payloads = self.materialization_payloads_data()?;
        let media = media_types();
        let mut total_bytes = 0usize;
        for index in 0..OUTPUT_COUNT {
            if payloads[..index]
                .iter()
                .any(|value| value.0 == payloads[index].0)
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            owner.slots[index].copy_data(
                payloads[index].0,
                payloads[index].1,
                media[index],
                row.bound_data(index)?,
            )?;
            owner.retained_storage_data(maximum)?;
            total_bytes = total_bytes
                .checked_add(payloads[index].1.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            if payloads[index].1.len() > limits.maximum_record_bytes
                || total_bytes > limits.maximum_total_record_bytes
            {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        source.storage_origin_with_error::<RuntimeError>()?;
        claim.authenticate_current_data(source, self.row.controller)?;
        self.row.authenticate_capture_output_limits_data(limits)?;
        owner.retained_storage_data(maximum)?;
        owner.move_into_data(claim.ticket_data().cut(), completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_hash_retains_the_copied_reference_bytes_and_spent_slot() {
        let reference = canonical::content_ref(b"retained original", "application/json").unwrap();
        let mut copy = PayloadCopy::empty();
        let changed = b"changed original!";
        assert!(
            copy.copy_data(&reference, changed, "application/json", 64)
                .is_err()
        );
        assert!(copy.started);
        assert!(!copy.completed);
        assert_eq!(copy.reference.as_ref(), Some(&reference));
        assert_eq!(copy.bytes, changed);
        assert!(
            copy.copy_data(&reference, b"retained original", "application/json", 64)
                .is_err()
        );
    }

    #[test]
    fn exact_copy_preserves_full_reference_and_cannot_recycle_its_slot() {
        let original = b"actual full bytes";
        let reference = canonical::content_ref(original, "application/json").unwrap();
        let mut copy = PayloadCopy::empty();
        copy.copy_data(&reference, original, "application/json", original.len())
            .unwrap();
        let payload = copy.take_data().unwrap();
        assert_eq!(payload.reference, reference);
        assert_eq!(payload.bytes, original);
        assert!(
            copy.copy_data(&reference, original, "application/json", original.len())
                .is_err()
        );
    }
}

#[path = "materialization/born.rs"]
mod born;
use born::CaptureBornOwner;
pub(in super::super) use born::CaptureBornStorage;
