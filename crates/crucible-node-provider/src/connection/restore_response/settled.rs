//! Borrows complete native Connection child history without reviving rights.
//!
//! Actual shared payloads are encoded once by the enclosing native17 graph.
//! This view preserves all raw/typed/partial fields and records their real alias
//! edges. Deadline labels are historical roles; host clock coordinates are
//! deliberately unencoded and no fresh deadline or issuer is reconstructed.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct ChildHistory<'a>(&'a AssignedNativeRestoreResponse);

impl AssignedNativeRestoreResponse {
    /// Borrows every actual field under its original native owner relation.
    ///
    /// # Errors
    /// Refuses foreign originating roots, borrowed token relations or a changed
    /// installed mapping. This grants no Capture, continuation or installation.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        Ok(ChildHistory(self))
    }

    /// Appends complete actual child capacities and shared edges without reset.
    ///
    /// # Errors
    /// Refuses foreign/borrowed roots, exhausted admitted banks or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            original,
            canonical,
            literal_slot,
            request_sequence,
            completed_proof,
            deadline,
            cut,
            phase,
        } = self;
        observer.observe(original)?;
        observer.observe(canonical)?;
        observer.observe(literal_slot)?;
        observer.observe(request_sequence)?;
        if let Some(proof) = completed_proof {
            proof.observe_settled_history_metadata_data(observer)?;
        }
        deadline.observe_owned11_metadata(observer)?;
        observer.observe(&(self.deadline.original_cut() == *cut))?;
        let phase = match phase {
            Phase::Unsigned => 0usize,
            Phase::Sealing => 1,
            Phase::Sealed => 2,
            Phase::Publishing => 3,
            Phase::Complete => 4,
        };
        observer.observe(&phase)?;
        Ok(())
    }

    /// Names the defining borrowed field, serializer, option and error headers.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<ChildHistory<'static>>()
            + size_of::<Result<ChildHistory<'static>, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes()
            + super::super::restore_held_proof::CompletedHeldProof::settled_history_counter_scratch_data()
            + size_of::<Option<&super::super::restore_held_proof::CompletedHeldProof>>()
            + size_of::<Option<usize>>()
            + size_of::<bool>()
            + size_of::<&str>()
            + field_view_bytes(|value: &'static AssignedNativeRestoreResponse| {
                let AssignedNativeRestoreResponse { original, canonical, literal_slot, request_sequence, completed_proof, deadline, cut, phase } = value;
                (original, canonical, literal_slot, request_sequence, completed_proof, deadline, cut, phase,)
            })
    }
}

impl Serialize for ChildHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let AssignedNativeRestoreResponse {
            original,
            canonical,
            literal_slot,
            request_sequence,
            completed_proof,
            deadline,
            cut,
            phase,
        } = self.0;
        let mut state = serializer.serialize_struct("NativeConnectionChildHistory17", 9)?;
        state.serialize_field("schema", "source-private.restore-response-history/17")?;
        state.serialize_field("original", original)?;
        state.serialize_field(
            "canonical",
            &crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(canonical),
        )?;
        state.serialize_field("literal_slot", literal_slot)?;
        state.serialize_field("request_sequence", request_sequence)?;
        let proof = completed_proof
            .as_ref()
            .map(|proof| proof.borrowed_settled_history_data())
            .transpose()
            .map_err(serde::ser::Error::custom)?;
        state.serialize_field("completed_proof", &proof)?;
        let _ = deadline;
        state.serialize_field(
            "deadline_role",
            "native-shared-operational-deadline-history-only",
        )?;
        state.serialize_field(
            "original_cut_matches_deadline",
            &(self.0.deadline.original_cut() == *cut),
        )?;
        state.serialize_field(
            "phase",
            match phase {
                Phase::Unsigned => "unsigned",
                Phase::Sealing => "sealing",
                Phase::Sealed => "sealed",
                Phase::Publishing => "publishing",
                Phase::Complete => "complete",
            },
        )?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}
