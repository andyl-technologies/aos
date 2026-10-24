//! Measures the complete reached lifecycle replay before any typed map grows.
//!
//! Every cardinality comes from actual reached row lengths and the existing wire
//! widths. These bounds include invalid input: the sole parser either refuses
//! before allocation or passes its exact count/length preflight. This module
//! creates no account, verifier, namespace, currentness proof or IO permission.

use std::mem::size_of;

use super::*;
use crate::lifecycle::{
    LifecycleAssignmentCommitFactV1, LifecycleCommittedResourceV1, LifecycleEffectAttemptV1,
    LifecycleMethodSemanticCommitV1, LifecycleReadCommitFactV1,
    LifecycleReservationCommitFactV1, LifecycleRetentionAcknowledgementV1,
    LifecycleRetentionLedgerEntryV1, LifecycleStepV1, ResourceExpectationV1,
    MAXIMUM_LIFECYCLE_EXPECTATIONS, MAXIMUM_LIFECYCLE_STEPS,
};
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::{LifecycleDependencyEdgeV1, LifecycleResourceV1};
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedCurrentRecordCandidateV1, ReplayProjectionRecordsCaptureV1,
    CurrentRecordCandidatesCaptureV1,
};

/// Describes inert receiving DATA for the actual reached lifecycle prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleReplayReceivingV1 {
    memory_bytes: usize,
    metadata_entries: usize,
}

impl LifecycleReplayReceivingV1 {
    /// Measures complete candidate recovery, replay and latest-operation selection.
    ///
    /// The original raw Source reader is separate. This prices every additional
    /// candidate/key copy, concrete generic replay carrier, B-tree backing,
    /// verifier digest array and simultaneous schema/selection graph plane.
    /// Non-lifecycle rows are skipped exactly as the canonical candidate/replay
    /// engines skip them. It does not parse, allocate, validate or admit input.
    /// Arithmetic overflow returns `None` before receiving growth.
    #[must_use]
    pub fn from_records_v1<'row>(
        records: impl Iterator<Item = (RecordNamespace, &'row [u8], &'row [u8])>,
    ) -> Option<Self> {
        type Schema = LifecycleProtectedJournalSchemaV1;
        Self::from_lifecycle_record_lengths_v1(records.filter_map(|(_, key, value)|
            key.starts_with(Schema::KEY_PREFIX).then_some((key.len(), value.len()))))
    }

    /// Measures already classified Lifecycle key/value widths without allocation.
    ///
    /// This permits the same canonical recipe to include a closed producer's
    /// future member before its encoder or model allocates. Widths validate no
    /// record, schema or write authority; native limits remain independently gated.
    #[must_use]
    pub fn from_lifecycle_record_lengths_v1(
        records: impl Iterator<Item = (usize, usize)>,
    ) -> Option<Self> {
        type Schema = LifecycleProtectedJournalSchemaV1;
        let mut rows = 0_usize;
        let mut encoded = 0_usize;
        let mut model_peak = 0_usize;
        let mut model_names_peak = 0_usize;
        for (key_bytes, value_bytes) in records {
            rows = rows.checked_add(1)?;
            encoded = encoded.checked_add(key_bytes)?.checked_add(value_bytes)?;
            // A complete reducer body and every nested operation/auxiliary
            // payload are disjoint slices within this actual native value.
            model_peak = model_peak.max(auxiliary_model_bytes(value_bytes)?);
            model_names_peak = model_names_peak.max(DeleteBatchViewV1::nested_decode_metadata_entries_v1(value_bytes)?);
        }

        let generic = ReplayProjectionRecordsCaptureV1::<Schema>::receiving_construction_bytes_v1()?
            .checked_add(ReplayProjectionRecordsCaptureV1::<Schema>::receiving_carrier_bytes_v1(rows)?)?
            .checked_add(ReplayProjectionRecordsCaptureV1::<Schema>::receiving_encoded_backing_bytes_v1(encoded)?)?;
        // Body/key copies plus the current decoder's identity/roundtrip bytes.
        let candidate_rows = rows.max(4).checked_mul(2)?
            .checked_mul(size_of::<ProtectedCurrentRecordCandidateV1<Schema>>())?
            .checked_add(encoded.checked_mul(4)?)?;
        let candidates = CurrentRecordCandidatesCaptureV1::<Schema>::receiving_construction_bytes_v1()?
            .checked_add(candidate_rows)?;
        // Candidate and replay seen-key indices and the replay transaction
        // grouping map use the pinned actual Rust B-tree node geometry.
        let indices = nodes::<Vec<u8>, ()>(rows)?.checked_mul(2)?
            .checked_add(nodes::<[u8; 16], Vec<usize>>(rows)?)?;
        let verifier = rows.max(4).checked_mul(size_of::<ObjectDigest>())?
            .checked_mul(4)?
            .checked_add(size_of::<LifecycleJournalVerifierV1>().checked_mul(2)?)?;
        // Recovery's current auxiliary, the schema's current model, and latest
        // selection's retained/incoming models may all remain on the caller.
        // Each plane uses the complete auxiliary bound, including its nested
        // operation, cancellation copy and pure constructor validation scratch.
        let models = model_peak.checked_mul(4)?
            .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::
                LifecycleAuxiliaryFrameDataV1<'_>>().checked_mul(2)?)?;
        let memory_bytes = generic.checked_add(candidates)?.checked_add(indices)?
            .checked_add(verifier)?.checked_add(models)?
            .checked_add(size_of::<LifecycleSchemaReplayCaptureV1>().checked_mul(2)?)?
            .checked_add(size_of::<crate::lifecycle::LifecycleAuxiliaryDecodeOriginalV1>().checked_mul(2)?)?;
        // Real names only: two seen-key indices, candidates, replay members,
        // grouped transaction keys, reconstructed transaction record names,
        // final projection names and two verifier accepted-digest catalogs.
        // Scalar/Option/result/control fields receive no MetadataEntries fee.
        let metadata_entries = rows.checked_mul(9)?
            .checked_add(model_names_peak.checked_mul(4)?)?;
        Some(Self { memory_bytes, metadata_entries })
    }

    // A caller that holds latest selection while decoding a separate
    // historical row needs its own retained+incoming selection planes. This
    // delegates to the same auxiliary/count preflight used above; it does not
    // duplicate a decoder or invent field namespace fees.
    pub(crate) fn additional_selection_receiving_v1<'row>(
        records: impl Iterator<Item = (RecordNamespace, &'row [u8], &'row [u8])>,
    ) -> Option<aos_sandbox_model::ResourceVector> {
        let mut memory = 0_usize;
        let mut names = 0_usize;
        for (_, key, value) in records.filter(|(_,key,_)|
            key.starts_with(LifecycleProtectedJournalSchemaV1::KEY_PREFIX)) {
            let _ = key;
            memory = memory.max(auxiliary_model_bytes(value.len())?);
            names = names.max(DeleteBatchViewV1::nested_decode_metadata_entries_v1(value.len())?);
        }
        Some(aos_sandbox_model::ResourceVector::ZERO
            .with(aos_sandbox_model::ResourceDimension::MemoryBytes,
                u64::try_from(memory.checked_mul(2)?).ok()?)
            .with(aos_sandbox_model::ResourceDimension::MetadataEntries,
                u64::try_from(names.checked_mul(2)?).ok()?))
    }

    /// Returns the conservative actual typed/copy/backing memory peak in bytes.
    #[must_use]
    pub const fn memory_bytes_v1(self) -> usize {
        self.memory_bytes
    }

    /// Returns real resident namespace/index/catalog row entries, without fields.
    #[must_use]
    pub const fn metadata_entries_v1(self) -> usize {
        self.metadata_entries
    }
}

fn vector_bytes<T>(encoded: usize, wire_width: usize, maximum: usize) -> Option<usize> {
    (encoded / wire_width).min(maximum).checked_mul(size_of::<T>())
}

fn operation_model_bytes(encoded: usize) -> Option<usize> {
    let expectations = vector_bytes::<ResourceExpectationV1>(encoded, 60, MAXIMUM_LIFECYCLE_EXPECTATIONS)?;
    let attempts_per_step = crate::lifecycle::MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP.checked_mul(2)?;
    let step_wire = 364_usize.checked_add(276_usize.checked_mul(attempts_per_step)?)?;
    let steps = vector_bytes::<LifecycleStepV1>(encoded, step_wire, MAXIMUM_LIFECYCLE_STEPS)?;
    let attempts = vector_bytes::<LifecycleEffectAttemptV1>(encoded, 276,
        MAXIMUM_LIFECYCLE_STEPS.checked_mul(attempts_per_step)?)?;
    let facts = vector_bytes::<LifecycleReadCommitFactV1>(encoded, 68, MAXIMUM_LIFECYCLE_EXPECTATIONS)?
        .checked_add(vector_bytes::<LifecycleCommittedResourceV1>(encoded, 148, MAXIMUM_LIFECYCLE_EXPECTATIONS)?)?
        .checked_add(vector_bytes::<LifecycleAssignmentCommitFactV1>(encoded, 40, MAXIMUM_LIFECYCLE_EXPECTATIONS)?)?
        .checked_add(vector_bytes::<LifecycleReservationCommitFactV1>(encoded, 56, MAXIMUM_LIFECYCLE_EXPECTATIONS)?)?
        .checked_add(vector_bytes::<LifecycleRetentionAcknowledgementV1>(encoded, 193, MAXIMUM_LIFECYCLE_EXPECTATIONS)?)?
        .checked_add(vector_bytes::<LifecycleDependencyEdgeV1>(encoded, 34, MAXIMUM_LIFECYCLE_EXPECTATIONS)?)?
        .checked_add(vector_bytes::<LifecycleResourceV1>(encoded, 17, MAXIMUM_LIFECYCLE_EXPECTATIONS)?)?;
    // The original operation keeps its fact graph while its constructor checks
    // one existing cloned semantic commit. A step similarly checks cloned
    // forward/compensation histories; those allocations are explicitly priced.
    expectations.checked_add(steps)?.checked_add(attempts.checked_mul(2)?)?
        .checked_add(facts.checked_mul(2)?)?
        .checked_add(encoded.checked_mul(4)?)? // fact/batch/encoder byte backing
        .checked_add(delete_graph_bytes(encoded)?)?
        .checked_add(size_of::<LifecycleMethodSemanticCommitV1>().checked_mul(2)?)?
        .checked_add(size_of::<crate::lifecycle::LifecycleOperationDecodeOriginalV1>().checked_mul(2)?)
}

fn auxiliary_model_bytes(encoded: usize) -> Option<usize> {
    // A7 retains a literal SDK request and invokes that canonical protobuf
    // engine during replay, even before an upper Stop consumer is selected.
    // Use its shared reached schema bound at the actual enclosing row width.
    // Other format forecasts supply only lengths, so this remains dominant
    // for every candidate, including a malformed A7 prefix before rejection.
    let request_bytes = encoded.min(
        aos_sandbox_broker_session_protocol::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES);
    let request_models = aos_sandbox_broker_session_protocol::receiving_geometry::
        schema_protobuf_carriers_v1(u64::try_from(request_bytes).ok()?, 2).ok()?;
    let request_models = usize::try_from(request_models).ok()?;
    let coordination = vector_bytes::<LifecycleResourceV1>(encoded, 17, MAXIMUM_LIFECYCLE_EXPECTATIONS)?
        .checked_mul(3)? // dependencies, postorder and boot-inventory resources
        .checked_add(vector_bytes::<LifecycleDependencyEdgeV1>(encoded, 34, MAXIMUM_LIFECYCLE_EXPECTATIONS)?)?;
    let retention = vector_bytes::<LifecycleRetentionLedgerEntryV1>(encoded, 66, MAXIMUM_LIFECYCLE_EXPECTATIONS)?;
    // Cancellation really clones its decoded operation into its stored outcome;
    // Snapshot coordination stores one original. Both are covered before entry.
    operation_model_bytes(encoded)?.checked_mul(2)?
        .checked_add(request_models.checked_mul(2)?)?
        .checked_add(coordination)?.checked_add(retention)?
        .checked_add(encoded.checked_mul(8)?)? // payload/envelope/roundtrip encoders
        .checked_add(size_of::<LifecycleAuxiliaryRecordV1>().checked_mul(2)?)?
        .checked_add(size_of::<crate::lifecycle::LifecycleAuxiliaryDecodeOriginalV1>().checked_mul(2)?)
}

fn delete_graph_bytes(encoded: usize) -> Option<usize> {
    DeleteBatchViewV1::nested_decode_receiving_bytes_v1(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_rows_add_backing_names_and_graph_receiving() {
        let key = LifecycleProtectedJournalSchemaV1::KEY_PREFIX;
        let small = [0_u8; 1024];
        let large = [0_u8; 4096];
        let first = LifecycleReplayReceivingV1::from_records_v1(
            std::iter::once((RecordNamespace::DesiredState, key, small.as_slice())),
        ).unwrap();
        let second = LifecycleReplayReceivingV1::from_records_v1(
            std::iter::once((RecordNamespace::DesiredState, key, large.as_slice())),
        ).unwrap();
        assert!(second.memory_bytes_v1() > first.memory_bytes_v1());
        assert!(second.metadata_entries_v1() >= first.metadata_entries_v1());
        assert!(operation_model_bytes(usize::MAX).is_none());
    }
}
