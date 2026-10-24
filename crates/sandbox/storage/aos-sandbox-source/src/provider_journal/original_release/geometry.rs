//! Preserves Source Release's complete same-owner logical copy allowance.
//!
//! Native wire arithmetic is shared with the other real reread owners. Source
//! retains its actual cache/challenge resident terms and historical descriptor
//! bound. These are the existing ordinary logical-copy limits, not a new
//! Provider receiving bank or a claim about allocator/native profile fit.

use super::super::original::{SourceOriginalAdmissionDataV5, SourceOriginalPhysicalCutV5};
use super::super::{Journal, JournalError, RecordNamespace};
use super::OriginalReleaseSourceCutCaptureV1;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;

impl Journal {
    pub(in crate::provider_journal) fn original_release_source_replay_copy_bytes_v1(
        &self,
        physical_end: u64,
        challenges: &super::super::original::SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<usize, JournalError> {
        let limit = || JournalError::LimitExceeded("Source original Release replay copy");
        let physical = usize::try_from(physical_end).map_err(|_| limit())?;
        let native = self.native_view();
        let limits = native.limits();
        let transactions = native.committed_transactions();
        if transactions == 0 || transactions > limits.maximum_transactions {
            return Err(JournalError::ProtectedBoundary);
        }
        let pairs = transactions.checked_mul(transactions).ok_or_else(limit)?;
        let historical_descriptor = historical_descriptor_bytes()?;
        let source_payload = transactions
            .checked_mul(9)
            .and_then(|linear| {
                pairs
                    .checked_mul(3)
                    .and_then(|square| linear.checked_add(square))
            })
            .and_then(|factor| physical.checked_mul(factor))
            .and_then(|bytes| {
                bytes.checked_add(
                    transactions.checked_mul(
                        std::mem::size_of::<SourceOriginalAdmissionDataV5>()
                            .checked_add(std::mem::size_of::<SourceOriginalPhysicalCutV5>())?,
                    )?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(pairs.checked_mul(2)?.checked_mul(historical_descriptor)?)
            })
            .ok_or_else(limit)?
            .min(limits.maximum_materialized_bytes);
        let resident = self
            .source_original_replay
            .original_release_resident_copy_bytes_v1()?;
        let challenge_resident = challenges.checkpoints()?.try_fold(0_usize, |bytes, row| {
            bytes
                .checked_add(std::mem::size_of::<
                    super::super::SourceOriginalChallengeCheckpointV5,
                >())
                .and_then(|bytes| bytes.checked_add(row.key().len()))
                .and_then(|bytes| bytes.checked_add(row.value().len()))
                .ok_or_else(limit)
        })?;

        let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();
        let index_entry = std::mem::size_of::<(Vec<u8>, IdempotencyDecisionV1)>();
        let original = native
            .state()
            .len()
            .checked_mul(map_entry)
            .and_then(|bytes| bytes.checked_add(native.materialized_bytes()))
            .and_then(|bytes| bytes.checked_add(native.transaction_ids().len().checked_mul(16)?))
            .and_then(|bytes| {
                bytes.checked_add(
                    native
                        .committed_namespaces()
                        .len()
                        .checked_mul(std::mem::size_of::<RecordNamespace>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(native.idempotency_index().len().checked_mul(index_entry)?)
            })
            .ok_or_else(limit)?;
        let original = native
            .idempotency_index()
            .keys()
            .try_fold(original, |bytes, key| {
                bytes.checked_add(key.len()).ok_or_else(limit)
            })?;
        let wire = aos_sandbox_broker::canonical_journal::ordinary_reread_wire_work_data_v1(
            physical, limits,
        )
        .ok_or_else(limit)?;
        // The old native/returned control headers are replaced by the actual
        // common and Source constructor carriers, without copying wire payload
        // allowances or calling the full dynamic reread supplier twice.
        let controls = super::super::reread::receiving_control_bytes_data_v1()
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<OriginalReleaseSourceCutCaptureV1>())
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::cell::Cell<bool>>()))
            .ok_or_else(limit)?;
        original
            .checked_add(wire.replay_indexes)
            .and_then(|bytes| bytes.checked_add(wire.pending_records))
            .and_then(|bytes| bytes.checked_add(wire.frame_payload))
            .and_then(|bytes| bytes.checked_add(controls))
            .and_then(|bytes| bytes.checked_add(resident))
            .and_then(|bytes| bytes.checked_add(challenge_resident))
            .and_then(|bytes| bytes.checked_add(source_payload.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(physical.checked_mul(6)?))
            .ok_or_else(limit)
    }
}

// Same four private descriptor fields and four original padding allowances.
fn historical_descriptor_bytes() -> Result<usize, JournalError> {
    use aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceRetirementComparisonV5;

    std::mem::size_of::<[u8; 16]>()
        .checked_add(std::mem::size_of::<bool>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_model::ObjectDigest>()))
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                std::sync::Arc<OriginalSourceRetirementComparisonV5>,
            >())
        })
        .and_then(|bytes| {
            bytes.checked_add(4 * std::mem::align_of::<SourceOriginalAdmissionDataV5>())
        })
        .ok_or(JournalError::LimitExceeded(
            "Source original Release replay copy",
        ))
}
