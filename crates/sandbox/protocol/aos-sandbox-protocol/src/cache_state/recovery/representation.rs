//! Conservative general semantic bounds from actually held encoded extents.
//!
//! Closed Genesis has its narrower actual-count supplier. This fallback keeps
//! arbitrary supported histories; it uses each disjoint wire family's carrier
//! expansion, not an Atomic model per input byte or products of nested maxima.
//! These are complete semantic representation bounds for one original owner.
//! Native maps/replay, other Source owners and physical/input/IO costs remain
//! separate. The actual role consumer admits the chosen bound before growth. This DATA supplier owns no payer, native opener or authority.

use std::mem::size_of;

use super::CacheRecoveryInventoryDataV1 as CacheRecoveryInventoryV1;
use super::*;
use crate::cache_state::{
    protected_replay::CacheResidencyHistoricalSchemaDataV1 as CacheResidencyProtectedJournalSchemaV1,
    replay_envelope::CacheReplayPartitionEvidenceDataV1 as CacheResidencyReplayPartitionEvidenceV1,
};
use crate::domain_ledger::{
    records::{
        DurableDomainMemberV1, ProtectedDomainEnvelopeV1, ProtectedDomainReplayTransactionV1,
    },
    transaction::JournalRecord,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

/// Identifies the actual semantic phase whose complete requirement is priced.
#[derive(Clone, Copy)]
pub enum CacheReplayRepresentationPhaseV1 {
    /// Includes evidence and complete temporary checkpoint-only inventories.
    ManifestValidation,
    /// Includes evidence, complete inventories and the current reconstruction.
    InitialInventory,
}

/// Bounds one owner's general semantic representations from reached raw DATA.
///
/// `encoded_bytes` and `partitions` must come from the same held original rows
/// which the decoder will consume. At InitialInventory, `partitions` bounds
/// manifest count PLUS every actual State row, including malformed/foreign rows;
/// it is not merely the number of unique physical partitions. They do not
/// establish Native currentness or authority. Existing strict format/count limits still apply. Complete bounds
/// for the same owner require a monotonic high-water update, not additive
/// charging of evidence a second time when inventory construction follows.
///
/// # Errors
///
/// Refuses any unrepresentable byte/count/rate arithmetic.
pub fn general_replay_representation_bound_v1(
    encoded_bytes: usize,
    partitions: usize,
    phase: CacheReplayRepresentationPhaseV1,
) -> Result<ResourceVector, RecoveryError> {
    let rates = CarrierRates::new()?;
    // The current typed checkpoint and its validator's baseline clone coexist.
    let validation_models = product(encoded_bytes, rates.models, 2)?;
    // Evidence validation invokes the same complete from_verified constructor
    // before State opens. Its checkpoint-only temporary inventory still clones
    // globals and classifies work; this frontier belongs to BOTH phases.
    let current_models = product(encoded_bytes, rates.models, 1)?
        .checked_add(product(encoded_bytes, rates.globals, 2)?)
        .ok_or(RecoveryError::Capacity)?;
    let mut memory = validation_models
        .max(current_models)
        .checked_add(product(encoded_bytes, rates.work, 1)?)
        .ok_or(RecoveryError::Capacity)?;
    // Main recovery's identity/tombstone indices and accounting projection
    // coexist. The validator's corresponding temporary indices are sequential;
    // this shared conservative allowance covers either reached phase.
    memory = memory
        .checked_add(product(encoded_bytes, rates.indices, 1)?)
        .ok_or(RecoveryError::Capacity)?;
    memory = memory
        .checked_add(raw_byte_lanes(encoded_bytes, phase)?)
        .and_then(|bytes| bytes.checked_add(partitions.checked_mul(rates.partition)?))
        .and_then(|bytes| bytes.checked_add(rates.in_flight))
        .ok_or(RecoveryError::Capacity)?;
    if matches!(phase, CacheReplayRepresentationPhaseV1::InitialInventory) {
        // The supplied partition bound includes EVERY actual State row, even
        // a malformed row whose key enters `seen` before its value decodes.
        // Fixed replay carriers therefore use actual row counts, not the
        // minimum width of a successfully decoded member.
        memory = memory
            .checked_add(product(partitions, projection_row_carriers()?, 1)?)
            .ok_or(RecoveryError::Capacity)?;
    }
    // These are transient parser, model and index representations. They do
    // not add resident namespace entries; the genuine surrounding Native
    // owner separately prices its actual journal state and named originals.
    Ok(ResourceVector::ZERO.with(
        D::MemoryBytes,
        u64::try_from(memory).map_err(|_| RecoveryError::Capacity)?,
    ))
}

struct CarrierRates {
    models: usize,
    globals: usize,
    indices: usize,
    work: usize,
    partition: usize,
    in_flight: usize,
}

impl CarrierRates {
    fn new() -> Result<Self, RecoveryError> {
        // Minima exclude optional/nested children; those children have their
        // own disjoint wire extents. String bytes use the separate byte copies.
        // The maximum ratio bounds any mixture, without summing every family's
        // hypothetical maximum against the same input byte.
        let global_cells = [
            (size_of::<ProjectCacheQuotaV1>(), 88),
            (size_of::<WatermarkRequirementV1>(), 64),
            (size_of::<CacheIdempotencyBindingV1>(), 200),
            (size_of::<CacheReadHandoffStateV1>(), 276),
            (size_of::<CacheLookupStateV1>(), 46),
        ];
        let model_cells = [
            (
                size_of::<(ObjectDigest, CacheAtomicObjectPayloadV1, [usize; 4])>(),
                1520,
            ),
            (size_of::<CacheTypedCheckpointV1>(), 567),
            (size_of::<CacheSubjectFamilyHeadV1>(), 73),
            (size_of::<CachePinV1>(), 238),
            (size_of::<ReleasedCachePinV1>(), 299),
            (size_of::<EvictionCandidateV1>(), 191),
            (size_of::<EvictionProgressV1>(), 333),
        ];
        // For the selected standard Vec implementation, four reached typed
        // carriers cover initial capacity and old/new reallocation overlap;
        // unread advertised counts allocate none after the reached-carrier cut.
        let globals = ratio_max(global_cells)?
            .checked_mul(4)
            .ok_or(RecoveryError::Capacity)?;
        let models = ratio_max(model_cells)?
            .max(ratio_max(global_cells)?)
            .checked_mul(4)
            .ok_or(RecoveryError::Capacity)?;

        let quota_indices = size_of::<([u8; 16], ProjectCacheQuotaV1, [usize; 4])>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(size_of::<([u8; 16], CacheUsageV1, [usize; 4])>() * 2)
            })
            .ok_or(RecoveryError::Capacity)?;
        let subject_indices = size_of::<CacheReservationV1>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(size_of::<([u8; 32], ObjectDigest, [usize; 4])>() * 3)
            })
            .and_then(|bytes| {
                bytes.checked_add(size_of::<([u8; 16], CacheUsageV1, u64, [usize; 4])>())
            })
            .ok_or(RecoveryError::Capacity)?;
        let pin_indices = size_of::<CachePinV1>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(size_of::<(CachePinId, ObjectDigest, [usize; 4])>() * 2)
            })
            .and_then(|bytes| {
                bytes.checked_add(size_of::<(
                    ObjectDigest,
                    ObjectDigest,
                    ProjectId,
                    ViewId,
                    Option<AttachmentId>,
                    CachePinId,
                    [usize; 4],
                )>())
            })
            .and_then(|bytes| {
                bytes.checked_add(size_of::<([u8; 16], CacheUsageV1, [usize; 4])>() * 2)
            })
            .ok_or(RecoveryError::Capacity)?;
        let released_indices = size_of::<ReleasedCachePinV1>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(size_of::<(CachePinId, ObjectDigest, [usize; 4])>() * 2)
            })
            .ok_or(RecoveryError::Capacity)?;
        let indices = ratio_max([
            (quota_indices, 88),
            (subject_indices, 1520),
            (pin_indices, 238),
            (released_indices, 299),
        ])?
        .checked_mul(4)
        .ok_or(RecoveryError::Capacity)?;
        // Local classify_work and the outer queue may coexist; lookup/handoff
        // additions go directly into the outer queue. Four fixed subject work
        // variants plus physical pins conservatively bound local classification.
        let work = ratio_max([
            (size_of::<CacheRecoveryWorkV1>() * 8 * 4, 1520),
            (size_of::<CacheRecoveryWorkV1>() * 8, 238),
            (size_of::<CacheRecoveryWorkV1>() * 4, 46),
            (size_of::<CacheRecoveryWorkV1>() * 4, 276),
        ])?;
        let partition = size_of::<(
            CacheRecoveryInventoryV1,
            CacheTypedCheckpointV1,
            ObjectDigest,
            PhysicalPartitionId,
            CacheAuthorityScopeV1,
            [usize; 8],
        )>()
        .checked_mul(8)
        .and_then(|bytes| {
            bytes.checked_add(
                size_of::<(
                    CacheResidencyReplayPartitionEvidenceV1,
                    ObjectDigest,
                    std::sync::Arc<CacheResidencyReplayPartitionEvidenceV1>,
                    [usize; 4],
                )>()
                .checked_mul(4)?,
            )
        })
        .ok_or(RecoveryError::Capacity)?;
        // One partially decoded child and fixed canonical writer floors can
        // exist even when no complete variable item has been pushed.
        let assembly_carriers = super::recovery_assembly_inline_bytes_v1()
            .checked_mul(2)
            .ok_or(RecoveryError::Capacity)?;
        let in_flight = size_of::<(
            CacheAtomicObjectPayloadV1,
            CacheTypedCheckpointV1,
            CacheGlobalRecoveryStateV1,
            CachePinV1,
            ReleasedCachePinV1,
            EvictionCandidateV1,
            EvictionProgressV1,
            CacheReadHandoffStateV1,
            CacheLookupStateV1,
            ProjectCacheQuotaV1,
        )>()
        .checked_add(assembly_carriers)
        .and_then(|bytes| {
            bytes.checked_add(
                crate::cache_state::protected_replay::partition_history_inline_bytes_v1()
                    .checked_mul(2)?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(super::canonical_writer_initial_capacity_data_v1().checked_mul(4)?)
        })
        .ok_or(RecoveryError::Capacity)?;
        Ok(Self {
            models,
            globals,
            indices,
            work,
            partition,
            in_flight,
        })
    }
}

/// Covers separately owned raw bytes, including descriptor strings in models.
fn raw_byte_lanes(
    bytes: usize,
    phase: CacheReplayRepresentationPhaseV1,
) -> Result<usize, RecoveryError> {
    // Immutable evidence, its retained initialization copy and one manifest
    // round-trip buffer each fit the complete reached manifest extents.
    let evidence = product(bytes, 3, 1)?;
    // Typed models, the checkpoint validator clone, two mutable-global copies,
    // accounting/PinLedger clones (two disjoint-family copies), and one leaf
    // validator clone. Carrier sizes above cover String headers, not contents.
    let strings = product(bytes, 1 + 1 + 2 + 2 + 1, 1)?;
    // TypedCheckpoint -> AtomicPayload -> Scrub/Eviction -> Catalog/Candidate
    // can retain four writers. Each pays old+new growth up to three reached
    // extents; four initial-capacity floors are included in `in_flight`.
    let canonical = product(bytes, 4, 3)?;
    let mut total = evidence
        .checked_add(strings)
        .and_then(|value| value.checked_add(canonical))
        .ok_or(RecoveryError::Capacity)?;

    if matches!(phase, CacheReplayRepresentationPhaseV1::InitialInventory) {
        // Each envelope owns payload plus identity and encoded-key buffers,
        // bounded by twice the actual key+value extent. The saved projection
        // retains both its record envelopes and transaction envelope clones.
        let saved_projection = product(bytes, 2, 2)?;
        // Fresh replay: member encoded+payload+keys (2), seen keys (1),
        // transaction envelope clones (2), digest transaction keys/values (1),
        // temporary envelope/member encoding (2), and reducer companion
        // digest/reference/derived buffers (3). These allow simultaneous
        // ownership conservatively, including malformed final members.
        let fresh_projection = product(bytes, 2 + 1 + 2 + 1 + 2 + 3, 1)?;
        // Reconstruction copies checkpoint/suffix bytes into grouping maps;
        // the existing owned record entrypoint may copy the current suffix
        // once more. No borrowed-suffix optimization is assumed here.
        let reconstruction = product(bytes, 1 + 1, 1)?;
        total = total
            .checked_add(saved_projection)
            .and_then(|value| value.checked_add(fresh_projection))
            .and_then(|value| value.checked_add(reconstruction))
            .ok_or(RecoveryError::Capacity)?;
    }

    Ok(total)
}

/// Prices fixed cold-replay carriers per actually reached State row.
fn projection_row_carriers() -> Result<usize, RecoveryError> {
    type Schema = CacheResidencyProtectedJournalSchemaV1;
    // Four slots cover Vec's first allocation and old/new growth. Original
    // members can overlap their final moved-envelope output allocation.
    let members = size_of::<DurableDomainMemberV1<Schema>>().checked_mul(4);
    // Saved/fresh record and transaction-envelope collections can all coexist.
    let envelopes = size_of::<ProtectedDomainEnvelopeV1<Schema>>().checked_mul(16);
    let transactions = size_of::<ProtectedDomainReplayTransactionV1<Schema>>().checked_mul(8);
    let digest_records = size_of::<JournalRecord>().checked_mul(4);
    // Grouped member references, seen key headers, suffix/checkpoint Vec
    // headers and their partition/sequence map cells are separate carriers.
    let grouping = size_of::<(
        [usize; 4], // Reached grouped-member reference slots.
        [u8; 16],
        Vec<usize>,
        [usize; 4],
        Vec<u8>,
        [usize; 4],
        ObjectDigest,
        Vec<Vec<u8>>,
        [usize; 4],
        u64,
        Vec<u8>,
        [usize; 4],
    )>()
    .checked_mul(4);

    members
        .and_then(|value| value.checked_add(envelopes?))
        .and_then(|value| value.checked_add(transactions?))
        .and_then(|value| value.checked_add(digest_records?))
        .and_then(|value| value.checked_add(grouping?))
        .ok_or(RecoveryError::Capacity)
}

fn ratio_max<const N: usize>(families: [(usize, usize); N]) -> Result<usize, RecoveryError> {
    let mut maximum = 1;
    for (carrier, wire) in families {
        if wire == 0 {
            return Err(RecoveryError::Capacity);
        }
        let rate = carrier
            .checked_add(wire - 1)
            .ok_or(RecoveryError::Capacity)?
            / wire;
        maximum = maximum.max(rate);
    }
    Ok(maximum)
}

fn product(bytes: usize, rate: usize, copies: usize) -> Result<usize, RecoveryError> {
    bytes
        .checked_mul(rate)
        .and_then(|bytes| bytes.checked_mul(copies))
        .ok_or(RecoveryError::Capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_phase_keeps_earlier_evidence_and_adds_actual_reconstruction_frontier() {
        let evidence = general_replay_representation_bound_v1(
            4096,
            2,
            CacheReplayRepresentationPhaseV1::ManifestValidation,
        )
        .unwrap();
        let inventory = general_replay_representation_bound_v1(
            4096,
            2,
            CacheReplayRepresentationPhaseV1::InitialInventory,
        )
        .unwrap();

        assert!(evidence.is_within(inventory));
        assert_eq!(inventory.get(D::StorageBytes), 0);
        assert_eq!(inventory.get(D::OutputBytes), 0);
    }

    #[test]
    fn general_bound_refuses_unrepresentable_real_extents() {
        assert!(matches!(
            general_replay_representation_bound_v1(
                usize::MAX,
                1,
                CacheReplayRepresentationPhaseV1::InitialInventory
            ),
            Err(RecoveryError::Capacity)
        ));
        assert!(matches!(
            general_replay_representation_bound_v1(
                1,
                usize::MAX,
                CacheReplayRepresentationPhaseV1::ManifestValidation
            ),
            Err(RecoveryError::Capacity)
        ));
    }
}
