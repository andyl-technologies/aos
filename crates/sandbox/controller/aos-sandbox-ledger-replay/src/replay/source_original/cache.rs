//! Owns saved Source original replay state and its sole pure comparisons.
//!
//! Native challenge observations remain with the physical Journal. The fixed
//! Source-domain opener supplies no challenge history and preserves the same
//! irrelevant-or-pending disposition through this DATA engine.

use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily;
use std::collections::BTreeMap;
use std::sync::Arc;
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_source_provider_ledger::ledger::{
    native_held_completion::SourceNativeHeldCompletionRecordV1,
    source_capacity::{OriginalSourceChallengeDataV5, compare_original_source_capacity_owner_edge_v5},
};
use super::{State, SourceOriginalAdmissionDataV5, SourceOriginalAdmissionInputV5,
    SourceCapacityUnionComparisonDataV5, compare_source_original_admission_data_v5, invalid, owner_views,
    union::{SourceHistoricalRetirementReferenceV5, compare_source_capacity_union_at_physical_cuts_v5}};
use crate::replay::{JournalError, JournalLimits, JournalTransaction, RecordNamespace,
    challenge::{SourceChallengeReplayWitnessDataV5, SourceOriginalChallengeCheckpointV5}};

/// Describes a saved original-related physical transaction boundary.
///
/// Supplied identities and maps are DATA; physical membership and currentness
/// remain independently checked by the original native owner.
#[derive(Clone)]
pub struct SourceOriginalPhysicalCutV5 {
    /// Retains the saved file device.
    pub device: u64,
    /// Retains the saved file inode.
    pub inode: u64,
    /// Retains the committed transaction identifier.
    pub transaction: [u8; 16],
    /// Retains the ordered-record digest.
    pub digest: [u8; 32],
    /// Retains the saved BEGIN frame sequence.
    pub begin_sequence: u64,
    /// Retains the saved COMMIT frame sequence.
    pub commit_sequence: u64,
    /// Retains the saved BEGIN frame offset.
    pub begin_offset: u64,
    /// Retains the saved committed-prefix end.
    pub durable_end: u64,
    /// Retains immutable before rows.
    pub before: Arc<State>,
    /// Retains immutable after rows.
    pub after: Arc<State>,
    /// Retains the saved selected challenge checkpoint index.
    pub challenge_checkpoint: Option<usize>,
}

impl SourceOriginalPhysicalCutV5 {
    /// Borrows saved complete before rows.
    pub fn before_rows(&self) -> &State {
        &self.before
    }

    /// Borrows saved complete after rows.
    pub fn after_rows(&self) -> &State {
        &self.after
    }

    /// Returns the saved selected checkpoint index.
    pub const fn challenge_checkpoint(&self) -> Option<usize> {
        self.challenge_checkpoint
    }

    /// Returns the saved device and inode DATA.
    pub const fn file_identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Returns the saved ordered transaction identity.
    pub const fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction
    }

    /// Returns the digest of the exact ordered records, not an admission permit.
    pub const fn transaction_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns saved BEGIN and COMMIT frame sequences.
    pub const fn frame_sequences(&self) -> (u64, u64) {
        (self.begin_sequence, self.commit_sequence)
    }

    /// Returns the saved BEGIN offset and committed-prefix end.
    pub const fn file_offsets(&self) -> (u64, u64) {
        (self.begin_offset, self.durable_end)
    }
}

/// Retains saved original admissions, cuts, and replay comparison state.
///
/// This DATA type performs no native observation and proves no writer custody,
/// membership, nonce authority, or semantic readiness. Its optional witness
/// compares only a caller-held opaque identity; the physical owner checks it.
#[doc(hidden)]
pub struct SourceOriginalReplayDataV5<I> {
    /// Records that a reached dependency still needs physical-history closure.
    pub pending: bool,
    /// Retains the original admission comparisons.
    pub origins: Vec<SourceOriginalAdmissionDataV5>,
    /// Retains historical retirement carrier references.
    pub historical: Vec<SourceHistoricalRetirementReferenceV5>,
    /// Retains saved original-related transaction boundaries.
    pub cuts: Vec<SourceOriginalPhysicalCutV5>,
    /// Tracks the existing logical retained representation bound.
    pub retained_bytes: usize,
    /// Tracks each acquisition's current retained retirement width.
    pub current_retirement_bytes: BTreeMap<ObjectDigest, usize>,
    /// Retains saved challenge rows and an opaque identity for comparison only.
    pub challenges: Option<SourceChallengeReplayWitnessDataV5<I>>,
    /// Retains the checkpoint selected by a prospective comparison.
    pub prospective_challenge_checkpoint: Option<usize>,
}

impl<I> Clone for SourceOriginalReplayDataV5<I> {
    fn clone(&self) -> Self {
        Self {
            pending: self.pending,
            origins: self.origins.clone(),
            historical: self.historical.clone(),
            cuts: self.cuts.clone(),
            retained_bytes: self.retained_bytes,
            current_retirement_bytes: self.current_retirement_bytes.clone(),
            challenges: self.challenges.clone(),
            prospective_challenge_checkpoint: self.prospective_challenge_checkpoint,
        }
    }
}

impl<I> Default for SourceOriginalReplayDataV5<I> {
    fn default() -> Self {
        Self {
            pending: false,
            origins: Vec::new(),
            historical: Vec::new(),
            cuts: Vec::new(),
            retained_bytes: 0,
            current_retirement_bytes: BTreeMap::new(),
            challenges: None,
            prospective_challenge_checkpoint: None,
        }
    }
}

impl<I> SourceOriginalReplayDataV5<I> {
    /// Reports whether the saved rows or transaction require original history.
    pub fn requires_history(&self, state: &State, transaction: &JournalTransaction) -> bool {
        !(!self.has_dependencies()
            && !has_original_rows(state)
            && !transaction.records().iter().any(|record| {
                record.value().is_some_and(|value| {
                    is_original_row(record.namespace(), record.key(), value)
                })
            }))
    }

    /// Preserves the ordinary fixed opener's no-history replay disposition.
    ///
    /// Unrelated transactions stay irrelevant. Reached original dependencies
    /// remain pending until a separate real physical-history owner closes them.
    pub fn replay_without_history(&mut self, state: &State, transaction: &JournalTransaction) -> bool {
        if !self.requires_history(state, transaction) {
            return false;
        }
        self.pending = true;
        true
    }

    // This reuses the unique-map payload accumulator. It is logical resident
    // representation accounting, not measured allocator RAM or a paid loan.
    /// Bounds the same logical retained release-copy representation.
    ///
    /// # Errors
    /// Returns the original arithmetic overflow classification.
    pub fn original_release_resident_copy_bytes_v1(
        &self,
    ) -> Result<usize, JournalError> {
        let limit = || JournalError::LimitExceeded("Source original Release resident copy");
        let vacant_origins = self.origins.capacity().checked_sub(self.origins.len())
            .and_then(|count| count.checked_mul(std::mem::size_of::<SourceOriginalAdmissionDataV5>()))
            .ok_or_else(limit)?;
        let vacant_cuts = self.cuts.capacity().checked_sub(self.cuts.len())
            .and_then(|count| count.checked_mul(std::mem::size_of::<SourceOriginalPhysicalCutV5>()))
            .ok_or_else(limit)?;
        let vacant_history = self.historical.capacity().checked_sub(self.historical.len())
            .and_then(|count| count.checked_mul(std::mem::size_of::<SourceHistoricalRetirementReferenceV5>()))
            .ok_or_else(limit)?;

        let mut bytes = self.retained_bytes.checked_add(vacant_origins)
            .and_then(|bytes| bytes.checked_add(vacant_cuts))
            .and_then(|bytes| bytes.checked_add(vacant_history))
            .and_then(|bytes| bytes.checked_add(self.current_retirement_bytes.len()
                .checked_mul(std::mem::size_of::<(ObjectDigest, usize)>())?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or_else(limit)?;
        if let Some(history) = self.challenges.as_ref() {
            bytes = bytes.checked_add(history.rows().len()
                .checked_mul(std::mem::size_of::<SourceOriginalChallengeCheckpointV5>())
                .ok_or_else(limit)?)
                .ok_or_else(limit)?;
            for row in history.rows() {
                bytes = bytes.checked_add(row.key().len())
                    .and_then(|bytes| bytes.checked_add(row.value().len()))
                    .ok_or_else(limit)?;
            }
        }
        Ok(bytes)
    }

    /// Reports an unresolved original-history dependency.
    pub fn needs_closure(&self) -> bool {
        self.pending
    }

    /// Reports retained admissions or unresolved history dependencies.
    pub fn has_dependencies(&self) -> bool {
        self.pending || !self.origins.is_empty()
    }

    /// Borrows retained original admission DATA.
    pub fn origins(&self) -> &[SourceOriginalAdmissionDataV5] {
        &self.origins
    }

    /// Borrows saved original-related transaction cuts.
    pub fn cuts(&self) -> &[SourceOriginalPhysicalCutV5] {
        &self.cuts
    }

    /// Returns the saved prospective checkpoint selection.
    pub fn prospective_challenge_checkpoint(&self) -> Option<usize> {
        self.prospective_challenge_checkpoint
    }

    /// Compares against the same retained challenge rows.
    ///
    /// # Errors
    /// Returns the original missing-history or canonical comparison error.
    pub fn compare_cached(
        &self,
        state: &State,
        transaction: Option<&JournalTransaction>,
        limits: JournalLimits,
    ) -> Result<SourceCapacityUnionComparisonDataV5, JournalError> {
        let history = self.challenges.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.compare_rows(state, transaction, history.rows(), limits)
            .map(|(comparison, _)| comparison)
    }

    /// Builds the same bounded prospective comparison DATA.
    ///
    /// # Errors
    /// Returns the original pending, payload-limit, admission, or comparison error.
    pub fn preview_transaction(
        &self,
        state: &State,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<(Self, SourceCapacityUnionComparisonDataV5), JournalError> {
        if self.pending || self.retained_bytes > limits.maximum_materialized_bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        let duplicate_payload = self.origins.iter().try_fold(0_usize, |bytes, origin| {
            bytes.checked_add(admission_payload_bound(origin.original_before(), origin.applying_transaction())?)
                .ok_or(JournalError::LimitExceeded("Source candidate custody payload"))
        })?;
        let duplicate_payload = self.current_retirement_bytes.values().try_fold(
            duplicate_payload, |bytes, width| bytes.checked_add(*width)
                .ok_or(JournalError::LimitExceeded("Source candidate custody payload")),
        )?;
        if self.retained_bytes.checked_add(duplicate_payload)
            .is_none_or(|bytes| bytes > limits.maximum_materialized_bytes)
        {
            return Err(JournalError::LimitExceeded("Source candidate custody payload"));
        }
        let mut prospective = self.clone();
        let applying = transaction.records().len() == 5
            && transaction.records().last().is_some_and(|record| {
                record.namespace() == RecordNamespace::GlobalCapacityReservation
                    && record.value().is_some_and(|value| {
                        aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily::decode(
                            record.key(), value,
                        ).map_err(JournalError::from).is_ok_and(|family| matches!(family,
                            aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily::OriginalSource5(
                                floor
                            ) if floor.request().future_transactions == 20))
                    })
            });
        if applying {
            let before_bytes = super::bounded_snapshot_bytes(state, limits)?;
            let admission_payload = admission_payload_bound(state, transaction)?;
            let owner_growth = transaction.records().iter().try_fold(
                0_usize,
                |bytes, record| {
                    bytes.checked_add(record.key().len())
                        .and_then(|bytes| bytes.checked_add(
                            record.value().map_or(0, <[u8]>::len),
                        ))
                        .ok_or(JournalError::LimitExceeded("Source retained original cuts"))
                },
            )?;
            let bound = before_bytes.checked_mul(2)
                .and_then(|bytes| bytes.checked_add(owner_growth))
                .and_then(|bytes| bytes.checked_add(self.retained_bytes))
                .and_then(|bytes| bytes.checked_add(duplicate_payload))
                .and_then(|bytes| bytes.checked_add(admission_payload))
                .ok_or(JournalError::LimitExceeded("Source retained original cuts"))?;
            if bound > limits.maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded("Source retained original cuts"));
            }
            let mut admission = compare_source_original_admission_data_v5(
                SourceOriginalAdmissionInputV5 {
                    original_before: state,
                    original_applying: transaction,
                },
                limits,
            )?;
            if let Some(previous) = self.cuts.last() {
                admission.reuse_retained_before(&previous.after)?;
            }
            prospective.retain_admission(admission, transaction, limits)?;
        }
        let history = prospective.challenges.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let (comparison, selected) = prospective.compare_rows(
            state, Some(transaction), history.rows(), limits,
        )?;
        prospective.prospective_challenge_checkpoint = match selected.as_slice() {
            [] => None,
            [selected] => Some(history.rows().iter().position(|row| {
                row.key() == selected.key && row.value() == selected.value
            }).ok_or(JournalError::ProtectedBoundary)?),
            _ => return Err(JournalError::ProtectedBoundary),
        };
        Ok((prospective, comparison))
    }

    /// Preserves pending closure when compaction retains original rows.
    pub fn observe_compaction(&mut self, state: &State) {
        if has_original_rows(state) {
            self.pending = true;
        }
    }

    /// Retains the same bounded original admission and historical carriers.
    ///
    /// # Errors
    /// Returns the original duplicate, overflow, or retained-payload bound error.
    pub fn retain_admission(
        &mut self,
        admission: SourceOriginalAdmissionDataV5,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let acquisition = admission.admission_comparison().original().acquisition_id;
        if self.origins.iter().any(|origin| {
            origin.admission_comparison().original().acquisition_id == acquisition
        }) {
            return Err(invalid("Source duplicate physical original admission"));
        }
        let before_reused = self.cuts.last().is_some_and(|cut| {
            Arc::ptr_eq(&cut.after, &admission.retained_cut_rows().0)
        });
        let bytes = [(!before_reused).then_some(admission.original_before()), Some(admission.applying_after())]
            .into_iter().flatten()
            .try_fold(0_usize, |total, state| {
                total.checked_add(super::bounded_snapshot_bytes(state, limits)?)
                    .ok_or(JournalError::LimitExceeded("Source retained original cuts"))
            })?;
        let payload = admission_payload_bound(admission.original_before(), transaction)?;
        let mut next = self.retained_bytes.checked_add(bytes)
            .and_then(|bytes| bytes.checked_add(payload))
            .ok_or(JournalError::LimitExceeded("Source retained original cuts"))?;
        for origin in &self.origins {
            if origin.retained_retirement().is_some() {
                next = next.checked_add(retirement_width(origin, admission.original_before())?)
                    .and_then(|bytes| bytes.checked_add(
                        2 * std::mem::size_of::<SourceHistoricalRetirementReferenceV5>(),
                    ))
                    .ok_or(JournalError::LimitExceeded("Source retained historical carriers"))?;
            }
        }
        if next > limits.maximum_materialized_bytes {
            return Err(JournalError::LimitExceeded("Source retained original cuts"));
        }

        // Historical references are captured NOW from the exact current
        // carriers. Later carry-forward never replaces these historical values.
        for origin in &self.origins {
            if let Some(retirement) = origin.retained_retirement() {
                let retained = Arc::new(retirement.clone());
                for applying_after in [false, true] {
                    self.historical.push(SourceHistoricalRetirementReferenceV5 {
                        admission: *transaction.id(),
                        applying_after,
                        acquisition: retirement.acquisition(),
                        retirement: Arc::clone(&retained),
                    });
                }
            }
        }
        self.retained_bytes = next;
        self.origins.push(admission);
        Ok(())
    }

    /// Compares the exact saved cuts against supplied challenge rows.
    ///
    /// # Errors
    /// Returns the original ambiguous, missing, or invalid canonical owner edge.
    pub fn compare_rows<'challenge>(
        &self,
        state: &State,
        transaction: Option<&JournalTransaction>,
        challenges: &'challenge [SourceOriginalChallengeCheckpointV5],
        limits: JournalLimits,
    ) -> Result<(SourceCapacityUnionComparisonDataV5, Vec<OriginalSourceChallengeDataV5<'challenge>>), JournalError> {
        if transaction.is_none() {
            return Ok((compare_source_capacity_union_at_physical_cuts_v5(
                state, None, &self.origins, &[], &self.historical, limits,
            )?, Vec::new()));
        }
        let transaction = transaction.ok_or(JournalError::InvalidTransaction)?;
        let after = crate::replay::root_original_inventory::materialize(state, transaction);
        let origins = self.origins.iter().map(SourceOriginalAdmissionDataV5::origin)
            .collect::<Vec<_>>();
        if compare_original_source_capacity_owner_edge_v5(
            owner_views(state), owner_views(&after), &origins, &[],
        ).is_ok() {
            return Ok((compare_source_capacity_union_at_physical_cuts_v5(
                state, Some(transaction), &self.origins, &[], &self.historical, limits,
            )?, Vec::new()));
        }

        let mut selected = None;
        for (key, value) in owner_views(&after) {
            let Ok(held) = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(key, value) else {
                continue;
            };
            let challenge_key = [b"AOSZHK01".as_slice(), &held.original().challenge].concat();
            for checkpoint in challenges.iter().filter(|checkpoint| {
                checkpoint.key() == challenge_key
            }) {
                let row = OriginalSourceChallengeDataV5 {
                    acquisition: held.original().acquisition_id,
                    key: checkpoint.key(),
                    value: checkpoint.value(),
                };
                if compare_original_source_capacity_owner_edge_v5(
                    owner_views(state), owner_views(&after), &origins, &[row],
                ).is_err() {
                    continue;
                }
                let comparison = compare_source_capacity_union_at_physical_cuts_v5(
                    state, Some(transaction), &self.origins, &[row], &self.historical, limits,
                )?;
                if selected.is_some() {
                    return Err(invalid("Source physical challenge checkpoint ambiguous"));
                }
                selected = Some((comparison, vec![row]));
            }
        }
        selected.ok_or(invalid("Source exact edge lacks actual challenge history"))
    }
}

/// Measures the same prospective logical payload change.
///
/// # Errors
/// Returns the original subtraction or addition overflow classification.
pub fn prospective_payload_bytes(
    before: &State,
    transaction: &JournalTransaction,
    before_bytes: usize,
) -> Result<usize, JournalError> {
    transaction.records().iter().try_fold(before_bytes, |bytes, record| {
        let key = (record.namespace(), record.key().to_vec());
        let old = before.get(&key).map_or(0, |value| key.1.len() + value.len());
        let new = record.value().map_or(0, |value| key.1.len() + value.len());
        bytes.checked_sub(old).and_then(|bytes| bytes.checked_add(new))
            .ok_or(JournalError::LimitExceeded("Source retained physical cuts"))
    })
}

/// Measures the same retained retirement carrier payload.
///
/// # Errors
/// Returns the original missing carrier, floor, or arithmetic error.
pub fn retirement_width(
    origin: &SourceOriginalAdmissionDataV5,
    state: &State,
) -> Result<usize, JournalError> {
    let acquisition = origin.admission_comparison().original().acquisition_id;
    let key = aos_sandbox_source_provider_ledger::ledger::native_completion::native_completion_key_v2(
        acquisition,
    );
    let carrier = state.get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
        .ok_or(invalid("Source retained historical carrier absent"))?;
    let floor = origin.applying_transaction().records().last()
        .and_then(|record| record.value())
        .ok_or(invalid("Source retained original floor absent"))?;
    origin.applying_transaction().records().iter().take(4).try_fold(
        key.len().checked_add(carrier.len())
            .and_then(|bytes| bytes.checked_add(floor.len()))
            .ok_or(JournalError::LimitExceeded("Source retained carrier bytes"))?,
        |total, row| {
            let before = origin.original_before().get(&(row.namespace(), row.key().to_vec()))
                .map_or(0, Vec::len);
            total.checked_add(row.key().len())
                .and_then(|bytes| bytes.checked_add(row.value().map_or(0, <[u8]>::len)))
                .and_then(|bytes| bytes.checked_add(before))
                .ok_or(JournalError::LimitExceeded("Source retained carrier bytes"))
        },
    )
}

/// Bounds retained TX, quartet before/after payload and decoded floor DATA.
///
/// Complete maps have their own shared-Arc payload accounting. This is a
/// conservative encoded-payload/descriptor bound, not an exact allocator-RAM claim.
/// Bounds the retained transaction and original quartet payload.
///
/// # Errors
/// Returns the original missing floor or arithmetic bound error.
pub fn admission_payload_bound(before: &State, transaction: &JournalTransaction)
    -> Result<usize, JournalError>
{
    let floor = transaction.records().last().and_then(|record| record.value())
        .ok_or(invalid("Source original floor payload absent"))?;
    let mut bytes = std::mem::size_of::<SourceOriginalAdmissionDataV5>()
        .checked_add(floor.len()).ok_or(JournalError::LimitExceeded("Source origin payload"))?;
    for (index, record) in transaction.records().iter().enumerate() {
        let value = record.value().map_or(0, <[u8]>::len);
        bytes = bytes.checked_add(record.key().len()).and_then(|bytes| bytes.checked_add(value))
            .ok_or(JournalError::LimitExceeded("Source origin payload"))?;
        if index < 4 {
            let old = before.get(&(record.namespace(), record.key().to_vec())).map_or(0, Vec::len);
            bytes = bytes.checked_add(record.key().len())
                .and_then(|bytes| bytes.checked_add(value))
                .and_then(|bytes| bytes.checked_add(old))
                .ok_or(JournalError::LimitExceeded("Source origin payload"))?;
        }
    }
    Ok(bytes)
}

/// Checks the same capacity, sequence, and geometry headroom DATA.
///
/// # Errors
/// Returns the original capacity, sequence, or geometry bound error.
pub fn require_advisory_bounds(
    comparison: &SourceCapacityUnionComparisonDataV5,
    limits: JournalLimits,
    journal_bytes: u64,
    transactions: usize,
    next_sequence: u64,
) -> Result<(), JournalError> {
    let state = comparison.after();
    let materialized_bytes = super::bounded_snapshot_bytes(state, limits)?;
    aos_sandbox_broker::domain_transaction_custody::pressure::validate_reserved_capacity_data_v1(
        state, materialized_bytes, &[],
        aos_sandbox_broker::domain_transaction_custody::pressure::CapacityDeletionSelectorDataV1::Reservation(None),
        journal_bytes, transactions, limits,
    )?;
    crate::replay::root_original_inventory::require_sequence_headroom(state, next_sequence)?;
    comparison.require_geometry_headroom(
        limits,
        crate::replay::native_held::NativeHeldCapacityUsageV3 {
            journal_bytes,
            transactions: transactions as u64,
            materialized_bytes: materialized_bytes as u64,
            materialized_records: state.len() as u64,
            ..crate::replay::native_held::NativeHeldCapacityUsageV3::default()
        },
        next_sequence,
    )
}

/// Recognizes original-dependent rows in supplied saved state.
pub fn has_original_rows(state: &State) -> bool {
    state.iter().any(|((namespace, key), value)| {
        is_original_row(*namespace, key, value)
    })
}

/// Recognizes the same canonical original Source row families.
pub fn is_original_row(namespace: RecordNamespace, key: &[u8], value: &[u8]) -> bool {
    if namespace == RecordNamespace::SourceProviderAuthority {
        return value.get(..8) == Some(b"AOSSPL01")
            && matches!(value.get(8..10), Some([0, 8]) | Some([0, 9]));
    }
    if namespace != RecordNamespace::GlobalCapacityReservation {
        return false;
    }

    // Root5 shares a version number, not Source ownership. The existing
    // canonical family decoder remains the discriminator for floor rows.

    matches!(
        CanonicalCapacityFamily::decode(key, value).map_err(JournalError::from),
        Ok(CanonicalCapacityFamily::OriginalSource5(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;

    #[test]
    fn no_history_route_leaves_unrelated_transactions_inert() {
        let mut cache = SourceOriginalReplayDataV5::<()>::default();
        let state = State::new();
        let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, vec![1], vec![2],
        )]).unwrap();

        assert!(!cache.replay_without_history(&state, &transaction));
        assert!(!cache.needs_closure());
        assert!(!cache.has_dependencies());
    }

    #[test]
    fn no_history_route_keeps_reached_and_compacted_dependencies_pending() {
        let mut cache = SourceOriginalReplayDataV5::<()>::default();
        let mut state = State::new();
        let mut value = vec![0; 12];
        value[..8].copy_from_slice(b"AOSSPL01");
        value[8..10].copy_from_slice(&8_u16.to_be_bytes());
        let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority, vec![1], value.clone(),
        )]).unwrap();

        assert!(cache.replay_without_history(&state, &transaction));
        assert!(cache.needs_closure());
        assert!(cache.has_dependencies());
        assert!(cache.origins().is_empty());
        assert!(cache.cuts().is_empty());

        state.insert((RecordNamespace::SourceProviderAuthority, vec![1]), value);
        let mut compacted = SourceOriginalReplayDataV5::<()>::default();
        compacted.observe_compaction(&state);
        assert!(compacted.needs_closure());
        assert!(compacted.replay_without_history(&State::new(), &transaction));
    }
}
