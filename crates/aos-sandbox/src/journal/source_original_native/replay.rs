//! Physical original admissions, exact retirement carriers and cut references.
//!
//! This cache is populated by the shared checksum-verified Journal parser. It
//! reruns existing Ledger owner comparisons and the sole Sandbox union fold.
//! Current markers, inverse floor identities and caller DATA never create history.

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::ledger::{
    native_held_completion::SourceNativeHeldCompletionRecordV1,
    source_capacity::{
        OriginalSourceChallengeDataV5,
        compare_original_source_capacity_owner_edge_v5,
    },
};

use super::{
    State, SourceOriginalAdmissionDataV5, SourceOriginalAdmissionInputV5,
    SourceOriginalChallengeHistoryViewV5, SourceCapacityUnionComparisonDataV5,
    compare_source_original_admission_data_v5, invalid, owner_views,
    union::{
        SourceHistoricalRetirementReferenceV5,
        compare_source_capacity_union_at_physical_cuts_v5,
    },
    challenge::{SourceChallengeReplayWitnessV5, SourceOriginalChallengeCheckpointV5},
};
use super::super::{JournalError, JournalLimits, JournalTransaction, RecordNamespace};

/// Borrows an actual original-related physical transaction boundary.
#[derive(Clone)]
pub struct SourceOriginalPhysicalCutV5 {
    device: u64,
    inode: u64,
    transaction: [u8; 16],
    digest: [u8; 32],
    begin_sequence: u64,
    commit_sequence: u64,
    begin_offset: u64,
    durable_end: u64,
    before: Arc<State>,
    after: Arc<State>,
    challenge_checkpoint: Option<usize>,
}

impl SourceOriginalPhysicalCutV5 {
    /// Borrows actual complete before rows from this committed physical prefix.
    pub fn before_rows(&self) -> &State {
        &self.before
    }

    /// Borrows actual complete after rows from this committed physical prefix.
    pub fn after_rows(&self) -> &State {
        &self.after
    }

    /// Returns the actual checkpoint index selected by the existing exact proposer.
    pub const fn challenge_checkpoint(&self) -> Option<usize> {
        self.challenge_checkpoint
    }

    /// Returns the actual held Journal device and inode, not caller claims.
    pub const fn file_identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Returns the actual ordered committed transaction identity.
    pub const fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction
    }

    /// Returns the digest of the exact ordered records, not an admission permit.
    pub const fn transaction_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns actual begin and commit frame sequences.
    pub const fn frame_sequences(&self) -> (u64, u64) {
        (self.begin_sequence, self.commit_sequence)
    }

    /// Returns actual begin offset and committed-prefix end.
    pub const fn file_offsets(&self) -> (u64, u64) {
        (self.begin_offset, self.durable_end)
    }
}

#[derive(Clone, Default)]
pub(in crate::journal) struct SourceOriginalReplayCacheV5 {
    pending: bool,
    origins: Vec<SourceOriginalAdmissionDataV5>,
    historical: Vec<SourceHistoricalRetirementReferenceV5>,
    cuts: Vec<SourceOriginalPhysicalCutV5>,
    retained_bytes: usize,
    current_retirement_bytes: BTreeMap<ObjectDigest, usize>,
    challenges: Option<SourceChallengeReplayWitnessV5>,
    prospective_challenge_checkpoint: Option<usize>,
}

impl SourceOriginalReplayCacheV5 {
    pub(in crate::journal) fn needs_closure(&self) -> bool {
        self.pending
    }

    pub(in crate::journal) fn has_dependencies(&self) -> bool {
        self.pending || !self.origins.is_empty()
    }

    pub(super) fn origins(&self) -> &[SourceOriginalAdmissionDataV5] {
        &self.origins
    }

    pub(super) fn cuts(&self) -> &[SourceOriginalPhysicalCutV5] {
        &self.cuts
    }

    pub(super) fn prospective_challenge_checkpoint(&self) -> Option<usize> {
        self.prospective_challenge_checkpoint
    }

    pub(super) fn retain_challenges(
        &mut self,
        view: &SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        self.challenges = Some(view.retained_witness()?);
        Ok(())
    }

    pub(super) fn validate_challenges(
        &self,
        view: &SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        self.challenges.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .validate_current(view)
    }

    pub(in crate::journal) fn compare_cached(
        &self,
        state: &State,
        transaction: Option<&JournalTransaction>,
        limits: JournalLimits,
    ) -> Result<SourceCapacityUnionComparisonDataV5, JournalError> {
        let history = self.challenges.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.compare_rows(state, transaction, history.rows(), limits)
            .map(|(comparison, _)| comparison)
    }

    pub(super) fn preview_transaction(
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
                        super::super::capacity_reservation::family::CanonicalCapacityFamily::decode(
                            record.key(), value,
                        ).is_ok_and(|family| matches!(family,
                            super::super::capacity_reservation::family::CanonicalCapacityFamily::OriginalSource5(
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

    pub(in crate::journal) fn observe_compaction(&mut self, state: &State) {
        if has_original_rows(state) {
            self.pending = true;
        }
    }

    pub(in crate::journal) fn replay_transaction(
        &mut self,
        state: &State,
        transaction: &JournalTransaction,
        challenges: Option<&SourceOriginalChallengeHistoryViewV5<'_>>,
        limits: JournalLimits,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        durable_end: u64,
        committed_transactions: usize,
        journal_identity: (u64, u64),
    ) -> Result<bool, JournalError> {
        if !self.has_dependencies()
            && !has_original_rows(state)
            && !transaction.records().iter().any(|record| {
                record.value().is_some_and(|value| {
                    is_original_row(record.namespace(), record.key(), value)
                })
            })
        {
            return Ok(false);
        }

        let Some(challenges) = challenges else {
            // The generic open remains inert. Only the fixed owner can close
            // this SAME physical parser with the separately held actual history.
            self.pending = true;
            return Ok(true);
        };
        challenges.validate_current()?;

        // Preflight the complete retained payload before any prospective map or
        // cut allocation. Adjacent cuts share their identical immutable map.
        let before_bytes = super::bounded_snapshot_bytes(state, limits)?;
        let after_bytes = prospective_payload_bytes(state, transaction, before_bytes)?;
        let previous_after = self.cuts.last().filter(|cut| cut.after_rows() == state);
        let retained_before_bytes = if previous_after.is_some() { 0 } else { before_bytes };
        let additional = after_bytes.checked_add(retained_before_bytes)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceOriginalPhysicalCutV5>()))
            .ok_or(JournalError::LimitExceeded("Source retained physical cuts"))?;
        if self.retained_bytes.checked_add(additional)
            .is_none_or(|bytes| bytes > limits.maximum_materialized_bytes)
        {
            return Err(JournalError::LimitExceeded("Source retained physical cuts"));
        }
        let prospective = super::super::root_original_inventory::materialize(state, transaction);
        let added = transaction.records().len() == 5
            && transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::GlobalCapacityReservation
                    && record.value().is_some_and(|value| value.get(8..10) == Some(&5_u16.to_be_bytes()))
                    && super::super::capacity_reservation::family::CanonicalCapacityFamily::decode(
                        record.key(), record.value().unwrap_or_default(),
                    ).is_ok_and(|family| matches!(family,
                        super::super::capacity_reservation::family::CanonicalCapacityFamily::OriginalSource5(_)))
            });
        let mut admission = if added {
            let admission_payload = admission_payload_bound(state, transaction)?;
            let cut_bytes = super::bounded_snapshot_bytes(state, limits)?
                .checked_add(super::bounded_snapshot_bytes(&prospective, limits)?)
                .and_then(|bytes| bytes.checked_add(self.retained_bytes))
                .and_then(|bytes| bytes.checked_add(admission_payload))
                .ok_or(JournalError::LimitExceeded("Source retained original cuts"))?;
            if cut_bytes > limits.maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded("Source retained original cuts"));
            }
            // Only the real five-row original Applying comparator can create an
            // origin. A later successor PUT does not satisfy that comparator.
            compare_source_original_admission_data_v5(
                SourceOriginalAdmissionInputV5 {
                    original_before: state,
                    original_applying: transaction,
                },
                limits,
            ).ok()
        } else {
            None
        };
        if let Some(admission) = admission.as_mut()
            && let Some(previous) = self.cuts.last()
        {
            admission.reuse_retained_before(&previous.after)?;
        }
        let admission_rows = admission.as_ref().map(SourceOriginalAdmissionDataV5::retained_cut_rows);
        if let Some(admission) = admission {
            self.retain_admission(admission, transaction, limits)?;
        }

        let (comparison, selected_challenges) = self.compare(state, Some(transaction), challenges, limits)?;
        let challenge_checkpoint = match selected_challenges.as_slice() {
            [] => None,
            [selected] => Some(challenges.retained_rows()?.iter().position(|checkpoint| {
                checkpoint.key() == selected.key && checkpoint.value() == selected.value
            }).ok_or(JournalError::ProtectedBoundary)?),
            _ => return Err(JournalError::ProtectedBoundary),
        };
        require_advisory_bounds(
            &comparison,
            limits,
            durable_end,
            committed_transactions,
            commit_sequence.checked_add(1).ok_or(JournalError::SequenceExhausted)?,
        )?;
        if let Some(edge) = comparison.owner_edge()
            && let Some(retirement) = edge.retirement()
        {
            let origin = self.origins.iter().find(|origin| {
                origin.admission_comparison().original().acquisition_id == edge.acquisition()
            }).ok_or(invalid("Source physical retirement has no original"))?;
            let width = retirement_width(origin, comparison.after())?;
            let previous = self.current_retirement_bytes.get(&edge.acquisition()).copied()
                .unwrap_or_default();
            let next = self.retained_bytes.checked_sub(previous)
                .and_then(|bytes| bytes.checked_add(width))
                .ok_or(JournalError::LimitExceeded("Source retained final carriers"))?;
            if next > limits.maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded("Source retained final carriers"));
            }
            let origin = self.origins.iter_mut().find(|origin| {
                origin.admission_comparison().original().acquisition_id == edge.acquisition()
            }).ok_or(invalid("Source physical retirement has no original"))?;
            origin.retain_compared_retirement(retirement)?;
            self.current_retirement_bytes.insert(edge.acquisition(), width);
            self.retained_bytes = next;
        }

        let (before, after, new_payload) = match admission_rows {
            Some((before, after)) => (before, after, 0),
            None => {
                let (before, before_payload) = match self.cuts.last() {
                    Some(previous) if previous.after_rows() == state => (Arc::clone(&previous.after), 0),
                    _ => (Arc::new(state.clone()), before_bytes),
                };
                (before, Arc::new(prospective), before_payload.checked_add(after_bytes)
                    .ok_or(JournalError::LimitExceeded("Source retained physical cuts"))?)
            }
        };

        // Descriptor count/payload is bounded before retention. Ordinary cuts
        // before the first dependency are streamed and discarded by the parser.
        self.retained_bytes = self.retained_bytes.checked_add(new_payload)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceOriginalPhysicalCutV5>()))
            .ok_or(JournalError::LimitExceeded("Source retained physical cuts"))?;
        if self.retained_bytes > limits.maximum_materialized_bytes {
            return Err(JournalError::LimitExceeded("Source retained physical cuts"));
        }
        self.cuts.push(SourceOriginalPhysicalCutV5 {
            device: journal_identity.0,
            inode: journal_identity.1,
            transaction: *transaction.id(),
            digest: super::super::authority_preflight_digest(std::slice::from_ref(transaction)),
            begin_sequence,
            commit_sequence,
            begin_offset,
            durable_end,
            before,
            after,
            challenge_checkpoint,
        });
        self.pending = false;
        Ok(true)
    }

    fn retain_admission(
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

    pub(super) fn compare<'challenge>(
        &self,
        state: &State,
        transaction: Option<&JournalTransaction>,
        challenges: &'challenge SourceOriginalChallengeHistoryViewV5<'_>,
        limits: JournalLimits,
    ) -> Result<(SourceCapacityUnionComparisonDataV5, Vec<OriginalSourceChallengeDataV5<'challenge>>), JournalError> {
        challenges.validate_current()?;
        self.compare_rows(
            state,
            transaction,
            challenges.retained_rows()?,
            limits,
        )
    }

    fn compare_rows<'challenge>(
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
        let after = super::super::root_original_inventory::materialize(state, transaction);
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

fn prospective_payload_bytes(
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

fn retirement_width(
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
fn admission_payload_bound(before: &State, transaction: &JournalTransaction)
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

pub(in crate::journal) fn require_advisory_bounds(
    comparison: &SourceCapacityUnionComparisonDataV5,
    limits: JournalLimits,
    journal_bytes: u64,
    transactions: usize,
    next_sequence: u64,
) -> Result<(), JournalError> {
    let state = comparison.after();
    let materialized_bytes = super::bounded_snapshot_bytes(state, limits)?;
    super::super::validate_reserved_capacity(
        state, materialized_bytes, &[], None, journal_bytes, transactions, limits, None,
    )?;
    super::super::root_original_inventory::require_sequence_headroom(state, next_sequence)?;
    comparison.require_geometry_headroom(
        limits,
        super::super::native_held::NativeHeldCapacityUsageV3 {
            journal_bytes,
            transactions: transactions as u64,
            materialized_bytes: materialized_bytes as u64,
            materialized_records: state.len() as u64,
            ..super::super::native_held::NativeHeldCapacityUsageV3::default()
        },
        next_sequence,
    )
}

pub(in crate::journal) fn has_original_rows(state: &State) -> bool {
    state.iter().any(|((namespace, key), value)| {
        is_original_row(*namespace, key, value)
    })
}

fn is_original_row(namespace: RecordNamespace, key: &[u8], value: &[u8]) -> bool {
    if namespace == RecordNamespace::SourceProviderAuthority {
        return value.get(..8) == Some(b"AOSSPL01")
            && matches!(value.get(8..10), Some([0, 8]) | Some([0, 9]));
    }
    if namespace != RecordNamespace::GlobalCapacityReservation {
        return false;
    }

    // Root5 shares a version number, not Source ownership. The existing
    // canonical family decoder remains the discriminator for floor rows.
    use super::super::capacity_reservation::family::CanonicalCapacityFamily;
    matches!(
        CanonicalCapacityFamily::decode(key, value),
        Ok(CanonicalCapacityFamily::OriginalSource5(_))
    )
}

#[cfg(test)]
mod tests;
