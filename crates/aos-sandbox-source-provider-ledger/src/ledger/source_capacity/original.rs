//! Exact existing original-owner edge comparisons and retained retirement DATA.
//!
//! Edge inference tries the existing complete-graph proposers. It does not
//! implement another reducer or accept a caller's edge label as evidence.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;

use super::{OriginalSourceOwnerOriginInputV5, corrupt, views};
use crate::ledger::{
    LedgerFormatErrorV1,
    native_completion::{
        OriginalSourceAdmissionComparisonV5, OriginalSourceProvenanceV5,
        SourcePreRequestedColdPhaseV1, native_completion_key_v2,
        propose_original_source_applying_v5,
        propose_original_source_pre_requested_closed_v1,
        propose_original_source_pre_requested_closure_stored_v1,
        propose_original_source_pre_requested_root_acknowledged_v1,
    },
    native_held_completion::{
        SourceNativeHeldCompletionRecordV1, SourceNativeHeldLifecycleV1 as Lifecycle,
        SourceNativeHeldMutationV1, SourceNativeHeldStepV1 as Step, graph,
        propose_native_held_lifecycle_v1, propose_native_held_transition_v1,
        validate_original_source_admission_provenance_v5,
        validate_original_source_current_origin_v5,
    },
};

type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// Borrows actual canonical challenge-journal DATA for an original acquisition.
///
/// These bytes are separately observed DATA, not membership/currentness proof
/// or an atomic Source/challenge transaction. No comparison fabricates them.
#[derive(Clone, Copy)]
pub struct OriginalSourceChallengeDataV5<'a> {
    /// Names the actual original acquisition whose challenge is compared.
    pub acquisition: ObjectDigest,
    /// Borrows the actual canonical challenge key.
    pub key: &'a [u8],
    /// Borrows the actual canonical value observed by the caller.
    pub value: &'a [u8],
}

/// Names an inferred exact existing owner edge, without authorizing its effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCapacityOwnerEdgeKindV5 {
    /// Compares the genuine initial four-owner Applying reservation.
    Applying,
    /// Compares an existing held checkpoint, including initial Requested.
    Held(Step),
    /// Compares an existing retained lifecycle.
    Lifecycle(Lifecycle),
    /// Compares one of the integrated distinct pre-Requested cold edges.
    PreRequestedCold(SourcePreRequestedColdPhaseV1),
}

/// Retains exact final-edge origin/carrier comparison, never custody closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceRetirementComparisonV5 {
    comparison: OriginalSourceAdmissionComparisonV5,
    provenance: OriginalSourceProvenanceV5,
    key: Vec<u8>,
    after: Vec<u8>,
    kind: SourceCapacityOwnerEdgeKindV5,
}

impl OriginalSourceRetirementComparisonV5 {
    /// Returns the actual acquisition whose own debt was compared at a final edge.
    #[must_use]
    pub fn acquisition(&self) -> ObjectDigest {
        self.comparison.original().acquisition_id
    }

    /// Returns the exact compared final operation, not current custody evidence.
    #[must_use]
    pub const fn kind(&self) -> SourceCapacityOwnerEdgeKindV5 {
        self.kind
    }

    pub(super) fn retained_bytes(&self) -> usize {
        let quartet = self
            .comparison
            .quartet()
            .iter()
            .map(|row| row.key().len() + row.after().len())
            .sum::<usize>();
        quartet + self.provenance.to_canonical_bytes().len() + self.key.len() + self.after.len()
    }

    pub(super) fn validate_current(
        &self,
        records: &Records,
        origin: &OriginalSourceOwnerOriginInputV5<'_>,
    ) -> Result<(), LedgerFormatErrorV1> {
        if &self.comparison != origin.comparison
            || &self.provenance != origin.provenance
            || records.get(&self.key) != Some(&self.after)
        {
            return Err(corrupt("original Source retained final edge changed"));
        }
        Ok(())
    }
}

/// Retains the exact existing reducer mutations and unresolved owner obligations.
pub struct SourceCapacityOwnerEdgeDataV5 {
    acquisition: ObjectDigest,
    kind: SourceCapacityOwnerEdgeKindV5,
    mutations: Vec<SourceNativeHeldMutationV1>,
    retirement: Option<OriginalSourceRetirementComparisonV5>,
    independent_cut: bool,
    original_custody: bool,
    newly_retired: bool,
}

impl SourceCapacityOwnerEdgeDataV5 {
    /// Returns the actual origin selected by a successful exact comparison.
    #[must_use]
    pub const fn acquisition(&self) -> ObjectDigest {
        self.acquisition
    }

    /// Returns the inferred edge, not a caller-selected permission.
    #[must_use]
    pub const fn kind(&self) -> SourceCapacityOwnerEdgeKindV5 {
        self.kind
    }

    /// Borrows exact owner mutations, excluding every physical floor operation.
    #[must_use]
    pub fn mutations(&self) -> &[SourceNativeHeldMutationV1] {
        &self.mutations
    }

    /// Borrows final-edge comparison DATA that later cuts must independently join.
    #[must_use]
    pub const fn retirement(&self) -> Option<&OriginalSourceRetirementComparisonV5> {
        self.retirement.as_ref()
    }

    /// Reports an independently funded admission or current-owner predecessor.
    #[must_use]
    pub const fn requires_independent_cut(&self) -> bool {
        self.independent_cut
    }

    /// Reports actual original custody closure that this DATA cannot discharge.
    #[must_use]
    pub const fn requires_original_custody(&self) -> bool {
        self.original_custody
    }

    /// Reports a new final edge, not carry-forward of an already retired lineage.
    #[must_use]
    pub const fn newly_retires_original_debt(&self) -> bool {
        self.newly_retired
    }
}

/// Infers one exact original owner edge through the unchanged concrete proposers.
///
/// Complete canonical graphs, every historical origin and bounded separately
/// observed challenge DATA are checked before returning an existing proposal.
/// CurrentOwnersAdvanced is considered only after no specific edge matches; it
/// cannot certify a final own-floor deletion.
///
/// # Errors
///
/// Rejects invalid graphs/origins, duplicate/foreign/noncanonical challenge DATA,
/// missing required challenge bytes, ambiguous or unsupported actual mutations,
/// and any mismatch rejected by the existing exact reducers/Witness checks.
pub fn compare_original_source_capacity_owner_edge_v5<'before, 'after>(
    complete_before_owner_rows: impl IntoIterator<Item = (&'before [u8], &'before [u8])>,
    complete_after_owner_rows: impl IntoIterator<Item = (&'after [u8], &'after [u8])>,
    original_origins: &[OriginalSourceOwnerOriginInputV5<'_>],
    challenges: &[OriginalSourceChallengeDataV5<'_>],
) -> Result<SourceCapacityOwnerEdgeDataV5, LedgerFormatErrorV1> {
    super::bound_original_origins(original_origins)?;
    bound_challenges(challenges)?;
    let before = crate::collect_bounded_records(complete_before_owner_rows)?;
    let after = crate::collect_bounded_records(complete_after_owner_rows)?;
    crate::validate_current_records(&before)?;
    crate::validate_current_records(&after)?;
    crate::validate_transition_structure(&before, &after)?;
    if before == after {
        return Err(corrupt("original Source owner edge unchanged"));
    }

    let challenge_rows = validate_challenges(&before, &after, original_origins, challenges)?;
    let mut selected = None;
    for origin in original_origins {
        validate_original_source_admission_provenance_v5(
            origin.comparison,
            origin.provenance,
            origin.comparison.original().configuration_digest,
        )?;
        if let Some(retirement) = origin.retirement {
            retirement.validate_current(&before, origin)?;
        }
        let acquisition = origin.comparison.original().acquisition_id;
        let original = origin.comparison.original();
        let acquisition_key = crate::ledger::format::acquisition_key(
            &crate::ledger::model::AcquisitionKeyV1 {
                provider_id: original.provider.authority_id(),
                holder_id: original.holder.authority_id(),
                acquisition_id: acquisition,
            },
        );
        if before.contains_key(&acquisition_key) {
            validate_original_source_current_origin_v5(
                views(&before),
                origin.comparison,
                origin.provenance,
                original.configuration_digest,
            )?;
        }
        let challenge = challenge_rows.get(&acquisition).copied();
        infer_specific(&before, &after, origin, challenge, &mut selected)?;
    }
    if let Some(edge) = selected {
        return Ok(edge);
    }

    // This separate cut leaves the original acquisition/native byte exact.
    // It is never a Source-slot spend or a retained final retirement comparison.
    for origin in original_origins {
        let acquisition = origin.comparison.original().acquisition_id;
        if let Ok(proposal) = propose_native_held_lifecycle_v1(
            views(&before),
            views(&after),
            acquisition,
            Lifecycle::CurrentOwnersAdvanced,
        ) {
            return Ok(SourceCapacityOwnerEdgeDataV5 {
                acquisition,
                kind: SourceCapacityOwnerEdgeKindV5::Lifecycle(Lifecycle::CurrentOwnersAdvanced),
                mutations: proposal.mutations().to_vec(),
                retirement: None,
                independent_cut: true,
                original_custody: false,
                newly_retired: false,
            });
        }
    }
    Err(corrupt("original Source exact owner edge unsupported"))
}

fn infer_specific(
    before: &Records,
    after: &Records,
    origin: &OriginalSourceOwnerOriginInputV5<'_>,
    challenge: Option<&[u8]>,
    selected: &mut Option<SourceCapacityOwnerEdgeDataV5>,
) -> Result<(), LedgerFormatErrorV1> {
    let acquisition = origin.comparison.original().acquisition_id;
    validate_original_source_current_origin_v5(
        views(after),
        origin.comparison,
        origin.provenance,
        origin.comparison.original().configuration_digest,
    )?;
    let changed = after
        .iter()
        .filter(|(key, value)| before.get(*key) != Some(*value))
        .map(|(key, value)| (key.as_slice(), Some(value.as_slice())))
        .collect::<Vec<_>>();
    let configuration = origin.comparison.original().configuration_digest;
    if let Ok(proposal) = propose_original_source_applying_v5(
        views(before),
        changed.iter().copied(),
        origin.provenance,
        configuration,
    ) {
        if proposal.admission_comparison()? == *origin.comparison {
            select(
                selected,
                edge(
                    origin,
                    after,
                    SourceCapacityOwnerEdgeKindV5::Applying,
                    proposal.mutations(),
                    false,
                    false,
                    false,
                )?,
            )?;
        }
    }

    for step in [
        Step::Requested,
        Step::ChallengeIssued,
        Step::StoragePrepared,
        Step::ChallengeSpent,
        Step::CompletionCommitted,
        Step::HeldPrepared,
        Step::HeldStored,
        Step::RootDispositionPrepared,
        Step::RelayStored,
        Step::StorageSettlementRecorded,
        Step::ProviderSettledPrepared,
        Step::ProviderSettledStored,
        Step::RootRecoveryRecorded,
        Step::StorageRecoveryPrepared,
        Step::StorageRecoveryQueryStored,
        Step::StorageRecoveryRecorded,
        Step::ProviderRecoveryPrepared,
        Step::ProviderRecoveryStored,
        Step::RootTerminalRecorded,
    ] {
        if let Ok(proposal) = propose_native_held_transition_v1(
            views(before),
            views(after),
            acquisition,
            step,
            challenge,
        ) {
            select(
                selected,
                edge(
                    origin,
                    after,
                    SourceCapacityOwnerEdgeKindV5::Held(step),
                    proposal.mutations(),
                    false,
                    false,
                    false,
                )?,
            )?;
        }
    }
    for lifecycle in [
        Lifecycle::OriginalCustodyMarked,
        Lifecycle::ColdTerminalCleanupMarked,
        Lifecycle::ReleaseAdmitted,
        Lifecycle::ReleaseStatusCompleted,
        Lifecycle::ReleaseCompleted,
        Lifecycle::ReleasedArtifactsCompacted,
    ] {
        if let Ok(proposal) = propose_native_held_lifecycle_v1(
            views(before),
            views(after),
            acquisition,
            lifecycle,
        ) {
            let independent = lifecycle == Lifecycle::ReleaseAdmitted;
            select(
                selected,
                edge(
                    origin,
                    after,
                    SourceCapacityOwnerEdgeKindV5::Lifecycle(lifecycle),
                    proposal.mutations(),
                    !independent,
                    independent,
                    proposal.original_custody_required().is_some(),
                )?,
            )?;
        }
    }

    if let Ok(proposal) = propose_original_source_pre_requested_closed_v1(
        views(before),
        changed.iter().copied(),
        origin.provenance,
        configuration,
    ) {
        select(
            selected,
            edge(
                origin,
                after,
                SourceCapacityOwnerEdgeKindV5::PreRequestedCold(
                    SourcePreRequestedColdPhaseV1::ClosedPrepared,
                ),
                proposal.mutations(),
                false,
                false,
                false,
            )?,
        )?;
    }
    if let Ok(proposal) = propose_original_source_pre_requested_closure_stored_v1(
        views(before),
        changed.iter().copied(),
        acquisition,
    ) {
        select(
            selected,
            edge(
                origin,
                after,
                SourceCapacityOwnerEdgeKindV5::PreRequestedCold(
                    SourcePreRequestedColdPhaseV1::ClosureStored,
                ),
                proposal.mutations(),
                false,
                false,
                false,
            )?,
        )?;
    }
    if let Ok(proposal) = propose_original_source_pre_requested_root_acknowledged_v1(
        views(before),
        changed.iter().copied(),
        acquisition,
    ) {
        select(
            selected,
            edge(
                origin,
                after,
                SourceCapacityOwnerEdgeKindV5::PreRequestedCold(
                    SourcePreRequestedColdPhaseV1::RootAcknowledged,
                ),
                proposal.mutations(),
                true,
                false,
                false,
            )?,
        )?;
    }
    Ok(())
}

fn edge(
    origin: &OriginalSourceOwnerOriginInputV5<'_>,
    after: &Records,
    kind: SourceCapacityOwnerEdgeKindV5,
    mutations: &[SourceNativeHeldMutationV1],
    final_edge: bool,
    independent_cut: bool,
    original_custody: bool,
) -> Result<SourceCapacityOwnerEdgeDataV5, LedgerFormatErrorV1> {
    let acquisition = origin.comparison.original().acquisition_id;
    let retirement = if final_edge || origin.retirement.is_some() {
        let key = native_completion_key_v2(acquisition);
        let bytes = after
            .get(&key)
            .ok_or(corrupt("original Source final carrier absent"))?;
        Some(OriginalSourceRetirementComparisonV5 {
            comparison: origin.comparison.clone(),
            provenance: origin.provenance.clone(),
            key,
            after: bytes.clone(),
            kind: origin.retirement.map_or(kind, |retirement| retirement.kind),
        })
    } else {
        None
    };
    let mutations = if matches!(
        kind,
        SourceCapacityOwnerEdgeKindV5::Applying
            | SourceCapacityOwnerEdgeKindV5::PreRequestedCold(
                SourcePreRequestedColdPhaseV1::ClosedPrepared,
            )
    ) {
        let mut ordered = origin
            .provenance
            .claims()
            .records
            .iter()
            .map(|witness| {
                mutations
                    .iter()
                    .find(|mutation| mutation.key() == witness.key())
                    .cloned()
                    .ok_or(corrupt("original Source exact semantic owner order"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if kind != SourceCapacityOwnerEdgeKindV5::Applying {
            let native = native_completion_key_v2(acquisition);
            ordered.push(
                mutations
                    .iter()
                    .find(|mutation| mutation.key() == native)
                    .cloned()
                    .ok_or(corrupt("original Source exact cold carrier order"))?,
            );
        }
        ordered
    } else {
        mutations.to_vec()
    };
    Ok(SourceCapacityOwnerEdgeDataV5 {
        acquisition,
        kind,
        mutations,
        retirement,
        independent_cut,
        original_custody,
        newly_retired: final_edge && origin.retirement.is_none(),
    })
}

fn select(
    selected: &mut Option<SourceCapacityOwnerEdgeDataV5>,
    edge: SourceCapacityOwnerEdgeDataV5,
) -> Result<(), LedgerFormatErrorV1> {
    if selected.is_some() {
        return Err(corrupt("original Source owner edge ambiguous"));
    }
    *selected = Some(edge);
    Ok(())
}

/// Bounds borrowed challenge DATA before a caller clones current owner cuts.
///
/// This checks only count and aggregate byte retention. Canonical binding and
/// Witness joins still require the exact owner comparator; it grants no proof.
///
/// # Errors
///
/// Rejects excessive challenge count/bytes or checked byte-sum overflow.
pub fn validate_original_source_challenge_data_bounds_v5(
    challenges: &[OriginalSourceChallengeDataV5<'_>],
) -> Result<(), LedgerFormatErrorV1> {
    bound_challenges(challenges)
}

fn bound_challenges(
    challenges: &[OriginalSourceChallengeDataV5<'_>],
) -> Result<(), LedgerFormatErrorV1> {
    if challenges.len() > crate::limits::MAXIMUM_LEDGER_RECORDS {
        return Err(LedgerFormatErrorV1::LimitExceeded("original Source challenge count"));
    }
    let bytes = challenges.iter().try_fold(0_usize, |sum, row| {
        sum.checked_add(row.key.len())
            .and_then(|sum| sum.checked_add(row.value.len()))
            .ok_or(LedgerFormatErrorV1::LimitExceeded("original Source challenge bytes"))
    })?;
    if bytes > crate::limits::MAXIMUM_LEDGER_GRAPH_BYTES {
        return Err(LedgerFormatErrorV1::LimitExceeded("original Source challenge bytes"));
    }
    Ok(())
}

fn validate_challenges<'a>(
    before: &Records,
    after: &Records,
    origins: &[OriginalSourceOwnerOriginInputV5<'_>],
    challenges: &[OriginalSourceChallengeDataV5<'a>],
) -> Result<BTreeMap<ObjectDigest, &'a [u8]>, LedgerFormatErrorV1> {
    let mut result = BTreeMap::new();
    for row in challenges {
        if !origins
            .iter()
            .any(|origin| origin.comparison.original().acquisition_id == row.acquisition)
            || result.contains_key(&row.acquisition)
        {
            return Err(corrupt("original Source challenge duplicate or foreign"));
        }
        let key = native_completion_key_v2(row.acquisition);
        let held = after
            .get(&key)
            .or_else(|| before.get(&key))
            .ok_or(corrupt("original Source challenge held carrier missing"))?;
        let held = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, held)?;
        if graph::challenge_key(&held) != row.key
            || (graph::validate_challenge(&held, Some(row.value), false).is_err()
                && graph::validate_challenge(&held, Some(row.value), true).is_err())
        {
            return Err(corrupt("original Source challenge canonical binding"));
        }
        result.insert(row.acquisition, row.value);
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
