//! Canonical Source floor-union DATA and unchanged ordinary request policy.
//!
//! Ledger owns real owner eligibility. This adapter owns Journal family codecs,
//! framing and exact complete-union accounting; no request DATA grants custody.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::ledger::{
    format,
    model::{AcquisitionKeyV1, DecodedRecordV1},
    native_completion::{
        OriginalSourceAdmissionComparisonV5, SourcePreRequestedColdArchiveV1,
        SourcePreRequestedColdPhaseV1, native_completion_key_v2,
        release_fence::{
            NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1, NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1,
            NativeReleaseStatusCapacityBindingV1,
        },
    },
    native_held_completion::{
        OriginalSourceContinuationPrefixV5, SourceNativeHeldCompletionRecordV1,
        SourceNativeHeldLifecycleV1,
    },
    source_capacity::{
        SourceCapacityBindingFieldsV1, SourceOrdinaryCapacityBindingV1,
        SourceOrdinaryCapacityKindV1, OriginalSourceChallengeDataV5,
        OriginalSourceOwnerOriginInputV5, OriginalSourceRetirementComparisonV5,
        SourceCapacityOwnerDataV1, SourceCapacityOwnerEdgeDataV5,
        SourceCapacityOwnerEdgeKindV5, SourceCapacityProfileV1,
        compare_original_source_capacity_owner_edge_v5, derive_source_capacity_owner_data_v1,
        validate_original_source_challenge_data_bounds_v5,
    },
};
use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1;

use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, RecordNamespace,
    JournalError, JournalLimits, JournalRecord, JournalTransaction,
    capacity_reservation::family::{
        CanonicalCapacityFamily, accounting_reservations, canonical_reservations,
    },
    native_held::{
        NativeHeldCapacityPurposeV3, OriginalSourceCapacityRecordV5,
        OriginalSourceGeometryDataV5, check_bounded_transfer,
    },
};

use super::{State, bounded_snapshot_bytes, invalid, owner_views, prospective_state};

/// Names bounded Source-owner and global-floor comparison DATA.
pub type SourceCapacityStateV5 = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Borrows actual retained initial Applying inputs without claiming their custody.
#[derive(Clone, Copy)]
pub struct SourceOriginalAdmissionInputV5<'a> {
    /// Borrows the complete original owner/floor before cut.
    pub original_before: &'a SourceCapacityStateV5,
    /// Borrows the exact actual five-record Applying transaction DATA.
    pub original_applying: &'a JournalTransaction,
}

/// Retains an exact Applying comparison, never a physical admission receipt.
#[derive(Clone)]
pub struct SourceOriginalAdmissionDataV5 {
    original_before: Arc<State>,
    applying_after: Arc<State>,
    applying: JournalTransaction,
    initial_floor: OriginalSourceCapacityRecordV5,
    comparison: OriginalSourceAdmissionComparisonV5,
    retirement: Option<OriginalSourceRetirementComparisonV5>,
}

impl SourceOriginalAdmissionDataV5 {
    pub(super) fn retained_cut_rows(&self) -> (Arc<State>, Arc<State>) {
        (Arc::clone(&self.original_before), Arc::clone(&self.applying_after))
    }

    pub(super) fn reuse_retained_before(&mut self, before: &Arc<State>) -> Result<(), JournalError> {
        if before.as_ref() != self.original_before.as_ref() {
            return Err(invalid("Source adjacent original cut changed"));
        }
        self.original_before = Arc::clone(before);
        Ok(())
    }

    /// Borrows the complete compared historical before cut.
    pub fn original_before(&self) -> &SourceCapacityStateV5 {
        &self.original_before
    }

    /// Borrows the exact historical Applying after cut, not a current graph.
    pub fn applying_after(&self) -> &SourceCapacityStateV5 {
        &self.applying_after
    }

    /// Borrows exact Applying bytes without proving same-instance membership.
    pub fn applying_transaction(&self) -> &JournalTransaction {
        &self.applying
    }

    /// Borrows the accepted historical quartet comparison DATA.
    pub fn admission_comparison(&self) -> &OriginalSourceAdmissionComparisonV5 {
        &self.comparison
    }

    /// Borrows immutable initial floor DATA, not a reservation grant.
    pub fn initial_floor(&self) -> &OriginalSourceCapacityRecordV5 {
        &self.initial_floor
    }

    /// Retains an exact final-edge reference for independently checked later cuts.
    ///
    /// # Errors
    ///
    /// Rejects a foreign acquisition. Every later union still checks the full
    /// seed/provenance/carrier join; this method grants no custody or membership.
    pub fn with_retirement_data(
        &self,
        retirement: &OriginalSourceRetirementComparisonV5,
    ) -> Result<Self, JournalError> {
        if retirement.acquisition() != self.comparison.original().acquisition_id {
            return Err(invalid("original Source retirement acquisition changed"));
        }
        let mut result = self.clone();
        result.retirement = Some(retirement.clone());
        Ok(result)
    }

    pub(super) fn origin(&self) -> OriginalSourceOwnerOriginInputV5<'_> {
        OriginalSourceOwnerOriginInputV5 {
            comparison: &self.comparison,
            provenance: self.initial_floor.original_provenance(),
            retirement: self.retirement.as_ref(),
        }
    }

    pub(super) fn retained_retirement(
        &self,
    ) -> Option<&OriginalSourceRetirementComparisonV5> {
        self.retirement.as_ref()
    }

    pub(super) fn retain_compared_retirement(
        &mut self,
        retirement: &OriginalSourceRetirementComparisonV5,
    ) -> Result<(), JournalError> {
        if retirement.acquisition() != self.comparison.original().acquisition_id {
            return Err(invalid("Source physical retirement acquisition changed"));
        }
        self.retirement = Some(retirement.clone());
        Ok(())
    }
}

/// Retains the final carrier that was real at one exact original historical cut.
///
/// Only the physical parser constructs this input. A later current carrier is
/// not interchangeable with either cut of a newly admitted original.
#[derive(Clone)]
pub(super) struct SourceHistoricalRetirementReferenceV5 {
    pub(super) admission: [u8; 16],
    pub(super) applying_after: bool,
    pub(super) acquisition: ObjectDigest,
    pub(super) retirement: Arc<OriginalSourceRetirementComparisonV5>,
}

/// Retains complete compared unions and unresolved physical proof obligations.
pub struct SourceCapacityUnionComparisonDataV5 {
    before: State,
    after: State,
    before_ids: BTreeSet<[u8; 32]>,
    after_ids: BTreeSet<[u8; 32]>,
    removed_ids: BTreeSet<[u8; 32]>,
    inserted_ids: BTreeSet<[u8; 32]>,
    remaining: BTreeMap<ObjectDigest, OriginalSourceCapacityRecordV5>,
    edge: Option<SourceCapacityOwnerEdgeDataV5>,
    geometries: BTreeMap<ObjectDigest, OriginalSourceGeometryDataV5>,
    actual_source_ids: BTreeMap<ObjectDigest, [u8; 32]>,
    independent_headroom: bool,
}

impl SourceCapacityUnionComparisonDataV5 {
    /// Borrows the complete checked before DATA.
    pub fn before(&self) -> &SourceCapacityStateV5 {
        &self.before
    }

    /// Borrows the exact transaction-derived after DATA.
    pub fn after(&self) -> &SourceCapacityStateV5 {
        &self.after
    }

    /// Borrows all independently associated before/after floor identities.
    pub fn floor_ids(&self) -> (&BTreeSet<[u8; 32]>, &BTreeSet<[u8; 32]>) {
        (&self.before_ids, &self.after_ids)
    }

    /// Borrows exact removed/inserted identities; unchanged obligations count once.
    pub fn changed_floor_ids(&self) -> (&BTreeSet<[u8; 32]>, &BTreeSet<[u8; 32]>) {
        (&self.removed_ids, &self.inserted_ids)
    }

    /// Borrows every measured exact remaining own-floor envelope.
    pub fn remaining_own_floors(
        &self,
    ) -> impl Iterator<Item = (&ObjectDigest, &OriginalSourceCapacityRecordV5)> {
        self.remaining.iter()
    }

    /// Borrows the inferred concrete owner edge, not permission to append it.
    pub fn owner_edge(&self) -> Option<&SourceCapacityOwnerEdgeDataV5> {
        self.edge.as_ref()
    }

    /// Reports unresolved membership/configuration/archive/custody/funding proofs.
    #[must_use]
    pub const fn requires_physical_owner_proofs(&self) -> bool {
        true
    }

    /// Reports separately held current-writer headroom, not a funded receipt.
    #[must_use]
    pub const fn requires_independent_journal_headroom(&self) -> bool {
        self.independent_headroom
    }

    /// Checks retained futures against actual usage without minting a grant.
    ///
    /// # Errors
    ///
    /// Rejects missing actual own debt, any opened ceiling or NEXT exhaustion.
    pub(in crate::journal) fn require_geometry_headroom(
        &self,
        limits: JournalLimits,
        usage: crate::journal::native_held::NativeHeldCapacityUsageV3,
        next_sequence: u64,
    ) -> Result<(), JournalError> {
        let debts = accounting_reservations(&self.after)?;
        for (acquisition, geometry) in &self.geometries {
            let own_id = self
                .actual_source_ids
                .get(acquisition)
                .ok_or(invalid("Source measured current floor missing"))?;
            let mut selected_usage = usage;
            let mut other_frames = 0_u64;

            for (identifier, debt) in &debts {
                if identifier == own_id {
                    continue;
                }
                selected_usage.reserved_bytes = selected_usage
                    .reserved_bytes
                    .checked_add(debt.maximum_bytes)
                    .ok_or(JournalError::JournalTooLarge)?;
                selected_usage.reserved_records = selected_usage
                    .reserved_records
                    .checked_add(debt.maximum_records as u64)
                    .ok_or(JournalError::LimitExceeded("Source other record debt"))?;
                selected_usage.reserved_transactions = selected_usage
                    .reserved_transactions
                    .checked_add(debt.maximum_transactions as u64)
                    .ok_or(JournalError::LimitExceeded("Source other transaction debt"))?;
                let transaction_frames = (debt.maximum_transactions as u64)
                    .checked_mul(2)
                    .ok_or(JournalError::SequenceExhausted)?;
                let frames = (debt.maximum_records as u64)
                    .checked_add(transaction_frames)
                    .ok_or(JournalError::SequenceExhausted)?;
                other_frames = other_frames
                    .checked_add(frames)
                    .ok_or(JournalError::SequenceExhausted)?;
            }
            geometry.require_usage_headroom(limits, selected_usage, next_sequence, other_frames)?;
        }
        Ok(())
    }
}

/// Compares bounded actual Applying inputs through the existing exact proposer.
///
/// # Errors
///
/// Rejects malformed/foreign states, noncanonical floors, an incorrect five-row
/// transaction, changed owner origin or any existing exact Applying join error.
pub fn compare_source_original_admission_data_v5(
    input: SourceOriginalAdmissionInputV5<'_>,
    limits: JournalLimits,
) -> Result<SourceOriginalAdmissionDataV5, JournalError> {
    bound_source_state(input.original_before, limits)?;
    crate::journal::validate_transaction(input.original_applying, limits)?;
    let floor = input
        .original_applying
        .records()
        .last()
        .ok_or(JournalError::InvalidTransaction)?;
    let floor = OriginalSourceCapacityRecordV5::from_journal_record(floor)?;
    let candidate = super::compare_original_source_applying_transaction_v5(
        input.original_before,
        input.original_applying,
        floor.original_provenance().claims().configuration,
        limits,
    )?;
    let comparison = candidate
        .owner
        .admission_comparison()
        .map_err(|_| invalid("original Source Applying comparison"))?;
    Ok(SourceOriginalAdmissionDataV5 {
        original_before: Arc::new(candidate.before),
        applying_after: Arc::new(candidate.after),
        applying: candidate.transaction,
        initial_floor: candidate.floor,
        comparison,
        retirement: None,
    })
}

/// Compares the canonical complete Source floor union and one full actual TX.
///
/// Every current owner obligation is derived below Sandbox. Supplied origin and
/// challenge bytes remain DATA. Independent Release admission does not spend a
/// Source slot; ordinary deletion requires real before/after retirement.
///
/// # Errors
///
/// Rejects unsupported families/Native3 intermediates, missing/extra/ambiguous
/// obligations, changed origins, an unsupported exact owner edge, nonderived
/// successor debt, incomplete transaction conservation or opened format limits.
pub fn compare_source_capacity_union_data_v5(
    before: &SourceCapacityStateV5,
    transaction: Option<&JournalTransaction>,
    origins: &[SourceOriginalAdmissionDataV5],
    challenges: &[OriginalSourceChallengeDataV5<'_>],
    limits: JournalLimits,
) -> Result<SourceCapacityUnionComparisonDataV5, JournalError> {
    compare_source_capacity_union_at_physical_cuts_v5(
        before, transaction, origins, challenges, &[], limits,
    )
}

pub(super) fn compare_source_capacity_union_at_physical_cuts_v5(
    before: &SourceCapacityStateV5,
    transaction: Option<&JournalTransaction>,
    origins: &[SourceOriginalAdmissionDataV5],
    challenges: &[OriginalSourceChallengeDataV5<'_>],
    historical: &[SourceHistoricalRetirementReferenceV5],
    limits: JournalLimits,
) -> Result<SourceCapacityUnionComparisonDataV5, JournalError> {
    validate_original_source_challenge_data_bounds_v5(challenges)
        .map_err(|_| JournalError::LimitExceeded("Source borrowed challenge DATA bounds"))?;
    bound_source_state(before, limits)?;
    bound_origins(origins, limits)?;
    let before_bytes = bounded_snapshot_bytes(before, limits)?;
    let after = match transaction {
        Some(transaction) => {
            crate::journal::validate_transaction(transaction, limits)?;
            prospective_state(before, before_bytes, transaction.records(), limits)?
        }
        None => before.clone(),
    };
    bound_source_state(&after, limits)?;
    let origin_inputs = origins
        .iter()
        .map(SourceOriginalAdmissionDataV5::origin)
        .collect::<Vec<_>>();
    let edge = match transaction {
        Some(_) => Some(
            compare_original_source_capacity_owner_edge_v5(
                owner_views(before),
                owner_views(&after),
                &origin_inputs,
                challenges,
            )
            .map_err(|_| invalid("original Source exact owner edge"))?,
        ),
        None => {
            if !challenges.is_empty() {
                return Err(invalid("original Source recovery cut has extraneous challenge DATA"));
            }
            None
        }
    };

    for origin in origins {
        let original = origin.comparison.original();
        let key = (
            RecordNamespace::SourceProviderAuthority,
            format::acquisition_key(&AcquisitionKeyV1 {
                provider_id: original.provider.authority_id(),
                holder_id: original.holder.authority_id(),
                acquisition_id: original.acquisition_id,
            }),
        );
        if !after.contains_key(&key) {
            return Err(invalid("Source retained admission is foreign to current cut"));
        }
        if !before.contains_key(&key) {
            if edge.as_ref().map(|edge| (edge.acquisition(), edge.kind()))
                != Some((original.acquisition_id, SourceCapacityOwnerEdgeKindV5::Applying))
                || before != origin.original_before()
                || &after != origin.applying_after()
                || transaction != Some(&origin.applying)
            {
                return Err(invalid("Source initial Applying differs from retained actual admission"));
            }
        } else if transaction.is_some_and(|transaction| transaction.id() == origin.applying.id()) {
            return Err(invalid("Source current append repeats original admission identity"));
        }
    }

    require_historical_unions(origins, historical, limits)?;
    let old = associate(before, origins, None, OriginCut::Current, limits)?;
    let next = associate(&after, origins, edge.as_ref(), OriginCut::Current, limits)?;
    let removed_ids = old.ids.difference(&next.ids).copied().collect();
    let inserted_ids = next.ids.difference(&old.ids).copied().collect();

    let independent_headroom = match transaction {
        Some(transaction) => require_exact_transaction(
            before,
            &after,
            transaction,
            edge.as_ref(),
            &old,
            &next,
            limits,
        )?,
        None => false,
    };
    Ok(SourceCapacityUnionComparisonDataV5 {
        before: before.clone(),
        after,
        before_ids: old.ids,
        after_ids: next.ids,
        removed_ids,
        inserted_ids,
        remaining: next.remaining,
        edge,
        actual_source_ids: next
            .source
            .iter()
            .map(|(acquisition, floor)| (*acquisition, floor.reservation_id()))
            .collect(),
        geometries: next.geometries,
        independent_headroom,
    })
}

struct Associated {
    ids: BTreeSet<[u8; 32]>,
    ordinary: BTreeMap<[u8; 32], GlobalCapacityReservationRequestV1>,
    ordinary_owners: BTreeMap<[u8; 32], (SourceOrdinaryCapacityKindV1, ObjectDigest)>,
    source: BTreeMap<ObjectDigest, OriginalSourceCapacityRecordV5>,
    remaining: BTreeMap<ObjectDigest, OriginalSourceCapacityRecordV5>,
    geometries: BTreeMap<ObjectDigest, OriginalSourceGeometryDataV5>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginCut {
    Current,
    RetainedHistorical {
        admission: [u8; 16],
        applying_after: bool,
    },
}

fn require_historical_unions(
    origins: &[SourceOriginalAdmissionDataV5],
    historical: &[SourceHistoricalRetirementReferenceV5],
    limits: JournalLimits,
) -> Result<(), JournalError> {
    for origin in origins {
        for (state, applying_after) in [
            (&origin.original_before, false),
            (&origin.applying_after, true),
        ] {
            // Origin/state bytes were bounded before this loop. The shared
            // Ledger derivation additionally bounds graph bytes times the
            // selected origin count before retaining any continuation graphs.
            // Discard each historical projection before deriving the next one.
            associate_with_historical_references(
                state,
                origins,
                None,
                OriginCut::RetainedHistorical {
                    admission: *origin.applying.id(),
                    applying_after,
                },
                historical,
                limits,
            )?;
        }
    }
    Ok(())
}

fn associate(
    state: &State,
    origins: &[SourceOriginalAdmissionDataV5],
    edge: Option<&SourceCapacityOwnerEdgeDataV5>,
    cut: OriginCut,
    limits: JournalLimits,
) -> Result<Associated, JournalError> {
    associate_with_historical_references(state, origins, edge, cut, &[], limits)
}

fn associate_with_historical_references(
    state: &State,
    origins: &[SourceOriginalAdmissionDataV5],
    edge: Option<&SourceCapacityOwnerEdgeDataV5>,
    cut: OriginCut,
    historical: &[SourceHistoricalRetirementReferenceV5],
    limits: JournalLimits,
) -> Result<Associated, JournalError> {
    let families = canonical_reservations(state)?;
    // Decode the complete inventory first: a recognized foreign family cannot
    // conceal a later malformed row, nor become a Source-scope authorization.
    if families.iter().any(|family| {
        !matches!(
            family,
            CanonicalCapacityFamily::Legacy1(_)
                | CanonicalCapacityFamily::Native3(_)
                | CanonicalCapacityFamily::OriginalSource5(_)
        )
    }) {
        return Err(invalid("Source complete union contains unsupported family"));
    }

    let current = owner_views(state).map(|(key, _)| key).collect::<BTreeSet<_>>();
    let mut inputs = origins
        .iter()
        .filter(|origin| {
            let original = origin.comparison.original();
            let key = format::acquisition_key(&AcquisitionKeyV1 {
                provider_id: original.provider.authority_id(),
                holder_id: original.holder.authority_id(),
                acquisition_id: original.acquisition_id,
            });
            current.contains(key.as_slice())
        })
        .map(SourceOriginalAdmissionDataV5::origin)
        .collect::<Vec<_>>();

    if let OriginCut::RetainedHistorical { admission, applying_after } = cut {
        for input in &mut inputs {
            let origin = origins
                .iter()
                .find(|origin| {
                    origin.comparison.original().acquisition_id
                        == input.comparison.original().acquisition_id
                })
                .ok_or(invalid("Source historical original admission missing"))?;
            let matching = families
                .iter()
                .filter_map(|family| match family {
                    CanonicalCapacityFamily::OriginalSource5(floor)
                        if floor.request().owner_id == origin.initial_floor.request().owner_id =>
                    {
                        Some(floor)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if let [floor] = matching.as_slice() {
                require_origin_floor(origin, floor)?;
                // The exact historical live floor must still pass current
                // origin and full geometry checks below. A later retirement
                // reference cannot turn this earlier live cut into retired DATA.
                input.retirement = None;
            } else {
                let references = historical.iter().filter(|reference| {
                    reference.admission == admission
                        && reference.applying_after == applying_after
                        && reference.acquisition
                            == input.comparison.original().acquisition_id
                }).collect::<Vec<_>>();
                match references.as_slice() {
                    [reference] => input.retirement = Some(reference.retirement.as_ref()),
                    [] if historical.is_empty() => {}
                    [] => input.retirement = None,
                    _ => return Err(invalid("Source ambiguous physical historical retirement")),
                }
            }
        }
    }

    // Only the exact compared final edge can supply retirement DATA for its
    // newly produced after cut. CleanupRequired by itself never qualifies.
    if let Some(edge) = edge
        && let Some(retirement) = edge.retirement()
        && let Some(input) = inputs
            .iter_mut()
            .find(|input| input.comparison.original().acquisition_id == edge.acquisition())
    {
        input.retirement = Some(retirement);
    }
    let owners = derive_source_capacity_owner_data_v1(owner_views(state), &inputs)
        .map_err(|_| invalid("Source complete owner obligations"))?;
    let mut result = Associated {
        ids: BTreeSet::new(),
        ordinary: BTreeMap::new(),
        source: BTreeMap::new(),
        ordinary_owners: BTreeMap::new(),
        remaining: BTreeMap::new(),
        geometries: BTreeMap::new(),
    };

    for binding in owners.ordinary_bindings() {
        let expected = source_native_ordinary_capacity_request_v1(binding);
        let matching = families
            .iter()
            .filter_map(|family| match family {
                CanonicalCapacityFamily::Legacy1((request, _, identifier))
                    if *request == expected =>
                {
                    Some(*identifier)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [identifier] = matching.as_slice() else {
            return Err(invalid("Source ordinary floor missing or ambiguous"));
        };
        insert_id(&mut result.ids, *identifier)?;
        result.ordinary.insert(*identifier, expected);
        result
            .ordinary_owners
            .insert(*identifier, (binding.kind(), binding.acquisition()));
    }

    for (acquisition, continuation) in owners.originals() {
        let origin = origins
            .iter()
            .find(|origin| origin.comparison.original().acquisition_id == *acquisition)
            .ok_or(invalid("Source original origin missing"))?;
        let matching = families
            .iter()
            .filter_map(|family| match family {
                CanonicalCapacityFamily::OriginalSource5(floor)
                    if floor.request().owner_id == origin.initial_floor.request().owner_id =>
                {
                    Some(floor)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let retired = owners.retirement(*acquisition).is_some();
        let no_future = continuation.prefix()
            == OriginalSourceContinuationPrefixV5::PreRequestedCold(
                SourcePreRequestedColdPhaseV1::RootAcknowledged,
            );
        if retired || no_future {
            if !matching.is_empty() {
                return Err(invalid("Source retired own floor still present"));
            }
            // Even no-future cold DATA must match the actual copied initial
            // floor/capsule. Absence never recreates a receipt or custody proof.
            OriginalSourceGeometryDataV5::validate_origin_data(&origin.initial_floor, continuation)?;
            continue;
        }
        let [floor] = matching.as_slice() else {
            return Err(invalid("Source original floor missing or ambiguous"));
        };
        require_origin_floor(origin, floor)?;
        let geometry = OriginalSourceGeometryDataV5::measure_remaining(floor, continuation, limits)?;
        let remaining = geometry
            .remaining_request()
            .ok_or(invalid("Source live own floor has no remaining geometry"))?;
        let remaining = OriginalSourceCapacityRecordV5::new(
            remaining,
            floor.admission_transaction_id(),
            floor.origin_budgets(),
            floor.original_provenance().clone(),
        )?;
        insert_id(&mut result.ids, floor.reservation_id())?;
        result.source.insert(*acquisition, (*floor).clone());
        result.remaining.insert(*acquisition, remaining);
        result.geometries.insert(*acquisition, geometry);
    }

    for (acquisition, profile) in owners.profiles() {
        if owners.is_original(*acquisition) {
            continue;
        }
        let SourceCapacityProfileV1::Held(held) = profile else {
            return Err(invalid("Source cold profile has no original provenance"));
        };
        associate_native3(&owners, *acquisition, held, &families, &mut result.ids)?;
    }

    for (acquisition, _) in owners.retired_originals() {
        let origin = origins
            .iter()
            .find(|origin| origin.comparison.original().acquisition_id == *acquisition)
            .ok_or(invalid("Source retired original admission missing"))?;
        if families.iter().any(|family| {
            matches!(
                family,
                CanonicalCapacityFamily::OriginalSource5(floor)
                    if floor.request().owner_id == origin.initial_floor.request().owner_id
            )
        }) {
            return Err(invalid("Source exact retired lineage retains own floor"));
        }
    }

    let all_ids = families
        .iter()
        .map(|family| match family {
            CanonicalCapacityFamily::Legacy1((_, _, identifier)) => Ok(*identifier),
            CanonicalCapacityFamily::Native3(floor) => Ok(floor.reservation_id()),
            CanonicalCapacityFamily::OriginalSource5(floor) => Ok(floor.reservation_id()),
            _ => Err(invalid("Source complete union contains unsupported family")),
        })
        .collect::<Result<BTreeSet<_>, JournalError>>()?;
    if result.ids != all_ids {
        return Err(invalid("Source complete floor inventory differs from owner obligations"));
    }
    Ok(result)
}

fn associate_native3(
    owners: &SourceCapacityOwnerDataV1,
    acquisition: ObjectDigest,
    held: &SourceNativeHeldCompletionRecordV1,
    families: &[CanonicalCapacityFamily],
    ids: &mut BTreeSet<[u8; 32]>,
) -> Result<(), JournalError> {
    let count = match held.suffix().phase() {
        0 => 19,
        10 => 1,
        _ => return Err(invalid("Source Native3 intermediate remains unsupported")),
    };
    let original = held.original();
    let signed = original
        .canonical_request
        .as_ref()
        .ok_or(invalid("Source Native3 signed request"))?;
    let checkpoint = held
        .suffix()
        .control(NativeHeldControlKindV1::RootPrepared)
        .ok_or(invalid("Source Native3 Root preparation"))?
        .digest();
    let acquisition_row = owners
        .records()
        .find_map(|(key, value)| match format::decode_record(key, value) {
            Ok(DecodedRecordV1::Acquisition(row)) if row.acquisition_id == acquisition => Some(row),
            _ => None,
        })
        .ok_or(invalid("Source Native3 acquisition"))?;
    let owner_digest = original
        .reservation_acquisition_digest
        .ok_or(invalid("Source Native3 original reservation"))?;
    let matching = families.iter().filter_map(|family| {
        let CanonicalCapacityFamily::Native3(floor) = family else {
            return None;
        };
        let request = floor.request();
        (request.purpose == NativeHeldCapacityPurposeV3::Provider
            && Some(request.owner_id) == owners.profile_owner_id(acquisition)
            && request.owner_digest == *owner_digest.as_bytes()
            && request.operation_id == acquisition_row.effect_id
            && request.artifact_digest == *original.native_request_digest.as_bytes()
            && request.checkpoint_digest == *checkpoint.as_bytes()
            && request.chain_head_digest == *signed.request().claims().catalog().digest().as_bytes()
            && request.future_transactions == count)
            .then_some(floor.reservation_id())
    }).collect::<Vec<_>>();
    let [identifier] = matching.as_slice() else {
        return Err(invalid("Source Native3 binding missing or ambiguous"));
    };
    insert_id(ids, *identifier)
}

fn require_origin_floor(
    origin: &SourceOriginalAdmissionDataV5,
    floor: &OriginalSourceCapacityRecordV5,
) -> Result<(), JournalError> {
    let initial = &origin.initial_floor;
    let mut request = floor.request();
    let original = initial.request();
    request.future_transactions = original.future_transactions;
    request.terminal_records = original.terminal_records;
    request.terminal_bytes = original.terminal_bytes;
    request.poison_records = original.poison_records;
    request.poison_bytes = original.poison_bytes;
    if request != original
        || floor.admission_transaction_id() != initial.admission_transaction_id()
        || floor.origin_budgets() != initial.origin_budgets()
        || floor.original_provenance() != initial.original_provenance()
        || floor.origin_reservation_id()? != initial.reservation_id()
    {
        return Err(invalid("Source complete union immutable original binding"));
    }
    Ok(())
}

fn insert_id(ids: &mut BTreeSet<[u8; 32]>, identifier: [u8; 32]) -> Result<(), JournalError> {
    if !ids.insert(identifier) {
        return Err(invalid("Source complete union duplicate obligation"));
    }
    Ok(())
}

fn bound_source_state(state: &State, limits: JournalLimits) -> Result<(), JournalError> {
    bounded_snapshot_bytes(state, limits)?;
    if state.keys().any(|(namespace, _)| {
        !matches!(
            namespace,
            RecordNamespace::SourceProviderAuthority | RecordNamespace::GlobalCapacityReservation
        )
    }) {
        return Err(invalid("Source capacity DATA contains foreign namespace"));
    }
    for ((_, key), value) in state {
        let payload = key
            .len()
            .checked_add(value.len())
            .and_then(|bytes| bytes.checked_add(7))
            .ok_or(JournalError::LimitExceeded("Source retained payload width"))?;
        if key.len() > limits.maximum_key_bytes || payload > limits.maximum_record_bytes {
            return Err(JournalError::LimitExceeded("Source retained payload width"));
        }
    }
    Ok(())
}

fn bound_origins(
    origins: &[SourceOriginalAdmissionDataV5],
    limits: JournalLimits,
) -> Result<(), JournalError> {
    let mut bytes = 0_usize;
    let mut identities = BTreeSet::new();
    for origin in origins {
        if !identities.insert(origin.comparison.original().acquisition_id) {
            return Err(invalid("Source duplicate retained admission"));
        }
        for state in [&origin.original_before, &origin.applying_after] {
            bytes = bytes
                .checked_add(bounded_snapshot_bytes(state, limits)?)
                .ok_or(JournalError::LimitExceeded("Source retained original cuts"))?;
        }
        crate::journal::validate_transaction(&origin.applying, limits)?;
        let append_bytes = crate::journal::encoded_transaction_append_bytes(&origin.applying)?;
        let append_bytes = usize::try_from(append_bytes)
            .map_err(|_| JournalError::LimitExceeded("Source retained original cuts"))?;
        bytes = bytes
            .checked_add(append_bytes)
            .ok_or(JournalError::LimitExceeded("Source retained original cuts"))?;
        if bytes > limits.maximum_materialized_bytes {
            return Err(JournalError::LimitExceeded("Source retained original cuts"));
        }
    }
    Ok(())
}

fn require_exact_transaction(
    before: &State,
    after: &State,
    transaction: &JournalTransaction,
    edge: Option<&SourceCapacityOwnerEdgeDataV5>,
    old: &Associated,
    next: &Associated,
    limits: JournalLimits,
) -> Result<bool, JournalError> {
    let edge = edge.ok_or(invalid("Source transaction has no exact owner edge"))?;
    let owners = transaction
        .records()
        .iter()
        .filter(|row| row.namespace() == RecordNamespace::SourceProviderAuthority)
        .collect::<Vec<_>>();
    if owners.len() != edge.mutations().len()
        || edge.mutations().iter().any(|mutation| {
            !owners.iter().any(|row| {
                row.key() == mutation.key()
                    && row.value() == Some(mutation.after())
                    && before
                        .get(&(row.namespace(), row.key().to_vec()))
                        .map(Vec::as_slice)
                        == mutation.before()
            })
        })
    {
        return Err(invalid("Source full transaction owner mutations changed"));
    }
    let changed = before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    let transaction_keys = transaction
        .records()
        .iter()
        .map(|row| (row.namespace(), row.key().to_vec()))
        .collect::<BTreeSet<_>>();
    if changed != transaction_keys {
        return Err(invalid("Source full transaction contains noop or hidden mutation"));
    }
    require_canonical_order(before, after, transaction, edge)?;

    let acquisition = edge.acquisition();
    let old_source = old.source.get(&acquisition);
    let next_source = next.source.get(&acquisition);
    let source_spend = old_source.is_some()
        && !edge.requires_independent_cut()
        && edge.kind() != SourceCapacityOwnerEdgeKindV5::Applying;
    if source_spend {
        let old_source = old_source.ok_or(invalid("Source exact spend has no current own floor"))?;
        match next_source {
            Some(floor) => {
                if next.remaining.get(&acquisition) != Some(floor)
                    || floor.request().future_transactions
                        >= old_source.request().future_transactions
                {
                    return Err(invalid("Source successor differs from complete remaining geometry"));
                }
            }
            None if edge.newly_retires_original_debt() => {}
            None => return Err(invalid("Source own floor removed without exact final edge")),
        }
    } else if edge.kind() != SourceCapacityOwnerEdgeKindV5::Applying
        && old_source != next_source
    {
        return Err(invalid("Source independent cut spends original own floor"));
    }
    for (identifier, floor) in &old.source {
        if *identifier != acquisition && next.source.get(identifier) != Some(floor) {
            return Err(invalid("Source independent own floor changed"));
        }
    }
    for (identifier, floor) in &next.source {
        if *identifier != acquisition && old.source.get(identifier) != Some(floor) {
            return Err(invalid("Source independent own floor inserted"));
        }
    }

    let removed = old.ids.difference(&next.ids).copied().collect::<BTreeSet<_>>();
    let inserted = next.ids.difference(&old.ids).copied().collect::<BTreeSet<_>>();
    for identifier in &removed {
        if Some(*identifier) == old_source.map(OriginalSourceCapacityRecordV5::reservation_id) {
            continue;
        }
        let request = old
            .ordinary
            .get(identifier)
            .ok_or(invalid("Source transaction removes unrelated floor family"))?;
        let release = matches!(
            edge.kind(),
            SourceCapacityOwnerEdgeKindV5::Lifecycle(
                SourceNativeHeldLifecycleV1::ReleaseStatusCompleted
                    | SourceNativeHeldLifecycleV1::ReleaseCompleted
            )
        );
        if !release
            || old.ordinary_owners.get(identifier)
                != Some(&(SourceOrdinaryCapacityKindV1::NativeReleaseStatus, acquisition))
        {
            return Err(invalid("Source ordinary co-settlement lacks genuine exact Release edge"));
        }
        // Full before/after association proves the actual Reserved obligation
        // disappeared. No labels, caller budget or CleanupRequired can do so.
        if next
            .ordinary
            .values()
            .any(|after| after.owner_id == request.owner_id)
        {
            return Err(invalid("Source ordinary obligation was not retired"));
        }
    }
    for identifier in &inserted {
        if Some(*identifier) == next_source.map(OriginalSourceCapacityRecordV5::reservation_id) {
            continue;
        }
        if !edge.requires_independent_cut() || !next.ordinary.contains_key(identifier) {
            return Err(invalid("Source spend inserts unrelated new floor"));
        }
    }
    for identifier in old.ids.intersection(&next.ids) {
        let key = crate::journal::capacity_reservation::reservation_key_for_validation(*identifier);
        let key = (RecordNamespace::GlobalCapacityReservation, key);
        if before.get(&key) != after.get(&key) {
            return Err(invalid("Source unchanged floor bytes changed"));
        }
    }

    let independently_funded = edge.requires_independent_cut()
        || edge.kind() == SourceCapacityOwnerEdgeKindV5::Applying;
    if independently_funded {
        return Ok(true);
    }

    if source_spend || !removed.is_empty() {
        let old_debt = selected_debt(before, &removed)?;
        let new_debt = selected_debt(after, &inserted)?;
        // Charge the whole framed transaction exactly once, including every
        // actual ordinary DELETE (154 bytes/one record for its real 75-byte key).
        let conservation = check_bounded_transfer(
            transaction,
            (old_debt.0, old_debt.1),
            Some((new_debt.0, new_debt.1)),
            limits,
            ("Source aggregate consumed records", "Source aggregate transferred debt"),
        );
        if !source_spend
            && matches!(
                &conservation,
                Err(JournalError::LimitExceeded("Source aggregate transferred debt"))
            )
        {
            // A genuine later Release can need more than its descriptor-free
            // status floor. The deficit requires separately held free headroom;
            // it does not relax the old promise or claim debt-funded sufficiency.
            return Ok(true);
        }
        conservation?;
        if new_debt.2.checked_add(1).is_none_or(|count| count > old_debt.2) {
            return Err(JournalError::LimitExceeded("Source aggregate future transactions"));
        }
        return Ok(false);
    }

    // Compaction or receipt-only recovery after own debt retired has no
    // transferable promise. Its full TX requires independent current headroom.
    Ok(true)
}

fn require_canonical_order(
    before: &State,
    after: &State,
    transaction: &JournalTransaction,
    edge: &SourceCapacityOwnerEdgeDataV5,
) -> Result<(), JournalError> {
    let mut expected = edge
        .mutations()
        .iter()
        .map(|mutation| {
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                mutation.key().to_vec(),
                mutation.after().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    let old_floors = before
        .iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::GlobalCapacityReservation);
    for (key, value) in old_floors {
        if after.get(key) != Some(value) {
            expected.push(JournalRecord::delete(key.0, key.1.clone()));
        }
    }
    let new_floors = after
        .iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::GlobalCapacityReservation);
    for (key, value) in new_floors {
        if before.get(key) != Some(value) {
            expected.push(JournalRecord::put(key.0, key.1.clone(), value.clone()));
        }
    }
    if transaction.records() != expected {
        return Err(invalid("Source full ordered transaction differs from canonical owner/floor proposal"));
    }

    if edge.kind()
        == SourceCapacityOwnerEdgeKindV5::PreRequestedCold(
            SourcePreRequestedColdPhaseV1::ClosedPrepared,
        )
    {
        let key = native_completion_key_v2(edge.acquisition());
        let bytes = after
            .get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(invalid("Source cold first carrier absent"))?;
        let archive = SourcePreRequestedColdArchiveV1::from_canonical_bytes(&key, bytes)
            .map_err(|_| invalid("Source cold first carrier"))?;
        if archive.prepared().claims().first_cold_transaction != *transaction.id() {
            return Err(invalid("Source cold first transaction identity differs"));
        }
    }
    let floor_rows = transaction
        .records()
        .iter()
        .filter(|row| row.namespace() == RecordNamespace::GlobalCapacityReservation);
    for row in floor_rows {
        let Some(value) = row.value() else {
            continue;
        };
        if let CanonicalCapacityFamily::Legacy1((_, admission, _)) = CanonicalCapacityFamily::decode(row.key(), value)?
            && admission != *transaction.id()
        {
            return Err(invalid("Source new ordinary admission transaction differs"));
        }
    }
    Ok(())
}

fn selected_debt(
    state: &State,
    selected: &BTreeSet<[u8; 32]>,
) -> Result<(u32, u64, u32), JournalError> {
    let debts = accounting_reservations(state)?;
    selected.iter().try_fold(
        (0_u32, 0_u64, 0_u32),
        |(records, bytes, transactions), identifier| {
            let debt = debts
                .get(identifier)
                .ok_or(invalid("Source selected debt missing"))?;
            let added_records = u32::try_from(debt.maximum_records)
                .map_err(|_| JournalError::LimitExceeded("Source aggregate records"))?;
            let added_transactions = u32::try_from(debt.maximum_transactions)
                .map_err(|_| JournalError::LimitExceeded("Source aggregate transactions"))?;

            Ok((
                records
                    .checked_add(added_records)
                    .ok_or(JournalError::LimitExceeded("Source aggregate records"))?,
                bytes
                    .checked_add(debt.maximum_bytes)
                    .ok_or(JournalError::LimitExceeded("Source aggregate bytes"))?,
                transactions
                    .checked_add(added_transactions)
                    .ok_or(JournalError::LimitExceeded("Source aggregate transactions"))?,
            ))
        },
    )
}

#[cfg(test)]
mod tests;

/// Preserves the existing Source proofless Acquire terminal byte policy.
///
/// This is a request-policy value, not a new Journal limit or a funded grant.
pub const SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1: usize = 3 * 1024 * 1024;

/// Preserves the existing dispatch six-owner-row and floor-deletion record budget.
pub const SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1: u32 = 7;

/// Preserves the existing dispatch owner/deletion/framing byte policy.
///
/// This includes mandatory body-7 clock bytes and is not a funded promise.
pub const SOURCE_NATIVE_DISPATCH_TERMINAL_BYTES_V1: u64 =
    aos_sandbox_source_provider_ledger::ledger::format::MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2
        as u64
        + 7 + 72
        + 72 * (SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1 as u64 + 2) + 40;

/// Maps a derived ordinary binding to the unchanged Source legacy request DATA.
///
/// Complete floor association still requires the full canonical owner graph.
/// Neither this request nor its copied binding fields authorizes settlement.
#[must_use]
pub fn source_native_ordinary_capacity_request_v1(
    binding: &SourceOrdinaryCapacityBindingV1,
) -> GlobalCapacityReservationRequestV1 {
    let budget = match binding.kind() {
        SourceOrdinaryCapacityKindV1::NoDispatchAcquire => {
            (5, SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1 as u64)
        }
        SourceOrdinaryCapacityKindV1::LegacyDispatchAcquire => (
            SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1,
            SOURCE_NATIVE_DISPATCH_TERMINAL_BYTES_V1,
        ),
        SourceOrdinaryCapacityKindV1::NativeReleaseStatus => (
            NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1,
            NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1,
        ),
    };
    ordinary_request(binding.fields(), budget)
}

/// Maps existing exact native Release binding DATA to the unchanged legacy policy.
///
/// This stabilizes the legacy Source request path without introducing a public
/// constructor for the new derived complete-obligation result.
#[must_use]
pub fn source_native_release_status_capacity_request_v1(
    binding: NativeReleaseStatusCapacityBindingV1,
) -> GlobalCapacityReservationRequestV1 {
    ordinary_request(
        SourceCapacityBindingFieldsV1 {
            owner_id: binding.owner_id,
            owner_digest: binding.owner_digest,
            operation_id: binding.operation_id,
            artifact_digest: binding.artifact_digest,
            checkpoint_digest: binding.checkpoint_digest,
            chain_head_digest: binding.chain_head_digest,
        },
        (
            NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1,
            NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1,
        ),
    )
}

fn ordinary_request(
    fields: SourceCapacityBindingFieldsV1,
    (records, bytes): (u32, u64),
) -> GlobalCapacityReservationRequestV1 {
    GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        owner_namespace: RecordNamespace::SourceProviderAuthority,
        owner_id: fields.owner_id,
        owner_digest: *fields.owner_digest.as_bytes(),
        operation_id: fields.operation_id,
        artifact_digest: *fields.artifact_digest.as_bytes(),
        checkpoint_digest: *fields.checkpoint_digest.as_bytes(),
        chain_head_digest: *fields.chain_head_digest.as_bytes(),
        future_transactions: 1,
        terminal_records: records,
        terminal_bytes: bytes,
        poison_records: records,
        poison_bytes: bytes,
    }
}
