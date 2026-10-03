//! Private original Source own-floor measurement and actual Journal headroom DATA.
//!
//! Ledger owns branch eligibility. This adapter measures every derived branch
//! through the existing engine with the actual immutable Source5 value width.
//! The Source union adapter reuses this fold for complete ordinary association
//! and transaction DATA. Original admission membership, challenge debt, physical
//! funding and live custody remain independent unresolved obligations. There is
//! no conversion from these measurements to a writer, receipt or live owner.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_ledger::ledger::{
    native_completion::{
        OriginalSourceOwnerTransactionV5, SourcePreRequestedColdPhaseV1 as ColdPhase,
        propose_original_source_applying_v5,
    },
    native_held_completion::{
        OriginalSourceBeforeDependencyV5, OriginalSourceContinuationAlternativeV5,
        OriginalSourceContinuationDataV5, OriginalSourceContinuationKindV5,
        OriginalSourceContinuationPrefixV5, SourceNativeHeldStepV1 as SourceStep,
    },
};

use super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, MeasuredAppends,
    MeasurementAppend, NativeHeldCapacityAppendV2, NativeHeldCapacityChangeV3,
    NativeHeldCapacityGeometryV3, NativeHeldCapacityPurposeV3, NativeHeldCapacityStepV3,
    NativeHeldCapacityUsageV3, RecordNamespace, add, encoded_transaction_append_bytes,
    measure_appends_with_prefixes, validate_transaction,
};
use super::super::{
    NativeHeldCapacityRequestV3, OriginalSourceCapacityBudgetsV5,
    OriginalSourceCapacityRecordV5, ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5,
    invalid,
};
#[cfg(test)]
use super::super::check_transfer;
use crate::journal::{
    Journal, capacity_reservation::family::accounting_reservations,
    projected_materialized_record_count, validate_materialized_change,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CoupledPrefix {
    bytes: i128,
    records: i64,
}

type OwnerView<'a> = BTreeMap<&'a [u8], &'a [u8]>;

/// Borrows one measured branch without providing a physical funding token.
pub(in crate::journal) struct OriginalSourceMeasuredAlternativeV5 {
    owner: NativeHeldCapacityGeometryV3,
    coupled: Vec<CoupledPrefix>,
    maximum_coupled_growth_bytes: u64,
    maximum_coupled_growth_records: u64,
    maximum_key_bytes: usize,
    maximum_record_payload_bytes: usize,
    frames: u64,
    poison: bool,
    independent_cut_required: bool,
    original_custody_required: bool,
}

/// Keeps bounded geometry and its incomplete physical-funding obligations private.
pub(in crate::journal) struct OriginalSourceGeometryDataV5 {
    alternatives: Vec<OriginalSourceMeasuredAlternativeV5>,
    normal: NativeHeldCapacityGeometryV3,
    poison: NativeHeldCapacityGeometryV3,
    remaining: Option<NativeHeldCapacityRequestV3>,
    staged_peak_bytes: u64,
    staged_peak_records: u64,
    other_frames: u64,
    ordinary_association_required: bool,
    original_membership_required: bool,
}

impl OriginalSourceGeometryDataV5 {
    /// Derives initial envelope DATA without inventing a provisionally funded floor.
    ///
    /// The canonical floor's fixed portion and reservation-key codec determine
    /// its width. The actual retained provenance supplies the variable portion.
    /// All physical admission and opened headroom checks remain with the writer.
    pub(in crate::journal) fn measure_initial_envelopes(
        continuation: &OriginalSourceContinuationDataV5,
        limits: JournalLimits,
    ) -> Result<OriginalSourceCapacityBudgetsV5, JournalError> {
        if continuation.prefix() != OriginalSourceContinuationPrefixV5::Applying
            || continuation.original().is_none()
        {
            return Err(invalid("original Source initial measurement requires Applying"));
        }
        let fixed_width = ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5
            - aos_sandbox_source_provider_ledger::ledger::native_completion::
                MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5;
        let floor_width = fixed_width
            .checked_add(continuation.provenance().to_canonical_bytes().len())
            .ok_or(JournalError::JournalTooLarge)?;
        let key_width = super::super::super::reservation_key([0; 32]).len();
        let owners = continuation.current_records().collect::<OwnerView<'_>>();
        let measured = measure_envelopes(
            continuation, &owners, limits, key_width, floor_width, true,
        )?;
        if measured.normal.transactions.max(measured.poison.transactions) != 20 {
            return Err(invalid("original Source initial continuation count"));
        }

        Ok(OriginalSourceCapacityBudgetsV5 {
            terminal_records: measured.normal.records,
            terminal_bytes: measured.normal.append_bytes,
            poison_records: measured.poison.records,
            poison_bytes: measured.poison.append_bytes,
        })
    }

    /// Measures every reducer-derived branch without Journal usage or authority.
    ///
    /// # Errors
    ///
    /// Rejects changed origin/bindings/capsules, incomplete geometry, insufficient
    /// supplied debt, codec/measurement limits or bounded arithmetic exhaustion.
    pub(in crate::journal) fn measure_remaining(
        floor: &OriginalSourceCapacityRecordV5,
        continuation: &OriginalSourceContinuationDataV5,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        let owners = continuation.current_records().collect::<OwnerView<'_>>();
        let floor_present = !continuation
            .alternatives()
            .iter()
            .all(|alternative| alternative.edges().is_empty());
        measure_remaining(floor, continuation, &owners, limits, floor_present)
    }

    /// Checks immutable original/cold capsule DATA without measuring retired debt.
    ///
    /// # Errors
    ///
    /// Rejects changed provenance, immutable bindings or copied initial floor.
    pub(in crate::journal) fn validate_origin_data(
        floor: &OriginalSourceCapacityRecordV5,
        continuation: &OriginalSourceContinuationDataV5,
    ) -> Result<(), JournalError> {
        if floor.original_provenance() != continuation.provenance() {
            return Err(invalid("original Source geometry provenance changed"));
        }
        validate_original_bindings(floor, continuation)?;
        validate_cold_capsule(floor, continuation)
    }

    /// Checks measured complete branches against actual usage and sequence DATA.
    ///
    /// # Errors
    ///
    /// Rejects any opened ceiling, coupled retained peak or sequence exhaustion.
    pub(in crate::journal) fn require_usage_headroom(
        &self,
        limits: JournalLimits,
        usage: NativeHeldCapacityUsageV3,
        next_sequence: u64,
        other_frames: u64,
    ) -> Result<(), JournalError> {
        for alternative in &self.alternatives {
            alternative.owner.require_headroom(limits, usage)?;
            require_coupled_headroom(limits, usage, alternative)?;
            require_sequence_headroom(next_sequence, alternative.frames, other_frames)?;
        }
        Ok(())
    }

    /// Borrows every measured branch, including the independently funded ones.
    pub(in crate::journal) fn alternatives(&self) -> &[OriginalSourceMeasuredAlternativeV5] {
        &self.alternatives
    }

    /// Returns computed own debt DATA, or no future debt for a retired cold prefix.
    pub(in crate::journal) const fn remaining_request(&self) -> Option<NativeHeldCapacityRequestV3> {
        self.remaining
    }

    /// Returns separate componentwise normal and poison accounting envelopes.
    pub(in crate::journal) const fn envelopes(
        &self,
    ) -> (NativeHeldCapacityGeometryV3, NativeHeldCapacityGeometryV3) {
        (self.normal, self.poison)
    }

    /// Returns retained byte/entry growth including a tentative exact admission.
    pub(in crate::journal) const fn staged_coupled_peak(&self) -> (u64, u64) {
        (self.staged_peak_bytes, self.staged_peak_records)
    }

    /// Reports unresolved complete ordinary-floor association and co-settlement.
    pub(in crate::journal) const fn ordinary_association_required(&self) -> bool {
        self.ordinary_association_required
    }

    /// Reports unresolved original physical admission membership, not a receipt.
    pub(in crate::journal) const fn original_membership_required(&self) -> bool {
        self.original_membership_required
    }

    /// Returns complete other-floor record/begin/commit frame debt counted once.
    pub(in crate::journal) const fn other_sequence_frames(&self) -> u64 {
        self.other_frames
    }
}

impl OriginalSourceMeasuredAlternativeV5 {
    /// Returns the unchanged owner-only geometry from the common accumulator.
    pub(in crate::journal) const fn owner_geometry(&self) -> NativeHeldCapacityGeometryV3 {
        self.owner
    }

    /// Returns actual owner-plus-floor retained byte and entry growth.
    pub(in crate::journal) const fn coupled_peak(&self) -> (u64, u64) {
        (self.maximum_coupled_growth_bytes, self.maximum_coupled_growth_records)
    }

    /// Borrows ordered signed retained deltas including final floor deletion.
    pub(in crate::journal) fn coupled_prefixes(&self) -> impl Iterator<Item = (i128, i64)> + '_ {
        self.coupled
            .iter()
            .map(|prefix| (prefix.bytes, prefix.records))
    }

    /// Returns the widest key and actual framed record payload on this branch.
    pub(in crate::journal) const fn maximum_payload_widths(&self) -> (usize, usize) {
        (self.maximum_key_bytes, self.maximum_record_payload_bytes)
    }

    /// Returns remaining record frames plus two frames per transaction.
    pub(in crate::journal) const fn sequence_frames(&self) -> u64 {
        self.frames
    }

    /// Reports separately funded admission/current-cut prerequisites.
    pub(in crate::journal) const fn requires_independent_cut(&self) -> bool {
        self.independent_cut_required
    }

    /// Reports live original custody closure that this DATA cannot prove.
    pub(in crate::journal) const fn requires_original_custody(&self) -> bool {
        self.original_custody_required
    }
}

enum SourceMeasurementAppend {
    Provider(NativeHeldCapacityAppendV2<'static>),
    Original {
        transaction_id: [u8; 16],
        changes: Vec<NativeHeldCapacityChangeV3>,
        final_append: bool,
    },
}

impl SourceMeasurementAppend {
    fn measurement(&self) -> MeasurementAppend<'_> {
        match self {
            Self::Provider(append) => append.measurement(),
            Self::Original {
                transaction_id,
                changes,
                final_append,
            } => MeasurementAppend {
                transaction_id: *transaction_id,
                changes,
                final_append: *final_append,
            },
        }
    }
}

/// Measures the complete Ledger projection against the actual locked Journal.
///
/// Inputs are canonical DATA, not authority. A tentative Applying proposal is
/// rederived against every actual Source owner row before its exact five-record
/// admission occupancy is staged. Existing own floors must be byte exact in the
/// actual state. Historical cold capsules cannot recreate an admission receipt.
///
/// # Errors
///
/// Rejects a stale owner cut, malformed floor of any family, foreign Source
/// origin/binding, insufficient own debt, any opened ceiling or format sequence
/// exhaustion. The result explicitly excludes ordinary co-settlement funding.
pub(in crate::journal) fn derive_original_source_geometry_v5(
    journal: &Journal,
    typed_own_source: &OriginalSourceCapacityRecordV5,
    continuation: &OriginalSourceContinuationDataV5,
    tentative_applying: Option<&OriginalSourceOwnerTransactionV5>,
) -> Result<OriginalSourceGeometryDataV5, JournalError> {
    // Validate all floor families before selecting the transferred own debt.
    let all_debts = accounting_reservations(&journal.state)?;
    let floor = typed_own_source.to_journal_record()?;
    if typed_own_source.original_provenance() != continuation.provenance() {
        return Err(invalid("original Source geometry provenance changed"));
    }
    validate_original_bindings(typed_own_source, continuation)?;
    validate_cold_capsule(typed_own_source, continuation)?;

    let floor_key = (
        RecordNamespace::GlobalCapacityReservation,
        floor.key().to_vec(),
    );
    let retained_floor = journal.state.get(&floor_key);
    let cold_retired = continuation.prefix()
        == OriginalSourceContinuationPrefixV5::PreRequestedCold(ColdPhase::RootAcknowledged)
        || continuation
            .alternatives()
            .iter()
            .all(|alternative| alternative.edges().is_empty());
    let existing = retained_floor.is_some();
    if existing && retained_floor.map(Vec::as_slice) != floor.value() {
        return Err(invalid("original Source geometry current floor before"));
    }
    if (existing && tentative_applying.is_some())
        || (!existing && !cold_retired && tentative_applying.is_none())
        || (cold_retired && (existing || tentative_applying.is_some()))
    {
        return Err(invalid("original Source geometry floor/admission presence"));
    }

    let mut owners = journal
        .state
        .iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
        .map(|((_, key), value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut usage = NativeHeldCapacityUsageV3 {
        journal_bytes: journal.file.metadata()?.len(),
        transactions: journal.committed_transactions as u64,
        materialized_bytes: journal.materialized_bytes as u64,
        materialized_records: journal.state.len() as u64,
        ..NativeHeldCapacityUsageV3::default()
    };
    let mut sequence = journal.next_sequence;
    let mut admission_growth = CoupledPrefix::default();

    if let Some(proposal) = tentative_applying {
        if continuation.prefix() != OriginalSourceContinuationPrefixV5::Applying {
            return Err(invalid("original Source tentative admission prefix"));
        }
        let exact = propose_original_source_applying_v5(
            owners
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            proposal
                .mutations()
                .iter()
                .map(|mutation| (mutation.key(), Some(mutation.after()))),
            continuation.provenance(),
            continuation.provenance().claims().configuration,
        )
        .map_err(|_| invalid("original Source tentative exact Applying proposal"))?;
        if &exact != proposal {
            return Err(invalid("original Source tentative Applying comparison"));
        }
        let mut records = exact
            .mutations()
            .iter()
            .map(|mutation| {
                owners.insert(mutation.key().to_vec(), mutation.after().to_vec());
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    mutation.key().to_vec(),
                    mutation.after().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        records.push(floor.clone());
        let admission =
            JournalTransaction::new(typed_own_source.admission_transaction_id(), records)?;
        if journal.transaction_ids.contains(admission.id()) {
            return Err(invalid("original Source tentative admission transaction reused"));
        }
        validate_transaction(&admission, journal.limits)?;
        let entries = projected_materialized_record_count(&journal.state, admission.records())?;
        let materialized = validate_materialized_change(
            &journal.state,
            journal.materialized_bytes,
            admission.records(),
            journal.limits,
        )?;
        admission_growth = CoupledPrefix {
            bytes: materialized as i128 - journal.materialized_bytes as i128,
            records: entries as i64 - journal.state.len() as i64,
        };
        usage.journal_bytes = add(
            usage.journal_bytes,
            encoded_transaction_append_bytes(&admission)?,
        )?;
        usage.transactions = add(usage.transactions, 1)?;
        usage.materialized_bytes = materialized as u64;
        usage.materialized_records = entries as u64;
        sequence = sequence
            .checked_add(transaction_frames(admission.records().len() as u64, 1)?)
            .ok_or(JournalError::SequenceExhausted)?;
    }
    if owners.len() != continuation.current_records().count()
        || continuation
            .current_records()
            .any(|(key, value)| owners.get(key).map(Vec::as_slice) != Some(value))
    {
        return Err(invalid("original Source geometry complete owner cut changed"));
    }

    let mut other_frames = 0_u64;
    for debt in all_debts.values() {
        if existing && debt.reservation_id == typed_own_source.reservation_id() {
            continue;
        }
        usage.reserved_bytes = add(usage.reserved_bytes, debt.maximum_bytes)?;
        usage.reserved_records = add(usage.reserved_records, debt.maximum_records as u64)?;
        usage.reserved_transactions = add(
            usage.reserved_transactions,
            debt.maximum_transactions as u64,
        )?;
        other_frames = add(
            other_frames,
            transaction_frames(
                debt.maximum_records as u64,
                debt.maximum_transactions as u64,
            )?,
        )?;
    }

    let owner_view = owners
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect::<OwnerView<'_>>();
    let mut result = measure_remaining(
        typed_own_source,
        continuation,
        &owner_view,
        journal.limits,
        !cold_retired,
    )?;
    let mut staged_peak_bytes = positive_bytes(admission_growth.bytes)?;
    let mut staged_peak_records = positive_records(admission_growth.records)?;
    for measured in &result.alternatives {
        measured.owner.require_headroom(journal.limits, usage)?;
        require_coupled_headroom(journal.limits, usage, measured)?;
        require_sequence_headroom(sequence, measured.frames, other_frames)?;
        staged_peak_bytes = staged_peak_bytes.max(positive_bytes(
            admission_growth.bytes + i128::from(measured.maximum_coupled_growth_bytes),
        )?);
        staged_peak_records = staged_peak_records.max(positive_records(
            admission_growth.records + measured.maximum_coupled_growth_records as i64,
        )?);
    }
    result.staged_peak_bytes = staged_peak_bytes;
    result.staged_peak_records = staged_peak_records;
    result.other_frames = other_frames;
    Ok(result)
}

fn measure_remaining(
    typed_own_source: &OriginalSourceCapacityRecordV5,
    continuation: &OriginalSourceContinuationDataV5,
    owners: &OwnerView<'_>,
    limits: JournalLimits,
    floor_present: bool,
) -> Result<OriginalSourceGeometryDataV5, JournalError> {
    if typed_own_source.original_provenance() != continuation.provenance() {
        return Err(invalid("original Source geometry provenance changed"));
    }
    validate_original_bindings(typed_own_source, continuation)?;
    validate_cold_capsule(typed_own_source, continuation)?;
    let floor = typed_own_source.to_journal_record()?;
    let floor_width = floor.value().ok_or(JournalError::InvalidTransaction)?.len();
    let mut result = measure_envelopes(
        continuation, owners, limits, floor.key().len(), floor_width, floor_present,
    )?;
    let normal = result.normal;
    let poison = result.poison;
    let transactions = normal.transactions.max(poison.transactions);
    result.remaining = if transactions == 0 {
        None
    } else {
        let mut request = typed_own_source.request();
        request.future_transactions = transactions;
        request.terminal_records = normal.records;
        request.terminal_bytes = normal.append_bytes;
        request.poison_records = poison.records;
        request.poison_bytes = poison.append_bytes;
        require_own_debt(typed_own_source.request(), request)?;
        // The same constructor retains immutable origin, admission and bindings.
        OriginalSourceCapacityRecordV5::new(
            request,
            typed_own_source.admission_transaction_id(),
            typed_own_source.origin_budgets(),
            typed_own_source.original_provenance().clone(),
        )?;
        if continuation.prefix() == OriginalSourceContinuationPrefixV5::Applying
            && typed_own_source.request() != request
        {
            return Err(invalid("original Source initial envelope differs from complete geometry"));
        }
        Some(request)
    };
    Ok(result)
}

fn measure_envelopes(
    continuation: &OriginalSourceContinuationDataV5,
    owners: &OwnerView<'_>,
    limits: JournalLimits,
    floor_key_width: usize,
    floor_width: usize,
    floor_present: bool,
) -> Result<OriginalSourceGeometryDataV5, JournalError> {
    let mut alternatives = Vec::new();
    let mut normal = NativeHeldCapacityGeometryV3::default();
    let mut poison = NativeHeldCapacityGeometryV3::default();
    let mut staged_peak_bytes = 0;
    let mut staged_peak_records = 0;

    for alternative in continuation.alternatives() {
        let appends = materialize_templates(alternative, owners, floor_width)?;
        let measured = measure_appends_with_prefixes(
            NativeHeldCapacityPurposeV3::Provider,
            appends.iter().map(SourceMeasurementAppend::measurement),
            limits,
            floor_width,
        )?;
        let measured = coupled_measurement(
            measured,
            alternative,
            floor_key_width,
            floor_width,
            floor_present,
        )?;
        staged_peak_bytes = staged_peak_bytes.max(positive_bytes(
            i128::from(measured.maximum_coupled_growth_bytes),
        )?);
        staged_peak_records = staged_peak_records.max(positive_records(
            measured.maximum_coupled_growth_records as i64,
        )?);

        if measured.poison {
            fold_envelope(&mut poison, measured.owner);
        } else {
            fold_envelope(&mut normal, measured.owner);
        }
        alternatives.push(measured);
    }
    if normal.transactions == 0 {
        normal = poison;
    }
    if poison.transactions == 0 {
        poison = normal;
    }

    Ok(OriginalSourceGeometryDataV5 {
        alternatives,
        normal,
        poison,
        remaining: None,
        staged_peak_bytes,
        staged_peak_records,
        other_frames: 0,
        ordinary_association_required: true,
        original_membership_required: true,
    })
}

fn validate_original_bindings(
    floor: &OriginalSourceCapacityRecordV5,
    data: &OriginalSourceContinuationDataV5,
) -> Result<(), JournalError> {
    if let Some(original) = data.original() {
        let request = floor.request();
        if request.owner_digest != *original.reservation_acquisition_digest.as_bytes()
            || request.operation_id != original.operation_id
            || request.artifact_digest != *original.attempt_digest.as_bytes()
            || request.checkpoint_digest != *original.root_request_digest.as_bytes()
            || request.chain_head_digest != *original.session_binding.as_bytes()
        {
            return Err(invalid("original Source geometry immutable owner bindings"));
        }
    }
    Ok(())
}

fn validate_cold_capsule(
    floor: &OriginalSourceCapacityRecordV5,
    data: &OriginalSourceContinuationDataV5,
) -> Result<(), JournalError> {
    let Some(archive) = data.cold_archive() else {
        return Ok(());
    };
    let mut original_request = floor.request();
    let origin = floor.origin_budgets();
    original_request.future_transactions = 20;
    original_request.terminal_records = origin.terminal_records;
    original_request.terminal_bytes = origin.terminal_bytes;
    original_request.poison_records = origin.poison_records;
    original_request.poison_bytes = origin.poison_bytes;
    let original = OriginalSourceCapacityRecordV5::new(
        original_request,
        floor.admission_transaction_id(),
        origin,
        floor.original_provenance().clone(),
    )?;
    let record = original.to_journal_record()?;
    let decoded = OriginalSourceCapacityRecordV5::decode(
        record.key(),
        archive.initial_source_floor_bytes(),
    )?;
    if decoded != original || record.value() != Some(archive.initial_source_floor_bytes())
        || archive.prepared().claims().original_source_floor.as_bytes() != &original.reservation_id()
        || archive.prepared().claims().admission_transaction != original.admission_transaction_id()
    {
        return Err(invalid("original Source cold copied initial floor differs"));
    }
    Ok(())
}

fn materialize_templates(
    alternative: &OriginalSourceContinuationAlternativeV5,
    owners: &OwnerView<'_>,
    floor_width: usize,
) -> Result<Vec<SourceMeasurementAppend>, JournalError> {
    let mut states = BTreeMap::<Vec<u8>, (usize, Vec<u8>)>::new();
    let mut appends = Vec::new();
    for (index, edge) in alternative.edges().iter().enumerate() {
        let mut changes = Vec::new();
        for (value_index, value) in edge.values().iter().enumerate() {
            let previous = states.get(value.key());
            let before = match value.before_dependency() {
                OriginalSourceBeforeDependencyV5::ActualGraph => {
                    if previous.is_some() {
                        return Err(invalid("original Source repeated first before dependency"));
                    }
                    owners.get(value.key()).copied().map(<[u8]>::to_vec)
                }
                OriginalSourceBeforeDependencyV5::PreviousOutput(predecessor) => {
                    let (actual, bytes) = previous
                        .ok_or(invalid("original Source forecast predecessor absent"))?;
                    if *actual != predecessor {
                        return Err(invalid("original Source forecast predecessor changed"));
                    }
                    Some(bytes.clone())
                }
                OriginalSourceBeforeDependencyV5::IndependentlyFundedCut => {
                    // No independently admitted row is invented. The baseline
                    // is actual absence/value or this branch's prior output;
                    // concrete funding must reacquire the full current cut.
                    previous
                        .map(|(_, bytes)| bytes.clone())
                        .or_else(|| owners.get(value.key()).copied().map(<[u8]>::to_vec))
                }
            };
            let width = value
                .maximum_value_bytes()
                .checked_add(if value.requires_source_floor_width() {
                    floor_width
                } else {
                    0
                })
                .ok_or(JournalError::JournalTooLarge)?;
            let after = forecast_marker(width, index, value_index)?;
            changes.push(NativeHeldCapacityChangeV3::new(
                value.key().to_vec(),
                before,
                Some(after.clone()),
            )?);
            states.insert(value.key().to_vec(), (index, after));
        }
        let transaction_id = template_transaction_id(index)?;
        let append = match edge.kind() {
            OriginalSourceContinuationKindV5::Held(step) => SourceMeasurementAppend::Provider(
                NativeHeldCapacityAppendV2::provider(
                    capacity_step(step)?,
                    transaction_id,
                    changes,
                )?,
            ),
            OriginalSourceContinuationKindV5::Cleanup(_) => SourceMeasurementAppend::Provider(
                NativeHeldCapacityAppendV2::provider(
                    NativeHeldCapacityStepV3::ProviderLifecycleCleanup,
                    transaction_id,
                    changes,
                )?,
            ),
            OriginalSourceContinuationKindV5::FirstRequested
            | OriginalSourceContinuationKindV5::PreRequestedCold(_) => {
                SourceMeasurementAppend::Original {
                    transaction_id,
                    changes,
                    final_append: edge.is_final(),
                }
            }
        };
        appends.push(append);
    }
    Ok(appends)
}

fn forecast_marker(width: usize, edge: usize, value: usize) -> Result<Vec<u8>, JournalError> {
    if width < 11 {
        return Err(invalid("original Source forecast value bound"));
    }

    let mut bytes = vec![0; width];
    bytes[0] = 0xfc; // Every real canonical owner value starts with AOSSPL01.
    bytes[1..9].copy_from_slice(&(edge as u64).to_be_bytes());
    bytes[9..11].copy_from_slice(
        &u16::try_from(value)
            .map_err(|_| JournalError::InvalidTransaction)?
            .to_be_bytes(),
    );
    Ok(bytes)
}

fn template_transaction_id(index: usize) -> Result<[u8; 16], JournalError> {
    let mut id = [0xfe; 16];
    id[8..].copy_from_slice(
        &u64::try_from(index)
            .map_err(|_| JournalError::InvalidTransaction)?
            .checked_add(1)
            .ok_or(JournalError::InvalidTransaction)?
            .to_be_bytes(),
    );
    Ok(id)
}

fn coupled_prefixes(
    measured: &MeasuredAppends,
    floor_key_width: usize,
    floor_width: usize,
    floor_present: bool,
) -> Result<(Vec<CoupledPrefix>, u64, u64), JournalError> {
    let floor_bytes = add(floor_key_width as u64, floor_width as u64)?;
    let mut coupled = Vec::new();
    let mut maximum_coupled_growth_bytes = 0;
    let mut maximum_coupled_growth_records = 0;
    for prefix in &measured.prefixes {
        let removed = floor_present && prefix.final_append;
        let prefix = CoupledPrefix {
            bytes: prefix.owner_bytes
                - if removed { i128::from(floor_bytes) } else { 0 },
            records: prefix.owner_records - i64::from(removed),
        };
        maximum_coupled_growth_bytes =
            maximum_coupled_growth_bytes.max(positive_bytes(prefix.bytes)?);
        maximum_coupled_growth_records =
            maximum_coupled_growth_records.max(positive_records(prefix.records)?);
        coupled.push(prefix);
    }
    Ok((
        coupled,
        maximum_coupled_growth_bytes,
        maximum_coupled_growth_records,
    ))
}

fn coupled_measurement(
    measured: MeasuredAppends,
    alternative: &OriginalSourceContinuationAlternativeV5,
    floor_key_width: usize,
    floor_width: usize,
    floor_present: bool,
) -> Result<OriginalSourceMeasuredAlternativeV5, JournalError> {
    let (coupled, maximum_coupled_growth_bytes, maximum_coupled_growth_records) =
        coupled_prefixes(&measured, floor_key_width, floor_width, floor_present)?;
    Ok(OriginalSourceMeasuredAlternativeV5 {
        frames: transaction_frames(
            u64::from(measured.geometry.records),
            u64::from(measured.geometry.transactions),
        )?,
        owner: measured.geometry,
        coupled,
        maximum_coupled_growth_bytes,
        maximum_coupled_growth_records,
        maximum_key_bytes: measured.maximum_key_bytes,
        maximum_record_payload_bytes: measured.maximum_record_payload_bytes,
        poison: alternative.is_poison(),
        independent_cut_required: alternative
            .edges()
            .iter()
            .any(|edge| edge.requires_independent_cut()),
        original_custody_required: alternative
            .edges()
            .iter()
            .any(|edge| edge.requires_original_custody_closure()),
    })
}

fn fold_envelope(target: &mut NativeHeldCapacityGeometryV3, geometry: NativeHeldCapacityGeometryV3) {
    target.transactions = target.transactions.max(geometry.transactions);
    target.records = target.records.max(geometry.records);
    target.append_bytes = target.append_bytes.max(geometry.append_bytes);
    target.maximum_transaction_records = target
        .maximum_transaction_records
        .max(geometry.maximum_transaction_records);
    target.maximum_transaction_record_bytes = target
        .maximum_transaction_record_bytes
        .max(geometry.maximum_transaction_record_bytes);
    target.maximum_retained_growth_bytes = target
        .maximum_retained_growth_bytes
        .max(geometry.maximum_retained_growth_bytes);
    target.maximum_retained_growth_records = target
        .maximum_retained_growth_records
        .max(geometry.maximum_retained_growth_records);
}

fn require_own_debt(
    old: NativeHeldCapacityRequestV3,
    next: NativeHeldCapacityRequestV3,
) -> Result<(), JournalError> {
    if next.future_transactions > old.future_transactions
        || next.terminal_records > old.terminal_records
        || next.terminal_bytes > old.terminal_bytes
        || next.poison_records > old.poison_records
        || next.poison_bytes > old.poison_bytes
    {
        return Err(JournalError::LimitExceeded(
            "original Source complete own-floor geometry",
        ));
    }
    Ok(())
}

fn require_coupled_headroom(
    limits: JournalLimits,
    usage: NativeHeldCapacityUsageV3,
    measured: &OriginalSourceMeasuredAlternativeV5,
) -> Result<(), JournalError> {
    if add(
        add(usage.materialized_bytes, usage.reserved_bytes)?,
        measured.maximum_coupled_growth_bytes,
    )? > limits.maximum_materialized_bytes as u64
        || add(
            add(usage.materialized_records, usage.reserved_records)?,
            measured.maximum_coupled_growth_records,
        )? > limits.maximum_materialized_records as u64
    {
        return Err(JournalError::LimitExceeded("original Source coupled retained peak"));
    }
    Ok(())
}

fn transaction_frames(records: u64, transactions: u64) -> Result<u64, JournalError> {
    add(
        records,
        transactions
            .checked_mul(2)
            .ok_or(JournalError::SequenceExhausted)?,
    )
}

fn require_sequence_headroom(
    next_sequence: u64,
    own_frames: u64,
    other_frames: u64,
) -> Result<(), JournalError> {
    next_sequence
        .checked_add(own_frames)
        .and_then(|next| next.checked_add(other_frames))
        .ok_or(JournalError::SequenceExhausted)?;
    Ok(())
}

fn positive_bytes(value: i128) -> Result<u64, JournalError> {
    u64::try_from(value.max(0)).map_err(|_| JournalError::JournalTooLarge)
}

fn positive_records(value: i64) -> Result<u64, JournalError> {
    u64::try_from(value.max(0))
        .map_err(|_| JournalError::LimitExceeded("original Source retained entries"))
}

fn capacity_step(step: SourceStep) -> Result<NativeHeldCapacityStepV3, JournalError> {
    use NativeHeldCapacityStepV3 as Capacity;
    Ok(match step {
        SourceStep::ChallengeIssued => Capacity::ProviderChallengeIssued,
        SourceStep::StoragePrepared => Capacity::ProviderStoragePrepared,
        SourceStep::ChallengeSpent => Capacity::ProviderChallengeSpent,
        SourceStep::CompletionCommitted => Capacity::ProviderSixRowComplete,
        SourceStep::HeldPrepared => Capacity::ProviderHeldPrepared,
        SourceStep::HeldStored => Capacity::ProviderHeldStored,
        SourceStep::RootDispositionPrepared => Capacity::ProviderRootDispositionPrepared,
        SourceStep::RelayStored => Capacity::ProviderRelayStored,
        SourceStep::StorageSettlementRecorded => Capacity::ProviderStorageSettlement,
        SourceStep::ProviderSettledPrepared => Capacity::ProviderSettledPrepared,
        SourceStep::ProviderSettledStored => Capacity::ProviderSettledStored,
        SourceStep::RootRecoveryRecorded => Capacity::ProviderRootRecoveryStored,
        SourceStep::StorageRecoveryPrepared => Capacity::ProviderRecoveryRelayPrepared,
        SourceStep::StorageRecoveryQueryStored => Capacity::ProviderRecoveryRelayStored,
        SourceStep::StorageRecoveryRecorded => Capacity::ProviderStorageRecoveryStored,
        SourceStep::ProviderRecoveryPrepared => Capacity::ProviderRecoveryTerminalPrepared,
        SourceStep::ProviderRecoveryStored => Capacity::ProviderRecoveryTerminalStored,
        SourceStep::RootTerminalRecorded => Capacity::ProviderRootTerminalStored,
        SourceStep::Requested => {
            return Err(invalid("original Source initial Requested uses distinct framing"));
        }
    })
}

/// Delegates actual Source candidate spend to the complete union advisory.
///
/// # Errors
///
/// Rejects any complete owner/floor association, ordered transaction,
/// aggregate conservation or actual opened-headroom/sequence contradiction.
/// The result remains DATA, not a protected reservation or append permission.
pub(in crate::journal) fn check_original_source_candidate_spend_v5(
    journal: &Journal,
    transaction: &JournalTransaction,
    origins: &[crate::journal::SourceOriginalAdmissionDataV5],
    challenges: &[aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceChallengeDataV5<'_>],
) -> Result<crate::journal::SourceCapacityUnionComparisonDataV5, JournalError> {
    journal.compare_source_capacity_advisory_v5(Some(transaction), origins, challenges)
}

#[cfg(test)]
#[path = "original_source/tests.rs"]
mod tests;
