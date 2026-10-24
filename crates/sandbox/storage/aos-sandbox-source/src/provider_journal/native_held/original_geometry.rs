//! Keeps actual opened Source headroom and advisory crossings with the writer.
//!
//! Canonical geometry and saved continuation measurements belong to Source.
//! These two actual Journal methods retain their original native observations.

use std::collections::BTreeMap;
use aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservations;
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    OriginalSourceCapacityRecordV5,
};
use aos_sandbox_source_provider_ledger::ledger::native_completion::{
    OriginalSourceOwnerTransactionV5, SourcePreRequestedColdPhaseV1 as ColdPhase,
    propose_original_source_applying_v5,
};
use aos_sandbox_source_provider_ledger::ledger::native_held_completion::{
    OriginalSourceContinuationDataV5, OriginalSourceContinuationPrefixV5,
};
use aos_sandbox_ledger_replay::replay::native_held::profile::original_source::*;
use super::{NativeHeldCapacityUsageV3, add};
use super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction,
    RecordNamespace, encoded_transaction_append_bytes, validate_transaction,
};
use super::invalid;
use crate::provider_journal::{Journal, projected_materialized_record_count, validate_materialized_change};

pub(in crate::provider_journal) fn derive_original_source_geometry_v5(
    journal: &Journal,
    typed_own_source: &OriginalSourceCapacityRecordV5,
    continuation: &OriginalSourceContinuationDataV5,
    tentative_applying: Option<&OriginalSourceOwnerTransactionV5>,
) -> Result<OriginalSourceGeometryDataV5, JournalError> {
    // Validate all floor families before selecting the transferred own debt.
    let all_debts = accounting_reservations(journal.native_view().state())?;
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
    let retained_floor = journal.native_view().state().get(&floor_key);
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

    let mut owners = journal.native_view().state()
        .iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
        .map(|((_, key), value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut usage = NativeHeldCapacityUsageV3 {
        journal_bytes: journal.native_view().metadata()?.len(),
        transactions: journal.native_view().committed_transactions() as u64,
        materialized_bytes: journal.native_view().materialized_bytes() as u64,
        materialized_records: journal.native_view().state().len() as u64,
        ..NativeHeldCapacityUsageV3::default()
    };
    let mut sequence = journal.native_view().next_sequence();
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
        if journal.native_view().transaction_ids().contains(admission.id()) {
            return Err(invalid("original Source tentative admission transaction reused"));
        }
        validate_transaction(&admission, journal.native_view().limits())?;
        let entries = projected_materialized_record_count(journal.native_view().state(), admission.records())?;
        let materialized = validate_materialized_change(
            journal.native_view().state(),
            journal.native_view().materialized_bytes(),
            admission.records(),
            journal.native_view().limits(),
        )?;
        admission_growth = CoupledPrefix {
            bytes: materialized as i128 - journal.native_view().materialized_bytes() as i128,
            records: entries as i64 - journal.native_view().state().len() as i64,
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
        journal.native_view().limits(),
        !cold_retired,
    )?;
    let mut staged_peak_bytes = positive_bytes(admission_growth.bytes)?;
    let mut staged_peak_records = positive_records(admission_growth.records)?;
    for measured in &result.alternatives {
        measured.owner.require_headroom(journal.native_view().limits(), usage)?;
        require_coupled_headroom(journal.native_view().limits(), usage, measured)?;
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

pub(in crate::provider_journal) fn check_original_source_candidate_spend_v5(
    journal: &Journal,
    transaction: &JournalTransaction,
    origins: &[crate::provider_journal::SourceOriginalAdmissionDataV5],
    challenges: &[aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceChallengeDataV5<'_>],
) -> Result<crate::provider_journal::SourceCapacityUnionComparisonDataV5, JournalError> {
    journal.compare_source_capacity_advisory_v5(Some(transaction), origins, challenges)
}
