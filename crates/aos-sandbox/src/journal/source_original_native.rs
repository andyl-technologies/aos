//! Original Source canonical comparisons and same-held physical replay bridge.
//!
//! The pure comparison layer remains DATA, with no conversion to live authority.
//! The separately named writer/replay route binds actual fixed ledger and
//! challenge owners, exact complete cut references and current opened headroom.
//! Source still authenticates public archived/current configurations and every
//! original signature. Neither layer lends Ready or an external effect capability.
//! Applying uses the complete before-to-after Ledger reservation proposal.
//!
//! The two coupled shapes are:
//!
//! ```text
//! Applying: Attempt PUT | Acquisition PUT | Holder PUT | History PUT | Source5 PUT
//! Requested: held8 PUT | old Source5 DELETE | successor Source5 PUT
//! ```

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::ledger::native_completion::{
    OriginalSourceOwnerDataV5, OriginalSourceOwnerPrefixV5, OriginalSourceOwnerTransactionV5,
    propose_original_source_applying_v5, propose_original_source_requested_v5,
};

use super::capacity_reservation::family::{CanonicalCapacityFamily, canonical_reservations};
use super::capacity_reservation::native_held::{
    NativeHeldCapacityGeometryV3, NativeHeldCapacityPurposeV3, NativeHeldCapacitySuffixV2,
    OriginalSourceCapacityRecordV5, check_transfer,
};
use super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    validate_materialized_change, validate_transaction,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

mod union;
pub(super) mod challenge;
pub(super) mod replay;
pub(super) mod writer;
pub use challenge::{
    SourceOriginalChallengeCheckpointV5, SourceOriginalChallengeHistoryViewV5,
};
pub use replay::SourceOriginalPhysicalCutV5;
pub use writer::{
    OriginalSourceProtectedReadbackV5, PreparedOriginalSourceAppendV5,
    SourceOriginalAppendSubjectV5,
    SourceOriginalNativeJournalAuthorityV5, SourceOriginalReplayViewV5,
};
pub use union::{
    SOURCE_NATIVE_DISPATCH_TERMINAL_BYTES_V1, SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1,
    SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1,
    SourceCapacityStateV5, SourceOriginalAdmissionInputV5, SourceOriginalAdmissionDataV5,
    SourceCapacityUnionComparisonDataV5, compare_source_original_admission_data_v5,
    compare_source_capacity_union_data_v5,
    source_native_ordinary_capacity_request_v1,
    source_native_release_status_capacity_request_v1,
};

/// Retains exact attempted bytes and complete before/after comparison DATA.
///
/// This owned container deliberately has no authority, clock, nonce, preflight
/// or commit fields. It cannot mint a physical receipt or be submitted through
/// a new production append route.
struct OriginalSourceAppendCandidateV5 {
    transaction: JournalTransaction,
    before: State,
    after: State,
    owner: OriginalSourceOwnerTransactionV5,
    floor: OriginalSourceCapacityRecordV5,
    original: OriginalAdmissionDataV5,
}

enum OriginalAdmissionDataV5 {
    ThisApplyingTransaction,
    Retained {
        transaction: JournalTransaction,
        floor: OriginalSourceCapacityRecordV5,
    },
}

impl OriginalSourceAppendCandidateV5 {
    fn original_transaction(&self) -> &JournalTransaction {
        match &self.original {
            OriginalAdmissionDataV5::ThisApplyingTransaction => &self.transaction,
            OriginalAdmissionDataV5::Retained { transaction, .. } => transaction,
        }
    }

    fn original_floor(&self) -> &OriginalSourceCapacityRecordV5 {
        match &self.original {
            OriginalAdmissionDataV5::ThisApplyingTransaction => &self.floor,
            OriginalAdmissionDataV5::Retained { floor, .. } => floor,
        }
    }
}

/// Compares exactly four owner PUTs and an initial count20 Source5 PUT.
///
/// Budgets remain untrusted DATA. The existing full Applying proposal, not just
/// an after-graph classifier, proves the idle/absent Session reservation join.
/// The caller retains its borrowed transaction across every failed comparison.
fn compare_original_source_applying_transaction_v5(
    before: &State,
    transaction: &JournalTransaction,
    configuration: ObjectDigest,
    limits: JournalLimits,
) -> Result<OriginalSourceAppendCandidateV5, JournalError> {
    let before_bytes = bounded_snapshot_bytes(before, limits)?;
    let families = canonical_reservations(before)?;
    validate_transaction(transaction, limits)?;
    validate_capacity_puts(transaction)?;
    let records = transaction.records();
    if records.len() != 5 {
        return Err(invalid("original Source Applying coupled record count"));
    }

    let floor = OriginalSourceCapacityRecordV5::from_journal_record(&records[4])?;
    if floor.request().future_transactions != 20
        || floor.admission_transaction_id() != *transaction.id()
        || floor.origin_reservation_id()? != floor.reservation_id()
    {
        return Err(invalid("original Source Applying initial floor DATA"));
    }
    if select_source_floor(&families, floor.request().owner_id)?.is_some() {
        return Err(invalid("original Source Applying floor already exists"));
    }

    // The wire order is fixed independently of the reducer's sorted mutations.
    let original_keys = &floor.original_provenance().claims().records;
    for (record, witness) in records[..4].iter().zip(original_keys) {
        if record.namespace() != RecordNamespace::SourceProviderAuthority
            || record.key() != witness.key()
            || record.value().is_none()
        {
            return Err(invalid("original Source Applying explicit owner order"));
        }
    }

    let owner = propose_original_source_applying_v5(
        owner_views(before),
        records[..4].iter().map(|record| (record.key(), record.value())),
        floor.original_provenance(),
        configuration,
    )
    .map_err(|_| invalid("original Source Applying owner proposal"))?;
    require_owner_binding(&floor, owner.data())?;
    require_mutations(&records[..4], &owner)?;

    let after = prospective_state(before, before_bytes, records, limits)?;
    canonical_reservations(&after)?;

    Ok(OriginalSourceAppendCandidateV5 {
        transaction: transaction.clone(),
        before: before.clone(),
        after,
        owner,
        floor,
        original: OriginalAdmissionDataV5::ThisApplyingTransaction,
    })
}

/// Compares exact held8 PUT / old Source5 DELETE / count19 Source5 PUT DATA.
///
/// The retained admission candidate is only a comparison reference. Its exact
/// transaction and inverse initial identity do not prove a physical commit.
/// The input transaction is cloned only after bounded successful comparison.
fn compare_original_source_requested_transaction_v5(
    before: &State,
    transaction: &JournalTransaction,
    admission: &OriginalSourceAppendCandidateV5,
    configuration: ObjectDigest,
    limits: JournalLimits,
) -> Result<OriginalSourceAppendCandidateV5, JournalError> {
    let before_bytes = bounded_snapshot_bytes(before, limits)?;
    let families = canonical_reservations(before)?;
    validate_transaction(transaction, limits)?;
    validate_capacity_puts(transaction)?;
    let records = transaction.records();
    if records.len() != 3
        || admission.owner.data().prefix != OriginalSourceOwnerPrefixV5::Applying
        || before != &admission.after
        || transaction.id() == admission.transaction.id()
    {
        return Err(invalid("original Source Requested before or coupled shape"));
    }

    let old = select_source_floor(&families, admission.floor.request().owner_id)?
        .ok_or(invalid("original Source Requested floor absent"))?;
    let old_record = old.to_journal_record()?;
    let next = OriginalSourceCapacityRecordV5::from_journal_record(&records[2])?;
    if old != &admission.floor
        || old.request().future_transactions != 20
        || next.request().future_transactions != 19
        || records[0].namespace() != RecordNamespace::SourceProviderAuthority
        || records[0].value().is_none()
        || records[1].namespace() != RecordNamespace::GlobalCapacityReservation
        || records[1].key() != old_record.key()
        || records[1].value().is_some()
    {
        return Err(invalid("original Source Requested ordered floor transfer"));
    }
    compare_origin_floor_data(admission, &next)?;

    let owner = propose_original_source_requested_v5(
        owner_views(before),
        std::iter::once((records[0].key(), records[0].value())),
        next.original_provenance(),
        configuration,
    )
    .map_err(|_| invalid("original Source Requested owner proposal"))?;
    require_owner_binding(&next, owner.data())?;
    require_mutations(&records[..1], &owner)?;

    // This arithmetic compares supplied envelopes; it cannot prove that they
    // cover every future owner branch or other ordinary/challenge obligations.
    check_transfer(
        transaction,
        old.request(),
        Some(next.request()),
        limits,
        (
            "original Source consumed records",
            "original Source transferred budget DATA",
        ),
    )?;

    let after = prospective_state(before, before_bytes, records, limits)?;
    canonical_reservations(&after)?;

    Ok(OriginalSourceAppendCandidateV5 {
        transaction: transaction.clone(),
        before: before.clone(),
        after,
        owner,
        floor: next,
        original: OriginalAdmissionDataV5::Retained {
            transaction: admission.original_transaction().clone(),
            floor: admission.original_floor().clone(),
        },
    })
}

/// Compares retained initial TX bytes and immutable inverse-origin floor DATA.
fn compare_origin_floor_data(
    admission: &OriginalSourceAppendCandidateV5,
    current: &OriginalSourceCapacityRecordV5,
) -> Result<(), JournalError> {
    let original = admission.original_floor();
    let mut current_bindings = current.request();
    let original_bindings = original.request();
    current_bindings.future_transactions = original_bindings.future_transactions;
    current_bindings.terminal_records = original_bindings.terminal_records;
    current_bindings.terminal_bytes = original_bindings.terminal_bytes;
    current_bindings.poison_records = original_bindings.poison_records;
    current_bindings.poison_bytes = original_bindings.poison_bytes;

    if original_bindings.future_transactions != 20
        || original.admission_transaction_id() != *admission.original_transaction().id()
        || current.admission_transaction_id() != original.admission_transaction_id()
        || current.origin_budgets() != original.origin_budgets()
        || current.original_provenance() != original.original_provenance()
        || current.origin_reservation_id()? != original.reservation_id()
        || current_bindings != original_bindings
        || current.request().terminal_records > original_bindings.terminal_records
        || current.request().terminal_bytes > original_bindings.terminal_bytes
        || current.request().poison_records > original_bindings.poison_records
        || current.request().poison_bytes > original_bindings.poison_bytes
    {
        return Err(invalid("original Source retained admission comparison DATA"));
    }
    Ok(())
}

/// Compares copied readback DATA against the complete retained candidate.
///
/// Neither matching positions nor supplied transaction bytes establish actual
/// file history, same-instance custody or a current ProtectedJournalSnapshot.
fn compare_readback_data(
    candidate: &OriginalSourceAppendCandidateV5,
    observed_before: &State,
    observed_after: &State,
    observed_transaction: &JournalTransaction,
    before_next_sequence: u64,
    commit_sequence: u64,
    after_next_sequence: u64,
) -> Result<(), JournalError> {
    canonical_reservations(observed_before)?;
    canonical_reservations(observed_after)?;
    if observed_before != &candidate.before
        || observed_after != &candidate.after
        || observed_transaction != &candidate.transaction
    {
        return Err(invalid("original Source exact readback comparison DATA"));
    }
    compare_frame_positions(
        &candidate.transaction,
        before_next_sequence,
        commit_sequence,
        after_next_sequence,
    )
}

/// Compares next-frame cuts with the separately named final commit frame.
fn compare_frame_positions(
    transaction: &JournalTransaction,
    before_next_sequence: u64,
    commit_sequence: u64,
    after_next_sequence: u64,
) -> Result<(), JournalError> {
    let frames = u64::try_from(transaction.records().len())
        .map_err(|_| JournalError::SequenceExhausted)?
        .checked_add(2)
        .ok_or(JournalError::SequenceExhausted)?;
    let expected_after = before_next_sequence
        .checked_add(frames)
        .ok_or(JournalError::SequenceExhausted)?;
    if before_next_sequence == 0
        || after_next_sequence != expected_after
        || commit_sequence.checked_add(1) != Some(expected_after)
    {
        return Err(invalid("original Source commit frame versus next-frame DATA"));
    }
    Ok(())
}

/// Measures a supplied suffix using the actual canonical Source5 width.
///
/// This remains syntactic suffix DATA and owner-only retained growth. It is not
/// the missing all-prefix producer, full floor-coupled peak or funding proof.
fn measure_source_suffix_data(
    floor: &OriginalSourceCapacityRecordV5,
    suffix: &NativeHeldCapacitySuffixV2<'_>,
    limits: JournalLimits,
) -> Result<NativeHeldCapacityGeometryV3, JournalError> {
    if suffix.purpose() != NativeHeldCapacityPurposeV3::Provider {
        return Err(invalid("original Source suffix DATA owner"));
    }
    let encoded = floor.to_journal_record()?;
    let width = encoded.value().ok_or(JournalError::InvalidTransaction)?.len();
    suffix.measure_with_floor_value_bytes(limits, width)
}

fn select_source_floor(
    families: &[CanonicalCapacityFamily],
    owner_id: [u8; 32],
) -> Result<Option<&OriginalSourceCapacityRecordV5>, JournalError> {
    let mut selected = None;
    for family in families {
        let CanonicalCapacityFamily::OriginalSource5(floor) = family else {
            continue;
        };
        if floor.request().owner_id != owner_id {
            continue;
        }
        if selected.replace(floor).is_some() {
            return Err(invalid("duplicate original Source owner floor DATA"));
        }
    }
    Ok(selected)
}

// Touched PUTs join the complete before inventory before own-floor selection.
fn validate_capacity_puts(transaction: &JournalTransaction) -> Result<(), JournalError> {
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        if let Some(value) = record.value() {
            CanonicalCapacityFamily::decode(record.key(), value)?;
        }
    }
    Ok(())
}

fn require_owner_binding(
    floor: &OriginalSourceCapacityRecordV5,
    owner: &OriginalSourceOwnerDataV5,
) -> Result<(), JournalError> {
    let request = floor.request();
    if request.owner_digest != *owner.reservation_acquisition_digest.as_bytes()
        || request.operation_id != owner.operation_id
        || request.artifact_digest != *owner.attempt_digest.as_bytes()
        || request.checkpoint_digest != *owner.root_request_digest.as_bytes()
        || request.chain_head_digest != *owner.session_binding.as_bytes()
    {
        return Err(invalid("original Source actual owner binding DATA"));
    }
    Ok(())
}

fn require_mutations(
    records: &[JournalRecord],
    owner: &OriginalSourceOwnerTransactionV5,
) -> Result<(), JournalError> {
    if records.len() != owner.mutations().len()
        || owner.mutations().iter().any(|mutation| {
            !records.iter().any(|record| {
                record.key() == mutation.key() && record.value() == Some(mutation.after())
            })
        })
    {
        return Err(invalid("original Source exact canonical owner mutation DATA"));
    }
    Ok(())
}

fn owner_views(state: &State) -> impl Iterator<Item = (&[u8], &[u8])> {
    state.iter().filter_map(|((namespace, key), value)| {
        (*namespace == RecordNamespace::SourceProviderAuthority)
            .then_some((key.as_slice(), value.as_slice()))
    })
}

fn bounded_snapshot_bytes(state: &State, limits: JournalLimits) -> Result<usize, JournalError> {
    if state.len() > limits.maximum_materialized_records {
        return Err(JournalError::LimitExceeded("materialized record count"));
    }
    let bytes = state
        .iter()
        .try_fold(0_usize, |bytes, ((namespace, key), value)| {
            if !matches!(
                namespace,
                RecordNamespace::SourceProviderAuthority | RecordNamespace::GlobalCapacityReservation
            ) {
                return Err(JournalError::ForeignAuthorityNamespace);
            }
            bytes
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(JournalError::LimitExceeded("materialized state bytes"))
        })?;
    if bytes > limits.maximum_materialized_bytes {
        return Err(JournalError::LimitExceeded("materialized state bytes"));
    }
    Ok(bytes)
}

fn prospective_state(
    before: &State,
    before_bytes: usize,
    records: &[JournalRecord],
    limits: JournalLimits,
) -> Result<State, JournalError> {
    validate_materialized_change(before, before_bytes, records, limits)?;

    let mut after = before.clone();
    for record in records {
        let key = (record.namespace(), record.key().to_vec());
        match record.value() {
            Some(value) => {
                after.insert(key, value.to_vec());
            }
            None => {
                after.remove(&key);
            }
        }
    }
    Ok(after)
}

fn invalid(reason: &'static str) -> JournalError {
    JournalError::MalformedRecord(reason)
}

#[cfg(test)]
mod tests;
