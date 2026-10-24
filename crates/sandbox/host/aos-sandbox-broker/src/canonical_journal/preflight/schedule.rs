//! Shares the prospective canonical schedule at lexical role boundaries.
//!
//! The macro expands in each actual private journal owner. Its role clauses
//! remain lexical code at the original semantic frontiers; they are neither
//! stored callbacks nor public native selectors. The common body owns every
//! prospective map, canonical transaction step and failed-prefix transfer.
//! A successful forecast grants no writer, funding, currentness or permission.

use std::mem::size_of;

use aos_sandbox_journal::materialized::{self, RecordMutationRef};
use aos_sandbox_protocol::domain_ledger::readonly::{self, IdempotencyDecisionV1};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

use super::{CanonicalPreflightModelsDataV1, JournalError};

/// Keeps prospective models in the original ordinary destruction order.
///
/// Fields are destroyed as IDs, idempotency, then rows, including unwind.
/// Actual callers initialize rows, idempotency, then IDs, matching the original
/// separate local declarations. Selected outcomes move into the unchanged
/// retained DATA layout only after the complete prospective recipe returns.
pub struct CanonicalPreflightWorkingModelsDataV1 {
    /// Keeps the prospective committed identities; it is destroyed first.
    pub transaction_ids: std::collections::BTreeSet<[u8; 16]>,
    /// Keeps the prospective idempotency map; it is destroyed second.
    pub idempotency: std::collections::BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    /// Keeps the prospective materialized rows; they are destroyed last.
    pub state: std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
    /// Counts the prospective materialized bytes.
    pub materialized_bytes: usize,
    /// Keeps the prospective next sequence.
    pub next_sequence: u64,
    /// Counts the prospective committed transactions.
    pub committed_transactions: usize,
}

/// Prices the original prospective source and retained destination model headers.
///
/// This replaces the original two retained-model header allowance with its two
/// actual current types. It adds neither a second copy of those planes nor any
/// map backing; complete actual future native/semantic suppliers remain owed.
#[must_use]
pub fn model_receiving_bytes_v1() -> Option<usize> {
    size_of::<CanonicalPreflightWorkingModelsDataV1>()
        .checked_add(size_of::<CanonicalPreflightModelsDataV1>())
}

/// Prices the shared forwarding controls before any prospective model grows.
///
/// Actual role suppliers separately price their error carriers, native source,
/// future canonical maps and lexical semantic models. These stack controls add
/// Memory only; no field or decision creates a namespace entry.
#[must_use]
pub fn control_receiving_bytes_v1<E>() -> Option<usize> {
    mechanical_control_receiving_bytes_v1()?.checked_add(role_control_receiving_bytes_v1::<E>()?)
}

/// Prices only the actual two role-level schedule Result controls.
///
/// A composite supplier adds this once beside the lower helper invoice.
#[must_use]
pub fn role_control_receiving_bytes_v1<E>() -> Option<usize> {
    size_of::<Result<(), E>>().checked_mul(2)
}

/// Prices the common mechanical forwarding and completed-frame controls once.
///
/// This excludes the role's two outer Results. Callers using a complete quote
/// must not add this set again to `control_receiving_bytes_v1`.
#[must_use]
pub fn mechanical_control_receiving_bytes_v1() -> Option<usize> {
    size_of::<Result<(), JournalError>>()
        .checked_mul(2)?
        .checked_add(size_of::<Result<usize, JournalError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<Vec<Vec<u8>>, JournalError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<u64, JournalError>>().checked_mul(2)?)?
        .checked_add(size_of::<Option<Vec<Vec<u8>>>>().checked_mul(2)?)
}

/// Uses the original materialized projection with the canonical error mapping.
///
/// # Errors
/// Preserves byte/count overflow and the actual configured materialized limits.
#[doc(hidden)]
pub fn validate_materialized_v1(
    models: &CanonicalPreflightWorkingModelsDataV1,
    transaction: &JournalTransaction,
    limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
) -> Result<usize, JournalError> {
    materialized::validate_change(
        &models.state,
        models.materialized_bytes,
        transaction.records().iter().map(RecordMutationRef::from),
        limits.maximum_materialized_bytes,
        limits.maximum_materialized_records,
    )
    .map_err(JournalError::from)
}

/// Applies one original record to the same prospective row and idempotency maps.
///
/// # Errors
/// Preserves the sole canonical idempotency record error after row application.
#[doc(hidden)]
pub fn apply_record_v1(
    models: &mut CanonicalPreflightWorkingModelsDataV1,
    record: &JournalRecord,
) -> Result<(), JournalError> {
    materialized::apply_mutation(&mut models.state, RecordMutationRef::from(record));
    readonly::apply_idempotency_record(&mut models.idempotency, record).map_err(JournalError::from)
}

/// Validates the original idempotency changes before materialized projection.
///
/// # Errors
/// Preserves the canonical conflict or malformed idempotency record cause.
#[doc(hidden)]
pub fn validate_idempotency_v1(
    index: &std::collections::BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    readonly::validate_idempotency_changes(index, transaction.records()).map_err(JournalError::from)
}

/// Expands the complete prospective preflight in the actual private owner.
///
/// Every clause is lexical source, evaluated at its named original frontier.
/// The caller performs its genuine entry/gate checks before this expansion and
/// supplies the complete actual transaction view and held canonical models.
/// Role-specific namespace, Q04, currentness and reserved-capacity gates stay
/// in the private clauses. No clause is retained as a runtime callback.
///
/// The expansion retains reached frames and all prospective models on either
/// outcome when `retained` is present. It never fabricates a successful native
/// observation, mutates the held writer, or creates an authority token.
#[macro_export]
macro_rules! canonical_prospective_preflight_data_v1 {
    (
        error $error:ty;
        transactions $transactions:expr;
        count $count:expr;
        transaction($index:ident) $transaction_expr:expr;
        models $models:ident = $initial:expr;
        limits $limits:expr;
        retained $sink:expr;
        preview $preview:block
        metadata $metadata:expr;
        before_transaction($transaction:ident) { $($before:tt)* }
        delete $delete:block
        after_frames($frame_count:ident) $after_frames:block
        reserved($expected_length:ident) $reserved:block
    ) => {{
        use $crate::canonical_journal::preflight::{
            CanonicalPreflightDataOriginalV1, CanonicalPreflightModelsDataV1,
        };
        use $crate::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
        let mut retained: Option<&mut CanonicalPreflightDataOriginalV1> = $sink;
        $preview
        if let Some(original) = retained.as_deref_mut() {
            original.reserve_transactions_v2($count).map_err(<$error>::from)?;
        }
        let mut $models: $crate::canonical_journal::preflight::schedule::CanonicalPreflightWorkingModelsDataV1 = $initial;
        let result: Result<(), $error> = (|| {
            let mut $expected_length = match retained.as_deref_mut() {
                Some(original) => original.capture_metadata_v2($metadata)
                    .map_err(<$error>::from)?,
                None => ($metadata).map_err(<$error>::from)?.len(),
            };
            for $index in 0..$count {
                let $transaction = $transaction_expr;
                if let Some(original) = retained.as_deref_mut() {
                    original.begin_transaction_v2();
                }
                let mut retained_frames = None;
                let transaction_result: Result<(), $error> = (|| {
                    $($before)*
                    match retained.as_deref_mut() {
                        Some(original) => original.validate_transaction_v2($transaction, $limits)
                            .map_err(<$error>::from)?,
                        None => $crate::canonical_journal::preflight::schedule::validate_transaction_v1(
                            $transaction, $limits,
                        ).map_err(<$error>::from)?,
                    }
                    $delete
                    if !$models.transaction_ids.insert(*$transaction.id()) {
                        return Err(<$error>::from(Mechanical::DuplicateTransaction));
                    }
                    if $models.committed_transactions >= ($limits).maximum_transactions {
                        return Err(<$error>::from(Mechanical::LimitExceeded("committed transaction count")));
                    }
                    $crate::canonical_journal::preflight::schedule::validate_idempotency_v1(
                        &$models.idempotency, $transaction,
                    ).map_err(<$error>::from)?;
                    $models.materialized_bytes = $crate::canonical_journal::preflight::schedule::validate_materialized_v1(
                        &$models, $transaction, $limits,
                    ).map_err(<$error>::from)?;
                    retained_frames = Some(match retained.as_deref_mut() {
                        Some(original) => original.encode_transaction_v2($transaction, $models.next_sequence)
                            .map_err(<$error>::from)?,
                        None => $crate::canonical_journal::preflight::schedule::encode_transaction_v1(
                            $transaction, $models.next_sequence,
                        ).map_err(<$error>::from)?,
                    });
                    let frames = retained_frames.as_ref()
                        .ok_or_else(|| <$error>::from(Mechanical::ProtectedBoundary))?;
                    let $frame_count = u64::try_from(frames.len())
                        .map_err(|_| <$error>::from(Mechanical::LimitExceeded("transaction frame count")))?;
                    $after_frames
                    let additional_bytes = frames.iter().try_fold(0_u64,
                        |total, frame| total.checked_add(frame.len() as u64));
                    $expected_length = $expected_length
                        .checked_add(additional_bytes.ok_or_else(|| <$error>::from(Mechanical::JournalTooLarge))?)
                        .ok_or_else(|| <$error>::from(Mechanical::JournalTooLarge))?;
                    if $expected_length > ($limits).maximum_journal_bytes {
                        return Err(<$error>::from(Mechanical::JournalTooLarge));
                    }
                    $reserved
                    for record in $transaction.records() {
                        $crate::canonical_journal::preflight::schedule::apply_record_v1(&mut $models, record)
                            .map_err(<$error>::from)?;
                    }
                    $models.next_sequence = $models.next_sequence.checked_add($frame_count)
                        .ok_or_else(|| <$error>::from(Mechanical::SequenceExhausted))?;
                    $models.committed_transactions += 1;
                    Ok(())
                })();
                if let Some(original) = retained.as_deref_mut() {
                    original.retain_frames_v2(retained_frames);
                }
                transaction_result?;
            }
            Ok(())
        })();
        if let Some(original) = retained {
            original.retain_models_v2(CanonicalPreflightModelsDataV1 {
                state: $models.state,
                idempotency: $models.idempotency,
                transaction_ids: $models.transaction_ids,
                materialized_bytes: $models.materialized_bytes,
                next_sequence: $models.next_sequence,
                committed_transactions: $models.committed_transactions,
            });
        }
        result
    }};
}

/// Uses the sole ordinary transaction validator without a retained destination.
///
/// # Errors
/// Preserves the existing canonical transaction schema and configured limits.
#[doc(hidden)]
pub fn validate_transaction_v1(
    transaction: &JournalTransaction,
    limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_protocol::domain_ledger::transaction::validate_transaction(transaction, limits)
        .map_err(JournalError::from)
}

/// Uses the sole ordinary encoder without a retained destination.
///
/// # Errors
/// Preserves the original frame encoding and sequence geometry failures.
#[doc(hidden)]
pub fn encode_transaction_v1(
    transaction: &JournalTransaction,
    sequence: u64,
) -> Result<Vec<Vec<u8>>, JournalError> {
    aos_sandbox_protocol::domain_ledger::transaction::encode_transaction(transaction, sequence)
        .map_err(JournalError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_journal::preflight::CanonicalPreflightDataOriginalV1;
    use aos_sandbox_model::RecordNamespace;
    use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn lexical_gate_precedes_duplicate_and_retains_prior_models_and_frames() {
        let directory = tempfile::tempdir().unwrap();
        let metadata_path = directory.path();
        let transactions = [1, 2].map(|value| {
            JournalTransaction::new(
                [1; 16],
                vec![JournalRecord::put(
                    RecordNamespace::BrokerSessionTraffic,
                    vec![value],
                    vec![value],
                )],
            )
            .unwrap()
        });
        let mut original = CanonicalPreflightDataOriginalV1::new();
        let mut reached = Vec::new();

        let result = (|| -> Result<(), JournalError> {
            crate::canonical_prospective_preflight_data_v1! {
                error JournalError;
                transactions transactions;
                count transactions.len();
                transaction(index) &transactions[index];
                models models = CanonicalPreflightWorkingModelsDataV1 {
                    state: BTreeMap::new(),
                    idempotency: BTreeMap::new(),
                    transaction_ids: BTreeSet::new(),
                    materialized_bytes: 0,
                    next_sequence: 1,
                    committed_transactions: 0,
                };
                limits JournalLimits::default();
                retained Some(&mut original);
                preview {}
                metadata std::fs::metadata(metadata_path);
                before_transaction(transaction) {
                    reached.push(index);
                    if index == 1 {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                delete {}
                after_frames(frame_count) {}
                reserved(expected_length) {}
            }
        })();

        assert!(matches!(result, Err(JournalError::ProtectedBoundary)));
        assert_eq!(reached, [0, 1]);
        assert_eq!(original.reached_transactions(), 2);
        assert_eq!(original.frames(0).unwrap().len(), 3);
        assert!(original.frames(1).is_none());
        let models = original.models().unwrap();
        assert_eq!(models.committed_transactions, 1);
        assert_eq!(models.transaction_ids.len(), 1);
        assert_eq!(models.state.len(), 1);
        assert_eq!(
            models
                .state
                .get(&(RecordNamespace::BrokerSessionTraffic, vec![1])),
            Some(&vec![1]),
        );
    }
}
