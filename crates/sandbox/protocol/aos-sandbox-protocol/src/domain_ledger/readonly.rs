//! Borrows historical ledger DATA from the existing native owner and index.
//!
//! This view performs no IO, recovery, signature verification, protected-name
//! observation or native mutation. Its constructor accepts diagnostic DATA already
//! exposed by the generic native owner. It establishes no protected admission,
//! currentness, operation loan or effect permission. The actual native owner
//! remains borrowed throughout every returned row and iterator.
//!
//! Idempotency decisions preserve the established 32-byte request commitment
//! and 16-byte operation identity. Canonical on-disk encoding remains owned by
//! the transaction schema; this module shares resident index lookup and update mechanics.

use std::collections::BTreeMap;

use aos_sandbox_model::{OperationId, RecordNamespace};
use aos_sandbox_journal::owner::NativeJournal;

use super::transaction::{IdempotencyKey, JournalLimits, JournalRecord};

/// Borrows a historical fixed-journal cut as nonauthorizing comparison DATA.
///
/// The fields preserve the existing readback layout. A supplied value proves no
/// protected origin, completed replay, currentness, receiving, or effect right.
/// Actual native owners retain custody and enforce those independent gates.
pub struct FixedJournalReadbackDataV1<'a> {
    /// The historical marked transaction, when requested by the reader.
    pub marked_transaction: Option<&'a super::transaction::JournalTransaction>,
    /// The materialized rows borrowed from the historical prefix.
    pub state: &'a BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    /// The captured historical physical names.
    pub names: super::protected_names::ProtectedJournalNamesV1,
    /// The durable next sequence at the historical cut.
    pub next: u64,
    /// The durable byte end at the historical cut.
    pub end: u64,
}

/// Reports whether a request key is new, an exact replay, or a conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyOutcome {
    /// No durable decision exists for this key.
    Vacant,
    /// The exact semantic request was previously accepted as this operation.
    Replay(OperationId),
    /// The key is already bound to different semantic request bytes.
    Conflict,
}

/// Carries one resident idempotency decision as comparison DATA.
///
/// A supplied value does not admit its key, validate a committed prefix or
/// authorize replay. Genuine native owners retain those checks and provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyDecisionV1 {
    /// Commitment to the request associated with the key.
    pub request_digest: [u8; 32],
    /// Operation identity associated with the request.
    pub operation_id: OperationId,
}


/// Borrows the actual native map and its existing diagnostic idempotency index.
///
/// This is a historical DATA view, not evidence that the supplied index matches
/// the native prefix or that either owner has protected/current provenance.
#[derive(Clone, Copy)]
pub struct HistoricalLedgerReadViewV1<'native> {
    native: &'native NativeJournal<RecordNamespace, JournalLimits>,
    idempotency: &'native BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
}

impl<'native> HistoricalLedgerReadViewV1<'native> {
    /// Borrows supplied native and index DATA without authenticating either.
    pub const fn new(
        native: &'native NativeJournal<RecordNamespace, JournalLimits>,
        idempotency: &'native BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    ) -> Self {
        Self { native, idempotency }
    }

    /// Borrows the same complete native rows and idempotency index as DATA.
    #[must_use]
    pub fn rows_data_v2(self) -> HistoricalLedgerRowsDataV2<'native> {
        HistoricalLedgerRowsDataV2::new(self.native.state(), self.idempotency)
    }

    /// Borrows one existing diagnostic idempotency-index decision as DATA.
    ///
    /// This performs no lookup allocation, replay or native observation. It
    /// authenticates neither the index nor the request; the actual caller
    /// retains its independently admitted complete native prefix and posts.
    #[must_use]
    pub fn idempotency_decision_data_v2(
        self,
        key: &[u8],
    ) -> Option<&'native IdempotencyDecisionV1> {
        self.idempotency.get(key)
    }

    /// Reports the actual native owner's recorded poison state as DATA.
    ///
    /// A negative result alone establishes no positive health or provenance.
    #[must_use]
    pub fn is_poisoned(self) -> bool {
        self.native.is_poisoned()
    }

    /// Borrows the original materialized map as nonauthorizing diagnostic DATA.
    ///
    /// This performs no allocation, observation or validation. It establishes
    /// neither protected provenance nor a paid role operation; genuine callers
    /// retain those checks while this same native owner remains borrowed.
    #[must_use]
    pub fn materialized_state_v1(
        self,
    ) -> &'native BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        self.native.state()
    }

    /// Borrows one diagnostic value, including after native poison.
    #[must_use]
    pub fn get(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'native [u8]> { HistoricalLedgerComparisonV2::Native(self).get(namespace, key) }

    /// Iterates one diagnostic namespace in established bytewise key order.
    pub fn records(
        self,
        namespace: RecordNamespace,
    ) -> impl Iterator<Item = (&'native [u8], &'native [u8])> + Clone + 'native { HistoricalLedgerComparisonV2::Native(self).records(namespace) }

    /// Iterates every diagnostic row by namespace and bytewise key order.
    pub fn all_records(
        self,
    ) -> impl Iterator<Item = (RecordNamespace, &'native [u8], &'native [u8])> + Clone + 'native {
        self.rows_data_v2().all_records()
    }

    /// Resolves an existing diagnostic index key without granting replay.
    #[must_use]
    pub fn check_idempotency(
        self,
        key: &IdempotencyKey,
        request_digest: [u8; 32],
    ) -> IdempotencyOutcome { HistoricalLedgerComparisonV2::Native(self).check_idempotency(key, request_digest) }
}


/// Borrows complete historical rows and their recorded idempotency index.
///
/// This passive view authenticates neither input and records no native health.
/// Actual readers must retain their own complete prefix, index, currentness and
/// independently owed observations before using a comparison result.
#[derive(Clone, Copy)]
pub struct HistoricalLedgerRowsDataV2<'rows> {
    state: &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    idempotency: &'rows BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
}

impl<'rows> HistoricalLedgerRowsDataV2<'rows> {
    /// Borrows supplied complete rows and index as comparison DATA only.
    pub const fn new(
        state: &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        idempotency: &'rows BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    ) -> Self {
        Self { state, idempotency }
    }
    /// Borrows one supplied diagnostic idempotency decision as comparison DATA.
    ///
    /// This performs no allocation, replay or native observation and authenticates
    /// neither the index nor the request. Actual callers retain their independent
    /// complete-prefix, currentness and owed-post checks.
    #[must_use]
    pub fn idempotency_decision_data_v2(
        self,
        key: &[u8],
    ) -> Option<&'rows IdempotencyDecisionV1> {
        self.idempotency.get(key)
    }

    /// Borrows the same supplied complete materialized map as comparison DATA.
    ///
    /// This performs no validation and establishes no protected provenance,
    /// native health, paid observation or current role.
    #[must_use]
    pub fn materialized_state_data_v2(
        self,
    ) -> &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        self.state
    }

    /// Selects one supplied row through the existing historical lookup recipe.
    ///
    /// The lookup preserves the original temporary key allocation. It grants
    /// no native custody or positive interpretation to the supplied bytes.
    #[must_use]
    pub fn get_data_v2(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'rows [u8]> {
        HistoricalLedgerComparisonV2::Rows(self).get(namespace, key)
    }

    /// Iterates one supplied namespace in the original bytewise key order.
    pub fn records_data_v2(
        self,
        namespace: RecordNamespace,
    ) -> impl Iterator<Item = (&'rows [u8], &'rows [u8])> + Clone + 'rows {
        HistoricalLedgerComparisonV2::Rows(self).records(namespace)
    }

    /// Compares one supplied idempotency decision without authenticating it.
    #[must_use]
    pub fn check_idempotency_data_v2(
        self,
        key: &IdempotencyKey,
        request_digest: [u8; 32],
    ) -> IdempotencyOutcome {
        HistoricalLedgerComparisonV2::Rows(self).check_idempotency(key, request_digest)
    }

    /// Borrows one supplied historical row without native admission.
    pub fn get_record_data_v1(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'rows [u8]> {
        HistoricalLedgerComparisonV2::Rows(self).get(namespace, key)
    }

    /// Borrows the supplied map without claiming native prefix or currentness.
    pub const fn materialized_state_data_v1(self) -> &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        self.state
    }

    /// Iterates supplied complete rows without authenticating their provenance.
    pub fn all_records(self)
        -> impl Iterator<Item = (RecordNamespace, &'rows [u8], &'rows [u8])> + Clone + 'rows
    {
        self.state.iter().map(|((namespace,key),value)| (*namespace,key.as_slice(),value.as_slice()))
    }

}

// Native adapters retain the original poison checks at each old frontier.
// Rows-only consumers perform historical comparisons, never native admission.
#[derive(Clone, Copy)]
pub(crate) enum HistoricalLedgerComparisonV2<'rows> {
    Native(HistoricalLedgerReadViewV1<'rows>),
    Rows(HistoricalLedgerRowsDataV2<'rows>),
}

impl<'rows> HistoricalLedgerComparisonV2<'rows> {
    pub(crate) fn native_poisoned_v2(self) -> bool {
        matches!(self, Self::Native(native) if native.is_poisoned())
    }

    fn rows_v2(self) -> HistoricalLedgerRowsDataV2<'rows> {
        match self {
            Self::Native(native) => HistoricalLedgerRowsDataV2::new(
                native.native.state(), native.idempotency),
            Self::Rows(rows) => rows,
        }
    }

    pub(crate) fn get(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'rows [u8]> {
        self.rows_v2().state.get(&(namespace, key.to_vec())).map(Vec::as_slice)
    }

    pub(crate) fn records(self, namespace: RecordNamespace)
        -> impl Iterator<Item = (&'rows [u8], &'rows [u8])> + Clone + 'rows
    {
        self.rows_v2().state.range((namespace, Vec::new())..)
            .take_while(move |((actual, _), _)| *actual == namespace)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
    }

    pub(crate) fn check_idempotency(self, key: &IdempotencyKey, request_digest: [u8; 32])
        -> IdempotencyOutcome
    {
        match self.rows_v2().idempotency.get(key.as_bytes()) {
            None => IdempotencyOutcome::Vacant,
            Some(decision) if decision.request_digest == request_digest =>
                IdempotencyOutcome::Replay(decision.operation_id),
            Some(_) => IdempotencyOutcome::Conflict,
        }
    }
}

/// Reports resident index comparison or malformed record DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdempotencyRecordDataErrorV1 {
    /// The key is already bound to different request or operation DATA.
    #[error("idempotency key conflicts with its existing decision")]
    Conflict,
    /// The unchanged canonical record fields cannot be read completely.
    #[error("malformed journal record: {0}")]
    MalformedRecord(&'static str),
}

/// Compares every proposed decision before native materialization.
///
/// This is index DATA only. Actual callers retain complete canonical transaction
/// validation, native registration, original/currentness and all role admission.
///
/// # Errors
/// Refuses a deleted or incomplete decision or the original request/operation
/// conflict, without mutating the supplied resident index.
pub fn validate_idempotency_changes(
    idempotency: &BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    records: &[JournalRecord],
) -> Result<(), IdempotencyRecordDataErrorV1> {
    for record in records {
        if record.namespace() != RecordNamespace::Idempotency {
            continue;
        }
        let proposed = decision_from_record(record)?;
        if idempotency
            .get(record.key())
            .is_some_and(|existing| existing != &proposed)
        {
            return Err(IdempotencyRecordDataErrorV1::Conflict);
        }
    }
    Ok(())
}

/// Applies the same index step after one actual native record materialization.
///
/// Actual role adapters call this after their complete transaction comparison
/// and after EACH native record apply, before advancing to the next record.
/// Calling it on arbitrary DATA grants no native mutation or replay permission.
///
/// # Errors
/// Refuses deletion or an incomplete decision before allocating its index key.
pub fn apply_idempotency_record(
    idempotency: &mut BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    record: &JournalRecord,
) -> Result<(), IdempotencyRecordDataErrorV1> {
    if record.namespace() == RecordNamespace::Idempotency {
        let decision = decision_from_record(record)?;
        idempotency.insert(record.key().to_vec(), decision);
    }
    Ok(())
}

fn decision_from_record(
    record: &JournalRecord,
) -> Result<IdempotencyDecisionV1, IdempotencyRecordDataErrorV1> {
    let value = record.value().ok_or(IdempotencyRecordDataErrorV1::MalformedRecord(
        "idempotency records cannot be deleted",
    ))?;
    // Native callers have already validated the canonical 48-byte record. The
    // shared public DATA seam also checks slices so arbitrary comparison inputs
    // cannot turn that former private precondition into a panic.
    let request_digest = value.get(..32)
        .ok_or(IdempotencyRecordDataErrorV1::MalformedRecord("invalid idempotency digest"))?
        .try_into()
        .map_err(|_| IdempotencyRecordDataErrorV1::MalformedRecord("invalid idempotency digest"))?;
    let operation_bytes = value.get(32..)
        .ok_or(IdempotencyRecordDataErrorV1::MalformedRecord("invalid operation identity"))?
        .try_into()
        .map_err(|_| IdempotencyRecordDataErrorV1::MalformedRecord("invalid operation identity"))?;
    Ok(IdempotencyDecisionV1 {
        request_digest,
        operation_id: OperationId::from_bytes(operation_bytes),
    })
}

#[cfg(test)]
mod idempotency_record_tests {
    use super::*;

    #[test]
    fn incomplete_comparison_data_keeps_the_existing_index_untouched() {
        let decision = IdempotencyDecisionV1 {
            request_digest: [3; 32],
            operation_id: OperationId::from_bytes([4; 16]),
        };
        let mut index = BTreeMap::from([(vec![1, 2], decision.clone())]);
        let original_key = index.keys().next().unwrap().as_ptr();

        for width in [0, 1, 31, 32, 47, 49, 64] {
            let record = JournalRecord::put(RecordNamespace::Idempotency, vec![1, 2], vec![0; width]);
            assert!(matches!(
                validate_idempotency_changes(&index, std::slice::from_ref(&record)),
                Err(IdempotencyRecordDataErrorV1::MalformedRecord(_)),
            ));
            assert!(matches!(
                apply_idempotency_record(&mut index, &record),
                Err(IdempotencyRecordDataErrorV1::MalformedRecord(_)),
            ));
            assert_eq!(index.get([1, 2].as_slice()), Some(&decision));
            assert_eq!(index.keys().next().unwrap().as_ptr(), original_key);
        }
    }
}
