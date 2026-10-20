//! Retains the same latest-operation selector's actual failed decode prefix.
//!
//! The selected entry borrows a canonical historical projection and verifier;
//! it cannot claim a Source owner or create CurrentLifecycleOperation authority.

use super::*;
use std::error::Error;
use aos_sandbox_protocol::domain_ledger::records::{
    ReducerPayloadDecodeCaptureV1, decode_reducer_payload_with_schema_capture_v1,
};
use crate::lifecycle::protected_journal::LifecycleSchemaReplayCaptureV1;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;

type SelectedOperation = (LifecycleProtectedJournalKeyV1, LifecycleOperationV1,
    LifecycleRecordDigestV1);

/// Holds both the selected predecessor and any refused incoming operation.
#[derive(Default)]
pub(crate) struct LifecycleCurrentOperationSelectionOriginalV1 {
    reducer: ReducerPayloadDecodeCaptureV1,
    schema: LifecycleSchemaReplayCaptureV1,
    incoming: Option<LifecycleOperationV1>,
    canonical: Option<Result<bool, LifecycleModelError>>,
    selected: Option<SelectedOperation>,
    returned: Option<Result<(), LifecycleProtectedJournalErrorV1>>,
    reentry: Option<LifecycleProtectedJournalErrorV1>,
    entered: bool,
}

impl LifecycleCurrentOperationSelectionOriginalV1 {
    pub(crate) fn new() -> Self { Self::default() }

    pub(crate) fn carrier_receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)
    }

    pub(crate) fn select_once_v1(
        &mut self, projection: &LifecycleProtectedJournalProjectionV1,
        verifier: &LifecycleJournalVerifierV1, operation: OperationId,
    ) -> Result<(), LifecycleProtectedJournalErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        self.entered = true;
        self.returned = Some(self.select_engine(projection, verifier, operation, true, None));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord) }
    }

    // Selects a historical row from the already fully validated projection.
    // This shares every decode, canonical check and retained failure slot with
    // latest selection, and creates no CurrentLifecycleOperation authority.
    pub(crate) fn select_key_once_v1(
        &mut self, projection: &LifecycleProtectedJournalProjectionV1,
        verifier: &LifecycleJournalVerifierV1, operation: OperationId,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<(), LifecycleProtectedJournalErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        self.entered = true;
        self.returned = Some(self.select_engine(projection, verifier, operation, true, Some(key)));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord) }
    }

    pub(crate) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.schema.failure_view_v1()
            .or_else(|| self.reducer.failure().map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.canonical.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }

    pub(crate) fn completed_v1(&self) -> Option<&SelectedOperation> {
        if !matches!(self.returned, Some(Ok(()))) || self.reentry.is_some() { return None; }
        self.selected.as_ref()
    }

    fn select_engine(
        &mut self, projection: &LifecycleProtectedJournalProjectionV1,
        verifier: &LifecycleJournalVerifierV1, operation_id: OperationId, retaining: bool,
        exact_key: Option<&LifecycleProtectedJournalKeyV1>,
    ) -> Result<(), LifecycleProtectedJournalErrorV1> {
        let invalid = || LifecycleProtectedJournalErrorV1::NonCanonicalRecord;
        if operation_id.as_bytes() == &[0; 16] { return Err(invalid()); }
        for envelope in projection.records().iter().filter(|envelope| {
            exact_key.is_none_or(|key| key == envelope.key())
                && crate::lifecycle::protected_journal::lifecycle_key_selects_operation_v2(
                    envelope.key(), operation_id)
        }) {
            // Only the previous complete pure row reaches another iteration.
            // A failure returns with every incoming decoder/model still resident.
            self.reducer = ReducerPayloadDecodeCaptureV1::new();
            self.schema = LifecycleSchemaReplayCaptureV1::new();
            self.incoming = None;
            self.canonical = None;
            let ordinary_reducer;
            let body = if retaining {
                decode_reducer_payload_with_schema_capture_v1::<LifecycleProtectedJournalSchemaV1>(
                    envelope.key(), envelope.payload(), verifier, &mut self.reducer, &mut self.schema,
                )?;
                let range = self.reducer.body_range_v1().ok_or_else(invalid)?;
                envelope.payload().get(range).ok_or_else(invalid)?
            } else {
                ordinary_reducer = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
                    envelope.key(), envelope.payload(), verifier,
                )?;
                ordinary_reducer.body()
            };
            self.incoming = Some(if retaining {
                // The same schema parser already retained and canonically
                // checked this operation. Move that model, never parse it twice.
                self.schema.take_completed_operation_v1().ok_or_else(invalid)?
            } else {
                decode_operation_record_v1(body).map_err(|_| invalid())?
            });
            let operation = self.incoming.as_ref().ok_or_else(invalid)?;
            if operation.operation_id() != operation_id { return Err(invalid()); }
            self.canonical = Some(crate::lifecycle::format::operation_record_matches_canonical_encoding(
                operation, body,
            ));
            if self.canonical != Some(Ok(true)) { return Err(invalid()); }
            let record = crate::lifecycle::format::record_digest(body).map_err(|_| invalid())?;
            let Some((_, current, _)) = self.selected.as_ref() else {
                let operation = self.incoming.take().ok_or_else(invalid)?;
                self.selected = Some((envelope.key().clone(), operation, record));
                continue;
            };
            require_same_lifecycle_admission_v1(current, operation)?;
            if current.record_revision() == operation.record_revision() { return Err(invalid()); }
            if operation.record_revision() > current.record_revision() {
                let operation = self.incoming.take().ok_or_else(invalid)?;
                self.selected = Some((envelope.key().clone(), operation, record));
            }
        }
        Ok(())
    }
}

/// Delegates the ordinary writer lookup to the same selector engine.
pub(crate) fn select_latest_operation_data_v1(
    projection: &LifecycleProtectedJournalProjectionV1,
    verifier: &LifecycleJournalVerifierV1,
    operation_id: OperationId,
) -> Result<Option<SelectedOperation>, LifecycleProtectedJournalErrorV1> {
    let mut original = LifecycleCurrentOperationSelectionOriginalV1::new();
    original.select_engine(projection, verifier, operation_id, false, None)?;
    Ok(original.selected.take())
}

/// Compares only the immutable fields of the same accepted lifecycle operation.
///
/// This shared DATA predicate creates no current operation, Source loan or
/// phase transition. Revision/progress comparisons remain at their existing
/// callers after these unchanged immutable-admission comparisons.
pub(crate) fn require_same_lifecycle_admission_v1(
    expected: &LifecycleOperationV1,
    actual: &LifecycleOperationV1,
) -> Result<(), LifecycleProtectedJournalErrorV1> {
    if expected.caller() != actual.caller()
        || expected.project() != actual.project()
        || expected.idempotency() != actual.idempotency()
        || expected.normalized_request() != actual.normalized_request()
        || expected.intent() != actual.intent()
        || expected.accepted_at() != actual.accepted_at()
        || expected.start_native_origin_v1() != actual.start_native_origin_v1() {
        return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}
