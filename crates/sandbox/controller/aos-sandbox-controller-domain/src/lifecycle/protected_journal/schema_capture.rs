//! Retains each schema parse at the canonical companion/phase frontiers.

use super::*;
use crate::lifecycle::{
    LifecycleAuxiliaryDecodeOriginalV1, LifecycleOperationDecodeOriginalV1,
};
use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaReplayCaptureV1;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;

/// Owns the current schema decoder and its complete canonical comparison result.
///
/// A following row can replace this pure DATA only after this row's whole
/// schema comparison succeeded. A failed row is sticky and is never replaced.
#[derive(Default)]
pub struct LifecycleSchemaReplayCaptureV1 {
    kind: Option<LifecycleProtectedRecordKindV1>,
    body: Vec<u8>,
    active: bool,
    operation: LifecycleOperationDecodeOriginalV1,
    auxiliary: LifecycleAuxiliaryDecodeOriginalV1,
    idempotency: Option<Result<LifecycleJournalOwnershipRecordV1, LifecycleModelError>>,
    roundtrip: Option<Result<Vec<u8>, LifecycleModelError>>,
    canonical: Option<Result<bool, LifecycleModelError>>,
    returned: Option<Result<ProtectedReducerPhaseV1, LifecycleModelError>>,
    reentry: Option<LifecycleModelError>,
}

impl LifecycleSchemaReplayCaptureV1 {
    /// Constructs inert schema storage without parsing or allocating a model.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the original schema error before any later reentry refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&LifecycleModelError> {
        self.operation.failure().or_else(|| self.auxiliary.failure())
            .or_else(|| self.idempotency.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.roundtrip.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.canonical.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.reentry.as_ref())
    }

    /// Borrows the actual parser cause before its schema error projection.
    #[must_use]
    pub fn failure_view_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.operation.failure_view_v1()
            .or_else(|| self.auxiliary.failure_view_v1())
            .or_else(|| self.failure().map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    // Selection consumes only the same actual complete schema model. This
    // historical DATA move grants no Current operation or Source authority.
    pub(in crate::lifecycle) fn take_completed_operation_v1(&mut self) -> Option<LifecycleOperationV1> {
        if !matches!(self.returned, Some(Ok(_))) || self.failure().is_some() {
            return None;
        }
        self.operation.take_completed_once()
    }

    fn begin_row(&mut self, kind: LifecycleProtectedRecordKindV1, body: &[u8]) -> bool {
        if self.reentry.is_some() || (self.active && !matches!(self.returned, Some(Ok(_)))) {
            self.reentry.get_or_insert(LifecycleModelError::InvalidTransition);
            return false;
        }
        // No native owner is disposed here. This is the completed pure schema
        // comparison's reusable resident peak; cumulative input is paid outside.
        *self = Self::new();
        self.active = true;
        self.kind = Some(kind);
        if self.body.try_reserve_exact(body.len()).is_err() {
            self.returned = Some(Err(LifecycleModelError::Allocation));
            return false;
        }
        self.body.extend_from_slice(body);
        true
    }

    fn original_operation(&mut self, body: &[u8]) -> Option<&LifecycleOperationV1> {
        self.operation.decode_once(body).ok()?;
        let operation = self.operation.completed()?;
        self.canonical = Some(super::super::format::operation_record_matches_canonical_encoding(operation, body));
        if self.canonical != Some(Ok(true)) {
            self.returned = Some(Err(LifecycleModelError::CorruptEncoding));
            return None;
        }
        Some(operation)
    }
}

impl ProtectedDomainSchemaReplayCaptureV1 for LifecycleProtectedJournalSchemaV1 {
    type ReplayCapture = LifecycleSchemaReplayCaptureV1;

    fn semantic_tuple_retaining_v1(
        kind: Self::Kind, identity: &[u8], body: &[u8], capture: &mut Self::ReplayCapture,
    ) -> Option<[u8; 32]> {
        if !capture.begin_row(kind, body) {
            return None;
        }
        if !matches!(kind, Self::Kind::Intent | Self::Kind::Operation | Self::Kind::Effect) {
            return None;
        }
        let operation = capture.original_operation(body)?;
        operation_tuple(operation, identity)
    }

    fn decode_reducer_phase_retaining_v1(
        verifier: &Self::ReplayValidator, kind: Self::Kind, identity: &[u8], body: &[u8],
        capture: &mut Self::ReplayCapture,
    ) -> Option<ProtectedReducerPhaseV1> {
        if !capture.active || capture.kind != Some(kind) || capture.body.as_slice() != body
            || capture.returned.is_some() || capture.failure().is_some()
        {
            if capture.failure().is_none() {
                capture.reentry.get_or_insert(LifecycleModelError::InvalidTransition);
            }
            capture.returned.get_or_insert(Err(LifecycleModelError::CorruptEncoding));
            return None;
        }
        let phase = decode_reducer_phase_with_original(verifier, kind, identity, body, Some(&mut *capture));
        capture.returned = Some(phase.ok_or(LifecycleModelError::CorruptEncoding));
        phase
    }
}

pub(super) fn operation_tuple(operation: &LifecycleOperationV1, identity: &[u8]) -> Option<[u8; 32]> {
    let mut tuple = [0; 32];
    tuple[..16].copy_from_slice(operation.project().as_bytes());
    tuple[16..].copy_from_slice(&lifecycle_journal_subject(operation.intent()));
    (identity.get(..32) == Some(tuple.as_slice())).then_some(tuple)
}

pub(super) fn decode_reducer_phase_with_original(
    verifier: &LifecycleJournalVerifierV1,
    kind: LifecycleProtectedRecordKindV1,
    identity: &[u8],
    body: &[u8],
    original: Option<&mut LifecycleSchemaReplayCaptureV1>,
) -> Option<ProtectedReducerPhaseV1> {
    if identity.len() != 48 {
        return None;
    }
    match kind {
        LifecycleProtectedRecordKindV1::Intent
        | LifecycleProtectedRecordKindV1::Operation
        | LifecycleProtectedRecordKindV1::Effect => {
            let ordinary;
            let operation = match original {
                Some(original) => original.operation.completed()?,
                None => {
                    ordinary = canonical_operation(body)?;
                    &ordinary
                }
            };
            operation_identity_phase(kind, identity, operation)
        }
        LifecycleProtectedRecordKindV1::Idempotency => {
            match original {
                Some(original) => {
                    original.idempotency = Some(decode_lifecycle_journal_record_v1(body, verifier));
                    let record = original.idempotency.as_ref()?.as_ref().ok()?;
                    idempotency_phase(*record, identity, body, &mut original.roundtrip)
                }
                None => {
                    let record = decode_lifecycle_journal_record_v1(body, verifier).ok()?;
                    idempotency_phase(record, identity, body, &mut None)
                }
            }
        }
        LifecycleProtectedRecordKindV1::Auxiliary => {
            match original {
                Some(original) => {
                    original.auxiliary.decode_from_protected_envelope_once(body, verifier.replay()).ok()?;
                    let record = original.auxiliary.completed()?;
                    auxiliary_phase(record, identity, body, &mut original.roundtrip)
                }
                None => {
                    let record = crate::lifecycle::decode_lifecycle_auxiliary_record_from_protected_envelope_v1(
                        body, verifier.replay(),
                    ).ok()?;
                    auxiliary_phase(&record, identity, body, &mut None)
                }
            }
        }
        LifecycleProtectedRecordKindV1::Checkpoint => None,
    }
}

fn operation_identity_phase(
    kind: LifecycleProtectedRecordKindV1, identity: &[u8], operation: &LifecycleOperationV1,
) -> Option<ProtectedReducerPhaseV1> {
    if operation.project().as_bytes() != identity.get(..16)?
        || lifecycle_journal_subject(operation.intent()).as_slice() != identity.get(16..32)?
        || operation.operation_id().as_bytes() != identity.get(32..48)?
    {
        return None;
    }
    operation_phase(kind, operation.phase() as u8)
}

fn idempotency_phase(
    record: LifecycleJournalOwnershipRecordV1, identity: &[u8], body: &[u8],
    roundtrip: &mut Option<Result<Vec<u8>, LifecycleModelError>>,
) -> Option<ProtectedReducerPhaseV1> {
    *roundtrip = Some(encode_lifecycle_journal_record_v1(record));
    if roundtrip.as_ref()?.as_ref().ok()?.as_slice() != body
        || record.kind() != LifecycleJournalRecordKindV1::Idempotency
        || record.project().as_bytes() != &identity[..16]
        || record.namespace().as_bytes() != &identity[16..32]
        || record.operation().is_none_or(|operation| operation.as_bytes() != &identity[32..48])
    {
        return None;
    }
    Some(ProtectedReducerPhaseV1::Observed)
}

fn auxiliary_phase(
    record: &LifecycleAuxiliaryRecordV1, identity: &[u8], body: &[u8],
    roundtrip: &mut Option<Result<Vec<u8>, LifecycleModelError>>,
) -> Option<ProtectedReducerPhaseV1> {
    *roundtrip = Some(encode_lifecycle_auxiliary_record_v1(record));
    if roundtrip.as_ref()?.as_ref().ok()?.as_slice() != body
        || record.project().as_bytes() != &identity[..16]
        || record.lineage().as_bytes() != &identity[16..32]
        || record.operation().as_bytes() != &identity[32..48]
    {
        return None;
    }
    match record.kind() {
        LifecycleAuxiliaryKindV1::Coordination => Some(ProtectedReducerPhaseV1::Prepared),
        LifecycleAuxiliaryKindV1::Operation | LifecycleAuxiliaryKindV1::RetentionLedger
        | LifecycleAuxiliaryKindV1::SuspendObservation | LifecycleAuxiliaryKindV1::BootInventory
        | LifecycleAuxiliaryKindV1::DeleteBatch | LifecycleAuxiliaryKindV1::StopDispatch
        | LifecycleAuxiliaryKindV1::StopCompletion => Some(ProtectedReducerPhaseV1::Observed),
        LifecycleAuxiliaryKindV1::Cancellation => Some(ProtectedReducerPhaseV1::Terminal),
    }
}
