//! Adds a concrete pure schema destination at the existing reducer decode call.
//!
//! The physical caller still owns its actual receiving original and both typed
//! partial sinks. This DATA interface neither observes native state nor grants
//! effects, IO, currentness or a replacement validator.

use super::*;

/// Adds one concrete, pure schema partial destination to ordinary schema DATA.
///
/// This extension does not alter the canonical record format or grant physical
/// observation, effects, currentness or receiving capacity. Implementations must
/// use the same schema validator and semantic ordering as their ordinary phase
/// decoder, retaining their actual concrete parser prefixes on failure.
pub trait ProtectedDomainSchemaReplayCaptureV1: ProtectedDomainSchemaV1 {
    /// Owns that schema's concrete typed partial models without a journal grant.
    type ReplayCapture;

    /// Derives the same companion tuple at its original pre-phase frontier.
    ///
    /// Schemas with a parsing tuple implementation may retain that actual
    /// prefix here and reuse its complete model for the following phase check.
    fn semantic_tuple_retaining_v1(
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
        _capture: &mut Self::ReplayCapture,
    ) -> Option<[u8; 32]> {
        Self::semantic_tuple(kind, identity, body)
    }

    /// Decodes the same reducer phase while retaining its schema-owned prefix.
    fn decode_reducer_phase_retaining_v1(
        validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
        capture: &mut Self::ReplayCapture,
    ) -> Option<ProtectedReducerPhaseV1>;
}

pub(in crate::domain_ledger::records) trait SchemaReplayDispositionV1<S: ProtectedDomainSchemaV1> {
    fn semantic_tuple(&mut self, kind: S::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]>;

    fn decode_phase(
        &mut self,
        validator: &S::ReplayValidator,
        kind: S::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1>;
}

pub(in crate::domain_ledger::records) struct OrdinarySchemaReplayV1;

impl<S: ProtectedDomainSchemaV1> SchemaReplayDispositionV1<S> for OrdinarySchemaReplayV1 {
    fn semantic_tuple(&mut self, kind: S::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        S::semantic_tuple(kind, identity, body)
    }

    fn decode_phase(
        &mut self, validator: &S::ReplayValidator, kind: S::Kind,
        identity: &[u8], body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        S::decode_reducer_phase(validator, kind, identity, body)
    }
}

pub(super) struct RetainedSchemaReplayV1<'capture, S: ProtectedDomainSchemaReplayCaptureV1>(
    pub(super) &'capture mut S::ReplayCapture,
);

impl<S: ProtectedDomainSchemaReplayCaptureV1> SchemaReplayDispositionV1<S>
    for RetainedSchemaReplayV1<'_, S>
{
    fn semantic_tuple(&mut self, kind: S::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        S::semantic_tuple_retaining_v1(kind, identity, body, self.0)
    }

    fn decode_phase(
        &mut self, validator: &S::ReplayValidator, kind: S::Kind,
        identity: &[u8], body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        S::decode_reducer_phase_retaining_v1(validator, kind, identity, body, self.0)
    }
}

/// Replays identical canonical framing with the schema's actual typed sink.
///
/// The same caller owns and prepays both partial destinations. This function
/// constructs no allowance or effect callback; only pure schema decoding uses
/// the associated sink, at the exact existing reducer-validation position.
///
/// # Errors
/// Retains the portable failure and rejects reentry. The caller separately
/// projects its original typed schema cause before a coarse portable marker.
pub fn replay_projection_records_with_schema_capture_v1<'records, S: ProtectedDomainSchemaReplayCaptureV1>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
    validator: &S::ReplayValidator,
    capture: &mut ReplayProjectionRecordsCaptureV1<S>,
    schema_capture: &mut S::ReplayCapture,
) -> Result<(), DomainLedgerDataError> {
    if capture.entered {
        capture.closed.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    capture.entered = true;
    capture.completion = Some(match replay(records, validator, &mut capture.work, &mut RetainedSchemaReplayV1::<S>(schema_capture)) {
        Ok(projection) => {
            capture.projection = Some(projection);
            Ok(())
        }
        Err(cause) => Err(cause),
    });
    if matches!(capture.completion, Some(Ok(()))) {
        Ok(())
    } else {
        Err(DomainLedgerDataError::NonCanonicalRecord)
    }
}

/// Decodes identical reducer framing with its concrete associated schema sink.
///
/// # Errors
/// Retains generic decoder failures and refuses reentry. The actual caller also
/// retains and projects its concrete schema prefix under the same original.
pub fn decode_reducer_payload_with_schema_capture_v1<S: ProtectedDomainSchemaReplayCaptureV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &[u8],
    validator: &S::ReplayValidator,
    capture: &mut ReducerPayloadDecodeCaptureV1,
    schema_capture: &mut S::ReplayCapture,
) -> Result<(), DomainLedgerDataError> {
    if capture.entered {
        capture.closed.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    capture.entered = true;
    capture.completion = Some(match decode_reducer_into_work(
        key, bytes, validator,
        &mut capture.derived, &mut capture.encoded_derived, &mut capture.companions,
        &mut RetainedSchemaReplayV1::<S>(schema_capture),
    ) {
        Some((phase, body)) => {
            capture.phase = Some(phase);
            capture.body = Some(body);
            Ok(())
        }
        None => Err(DomainLedgerDataError::NonCanonicalRecord),
    });
    if matches!(capture.completion, Some(Ok(()))) {
        Ok(())
    } else {
        Err(DomainLedgerDataError::NonCanonicalRecord)
    }
}
