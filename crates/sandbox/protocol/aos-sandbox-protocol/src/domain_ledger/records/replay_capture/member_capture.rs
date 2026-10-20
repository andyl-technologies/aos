//! Retains durable-member results from the sole bounded consuming codec engine.
//!
//! The associated schema sink owns concrete schema prefixes. This DATA owner
//! contains no native Journal, payer, signature authority or currentness grant.

use super::*;

/// Keeps the completed member or actual portable error from one decode.
///
/// Decoding uses the existing member engine. A caller retains its concrete
/// schema sink and input independently through later comparisons.
#[must_use = "retain this owner and the actual schema sink through caller posts"]
pub struct DurableMemberCaptureV1<S: ProtectedDomainSchemaV1> {
    member: Option<DurableDomainMemberV1<S>>,
    completion: Option<Result<(), DomainLedgerDataError>>,
    closed: Option<DomainLedgerDataError>,
    entered: bool,
}

impl<S: ProtectedDomainSchemaV1> DurableMemberCaptureV1<S> {
    /// Creates empty storage without allocating or validating an input.
    #[must_use]
    pub const fn new() -> Self {
        Self { member: None, completion: None,
            closed: None, entered: false }
    }

    /// Borrows the original portable cause before any later repeated entry.
    #[must_use]
    pub fn failure(&self) -> Option<&DomainLedgerDataError> {
        self.completion.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows the completed actual member for the caller's later comparisons.
    #[must_use]
    pub fn member(&self) -> Option<&DurableDomainMemberV1<S>> {
        if self.failure().is_none() { self.member.as_ref() } else { None }
    }

    /// Bounds this owner's actual construction and codec control temporaries.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<borrowed::DurableMemberFrameDataV1<'_>>().checked_mul(2)?)?
            .checked_add(size_of::<borrowed::ProtectedEnvelopeFrameDataV1<'_>>().checked_mul(2)?)?
            .checked_add(size_of::<borrowed::ReducerFrameDataV1<'_>>().checked_mul(2)?)?
            .checked_add(size_of::<MemberDecodeWorkV1<S>>().checked_mul(2)?)?
            .checked_add(size_of::<DurableDomainMemberV1<S>>().checked_mul(2)?)?
            .checked_add(size_of::<ProtectedDomainEnvelopeV1<S>>().checked_mul(2)?)?
            .checked_add(size_of::<ProtectedDomainKeyV1<S>>())?
            .checked_add(size_of::<Result<DurableDomainMemberV1<S>, DomainLedgerDataError>>())?
            .checked_add(size_of::<Result<ProtectedDomainEnvelopeV1<S>, DomainLedgerDataError>>())?
            .checked_add(size_of::<Sha256>().checked_mul(2)?)?
            .checked_add(size_of::<[u8; 32]>().checked_mul(4)?)?
            .checked_add(size_of::<[u8; 16]>())?
            .checked_add(size_of::<Option<ObjectDigest>>())?
            .checked_add(size_of::<Option<ProtectedReducerPhaseV1>>())?
            .checked_add(size_of::<S::Kind>())?
            .checked_add(size_of::<usize>().checked_mul(4)?)?
            .checked_add(size_of::<u16>().checked_mul(2)?)?
            .checked_add(size_of::<u64>())?
            .checked_add(size_of::<u32>())?
            .checked_add(size_of::<Vec<u8>>())?
            .checked_add(size_of::<&[u8]>().checked_mul(3)?)?
            .checked_add(size_of::<&mut Self>())?
            .checked_add(size_of::<&S::ReplayValidator>())?
            .checked_add(size_of::<&ProtectedDomainEnvelopeV1<S>>())
    }

    /// Bounds byte copies by the actual supplied key and durable-member widths.
    ///
    /// Payload, roundtrip, inner, durable and companion encodings remain separate;
    /// the caller separately pays the associated schema's typed destinations.
    #[must_use]
    pub const fn receiving_encoded_backing_bytes_v1(key_bytes: usize, member_bytes: usize) -> Option<usize> {
        let member = match member_bytes.checked_mul(8) { Some(bytes) => bytes, None => return None };
        match key_bytes.checked_mul(2) { Some(key) => member.checked_add(key), None => None }
    }

    fn begin(&mut self) -> Result<(), DomainLedgerDataError> {
        if self.entered {
            self.closed.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        self.entered = true;
        Ok(())
    }

    fn finish(&mut self, result: Result<DurableDomainMemberV1<S>, DomainLedgerDataError>) -> Result<(), DomainLedgerDataError> {
        self.completion = Some(match result {
            Ok(member) => { self.member = Some(member); Ok(()) }
            Err(cause) => Err(cause),
        });
        if matches!(self.completion, Some(Ok(()))) { Ok(()) }
        else { Err(DomainLedgerDataError::NonCanonicalRecord) }
    }
}

impl<S: ProtectedDomainSchemaV1> Default for DurableMemberCaptureV1<S> {
    fn default() -> Self { Self::new() }
}

/// Decodes the original durable-member engine with the actual schema destination.
///
/// # Errors
/// Retains the first returned portable failure or completed member; repeated
/// entry refuses. Bounded codec work is consumed locally. Concrete schema
/// observations remain in the caller's same separate sink.
pub fn decode_durable_member_with_schema_capture_v1<S: ProtectedDomainSchemaReplayCaptureV1>(
    key: ProtectedDomainKeyV1<S>, bytes: &[u8], validator: &S::ReplayValidator,
    capture: &mut DurableMemberCaptureV1<S>, schema_capture: &mut S::ReplayCapture,
) -> Result<(), DomainLedgerDataError> {
    capture.begin()?;
    // The caller owns raw input and the actual schema sink. The prepaid
    // byte bound covers this same engine's temporary work, which installs no
    // namespace entries and need not outlive the returned member/error.
    let mut work = MemberDecodeWorkV1::<S>::new();
    let result = decode_member(key, bytes, validator, &mut work,
        &mut schema::RetainedSchemaReplayV1::<S>(schema_capture));
    capture.finish(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{Schema, SchemaOriginals};

    fn envelope() -> ProtectedDomainEnvelopeV1<Schema> {
        let key = ProtectedDomainKeyV1::<Schema>::new(1, vec![2]).unwrap();
        let payload = encode_reducer_payload_with_validator(&key, b"body0001", &true).unwrap();
        ProtectedDomainEnvelopeV1::new_with_validator(key, 1, None, payload, &true).unwrap()
    }

    fn member() -> DurableDomainMemberV1<Schema> {
        let envelope = envelope();
        let set = domain_transaction_set_digest::<Schema>([7; 16], std::slice::from_ref(&envelope));
        encode_durable_member([7; 16], 0, 1, set, envelope).unwrap()
    }

    #[test]
    fn later_envelope_digest_refusal_keeps_the_returned_error_and_original_input() {
        let original = member();
        let mut bytes = original.encoded().to_vec();
        let inner_digest_last = bytes.len() - 33;
        bytes[inner_digest_last] ^= 1;
        let end = bytes.len() - 32;
        let outer: [u8; 32] = Sha256::new().chain_update(Schema::HASH_DOMAIN)
            .chain_update(b"durable-member\0").chain_update(&bytes[..end]).finalize().into();
        bytes[end..].copy_from_slice(&outer);
        assert!(decode_durable_member(original.envelope().key().clone(), &bytes, &true).is_err());

        let input = bytes.clone();
        let mut capture = DurableMemberCaptureV1::<Schema>::new();
        let mut schema = SchemaOriginals::default();
        assert!(decode_durable_member_with_schema_capture_v1(original.envelope().key().clone(),
            &bytes, &true, &mut capture, &mut schema).is_err());
        assert_eq!(bytes, input);
        assert!(capture.member().is_none());
        let cause = capture.failure().unwrap() as *const _;
        assert!(matches!(capture.failure(), Some(DomainLedgerDataError::NonCanonicalRecord)));

        assert!(decode_durable_member_with_schema_capture_v1(original.envelope().key().clone(),
            original.encoded(), &true, &mut capture, &mut schema).is_err());
        assert_eq!(capture.failure().unwrap() as *const _, cause);
        assert_eq!(bytes, input);
        assert!(capture.member().is_none());
    }

    #[test]
    fn original_schema_refusal_keeps_returned_error_and_same_caller_owned_input() {
        let original = member();
        assert!(decode_durable_member(original.envelope().key().clone(), original.encoded(), &false).is_err());
        let mut capture = DurableMemberCaptureV1::<Schema>::new();
        let mut schema = SchemaOriginals::default();

        assert!(decode_durable_member_with_schema_capture_v1(original.envelope().key().clone(),
            original.encoded(), &false, &mut capture, &mut schema).is_err());
        assert!(capture.member().is_none());
        assert!(matches!(capture.failure(), Some(DomainLedgerDataError::NonCanonicalRecord)));
        assert!(decode_durable_member(original.envelope().key().clone(), original.encoded(), &true).is_ok());
        assert!(capture.failure().is_some());
    }

    #[test]
    fn ordinary_encoder_still_rejects_an_invalid_transaction_identity() {
        assert!(matches!(encode_durable_member([0; 16], 0, 1,
            ObjectDigest::from_bytes([7; 32]), envelope()),
            Err(DomainLedgerDataError::NonCanonicalRecord)));
    }

    #[test]
    fn completed_member_matches_ordinary_without_an_unused_move_out_port() {
        let original = member();
        let mut capture = DurableMemberCaptureV1::<Schema>::new();
        let mut schema = SchemaOriginals::default();
        decode_durable_member_with_schema_capture_v1(original.envelope().key().clone(),
            original.encoded(), &true, &mut capture, &mut schema).unwrap();
        assert_eq!(capture.member().unwrap().encoded(), original.encoded());
        let encoding = capture.member().unwrap().encoded().as_ptr();
        assert_eq!(capture.member().unwrap().envelope(), original.envelope());
        assert_eq!(capture.member().unwrap().encoded().as_ptr(), encoding);
        assert!(capture.failure().is_none());

        assert!(decode_durable_member_with_schema_capture_v1(original.envelope().key().clone(),
            original.encoded(), &true, &mut capture, &mut schema).is_err());
        assert!(capture.member().is_none());
        assert_eq!(capture.member.as_ref().unwrap().encoded().as_ptr(), encoding);
        assert!(DurableMemberCaptureV1::<Schema>::receiving_construction_bytes_v1().is_some());
        assert!(DurableMemberCaptureV1::<Schema>::receiving_encoded_backing_bytes_v1(usize::MAX, 1).is_none());
    }
}
