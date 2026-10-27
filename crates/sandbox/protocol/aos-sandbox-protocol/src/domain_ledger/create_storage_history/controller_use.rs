//! Carries the original signed, dispatch-bound and Session-reserved C rows.
//!
//! ```text
//! Signed = AOSXCS01 | UseAdmitted-receipt[460] | bundle-length:u32be | bundle
//! DispatchBound[444] = AOSXCD01 | Signed-checksum[32] | SignedBound-receipt[404]
//! SessionReserved[272] = AOSXCR01 | DispatchBound[32] | Session[32] |
//!   request-id[16] | signed-request[32] | client-sequence:u64be |
//!   generation:u64be | head[32] | revision:u64be | commitment[32] |
//!   physical-names[48] | NEXT:u64be | end:u64be
//! ```
//!
//! All fields are comparison DATA. Native producers must borrow the genuine
//! completed U, Root turn and same Session commit/readback owners continuously.
//! No decoder returns a writer, paid grant, signing key or dispatch permission.

use sha2::{Digest as _, Sha256};
use super::{HistoryErrorV1, nonzero, reader};
use super::super::protected_names::ProtectedJournalNamesV1;
use super::continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1,
    SignedBoundBodyDataV1, SignedPreparationBundleDataV1, UseAdmittedBodyDataV1,
    USE_ADMITTED_RECEIPT_BYTES_V1, SIGNED_BOUND_RECEIPT_BYTES_V1};

/// Specifies the fixed prefix before the actual canonical three-field bundle.
pub const SIGNED_BODY_PREFIX_BYTES_V1: usize = 8 + USE_ADMITTED_RECEIPT_BYTES_V1 + 4;
/// Specifies the complete fixed Controller dispatch-binding body width.
pub const DISPATCH_BOUND_BODY_BYTES_V1: usize = 8 + 32 + SIGNED_BOUND_RECEIPT_BYTES_V1;
/// Specifies the complete fixed Controller Session-reservation body width.
pub const SESSION_RESERVED_BODY_BYTES_V1: usize = 272;

/// Borrows the original admitted-use receipt and completed signed bundle.
#[derive(Clone, Copy)]
pub struct ControllerSignedBodyDataV1<'bytes> {
    /// The real Root revision-three receipt retained before signing.
    pub admitted: ContinuationNativeReceiptDataV1<'bytes>,
    /// The actual encoded plan/signature/Prepare-body bundle, without rebuilding.
    pub bundle: &'bytes [u8],
}

impl<'bytes> ControllerSignedBodyDataV1<'bytes> {
    /// Decodes bounded exact framing and the unsigned-plan admission join.
    ///
    /// # Errors
    /// Rejects malformed receipt/bundle framing or a substituted admitted plan.
    pub fn decode(bytes: &'bytes [u8], lane: [u8; 16], request_shape: usize)
        -> Result<Self, HistoryErrorV1>
    {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXCS01" { return Err(HistoryErrorV1::Malformed); }
        let admitted = ContinuationNativeReceiptDataV1::decode(
            input.bytes(USE_ADMITTED_RECEIPT_BYTES_V1)?, lane, ContinuationKindV1::UseAdmitted)?;
        let length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
        let value = Self { admitted, bundle: input.bytes(length)? };
        input.finish()?;
        value.bundle_data_v1(lane, request_shape)?;
        Ok(value)
    }

    /// Borrows the same bundle and checks its plan against the admitted bytes.
    ///
    /// # Errors
    /// Rejects invalid bounds, receipt framing or a changed canonical plan hash.
    pub fn bundle_data_v1(self, lane: [u8; 16], request_shape: usize)
        -> Result<SignedPreparationBundleDataV1<'bytes>, HistoryErrorV1>
    {
        let record = self.admitted.record_data(lane, ContinuationKindV1::UseAdmitted)?;
        let admitted = UseAdmittedBodyDataV1::decode(record.body())?;
        let bundle = SignedPreparationBundleDataV1::decode(self.bundle, [request_shape; 3])?;
        if <[u8; 32]>::from(Sha256::digest(bundle.plan)) != admitted.unsigned_plan {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(bundle)
    }

    /// Measures the exact body without introducing a configured transfer cap.
    ///
    /// # Errors
    /// Rejects a wire-width excess or checked total-size overflow.
    pub fn encoded_bytes(self) -> Result<usize, HistoryErrorV1> {
        u32::try_from(self.bundle.len()).map_err(|_| HistoryErrorV1::Extent)?;
        SIGNED_BODY_PREFIX_BYTES_V1.checked_add(self.bundle.len()).ok_or(HistoryErrorV1::Extent)
    }

    /// Copies only original admitted/signed bytes into prepaid exact storage.
    ///
    /// # Errors
    /// Rejects substituted DATA, invalid bounds or a nonexact destination width.
    pub fn encode_into(self, lane: [u8; 16], request_shape: usize, output: &mut [u8])
        -> Result<(), HistoryErrorV1>
    {
        self.bundle_data_v1(lane, request_shape)?;
        if output.len() != self.encoded_bytes()? { return Err(HistoryErrorV1::Extent); }
        output[..8].copy_from_slice(b"AOSXCS01");
        let end = 8 + USE_ADMITTED_RECEIPT_BYTES_V1;
        self.admitted.encode_into(lane, ContinuationKindV1::UseAdmitted, &mut output[8..end])?;
        output[end..end + 4].copy_from_slice(&(self.bundle.len() as u32).to_be_bytes());
        output[end + 4..].copy_from_slice(self.bundle);
        Ok(())
    }
}

/// Borrows Root's actual binding of the same signed result before dispatch.
#[derive(Clone, Copy)]
pub struct ControllerDispatchBoundBodyDataV1<'bytes> {
    /// The actual Controller revision-six Signed record checksum.
    pub signed: [u8; 32],
    /// The original Root revision-four SignedBound receipt.
    pub bound: ContinuationNativeReceiptDataV1<'bytes>,
}

impl<'bytes> ControllerDispatchBoundBodyDataV1<'bytes> {
    /// Decodes the exact fixed dispatch binding under its closed Root purpose.
    ///
    /// # Errors
    /// Rejects wrong framing, zero Signed identity or invalid Root receipt DATA.
    pub fn decode(bytes: &'bytes [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXCD01" { return Err(HistoryErrorV1::Malformed); }
        let signed = input.array()?;
        nonzero(&signed)?;
        let bound = ContinuationNativeReceiptDataV1::decode(
            input.bytes(SIGNED_BOUND_RECEIPT_BYTES_V1)?, lane, ContinuationKindV1::SignedBound)?;
        input.finish()?;
        Ok(Self { signed, bound })
    }

    /// Encodes the same original Root receipt without changing its native cut.
    ///
    /// # Errors
    /// Rejects zero Signed identity or invalid Root receipt DATA.
    pub fn encode(self, lane: [u8; 16]) -> Result<[u8; DISPATCH_BOUND_BODY_BYTES_V1], HistoryErrorV1> {
        nonzero(&self.signed)?;
        let mut output = [0; DISPATCH_BOUND_BODY_BYTES_V1];
        output[..8].copy_from_slice(b"AOSXCD01");
        output[8..40].copy_from_slice(&self.signed);
        self.bound.encode_into(lane, ContinuationKindV1::SignedBound, &mut output[40..])?;
        Ok(output)
    }

    /// Checks Root's exact signed-result hashes against the retained C bundle.
    ///
    /// # Errors
    /// Rejects a changed bundle, canonical plan, signature or Prepare body.
    pub fn require_signed_v1(self, signed: ControllerSignedBodyDataV1<'_>,
        lane: [u8; 16], request_shape: usize,
    ) -> Result<(), HistoryErrorV1> {
        let bundle = signed.bundle_data_v1(lane, request_shape)?;
        let bound = SignedBoundBodyDataV1::decode(
            self.bound.record_data(lane, ContinuationKindV1::SignedBound)?.body())?;
        bundle.require_bound(bound)
    }
}

/// Records actual request reservation and its confirmed same-Session position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerSessionReservedBodyDataV1 {
    /// The actual preceding Controller DispatchBound checksum.
    pub dispatch_bound: [u8; 32],
    /// The actual signed narrow Session binding.
    pub session_binding: [u8; 32],
    /// The real protected request identifier.
    pub request_id: [u8; 16],
    /// The authenticated canonical request's signed digest.
    pub signed_request: [u8; 32],
    /// The request's actual client sequence, without renewal.
    pub client_sequence: u64,
    /// The generation from the actual stored request readback.
    pub generation: u64,
    /// The actual stored history head after request reservation.
    pub head: [u8; 32],
    /// The actual durable request-record revision.
    pub revision: u64,
    /// The actual durable request-record commitment.
    pub commitment: [u8; 32],
    /// The same held Session journal's actual physical-name coordinates.
    pub names: ProtectedJournalNamesV1,
    /// The actual readback NEXT, never a proposed increment.
    pub after_next: u64,
    /// The actual durable native end after request readback.
    pub after_end: u64,
}

impl ControllerSessionReservedBodyDataV1 {
    /// Decodes the fixed request-reservation DATA without granting dispatch.
    ///
    /// # Errors
    /// Rejects malformed framing or absent record/native comparison identities.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXCR01" { return Err(HistoryErrorV1::Malformed); }
        let value = Self { dispatch_bound: input.array()?, session_binding: input.array()?,
            request_id: input.array()?, signed_request: input.array()?, client_sequence: input.u64()?,
            generation: input.u64()?, head: input.array()?, revision: input.u64()?,
            commitment: input.array()?, names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            after_next: input.u64()?, after_end: input.u64()? };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }

    /// Encodes original confirmed request coordinates into fixed storage.
    ///
    /// # Errors
    /// Rejects zero request/history identities or absent native position DATA.
    pub fn encode(self) -> Result<[u8; SESSION_RESERVED_BODY_BYTES_V1], HistoryErrorV1> {
        nonzero(&self.request_id)?;
        for field in [self.dispatch_bound, self.session_binding, self.signed_request,
            self.head, self.commitment] { nonzero(&field)?; }
        if self.generation == 0 || self.revision == 0 || self.after_next == 0 || self.after_end == 0 {
            return Err(HistoryErrorV1::Extent);
        }
        let mut output = [0; SESSION_RESERVED_BODY_BYTES_V1];
        let mut offset = 0;
        for bytes in [b"AOSXCR01".as_slice(), &self.dispatch_bound, &self.session_binding,
            &self.request_id, &self.signed_request, &self.client_sequence.to_be_bytes(),
            &self.generation.to_be_bytes(), &self.head, &self.revision.to_be_bytes(),
            &self.commitment, &self.names.to_bytes(), &self.after_next.to_be_bytes(),
            &self.after_end.to_be_bytes()] {
            output[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
        RecordCoordinatesV1, RecordEnvelopeV1, RECORD_OVERHEAD_BYTES};

    fn receipt_record(revision: u64, phase: u8, body: &[u8]) -> (Vec<u8>, [u8; 40]) {
        let mut record = vec![0; RECORD_OVERHEAD_BYTES + body.len()];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new([7; 16], OwnerV1::Root, revision).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, phase).unwrap(),
            predecessor: [8; 32], correlation: [9; 32],
        }, body, &mut record).unwrap();
        (record, LatestHeadV1::new(revision, checksum).unwrap().encode())
    }

    fn receipt<'a>(record: &'a [u8], latest_head: [u8; 40]) -> ContinuationNativeReceiptDataV1<'a> {
        ContinuationNativeReceiptDataV1 { record, latest_head,
            names: ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap(),
            after_next: 13, after_end: 8192 }
    }

    #[test]
    fn signed_row_retains_original_bundle_and_refuses_substituted_plan() {
        let bundle = SignedPreparationBundleDataV1 { plan: b"original-plan",
            signature: b"original-signature", request_body: b"original-request" };
        let mut packet = vec![0; bundle.encoded_bytes().unwrap()];
        bundle.encode_into(&mut packet).unwrap();
        let body = UseAdmittedBodyDataV1 { use_reserved: [1; 32], current_proofs: [2; 32],
            source_current: [3; 32], cache_current: [4; 32], use_claim: [5; 16],
            unsigned_plan: Sha256::digest(bundle.plan).into(), signing_statement: [6; 32] };
        let (record, head) = receipt_record(3, 3, &body.encode().unwrap());
        let signed = ControllerSignedBodyDataV1 { admitted: receipt(&record, head), bundle: &packet };
        let mut encoded = vec![0; signed.encoded_bytes().unwrap()];

        signed.encode_into([7; 16], 128, &mut encoded).unwrap();
        let decoded = ControllerSignedBodyDataV1::decode(&encoded, [7; 16], 128).unwrap();

        assert_eq!(decoded.bundle.as_ptr(), encoded[SIGNED_BODY_PREFIX_BYTES_V1..].as_ptr());
        assert_eq!(decoded.bundle, packet);
        assert!(ControllerSignedBodyDataV1::decode(&encoded, [7; 16], 3).is_err());
        let last = encoded.len() - b"original-request".len() - b"original-signature".len() - 1;
        encoded[last] ^= 1;
        assert!(ControllerSignedBodyDataV1::decode(&encoded, [7; 16], 128).is_err());
    }

    #[test]
    fn dispatch_binding_reuses_all_signed_bundle_checks() {
        let bundle = SignedPreparationBundleDataV1 { plan: b"plan",
            signature: b"signature", request_body: b"request" };
        let mut packet = vec![0; bundle.encoded_bytes().unwrap()];
        bundle.encode_into(&mut packet).unwrap();
        let admitted = UseAdmittedBodyDataV1 { use_reserved: [1; 32], current_proofs: [2; 32],
            source_current: [3; 32], cache_current: [4; 32], use_claim: [5; 16],
            unsigned_plan: Sha256::digest(bundle.plan).into(), signing_statement: [6; 32] };
        let (admitted_record, admitted_head) = receipt_record(3, 3, &admitted.encode().unwrap());
        let signed = ControllerSignedBodyDataV1 { admitted: receipt(&admitted_record, admitted_head), bundle: &packet };
        let bound = SignedBoundBodyDataV1 { bundle: bundle.commitment().unwrap(),
            bundle_bytes: bundle.encoded_bytes().unwrap() as u64, request_id: [6; 16],
            request_body: Sha256::digest(bundle.request_body).into(),
            plan: Sha256::digest(bundle.plan).into(), signature: Sha256::digest(bundle.signature).into() };
        let (record, head) = receipt_record(4, 4, &bound.encode().unwrap());
        let dispatch = ControllerDispatchBoundBodyDataV1 { signed: [10; 32], bound: receipt(&record, head) };

        let encoded = dispatch.encode([7; 16]).unwrap();
        let decoded = ControllerDispatchBoundBodyDataV1::decode(&encoded, [7; 16]).unwrap();

        decoded.require_signed_v1(signed, [7; 16], 128).unwrap();
        let changed = SignedBoundBodyDataV1 { signature: [11; 32], ..bound };
        let (record, head) = receipt_record(4, 4, &changed.encode().unwrap());
        assert!(ControllerDispatchBoundBodyDataV1 { signed: [10; 32], bound: receipt(&record, head) }
            .require_signed_v1(signed, [7; 16], 128).is_err());
        assert!(ControllerDispatchBoundBodyDataV1::decode(&encoded[..encoded.len() - 1], [7; 16]).is_err());
    }

    #[test]
    fn session_reserved_preserves_actual_readback_and_rejects_missing_native_end() {
        let data = ControllerSessionReservedBodyDataV1 { dispatch_bound: [1; 32], session_binding: [2; 32],
            request_id: [3; 16], signed_request: [4; 32], client_sequence: 17,
            generation: 11, head: [5; 32], revision: 29, commitment: [6; 32],
            names: ProtectedJournalNamesV1::from_bytes(&[7; 48]).unwrap(), after_next: 38, after_end: 9999 };

        let encoded = data.encode().unwrap();

        assert_eq!(encoded.len(), 272);
        assert_eq!(ControllerSessionReservedBodyDataV1::decode(&encoded).unwrap(), data);
        for end in 0..encoded.len() {
            assert!(ControllerSessionReservedBodyDataV1::decode(&encoded[..end]).is_err());
        }
        assert!(ControllerSessionReservedBodyDataV1 { after_end: 0, ..data }.encode().is_err());
    }
}
