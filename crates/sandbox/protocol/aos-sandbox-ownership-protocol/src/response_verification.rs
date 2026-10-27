//! Retains actual issuer response verification through all later comparisons.
//!
//! Every positive model still comes from the existing verifier and its supplied
//! trust anchor. These destinations cannot supply a key, clock, permit or payer.

use super::*;
use aos_sandbox_model::format::authorization_capture::{SignatureDecodeCaptureV1, decode_signature_retaining_v1};
use aos_sandbox_model::ownership_lease::retained::{OwnershipLeaseVerificationCaptureV1,
    OwnershipReceiptVerificationCaptureV1, verify_ownership_lease_retaining_v1,
    verify_ownership_receipt_signature_retaining_v1};
use aos_sandbox_model::model::Signature;

pub(crate) mod receipt;

#[derive(Default)]
struct ResponseWorkV1 {
    response: Option<UnverifiedOwnershipLeaseResponse>,
    signature_decode: SignatureDecodeCaptureV1,
    signature: Option<Signature>,
    signature_canonical: Vec<u8>,
    lease_verification: OwnershipLeaseVerificationCaptureV1,
    ordinary_verified: Option<aos_sandbox_model::VerifiedOwnershipLease>,
    claim_binding: Option<Result<(), OwnershipLeaseAcquisitionError>>,
    receipt_decode: receipt::ReceiptDecodeWorkV1,
    receipt_result: Option<Result<OwnershipTransactionReceiptV1, OwnershipReceiptError>>,
    context: receipt::ReceiptContextWorkV1,
    receipt_context: Option<Result<(), OwnershipReceiptError>>,
    receipt_signature_decode: SignatureDecodeCaptureV1,
    receipt_signature: Option<Signature>,
    receipt_signature_canonical: Vec<u8>,
    receipt_verification: OwnershipReceiptVerificationCaptureV1,
}

/// Owns the actual quartet, partial models, crypto outcomes and verified result.
#[derive(Default)]
pub struct OwnershipResponseVerifyCaptureV1 {
    work: ResponseWorkV1,
    transport: Option<Result<(), OwnershipLeaseAcquisitionError>>,
    result: Option<Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError>>,
    entered: bool,
    repeated: bool,
    taken: bool,
}

impl OwnershipResponseVerifyCaptureV1 {
    /// Creates inert destinations without acquiring trust or verification authority.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the returned verifier classification without dropping its owner.
    #[must_use]
    pub fn failure(&self) -> Option<&OwnershipLeaseAcquisitionError> {
        self.transport.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()))
    }

    /// Borrows the actual reached canonical, context or native crypto cause.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(result: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)> {
            result.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        error(&self.transport).or_else(|| self.work.signature_decode.cause())
            .or_else(|| self.work.lease_verification.failure())
            .or_else(|| error(&self.work.claim_binding)).or_else(|| error(&self.work.receipt_result))
            .or_else(|| error(&self.work.receipt_context)).or_else(|| self.work.receipt_signature_decode.cause())
            .or_else(|| self.work.receipt_verification.failure()).or_else(|| error(&self.result))
    }

    /// Borrows the complete existing verified result after all receipt checks.
    #[must_use]
    pub fn value(&self) -> Option<&SignedOwnershipLease> {
        if self.repeated { return None; }
        self.result.as_ref()?.as_ref().ok()
    }

    /// Borrows the same receipt only after complete response verification.
    ///
    /// The receipt remains beside the actual verified lease and crypto work.
    /// This borrow performs no decode or IO and grants no currentness, trust
    /// or effect authority beyond the existing completed verification result.
    #[must_use]
    pub fn verified_receipt_v1(&self) -> Option<&OwnershipTransactionReceiptV1> {
        self.value()?;
        self.work.receipt_result.as_ref()?.as_ref().ok()
    }

    /// Transfers the actual completed result once, preserving negative owners.
    #[must_use]
    pub fn take_value_once(&mut self) -> Option<SignedOwnershipLease> {
        if self.taken || self.repeated || !matches!(self.result, Some(Ok(_))) { return None; }
        self.taken = true;
        self.result.take()?.ok()
    }
}

pub(super) fn verify_response_ordinary(
    verifier: &OwnershipAuthorityVerifier, claim: &OwnershipClaimV1,
    response: UnverifiedOwnershipLeaseResponse, clock: &RawPairedClockSample,
) -> Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError> {
    verify_response_engine(verifier, claim, response, clock, None)
}

fn verify_response_engine(
    verifier: &OwnershipAuthorityVerifier, claim: &OwnershipClaimV1,
    response: UnverifiedOwnershipLeaseResponse, clock: &RawPairedClockSample,
    capture: Option<&mut ResponseWorkV1>,
) -> Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError> {
    let selected = capture.is_some();
    let mut work = aos_sandbox_model::retained::CaptureValueV1::new(ResponseWorkV1::default(), capture);
    work.response = Some(response);
    verify_response_work(verifier, claim, clock, &mut work, selected)
}

fn verify_response_work(verifier: &OwnershipAuthorityVerifier, claim: &OwnershipClaimV1,
    clock: &RawPairedClockSample, work: &mut ResponseWorkV1, selected: bool,
) -> Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError> {
    let response = work.response.as_ref().ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    work.signature = Some(if selected {
        decode_signature_retaining_v1(&response.signature, response_limits(), &mut work.signature_decode)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        work.signature_decode.take_model_once()
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
    } else {
        decode_signature(&response.signature, response_limits())
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
    });
    let signature = work.signature.as_ref().ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    {
        let canonical = aos_sandbox_model::retained::CaptureValueV1::new(encode_signature(signature),
            selected.then_some(&mut work.signature_canonical));
        if *canonical != response.signature {
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
    }
    let expectation = aos_sandbox_model::OwnershipLeaseExpectation {
        assignment: claim.broker_assignment()?, node: claim.node,
        ownership_authority: &verifier.authority, clock,
    };
    if selected {
        verify_ownership_lease_retaining_v1(&response.lease, signature, &verifier.anchor,
            expectation, response_limits(), &mut work.lease_verification)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    } else {
        work.ordinary_verified = Some(verify_ownership_lease(&response.lease, signature,
            &verifier.anchor, expectation, response_limits())
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?);
    }
    let verified = if selected { work.lease_verification.verified() }
        else { work.ordinary_verified.as_ref() }
        .ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    work.claim_binding = Some(validate_verified_response(claim, verified.lease()));
    work.claim_binding.as_ref().ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
        .as_ref().map_err(Clone::clone)?;

    work.receipt_result = Some(receipt::decode_receipt_engine(&response.receipt,
        selected.then_some(&mut work.receipt_decode)));
    match work.receipt_result.as_ref() {
        Some(Ok(_)) => {},
        _ => return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse),
    }
    let receipt = work.receipt_result.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    work.receipt_context = Some(receipt::verify_context_engine(receipt,
        &verifier.authority, claim, &response.lease, selected.then_some(&mut work.context)));
    if !matches!(work.receipt_context, Some(Ok(()))) {
        return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
    }
    work.receipt_signature = Some(if selected {
        decode_signature_retaining_v1(&response.receipt_signature, response_limits(),
            &mut work.receipt_signature_decode)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        work.receipt_signature_decode.take_model_once()
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
    } else {
        decode_signature(&response.receipt_signature, response_limits())
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
    });
    let receipt_signature = work.receipt_signature.as_ref()
        .ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    {
        let canonical = aos_sandbox_model::retained::CaptureValueV1::new(encode_signature(receipt_signature),
            selected.then_some(&mut work.receipt_signature_canonical));
        if *canonical != response.receipt_signature {
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
    }
    if selected {
        verify_ownership_receipt_signature_retaining_v1(receipt.canonical_bytes(), receipt_signature,
            &verifier.anchor, verified.lease().authority_issued_seconds(),
            verified.lease().authority_expires_seconds(), clock.wall_seconds(), response_limits(),
            &mut work.receipt_verification)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    } else {
        verify_ownership_transaction_receipt_signature(receipt.canonical_bytes(), receipt_signature,
            &verifier.anchor, verified.lease().authority_issued_seconds(),
            verified.lease().authority_expires_seconds(), clock.wall_seconds(), response_limits())
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    }
    let response = work.response.take().ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;

    Ok(SignedOwnershipLease {
        canonical_lease: response.lease,
        canonical_signature: response.signature,
        canonical_receipt: response.receipt,
        canonical_receipt_signature: response.receipt_signature,
        generation: verified.lease().lease_generation(),
        digest: verified.lease_digest(),
        assignment: verified.lease().assignment(),
        desired_generation: claim.desired_generation(),
        node: verified.lease().node(),
        authority_issued_seconds: verified.lease().authority_issued_seconds(),
        authority_expires_seconds: verified.lease().authority_expires_seconds(),
        maximum_clock_skew_seconds: verified.lease().maximum_clock_skew_seconds(),
        renewal_nonce: *verified.lease().renewal_nonce(),
        signer: signature.statement().signer().clone(),
    })
}

pub(super) fn validate_response_lengths(lease: &[u8], signature: &[u8], receipt: &[u8],
    receipt_signature: &[u8]) -> Result<(), OwnershipLeaseAcquisitionError> {
    if lease.is_empty()
        || lease.len() > MAXIMUM_LEASE_BYTES
        || signature.is_empty()
        || signature.len() > MAXIMUM_SIGNATURE_BYTES
        || receipt.is_empty()
        || receipt.len() > MAXIMUM_RECEIPT_BYTES
        || receipt_signature.is_empty()
        || receipt_signature.len() > MAXIMUM_SIGNATURE_BYTES
    {
        return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
    }
    Ok(())
}

impl OwnershipAuthorityVerifier {
    /// Runs the same verifier while keeping its actual reached models and causes.
    ///
    /// # Errors
    /// Preserves the ordinary returned classification and refuses repeated capture.
    pub fn verify_response_retaining_v1(&self, claim: &OwnershipClaimV1,
        response: UnverifiedOwnershipLeaseResponse, clock: &RawPairedClockSample,
        capture: &mut OwnershipResponseVerifyCaptureV1,
    ) -> Result<(), OwnershipLeaseAcquisitionError> {
        if capture.entered {
            capture.repeated = true;
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
        capture.entered = true;
        capture.result = Some(verify_response_engine(self, claim, response, clock, Some(&mut capture.work)));
        capture.result.as_ref().ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
            .as_ref().map(|_| ()).map_err(Clone::clone)
    }

    /// Checks actual quartet lengths before copying borrowed hostile wire fields.
    ///
    /// The caller keeps the original encoded input and prepays its actual copies.
    /// Neither length acceptance nor this capsule supplies trust or an account.
    ///
    /// # Errors
    /// Preserves the actual length or complete original verifier refusal.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_response_bytes_retaining_v1(&self, claim: &OwnershipClaimV1,
        lease: &[u8], signature: &[u8], receipt: &[u8], receipt_signature: &[u8],
        clock: &RawPairedClockSample, capture: &mut OwnershipResponseVerifyCaptureV1,
    ) -> Result<(), OwnershipLeaseAcquisitionError> {
        if capture.entered {
            capture.repeated = true;
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
        capture.entered = true;
        capture.transport = Some(validate_response_lengths(lease, signature, receipt, receipt_signature));
        capture.transport.as_ref().ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
            .as_ref().map_err(Clone::clone)?;
        let response = UnverifiedOwnershipLeaseResponse { lease: lease.to_vec(), signature: signature.to_vec(),
            receipt: receipt.to_vec(), receipt_signature: receipt_signature.to_vec() };
        capture.result = Some(verify_response_engine(self, claim, response, clock, Some(&mut capture.work)));
        capture.result.as_ref().ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?
            .as_ref().map(|_| ()).map_err(Clone::clone)
    }
}


/// Retains the existing fixed-width canonical claim parser's actual result.
///
/// Its reached pre-result fields are fixed arrays and integers, with no heap or
/// native originals. The actual caller keeps the encoded claim bytes resident.
#[derive(Default)]
pub struct OwnershipClaimDecodeCaptureV1 {
    result: Option<Result<OwnershipClaimV1, OwnershipClaimError>>,
    entered: bool,
    repeated: bool,
    taken: bool,
}

impl OwnershipClaimDecodeCaptureV1 {
    /// Creates an inert claim DATA destination without verifying ownership.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs the same fixed claim parser once and retains its whole returned result.
    ///
    /// # Errors
    /// Returns the original framing/semantic error and refuses repeated entry.
    pub fn decode_once_v1(&mut self, bytes: &[u8]) -> Result<(), OwnershipClaimError> {
        if self.entered { self.repeated = true; return Err(OwnershipClaimError::InvalidEncoding); }
        self.entered = true;
        self.result = Some(OwnershipClaimV1::from_canonical_bytes(bytes));
        self.result.as_ref().ok_or(OwnershipClaimError::InvalidEncoding)?
            .as_ref().map(|_| ()).map_err(Clone::clone)
    }

    /// Borrows the actual returned parser error before coarse upper projection.
    #[must_use]
    pub fn failure(&self) -> Option<&OwnershipClaimError> {
        self.result.as_ref()?.as_ref().err()
    }

    /// Borrows complete claim DATA while the real incoming bytes remain held.
    #[must_use]
    pub fn value(&self) -> Option<&OwnershipClaimV1> {
        if self.repeated { return None; }
        self.result.as_ref()?.as_ref().ok()
    }

    /// Moves complete claim DATA once, conferring no lease/receipt authority.
    #[must_use]
    pub fn take_value_once(&mut self) -> Option<OwnershipClaimV1> {
        if self.taken || self.repeated || !matches!(self.result, Some(Ok(_))) { return None; }
        self.taken = true;
        self.result.take()?.ok()
    }

    /// Bounds the actual fixed destination and its construction temporary.
    #[must_use]
    pub const fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)
    }

}

impl OwnershipResponseVerifyCaptureV1 {
    /// Bounds the compiled destination and one construction temporary.
    #[must_use]
    pub const fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)
    }
}

impl OwnershipAuthorityVerifier {
    /// Derives passive verification geometry from this exact retained trust anchor.
    ///
    /// The input bound must cover the actual co-resident incoming quartet. The
    /// caller pays its existing encoded input separately before parsing, and
    /// retains this same verifier and actual private receiving original.
    #[must_use]
    pub fn response_receiving_dynamic_bytes_v2(&self, actual_quartet_bytes: usize)
        -> Option<usize> {
        let core_bytes = aos_sandbox_model::ownership_lease::retained::
            verification_dynamic_bytes_v2(&self.anchor, actual_quartet_bytes)?;
        // Actual copied quartet, two canonical signature comparisons, receipt
        // canonical reconstruction and key/descriptor/comparison text backing.
        let body = actual_quartet_bytes.checked_mul(8)?
            .checked_add(SignatureDecodeCaptureV1::receiving_dynamic_bytes_v1(actual_quartet_bytes)?.checked_mul(2)?)?;
        let temporary = std::mem::size_of::<ResponseTemporariesV1>();
        let bytes = core_bytes.checked_add(body)?.checked_add(temporary)?;
        Some(bytes)
    }
}


// Actual extra decoder/return/borrow carriers, separate from the embedded owner.
// This compiled-layout supplier is never constructed and conveys no authority.
#[allow(dead_code)]
struct ResponseTemporariesV1 {
    work: ResponseWorkV1,
    returned: SignedOwnershipLease,
    receipt: receipt::ReceiptDecodeWorkV1,
    context: receipt::ReceiptContextWorkV1,
    lease_canonical: aos_sandbox_model::retained::CaptureValueV1<'static, Vec<u8>>,
    receipt_canonical: aos_sandbox_model::retained::CaptureValueV1<'static, Vec<u8>>,
    expectation: aos_sandbox_model::OwnershipLeaseExpectation<'static>,
    input: &'static UnverifiedOwnershipLeaseResponse,
}


#[cfg(test)]
mod tests;
