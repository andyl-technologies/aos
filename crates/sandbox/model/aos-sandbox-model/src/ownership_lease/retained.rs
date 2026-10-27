//! Retains actual lease and transaction-receipt verification intermediates.
//!
//! Construction is inert. Only the existing verifier can complete these
//! destinations using its actual supplied anchor and all original checks.

use super::*;
use crate::crypto::retained::SignatureVerificationCaptureV1;
use crate::crypto::VerifiedSignature;
use crate::format::authorization_capture::OwnershipLeaseDecodeCaptureV1;

/// Reports incomplete, repeated or already moved retained verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retained ownership verification is closed")]
pub struct OwnershipVerificationClosedV1;

#[derive(Default)]
pub(super) struct LeaseVerificationWorkV1 {
    pub(super) decode: OwnershipLeaseDecodeCaptureV1,
    pub(super) lease: Option<OwnershipLease>,
    pub(super) descriptor: Option<ObjectDescriptor>,
    pub(super) crypto: SignatureVerificationCaptureV1,
    pub(super) signature: Option<Result<VerifiedSignature, SignatureVerificationError>>,
}

#[derive(Default)]
pub(super) struct ReceiptVerificationWorkV1 {
    pub(super) descriptor: Option<ObjectDescriptor>,
    pub(super) crypto: SignatureVerificationCaptureV1,
    pub(super) signature: Option<Result<VerifiedSignature, SignatureVerificationError>>,
}

fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

/// Owns reached lease, descriptor, trust and cryptographic verification DATA.
#[derive(Default)]
pub struct OwnershipLeaseVerificationCaptureV1 {
    work: LeaseVerificationWorkV1,
    result: Option<Result<VerifiedOwnershipLease, OwnershipLeaseVerificationError>>,
    entered: bool,
    closed: Option<OwnershipVerificationClosedV1>,
    taken: bool,
}

impl OwnershipLeaseVerificationCaptureV1 {
    /// Creates inert destinations without an anchor, IO or verification grant.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the earliest actual canonical, native crypto or typed refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.work.decode.cause().or_else(|| self.work.crypto.failure())
            .or_else(|| error(&self.work.signature)).or_else(|| error(&self.result))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Borrows a completed verified lease, with its failed prefixes still owned.
    #[must_use]
    pub fn verified(&self) -> Option<&VerifiedOwnershipLease> {
        if self.closed.is_some() { return None; }
        self.result.as_ref()?.as_ref().ok()
    }

    /// Transfers the actual verified model once after all existing checks.
    #[must_use]
    pub fn take_verified_once(&mut self) -> Option<VerifiedOwnershipLease> {
        if self.taken || self.closed.is_some() || !matches!(self.result, Some(Ok(_))) {
            return None;
        }
        self.taken = true;
        self.result.take()?.ok()
    }
}

/// Owns the reached descriptor, policy and crypto results for one receipt.
#[derive(Default)]
pub struct OwnershipReceiptVerificationCaptureV1 {
    work: ReceiptVerificationWorkV1,
    result: Option<Result<(), OwnershipLeaseVerificationError>>,
    entered: bool,
    closed: Option<OwnershipVerificationClosedV1>,
}

impl OwnershipReceiptVerificationCaptureV1 {
    /// Creates inert destinations without establishing receipt authority.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the actual crypto cause before its returned classification.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.work.crypto.failure().or_else(|| error(&self.work.signature))
            .or_else(|| error(&self.result))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Reports completion of the same receipt's original verification engine.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.closed.is_none() && matches!(self.result, Some(Ok(())))
    }
}

/// Runs every existing lease verification check into actual retained owners.
///
/// # Errors
/// Returns a closed marker while preserving the original failure and prefixes.
pub fn verify_ownership_lease_retaining_v1(
    canonical: &[u8], signature: &Signature, anchor: &OwnershipLeaseTrustAnchor,
    expectation: OwnershipLeaseExpectation<'_>, limits: DecodeLimits,
    capture: &mut OwnershipLeaseVerificationCaptureV1,
) -> Result<(), OwnershipVerificationClosedV1> {
    if capture.entered {
        capture.closed.get_or_insert(OwnershipVerificationClosedV1);
        return Err(OwnershipVerificationClosedV1);
    }
    capture.entered = true;
    capture.result = Some(super::verify_ownership_lease_engine(canonical, signature,
        anchor, expectation, limits, Some(&mut capture.work)));
    if matches!(capture.result, Some(Ok(_))) { Ok(()) }
    else { Err(OwnershipVerificationClosedV1) }
}

/// Runs the existing receipt signature verifier with actual retained partials.
///
/// # Errors
/// Returns a closed marker while preserving the actual typed/native failure.
#[allow(clippy::too_many_arguments)]
pub fn verify_ownership_receipt_signature_retaining_v1(
    canonical: &[u8], signature: &Signature, anchor: &OwnershipLeaseTrustAnchor,
    issued: i64, expires: i64, now: i64, limits: DecodeLimits,
    capture: &mut OwnershipReceiptVerificationCaptureV1,
) -> Result<(), OwnershipVerificationClosedV1> {
    if capture.entered {
        capture.closed.get_or_insert(OwnershipVerificationClosedV1);
        return Err(OwnershipVerificationClosedV1);
    }
    capture.entered = true;
    capture.result = Some(super::verify_ownership_transaction_receipt_signature_engine(
        canonical, signature, anchor, issued, expires, now, limits, Some(&mut capture.work)));
    if matches!(capture.result, Some(Ok(()))) { Ok(()) }
    else { Err(OwnershipVerificationClosedV1) }
}


/// Prices the actual two verification lanes against this exact held anchor.
///
/// Returns additional heap and decoder-temporary bytes. Embedded
/// capsule storage is separately included in the upper compiled owner layout.
/// The artifact bound is passive input DATA, never an account or permission.
#[must_use]
pub fn verification_dynamic_bytes_v2(anchor: &OwnershipLeaseTrustAnchor,
    actual_artifact_bytes: usize) -> Option<usize> {
    use crate::format::TrustPolicyDecodeCaptureV1;
    let policy = anchor.canonical_policy.len();
    let policy_backing = TrustPolicyDecodeCaptureV1::receiving_carrier_bytes_v1(policy)?
        .checked_mul(2)?;
    // Each of two crypto calls retains encoded statement and domain-separated
    // message, computed/verified descriptor text and constructor move backing.
    let messages = actual_artifact_bytes.checked_mul(6)?
        .checked_add(crate::crypto::SIGNATURE_DOMAIN.len().checked_mul(2)?)?;
    let fixed_text = crate::PortableMediaType::OwnershipLease.as_str().len()
        .checked_add(crate::PortableMediaType::OwnershipTransactionReceipt.as_str().len())?
        .checked_add(anchor.authority.stable_key_id().as_str().len())?;
    let temporaries = std::mem::size_of::<LeaseVerificationWorkV1>()
        .checked_add(std::mem::size_of::<ReceiptVerificationWorkV1>())?
        .checked_add(std::mem::size_of::<SignatureVerificationCaptureV1>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<VerifiedOwnershipLease>())?
        .checked_add(std::mem::size_of::<crate::crypto::VerifiedSignature>().checked_mul(2)?)?;
    let bytes = policy_backing.checked_add(messages)?.checked_add(fixed_text)?
        .checked_add(temporaries)?;
    Some(bytes)
}
