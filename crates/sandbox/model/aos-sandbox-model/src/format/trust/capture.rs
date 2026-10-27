//! Retains one complete canonical trust policy or its original parse refusal.
//!
//! This is portable DATA only. The actual credential owner retains the exact
//! input bytes and pays fixed/schema growth before this parser is entered.

use super::*;
use super::super::decode_attempt::DecodeAttempt;
use crate::FeatureRef;
use std::mem::size_of;

/// Reports a retained trust decoder's closed projection without losing its cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retained trust policy decoding is closed")]
pub struct TrustPolicyDecodeClosedV1;

/// Retains a complete canonical policy or its original failure without input borrows.
#[must_use = "retain beside the actual protected canonical policy input"]
pub struct TrustPolicyDecodeCaptureV1 {
    attempt: DecodeAttempt<TrustPolicy>,
}

impl TrustPolicyDecodeCaptureV1 {
    /// Creates allocation-free destinations without validating any bytes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempt: DecodeAttempt::new(),
        }
    }

    /// Borrows the original first canonical or semantic decoder error.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalCborError> {
        self.attempt.failure()
    }

    /// Borrows the earliest actual typed parser or constructor cause.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.attempt.cause()
    }

    /// Borrows a complete parsed policy after the original decode succeeds.
    #[must_use]
    pub fn policy(&self) -> Option<&TrustPolicy> {
        self.attempt.model()
    }

    /// Moves the actual complete policy once, retaining its original failure.
    #[must_use]
    pub fn take_policy_once(&mut self) -> Option<TrustPolicy> {
        self.attempt.take_model_option_once()
    }

    /// Bounds a concrete construction temporary plus the resident destination.
    #[must_use]
    pub const fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)
    }

    /// Bounds typed vectors from the actual canonical input's byte extent.
    ///
    /// The preliminary deterministic CBOR validation requires complete arrays;
    /// every declared element consumes at least one actual encoded byte.
    #[must_use]
    pub fn receiving_carrier_bytes_v1(input_bytes: usize) -> Option<usize> {
        // Raw current text, completed typed text, a registry-owned namespace
        // and its canonical error projection may coexist. Collection backing
        // and constructor/move carriers are separate from those four copies.
        size_of::<KeyReference>().checked_add(size_of::<FeatureRef>())?
            .checked_mul(input_bytes)?.checked_mul(2)?
            .checked_add(input_bytes.checked_mul(4)?)
    }

    /// Bounds typed destinations from the same actual input byte extent.
    #[must_use]
    pub fn receiving_metadata_cells_v1(input_bytes: usize) -> Option<usize> {
        // Ten root/parser/constructor/once destinations, seven key/feature
        // destinations, and matching seventeen transient controls.
        // Collection entries remain separate.
        input_bytes.checked_mul(2)?.checked_add(34)
    }
}

impl Default for TrustPolicyDecodeCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Decodes the shared canonical engine into its once-only complete result.
///
/// # Errors
/// Returns a closed marker while preserving the original canonical/semantic
/// cause. Reentry never parses again or replaces the original failure.
pub fn decode_trust_policy_retaining_v1(
    bytes: &[u8],
    limits: DecodeLimits,
    capture: &mut TrustPolicyDecodeCaptureV1,
) -> Result<(), TrustPolicyDecodeClosedV1> {
    capture
        .attempt
        .begin()
        .map_err(|_| TrustPolicyDecodeClosedV1)?;
    capture
        .attempt
        .finish(super::decode_policy_engine(bytes, limits))
        .map_err(|_| TrustPolicyDecodeClosedV1)
}

#[cfg(test)]
mod tests;
