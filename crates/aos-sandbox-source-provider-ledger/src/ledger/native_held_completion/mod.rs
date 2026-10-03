//! Pure Source-owned held completion records and exact transition proposals.
//!
//! This explicit profile is separate from legacy native recovery and Release.
//! It validates canonical rows and comparison claims, not protected snapshots,
//! signatures' current eligibility, original FD custody or permission to dispatch.
//!
//! ```text
//! AOSSPL01/envelope8, existing outer state/revision, AOSNCR05/body5 =
//! exact clocked native fields | signed request | optional reply | AOSNHS01 suffix
//! ```

use aos_sandbox_source_provider_protocol::native_held_completion::{
    MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1, NativeHeldOwnerV1, suffix::NativeHeldCompletionSuffixV1,
};

use super::{LedgerFormatErrorV1, native_completion::NativeAcquireCompletionRecordV2};

mod admission;
mod codec;
mod continuation;
mod evidence;
pub(crate) mod graph;
mod lifecycle;
pub(crate) mod transition;

pub use admission::SourceNativeHeldAdmissionBindingV1;
pub use continuation::{
    OriginalSourceBeforeDependencyV5, OriginalSourceContinuationAlternativeV5,
    OriginalSourceContinuationDataV5, OriginalSourceContinuationEdgeV5,
    OriginalSourceContinuationKindV5, OriginalSourceContinuationPrefixV5,
    OriginalSourceContinuationValueBoundV5, derive_original_source_continuations_v5,
};
pub(crate) use continuation::validate_comparison as validate_original_source_admission_provenance_v5;
pub(crate) use continuation::validate_current_origin as validate_original_source_current_origin_v5;
pub use graph::{derive_provider_held_preparation_data_v5, validate_native_held_records_v1};
pub use lifecycle::{
    SourceNativeHeldLifecycleTransactionV1, SourceNativeHeldLifecycleV1,
    native_held_release_status_binding_v1, propose_native_held_lifecycle_v1,
};
pub use transition::{
    SourceNativeHeldMutationV1, SourceNativeHeldStepV1, SourceNativeHeldTransactionV1,
    propose_native_held_transition_v1,
};

#[cfg(test)]
mod tests;

/// Bounds only the new held body; the legacy body maximum remains 1,071,930.
pub const MAXIMUM_NATIVE_HELD_BODY_BYTES_V1: usize =
    super::native_completion::MAXIMUM_BODY_BYTES + MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1;
/// Bounds the new held envelope plus body, excluding key and journal framing.
pub const MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1: usize = 64 + MAXIMUM_NATIVE_HELD_BODY_BYTES_V1;
/// Bounds the new carrier mutation, including key and nine-byte mutation framing.
pub const MAXIMUM_NATIVE_HELD_CARRIER_MUTATION_BYTES_V1: usize =
    MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1 + 40 + 9;
/// Bounds all six actual completion owner mutations for the held profile only.
pub const MAXIMUM_NATIVE_HELD_COMPLETION_OWNER_BYTES_V1: usize =
    super::format::MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2
        + MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1;

/// Bounds exact attempt/acquisition/current/history/authority/native mutations.
///
/// Only the last member adds the held suffix. Every legacy per-family bound and
/// the old dispatch-purpose3 floor remain unchanged.
pub const NATIVE_HELD_COMPLETION_OWNER_RECORD_BOUNDS_V1: [usize; 6] = {
    let mut bounds = super::format::NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2;
    bounds[5] += MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1;
    bounds
};

const _: () = assert!(MAXIMUM_NATIVE_HELD_BODY_BYTES_V1 == 1_178_578);
const _: () = assert!(MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1 == 1_178_642);
const _: () = assert!(MAXIMUM_NATIVE_HELD_COMPLETION_OWNER_BYTES_V1 == 3_784_222);
const _: () = assert!(
    MAXIMUM_NATIVE_HELD_COMPLETION_OWNER_BYTES_V1 < crate::limits::MAXIMUM_TRANSACTION_BYTES
);

/// Retains the original native fields and one Source-owned nonauthorizing suffix.
///
/// The outer legacy phase is preserved independently from the held phase. Cold
/// Closed settlement therefore cannot fabricate challenge spend or native Active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceNativeHeldCompletionRecordV1 {
    original: NativeAcquireCompletionRecordV2,
    suffix: NativeHeldCompletionSuffixV1,
}

impl SourceNativeHeldCompletionRecordV1 {
    /// Validates the native artifacts and Source-specific archive joins.
    ///
    /// This constructor creates DATA only. Original admission, enrolled trust,
    /// writers, clocks and dispatch qualification are not produced here.
    ///
    /// # Errors
    ///
    /// Rejects historical unclocked carriers, wrong owner, changed original scope,
    /// skipped evidence, inconsistent archives or an impossible outer phase.
    pub fn new(
        original: NativeAcquireCompletionRecordV2,
        suffix: NativeHeldCompletionSuffixV1,
    ) -> Result<Self, LedgerFormatErrorV1> {
        if original.revision == 0
            || original.original_clock.is_none()
            || original.canonical_request.is_none()
            || suffix.owner() != NativeHeldOwnerV1::Provider
        {
            return Err(corrupt("held original clock/request/owner"));
        }
        original.validate_canonical_artifacts()?;
        let value = Self { original, suffix };
        evidence::validate_record(&value)?;
        Ok(value)
    }

    /// Borrows the exact existing physical/request/outer-phase fields.
    #[must_use]
    pub const fn original(&self) -> &NativeAcquireCompletionRecordV2 {
        &self.original
    }

    /// Borrows the append-once Source suffix, never a live writer token.
    #[must_use]
    pub const fn suffix(&self) -> &NativeHeldCompletionSuffixV1 {
        &self.suffix
    }

    /// Encodes this separate version8/body5 record without enabling legacy recovery.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent artifacts/archives or the held profile's size bound.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, LedgerFormatErrorV1> {
        codec::encode(self)
    }

    /// Decodes only the explicit version8/body5 native profile.
    ///
    /// # Errors
    ///
    /// Rejects all legacy members, key/digest/length mismatch and noncanonical data.
    pub fn from_canonical_bytes(key: &[u8], bytes: &[u8]) -> Result<Self, LedgerFormatErrorV1> {
        codec::decode(key, bytes)
    }
}

fn corrupt(reason: &'static str) -> LedgerFormatErrorV1 {
    LedgerFormatErrorV1::Corrupt(reason)
}

fn schema_error(
    _: aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldCompletionErrorV1,
) -> LedgerFormatErrorV1 {
    corrupt("held control/assertion schema")
}
