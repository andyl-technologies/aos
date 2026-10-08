//! Closed legacy native Acquire frontier and historical regression DATA.
//!
//! The uninstalled V2 producer is retired. Its callers retain their existing
//! refusal cuts; the selected V5 original owner keeps its separate implementation.
//! Historical Requested/challenge fixtures remain test-only and cannot mint a
//! runtime readback token, Storage send authority or an installed bridge.

use aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1;

use super::*;
use crate::zfs_hold_challenge::ProtectedZfsHoldChallengesV1;
use crate::{DurableAcquireEffectPermitV1, DurableProviderReplyV1};

#[cfg(test)]
use aos_sandbox::{JournalRecord, JournalTransaction, RecordNamespace};
#[cfg(test)]
use crate::zfs_hold_challenge::current_seconds;

/// Borrows historical record DATA for protected nonce-recovery regressions.
///
/// This test-only fixture does not authenticate a live owner graph or supply
/// a runtime token issuer. The selected V5 path uses its own protected readback.
#[cfg(test)]
pub(crate) struct RetainedNativeChallengeRequestV1<'a> {
    record: &'a NativeAcquireCompletionRecordV2,
}

#[cfg(test)]
impl RetainedNativeChallengeRequestV1<'_> {
    pub(crate) const fn record(&self) -> &NativeAcquireCompletionRecordV2 {
        self.record
    }
}

impl ProviderLedgerV1<'_> {
    /// Refuses legacy original-request recovery at its existing first frontier.
    ///
    /// No production ledger installs the retired V2 bridge. Historical dispatch
    /// rows remain unavailable, not ordinary Acquire or proven no-dispatch.
    pub(crate) fn resume_native_original_request_v3(
        &mut self,
        _acquisition_id: ObjectDigest,
        _effect_id: [u8; 16],
        _original: &SignedSourceProviderRequestV1,
    ) -> Result<DurableAcquireEffectPermitV1, ProviderLedgerError> {
        Err(ProviderLedgerError::Unavailable)
    }

    /// Consumes the legacy permit at the existing closed preparation boundary.
    ///
    /// The caller checks ledger openness, original reply identity and reserved
    /// custody before moving the permit here. Refusal cannot sign, append,
    /// dispatch, sample a clock or reinterpret the reservation as absence.
    pub(super) fn prepare_native_acquire_request_v2(
        &mut self,
        _challenges: &mut ProtectedZfsHoldChallengesV1,
        _permit: DurableAcquireEffectPermitV1,
        _original: &SignedSourceProviderRequestV1,
        _current_catalog: (&[u8], &[u8]),
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        Err(ProviderLedgerError::Unavailable)
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
pub(crate) mod tests;
