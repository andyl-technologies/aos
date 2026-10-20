//! Borrows or extends Capture terminal metadata on the existing native claim.
//!
//! The caller's private Host gate retains actual Storage completion and every
//! independently owed post. This child exposes no positive Storage completion
//! constructor: its output only authenticates bytes under the held journal.

use aos_sandbox_core::runtime_backend::DurableExecutionEffectV1;
use aos_sandbox_protocol::host_execution::capture_terminal::HostExecutionTerminalMarkerDataV3;
use aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2;

use super::{DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1};

/// Borrows one cold-validated extended marker from the same protected writer.
///
/// This does not prove current Storage readiness. Historical publication also
/// requires a fresh authenticated Source61 result matching its whole record.
pub struct ProtectedCaptureTerminalMarkerV3<'claim> {
    bytes: &'claim [u8],
    complete: CaptureCompleteRecordDataV2,
}

impl ProtectedCaptureTerminalMarkerV3<'_> {
    /// Borrows exact canonical marker bytes while the actual claim remains held.
    #[must_use]
    pub fn canonical_bytes_v3(&self) -> &[u8] { self.bytes }

    /// Borrows the complete result authenticated by this same marker.
    #[must_use]
    pub const fn complete_record_v3(&self) -> &CaptureCompleteRecordDataV2 { &self.complete }
}

impl DormantRuntimeExecutionClaimV1<'_> {
    /// Extends only the existing terminal marker for the exact stored Complete.
    ///
    /// The genuine Host caller must first hold actual Storage completion and
    /// independently completed posts under its private ongoing permission.
    /// This neither completes an effect nor settles capacity again.
    ///
    /// # Errors
    /// Rejects stale native custody, a foreign/nonterminal C1, incompatible
    /// prior extension, mismatched result or ambiguous native append/readback.
    pub fn extend_capture_terminal_marker_v3(
        &mut self,
        terminal: &DurableExecutionEffectV1,
        complete: CaptureCompleteRecordDataV2,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let primary = self.execution.extend_capture_terminal_marker_v3(terminal, complete);
        let after = self.validate_current();
        primary?;
        after
    }

    /// Borrows an extended marker after exact C1, reservation and cold joins.
    ///
    /// An ordinary unextended marker is insufficient for physical completion.
    /// The caller must still independently compare fresh Source61/full676.
    ///
    /// # Errors
    /// Rejects changed native currentness, a foreign C1 or corrupt metadata.
    pub fn capture_terminal_marker_v3(
        &self,
        terminal: &DurableExecutionEffectV1,
    ) -> Result<Option<ProtectedCaptureTerminalMarkerV3<'_>>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let Some(bytes) = self.execution.capture_terminal_marker_v3(terminal)? else {
            return Ok(None);
        };
        let decoded = HostExecutionTerminalMarkerDataV3::decode_v3(bytes)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let complete = *decoded.capture_complete_v3()
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        Ok(Some(ProtectedCaptureTerminalMarkerV3 { bytes, complete }))
    }
}

impl super::DormantRuntimeExecutionOwnerV1 {
    /// Forecasts the same held-journal Capture marker extension and its readback.
    ///
    /// This is paid before either claim or result/model growth. Real Storage
    /// completion, native/name/clock posts and financial interval carriers stay
    /// separate; this amount supplies neither authority nor a new reservation.
    ///
    /// # Errors
    /// Preserves actual retained append geometry failures and checked overflow.
    pub fn capture_terminal_marker_receiving_demand_v3(
        &self,
        specification_bytes: usize,
    ) -> Result<aos_sandbox_core::ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1> {
        use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
        use aos_sandbox_journal::geometry::RecordShape;
        use aos_sandbox_protocol::host_execution::capture_terminal::CAPTURE_TERMINAL_MARKER_BYTES_V3;
        use crate::journal::JournalAppendReceivingDemandErrorV1;

        let overflow = || JournalAppendReceivingDemandErrorV1::Accounting(
            AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes });
        let effect = aos_sandbox_core::runtime_backend::durable_execution_effect_encoded_width_v5(
            specification_bytes,
            Some(aos_sandbox_protocol::execution_evidence::execution_completion_evidence_bytes_v5()),
        ).ok_or_else(overflow)?;
        let spec_model = aos_sandbox_protocol::execution_spec_attempt::
            execution_spec_validation_model_memory_bytes_v2(specification_bytes).ok_or_else(overflow)?;
        // Exact C1, decoded/readback views, marker DATA and transaction backing
        // coexist. The shared append supplier separately owns all native stages.
        let model = effect.checked_mul(4)
            .and_then(|bytes| bytes.checked_add(spec_model))
            .and_then(|bytes| bytes.checked_add(CAPTURE_TERMINAL_MARKER_BYTES_V3.checked_mul(8)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProtectedCaptureTerminalMarkerV3<'_>>().checked_mul(2)?))
            .ok_or_else(overflow)?;
        let append = self.execution_journal.append_receiving_demand_v1([RecordShape {
            key_bytes: super::super::store::EFFECT_KEY_BYTES_V5,
            value_bytes: Some(CAPTURE_TERMINAL_MARKER_BYTES_V3),
        }].into_iter())?;
        let claim = self.initial_claim_receiving_demand_v2()?;
        claim.checked_add(claim)?.checked_add(append)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(model).map_err(|_| overflow())?)).map_err(Into::into)
    }
}
