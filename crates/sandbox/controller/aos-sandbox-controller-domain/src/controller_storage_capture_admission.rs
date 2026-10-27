//! Retains immutable historical Capture60 DATA on the actual Controller writer.
//!
//! The genuine C18 interval prepays the complete signed-history decoder before
//! this owner runs. Its exact append geometry is admitted before anchor encoding,
//! transaction construction or native COMMIT. A successful row is historical
//! custody, never a replacement for the live Storage Capture owner or its pipes.
//!
//! ```text
//! ControllerStorageCaptureAdmission / execution[16] = canonical AOSCCA02
//! ```

use aos_sandbox_model::{ExecutionId, RawPairedClockSample};
use aos_sandbox_protocol::controller_capture_admission::{
    ControllerCaptureAdmissionAnchorDataV1, ControllerCaptureAdmissionAnchorErrorV1,
};
use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_operation::ControllerExecutionReadReceivingLoanV1;
use crate::controller_execution_output_settlement::{
    ProtectedControllerOutputSettlementV1, ControllerExecutionOutputSettlementErrorV1};
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::runtime_scope::CurrentAssignmentTarget;
use crate::{ControllerResourceBankOpeningV1, Journal, JournalError, JournalRecord,
    JournalTransaction, RecordNamespace, ResourceReservationErrorV1};

/// Reports failed historical binding or native Controller custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerStorageCaptureAdmissionErrorV3 {
    /// The exact accepted operation, settlement, clock or immutable row differs.
    #[error("Controller Capture admission differs from its original source")]
    Mismatch,
    /// The canonical original signed Session DATA is invalid.
    #[error(transparent)]
    Data(#[from] ControllerCaptureAdmissionAnchorErrorV1),
    /// The actual same-C18 financial interval refused its reached demand.
    #[error(transparent)]
    Receiving(#[from] ResourceReservationErrorV1),
    /// The actual protected append or readback failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Parks one real native append and its exact immutable historical anchor.
///
/// Only the private Runtime completed60 caller uses this owner to retain its
/// authenticated Session result. This type does not construct a native Storage
/// admission observation, physical writer, completion or new financial loan.
#[derive(Default)]
pub struct ControllerStorageCaptureAdmissionOriginalV3 {
    settlement: Option<Result<Option<ProtectedControllerOutputSettlementV1>, ControllerExecutionOutputSettlementErrorV1>>,
    model_demand: Option<Result<aos_sandbox_model::ResourceVector,
        crate::journal::broker_session_receiving::StorageSessionGeometryRefusalV1>>,
    anchor: Option<Result<ControllerCaptureAdmissionAnchorDataV1, ControllerCaptureAdmissionAnchorErrorV1>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    native: Option<Result<(), JournalError>>,
    before: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    after: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    returned: Option<Result<(), ControllerStorageCaptureAdmissionErrorV3>>,
    completed: bool,
}

impl ControllerStorageCaptureAdmissionOriginalV3 {
    /// Constructs empty result destinations without granting admission.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Retains the same native anchor with selected assignment failure custody.
    ///
    /// # Errors
    /// Preserves the actual append/source/clock/financial errors; the supplied
    /// original retains any partial ownership verification before propagation.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_ongoing_once_with_checks_v4<T>(
        &mut self, controller: &mut Journal, assignment: &CurrentAssignmentTarget,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &ControllerResourceBankOpeningV1, profile: &ProductionControllerNormalRootProfileV1,
        selected: &StorageCaptureGrantSourceV2, response: &[u8], history: &[u8], clock: &mut T,
        checks: &mut crate::runtime_scope::ControllerCaptureAssignmentChecksV4,
    ) -> Result<(), ControllerStorageCaptureAdmissionErrorV3>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        let source = selected.original_source_v1();
        if self.returned.is_some() || self.anchor.is_some() || self.native.is_some() {
            return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch);
        }
        self.returned = Some((|| {
            if receiving.operation_v3() != selected.lifetime_v2().accepted_operation_v2() {
                return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch);
            }
            receiving.require_current_v1(bank, controller, profile)?;
            controller.ensure_protected_authority()?;
            self.settlement = Some(crate::controller_execution_output_settlement::read_current_controller_output_settlement_with_checks_v4(
                controller, assignment, source.settlement().execution(), source.settlement().create_operation(), clock, checks));
            let current = self.settlement.as_ref().and_then(|v| v.as_ref().ok()).and_then(Option::as_ref)
                .ok_or(ControllerStorageCaptureAdmissionErrorV3::Mismatch)?;
            if current.canonical_bytes().as_slice() != source.settlement().canonical_bytes() {
                return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch);
            }
            self.model_demand = Some(crate::journal::broker_session_receiving::controller_capture_anchor_model_demand_ongoing_v4(
                response.len(), history.len()));
            let model = self.model_demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ControllerStorageCaptureAdmissionErrorV3::Mismatch)?;
            receiving.admit_stage_v1(bank, controller, profile,
                aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(model))?;
            let width = ControllerCaptureAdmissionAnchorDataV1::encoded_len_ongoing_v4(response.len(), history.len())
                .ok_or(ControllerStorageCaptureAdmissionErrorV3::Mismatch)?;
            receiving.admit_controller_append_v1(bank, controller, profile, std::iter::once(
                aos_sandbox_journal::geometry::RecordShape { key_bytes: 16, value_bytes: Some(width) }))?;
            self.anchor = Some(ControllerCaptureAdmissionAnchorDataV1::new_ongoing_v4(selected, response, history));
            let anchor = self.anchor.as_ref().and_then(|v| v.as_ref().ok())
                .ok_or(ControllerStorageCaptureAdmissionErrorV3::Mismatch)?;
            self.before = Some(clock());
            let before = self.before.as_ref().and_then(|v| v.as_ref().ok()).copied()
                .ok_or(ControllerStorageCaptureAdmissionErrorV3::Mismatch)?;
            require_clock(selected, anchor.effective_deadline_boottime_nanoseconds_v3(), before)?;
            receiving.require_current_v1(bank, controller, profile)?;
            let key = source.settlement().execution();
            if let Some(existing) = controller.get(RecordNamespace::ControllerStorageCaptureAdmission, key.as_bytes()) {
                if existing != anchor.canonical_bytes_v1() {
                    return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch);
                }
            } else {
                let digest: [u8; 32] = Sha256::new()
                    .chain_update(b"aos.sandbox.controller.capture-admission-tx.v1\0")
                    .chain_update(key.as_bytes())
                    .chain_update(selected.source_digest_v2().as_bytes())
                    .finalize().into();
                let mut id = [0; 16];
                id.copy_from_slice(&digest[..16]);
                self.transaction = Some(JournalTransaction::new(id, vec![JournalRecord::put(
                    RecordNamespace::ControllerStorageCaptureAdmission, key.as_bytes().to_vec(),
                    anchor.canonical_bytes_v1().to_vec())]).map_err(JournalError::from));
                let transaction = self.transaction.as_ref().and_then(|v| v.as_ref().ok())
                    .ok_or(ControllerStorageCaptureAdmissionErrorV3::Mismatch)?;
                self.native = Some(controller.commit(transaction).map(|_| ()));
                if !matches!(self.native, Some(Ok(()))) {
                    return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch);
                }
                controller.ensure_healthy()?;
                if controller.get(RecordNamespace::ControllerStorageCaptureAdmission, key.as_bytes())
                    != Some(anchor.canonical_bytes_v1())
                { return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch); }
            }
            self.after = Some(clock());
            let after = self.after.as_ref().and_then(|v| v.as_ref().ok()).copied()
                .ok_or(ControllerStorageCaptureAdmissionErrorV3::Mismatch)?;
            require_clock(selected, anchor.effective_deadline_boottime_nanoseconds_v3(), after)?;
            if before.validate_later_sample(after).is_err() {
                return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch);
            }
            receiving.require_current_v1(bank, controller, profile)?;
            self.completed = true;
            Ok(())
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch) }
    }

    /// Borrows exact persisted bytes only after real commit/readback and posts.
    #[must_use]
    pub fn completed_anchor_bytes_v3(&self) -> Option<&[u8]> {
        if !self.completed || !matches!(self.returned, Some(Ok(()))) { return None; }
        Some(self.anchor.as_ref()?.as_ref().ok()?.canonical_bytes_v1())
    }

    /// Borrows the retained typed or native cause without cloning it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.settlement.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)
            .or_else(|| self.model_demand.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.anchor.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.before.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.transaction.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.native.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.after.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.returned.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
    }
}

fn require_clock(source: &StorageCaptureGrantSourceV2, effective_deadline: u64, sample: RawPairedClockSample)
    -> Result<(), ControllerStorageCaptureAdmissionErrorV3>
{
    if sample.host_boot_id() != source.original_source_v1().host_boot_id()
        || effective_deadline == 0
        || sample.boottime_nanoseconds() >= effective_deadline.min(source.effective_execution_deadline_v2())
    { return Err(ControllerStorageCaptureAdmissionErrorV3::Mismatch); }
    Ok(())
}

/// Borrows exact protected historical anchor bytes for cold equality only.
///
/// # Errors
/// Refuses unprotected custody. It does not mint a completed native60 observation.
pub fn controller_capture_admission_bytes_v3(controller: &Journal, execution: ExecutionId)
    -> Result<Option<&[u8]>, JournalError>
{
    controller.ensure_protected_authority()?;
    Ok(controller.get(RecordNamespace::ControllerStorageCaptureAdmission, execution.as_bytes()))
}
