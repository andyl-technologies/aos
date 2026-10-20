//! Shares the retained Session engine with genuine C17 Delete26 and Apply7 loans.
//!
//! This destination contains the existing native phase state. Its empty
//! constructor grants nothing; only the actual Root/Source/C17 loan can enter
//! the finite Delete member, and the enclosing owner always owes its own posts.

mod apply;
mod network;
pub use network::DeleteNetworkApplyIoOriginalV4;
mod mount;
pub use mount::DeleteMountReapIoOriginalV4;

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
};

/// Retains Delete26's same-engine native phase and all reached error originals.
#[doc(hidden)]
#[must_use = "retain this destination on the actual Delete owner through all outer posts"]
pub struct DeleteStoragePreparationIoOriginalV3 {
    pub(super) stages: StorageIoStagesV1,
    session: crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3,
}

impl DeleteStoragePreparationIoOriginalV3 {
    /// Constructs empty inline custody without allocation, IO or permission.
    #[must_use]
    pub fn new() -> Self {
        Self { stages: StorageIoStagesV1::default(),
        session: crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3::preparation_v3() }
    }

    /// Borrows the first retained native or receiving refusal without new work.
    #[must_use]
    pub fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.session.failure_v3().or_else(|| self.stages.failure())
    }

    /// Returns actual resident and same-turn spent demand as passive DATA.
    ///
    /// # Errors
    /// Refuses arithmetic overflow; a different turn never refunds resident work.
    pub fn retained_demand_v3(
        &self,
        native_turn: u64,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.stages.retained_demand_v1(native_turn)
    }

    /// Borrows the actual native terminal only after the entire entered phase completed.
    ///
    /// # Errors
    /// Refuses incomplete request, receipt, protected-row or independent native posts.
    pub fn completed_native_v3(&self) -> Result<&[u8; 64], ResourceReservationErrorV1> {
        completed_native_v3(&self.stages, &self.session)
    }
}

fn completed_native_v3<'held>(
    stages: &'held StorageIoStagesV1,
    session: &crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3,
) -> Result<&'held [u8; 64], ResourceReservationErrorV1> {
    session.require_completed_capture_v3()?;
    let stage = &stages.apply;
    if stages.active != Some(false)
        || stages.failure().is_some()
        || stage.phase != IoPhaseV1::Complete
        || !matches!(stage.request_binding, Some(Ok(())))
        || !matches!(stage.terminal_association, Some(Ok(())))
        || !matches!(stage.native_position, Some(Ok(_)))
        || stage.terminal_identity.is_none()
    {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    stage
        .terminal_native
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(ResourceReservationErrorV1::Conflict)
}

/// Retains DeleteApply7's same-engine phases and actual completed26 association.
#[doc(hidden)]
#[must_use = "retain this destination through every same-C and Root post"]
pub struct DeleteStorageApplyIoOriginalV3 {
    pub(super) stages: StorageIoStagesV1,
    session: crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3,
    predecessor: Option<Result<(), ResourceReservationErrorV1>>,
}

impl DeleteStorageApplyIoOriginalV3 {
    /// Constructs inert inline custody without IO, allocation or permission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stages: StorageIoStagesV1::default(),
            session: crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3::apply_v3(),
            predecessor: None,
        }
    }

    /// Borrows the actual earliest predecessor, native or receiving refusal.
    #[must_use]
    pub fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.session.failure_v3())
            .or_else(|| self.stages.failure())
    }

    /// Returns actual resident and same-turn spent demand as comparison DATA.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow without resetting earlier residents.
    pub fn retained_demand_v3(
        &self,
        native_turn: u64,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.stages.retained_demand_v1(native_turn)
    }

    /// Borrows the native terminal only after this actual complete Apply7 phase.
    ///
    /// # Errors
    /// Refuses absent completed26 custody or incomplete request/receipt/posts.
    pub fn completed_native_v3(&self) -> Result<&[u8; 64], ResourceReservationErrorV1> {
        if !matches!(self.predecessor, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        completed_native_v3(&self.stages, &self.session)
    }
}

impl Default for DeleteStorageApplyIoOriginalV3 {
    fn default() -> Self {
        Self::new()
    }
}

impl DeleteStoragePreparationIoOriginalV3 {
    /// Borrows the exact canonical receipt identity from this completed original.
    ///
    /// # Errors
    /// Refuses incomplete request/receipt/native custody or absent identity.
    pub(crate) fn completed_receipt_identity_data_v3(
        &self,
    ) -> Result<([u8; 32], [u8; 32]), ResourceReservationErrorV1> {
        self.completed_native_v3()?;
        self.stages.apply.terminal_identity.ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl DeleteStoragePreparationIoOriginalV3 {
    pub(crate) fn capture_receiving_demand_v3() -> Result<ResourceVector, JournalError> {
        crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3::capture_receiving_demand_v3()
    }

    pub(crate) fn capture_session_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        expected_native: (u64, u64, u64, u64),
    ) -> Result<(), ResourceReservationErrorV1> {
        self.session.capture_inventory_once_v3(journal, socket, transcript, expected_native)
    }

    pub(crate) fn require_session_v3(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.session.require_session_v3(journal, socket, transcript)
    }

    pub(crate) fn require_journal_v3(
        &self,
        journal: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.session.require_journal_v3(journal)
    }

    pub(crate) fn prepare_append_demand_v3(
        &mut self,
        journal: &Journal,
        request_bytes: usize,
    ) -> Result<ResourceVector, JournalError> {
        self.session
            .prepare_append_demand_v3(journal, request_bytes)
    }

    pub(crate) fn install_prepaid_append_once_v3(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), JournalError> {
        self.session.install_prepaid_append_once_v3(journal)
    }

    pub(crate) fn close_append_window_v3(&self) {
        self.session.close_append_window_v3();
    }

    pub(crate) fn retire_prepaid_append_once_v3(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), JournalError> {
        self.session.retire_prepaid_append_once_v3(journal)
    }
}

impl Default for DeleteStoragePreparationIoOriginalV3 {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::OriginalDeleteStoragePreparationLoanV3<'_> {
    /// Admits only this issuer's exact signed26 on its already-entered C17 interval.
    ///
    /// # Errors
    /// Retains changed upper association, a reused phase or the actual receiving refusal.
    pub fn admit_preparation_io_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_preparation_contract_v3()?;
        let cutoff = self.cutoff_data_v3();
        NativeSessionIoMemberV2::DeletePreparation(self)
            .admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Binds the actual signed request to the same retained Root26/192 association.
    ///
    /// # Errors
    /// Refuses substituted body, artifacts, Session, method or original horizon.
    pub fn bind_preparation_request_once_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_preparation_contract_v3()?;
        self.require_preparation_request_v3(request)?;
        NativeSessionIoMemberV2::DeletePreparation(self)
            .bind_request_data_once_v2(request.exact_body(), request)
    }

    /// Joins the authenticated response to the actual protected terminal and original request.
    ///
    /// # Errors
    /// Refuses changed upper originals or incomplete receipt/currentness/native posts.
    pub fn finish_preparation_terminal_once_v3(
        &mut self,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_preparation_contract_v3()?;
        self.require_preparation_request_v3(outcome.request())?;
        NativeSessionIoMemberV2::DeletePreparation(self).finish_terminal_data_once_v2(
            outcome.request().exact_body(),
            journal,
            outcome,
        )
    }

    /// Runs the independently owed same-Session post even after an earlier refusal.
    ///
    /// # Errors
    /// Retains actual native association/name/witness failure without healthy reentry.
    pub fn observe_preparation_terminal_post_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::DeletePreparation(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_native_position_does_not_adopt_a_completed_delete_preparation() {
        let mut original = DeleteStoragePreparationIoOriginalV3::new();
        original.stages.apply.terminal_native = Some(Ok([7; 64]));
        assert!(original.completed_native_v3().is_err());

        original.stages.active = Some(false);
        original.stages.apply.phase = IoPhaseV1::Complete;
        assert!(original.completed_native_v3().is_err());

        original.stages.apply.request_binding = Some(Ok(()));
        original.stages.apply.terminal_association = Some(Ok(()));
        original.stages.apply.native_position = Some(Ok([8; 32]));
        assert!(original.completed_native_v3().is_err());
    }
}
