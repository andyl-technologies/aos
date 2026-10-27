//! Adapts genuine Reap62 to the one retained native Session engine.
//!
//! This private owner holds actual Mount names, transcript and captured
//! append custody. Its inert construction grants no cleanup or effect authority.

use super::*;

/// Retains the actual Mount62 native Session phase through every outer post.
#[doc(hidden)]
#[must_use = "retain this destination through actual SDK, Source, C and Root posts"]
pub struct DeleteMountReapIoOriginalV4 {
    pub(in super::super) stages: StorageIoStagesV1,
    session: crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3,
}

impl DeleteMountReapIoOriginalV4 {
    /// Borrows the signed request and whole outcome identities from this native original.
    ///
    /// # Errors
    /// Refuses incomplete native completion or a missing actual receipt identity.
    pub(crate) fn completed_receipt_identity_data_v4(
        &self,
    ) -> Result<([u8; 32], [u8; 32]), ResourceReservationErrorV1> {
        self.completed_native_v3()?;
        self.stages.apply.terminal_identity.ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Constructs empty inline custody without allocation, IO or permission.
    #[must_use]
    pub fn new() -> Self {
        Self { stages: StorageIoStagesV1::default(),
        session: crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3::mount_v4() }
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

impl DeleteMountReapIoOriginalV4 {
    pub(crate) fn capture_receiving_demand_v3() -> Result<ResourceVector, JournalError> {
        crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3::mount_capture_receiving_demand_v4()
    }

    pub(crate) fn capture_session_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        expected_native: (u64, u64, u64, u64),
    ) -> Result<(), ResourceReservationErrorV1> {
        self.session
            .capture_inventory_once_v3(journal, socket, transcript, expected_native)
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

impl Default for DeleteMountReapIoOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::OriginalDeleteMountReapLoanV4<'_> {
    /// Admits only this issuer's exact signed62 on its already-entered C17 interval.
    ///
    /// # Errors
    /// Retains changed upper association, a reused phase or the actual receiving refusal.
    pub fn admit_mount_io_once_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_mount_contract_v4()?;
        let cutoff = self.cutoff_data_v3();
        NativeSessionIoMemberV2::DeleteMount(self)
            .admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Binds the actual signed request to the same retained Root62/192 association.
    ///
    /// # Errors
    /// Refuses substituted body, artifacts, Session, method or original horizon.
    pub fn bind_mount_request_once_v4(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_mount_contract_v4()?;
        self.require_mount_request_v4(request)?;
        NativeSessionIoMemberV2::DeleteMount(self)
            .bind_request_data_once_v2(request.exact_body(), request)
    }

    /// Joins the authenticated response to the actual protected terminal and original request.
    ///
    /// # Errors
    /// Refuses changed upper originals or incomplete receipt/currentness/native posts.
    pub fn finish_mount_terminal_once_v4(
        &mut self,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_mount_contract_v4()?;
        self.require_mount_request_v4(outcome.request())?;
        NativeSessionIoMemberV2::DeleteMount(self).finish_terminal_data_once_v2(
            outcome.request().exact_body(),
            journal,
            outcome,
        )
    }

    /// Runs the independently owed same-Session post even after an earlier refusal.
    ///
    /// # Errors
    /// Retains actual native association/name/witness failure without healthy reentry.
    pub fn observe_mount_terminal_post_once_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::DeleteMount(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}
