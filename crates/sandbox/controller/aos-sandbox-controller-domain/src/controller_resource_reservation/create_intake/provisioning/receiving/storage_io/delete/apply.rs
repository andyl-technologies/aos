//! Joins signed DeleteApply7 to the actual completed26 and shared native turns.

use super::*;

impl DeleteStorageApplyIoOriginalV3 {
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

    pub(crate) fn capture_receiving_demand_v3() -> Result<ResourceVector, JournalError> {
        crate::journal::delete_storage_preparation::DeleteStorageSessionNativeOriginalV3::capture_receiving_demand_v3()
    }

    pub(crate) fn capture_session_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        preparation: &DeleteStoragePreparationIoOriginalV3,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.predecessor.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.predecessor = Some((|| {
            preparation.completed_native_v3()?;
            preparation.require_session_v3(journal, socket, transcript)?;
            let identity = preparation.completed_receipt_identity_data_v3()?;
            if outcome.method() != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                || identity != (outcome.request().signed_request_digest(),
                    *blake3::hash(outcome.canonical_packet()).as_bytes())
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(self.predecessor, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = *preparation.completed_native_v3()?;
        self.session
            .capture_preparation_once_v3(journal, socket, transcript, native)
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

impl crate::OriginalDeleteStorageApplyLoanV3<'_> {
    /// Admits only the genuine signed7 under its actual new C17/Root interval.
    ///
    /// # Errors
    /// Refuses changed contract, Session, original horizon or same-owner demand.
    pub fn admit_apply_io_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_apply_contract_v3()?;
        let cutoff = self.cutoff_data_v3();
        NativeSessionIoMemberV2::DeleteApply(self)
            .admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Binds the request to this actual Root-signed destructive7 contract.
    ///
    /// # Errors
    /// Refuses substituted body, artifacts, method, Session or original cutoff.
    pub fn bind_apply_request_once_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_apply_contract_v3()?;
        self.require_apply_request_v3(request)?;
        NativeSessionIoMemberV2::DeleteApply(self)
            .bind_request_data_once_v2(request.exact_body(), request)
    }

    /// Joins signed7's actual terminal to its protected Session and request.
    ///
    /// # Errors
    /// Refuses changed originals or incomplete receipt/currentness/native posts.
    pub fn finish_apply_terminal_once_v3(
        &mut self,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_apply_contract_v3()?;
        self.require_apply_request_v3(outcome.request())?;
        NativeSessionIoMemberV2::DeleteApply(self).finish_terminal_data_once_v2(
            outcome.request().exact_body(),
            journal,
            outcome,
        )
    }

    /// Runs the independently owed Session post despite earlier refusal.
    ///
    /// # Errors
    /// Retains actual native socket/name/witness failures without healthy entry.
    pub fn observe_apply_terminal_post_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::DeleteApply(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}
