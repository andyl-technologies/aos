//! Sends actual post9/Host3 coordinates through the same Root/C native interval.
//!
//! The fixed receipt creates no disposal or Mount permission. The receiver
//! independently reads and authenticates both complete native Session histories.

use super::*;
use crate::policy_compiler::bounded_stream_io::{
    DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::delete_root::cleanup_current::{
    DeleteRootCleanupCurrentDataV4, DeleteRootCleanupTerminalDataV4,
    cleanup_approval_commitment_data_v4,
};

#[derive(Clone, Copy)]
enum First {
    Association,
    Funding,
    Entry,
    Encoding,
    Send,
    After,
    Disposal,
    Reentry,
}

pub(super) struct CleanupCurrentSendOriginalV4 {
    entered: bool,
    association: Option<Result<(), JournalError>>,
    funding: Option<Result<(), JournalError>>,
    entry: Option<Result<(), RootDeleteClientClosedV1>>,
    encoding: Option<Result<[u8; 352], Cause>>,
    bytes: [u8; 352],
    io: FixedDeadlineStreamIoV1<352>,
    sent: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    after: Option<Result<(), RootDeleteClientClosedV1>>,
    disposal: Option<Result<(), JournalError>>,
    completed_clock: Option<RawPairedClockSample>,
    first: Option<First>,
}

impl Default for CleanupCurrentSendOriginalV4 {
    fn default() -> Self {
        Self {
            entered: false,
            association: None,
            funding: None,
            entry: None,
            encoding: None,
            bytes: [0; 352],
            io: Default::default(),
            sent: None,
            after: None,
            disposal: None,
            completed_clock: None,
            first: None,
        }
    }
}

impl CleanupCurrentSendOriginalV4 {
    pub(super) fn completed_frame_v4(
        &self,
        state: &DeleteSourceAcceptanceRootStateV3,
    ) -> Result<(DeleteRootCleanupCurrentDataV4, RawPairedClockSample), JournalError> {
        if self.first.is_some() || state.first.is_some() || !(9..=13).contains(&state.cursor)
            || !matches!(self.disposal, Some(Ok(()))) || !self.io.completed_exact()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let frame = DeleteRootCleanupCurrentDataV4::decode_v4(&self.bytes)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok((frame, self.completed_clock.ok_or(JournalError::ProtectedBoundary)?))
    }

    pub(super) fn funding_failed_v4(&self) -> bool {
        matches!(self.first, Some(First::Funding))
    }

    pub(super) fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Association => cause(&self.association),
            First::Funding => cause(&self.funding),
            First::Entry => cause(&self.entry),
            First::Encoding => self
                .encoding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Send => self.io.failure().or_else(|| cause(&self.sent)),
            First::After => cause(&self.after),
            First::Disposal => cause(&self.disposal),
            First::Reentry => None,
        }
    }
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn send_cleanup_current_once_v4(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        network: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
        host: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<(), RootDeleteClientClosedV1> {
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        if self.first.is_some()
            || self.turn.is_some()
            || state.first.is_some()
            || state.cursor != 9
            || state.interval.is_some()
            || !matches!(state.disposal, Some(Ok(())))
            || state.cleanup.entered
        {
            state.cleanup.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        state.cleanup.entered = true;
        let association = (|| {
            self.require_accepted_pending_v3(fence, controller, launch, accepted)?;
            self.require_network_resource_approval_v4()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            fence.require_source_controller_committed_v3()?;
            Ok(())
        })();
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.cleanup.association = Some(association);
        if !matches!(state.cleanup.association, Some(Ok(()))) {
            state.cleanup.first = Some(First::Association);
            state.first = Some(RootAdmissionFirst::CleanupCurrent);
            self.first = Some(super::super::First::SourceAdmission);
            return Err(self.closed);
        }
        // Inline sender/encoding storage was included in the actual state's
        // original construction invoice. This pays the reached hash workspace
        // and nonrefundable exact stream traffic before either is attempted.
        let memory = std::mem::size_of::<blake3::Hasher>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(self.closed)?;
        let fee = ResourceVector::ZERO
            .with(D::NetworkBytes, 352)
            .with(D::OutputBytes, 352)
            .with(D::MemoryBytes, memory);
        state.cleanup.funding = Some(fence.reserve_preaccept_additional_v1(
            controller,
            launch,
            self.profile.lower_original_v1(),
            fee,
        ));
        if !matches!(state.cleanup.funding, Some(Ok(()))) {
            state.cleanup.first = Some(First::Funding);
            state.first = Some(RootAdmissionFirst::CleanupCurrent);
            self.first = Some(super::super::First::SourceAdmission);
            return Err(self.closed);
        }
        let entered = self.begin_admission_interval_once_v3(
            fence,
            controller,
            launch,
            RootNativeAdmissionPhaseV3::CleanupCurrent(accepted),
        );
        self.source_admission
            .as_mut()
            .ok_or(self.closed)?
            .cleanup
            .entry = Some(entered);
        if !matches!(
            self.source_admission
                .as_ref()
                .ok_or(self.closed)?
                .cleanup
                .entry,
            Some(Ok(()))
        ) {
            // The common interval selected its actual financial/native cause.
            self.source_admission
                .as_mut()
                .ok_or(self.closed)?
                .cleanup
                .first = Some(First::Entry);
            return Err(self.closed);
        }
        let encoded = self.cleanup_frame_v4(network, host);
        let cutoff = self
            .challenge
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?
            .source
            .cutoff;
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.cleanup.encoding = Some(encoded);
        if let Some(Ok(bytes)) = state.cleanup.encoding.as_ref() {
            state.cleanup.bytes = *bytes;
            state.cleanup.sent = Some(match self.connection.stream_mut() {
                Ok(stream) => state.cleanup.io.run_once(
                    stream,
                    &mut state.cleanup.bytes,
                    cutoff,
                    DeadlineStreamDirectionV1::Write,
                ),
                Err(cause) => Err(cause),
            });
            if !matches!(state.cleanup.sent, Some(Ok(()))) {
                state.cleanup.first.get_or_insert(First::Send);
            }
        } else {
            state.cleanup.first.get_or_insert(First::Encoding);
        }
        // Latch the actual primary before the independently owed Root/C posts.
        if state.cleanup.first.is_some() {
            state
                .first
                .get_or_insert(RootAdmissionFirst::CleanupCurrent);
            if let Some(interval) = state.interval.as_mut() {
                interval.mark_external_primary_refusal_v2();
            }
        }
        let after = self.finish_source_readiness_interval_once_v3(controller);
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.cleanup.after = Some(after);
        if !matches!(state.cleanup.after, Some(Ok(()))) {
            state.cleanup.first.get_or_insert(First::After);
        }
        if state.first.is_some()
            || state.cleanup.first.is_some()
            || !state.cleanup.io.completed_exact()
        {
            self.first
                .get_or_insert(super::super::First::SourceAdmission);
            return Err(self.closed);
        }
        state.cleanup.disposal = Some((|| {
            let token = self
                .turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(state.interval.take());
            token.complete_after_upper_disposal_v1();
            Ok(())
        })());
        if !matches!(state.cleanup.disposal, Some(Ok(()))) {
            state.cleanup.first = Some(First::Disposal);
            state.first = Some(RootAdmissionFirst::CleanupCurrent);
            self.first = Some(super::super::First::SourceAdmission);
            return Err(self.closed);
        }
        drop(self.turn.take());
        state
            .binding
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .ok_or(self.closed)?
            .after = state.after.ok_or(self.closed)?;
        state.disposal = Some(Ok(()));
        state.cleanup.completed_clock = state.after;
        // Cursor9 remains reserved for the genuine Mount62 operation. Sending
        // receipt DATA alone cannot advance to Storage7's cursor10.
        Ok(())
    }

    fn cleanup_frame_v4(
        &self,
        network: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
        host: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<[u8; 352], Cause> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if state.first.is_some() || state.before.is_none() || state.after.is_some() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        if network.1.request().network_destroy_data_v4().is_none()
            || host.1.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let challenge = self
            .challenge
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let approval = self.preparatory_approval_complete
            [resource_slot_v3(DeleteResourcePurposeV3::Network9)]
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)?
        .approval;
        let receipt = |value: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1)| {
            DeleteRootCleanupTerminalDataV4 {
                native: *value.0,
                request: value.1.request().signed_request_digest(),
                outcome: *blake3::hash(value.1.canonical_packet()).as_bytes(),
            }
        };
        Ok(DeleteRootCleanupCurrentDataV4 {
            challenge: challenge.source.nonce,
            opening: challenge.open,
            approved9: cleanup_approval_commitment_data_v4(approval)?,
            network: receipt(network),
            host: receipt(host),
        }
        .encode_v4()?)
    }
}
