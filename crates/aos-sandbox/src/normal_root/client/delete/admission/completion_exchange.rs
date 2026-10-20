//! Keeps the same Root/C17 original through final Source544, ACK32 and positive EOF.
//!
//! ACK is passive pre-disposition correlation only. Explicit confirmation from
//! the permanent listener follows actual D-positive settlement. EOF alone may
//! race process exit_files while its PIDFD still reports alive, so both the
//! causal confirmation and the existing live-peer native after are mandatory.
//! All own afters precede C-turn disposal; the Source scope stays held separately.

use super::*;
use crate::policy_compiler::bounded_stream_io::{
    DeadlineStreamDirectionV1 as Direction, FixedDeadlineStreamIoV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use aos_sandbox_protocol::domain_ledger::delete_root::completion::DeleteRootSourceCompletionDataV4 as Frame;
use std::os::fd::AsFd as _;

#[derive(Clone, Copy)]
enum First {
    Association,
    Funding,
    Entry,
    Encoding,
    Send,
    WriteEnd,
    Ack,
    Positive,
    Eof,
    After,
    Disposal,
    Reentry,
}

pub(super) struct SourceCompletionExchangeOriginalV4 {
    entered: bool,
    association: Option<Result<(), Cause>>,
    funding: Option<Result<(), JournalError>>,
    entry: Option<Result<(), RootDeleteClientClosedV1>>,
    encoding: Option<Result<Frame, Cause>>,
    bytes: [u8; 544],
    sender: FixedDeadlineStreamIoV1<544>,
    sent: Option<Result<(), HistoryErrorV1>>,
    write_end: Option<Result<(), rustix::io::Errno>>,
    ack: [u8; 32],
    receiver: FixedDeadlineStreamIoV1<32>,
    received: Option<Result<(), HistoryErrorV1>>,
    comparison: Option<Result<(), HistoryErrorV1>>,
    positive_bytes: [u8; 48],
    positive_io: FixedDeadlineStreamIoV1<48>,
    positive_received: Option<Result<(), HistoryErrorV1>>,
    positive_comparison: Option<Result<(), HistoryErrorV1>>,
    eof_byte: [u8; 1],
    eof: FixedDeadlineStreamIoV1<1>,
    ended: Option<Result<(), HistoryErrorV1>>,
    after: Option<Result<(), RootDeleteClientClosedV1>>,
    disposal: Option<Result<(), JournalError>>,
    retired: bool,
    first: Option<First>,
}

impl Default for SourceCompletionExchangeOriginalV4 {
    fn default() -> Self {
        Self {
            entered: false,
            association: None,
            funding: None,
            entry: None,
            encoding: None,
            bytes: [0; 544],
            sender: Default::default(),
            sent: None,
            write_end: None,
            ack: [0; 32],
            receiver: Default::default(),
            received: None,
            comparison: None,
            positive_bytes: [0; 48],
            positive_io: Default::default(),
            positive_received: None,
            positive_comparison: None,
            eof_byte: [0],
            eof: Default::default(),
            ended: None,
            after: None,
            disposal: None,
            retired: false,
            first: None,
        }
    }
}

impl SourceCompletionExchangeOriginalV4 {
    pub(super) fn funding_failed_v4(&self) -> bool {
        matches!(self.first, Some(First::Funding))
    }

    pub(super) fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Association => self
                .association
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Funding => cause(&self.funding),
            First::Entry => cause(&self.entry),
            First::Encoding => self
                .encoding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Send => self.sender.failure().or_else(|| cause(&self.sent)),
            First::WriteEnd => cause(&self.write_end),
            First::Ack => self
                .receiver
                .failure()
                .or_else(|| cause(&self.received))
                .or_else(|| cause(&self.comparison)),
            First::Eof => self.eof.failure().or_else(|| cause(&self.ended)),
            First::Positive => self
                .positive_io
                .failure()
                .or_else(|| cause(&self.positive_received))
                .or_else(|| cause(&self.positive_comparison)),
            First::After => cause(&self.after),
            First::Disposal => cause(&self.disposal),
            First::Reentry => None,
        }
    }
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn exchange_source_completion_once_v4(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        frame: Frame,
    ) -> Result<(), RootDeleteClientClosedV1> {
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 13
            || state.interval.is_some()
            || self.turn.is_some()
            || state.terminal.entered
            || !matches!(state.disposal, Some(Ok(())))
        {
            state.terminal.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        state.terminal.entered = true;
        let association = (|| {
            self.require_accepted_pending_v3(fence, controller, launch, accepted)?;
            if frame.source != *fence.completion_native_data_v4()?
                || frame.controller != *accepted.completed_native_v3(controller, fence)?
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            frame.encode_v4()?;
            Ok(())
        })();
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.terminal.association = Some(association);
        if !matches!(state.terminal.association, Some(Ok(()))) {
            state.terminal.first = Some(First::Association);
            state.first = Some(RootAdmissionFirst::Terminal);
            self.first = Some(super::super::First::SourceAdmission);
            return Err(self.closed);
        }
        state.terminal.funding = Some(
            fence.reserve_preaccept_additional_v1(
                controller,
                launch,
                self.profile.lower_original_v1(),
                ResourceVector::ZERO
                    .with(D::NetworkBytes, 544 + 32 + 48 + 1)
                    .with(D::OutputBytes, 544),
            ),
        );
        if !matches!(state.terminal.funding, Some(Ok(()))) {
            state.terminal.first = Some(First::Funding);
            state.first = Some(RootAdmissionFirst::Terminal);
            self.first = Some(super::super::First::SourceAdmission);
            return Err(self.closed);
        }
        let entry = self.begin_admission_interval_once_v3(
            fence,
            controller,
            launch,
            RootNativeAdmissionPhaseV3::SourceFinal(accepted),
        );
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.terminal.entry = Some(entry);
        if !matches!(state.terminal.entry, Some(Ok(()))) {
            state.terminal.first = Some(First::Entry);
            return Err(self.closed);
        }
        let cutoff = state
            .binding
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?
            .cutoff;
        // The same already-entered native/financial frontier is rechecked
        // immediately before the first final Source frame byte is sent.
        if self.require_admission_native_frontier_v3().is_err() {
            let state = self.source_admission.as_mut().ok_or(self.closed)?;
            state.first.get_or_insert(RootAdmissionFirst::Frontier);
        }
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        if state.first.is_none() {
            state.terminal.encoding = Some((|| {
                if frame.source != *fence.completion_native_data_v4()?
                    || frame.controller != *accepted.completed_native_v3(controller, fence)?
                {
                    return Err(JournalError::StaleAuthoritySnapshot.into());
                }
                state.terminal.bytes = frame.encode_v4()?;
                Ok(frame)
            })());
            if !matches!(state.terminal.encoding, Some(Ok(_))) {
                state.terminal.first = Some(First::Encoding);
            }
            if state.terminal.first.is_none() {
                state.terminal.sent = Some(match self.connection.stream_mut() {
                    Ok(stream) => state.terminal.sender.run_once(
                        stream,
                        &mut state.terminal.bytes,
                        cutoff,
                        Direction::Write,
                    ),
                    Err(cause) => Err(cause),
                });
                if !matches!(state.terminal.sent, Some(Ok(()))) {
                    state.terminal.first = Some(First::Send);
                }
            }
            if state.terminal.first.is_none() {
                match self.connection.stream() {
                    Ok(stream) => {
                        state.terminal.write_end = Some(rustix::net::shutdown(
                            stream.as_fd(),
                            rustix::net::Shutdown::Write,
                        ))
                    }
                    Err(cause) => {
                        state.terminal.sent = Some(Err(cause));
                        state.terminal.first = Some(First::Send);
                    }
                }
                if state.terminal.first.is_none()
                    && !matches!(state.terminal.write_end, Some(Ok(())))
                {
                    state.terminal.first = Some(First::WriteEnd);
                }
            }
            if state.terminal.first.is_none() {
                state.terminal.received = Some(match self.connection.stream_mut() {
                    Ok(stream) => state.terminal.receiver.run_once(
                        stream,
                        &mut state.terminal.ack,
                        cutoff,
                        Direction::Read,
                    ),
                    Err(cause) => Err(cause),
                });
                state.terminal.comparison = Some((|| {
                    let expected = frame
                        .acknowledgement_digest_v4()
                        .map_err(|_| HistoryErrorV1::Correlation)?;
                    if !matches!(state.terminal.received, Some(Ok(())))
                        || !state.terminal.receiver.completed_exact()
                        || state.terminal.ack != expected
                    {
                        return Err(HistoryErrorV1::Correlation);
                    }
                    Ok(())
                })());
                if !matches!(state.terminal.comparison, Some(Ok(()))) {
                    state.terminal.first = Some(First::Ack);
                }
            }
            if state.terminal.first.is_none() {
                state.terminal.positive_received = Some(match self.connection.stream_mut() {
                    Ok(stream) => state.terminal.positive_io.run_once(
                        stream,
                        &mut state.terminal.positive_bytes,
                        cutoff,
                        Direction::Read,
                    ),
                    Err(cause) => Err(cause),
                });
                state.terminal.positive_comparison = Some((|| {
                    let acknowledgement = frame
                        .acknowledgement_digest_v4()
                        .map_err(|_| HistoryErrorV1::Correlation)?;
                    let expected = aos_sandbox_protocol::root_policy_completion::
                        delete_root_positive_completion_bytes_v2(acknowledgement);
                    if !matches!(state.terminal.positive_received, Some(Ok(())))
                        || !state.terminal.positive_io.completed_exact()
                        || state.terminal.positive_bytes != expected
                    {
                        return Err(HistoryErrorV1::Correlation);
                    }
                    Ok(())
                })());
                if !matches!(state.terminal.positive_comparison, Some(Ok(()))) {
                    state.terminal.first = Some(First::Positive);
                }
            }
            if state.terminal.first.is_none() {
                state.terminal.ended = Some(match self.connection.stream_mut() {
                    Ok(stream) => state.terminal.eof.run_once(
                        stream,
                        &mut state.terminal.eof_byte,
                        cutoff,
                        Direction::Eof,
                    ),
                    Err(cause) => Err(cause),
                });
                if !matches!(state.terminal.ended, Some(Ok(())))
                    || !state.terminal.eof.completed_exact()
                {
                    state.terminal.first = Some(First::Eof);
                }
            }
        }
        if state.terminal.first.is_some() || state.first.is_some() {
            state.first.get_or_insert(RootAdmissionFirst::Terminal);
            if let Some(interval) = state.interval.as_mut() {
                interval.mark_external_primary_refusal_v2();
            }
        }
        let after = self.finish_source_readiness_interval_once_v3(controller);
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.terminal.after = Some(after);
        if !matches!(state.terminal.after, Some(Ok(()))) {
            state.terminal.first.get_or_insert(First::After);
        }
        if state.first.is_some()
            || state.terminal.first.is_some()
            || !state.terminal.eof.completed_exact()
        {
            state.first.get_or_insert(RootAdmissionFirst::Terminal);
            self.first
                .get_or_insert(super::super::First::SourceAdmission);
            return Err(self.closed);
        }
        state.terminal.disposal = Some((|| {
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
        if !matches!(state.terminal.disposal, Some(Ok(()))) {
            state.terminal.first = Some(First::Disposal);
            state.first = Some(RootAdmissionFirst::Terminal);
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
        state.cursor = 14;
        state.terminal.retired = true;
        Ok(())
    }

    pub(crate) fn terminal_clock_bound_data_v4(
        &self,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 13
            || self.turn.is_some()
            || !matches!(state.disposal, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(state
            .binding
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?
            .clock_bound_data_v3())
    }

    pub(crate) fn require_terminal_exchange_complete_v4(
        &self,
        source: &[u8; 64],
    ) -> Result<(), JournalError> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let terminal = &state.terminal;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 14
            || !terminal.retired
            || terminal.first.is_some()
            || !matches!(terminal.after, Some(Ok(())))
            || !matches!(terminal.disposal, Some(Ok(())))
            || !matches!(terminal.positive_comparison, Some(Ok(())))
            || !terminal.positive_io.completed_exact()
            || !terminal.eof.completed_exact()
            || terminal
                .encoding
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .map(|frame| &frame.source)
                != Some(source)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn complete_terminal_upper_disposal_v4(&mut self) {
        // Only the genuine final Source/C17 token calls this after its own
        // fallible preparation and actual upper/native prefix disposal.
        self.terminal_complete = true;
    }

    pub(crate) fn completed_terminal_frame_v4(
        &self,
        source: &[u8; 64],
    ) -> Result<Frame, JournalError> {
        self.require_terminal_exchange_complete_v4(source)?;
        self.source_admission
            .as_ref()
            .and_then(|state| state.terminal.encoding.as_ref())
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn completed_terminal_clock_bound_v4(
        &self,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if state.cursor != 14 || self.first.is_some() || state.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(state
            .binding
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?
            .clock_bound_data_v3())
    }

    pub(crate) fn record_terminal_controller_once_v4(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), JournalError> {
        self.require_terminal_exchange_complete_v4(fence.completion_native_data_v4()?)?;
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if state.terminal_core.is_some() || self.turn.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (completion, turn) = crate::journal::ControllerDeleteTerminalOriginalV4::run_once_v4(
            self,
            controller,
            fence,
            accepted,
            launch,
            self.profile.lower_original_v1(),
        );
        let complete = completion.require_completed_v4();
        self.turn = turn;
        let state = self
            .source_admission
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        state.terminal_core = Some(completion);
        if complete.is_err() {
            state.first = Some(RootAdmissionFirst::TerminalCore);
            self.first = Some(super::super::First::SourceAdmission);
        }
        complete
    }

    pub(crate) fn require_terminal_controller_complete_v4(&self) -> Result<(), JournalError> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some() || state.first.is_some() || self.turn.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        state
            .terminal_core
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_completed_v4()
    }

    /// Lends the actual native terminal C owner for the final Source disposition.
    ///
    /// # Errors
    /// Refuses incomplete causal Root confirmation/peer posts, another held
    /// Source frontier, an unfinished C turn, or changed terminal C readback.
    pub(crate) fn borrow_terminal_controller_completed_v4(
        &self,
        controller: &Journal,
        source: &[u8; 64],
    ) -> Result<&crate::journal::ControllerDeleteTerminalOriginalV4, JournalError> {
        self.require_terminal_exchange_complete_v4(source)?;
        self.require_terminal_controller_complete_v4()?;
        let completed = self.source_admission.as_ref()
            .and_then(|state| state.terminal_core.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?;
        completed.require_current_readback_v4(controller, source)?;
        Ok(completed)
    }
}
