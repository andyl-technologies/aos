//! Shares per-IO Session/name/deadline originals behind genuine closed query loans.
//!
//! The same shared Security sender, receiver and readiness waiter perform IO.
//! This child admits its reached native probes and traffic before entry, then
//! retains independent after observations even when the primary refused. It
//! neither constructs a request nor releases the enclosing C/profile interval.

use std::error::Error;
use crate::journal::{Journal, JournalError, ProtectedJournalCurrentnessOriginalsV1,
    StorageNativeOpeningOwnerLinkV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1};
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_linux::seqpacket::{RecordBindingError, SeqpacketSocket, StorageSeqpacketSessionOriginV1};
use super::inventory_recipe;
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketReceiveErrorV1, StorageSeqpacketSendAttemptV1};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Turn { Preparation, Send, Receive, WaitSend, WaitReceive }

#[derive(Clone, Copy)]
enum First {
    Binding,
    Socket,
    Before,
    ClockBefore,
    AfterBinding,
    AfterSocket,
    After,
    ClockAfter,
    PendingSocket,
    Disposition,
    ClockDisposal,
    Reentry,
}

pub(crate) struct IoOriginals {
    turn: Option<Turn>,
    retain_cookie_originals: bool,
    socket_native: Option<Result<u64, aos_sandbox_linux::Error>>,
    after_socket_native: Option<Result<u64, aos_sandbox_linux::Error>>,
    pending_socket_native: Option<Result<u64, aos_sandbox_linux::Error>>,
    binding: Option<Result<(), JournalError>>,
    socket: Option<Result<(), RecordBindingError>>,
    before: ProtectedJournalCurrentnessOriginalsV1,
    before_result: Option<Result<(), JournalError>>,
    clock_before: Option<rustix::time::Timespec>,
    deadline_before: Option<Result<(), JournalError>>,
    after_binding: Option<Result<(), JournalError>>,
    after_socket: Option<Result<(), RecordBindingError>>,
    after: ProtectedJournalCurrentnessOriginalsV1,
    after_result: Option<Result<(), JournalError>>,
    clock_after: Option<rustix::time::Timespec>,
    deadline_after: Option<Result<(), JournalError>>,
    pending_socket: Option<Result<(), RecordBindingError>>,
    disposition: Option<Result<(), JournalError>>,
    clock_disposal: Option<rustix::time::Timespec>,
    deadline_disposal: Option<Result<(), JournalError>>,
    cutoff: Option<u64>,
    first: Option<First>,
    reentry: Option<JournalError>,
}

impl IoOriginals {
    pub(crate) fn new() -> Self {
        Self {
            turn: None, retain_cookie_originals: false,
            socket_native: None, after_socket_native: None, pending_socket_native: None,
            binding: None, socket: None,
            before: ProtectedJournalCurrentnessOriginalsV1::new(), before_result: None,
            clock_before: None, deadline_before: None,
            after_binding: None, after_socket: None,
            after: ProtectedJournalCurrentnessOriginalsV1::new(), after_result: None,
            clock_after: None, deadline_after: None,
            pending_socket: None, disposition: None,
            clock_disposal: None, deadline_disposal: None, cutoff: None,
            first: None, reentry: None,
        }
    }

    pub(crate) fn fixed_demand(directory: &str) -> Result<ResourceVector, JournalError> {
        let one = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            std::path::Path::new(directory), "session.journal",
        )?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<DeleteInventoryIoDisposalV1<'_>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Delete Inventory IO originals"))?;
        one.checked_add(one)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn traffic_demand(directory: &str, network: u64, output: u64)
        -> Result<ResourceVector, JournalError> {
        let one = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            std::path::Path::new(directory), "session.journal",
        )?;
        let names = aos_sandbox_model::component_receiving::operation_traffic_demand_v1(one);
        names.checked_add(names).and_then(|demand| demand.checked_add(
            ResourceVector::ZERO.with(D::NetworkBytes, network).with(D::OutputBytes, output),
        )).map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn retain_cookie_originals_once_v2(&mut self) -> Result<(), JournalError> {
        if !self.is_idle() || self.retain_cookie_originals {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.retain_cookie_originals = true;
        Ok(())
    }

    pub(crate) fn begin(&mut self, turn: Turn, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, expected_journal: &StorageNativeOpeningOwnerLinkV1,
        expected_socket: &StorageSeqpacketSessionOriginV1, protocol: BrokerSessionProtocolV1,
        binding: [u8; 32], method: BrokerMethod, directory: &str, uid: u32, cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.turn.is_some() || self.first.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.turn = Some(turn);
        self.cutoff = Some(cutoff);
        self.binding = Some((|| {
            if expected_journal.matches_journal_v1(journal)
                && transcript.protocol() == protocol
                && transcript.session_binding() == binding
                && inventory_recipe(transcript)?.1 == method
            {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            }
        })());
        if self.binding.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Binding);
            return Err(JournalError::ProtectedBoundary);
        }
        self.socket = Some(if self.retain_cookie_originals {
            expected_socket.require_same_socket_retaining_v4(socket, &mut self.socket_native)
        } else {
            expected_socket.require_same_socket(socket)
        });
        if self.socket.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Socket);
            return Err(JournalError::ProtectedBoundary);
        }
        self.before_result = Some(journal.validate_held_owned_at_for_uid_retaining(
            directory, "session.journal", uid, &mut self.before,
        ));
        if self.before_result.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Before);
        }
        self.clock_before = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.deadline_before = Some(require_before(self.clock_before, cutoff));
        if self.deadline_before.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::ClockBefore);
        }
        self.status()
    }

    pub(crate) fn after(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        expected_journal: &StorageNativeOpeningOwnerLinkV1,
        expected_socket: &StorageSeqpacketSessionOriginV1,
        protocol: BrokerSessionProtocolV1, binding: [u8; 32], cutoff: u64) -> Result<(), JournalError> {
        if self.turn.is_none() || self.after_result.is_some() || self.clock_after.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.after_binding = Some(if expected_journal.matches_journal_v1(journal)
            && transcript.protocol() == protocol && transcript.session_binding() == binding
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) });
        if self.after_binding.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::AfterBinding);
        }
        self.after_socket = Some(if self.retain_cookie_originals {
            expected_socket.require_same_socket_retaining_v4(socket, &mut self.after_socket_native)
        } else {
            expected_socket.require_same_socket(socket)
        });
        if self.after_socket.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::AfterSocket);
        }
        if self.before_result.is_some() {
            // This direct owed sampler never re-enters a healthy C/account.
            self.after_result = Some(journal.observe_held_names_post_retaining_v1(&mut self.after));
            if self.after_result.as_ref().is_some_and(Result::is_err) {
                self.first.get_or_insert(First::After);
            }
        }
        self.clock_after = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.deadline_after = Some(require_before(self.clock_after, cutoff));
        if self.deadline_after.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::ClockAfter);
        }
        self.status()
    }

    fn status(&self) -> Result<(), JournalError> {
        if self.first.is_none() { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Binding => error(&self.binding),
            First::Socket => error(&self.socket_native).or_else(|| error(&self.socket)),
            First::Before => self.before.failure().or_else(|| error(&self.before_result)),
            First::ClockBefore => error(&self.deadline_before),
            First::AfterBinding => error(&self.after_binding),
            First::AfterSocket => error(&self.after_socket_native).or_else(|| error(&self.after_socket)),
            First::After => self.after.failure().or_else(|| error(&self.after_result)),
            First::ClockAfter => error(&self.deadline_after),
            First::PendingSocket => error(&self.pending_socket_native).or_else(|| error(&self.pending_socket)),
            First::Disposition => error(&self.disposition),
            First::ClockDisposal => error(&self.deadline_disposal),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    pub(crate) fn positive_turn_v1(&self) -> Result<Turn, JournalError> {
        if self.first.is_some() || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
            || !matches!(self.deadline_before, Some(Ok(())))
            || !matches!(self.deadline_after, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.turn.ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn prepare_send_pending_v1<'positive>(
        &'positive mut self,
        native: &StorageSeqpacketSendAttemptV1,
        socket: &SeqpacketSocket,
    ) -> Result<DeleteInventoryIoDisposalV1<'positive>, JournalError> {
        let positive = self.positive_turn_v1().map(|turn| {
            turn == Turn::Send && native.is_nonconsuming()
        });
        self.require_disposition(matches!(positive, Ok(true)))?;
        self.pending_socket = Some(if self.retain_cookie_originals {
            native.require_same_socket_retaining_v4(socket, &mut self.pending_socket_native)
        } else {
            native.require_same_socket(socket)
        });
        if self.pending_socket.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::PendingSocket);
            return Err(JournalError::ProtectedBoundary);
        }
        self.disposal_clock()?;
        Ok(DeleteInventoryIoDisposalV1 { original: self, completed: false })
    }

    pub(crate) fn prepare_receive_pending_v1<'positive>(
        &'positive mut self,
        native: &RetainedSeqpacketReceiveErrorV1,
    ) -> Result<DeleteInventoryIoDisposalV1<'positive>, JournalError> {
        let positive = self.positive_turn_v1().map(|turn| {
            turn == Turn::Receive
                && (native.is_nonconsuming_would_block() || native.is_nonconsuming_interrupted())
        });
        self.require_disposition(matches!(positive, Ok(true)))?;
        self.disposal_clock()?;
        Ok(DeleteInventoryIoDisposalV1 { original: self, completed: false })
    }

    pub(crate) fn prepare_wait_positive_v1(
        &mut self,
    ) -> Result<DeleteInventoryIoDisposalV1<'_>, JournalError> {
        let positive = self.positive_turn_v1()
            .map(|turn| matches!(turn, Turn::WaitSend | Turn::WaitReceive));
        self.require_disposition(matches!(positive, Ok(true)))?;
        self.disposal_clock()?;
        Ok(DeleteInventoryIoDisposalV1 { original: self, completed: false })
    }

    pub(crate) fn complete_consumed_turn_v1(&mut self) -> Result<(), JournalError> {
        let positive = self.positive_turn_v1()
            .map(|turn| matches!(turn, Turn::Preparation | Turn::Send | Turn::Receive));
        self.require_disposition(matches!(positive, Ok(true)))?;
        self.disposal_clock()?;
        self.retire_positive();
        Ok(())
    }

    fn require_disposition(&mut self, positive: bool) -> Result<(), JournalError> {
        if self.disposition.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.disposition = Some(if positive { Ok(()) } else {
            Err(JournalError::ProtectedBoundary)
        });
        if !positive {
            self.first.get_or_insert(First::Disposition);
        }
        self.status()
    }

    fn disposal_clock(&mut self) -> Result<(), JournalError> {
        if self.clock_disposal.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.clock_disposal = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.deadline_disposal = Some(require_before(self.clock_disposal, self.cutoff.unwrap_or(0)));
        if self.deadline_disposal.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::ClockDisposal);
        }
        self.status()
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.turn.is_none() && self.first.is_none()
    }

    fn retire_positive(&mut self) {
        self.before.settle_positive_once_v1();
        self.after.settle_positive_once_v1();
        *self = Self::new();
    }
}

/// Keeps positive per-IO originals exclusive through actual raw disposal.
#[must_use]
pub struct DeleteInventoryIoDisposalV1<'positive> {
    original: &'positive mut IoOriginals,
    completed: bool,
}

impl DeleteInventoryIoDisposalV1<'_> {
    /// Completes only after the actual positive raw receipt was disposed.
    pub fn complete_after_receipt_disposal(mut self) {
        self.original.retire_positive();
        self.completed = true;
    }

    /// Completes only after the actual successful poll capsule was disposed.
    pub fn complete_after_wait_disposal(self) {
        self.complete_after_receipt_disposal();
    }
}

impl Drop for DeleteInventoryIoDisposalV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.original.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.original.first.get_or_insert(First::Reentry);
        }
    }
}

pub(crate) fn require_before(sample: Option<rustix::time::Timespec>, cutoff: u64) -> Result<(), JournalError> {
    let sample = sample.ok_or(JournalError::ProtectedBoundary)?;
    let seconds = u64::try_from(sample.tv_sec).map_err(|_| JournalError::ProtectedBoundary)?;
    let nanos = u64::try_from(sample.tv_nsec).map_err(|_| JournalError::ProtectedBoundary)?;
    let observed = seconds.checked_mul(1_000_000_000).and_then(|seconds| seconds.checked_add(nanos))
        .ok_or(JournalError::ProtectedBoundary)?;
    if cutoff == 0 || observed >= cutoff { return Err(JournalError::ProtectedBoundary); }
    Ok(())
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
