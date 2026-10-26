//! Retains one deadline-bounded initial-floor approval transport exchange.
//!
//! The request is one opaque 322-byte record; its response is one 64-byte
//! signature record. Canonical decoding, genuine funding, listener provenance,
//! key independence and approval verification belong to the enclosing owner.
//! These native mechanics grant no provisioning or TPM authority.

use std::os::fd::BorrowedFd;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::time::{ClockId, clock_gettime};

use super::{
    ReceivedRecord, RecordSubjectListener, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1, RetainedSeqpacketSendErrorV1, SeqpacketError,
    SeqpacketOwnedShutdownOriginalV1, SeqpacketRightsRestrictionOriginalV6, SeqpacketSocket,
};

/// Fixes the initial request's transport size without decoding its format.
pub const INITIAL_APPROVAL_REQUEST_BYTES_V1: usize = 322;

/// Fixes the initial signature's transport size.
pub const INITIAL_APPROVAL_SIGNATURE_BYTES_V1: usize = 64;

/// Reports refusal while the exchange retains its actual native observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("initial approval exchange is closed")]
pub struct InitialApprovalExchangeClosedV1;

struct ReadinessOriginal {
    before: Option<Timespec>,
    timeout: Option<Timespec>,
    result: Option<rustix::io::Result<usize>>,
    events: Option<PollFlags>,
    after: Option<Timespec>,
}

impl ReadinessOriginal {
    const fn new() -> Self {
        Self {
            before: None,
            timeout: None,
            result: None,
            events: None,
            after: None,
        }
    }

    fn observe(&mut self, fd: BorrowedFd<'_>, expected: PollFlags, deadline: u64) -> bool {
        self.before = Some(clock_gettime(ClockId::Boottime));
        let Some(before) = self.before.and_then(nanoseconds) else {
            return false;
        };
        let Some(remaining) = deadline
            .checked_sub(before)
            .filter(|remaining| *remaining > 0)
        else {
            return false;
        };
        self.timeout = Some(Timespec {
            tv_sec: (remaining / 1_000_000_000) as i64,
            tv_nsec: (remaining % 1_000_000_000) as i64,
        });
        let mut descriptors = [PollFd::new(&fd, expected)];
        self.result = Some(poll(&mut descriptors, self.timeout.as_ref()));
        self.events = Some(descriptors[0].revents());
        self.after = Some(clock_gettime(ClockId::Boottime));

        matches!(self.result, Some(Ok(1)))
            && self.events == Some(expected)
            && self
                .after
                .and_then(nanoseconds)
                .is_some_and(|after| after < deadline)
    }
}

fn nanoseconds(sample: Timespec) -> Option<u64> {
    let seconds = u64::try_from(sample.tv_sec).ok()?;
    let nanos = u64::try_from(sample.tv_nsec)
        .ok()
        .filter(|nanos| *nanos < 1_000_000_000)?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

/// Owns the reached outcomes of one finite initial-approval exchange.
///
/// Construction performs no IO. The caller prepays these carriers and keeps
/// its original listener throughout the exchange and independently owed posts.
/// There is one poll and at most one native operation per stage. Interruption,
/// backpressure after readiness and timeout refuse without retry or disposal
/// credit. Failed child admission, send and receive custody remain resident.
#[must_use = "retain the original exchange and its reached native outcomes"]
pub struct InitialApprovalExchangeOriginalV1 {
    request: Option<[u8; INITIAL_APPROVAL_REQUEST_BYTES_V1]>,
    deadline: Option<u64>,
    readiness: [ReadinessOriginal; 3],
    accepted: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    accept_after: Option<Timespec>,
    restriction: SeqpacketRightsRestrictionOriginalV6,
    restriction_result: Option<Result<(), SeqpacketError>>,
    restriction_after: Option<Timespec>,
    sent: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: Option<Timespec>,
    received: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    receive_after: Option<Timespec>,
    shutdown: SeqpacketOwnedShutdownOriginalV1,
    shutdown_result: Option<Result<(), SeqpacketError>>,
    shutdown_after: Option<Timespec>,
    signature:
        Option<Result<[u8; INITIAL_APPROVAL_SIGNATURE_BYTES_V1], std::array::TryFromSliceError>>,
    entered: bool,
    complete: bool,
    closed: bool,
}

impl InitialApprovalExchangeOriginalV1 {
    /// Creates inert destinations without observing a clock or descriptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            request: None,
            deadline: None,
            readiness: std::array::from_fn(|_| ReadinessOriginal::new()),
            accepted: None,
            accept_after: None,
            restriction: SeqpacketRightsRestrictionOriginalV6::new(),
            restriction_result: None,
            restriction_after: None,
            sent: None,
            send_after: None,
            received: None,
            receive_after: None,
            shutdown: SeqpacketOwnedShutdownOriginalV1::new(),
            shutdown_result: None,
            shutdown_after: None,
            signature: None,
            entered: false,
            complete: false,
            closed: false,
        }
    }

    /// Prices retained native carriers and the complete zero-rights receive peak.
    ///
    /// The pair is byte storage and newly retained descriptor slots. It excludes
    /// the caller's listener, socket kernel-buffer policy and enclosing Source
    /// accounting; it creates no funding authority and credits no failed disposal.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize)> {
        let (admission, admission_files) =
            super::raw_admission_obligations_v3::<SeqpacketSocket>()?;
        let (restriction, _) = SeqpacketRightsRestrictionOriginalV6::receiving_obligations_v6()?;
        let (receive, receive_files) = SeqpacketSocket::closed_zero_rights_receive_obligations_v1(
            INITIAL_APPROVAL_SIGNATURE_BYTES_V1,
        )?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(admission)?
            .checked_add(restriction)?
            .checked_add(receive)?
            .checked_add(16 * 1024)?;
        Some((
            bytes,
            admission_files.checked_add(receive_files)?.checked_add(1)?,
        ))
    }

    /// Exchanges exactly one request and signature under one absolute boot deadline.
    ///
    /// The deadline uses nanoseconds of `CLOCK_BOOTTIME`. The accepted child is
    /// restricted to zero incoming rights before publishing the request; queued
    /// data at that restriction refuses. The approver must wait for the request
    /// before sending its signature. Native record-subject checks still apply.
    /// Late successes remain resident and cannot expose a signature.
    /// The original active child is shut down on every reached exit, with its
    /// descriptor and native result retained. This local cleanup proves no peer
    /// termination or drain; cleanup remains owed after deadline expiry.
    ///
    /// # Errors
    /// Refuses reentry, invalid/expired time, readiness failure, failed native
    /// admission/restriction/send/receive, or an inexact signature length. It
    /// never retries, repairs a listener, or replaces an earlier native result.
    pub fn exchange_once_v1(
        &mut self,
        listener: &mut RecordSubjectListener,
        request: [u8; INITIAL_APPROVAL_REQUEST_BYTES_V1],
        deadline: u64,
    ) -> Result<(), InitialApprovalExchangeClosedV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(InitialApprovalExchangeClosedV1);
        }
        self.entered = true;
        self.request = Some(request);
        self.deadline = Some(deadline);
        let exchanged = self.exchange(listener, deadline);
        // Cleanup is independently owed even after a late success or an earlier
        // comparison failure. Fatal native errors already retain shutdown debt
        // with their original socket; no substitute descriptor is manufactured.
        if let Some(Ok(socket)) = self.accepted.as_mut() {
            if socket.as_fd().is_ok() {
                self.shutdown_result = Some(self.shutdown.shutdown_once_v1(socket));
                self.shutdown_after = Some(clock_gettime(ClockId::Boottime));
            }
        }
        // Publish the positive phase only after cleanup and its clock sample;
        // a caught unwind must never expose a partly completed signature.
        self.complete = exchanged
            && matches!(self.shutdown_result, Some(Ok(())))
            && self
                .shutdown_after
                .and_then(nanoseconds)
                .is_some_and(|after| after < deadline);
        self.closed = !self.complete;
        if self.complete {
            Ok(())
        } else {
            Err(InitialApprovalExchangeClosedV1)
        }
    }

    fn exchange(&mut self, listener: &mut RecordSubjectListener, deadline: u64) -> bool {
        if !self.readiness[0].observe(listener.as_fd(), PollFlags::IN, deadline) {
            return false;
        }
        self.accepted = Some(listener.accept_retaining());
        self.accept_after = Some(clock_gettime(ClockId::Boottime));
        let Some(Ok(socket)) = self.accepted.as_mut() else {
            return false;
        };
        if !self
            .accept_after
            .and_then(nanoseconds)
            .is_some_and(|after| after < deadline)
        {
            return false;
        }
        self.restriction_result =
            Some(socket.restrict_incoming_rights_retaining_v6(&mut self.restriction));
        self.restriction_after = Some(clock_gettime(ClockId::Boottime));
        if !matches!(self.restriction_result, Some(Ok(())))
            || !self
                .restriction_after
                .and_then(nanoseconds)
                .is_some_and(|after| after < deadline)
        {
            return false;
        }
        let Ok(fd) = socket.as_fd() else {
            return false;
        };
        if !self.readiness[1].observe(fd, PollFlags::OUT, deadline) {
            return false;
        }
        let Some(request) = &self.request else {
            return false;
        };
        self.sent = Some(socket.send_retaining(request));
        self.send_after = Some(clock_gettime(ClockId::Boottime));
        if !matches!(self.sent, Some(Ok(())))
            || !self
                .send_after
                .and_then(nanoseconds)
                .is_some_and(|after| after < deadline)
        {
            return false;
        }
        let Ok(fd) = socket.as_fd() else {
            return false;
        };
        if !self.readiness[2].observe(fd, PollFlags::IN, deadline) {
            return false;
        }
        if socket
            .require_rights_restriction_current_v6(&self.restriction)
            .is_err()
        {
            return false;
        }
        self.received = Some(socket.receive_ordinary_retaining_with_control(
            INITIAL_APPROVAL_SIGNATURE_BYTES_V1,
            crate::uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
        ));
        self.receive_after = Some(clock_gettime(ClockId::Boottime));
        let Some(Ok(record)) = self.received.as_ref() else {
            return false;
        };
        self.signature = Some(record.payload().try_into());
        matches!(self.signature, Some(Ok(_)))
            && self
                .receive_after
                .and_then(nanoseconds)
                .is_some_and(|after| after < deadline)
    }

    /// Copies signature DATA only after the complete original exchange succeeded.
    ///
    /// This verifies no signature and authenticates no independent approval key.
    #[must_use]
    pub fn signature_data_v1(&self) -> Option<[u8; INITIAL_APPROVAL_SIGNATURE_BYTES_V1]> {
        if self.complete && !self.closed {
            self.signature
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied()
        } else {
            None
        }
    }

    /// Borrows the first retained native error, if a native operation failed.
    ///
    /// Clock, readiness-flag and length comparisons can refuse without a native
    /// error. Absence therefore establishes neither completion nor approval.
    #[must_use]
    pub fn native_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for readiness in &self.readiness {
            if let Some(Err(error)) = &readiness.result {
                return Some(error);
            }
        }
        if let Some(Err(error)) = &self.accepted {
            return Some(error);
        }
        if let Some(Err(error)) = &self.restriction_result {
            return Some(error);
        }
        if let Some(Err(error)) = &self.sent {
            return Some(error);
        }
        if let Some(Err(error)) = &self.received {
            return Some(error);
        }
        self.shutdown.failure().map(|error| error as _)
    }
}

impl Default for InitialApprovalExchangeOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_conversion_refuses_negative_malformed_and_overflowed_samples() {
        assert_eq!(
            nanoseconds(Timespec {
                tv_sec: 2,
                tv_nsec: 3
            }),
            Some(2_000_000_003)
        );
        for sample in [
            Timespec {
                tv_sec: -1,
                tv_nsec: 0,
            },
            Timespec {
                tv_sec: 0,
                tv_nsec: -1,
            },
            Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            },
            Timespec {
                tv_sec: i64::MAX,
                tv_nsec: 0,
            },
        ] {
            assert_eq!(nanoseconds(sample), None);
        }
    }

    #[test]
    fn expiry_keeps_the_original_request_and_never_enters_accept_or_retry() {
        let directory = tempfile::tempdir().unwrap();
        let mut listener =
            RecordSubjectListener::bind(&directory.path().join("approval.sock"), 1).unwrap();
        let mut original = InitialApprovalExchangeOriginalV1::new();

        assert!(
            original
                .exchange_once_v1(&mut listener, [7; INITIAL_APPROVAL_REQUEST_BYTES_V1], 0)
                .is_err()
        );

        assert_eq!(
            original.request,
            Some([7; INITIAL_APPROVAL_REQUEST_BYTES_V1])
        );
        assert_eq!(original.deadline, Some(0));
        assert!(original.readiness[0].before.is_some());
        assert!(original.readiness[0].result.is_none());
        assert!(original.accepted.is_none());
        assert!(original.shutdown_result.is_none());
        let first_clock = original.readiness[0].before;

        assert!(
            original
                .exchange_once_v1(
                    &mut listener,
                    [9; INITIAL_APPROVAL_REQUEST_BYTES_V1],
                    u64::MAX
                )
                .is_err()
        );

        assert_eq!(
            original.request,
            Some([7; INITIAL_APPROVAL_REQUEST_BYTES_V1])
        );
        assert_eq!(original.deadline, Some(0));
        assert_eq!(original.readiness[0].before, first_clock);
        assert!(original.accepted.is_none());
        assert!(original.signature_data_v1().is_none());
    }

    #[test]
    fn inert_exchange_exposes_no_signature_or_deadline_and_prices_all_fd_slots() {
        let original = InitialApprovalExchangeOriginalV1::new();
        assert!(original.signature_data_v1().is_none());
        assert!(original.request.is_none());
        assert!(original.deadline.is_none());
        let (bytes, files) = InitialApprovalExchangeOriginalV1::receiving_obligations_v1().unwrap();
        assert!(bytes >= 2 * std::mem::size_of::<InitialApprovalExchangeOriginalV1>());
        assert_eq!(files, 6);
    }
}
