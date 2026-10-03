//! Original-endpoint custody for strict receives and their partial evidence.
//!
//! The attempt owns initialized syscall buffers, adopted ordinary descriptors,
//! partial process pins and complete subjects before later checks. Its armed
//! destructor shuts down the same socket before dropping that custody. Denied
//! or uninspected descriptors are disposed immediately; their retained words
//! are historical DATA, never usable descriptors or process-drain evidence.

use std::fmt;
use std::num::NonZeroU64;
use std::os::fd::{AsFd as _, OwnedFd};

use super::{KernelAuthorizedRecordSubject, RecordCredentials, SeqpacketError, checked_pid};
use crate::pidfd::PidFd;
use crate::uapi::{self, RawAncillary, RawReceiveObservationV1, ReceiveCustodyPolicyV1};

/// Owns a strict receive failure without exposing its captured sensitive data.
///
/// No constructor or descriptor accessor is provided. Retained preview data
/// is incomplete evidence, not a consumed record or proof that peers drained.
/// Only a failed, nonconsuming `recvmsg` before any captured sample permits a
/// retry. Errors after consumption remain fatal even when their errno would
/// ordinarily indicate interruption or backpressure.
pub struct RetainedSeqpacketReceiveErrorV1 {
    source: SeqpacketError,
    attempt: Option<Box<ReceiveAttemptV1>>,
    retry: RetryV1,
    additional_shutdown_failure: Option<std::io::Error>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryV1 {
    Never,
    WouldBlock,
    Interrupted,
}

impl RetainedSeqpacketReceiveErrorV1 {
    /// Reports backpressure only for an actual nonconsuming initial syscall.
    #[must_use]
    pub fn is_nonconsuming_would_block(&self) -> bool {
        self.retry == RetryV1::WouldBlock
    }

    /// Reports interruption only for an actual nonconsuming initial syscall.
    #[must_use]
    pub fn is_nonconsuming_interrupted(&self) -> bool {
        self.retry == RetryV1::Interrupted
    }

    /// Borrows the first recorded failure to shut down original custody.
    ///
    /// An inner retained-attempt failure takes precedence over an additional
    /// outer stream failure; both remain owned by this error. Absence reports
    /// no recorded failure, not successful shutdown, EOF, retirement or Drain.
    #[must_use]
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.attempt
            .as_ref()
            .and_then(|attempt| attempt.shutdown_failure.as_ref())
            .or(self.additional_shutdown_failure.as_ref())
    }

    pub(crate) fn before_receive(source: SeqpacketError) -> Self {
        Self {
            source,
            attempt: None,
            retry: RetryV1::Never,
            additional_shutdown_failure: None,
        }
    }

    pub(crate) fn record_shutdown_failure(&mut self, failure: Option<std::io::Error>) {
        self.additional_shutdown_failure = failure;
    }
}

impl fmt::Debug for RetainedSeqpacketReceiveErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedSeqpacketReceiveErrorV1")
            .field("retry", &self.retry)
            .field("captured_samples", &self.attempt.as_ref().map(|attempt| attempt.messages.len()))
            .field("additional_shutdown_failed", &self.additional_shutdown_failure.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RetainedSeqpacketReceiveErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("original strict receive failed; partial custody is retained")
    }
}

impl std::error::Error for RetainedSeqpacketReceiveErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) struct CapturedMessageV1 {
    pub(crate) payload: Vec<u8>,
    pub(crate) raw: RawReceiveObservationV1,
    credentials: Option<RecordCredentials>,
    partial_pidfd: Option<PidFd>,
    pub(crate) subject: Option<KernelAuthorizedRecordSubject>,
    pub(crate) socket_context: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
pub(crate) enum SubjectProfileV1 {
    Ordinary,
    Descriptors { expected: usize, allow_empty: bool },
    Stream,
}

impl CapturedMessageV1 {
    fn empty(maximum: usize) -> Self {
        Self {
            payload: vec![0; maximum],
            raw: RawReceiveObservationV1::empty(),
            credentials: None,
            partial_pidfd: None,
            subject: None,
            socket_context: None,
        }
    }

    fn legacy(ancillary: Vec<RawAncillary>) -> Self {
        Self {
            raw: RawReceiveObservationV1::legacy_slots(ancillary),
            ..Self::empty(0)
        }
    }

    /// Borrows staging throughout the original profile-specific check order.
    pub(crate) fn validate(
        &mut self,
        profile: SubjectProfileV1,
        policy: ReceiveCustodyPolicyV1,
    ) -> Result<(), SeqpacketError> {
        match profile {
            SubjectProfileV1::Descriptors { expected, allow_empty } => {
                let mut found = false;
                let mut length = 0;
                for item in self.raw.ancillary.iter().flatten() {
                    if let RawAncillary::Rights(fds) = item {
                        if found || fds.len() != expected || expected == 0 {
                            return Err(SeqpacketError::Ancillary("inexact SCM_RIGHTS descriptor table"));
                        }
                        found = true;
                        length = fds.len();
                    }
                }
                if length != expected && !(allow_empty && length == 0) {
                    return Err(SeqpacketError::Ancillary("missing SCM_RIGHTS descriptor table"));
                }
            }
            SubjectProfileV1::Stream => {
                for item in self.raw.ancillary.iter().flatten() {
                    if let RawAncillary::SecurityContext(context) = item {
                        if self.socket_context.is_some() || context.len() < 2 || context.len() > 256
                            || context.last() != Some(&0)
                            || context[..context.len() - 1].iter().any(|byte| !byte.is_ascii_graphic())
                        {
                            return Err(SeqpacketError::Ancillary("inexact SCM_SECURITY context"));
                        }
                        self.socket_context = Some(context[..context.len() - 1].to_vec());
                    }
                }
                if self.socket_context.is_none() {
                    return Err(SeqpacketError::Ancillary("missing SCM_SECURITY"));
                }
            }
            SubjectProfileV1::Ordinary => {}
        }

        // Keep encounter-order pidfd validation: a later structural error must
        // not hide an earlier kernel failure, nor the converse.
        for index in 0..self.raw.ancillary.len() {
            match self.raw.ancillary[index].as_ref() {
                Some(RawAncillary::Credentials(raw)) if self.credentials.is_none() => {
                    let pid = checked_pid(raw.pid)
                        .ok_or(SeqpacketError::Ancillary("invalid SCM_CREDENTIALS pid"))?;
                    self.credentials = Some(RecordCredentials {
                        pid,
                        uid: raw.uid,
                        gid: raw.gid,
                    });
                }
                Some(RawAncillary::Credentials(_)) => {
                    return Err(SeqpacketError::Ancillary("duplicate SCM_CREDENTIALS"));
                }
                Some(RawAncillary::PidFd(_)) if self.partial_pidfd.is_none() => {
                    match PidFd::adopt_received_slot(&mut self.raw.ancillary[index]) {
                        Ok(pidfd) => self.partial_pidfd = Some(pidfd),
                        Err(source) => {
                            if policy == ReceiveCustodyPolicyV1::Retaining {
                                self.raw.screen_failed_pidfd(index);
                            }
                            return Err(source.into());
                        }
                    }
                }
                Some(RawAncillary::PidFd(_)) => {
                    return Err(SeqpacketError::Ancillary("duplicate SCM_PIDFD"));
                }
                Some(RawAncillary::Rights(_)) if matches!(profile, SubjectProfileV1::Descriptors { .. }) => {}
                Some(RawAncillary::SecurityContext(_)) if matches!(profile, SubjectProfileV1::Stream) => {}
                Some(RawAncillary::Rights(_)) => {
                    return Err(SeqpacketError::Ancillary("SCM_RIGHTS is forbidden"));
                }
                Some(RawAncillary::SecurityContext(_)) => {
                    return Err(SeqpacketError::Ancillary(
                        "SCM_SECURITY is forbidden by this record profile",
                    ));
                }
                Some(RawAncillary::Unknown { .. }) => {
                    return Err(SeqpacketError::Ancillary("unknown control message"));
                }
                Some(RawAncillary::Malformed(_)) => {
                    return Err(SeqpacketError::Ancillary("malformed control message"));
                }
                None => {}
            }
        }
        let credentials = self.credentials.ok_or(SeqpacketError::Ancillary("missing SCM_CREDENTIALS"))?;
        let pidfd = self.partial_pidfd.as_ref().ok_or(SeqpacketError::Ancillary("missing SCM_PIDFD"))?;
        let initial_info = pidfd.info()?;
        if initial_info.pid() != credentials.pid().get() {
            return Err(SeqpacketError::Ancillary("SCM_CREDENTIALS and SCM_PIDFD identify different processes"));
        }

        // Every fallible observation is finished before moving the pin. The
        // complete subject immediately returns to this same guarded staging.
        if let Some(pidfd) = self.partial_pidfd.take() {
            self.subject = Some(KernelAuthorizedRecordSubject {
                credentials,
                pidfd,
                initial_info,
            });
            Ok(())
        } else {
            Err(SeqpacketError::Ancillary("missing SCM_PIDFD"))
        }
    }

    pub(crate) fn take_descriptors(&mut self) -> Vec<OwnedFd> {
        for slot in &mut self.raw.ancillary {
            if matches!(slot, Some(RawAncillary::Rights(_))) {
                match slot.take() {
                    Some(RawAncillary::Rights(fds)) => return fds,
                    other => *slot = other,
                }
            }
        }
        Vec::new()
    }
}

/// Uses the same borrowed profile checker without changing legacy shutdown.
pub(crate) fn validate_legacy(
    ancillary: Vec<RawAncillary>,
    profile: SubjectProfileV1,
) -> Result<(KernelAuthorizedRecordSubject, Vec<OwnedFd>, Option<Vec<u8>>), SeqpacketError> {
    let mut message = CapturedMessageV1::legacy(ancillary);
    message.validate(profile, ReceiveCustodyPolicyV1::Legacy)?;
    let subject = message.subject.take().ok_or(SeqpacketError::Ancillary("missing SCM_PIDFD"))?;
    Ok((subject, message.take_descriptors(), message.socket_context.take()))
}

/// Owns the same endpoint and all staged resources, including during unwind.
pub(crate) struct ReceiveAttemptV1 {
    endpoint: OwnedFd,
    original_cookie: Option<NonZeroU64>,
    armed: bool,
    pub(crate) messages: Vec<CapturedMessageV1>,
    shutdown_failure: Option<std::io::Error>,
}

impl ReceiveAttemptV1 {
    pub(crate) fn capture(
        fd: std::os::fd::BorrowedFd<'_>,
        cookie: NonZeroU64,
    ) -> Result<Self, RetainedSeqpacketReceiveErrorV1> {
        let endpoint = uapi::duplicate_at_least(fd, 0)
            .map_err(|source| RetainedSeqpacketReceiveErrorV1::before_receive(source.into()))?;
        let mut attempt = Self {
            endpoint,
            original_cookie: None,
            armed: true,
            messages: Vec::new(),
            shutdown_failure: None,
        };
        let observed = uapi::socket_cookie(attempt.endpoint.as_fd());
        if let Ok(value) = &observed {
            attempt.original_cookie = NonZeroU64::new(*value);
        }
        match observed {
            Ok(value) if value == cookie.get() => Ok(attempt),
            Ok(_) => Err(attempt.reject(SeqpacketError::Ancillary("original socket cookie changed"))),
            Err(source) => Err(attempt.reject(source.into())),
        }
    }

    pub(crate) fn receive(
        &mut self,
        maximum: usize,
        flags: i32,
    ) -> Result<usize, uapi::RawReceiveFailureV1> {
        if self.messages.len() >= 2 {
            return Err(uapi::RawReceiveFailureV1 {
                source: crate::Error::invalid("original receive samples", "fixed two-sample ceiling exceeded"),
                nonconsuming_syscall: false,
            });
        }

        self.messages.push(CapturedMessageV1::empty(maximum));
        let index = self.messages.len() - 1;
        let message = &mut self.messages[index];
        uapi::recv_seqpacket_staged(
            self.endpoint.as_fd(),
            &mut message.payload,
            flags,
            &mut message.raw,
            ReceiveCustodyPolicyV1::Retaining,
        )
    }

    pub(crate) fn syscall_failure(
        mut self,
        failure: uapi::RawReceiveFailureV1,
    ) -> RetainedSeqpacketReceiveErrorV1 {
        let retry = if failure.nonconsuming_syscall
            && self.messages.iter().all(|message| !message.raw.received)
        {
            match &failure.source {
                crate::Error::Syscall { source, .. } if source.raw_os_error() == Some(libc::EAGAIN) => RetryV1::WouldBlock,
                crate::Error::Syscall { source, .. } if source.raw_os_error() == Some(libc::EINTR) => RetryV1::Interrupted,
                _ => RetryV1::Never,
            }
        } else {
            RetryV1::Never
        };

        if retry != RetryV1::Never {
            self.armed = false;
            RetainedSeqpacketReceiveErrorV1 {
                source: failure.source.into(),
                attempt: Some(Box::new(self)),
                retry,
                additional_shutdown_failure: None,
            }
        } else {
            self.reject(failure.source.into())
        }
    }

    pub(crate) fn reject(mut self, source: SeqpacketError) -> RetainedSeqpacketReceiveErrorV1 {
        self.end_original();
        RetainedSeqpacketReceiveErrorV1 {
            source,
            attempt: Some(Box::new(self)),
            retry: RetryV1::Never,
            additional_shutdown_failure: None,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    fn end_original(&mut self) {
        if !self.armed {
            return;
        }

        // Exclude forbidden and unscreened capabilities before retaining error
        // custody. Screened ordinary FDs and typed pins remain owned through
        // shutdown, including when this function is reached during unwind.
        for message in &mut self.messages {
            message.raw.dispose_unscreened();
        }
        self.shutdown_failure = rustix::net::shutdown(&self.endpoint, rustix::net::Shutdown::Both)
            .err().map(std::io::Error::from);
        self.armed = false;
    }
}

impl Drop for ReceiveAttemptV1 {
    fn drop(&mut self) {
        self.end_original();
    }
}

pub(crate) fn receive_packet(
    mut attempt: ReceiveAttemptV1,
    maximum: usize,
    profile: SubjectProfileV1,
) -> Result<ReceiveAttemptV1, RetainedSeqpacketReceiveErrorV1> {
    let expected = match attempt.receive(1, libc::MSG_PEEK | libc::MSG_TRUNC) {
        Ok(bytes) => bytes,
        Err(failure) => return Err(attempt.syscall_failure(failure)),
    };
    let preview = &mut attempt.messages[0];
    let preflight = (|| {
        if preview.raw.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        preview.validate(profile, ReceiveCustodyPolicyV1::Retaining)?;
        if expected == 0 {
            return Err(SeqpacketError::EmptyRecord);
        }
        if expected > maximum {
            return Err(SeqpacketError::RecordTooLarge { actual: expected, maximum });
        }
        Ok(())
    })();
    if let Err(source) = preflight {
        return Err(attempt.reject(source));
    }

    let actual = match attempt.receive(expected, 0) {
        Ok(bytes) => bytes,
        Err(failure) => return Err(attempt.syscall_failure(failure)),
    };
    let message = &mut attempt.messages[1];
    let validated = (|| {
        if message.raw.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        if message.raw.flags & libc::MSG_TRUNC != 0 {
            return Err(SeqpacketError::PayloadTruncated);
        }
        if actual != expected {
            return Err(SeqpacketError::LengthChanged { previewed: expected, received: actual });
        }
        message.validate(profile, ReceiveCustodyPolicyV1::Retaining)
    })();
    if let Err(source) = validated {
        return Err(attempt.reject(source));
    }
    Ok(attempt)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use super::*;
    use crate::seqpacket::SeqpacketSocket;

    #[test]
    fn absent_shutdown_debt_is_not_a_closed_or_drain_proof() {
        let error = RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum);

        assert!(error.shutdown_failure().is_none());
        assert!(matches!(std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::InvalidMaximum)));
    }

    #[test]
    fn outer_shutdown_failure_is_borrowed_without_removing_its_owner() {
        let mut error = RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed);
        error.record_shutdown_failure(Some(std::io::Error::from(std::io::ErrorKind::PermissionDenied)));
        let original = error.additional_shutdown_failure.as_ref().unwrap() as *const std::io::Error;

        assert_eq!(error.shutdown_failure().unwrap() as *const std::io::Error, original);
        assert_eq!(error.shutdown_failure().unwrap().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.additional_shutdown_failure.as_ref().unwrap() as *const std::io::Error, original);
        assert!(error.attempt.is_none());
    }

    fn pair() -> (SeqpacketSocket, SeqpacketSocket) {
        let (left, right) = uapi::seqpacket_pair().unwrap();
        let mut left = SeqpacketSocket::from_owned(left).unwrap();
        let mut right = SeqpacketSocket::from_owned(right).unwrap();
        left.enable_record_subjects().unwrap();
        right.enable_record_subjects().unwrap();
        (left, right)
    }

    #[test]
    fn initial_nonconsuming_backpressure_keeps_the_original_connection() {
        let (mut sender, mut receiver) = pair();
        let error = receiver.receive_retaining(64).unwrap_err();

        assert!(error.is_nonconsuming_would_block());
        assert!(!error.is_nonconsuming_interrupted());
        assert!(receiver.as_fd().is_ok());
        drop(error);

        sender.send(b"same original attempt carrier").unwrap();
        assert_eq!(receiver.receive_retaining(64).unwrap().payload(), b"same original attempt carrier");
    }

    #[test]
    fn preview_then_nonconsuming_consume_failure_is_fatal_and_prefix_only() {
        let (mut sender, receiver) = pair();
        let complete = b"original queued body exceeds its peek prefix";
        sender.send(complete).unwrap();
        let mut attempt = ReceiveAttemptV1::capture(receiver.as_fd().unwrap(), receiver.peer().socket_cookie()).unwrap();
        assert_eq!(attempt.receive(1, libc::MSG_PEEK | libc::MSG_TRUNC).unwrap(), complete.len());
        attempt.messages[0].validate(SubjectProfileV1::Ordinary, ReceiveCustodyPolicyV1::Retaining).unwrap();
        // Consume through the sole original owner to create a real subsequent
        // EAGAIN; the retained attempt still owns its actual independent peek.
        let consumed = receiver.consume_exact(complete.len()).unwrap();
        let failure = attempt.receive(complete.len(), 0).unwrap_err();
        let error = attempt.syscall_failure(failure);

        assert!(!error.is_nonconsuming_would_block());
        let attempt = error.attempt.as_ref().unwrap();
        let preview = &attempt.messages[0];
        assert_eq!(preview.payload, complete[..1]);
        assert_eq!(preview.raw.reported, complete.len() as isize);
        assert_eq!(preview.raw.captured_length(preview.payload.len()), 1);
        assert_eq!(preview.raw.requested_flags, libc::MSG_PEEK | libc::MSG_TRUNC);
        assert!(preview.subject.is_some());
        assert!(!attempt.messages[1].raw.received);
        assert_eq!(consumed.payload(), complete);
        assert!(sender.send(b"must not revive").is_err());
    }

    #[test]
    fn descriptor_rejection_keeps_screened_ordinary_custody_until_after_shutdown() {
        let (mut sender, mut receiver) = pair();
        let ordinary = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(b"private body not printable", &[ordinary.as_fd()]).unwrap();
        let error = receiver.receive_retaining(64).unwrap_err();

        assert!(matches!(error.source, SeqpacketError::Ancillary("SCM_RIGHTS is forbidden")));
        assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
        let attempt = error.attempt.as_ref().unwrap();
        let Some(RawAncillary::Rights(fds)) = attempt.messages[0].raw.ancillary.iter().flatten()
            .find(|item| matches!(item, RawAncillary::Rights(_))) else { panic!("ordinary slot disappeared"); };
        let raw = fds[0].as_raw_fd();
        assert!(uapi::raw_fd_is_open(raw));
        assert!(sender.send(b"permanently ended").is_err());
        let debug = format!("{error:?}");
        assert!(!debug.contains("private body"));
        assert!(!debug.contains("/dev/null"));
        drop(error);
        assert!(!uapi::raw_fd_is_open(raw));
    }

    #[test]
    fn unwind_shuts_down_before_staged_ordinary_custody_drops() {
        let (mut sender, receiver) = pair();
        let ordinary = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(b"unwind prefix", &[ordinary.as_fd()]).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut attempt = ReceiveAttemptV1::capture(receiver.as_fd().unwrap(), receiver.peer().socket_cookie()).unwrap();
            attempt.receive(1, libc::MSG_PEEK | libc::MSG_TRUNC).unwrap();
            panic!("intentional post-staging unwind");
        }));

        assert!(result.is_err());
        assert!(sender.send(b"not a renewed invocation").is_err());
    }

    #[test]
    fn postconsumption_errno_is_never_retryable() {
        for errno in [libc::EAGAIN, libc::EINTR] {
            let (_sender, receiver) = pair();
            let mut attempt = ReceiveAttemptV1::capture(receiver.as_fd().unwrap(), receiver.peer().socket_cookie()).unwrap();
            // This private stage fixture tests error selection, not a kernel
            // receive, authority, complete-custody receipt or syscall outcome.
            attempt.messages.push(CapturedMessageV1::empty(1));
            attempt.messages[0].raw.received = true;
            let failure = uapi::RawReceiveFailureV1 {
                source: crate::Error::Syscall { operation: "post-receive inspection fixture", source: std::io::Error::from_raw_os_error(errno) },
                nonconsuming_syscall: false,
            };
            let error = attempt.syscall_failure(failure);

            assert!(!error.is_nonconsuming_would_block());
            assert!(!error.is_nonconsuming_interrupted());
            assert!(matches!(error.source, SeqpacketError::Kernel(crate::Error::Syscall { .. })));
        }
    }

    #[test]
    fn failed_pidfd_candidate_keeps_the_actual_screened_ordinary_descriptor() {
        let (mut sender, receiver) = pair();
        let ordinary = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(b"candidate failure", &[ordinary.as_fd()]).unwrap();
        let mut attempt = ReceiveAttemptV1::capture(receiver.as_fd().unwrap(), receiver.peer().socket_cookie()).unwrap();
        attempt.receive(64, 0).unwrap();
        let message = &mut attempt.messages[0];
        // Replace only this private test's staged variant. The actual FD stays
        // owned in the attempt; the checker must refuse it as a process pin.
        let index = message.raw.ancillary.iter().position(|item| matches!(item, Some(RawAncillary::Rights(_)))).unwrap();
        let slot = &mut message.raw.ancillary[index];
        let Some(RawAncillary::Rights(mut fds)) = slot.take() else { panic!("missing rights"); };
        let fd = fds.pop().unwrap();
        let original = fd.as_raw_fd();
        *slot = Some(RawAncillary::PidFd(fd));
        // The real kernel-provided pidfd would otherwise validate first.
        // Remove that exact pin from the profile while retaining it in another
        // guarded private staging slot, then validate this bad candidate.
        let kernel = message.raw.ancillary.iter().position(|item| matches!(item, Some(RawAncillary::PidFd(fd)) if fd.as_raw_fd() != original)).unwrap();
        let retained = PidFd::adopt_received_slot(&mut message.raw.ancillary[kernel]).unwrap();
        let mut held_pin = CapturedMessageV1::empty(0);
        held_pin.partial_pidfd = Some(retained);
        attempt.messages.push(held_pin);
        let source = attempt.messages[0].validate(SubjectProfileV1::Ordinary, ReceiveCustodyPolicyV1::Retaining).unwrap_err();
        let error = attempt.reject(source);

        assert!(matches!(error.source, SeqpacketError::Kernel(crate::Error::WrongDescriptorType { expected: "pidfd" })));
        assert!(uapi::raw_fd_is_open(original));
        assert!(sender.send(b"no retry").is_err());
        drop(error);
        assert!(!uapi::raw_fd_is_open(original));
    }

    #[test]
    fn exact_descriptor_success_preserves_ordinary_order_and_subject() {
        let (mut sender, mut receiver) = pair();
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/zero").unwrap();
        sender.send_with_descriptors(b"complete exact body", &[first.as_fd(), second.as_fd()]).unwrap();
        let record = receiver.receive_with_descriptors_retaining(64, 2).unwrap();
        let (payload, subject, fds) = record.into_parts();

        assert_eq!(payload, b"complete exact body");
        assert_eq!(subject.initial_info().pid(), std::process::id());
        assert_eq!(std::fs::read_link(format!("/proc/self/fd/{}", fds[0].as_raw_fd())).unwrap(), std::path::Path::new("/dev/null"));
        assert_eq!(std::fs::read_link(format!("/proc/self/fd/{}", fds[1].as_raw_fd())).unwrap(), std::path::Path::new("/dev/zero"));
        assert!(receiver.as_fd().is_ok());
    }

    #[test]
    fn profile_precedence_remains_closed_and_legacy_compatible() {
        let credentials = RawAncillary::Credentials(libc::ucred { pid: 0, uid: 0, gid: 0 });
        let error = validate_legacy(vec![credentials], SubjectProfileV1::Descriptors { expected: 2, allow_empty: false }).unwrap_err();
        assert!(matches!(error, SeqpacketError::Ancillary("missing SCM_RIGHTS descriptor table")));

        let credentials = RawAncillary::Credentials(libc::ucred { pid: 0, uid: 0, gid: 0 });
        let error = validate_legacy(vec![credentials], SubjectProfileV1::Stream).unwrap_err();
        assert!(matches!(error, SeqpacketError::Ancillary("missing SCM_SECURITY")));

        for expected in [1, 2, 5] {
            let error = validate_legacy(Vec::new(), SubjectProfileV1::Descriptors { expected, allow_empty: true }).unwrap_err();
            assert!(matches!(error, SeqpacketError::Ancillary("missing SCM_CREDENTIALS")));
        }
    }
}
