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

use super::{AncestorHostRecordPinV1, KernelAuthorizedRecordSubject, RecordCredentials, SeqpacketError, checked_pid};
use aos_linux_descriptors::pidfd::PidFd;
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
    original_capture_failed: bool,
    uncaptured_original: Option<(OwnedFd, Result<(), std::io::Error>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryV1 {
    Never,
    WouldBlock,
    Interrupted,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ReceiveFailureDispositionV4 {
    Existing,
    RetainUncapturedOriginal,
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
            .or_else(|| self.uncaptured_original.as_ref().and_then(|(_, result)| result.as_ref().err()))
    }

    pub(crate) fn before_receive(source: SeqpacketError) -> Self {
        Self {
            source,
            attempt: None,
            retry: RetryV1::Never,
            additional_shutdown_failure: None,
            original_capture_failed: false,
            uncaptured_original: None,
        }
    }

    fn before_original_capture(source: SeqpacketError) -> Self {
        Self { original_capture_failed: true, ..Self::before_receive(source) }
    }

    pub(super) fn needs_original_capture_v4(&self) -> bool {
        self.original_capture_failed && self.attempt.is_none()
    }

    pub(super) fn retain_uncaptured_original_v4(
        &mut self,
        endpoint: OwnedFd,
        shutdown: Result<(), std::io::Error>,
    ) {
        // This is the existing socket, moved only when no same-OFD duplicate
        // was acquired. The failed duplicate remains the primary source.
        self.uncaptured_original = Some((endpoint, shutdown));
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
    ancestor_credentials: Option<(u32, u32)>,
    pub(crate) ancestor: Option<AncestorHostRecordPinV1>,
    pub(crate) subject: Option<KernelAuthorizedRecordSubject>,
    pub(crate) socket_context: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
pub(crate) enum SubjectProfileV1 {
    Ordinary,
    Descriptors { expected: usize, allow_empty: bool },
    AgentAuthorizeV2,
    GuestSshListenersV1,
    NetworkObserverPublicHandoff6,
    NetworkPreparationFirstV2,
    NetworkPreparationOwedFirstOrAckV3,
    Stream,
    NetworkPid1CredentialsOnly,
    AncestorHost { credentials: (u32, u32), pin: (u64, u64) },
}

#[cfg(test)]
mod network_pid1_credentials_tests {
    use super::*;

    fn credentials(pid: i32, uid: u32, gid: u32) -> RawAncillary {
        RawAncillary::Credentials(libc::ucred { pid, uid, gid })
    }

    #[test]
    fn credentials_only_reply_never_constructs_a_fresh_subject() {
        let mut message = CapturedMessageV1::legacy(vec![credentials(1, 0, 0)]);
        message.validate(SubjectProfileV1::NetworkPid1CredentialsOnly,
            ReceiveCustodyPolicyV1::Retaining).unwrap();

        assert!(message.subject.is_none());
        assert!(message.partial_pidfd.is_none());
        assert_eq!(message.credentials.unwrap().pid().get(), 1);
    }

    #[test]
    fn credentials_only_reply_refuses_missing_duplicate_or_foreign_nomination() {
        for ancillary in [vec![], vec![credentials(2, 0, 0)],
            vec![credentials(1, 1, 0)], vec![credentials(1, 0, 1)],
            vec![credentials(1, 0, 0), credentials(1, 0, 0)]]
        {
            let mut message = CapturedMessageV1::legacy(ancillary);
            assert!(message.validate(SubjectProfileV1::NetworkPid1CredentialsOnly,
                ReceiveCustodyPolicyV1::Retaining).is_err());
            assert!(message.subject.is_none());
            assert!(message.partial_pidfd.is_none());
        }
    }
}

#[cfg(test)]
mod network_observer_rights_tests {
    use super::*;

    fn rights(count: usize) -> RawAncillary {
        RawAncillary::Rights((0..count).map(|_| {
            std::fs::File::open("/dev/null").unwrap().into()
        }).collect())
    }

    #[test]
    fn observer_requires_one_exact_six_right_table_before_subject_admission() {
        for count in [0, 1, 2, 3, 4, 5, 7] {
            let mut message = CapturedMessageV1::legacy(vec![rights(count)]);
            let error = message.validate(SubjectProfileV1::NetworkObserverPublicHandoff6,
                ReceiveCustodyPolicyV1::Retaining).unwrap_err();
            assert!(matches!(error, SeqpacketError::Ancillary("inexact SCM_RIGHTS descriptor table")));
        }
        let mut duplicate = CapturedMessageV1::legacy(vec![rights(6), rights(6)]);
        assert!(matches!(duplicate.validate(SubjectProfileV1::NetworkObserverPublicHandoff6,
            ReceiveCustodyPolicyV1::Retaining),
            Err(SeqpacketError::Ancillary("inexact SCM_RIGHTS descriptor table"))));

        let mut exact = CapturedMessageV1::legacy(vec![rights(6)]);
        assert!(matches!(exact.validate(SubjectProfileV1::NetworkObserverPublicHandoff6,
            ReceiveCustodyPolicyV1::Retaining),
            Err(SeqpacketError::Ancillary("missing SCM_CREDENTIALS"))));
        assert!(exact.subject.is_none());
    }
}

impl CapturedMessageV1 {
    fn empty(maximum: usize) -> Self {
        Self::with_control(maximum, uapi::ReceiveControlProfileV1::Standard)
    }

    fn with_control(maximum: usize, control: uapi::ReceiveControlProfileV1) -> Self {
        Self {
            payload: vec![0; maximum],
            raw: RawReceiveObservationV1::with_control(control),
            credentials: None,
            partial_pidfd: None,
            ancestor_credentials: None,
            ancestor: None,
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
            SubjectProfileV1::NetworkPid1CredentialsOnly => {
                // This narrow response follows an already-authenticated PID1
                // child-origin record on the same retained channel. It never
                // constructs a KernelAuthorizedRecordSubject or Source.
                for item in self.raw.ancillary.iter().flatten() {
                    match item {
                        RawAncillary::Credentials(raw) if self.credentials.is_none()
                            && raw.pid == 1 && raw.uid == 0 && raw.gid == 0 =>
                        {
                            self.credentials = Some(RecordCredentials {
                                pid: std::num::NonZeroU32::MIN, uid: 0, gid: 0,
                            });
                        }
                        _ => return Err(SeqpacketError::Ancillary(
                            "Network Source reply requires only exact PID1 credentials")),
                    }
                }
                return if self.credentials.is_some() { Ok(()) } else {
                    Err(SeqpacketError::Ancillary("missing PID1 reply credentials"))
                };
            }
            SubjectProfileV1::Descriptors { .. } | SubjectProfileV1::NetworkObserverPublicHandoff6 => {
                let (expected, allow_empty) = if let SubjectProfileV1::Descriptors { expected, allow_empty } = profile {
                    (expected, allow_empty)
                } else {
                    (6, false)
                };
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
            SubjectProfileV1::AgentAuthorizeV2 | SubjectProfileV1::GuestSshListenersV1
                | SubjectProfileV1::NetworkPreparationFirstV2
                | SubjectProfileV1::NetworkPreparationOwedFirstOrAckV3 => {
                let second = if matches!(profile, SubjectProfileV1::AgentAuthorizeV2) { 3 } else { 2 };
                let mut rights = None;
                for item in self.raw.ancillary.iter().flatten() {
                    if let RawAncillary::Rights(fds) = item {
                        if rights.is_some() || !(fds.len() == 1 || fds.len() == second) {
                            return Err(SeqpacketError::Ancillary(if matches!(profile, SubjectProfileV1::AgentAuthorizeV2) {
                                "inexact Agent descriptor table"
                            } else if matches!(profile, SubjectProfileV1::GuestSshListenersV1) {
                                "inexact SSH listener descriptor table"
                            } else { "inexact Network preparation descriptor table" }));
                        }
                        rights = Some(fds.len());
                    }
                }
                if matches!(profile, SubjectProfileV1::GuestSshListenersV1) && rights.is_none() {
                    return Err(SeqpacketError::Ancillary("missing SSH listener descriptor table"));
                }
                if matches!(profile, SubjectProfileV1::NetworkPreparationFirstV2) && rights.is_none() {
                    return Err(SeqpacketError::Ancillary("missing Network preparation descriptor table"));
                }
                // Agent control permits no rights; its other shapes remain
                // one sealed Stream/PTY or three Capture roles. SSH requires
                // its complete one-or-two actual listening-socket table.
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
            SubjectProfileV1::Ordinary | SubjectProfileV1::AncestorHost { .. } => {}
        }

        // Keep encounter-order pidfd validation: a later structural error must
        // not hide an earlier kernel failure, nor the converse.
        for index in 0..self.raw.ancillary.len() {
            if let SubjectProfileV1::AncestorHost { credentials, pin } = profile {
                match self.raw.ancillary[index].as_ref() {
                    Some(RawAncillary::Credentials(raw)) => {
                        if self.ancestor_credentials.is_some() {
                            return Err(SeqpacketError::Ancillary("duplicate SCM_CREDENTIALS"));
                        }
                        self.ancestor_credentials = Some((raw.uid, raw.gid));
                        if raw.pid != 0 || (raw.uid, raw.gid) != credentials {
                            return Err(SeqpacketError::Ancillary("ancestor Host credentials changed"));
                        }
                        continue;
                    }
                    Some(RawAncillary::PidFd(fd)) => {
                        if self.ancestor.is_some() {
                            return Err(SeqpacketError::Ancillary("duplicate SCM_PIDFD"));
                        }
                        let observed = crate::pidfd::require_ancestor_host_original(fd.as_fd());
                        match observed {
                            Ok(observed) if observed == pin => {}
                            Ok(_) => return Err(SeqpacketError::Ancillary("ancestor Host pin changed")),
                            Err(source) => {
                                self.raw.screen_failed_pidfd(index);
                                return Err(source.into());
                            }
                        }
                        // The actual staged kernel slot moves only after all
                        // fallible admission checks, directly into this owner.
                        if let Some(RawAncillary::PidFd(fd)) = self.raw.ancillary[index].take() {
                            self.ancestor = Some(AncestorHostRecordPinV1 { fd: fd.into_owned(), identity: pin });
                        }
                        continue;
                    }
                    _ => {}
                }
            }
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
                    match crate::pidfd::adopt_received_slot(&mut self.raw.ancillary[index]) {
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
                Some(RawAncillary::Rights(_)) if matches!(profile, SubjectProfileV1::Descriptors { .. }
                    | SubjectProfileV1::AgentAuthorizeV2 | SubjectProfileV1::GuestSshListenersV1
                    | SubjectProfileV1::NetworkObserverPublicHandoff6
                    | SubjectProfileV1::NetworkPreparationFirstV2
                    | SubjectProfileV1::NetworkPreparationOwedFirstOrAckV3) => {}
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
        if matches!(profile, SubjectProfileV1::AncestorHost { .. }) {
            if self.ancestor_credentials.is_none() || self.ancestor.is_none() {
                return Err(SeqpacketError::Ancillary("missing ancestor Host credentials or SCM_PIDFD"));
            }
            return Ok(());
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
    control: uapi::ReceiveControlProfileV1,
    armed: bool,
    pub(crate) messages: Vec<CapturedMessageV1>,
    shutdown_failure: Option<std::io::Error>,
    network_cutoff: Option<super::NetworkWorkerNativeCutoffV4>,
}

impl ReceiveAttemptV1 {
    pub(crate) fn capture(
        fd: std::os::fd::BorrowedFd<'_>,
        cookie: NonZeroU64,
    ) -> Result<Self, RetainedSeqpacketReceiveErrorV1> {
        Self::capture_with_control(fd, cookie, uapi::ReceiveControlProfileV1::Standard)
    }

    pub(crate) fn capture_with_control(
        fd: std::os::fd::BorrowedFd<'_>,
        cookie: NonZeroU64,
        control: uapi::ReceiveControlProfileV1,
    ) -> Result<Self, RetainedSeqpacketReceiveErrorV1> {
        Self::capture_with_network_cutoff_v4(fd, cookie, control, None)
    }

    pub(crate) fn capture_with_network_cutoff_v4(
        fd: std::os::fd::BorrowedFd<'_>,
        cookie: NonZeroU64,
        control: uapi::ReceiveControlProfileV1,
        network_cutoff: Option<super::NetworkWorkerNativeCutoffV4>,
    ) -> Result<Self, RetainedSeqpacketReceiveErrorV1> {
        if let Some(cutoff) = network_cutoff {
            cutoff.check_v4().map_err(|source|
                RetainedSeqpacketReceiveErrorV1::before_original_capture(source.into()))?;
        }
        let endpoint = aos_linux_descriptors::native::duplicate_at_least(fd, 0)
            .map_err(|source| RetainedSeqpacketReceiveErrorV1::before_original_capture(source.into()))?;
        let mut attempt = Self {
            endpoint,
            original_cookie: None,
            control,
            armed: true,
            messages: match control {
                uapi::ReceiveControlProfileV1::Standard | uapi::ReceiveControlProfileV1::ZeroAncillary => Vec::new(),
                // The paid report recipe includes exactly preview+consumed
                // CapturedMessage carriers before either native sample enters.
                uapi::ReceiveControlProfileV1::ComponentStartupReport5
                    | uapi::ReceiveControlProfileV1::NetworkChildOrigin9
                    | uapi::ReceiveControlProfileV1::NetworkBirthHandoff3
                    | uapi::ReceiveControlProfileV1::NetworkObserverPublicHandoff6
                    | uapi::ReceiveControlProfileV1::NetworkPid1CredentialsOnly => Vec::with_capacity(2),
                uapi::ReceiveControlProfileV1::Pid1ServiceOrigin
                    | uapi::ReceiveControlProfileV1::WorkerObserver
                    | uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80
                    | uapi::ReceiveControlProfileV1::AgentAuthorize
                    | uapi::ReceiveControlProfileV1::StreamContextWidth(_) => Vec::with_capacity(2),
            },
            shutdown_failure: None,
            network_cutoff,
        };
        let observed = aos_linux_descriptors::native::socket_cookie(attempt.endpoint.as_fd());
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
                source: aos_linux_descriptors::Error::invalid("original receive samples", "fixed two-sample ceiling exceeded"),
                nonconsuming_syscall: false,
            });
        }

        self.messages.push(CapturedMessageV1::with_control(maximum, self.control));
        let index = self.messages.len() - 1;
        let message = &mut self.messages[index];
        let cutoff = self.network_cutoff;
        let mut gate = || match cutoff {
            Some(cutoff) => cutoff.check_v4(),
            None => Ok(()),
        };
        uapi::recv_seqpacket_staged_with_gate_v4(
            self.endpoint.as_fd(),
            &mut message.payload,
            flags,
            &mut message.raw,
            ReceiveCustodyPolicyV1::Retaining,
            cutoff.map(|_| &mut gate as &mut dyn FnMut() -> aos_linux_descriptors::Result<()>),
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
                aos_linux_descriptors::Error::Syscall { source, .. } if source.raw_os_error() == Some(libc::EAGAIN) => RetryV1::WouldBlock,
                aos_linux_descriptors::Error::Syscall { source, .. } if source.raw_os_error() == Some(libc::EINTR) => RetryV1::Interrupted,
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
                original_capture_failed: false,
                uncaptured_original: None,
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
            original_capture_failed: false,
            uncaptured_original: None,
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
    attempt: ReceiveAttemptV1,
    maximum: usize,
    profile: SubjectProfileV1,
) -> Result<ReceiveAttemptV1, RetainedSeqpacketReceiveErrorV1> {
    let (attempt, expected) = preview_packet(attempt, maximum, profile, 1)?;
    consume_packet(attempt, expected, profile)
}

pub(crate) fn preview_packet(
    mut attempt: ReceiveAttemptV1,
    maximum: usize,
    profile: SubjectProfileV1,
    preview_bytes: usize,
) -> Result<(ReceiveAttemptV1, usize), RetainedSeqpacketReceiveErrorV1> {
    let expected = match attempt.receive(preview_bytes, libc::MSG_PEEK | libc::MSG_TRUNC) {
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

    Ok((attempt, expected))
}

pub(crate) fn consume_packet(
    mut attempt: ReceiveAttemptV1,
    expected: usize,
    profile: SubjectProfileV1,
) -> Result<ReceiveAttemptV1, RetainedSeqpacketReceiveErrorV1> {
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
        let (left, right) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        let mut left = SeqpacketSocket::from_owned(left).unwrap();
        let mut right = SeqpacketSocket::from_owned(right).unwrap();
        left.enable_record_subjects().unwrap();
        right.enable_record_subjects().unwrap();
        (left, right)
    }

    #[test]
    fn fixed_service_dup_failure_retains_only_original_socket() {
        const CHILD: &str = "AOS_FIXED_RECEIVE_DUP_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // Resource limits belong to an isolated test process, never the
            // parallel harness that owns unrelated native tests.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "seqpacket::receive_custody::tests::fixed_service_dup_failure_retains_only_original_socket",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let (_peer, mut selected) = pair();
        let (_ordinary_peer, mut ordinary) = pair();
        let selected_fd = selected.borrow_fd().unwrap().as_raw_fd();
        let ordinary_fd = ordinary.borrow_fd().unwrap().as_raw_fd();
        let cookie = aos_linux_descriptors::native::socket_cookie(selected.borrow_fd().unwrap()).unwrap();
        let old = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            // Keep F_DUPFD's minimum0 below the limit. The occupied standard
            // descriptors leave no free slot, producing EMFILE rather than EINVAL.
            rustix::process::Rlimit { current: Some(3), maximum: old.maximum },
        ).unwrap();

        let selected_result = selected.receive_fixed_service_request_retaining_v4(64);
        let ordinary_result = ordinary.receive_with_optional_descriptor_retaining(64);
        rustix::process::setrlimit(rustix::process::Resource::Nofile, old).unwrap();

        let selected_error = selected_result.unwrap_err();
        let ordinary_error = ordinary_result.unwrap_err();
        for error in [&selected_error, &ordinary_error] {
            assert!(matches!(&error.source,
                SeqpacketError::Kernel(aos_linux_descriptors::Error::Syscall { source, .. })
                    if source.raw_os_error() == Some(libc::EMFILE)));
            assert!(error.attempt.is_none());
            assert!(!error.is_nonconsuming_would_block());
            assert!(!error.is_nonconsuming_interrupted());
        }

        assert!(selected.fd.is_none());
        assert!(ordinary.fd.is_none());
        let (retained, shutdown) = selected_error.uncaptured_original.as_ref().unwrap();
        assert_eq!(retained.as_raw_fd(), selected_fd);
        assert_eq!(aos_linux_descriptors::native::socket_cookie(retained.as_fd()).unwrap(), cookie);
        assert!(shutdown.is_ok());
        assert!(aos_linux_descriptors::native::raw_fd_is_open(selected_fd));
        assert!(ordinary_error.uncaptured_original.is_none());
        assert!(!aos_linux_descriptors::native::raw_fd_is_open(ordinary_fd));

        drop(selected_error);
        assert!(!aos_linux_descriptors::native::raw_fd_is_open(selected_fd));
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
        assert!(aos_linux_descriptors::native::raw_fd_is_open(raw));
        assert!(sender.send(b"permanently ended").is_err());
        let debug = format!("{error:?}");
        assert!(!debug.contains("private body"));
        assert!(!debug.contains("/dev/null"));
        drop(error);
        assert!(!aos_linux_descriptors::native::raw_fd_is_open(raw));
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
                source: aos_linux_descriptors::Error::Syscall { operation: "post-receive inspection fixture", source: std::io::Error::from_raw_os_error(errno) },
                nonconsuming_syscall: false,
            };
            let error = attempt.syscall_failure(failure);

            assert!(!error.is_nonconsuming_would_block());
            assert!(!error.is_nonconsuming_interrupted());
            assert!(matches!(error.source, SeqpacketError::Kernel(aos_linux_descriptors::Error::Syscall { .. })));
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
        *slot = Some(RawAncillary::PidFd(aos_linux_descriptors::pidfd::PidFdAdmissionSlotV1::new(fd)));
        // The real kernel-provided pidfd would otherwise validate first.
        // Remove that exact pin from the profile while retaining it in another
        // guarded private staging slot, then validate this bad candidate.
        let kernel = message.raw.ancillary.iter().position(|item| matches!(item, Some(RawAncillary::PidFd(fd)) if fd.as_raw_fd() != original)).unwrap();
        let retained = crate::pidfd::adopt_received_slot(&mut message.raw.ancillary[kernel]).unwrap();
        let mut held_pin = CapturedMessageV1::empty(0);
        held_pin.partial_pidfd = Some(retained);
        attempt.messages.push(held_pin);
        let source = attempt.messages[0].validate(SubjectProfileV1::Ordinary, ReceiveCustodyPolicyV1::Retaining).unwrap_err();
        let error = attempt.reject(source);

        assert!(matches!(error.source, SeqpacketError::Kernel(aos_linux_descriptors::Error::WrongDescriptorType { expected: "pidfd" })));
        assert!(aos_linux_descriptors::native::raw_fd_is_open(original));
        assert!(sender.send(b"no retry").is_err());
        drop(error);
        assert!(!aos_linux_descriptors::native::raw_fd_is_open(original));
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

/// Reports the resident namespace charge for raw receive carriers.
///
/// Ancillary values, descriptor slots and native result carriers use the same
/// separately priced bytes and descriptor peak. They create no resident name
/// map, catalog, index or pathname entry.
pub(crate) fn requested_receive_metadata_cells_v1(
    _control: uapi::ReceiveControlProfileV1,
) -> Option<usize> {
    Some(0)
}
