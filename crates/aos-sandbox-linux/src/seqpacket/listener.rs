//! Listener adoption with inherited, pre-enqueue record-subject reporting.
//!
//! Linux 6.18.33 `net/unix/af_unix.c:unix_stream_connect` copies the listener's
//! `sk_scm_recv_flags` into the pending child before publishing the connection.
//! `SOCK_SEQPACKET` uses that path; `unix_accept` later grafts the same child.
//! The flags include both `SO_PASSCRED` and `SO_PASSPIDFD`.
//!
//! systemd 259.8 applies socket options after creating its listening socket.
//! Consequently even a correctly configured activated listener can contain an
//! older child that inherited disabled options. Every accepted child is checked
//! independently and rejected, never repaired, if either option is missing.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Component;
use std::path::Path;

use super::descriptor_subject::DescriptorSubjectSocket;
use super::{
    PendingSocketAdmissionV1, RetainedSeqpacketAdmissionErrorV1, SeqpacketError,
    SeqpacketSocket, map_kernel_error,
};
use crate::uapi;

/// Owns a listener whose accepted records retain kernel-authorized subjects.
///
/// Socket activation must use `Accept=no`, `PassCredentials=yes`, and
/// `PassPIDFD=yes`. This type validates the listening descriptor and performs
/// acceptance itself; an arbitrary preaccepted socket cannot prove historical
/// option inheritance. In particular, systemd `Accept=yes` may modify a child's
/// options after acceptance and is not this contract.
///
/// Adoption does not authenticate a service manager or an application principal.
/// Callers must exclusively control listener configuration and acceptance: an
/// external duplicate capable of changing options or accepting connections is
/// outside this guarantee. The same restriction applies to accepted sockets.
#[derive(Debug)]
pub struct RecordSubjectListener {
    fd: OwnedFd,
}

/// Borrows a retained listener admission cause or a permanent closed state.
#[derive(Debug)]
pub enum ListenerAdmissionFailureRefV1<'a> {
    /// The original typed validation or pathname failure remains resident.
    Cause(&'a SeqpacketError),
    /// Admission was reentered, abandoned during checking, or already ended.
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerAdmissionPhaseV1 {
    Fresh,
    Checking,
    Ready,
    Ended,
    Taken,
}

/// Retains one original listening descriptor through one complete admission.
///
/// Kernel and pathname checks are mechanical DATA observations, not PID 1 or
/// application authority. The same exclusive configuration/acceptance contract
/// as [`RecordSubjectListener`] applies. A failed attempt exposes neither its
/// descriptor nor a listener; dropping it releases custody without proving
/// population drain. Higher owners must retain it across their own failures.
#[must_use]
pub struct RecordSubjectListenerAdmissionAttemptV1 {
    descriptor: Option<OwnedFd>,
    listener: Option<RecordSubjectListener>,
    phase: ListenerAdmissionPhaseV1,
    failure: Option<SeqpacketError>,
}

impl RecordSubjectListenerAdmissionAttemptV1 {
    /// Parks the original descriptor without observing or configuring it.
    #[must_use]
    pub const fn new(original: OwnedFd) -> Self {
        Self {
            descriptor: Some(original),
            listener: None,
            phase: ListenerAdmissionPhaseV1::Fresh,
            failure: None,
        }
    }

    /// Checks the original listener and its exact pathname once.
    ///
    /// Checking is armed before the validator. Only success of both checks
    /// permits handoff; a caught unwind remains nonextractable. Reentry closes
    /// admission without IO and does not replace an earlier typed cause.
    ///
    /// # Errors
    ///
    /// Borrows the first actual type, option, flag or pathname cause, or reports
    /// a closed phase. Every original remains in this attempt on rejection.
    pub fn admit_once(
        &mut self,
        expected: &Path,
    ) -> Result<(), ListenerAdmissionFailureRefV1<'_>> {
        if self.phase != ListenerAdmissionPhaseV1::Fresh
            || self.failure.is_some()
            || self.listener.is_some()
        {
            return Err(self.close());
        }
        self.phase = ListenerAdmissionPhaseV1::Checking;

        let Some(descriptor) = self.descriptor.as_ref() else {
            return Err(self.close());
        };
        if let Err(cause) =
            uapi::prepare_record_subject_listener(descriptor.as_fd()).map_err(map_kernel_error)
        {
            return Err(self.fail(cause));
        }

        // The actual validated listener is resident before the fallible path
        // check. There is deliberately no Ready interval between the checks.
        let Some(fd) = self.descriptor.take() else {
            return Err(self.close());
        };
        self.listener = Some(RecordSubjectListener { fd });
        let Some(listener) = self.listener.as_ref() else {
            return Err(self.close());
        };
        if let Err(cause) = listener.require_local_filesystem_path(expected) {
            return Err(self.fail(cause));
        }

        self.phase = ListenerAdmissionPhaseV1::Ready;
        Ok(())
    }

    /// Borrows the resident first failure without observing the original.
    #[must_use]
    pub fn first_failure(&self) -> Option<ListenerAdmissionFailureRefV1<'_>> {
        if self.failure.is_some() || self.phase == ListenerAdmissionPhaseV1::Ended {
            Some(self.failure_view())
        } else {
            None
        }
    }

    /// Moves the same completely admitted listener exactly once.
    ///
    /// No observation, allocation or repair follows the checked move. The
    /// receiving owner must park it before any fallible continuation.
    #[must_use]
    pub fn take_completed_listener(&mut self) -> Option<RecordSubjectListener> {
        if self.phase != ListenerAdmissionPhaseV1::Ready
            || self.failure.is_some()
            || self.descriptor.is_some()
            || self.listener.is_none()
        {
            return None;
        }

        let listener = self.listener.take();
        self.phase = ListenerAdmissionPhaseV1::Taken;
        listener
    }

    fn close(&mut self) -> ListenerAdmissionFailureRefV1<'_> {
        self.phase = ListenerAdmissionPhaseV1::Ended;
        self.failure_view()
    }

    fn fail(&mut self, cause: SeqpacketError) -> ListenerAdmissionFailureRefV1<'_> {
        self.failure.get_or_insert(cause);
        self.close()
    }

    fn failure_view(&self) -> ListenerAdmissionFailureRefV1<'_> {
        match &self.failure {
            Some(cause) => ListenerAdmissionFailureRefV1::Cause(cause),
            None => ListenerAdmissionFailureRefV1::Closed,
        }
    }
}

impl RecordSubjectListener {
    /// Creates an owned record-subject listener at a filesystem pathname.
    ///
    /// The pathname must be absolute, nonempty, NUL-free, and short enough for
    /// a trailing NUL in `sockaddr_un::sun_path`. `backlog` must be within
    /// `1..=4096`. The socket is nonblocking and close-on-exec, and both record
    /// identity options are enabled before the pathname is bound or exposed to
    /// connecting peers.
    ///
    /// This method never removes or replaces an existing pathname. A successful
    /// caller owns pathname cleanup; dropping the listener closes its descriptor
    /// but does not unlink the socket. A failure after a successful bind, such as
    /// a listen failure, can likewise leave the newly created socket entry for
    /// the caller to inspect and remove. Removing paths automatically would race
    /// another owner that replaced the entry.
    ///
    /// Filesystem pathname ownership and permissions control reachability; the
    /// pathname itself does not authenticate a host application principal.
    ///
    /// # Errors
    ///
    /// Returns an error when pathname or backlog validation fails, socket
    /// creation or configuration fails, or the kernel rejects bind or listen.
    /// In particular, binding an occupied pathname reports the kernel's
    /// `EADDRINUSE` error without unlinking that pathname.
    pub fn bind(path: &Path, backlog: u32) -> Result<Self, SeqpacketError> {
        let fd = uapi::bind_record_subject_listener(path, backlog).map_err(map_kernel_error)?;
        Self::from_owned(fd)
    }

    /// Adopts an already-configured Unix sequenced-packet listener.
    ///
    /// Requires both identity options already enabled, without modifying them.
    /// Establishes close-on-exec and nonblocking descriptor flags. For a newly
    /// created listener, enable both identity options before exposing it to peers.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong family/type, nonlistener, missing identity
    /// option, or failed descriptor inspection/configuration. The owned input
    /// descriptor closes on every rejection path.
    pub fn from_owned(fd: OwnedFd) -> Result<Self, SeqpacketError> {
        uapi::prepare_record_subject_listener(fd.as_fd()).map_err(map_kernel_error)?;
        Ok(Self { fd })
    }

    /// Rechecks that the retained listener still has both identity options.
    ///
    /// This is useful immediately before acceptance when the caller needs to
    /// distinguish a corrupted listener from one old queued child that lacks
    /// inherited identity options. Exclusive configuration ownership remains
    /// required; a successful observation is not a lock against later changes.
    ///
    /// # Errors
    ///
    /// Returns an error when either required socket option is now disabled or
    /// the kernel cannot inspect the listener.
    pub fn validate_current(&self) -> Result<(), SeqpacketError> {
        uapi::require_seqpacket_identity(self.fd.as_fd()).map_err(map_kernel_error)
    }

    /// Verifies the exact filesystem pathname bound to this listener.
    ///
    /// Abstract, unnamed, unterminated, and noncanonical local addresses are
    /// rejected rather than compared as filesystem paths.
    ///
    /// # Errors
    ///
    /// Returns an error when `expected` is not one normalized absolute path,
    /// `getsockname(2)` fails, or the retained listener is bound elsewhere.
    pub fn require_local_filesystem_path(&self, expected: &Path) -> Result<(), SeqpacketError> {
        let expected_bytes = expected.as_os_str().as_bytes();
        let normalized = expected.is_absolute()
            && expected_bytes.len() > 1
            && !expected_bytes.contains(&0)
            && expected_bytes[1..]
                .split(|byte| *byte == b'/')
                .all(|component| !component.is_empty() && !matches!(component, b"." | b".."))
            && expected
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
        if !normalized {
            return Err(SeqpacketError::Kernel(crate::Error::invalid(
                "record subject listener path",
                "must be a normalized absolute path",
            )));
        }
        let observed = uapi::unix_socket_local_filesystem_path(self.fd.as_fd())?;
        if observed != expected_bytes {
            return Err(SeqpacketError::Kernel(crate::Error::invalid(
                "record subject listener path",
                "differs from the fixed endpoint",
            )));
        }
        Ok(())
    }

    /// Accepts one child with independently checked inherited identity options.
    ///
    /// An older child queued before listener configuration is closed, not
    /// repaired. The listener remains available for subsequent connections.
    /// Received records retain the existing no-`SCM_RIGHTS` contract.
    ///
    /// # Errors
    ///
    /// Returns [`SeqpacketError::WouldBlock`] when the queue is empty and
    /// [`SeqpacketError::Interrupted`] on interruption. Rejects missing listener
    /// or child options, failed acceptance, and peer-identity adoption failure.
    /// Any newly accepted descriptor closes before a rejection is returned.
    pub fn accept(&mut self) -> Result<SeqpacketSocket, SeqpacketError> {
        let child = self.accept_child()?;
        uapi::require_seqpacket_identity(child.as_fd()).map_err(map_kernel_error)?;
        SeqpacketSocket::from_owned(child)
    }

    /// Accepts one child while retaining failed admission of its original socket.
    ///
    /// A child is parked before inherited-option and peer checks. Rejection
    /// shuts down the original but cannot repair its historical subject options
    /// or assert peer termination. The listener remains available.
    ///
    /// # Errors
    ///
    /// Returns the original validation, acceptance, option or peer failure.
    /// Pre-accept failures own no child; later failures retain the original
    /// descriptor and separate shutdown debt without permitting I/O or retry.
    pub fn accept_retaining(
        &mut self,
    ) -> Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1> {
        SeqpacketSocket::from_pending_retaining(self.accept_pending_child()?)
    }

    /// Accepts one descriptor-capable child with inherited record subjects.
    ///
    /// This has the same pre-enqueue reporting-option guarantee as
    /// [`Self::accept`], while retaining the bounded `SCM_RIGHTS` carrier used
    /// by privileged source-provider replies. The reported subject remains a
    /// kernel-authorized nomination; descriptor roles, writer/session equality,
    /// and application authority remain higher-level protocol decisions.
    ///
    /// # Errors
    ///
    /// Returns [`SeqpacketError::WouldBlock`] when the queue is empty and
    /// [`SeqpacketError::Interrupted`] on interruption. Rejects missing listener
    /// or child identity options, failed acceptance, or child adoption failure.
    pub fn accept_descriptor_subject(&mut self) -> Result<DescriptorSubjectSocket, SeqpacketError> {
        let child = self.accept_child()?;
        uapi::require_seqpacket_identity(child.as_fd()).map_err(map_kernel_error)?;
        DescriptorSubjectSocket::from_owned(child)
    }

    /// Accepts a descriptor-capable child while retaining failed original custody.
    ///
    /// It preserves the inherited-option-before-adoption order of
    /// `accept_descriptor_subject`. No child reporting options are repaired.
    ///
    /// # Errors
    ///
    /// Returns the first typed validation, acceptance, option or peer cause.
    /// Any accepted descriptor remains in the error after shutdown, with no
    /// descriptor extraction, revival, application authority or drain claim.
    pub fn accept_descriptor_subject_retaining(
        &mut self,
    ) -> Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1> {
        DescriptorSubjectSocket::from_pending_retaining(self.accept_pending_child()?)
    }

    fn accept_child(&mut self) -> Result<OwnedFd, SeqpacketError> {
        self.validate_current()?;
        let child =
            uapi::accept_record_subject_socket(self.fd.as_fd()).map_err(map_kernel_error)?;
        Ok(child)
    }

    fn accept_pending_child(
        &mut self,
    ) -> Result<PendingSocketAdmissionV1, RetainedSeqpacketAdmissionErrorV1> {
        self.validate_current()
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        let child = uapi::accept_record_subject_socket_before_flags(self.fd.as_fd())
            .map_err(map_kernel_error)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        let pending = PendingSocketAdmissionV1::new(child);
        let prepared = pending
            .prepare_accepted_descriptor()
            .and_then(|()| pending.require_inherited_subjects());
        if let Err(source) = prepared {
            return Err(pending.fail(source));
        }
        Ok(pending)
    }

    /// Borrows the listener for readiness polling, not competing acceptance or configuration.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Kernel fixture failures intentionally panic."
)]
mod tests {
    use super::*;
    use crate::Error;
    use std::ffi::OsStr;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileTypeExt as _;

    fn configured_listener() -> RecordSubjectListener {
        let fd = uapi::seqpacket_listener().expect("create listener");
        uapi::enable_seqpacket_identity(fd.as_fd()).expect("configure listener");
        RecordSubjectListener::from_owned(fd).expect("adopt listener")
    }

    #[test]
    fn retained_wrong_kind_keeps_same_descriptor_and_first_cause() {
        let original: OwnedFd = tempfile::tempfile().expect("ordinary file").into();
        let raw = original.as_raw_fd();
        let mut attempt = RecordSubjectListenerAdmissionAttemptV1::new(original);

        assert!(matches!(
            attempt.admit_once(Path::new("/tmp/unused-publisher-listener")),
            Err(ListenerAdmissionFailureRefV1::Cause(SeqpacketError::Kernel(_)))
        ));
        let first = std::ptr::from_ref(attempt.failure.as_ref().expect("actual first cause"));

        assert_eq!(
            attempt
                .descriptor
                .as_ref()
                .expect("resident original")
                .as_raw_fd(),
            raw
        );
        assert!(attempt.take_completed_listener().is_none());
        assert!(
            attempt
                .admit_once(Path::new("not-another-observation"))
                .is_err()
        );
        assert_eq!(
            std::ptr::from_ref(attempt.failure.as_ref().expect("same first cause")),
            first
        );
        assert_eq!(attempt.phase, ListenerAdmissionPhaseV1::Ended);
    }

    #[test]
    fn retained_missing_options_keep_original_without_repair() {
        for enabled in [libc::SO_PASSCRED, uapi::SO_PASSPIDFD] {
            let original = uapi::seqpacket_listener().expect("create listener");
            uapi::enable_test_socket_option(original.as_fd(), enabled)
                .expect("enable only one option");
            let raw = original.as_raw_fd();
            let mut attempt = RecordSubjectListenerAdmissionAttemptV1::new(original);

            assert!(matches!(
                attempt.admit_once(Path::new("/tmp/unused-publisher-listener")),
                Err(ListenerAdmissionFailureRefV1::Cause(
                    SeqpacketError::Kernel(Error::InvalidInput {
                        field: "record subject options",
                        ..
                    })
                ))
            ));

            let original = attempt.descriptor.as_ref().expect("resident original");
            assert_eq!(original.as_raw_fd(), raw);
            assert!(uapi::require_seqpacket_identity(original.as_fd()).is_err());
            assert!(attempt.take_completed_listener().is_none());
        }
    }

    #[test]
    fn retained_path_failure_keeps_validated_listener_nonextractable() {
        let directory = tempfile::tempdir().expect("test directory");
        let path = directory.path().join("original.sock");
        let listener = RecordSubjectListener::bind(&path, 1).expect("bind listener");
        let raw = listener.fd.as_raw_fd();
        let mut attempt = RecordSubjectListenerAdmissionAttemptV1::new(listener.fd);

        assert!(matches!(
            attempt.admit_once(&directory.path().join("different.sock")),
            Err(ListenerAdmissionFailureRefV1::Cause(
                SeqpacketError::Kernel(Error::InvalidInput {
                    field: "record subject listener path",
                    ..
                })
            ))
        ));

        assert!(attempt.descriptor.is_none());
        assert_eq!(
            attempt.listener.as_ref().expect("resident listener").fd.as_raw_fd(),
            raw
        );
        assert_eq!(attempt.phase, ListenerAdmissionPhaseV1::Ended);
        assert!(attempt.take_completed_listener().is_none());
    }

    #[test]
    fn checking_phase_cannot_extract_or_retry_even_with_resident_listener() {
        let directory = tempfile::tempdir().expect("test directory");
        let path = directory.path().join("original.sock");
        let listener = RecordSubjectListener::bind(&path, 1).expect("bind listener");
        let raw = listener.fd.as_raw_fd();
        let mut attempt = RecordSubjectListenerAdmissionAttemptV1::new(listener.fd);
        assert!(attempt.admit_once(&path).is_ok());

        // Pure phase vector: model a caught crossing unwind, not an executed
        // panic fixture or a positive PID 1/application provenance assertion.
        attempt.phase = ListenerAdmissionPhaseV1::Checking;
        assert!(attempt.take_completed_listener().is_none());
        assert!(matches!(
            attempt.admit_once(&path),
            Err(ListenerAdmissionFailureRefV1::Closed)
        ));
        assert!(attempt.take_completed_listener().is_none());
        assert_eq!(
            attempt.listener.as_ref().expect("resident listener").fd.as_raw_fd(),
            raw
        );
    }

    #[test]
    fn ready_reentry_ends_admission_without_handoff() {
        let directory = tempfile::tempdir().expect("test directory");
        let path = directory.path().join("original.sock");
        let listener = RecordSubjectListener::bind(&path, 1).expect("bind listener");
        let mut attempt = RecordSubjectListenerAdmissionAttemptV1::new(listener.fd);
        assert!(attempt.admit_once(&path).is_ok());

        assert!(matches!(
            attempt.admit_once(&path),
            Err(ListenerAdmissionFailureRefV1::Closed)
        ));

        assert_eq!(attempt.phase, ListenerAdmissionPhaseV1::Ended);
        assert!(attempt.listener.is_some());
        assert!(attempt.take_completed_listener().is_none());
    }

    #[test]
    fn complete_admission_hands_off_same_original_once() {
        let directory = tempfile::tempdir().expect("test directory");
        let path = directory.path().join("original.sock");
        let listener = RecordSubjectListener::bind(&path, 1).expect("bind listener");
        let raw = listener.fd.as_raw_fd();
        let mut attempt = RecordSubjectListenerAdmissionAttemptV1::new(listener.fd);

        assert!(attempt.admit_once(&path).is_ok());
        let listener = attempt
            .take_completed_listener()
            .expect("single completed listener");

        assert_eq!(listener.fd.as_raw_fd(), raw);
        assert_eq!(attempt.phase, ListenerAdmissionPhaseV1::Taken);
        assert!(attempt.first_failure().is_none());
        assert!(attempt.take_completed_listener().is_none());
        assert!(matches!(
            attempt.admit_once(&path),
            Err(ListenerAdmissionFailureRefV1::Closed)
        ));
    }

    #[test]
    fn preaccept_backpressure_and_interruption_are_no_child_failures() {
        for source in [SeqpacketError::WouldBlock, SeqpacketError::Interrupted] {
            let failure = RetainedSeqpacketAdmissionErrorV1::before_creation(source);

            assert!(matches!(
                failure.cause(),
                SeqpacketError::WouldBlock | SeqpacketError::Interrupted
            ));
            assert!(!failure.retains_descriptor());
            assert!(!failure.shutdown_attempted());
            assert!(failure.shutdown_failure().is_none());
        }
    }

    #[test]
    fn filesystem_bind_preserves_identity_flags_collision_and_path_ownership() {
        let directory = tempfile::tempdir().expect("test directory");
        let path = directory.path().join("record-subject.sock");
        let mut listener = RecordSubjectListener::bind(&path, 1).expect("bind listener");

        listener
            .require_local_filesystem_path(&path)
            .expect("validate exact listener path");
        assert!(matches!(
            listener.require_local_filesystem_path(&directory.path().join("other.sock")),
            Err(SeqpacketError::Kernel(Error::InvalidInput {
                field: "record subject listener path",
                ..
            }))
        ));
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("socket metadata")
                .file_type()
                .is_socket()
        );
        assert!(uapi::is_cloexec(listener.as_fd()).expect("listener CLOEXEC"));
        assert!(matches!(listener.accept(), Err(SeqpacketError::WouldBlock)));

        assert!(matches!(
            RecordSubjectListener::bind(&path, 1),
            Err(SeqpacketError::Kernel(Error::Syscall { source, .. }))
                if source.raw_os_error() == Some(libc::EADDRINUSE)
        ));

        let sender = uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect sender");
        uapi::send_seqpacket(sender.as_fd(), b"filesystem listener").expect("enqueue record");
        let mut child = listener.accept().expect("accept configured child");
        let record = child.receive(128).expect("receive record");
        assert_eq!(record.payload(), b"filesystem listener");
        assert_eq!(
            record.subject().credentials().pid().get(),
            std::process::id()
        );

        drop(listener);
        assert!(path.exists(), "listener drop must not unlink its pathname");
        std::fs::remove_file(path).expect("caller-owned pathname cleanup");
    }

    #[test]
    fn filesystem_bind_rejects_invalid_paths_and_backlogs() {
        let directory = tempfile::tempdir().expect("test directory");
        let valid_path = directory.path().join("valid.sock");
        let nul_path = Path::new(OsStr::from_bytes(b"/tmp/aos\0listener"));
        let long_path = Path::new(OsStr::from_bytes(&[b'/'; 200]));

        for path in [
            Path::new(""),
            Path::new("relative.sock"),
            nul_path,
            long_path,
        ] {
            assert!(matches!(
                RecordSubjectListener::bind(path, 1),
                Err(SeqpacketError::Kernel(Error::InvalidInput {
                    field: "record subject listener path",
                    ..
                }))
            ));
        }
        for backlog in [0, 4097] {
            assert!(matches!(
                RecordSubjectListener::bind(&valid_path, backlog),
                Err(SeqpacketError::Kernel(Error::InvalidInput {
                    field: "record subject listener backlog",
                    ..
                }))
            ));
        }
        assert!(!valid_path.exists());
    }

    #[test]
    fn preaccept_record_retains_identity_and_cloexec_descriptors() {
        let mut listener = configured_listener();
        let sender = uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect sender");
        uapi::send_seqpacket(sender.as_fd(), b"before accept").expect("enqueue before accept");
        let mut child = listener.accept().expect("accept configured child");
        let record = child.receive(128).expect("receive preaccepted message");
        assert_eq!(record.payload(), b"before accept");
        assert_eq!(
            record.subject().credentials().pid().get(),
            std::process::id()
        );
        assert!(uapi::is_cloexec(listener.as_fd()).expect("listener CLOEXEC"));
        assert!(uapi::is_cloexec(child.as_fd().expect("child FD")).expect("child CLOEXEC"));
        assert!(uapi::is_cloexec(record.subject().pidfd().as_fd()).expect("subject CLOEXEC"));
        assert!(matches!(listener.accept(), Err(SeqpacketError::WouldBlock)));
    }

    #[test]
    fn descriptor_capable_accept_retains_subject_and_exact_rights() {
        let mut listener = configured_listener();
        let sender = uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect sender");
        let mut sender = DescriptorSubjectSocket::from_owned(sender).expect("adopt sender");
        let file = tempfile::tempfile().expect("source descriptor");
        sender
            .send_with_descriptors(b"source", &[file.as_fd()])
            .expect("send source descriptor");

        let mut child = listener
            .accept_descriptor_subject()
            .expect("accept descriptor child");
        let record = child.receive(128, 1).expect("receive exact descriptor");
        assert_eq!(record.payload(), b"source");
        assert_eq!(record.descriptors().len(), 1);
        assert_eq!(
            record.subject().credentials().pid().get(),
            std::process::id()
        );
    }

    #[test]
    fn optional_descriptor_reply_accepts_zero_or_one_but_not_two() {
        let mut listener = configured_listener();
        let sender = uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect sender");
        let mut sender = DescriptorSubjectSocket::from_owned(sender).expect("adopt sender");
        sender.send(b"error").expect("send descriptor-free error");
        let mut child = listener
            .accept_descriptor_subject()
            .expect("accept descriptor child");
        assert_eq!(
            child
                .receive_optional_descriptor_reply(128)
                .expect("receive descriptor-free reply")
                .descriptors()
                .len(),
            0
        );

        let mut listener = configured_listener();
        let sender = uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect sender");
        let mut sender = DescriptorSubjectSocket::from_owned(sender).expect("adopt sender");
        let first = tempfile::tempfile().expect("first descriptor");
        let second = tempfile::tempfile().expect("second descriptor");
        sender
            .send_with_descriptors(b"hostile", &[first.as_fd(), second.as_fd()])
            .expect("send two descriptors");
        let mut child = listener
            .accept_descriptor_subject()
            .expect("accept hostile child");
        assert!(child.receive_optional_descriptor_reply(128).is_err());
    }

    #[test]
    fn queued_unconfigured_child_is_rejected_but_later_child_succeeds() {
        let fd = uapi::seqpacket_listener().expect("create listener");
        let old_sender =
            uapi::connect_seqpacket_listener(fd.as_fd()).expect("connect early sender");
        uapi::send_seqpacket(old_sender.as_fd(), b"early").expect("enqueue early message");
        uapi::enable_seqpacket_identity(fd.as_fd()).expect("configure after early connect");
        let mut listener =
            RecordSubjectListener::from_owned(fd).expect("adopt configured listener");
        assert!(matches!(
            listener.accept(),
            Err(SeqpacketError::Kernel(Error::InvalidInput {
                field: "record subject options",
                ..
            }))
        ));
        // Rejected child's peer has been closed, not retained in a hidden queue.
        assert!(uapi::send_seqpacket(old_sender.as_fd(), b"closed").is_err());
        let sender =
            uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect later sender");
        uapi::send_seqpacket(sender.as_fd(), b"later").expect("enqueue later message");
        let mut child = listener.accept().expect("accept later child");
        assert_eq!(
            child.receive(128).expect("read later message").payload(),
            b"later"
        );
    }

    #[test]
    fn missing_each_identity_option_rejects_and_closes_owned_listener() {
        for enabled in [libc::SO_PASSCRED, uapi::SO_PASSPIDFD] {
            let fd = uapi::seqpacket_listener().expect("create listener");
            uapi::enable_test_socket_option(fd.as_fd(), enabled).expect("enable only one option");
            // Use an otherwise-unused high FD to avoid incidental low-FD reuse
            // by concurrently running tests between rejection and observation.
            let high = uapi::duplicate_at_least(fd.as_fd(), 512).expect("duplicate test FD");
            let raw = high.as_raw_fd();
            assert!(RecordSubjectListener::from_owned(high).is_err());
            assert!(!uapi::raw_fd_is_open(raw));
        }
    }

    #[test]
    fn wrong_socket_type_and_nonlistener_are_rejected() {
        let stream = std::os::unix::net::UnixListener::bind(
            tempfile::tempdir()
                .expect("test directory")
                .path()
                .join("socket"),
        )
        .expect("create stream listener");
        assert!(RecordSubjectListener::from_owned(stream.into()).is_err());
        let fd = uapi::unconnected_seqpacket().expect("create unconnected socket");
        uapi::enable_seqpacket_identity(fd.as_fd()).expect("enable options");
        assert!(RecordSubjectListener::from_owned(fd).is_err());
    }

    #[test]
    fn oversized_record_closes_accepted_child() {
        let mut listener = configured_listener();
        let sender = uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect sender");
        uapi::send_seqpacket(sender.as_fd(), b"oversized").expect("enqueue oversized message");
        let mut child = listener.accept().expect("accept child");
        assert!(matches!(
            child.receive(4),
            Err(SeqpacketError::RecordTooLarge {
                actual: 9,
                maximum: 4
            })
        ));
        assert!(matches!(child.as_fd(), Err(SeqpacketError::Closed)));
    }

    #[test]
    fn accepted_connection_still_rejects_rights() {
        let mut listener = configured_listener();
        let sender = uapi::connect_seqpacket_listener(listener.as_fd()).expect("connect sender");
        let file = tempfile::tempfile().expect("test descriptor");
        uapi::send_seqpacket_rights(sender.as_fd(), b"forbidden", &[file.as_fd()])
            .expect("send rights");
        let mut child = listener.accept().expect("accept child");
        assert!(matches!(
            child.receive(128),
            Err(SeqpacketError::Ancillary("SCM_RIGHTS is forbidden"))
        ));
        assert!(matches!(child.as_fd(), Err(SeqpacketError::Closed)));
    }
}
