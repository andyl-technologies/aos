//! Listener adoption with inherited, pre-enqueue record-subject options.
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

use super::{SeqpacketError, SeqpacketSocket, map_kernel_error};
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

impl RecordSubjectListener {
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
        uapi::require_seqpacket_identity(self.fd.as_fd()).map_err(map_kernel_error)?;
        let child =
            uapi::accept_record_subject_socket(self.fd.as_fd()).map_err(map_kernel_error)?;
        uapi::require_seqpacket_identity(child.as_fd()).map_err(map_kernel_error)?;
        SeqpacketSocket::from_owned(child)
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
    use std::os::fd::AsRawFd;

    fn configured_listener() -> RecordSubjectListener {
        let fd = uapi::seqpacket_listener().expect("create listener");
        uapi::enable_seqpacket_identity(fd.as_fd()).expect("configure listener");
        RecordSubjectListener::from_owned(fd).expect("adopt listener")
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
            let high = uapi::duplicate_at_least(fd.as_fd(), 1024).expect("duplicate test FD");
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
