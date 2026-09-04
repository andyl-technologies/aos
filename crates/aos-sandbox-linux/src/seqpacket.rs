//! Fail-closed, descriptor-owning Unix `SOCK_SEQPACKET` transport primitives.
//!
//! The receiver measures one complete record with `MSG_PEEK | MSG_TRUNC`,
//! admits that length against a caller-owned ceiling, and only then allocates
//! and consumes the record. Every consumed record must carry exactly one
//! kernel-validated `SCM_CREDENTIALS` and one `SCM_PIDFD`. All other ancillary
//! data is rejected and every received descriptor is closed on every path.
//!
//! Adoption separately captures the connection establisher with `SO_PEERCRED`
//! and `SO_PEERPIDFD`. That peer remains useful for service-manager policy, but
//! Unix descriptor delegation means it need not be the process writing later
//! records. [`ConnectionPeerIdentity`] and [`KernelAuthorizedRecordSubject`]
//! therefore remain separate types and neither claims application provenance.

use std::num::NonZeroU32;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::Error;
use crate::pidfd::{PidFd, PidFdInfo};
use crate::uapi::{self, RawAncillary};

/// A nonblocking, close-on-exec Unix sequenced-packet socket.
#[derive(Debug)]
pub struct SeqpacketSocket {
    fd: Option<OwnedFd>,
    peer: ConnectionPeerIdentity,
}

impl SeqpacketSocket {
    /// Validates and adopts an owned connected Unix `SOCK_SEQPACKET` descriptor.
    ///
    /// The constructor makes the descriptor nonblocking and close-on-exec.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor is not a connected Unix
    /// sequenced-packet socket, its connection peer cannot be pinned, or its
    /// descriptor flags cannot be inspected or changed.
    pub fn from_owned(fd: OwnedFd) -> Result<Self, SeqpacketError> {
        uapi::prepare_seqpacket(fd.as_fd())?;
        let credentials = PeerCredentials::from_raw(uapi::peer_credentials(fd.as_fd())?)?;
        let pidfd = PidFd::from_owned(uapi::peer_pidfd(fd.as_fd())?)?;
        let initial_info = pidfd.info()?;
        if initial_info.pid() != credentials.pid().get() {
            return Err(SeqpacketError::PeerIdentity(
                "SO_PEERCRED and SO_PEERPIDFD identify different processes",
            ));
        }
        let peer = ConnectionPeerIdentity {
            credentials,
            pidfd,
            initial_info,
        };
        Ok(Self { fd: Some(fd), peer })
    }

    /// Returns the process that established this socket connection.
    ///
    /// This identity does not prove which process later writes a record. Unix
    /// socket descriptors can be delegated after connection establishment;
    /// inspect [`ReceivedRecord::subject`] for each record separately.
    #[must_use]
    pub const fn peer(&self) -> &ConnectionPeerIdentity {
        &self.peer
    }

    /// Enables kernel-validated credentials and generated pidfds on records.
    ///
    /// This must be called before an untrusted sender can enqueue records.
    ///
    /// # Errors
    ///
    /// Returns an error if either socket option is unavailable or rejected.
    /// A partially configured socket is closed before the error is returned.
    pub fn enable_record_subjects(&mut self) -> Result<(), SeqpacketError> {
        match uapi::enable_seqpacket_identity(self.borrow_fd()?) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.fd.take();
                Err(SeqpacketError::Kernel(error))
            }
        }
    }

    /// Borrows the socket for readiness polling while it remains usable.
    ///
    /// Consuming records through the borrowed descriptor violates this type's
    /// preflight invariant and must be externally synchronized.
    ///
    /// # Errors
    ///
    /// Returns [`SeqpacketError::Closed`] after a fatal framing or ancillary
    /// violation has revoked the connection.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, SeqpacketError> {
        self.borrow_fd()
    }

    /// Sends one record without ancillary data.
    ///
    /// # Errors
    ///
    /// Returns [`SeqpacketError::WouldBlock`] under backpressure, or an error
    /// if the socket is closed or the kernel does not accept the whole record.
    pub fn send(&mut self, payload: &[u8]) -> Result<(), SeqpacketError> {
        if payload.is_empty() {
            return Err(SeqpacketError::EmptyRecord);
        }
        let sent = uapi::send_seqpacket(self.borrow_fd()?, payload).map_err(map_kernel_error)?;
        if sent != payload.len() {
            self.fd.take();
            return Err(SeqpacketError::PartialSend {
                expected: payload.len(),
                actual: sent,
            });
        }
        Ok(())
    }

    /// Receives one exactly sized record and its kernel-authorized subject.
    ///
    /// `maximum_bytes` is an admission ceiling, not a buffer size. No
    /// record-sized allocation occurs until the kernel-reported packet length
    /// has been checked against it.
    ///
    /// # Errors
    ///
    /// Returns [`SeqpacketError::WouldBlock`] when no record is ready and
    /// [`SeqpacketError::Interrupted`] after a signal interruption. Empty,
    /// oversized, truncated, length-drifting, ancillary-invalid, and other
    /// kernel-failed receives are fatal: the socket is closed first.
    pub fn receive(&mut self, maximum_bytes: usize) -> Result<ReceivedRecord, SeqpacketError> {
        if maximum_bytes == 0 {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_inner(maximum_bytes);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.fd.take();
        }
        result
    }

    fn receive_inner(&self, maximum_bytes: usize) -> Result<ReceivedRecord, SeqpacketError> {
        let mut probe = [0_u8; 1];
        let preview = uapi::recv_seqpacket(
            self.borrow_fd()?,
            &mut probe,
            libc::MSG_PEEK | libc::MSG_TRUNC,
        )
        .map_err(map_kernel_error)?;
        if preview.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        validate_record_subject(preview.ancillary)?;
        if preview.bytes == 0 {
            return Err(SeqpacketError::EmptyRecord);
        }
        if preview.bytes > maximum_bytes {
            return Err(SeqpacketError::RecordTooLarge {
                actual: preview.bytes,
                maximum: maximum_bytes,
            });
        }

        self.consume_exact(preview.bytes)
    }

    fn consume_exact(&self, expected: usize) -> Result<ReceivedRecord, SeqpacketError> {
        let mut payload = vec![0_u8; expected];
        let received =
            uapi::recv_seqpacket(self.borrow_fd()?, &mut payload, 0).map_err(map_kernel_error)?;
        if received.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        if received.flags & libc::MSG_TRUNC != 0 {
            return Err(SeqpacketError::PayloadTruncated);
        }
        if received.bytes != expected {
            return Err(SeqpacketError::LengthChanged {
                previewed: expected,
                received: received.bytes,
            });
        }
        let subject = validate_record_subject(received.ancillary)?;
        Ok(ReceivedRecord { payload, subject })
    }

    fn borrow_fd(&self) -> Result<BorrowedFd<'_>, SeqpacketError> {
        self.fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or(SeqpacketError::Closed)
    }
}

/// One received sequenced-packet record.
#[derive(Debug)]
pub struct ReceivedRecord {
    payload: Vec<u8>,
    subject: KernelAuthorizedRecordSubject,
}

impl ReceivedRecord {
    /// Returns the record payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the kernel-authorized subject nominated for this record.
    ///
    /// This subject is distinct from the connection establisher and is not,
    /// by itself, proof of higher-level execution provenance.
    #[must_use]
    pub const fn subject(&self) -> &KernelAuthorizedRecordSubject {
        &self.subject
    }

    /// Splits the record into its payload and retained record subject.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, KernelAuthorizedRecordSubject) {
        (self.payload, self.subject)
    }
}

/// The process identity captured when a Unix connection was established.
#[derive(Debug)]
pub struct ConnectionPeerIdentity {
    credentials: PeerCredentials,
    pidfd: PidFd,
    initial_info: PidFdInfo,
}

impl ConnectionPeerIdentity {
    /// Returns the peer credentials fixed at connection establishment.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    /// Returns the initial process information read from the retained pidfd.
    #[must_use]
    pub const fn initial_info(&self) -> PidFdInfo {
        self.initial_info
    }

    /// Borrows the retained pidfd for descriptor-oriented identity checks.
    #[must_use]
    pub const fn pidfd(&self) -> &PidFd {
        &self.pidfd
    }

    /// Tests whether the pinned connection-establisher process still exists.
    ///
    /// # Errors
    ///
    /// Returns an error for pidfd failures other than normal process exit.
    pub fn is_alive(&self) -> crate::Result<bool> {
        self.pidfd.is_alive()
    }
}

/// Credentials fixed by Unix sockets at connection establishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pid: NonZeroU32,
    uid: u32,
    gid: u32,
}

impl PeerCredentials {
    fn from_raw(raw: libc::ucred) -> Result<Self, SeqpacketError> {
        let pid = checked_pid(raw.pid).ok_or(SeqpacketError::PeerIdentity(
            "SO_PEERCRED contained an invalid pid",
        ))?;
        Ok(Self {
            pid,
            uid: raw.uid,
            gid: raw.gid,
        })
    }

    /// Returns the peer PID as observed in the receiver's PID namespace.
    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    /// Returns the peer effective user ID fixed by `SO_PEERCRED`.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the peer effective group ID fixed by `SO_PEERCRED`.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

/// The kernel-authorized process and credentials nominated for one record.
///
/// `SCM_CREDENTIALS` is a subject nomination. It can be supplied explicitly by
/// the writer or synthesized because `SO_PASSCRED` is enabled; the kernel
/// checks the writer's authority for every explicit PID, UID, and GID. UID and
/// GID are therefore not necessarily the writer's effective IDs. The
/// accompanying `SCM_PIDFD` is generated by the kernel, retained here, and
/// required to name the same PID. This establishes an authorized record
/// subject, not application execution provenance; a higher-level protocol must
/// bind that separately.
#[derive(Debug)]
pub struct KernelAuthorizedRecordSubject {
    credentials: RecordCredentials,
    pidfd: PidFd,
    initial_info: PidFdInfo,
}

impl KernelAuthorizedRecordSubject {
    /// Returns the kernel-authorized credentials nominated for this record.
    #[must_use]
    pub const fn credentials(&self) -> RecordCredentials {
        self.credentials
    }

    /// Returns initial process information read from the record's pidfd.
    #[must_use]
    pub const fn initial_info(&self) -> PidFdInfo {
        self.initial_info
    }

    /// Borrows the kernel-generated pidfd retained for this record.
    #[must_use]
    pub const fn pidfd(&self) -> &PidFd {
        &self.pidfd
    }

    /// Tests whether the process pinned for this record still exists.
    ///
    /// # Errors
    ///
    /// Returns an error for pidfd failures other than normal process exit.
    pub fn is_alive(&self) -> crate::Result<bool> {
        self.pidfd.is_alive()
    }
}

/// Credentials explicitly nominated in one `SCM_CREDENTIALS` record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordCredentials {
    pid: NonZeroU32,
    uid: u32,
    gid: u32,
}

impl RecordCredentials {
    /// Returns the authorized subject PID in the receiver's PID namespace.
    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    /// Returns the kernel-authorized nominated user ID.
    ///
    /// This can be a real, effective, or saved-set ID of the writer, or
    /// another ID when the writer holds the kernel-required capability.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the kernel-authorized nominated group ID.
    ///
    /// This can be a real, effective, or saved-set ID of the writer, or
    /// another ID when the writer holds the kernel-required capability.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

/// Failures produced by sequenced-packet primitives.
#[derive(Debug, thiserror::Error)]
pub enum SeqpacketError {
    /// A Linux descriptor or socket operation failed.
    #[error(transparent)]
    Kernel(#[from] Error),
    /// The nonblocking operation cannot currently make progress.
    #[error("SOCK_SEQPACKET operation would block")]
    WouldBlock,
    /// The operation was interrupted before consuming a record.
    #[error("SOCK_SEQPACKET operation was interrupted")]
    Interrupted,
    /// A fatal protocol violation already closed the socket.
    #[error("SOCK_SEQPACKET socket is closed")]
    Closed,
    /// A zero allocation ceiling was supplied.
    #[error("record admission maximum must be nonzero")]
    InvalidMaximum,
    /// Empty records are forbidden because they are ambiguous with shutdown.
    #[error("empty SOCK_SEQPACKET record or orderly shutdown")]
    EmptyRecord,
    /// A record exceeded the allocation admission ceiling.
    #[error("record length {actual} exceeds admission maximum {maximum}")]
    RecordTooLarge {
        /// Full record length reported by the kernel.
        actual: usize,
        /// Caller-provided allocation admission ceiling.
        maximum: usize,
    },
    /// Ancillary data did not fit the fixed, bounded control buffer.
    #[error("SOCK_SEQPACKET ancillary data was truncated")]
    ControlTruncated,
    /// Payload data was truncated after exact-length preflight.
    #[error("SOCK_SEQPACKET payload was truncated")]
    PayloadTruncated,
    /// The queued record changed between the non-consuming preview and receive.
    #[error("record length changed from {previewed} to {received}")]
    LengthChanged {
        /// Length returned by the non-consuming preview.
        previewed: usize,
        /// Length returned by the consuming receive.
        received: usize,
    },
    /// A sequenced-packet send was not atomic.
    #[error("partial SOCK_SEQPACKET send: expected {expected}, sent {actual}")]
    PartialSend {
        /// Complete record length supplied by the caller.
        expected: usize,
        /// Byte count unexpectedly accepted by the kernel.
        actual: usize,
    },
    /// Ancillary data violated the record-subject contract.
    #[error("invalid ancillary data: {0}")]
    Ancillary(&'static str),
    /// Connection-level peer credentials and pidfd did not correlate.
    #[error("invalid connection peer identity: {0}")]
    PeerIdentity(&'static str),
}

impl SeqpacketError {
    fn is_fatal(&self) -> bool {
        !matches!(
            self,
            Self::WouldBlock | Self::Interrupted | Self::InvalidMaximum | Self::Closed
        )
    }
}

fn map_kernel_error(error: Error) -> SeqpacketError {
    if matches!(
        &error,
        Error::Syscall { source, .. }
            if source.raw_os_error() == Some(libc::EAGAIN)
    ) {
        SeqpacketError::WouldBlock
    } else if matches!(
        &error,
        Error::Syscall { source, .. }
            if source.raw_os_error() == Some(libc::EINTR)
    ) {
        SeqpacketError::Interrupted
    } else {
        SeqpacketError::Kernel(error)
    }
}

fn validate_record_subject(
    ancillary: Vec<RawAncillary>,
) -> Result<KernelAuthorizedRecordSubject, SeqpacketError> {
    let mut credentials = None;
    let mut pidfd = None;
    for item in ancillary {
        match item {
            RawAncillary::Credentials(raw) if credentials.is_none() => {
                let pid = checked_pid(raw.pid)
                    .ok_or(SeqpacketError::Ancillary("invalid SCM_CREDENTIALS pid"))?;
                credentials = Some(RecordCredentials {
                    pid,
                    uid: raw.uid,
                    gid: raw.gid,
                });
            }
            RawAncillary::Credentials(_) => {
                return Err(SeqpacketError::Ancillary("duplicate SCM_CREDENTIALS"));
            }
            RawAncillary::PidFd(fd) if pidfd.is_none() => pidfd = Some(PidFd::from_owned(fd)?),
            RawAncillary::PidFd(_) => {
                return Err(SeqpacketError::Ancillary("duplicate SCM_PIDFD"));
            }
            RawAncillary::Rights(descriptors) => {
                drop(descriptors);
                return Err(SeqpacketError::Ancillary("SCM_RIGHTS is forbidden"));
            }
            RawAncillary::Unknown { level, kind } => {
                let _ = (level, kind);
                return Err(SeqpacketError::Ancillary("unknown control message"));
            }
            RawAncillary::Malformed(descriptors) => {
                drop(descriptors);
                return Err(SeqpacketError::Ancillary("malformed control message"));
            }
        }
    }
    let credentials = credentials.ok_or(SeqpacketError::Ancillary("missing SCM_CREDENTIALS"))?;
    let pidfd = pidfd.ok_or(SeqpacketError::Ancillary("missing SCM_PIDFD"))?;
    let initial_info = pidfd.info()?;
    if initial_info.pid() != credentials.pid().get() {
        return Err(SeqpacketError::Ancillary(
            "SCM_CREDENTIALS and SCM_PIDFD identify different processes",
        ));
    }
    Ok(KernelAuthorizedRecordSubject {
        credentials,
        pidfd,
        initial_info,
    })
}

fn checked_pid(pid: i32) -> Option<NonZeroU32> {
    u32::try_from(pid).ok().and_then(NonZeroU32::new)
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};

    use super::*;

    fn pair() -> (SeqpacketSocket, SeqpacketSocket) {
        let (left, right) = uapi::seqpacket_pair().expect("create seqpacket pair");
        (
            SeqpacketSocket::from_owned(left).expect("adopt left socket"),
            SeqpacketSocket::from_owned(right).expect("adopt right socket"),
        )
    }

    #[test]
    fn receives_exact_record_with_credentials_and_cloexec_pidfd() {
        let (mut sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        sender.send(b"query").expect("send query");

        let record = receiver.receive(64).expect("receive query");
        assert_eq!(record.payload(), b"query");
        assert_eq!(
            record.subject().credentials().pid().get(),
            std::process::id()
        );
        assert_eq!(record.subject().initial_info().pid(), std::process::id());
        assert!(record.subject().is_alive().expect("test subject liveness"));
        assert!(uapi::is_cloexec(record.subject().pidfd().as_fd()).expect("inspect pidfd flags"));
    }

    #[test]
    fn captures_and_retains_connection_establisher_identity() {
        let (socket, _peer) = pair();
        assert_eq!(socket.peer().credentials().pid().get(), std::process::id());
        assert_eq!(socket.peer().initial_info().pid(), std::process::id());
        assert!(socket.peer().is_alive().expect("test peer liveness"));
        assert!(uapi::is_cloexec(socket.peer().pidfd().as_fd()).expect("inspect peer pidfd flags"));
    }

    #[test]
    fn empty_queue_is_retryable_and_does_not_close_socket() {
        let (_sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        assert!(matches!(
            receiver.receive(64),
            Err(SeqpacketError::WouldBlock)
        ));
        assert!(receiver.as_fd().is_ok());
    }

    #[test]
    fn admission_bound_rejects_before_record_allocation_and_closes_socket() {
        let (mut sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        sender.send(b"oversized").expect("send record");

        assert!(matches!(
            receiver.receive(4),
            Err(SeqpacketError::RecordTooLarge {
                actual: 9,
                maximum: 4
            })
        ));
        assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
    }

    #[test]
    fn record_length_drift_is_detected() {
        let (mut sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        sender.send(b"first").expect("send first");
        sender.send(b"second-is-longer").expect("send second");

        let mut probe = [0_u8; 1];
        let preview = uapi::recv_seqpacket(
            receiver.as_fd().expect("borrow receiver"),
            &mut probe,
            libc::MSG_PEEK | libc::MSG_TRUNC,
        )
        .expect("preview first");
        let mut discard = vec![0_u8; preview.bytes];
        uapi::recv_seqpacket(receiver.as_fd().expect("borrow receiver"), &mut discard, 0)
            .expect("consume first elsewhere");

        assert!(matches!(
            receiver.consume_exact(preview.bytes),
            Err(SeqpacketError::PayloadTruncated)
        ));
    }

    #[test]
    fn scm_rights_is_rejected_and_closes_the_connection() {
        let (sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        let file = std::fs::File::open("/dev/null").expect("open test descriptor");
        uapi::send_seqpacket_rights(
            sender.as_fd().expect("borrow sender"),
            b"attack",
            &[file.as_fd()],
        )
        .expect("send rights");

        assert!(matches!(
            receiver.receive(64),
            Err(SeqpacketError::Ancillary("SCM_RIGHTS is forbidden"))
        ));
        assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
    }

    #[test]
    fn oversized_ancillary_set_is_rejected_as_control_truncation() {
        let (sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        let file = std::fs::File::open("/dev/null").expect("open test descriptor");
        let descriptors: Vec<_> = (0..200).map(|_| file.as_fd()).collect();
        uapi::send_seqpacket_rights(
            sender.as_fd().expect("borrow sender"),
            b"attack",
            &descriptors,
        )
        .expect("send many rights");

        assert!(matches!(
            receiver.receive(64),
            Err(SeqpacketError::ControlTruncated)
        ));
    }

    #[test]
    fn duplicate_and_unknown_ancillary_messages_are_rejected() {
        let credentials = libc::ucred {
            pid: i32::try_from(std::process::id()).expect("pid fits i32"),
            uid: 0,
            gid: 0,
        };
        assert!(matches!(
            validate_record_subject(vec![
                RawAncillary::Credentials(credentials),
                RawAncillary::Credentials(credentials),
            ]),
            Err(SeqpacketError::Ancillary("duplicate SCM_CREDENTIALS"))
        ));
        assert!(matches!(
            validate_record_subject(vec![RawAncillary::Unknown {
                level: libc::SOL_SOCKET,
                kind: 0x7fff,
            }]),
            Err(SeqpacketError::Ancillary("unknown control message"))
        ));

        let pidfd_one = uapi::pidfd_open(std::process::id()).expect("open first pidfd");
        let pidfd_two = uapi::pidfd_open(std::process::id()).expect("open second pidfd");
        assert!(matches!(
            validate_record_subject(vec![
                RawAncillary::Credentials(credentials),
                RawAncillary::PidFd(pidfd_one),
                RawAncillary::PidFd(pidfd_two),
            ]),
            Err(SeqpacketError::Ancillary("duplicate SCM_PIDFD"))
        ));
    }

    #[test]
    fn rejected_descriptor_ancillary_is_closed() {
        let file = std::fs::File::open("/dev/null").expect("open test descriptor");
        // Keep the observed descriptor far outside the allocator's normal
        // range so parallel fd-heavy tests cannot reuse its number before the
        // postcondition is inspected.
        let owned: OwnedFd =
            uapi::duplicate_at_least(file.as_fd(), 512).expect("duplicate test descriptor");
        let raw = owned.as_raw_fd();
        assert!(matches!(
            validate_record_subject(vec![RawAncillary::Rights(vec![owned])]),
            Err(SeqpacketError::Ancillary("SCM_RIGHTS is forbidden"))
        ));
        assert!(!uapi::raw_fd_is_open(raw));
    }

    #[test]
    fn adopted_socket_and_received_pidfd_are_close_on_exec() {
        let (left, _right) = uapi::seqpacket_pair().expect("create pair");
        let raw = left.as_raw_fd();
        let socket = SeqpacketSocket::from_owned(left).expect("adopt socket");
        assert_eq!(socket.as_fd().expect("borrow socket").as_raw_fd(), raw);
        assert!(uapi::is_cloexec(socket.as_fd().expect("borrow socket")).expect("inspect flags"));
    }

    #[test]
    fn listener_is_not_adopted_as_a_connected_transport() {
        let listener = uapi::seqpacket_listener().expect("create seqpacket listener");
        assert!(matches!(
            SeqpacketSocket::from_owned(listener),
            Err(SeqpacketError::Kernel(Error::WrongDescriptorType {
                expected: "connected Unix SOCK_SEQPACKET socket, not a listener"
            }))
        ));
    }

    #[test]
    fn unconnected_socket_is_not_adopted_as_a_connected_transport() {
        let socket = uapi::unconnected_seqpacket().expect("create unconnected seqpacket socket");
        assert!(matches!(
            SeqpacketSocket::from_owned(socket),
            Err(SeqpacketError::Kernel(Error::Syscall {
                operation: "getpeername(SOCK_SEQPACKET)",
                source,
            })) if source.raw_os_error() == Some(libc::ENOTCONN)
        ));
    }
}
