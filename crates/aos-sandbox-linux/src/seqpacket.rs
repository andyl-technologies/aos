//! Fail-closed, descriptor-owning Unix `SOCK_SEQPACKET` transport primitives.
//!
//! The receiver measures one complete record with `MSG_PEEK | MSG_TRUNC`,
//! admits that length against a caller-owned ceiling, and only then allocates
//! and consumes the record. Every consumed record must carry exactly one
//! kernel-checked `SCM_CREDENTIALS` nomination and one correlated `SCM_PIDFD`.
//! This metadata does not prove the actual syscall writer. Ordinary records
//! reject all other ancillary data; the explicit descriptor methods admit only
//! an exact one-to-five-entry `SCM_RIGHTS` table and retain ownership on every
//! ambiguity path.
//!
//! Adoption separately captures the connection establisher with `SO_PEERCRED`
//! and `SO_PEERPIDFD`. That peer remains useful for service-manager policy, but
//! Unix descriptor delegation means it need not be the process writing later
//! records. [`ConnectionPeerIdentity`] and [`KernelAuthorizedRecordSubject`]
//! therefore remain separate types and neither claims application provenance.
//! [`RecordSubjectListener`] checks inherited identity options before adopting
//! accepted children; enabling them after an untrusted peer connects is not an
//! equivalent record-provenance boundary. A consumed record can additionally
//! be bound to the exact retained socket object through a private `SO_COOKIE`
//! origin stamp. That binding is carrier continuity, not writer identity.

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path};

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use crate::Error;
use crate::pidfd::{PidFd, PidFdInfo};
use crate::uapi::{self, RawAncillary};

mod listener;
pub use listener::RecordSubjectListener;

mod socket_binding;
use socket_binding::{ConnectedSocketBinding, ReceivedSocketOrigin};

pub mod descriptor_subject;

#[cfg(test)]
mod process_tests;

/// A nonblocking, close-on-exec Unix sequenced-packet socket.
#[derive(Debug)]
pub struct SeqpacketSocket {
    fd: Option<OwnedFd>,
    peer: ConnectionPeerIdentity,
}

impl SeqpacketSocket {
    /// Connects to one absolute filesystem Unix sequenced-packet socket.
    ///
    /// Record credentials and pidfds are enabled on the fresh socket before
    /// connection, so an immediately sent first record retains its subject.
    /// The socket is nonblocking and close-on-exec.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-normalized or oversized path, socket-option
    /// failure, incomplete nonblocking connection, or peer-pinning failure.
    pub fn connect(path: &Path) -> Result<Self, SeqpacketError> {
        let normalized = path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
        if !normalized {
            return Err(SeqpacketError::Kernel(Error::invalid(
                "sequenced-packet connection path",
                "must be a normalized absolute path",
            )));
        }

        let socket = uapi::connect_seqpacket(path)?;
        Self::from_owned(socket)
    }

    /// Creates a private channel with record-subject reporting enabled before exposure.
    ///
    /// Returns the controller's bounded receiver and an owned endpoint for
    /// explicit delivery to a provisioned peer. Both ends are nonblocking and
    /// close-on-exec. Their connection establisher is the creating process.
    /// Record subjects are kernel-checked nominations, not authentication of a
    /// delivered endpoint's actual syscall writer; the application protocol
    /// and MAC/capability-confined deployment must establish that separately.
    ///
    /// # Errors
    ///
    /// Returns an error when socket creation, identity-option configuration, or
    /// peer pinning fails. Neither endpoint escapes on failure.
    pub fn pair_with_record_subjects() -> Result<(Self, OwnedFd), SeqpacketError> {
        let (receiver, endpoint) = uapi::seqpacket_pair()?;
        uapi::enable_seqpacket_identity(receiver.as_fd())?;
        uapi::enable_seqpacket_identity(endpoint.as_fd())?;
        Ok((Self::from_owned(receiver)?, endpoint))
    }

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
        let peer = ConnectionPeerIdentity::from_socket(fd.as_fd())?;
        Ok(Self { fd: Some(fd), peer })
    }

    /// Closes the transport while retaining its pinned connection identity.
    ///
    /// Repeated calls have no effect. The retained peer pidfd remains available
    /// for observing the old execution after transport failure; closure alone
    /// is neither process termination nor proof that its effects have stopped.
    pub fn close(&mut self) {
        self.fd.take();
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

    /// Enables kernel-checked credential nominations and generated pidfds on records.
    ///
    /// This must be called before an untrusted sender can enqueue records.
    /// Use [`RecordSubjectListener`] for externally reachable listeners: this
    /// method cannot establish whether earlier queued records had these options.
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

    /// Sends one atomic record with one to five owned-capability descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty descriptor table, more than five entries,
    /// backpressure, ancillary failure, or a short/fatal record send.
    pub fn send_with_descriptors(
        &mut self,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), SeqpacketError> {
        if payload.is_empty() || descriptors.is_empty() || descriptors.len() > 5 {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
            self.fd.take();
            return Err(SeqpacketError::Ancillary(
                "SCM_RIGHTS descriptor table exceeded its fixed buffer",
            ));
        }
        let result = sendmsg(
            self.borrow_fd()?,
            &[IoSlice::new(payload)],
            &mut control,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
        .map_err(|source| {
            map_kernel_error(Error::Syscall {
                operation: "sendmsg(SCM_RIGHTS)",
                source: source.into(),
            })
        });
        let written = match result {
            Ok(written) => written,
            Err(error) => {
                if error.is_fatal() {
                    self.fd.take();
                }
                return Err(error);
            }
        };
        if written != payload.len() {
            self.fd.take();
            return Err(SeqpacketError::PartialSend {
                expected: payload.len(),
                actual: written,
            });
        }
        Ok(())
    }

    /// Receives one exactly sized record and its kernel-checked nominated subject.
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

    /// Receives one record with an exact table of up to five descriptors.
    ///
    /// # Errors
    ///
    /// Returns the ordinary bounded-record errors and rejects a zero or
    /// above-five descriptor count, or any inexact ancillary table.
    pub fn receive_with_descriptors(
        &mut self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, SeqpacketError> {
        if maximum_bytes == 0 || expected_descriptors == 0 || expected_descriptors > 5 {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_descriptor_inner(maximum_bytes, expected_descriptors);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.fd.take();
        }
        result
    }

    /// Binds a descriptor record to this exact retained socket endpoint.
    ///
    /// # Errors
    ///
    /// Closes the socket and descriptors when the record originated elsewhere
    /// or the retained socket binding is no longer current.
    pub fn bind_received_descriptors<'socket>(
        &'socket mut self,
        record: descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<
        descriptor_subject::ConnectionBoundReceivedDescriptorRecord<'socket>,
        RecordBindingError,
    > {
        let result = self.require_descriptor_record_origin(&record);
        if let Err(error) = result {
            self.fd.take();
            return Err(error);
        }
        Ok(descriptor_subject::ConnectionBoundReceivedDescriptorRecord::new(record, &self.peer))
    }

    /// Binds an already received record to this exact retained socket endpoint.
    ///
    /// The record must have been consumed from this socket object or one of its
    /// duplicate descriptors. The returned wrapper owns the record and borrows
    /// this socket's exact retained peer, preventing competing mutable I/O
    /// through this owner while the result remains unresolved. This establishes
    /// only carrier continuity; it does not prove the record writer, equate the
    /// record subject with the connection peer, or authenticate a protocol role.
    ///
    /// # Errors
    ///
    /// Closes this socket and drops the record when the socket is closed, its
    /// current kernel cookie cannot be read or differs from the retained
    /// binding, or the record originated on another socket object.
    pub fn bind_received<'socket>(
        &'socket mut self,
        record: ReceivedRecord,
    ) -> Result<ConnectionBoundReceivedRecord<'socket>, RecordBindingError> {
        let result = self.require_record_origin(&record);
        if let Err(error) = result {
            self.fd.take();
            return Err(error);
        }

        Ok(ConnectionBoundReceivedRecord {
            record,
            peer: &self.peer,
        })
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

    fn receive_descriptor_inner(
        &self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, SeqpacketError> {
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
        drop(descriptor_subject::validate_ancillary(
            preview.ancillary,
            expected_descriptors,
            false,
        )?);
        if preview.bytes == 0 {
            return Err(SeqpacketError::EmptyRecord);
        }
        if preview.bytes > maximum_bytes {
            return Err(SeqpacketError::RecordTooLarge {
                actual: preview.bytes,
                maximum: maximum_bytes,
            });
        }

        let mut payload = vec![0_u8; preview.bytes];
        let received =
            uapi::recv_seqpacket(self.borrow_fd()?, &mut payload, 0).map_err(map_kernel_error)?;
        if received.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        if received.flags & libc::MSG_TRUNC != 0 {
            return Err(SeqpacketError::PayloadTruncated);
        }
        if received.bytes != preview.bytes {
            return Err(SeqpacketError::LengthChanged {
                previewed: preview.bytes,
                received: received.bytes,
            });
        }
        let (subject, descriptors) = descriptor_subject::validate_ancillary(
            received.ancillary,
            expected_descriptors,
            false,
        )?;
        Ok(descriptor_subject::ReceivedDescriptorRecord::from_parts(
            payload,
            subject,
            descriptors,
            self.peer.binding.received_origin(),
        ))
    }

    fn require_descriptor_record_origin(
        &self,
        record: &descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<(), RecordBindingError> {
        let fd = self
            .fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current(fd)?;
        record.require_origin(self.peer.binding)
    }

    fn consume_exact(&self, expected: usize) -> Result<ReceivedRecord, SeqpacketError> {
        let fd = self.borrow_fd()?;
        let mut payload = vec![0_u8; expected];
        let received = uapi::recv_seqpacket(fd, &mut payload, 0).map_err(map_kernel_error)?;
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
        let origin = self.peer.binding.received_origin();
        Ok(ReceivedRecord {
            payload,
            subject,
            origin,
        })
    }

    fn require_record_origin(&self, record: &ReceivedRecord) -> Result<(), RecordBindingError> {
        let fd = self
            .fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current(fd)?;
        record.origin.require_binding(self.peer.binding)
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
    origin: ReceivedSocketOrigin,
}

/// Owns a received record bound to the exact socket that consumed it.
///
/// This wrapper has no independent constructor. Its lifetime retains a borrow
/// of the receiving socket's pinned peer and prevents mutable socket operations
/// through that owner until the wrapper or the peer returned by
/// [`Self::into_parts`] is released. The binding is transport continuity only,
/// not writer authentication or an assertion that [`Self::peer`] equals
/// [`Self::subject`].
///
/// ```compile_fail
/// use aos_sandbox_linux::seqpacket::{ReceivedRecord, SeqpacketSocket};
///
/// fn compete(socket: &mut SeqpacketSocket, record: ReceivedRecord) {
///     let (_, _, peer) = socket.bind_received(record).unwrap().into_parts();
///     socket.send(b"competing I/O").unwrap();
///     let _ = peer.credentials();
/// }
/// ```
///
/// ```compile_fail
/// use aos_sandbox_linux::seqpacket::{
///     ConnectionBoundReceivedRecord, ConnectionPeerIdentity, ReceivedRecord,
/// };
///
/// fn forge<'a>(
///     record: ReceivedRecord,
///     peer: &'a ConnectionPeerIdentity,
/// ) -> ConnectionBoundReceivedRecord<'a> {
///     ConnectionBoundReceivedRecord { record, peer }
/// }
/// ```
#[derive(Debug)]
pub struct ConnectionBoundReceivedRecord<'socket> {
    record: ReceivedRecord,
    peer: &'socket ConnectionPeerIdentity,
}

impl<'socket> ConnectionBoundReceivedRecord<'socket> {
    /// Returns the exact received payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.record.payload()
    }

    /// Returns the kernel-authorized subject nominated for this record.
    #[must_use]
    pub const fn subject(&self) -> &KernelAuthorizedRecordSubject {
        self.record.subject()
    }

    /// Returns the peer pinned for the exact socket that consumed the record.
    #[must_use]
    pub const fn peer(&self) -> &ConnectionPeerIdentity {
        self.peer
    }

    /// Splits the record while preserving the exact socket-peer borrow.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        KernelAuthorizedRecordSubject,
        &'socket ConnectionPeerIdentity,
    ) {
        let (payload, subject) = self.record.into_parts();
        (payload, subject, self.peer)
    }
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
    binding: ConnectedSocketBinding,
}

impl ConnectionPeerIdentity {
    /// Pins the establisher of a connected Unix sequenced-packet socket.
    ///
    /// Captures `SO_PEERCRED`, `SO_PEERPIDFD`, and `SO_COOKIE` from the same
    /// borrowed socket, never reopening a recyclable numeric PID. The cookie
    /// is observed around peer capture so inconsistent kernel evidence fails
    /// closed. No socket options, descriptor flags, or file-status flags are
    /// modified. This does not identify later writers after socket delegation
    /// and requires no record-subject options.
    ///
    /// # Errors
    ///
    /// Rejects a wrong socket type/family, listener or unconnected socket,
    /// unavailable peer pidfd, invalid credentials, or inconsistent pidfd info.
    pub fn from_socket(fd: BorrowedFd<'_>) -> Result<Self, SeqpacketError> {
        uapi::validate_connected_seqpacket(fd)?;
        let binding = ConnectedSocketBinding::capture_peer(fd)?;
        let credentials = PeerCredentials::from_raw(uapi::peer_credentials(fd)?)?;
        let pidfd = PidFd::from_owned(uapi::peer_pidfd(fd)?)?;
        let initial_info = pidfd.info()?;
        let final_binding = ConnectedSocketBinding::capture_peer(fd)?;
        if initial_info.pid() != credentials.pid().get() {
            return Err(SeqpacketError::PeerIdentity(
                "SO_PEERCRED and SO_PEERPIDFD identify different processes",
            ));
        }
        if final_binding != binding {
            return Err(SeqpacketError::PeerIdentity(
                "SO_COOKIE changed during sequenced-packet peer capture",
            ));
        }
        Ok(Self {
            credentials,
            pidfd,
            initial_info,
            binding,
        })
    }

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

    /// Returns the nonzero kernel cookie of the connected socket endpoint.
    ///
    /// This observation is diagnostic carrier identity only. It does not
    /// authorize the connection, its peer, or any record writer.
    #[must_use]
    pub const fn socket_cookie(&self) -> NonZeroU64 {
        self.binding.socket_cookie()
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

/// Classifies a redacted failure to bind a received record to one socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecordBindingErrorCategory {
    /// The target socket was already closed.
    Closed,
    /// The target socket's current kernel identity could not be confirmed.
    CurrentSocket,
    /// The record's private origin differs from the target socket.
    OriginMismatch,
}

impl std::fmt::Display for RecordBindingErrorCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => formatter.write_str("socket closed"),
            Self::CurrentSocket => formatter.write_str("socket currentness unavailable"),
            Self::OriginMismatch => formatter.write_str("record origin mismatch"),
        }
    }
}

/// Reports a redacted failure to bind a record to its receiving socket.
///
/// This non-exhaustive type cannot be constructed by callers. It never exposes
/// a socket cookie, descriptor number, peer identity, or underlying kernel
/// error. [`Self::category`] provides the stable fail-closed classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("received record socket binding failed: {category}")]
#[non_exhaustive]
pub struct RecordBindingError {
    category: RecordBindingErrorCategory,
}

impl RecordBindingError {
    /// Returns the stable redacted failure category.
    #[must_use]
    pub const fn category(&self) -> RecordBindingErrorCategory {
        self.category
    }

    const fn closed() -> Self {
        Self {
            category: RecordBindingErrorCategory::Closed,
        }
    }

    const fn current_socket() -> Self {
        Self {
            category: RecordBindingErrorCategory::CurrentSocket,
        }
    }

    const fn origin_mismatch() -> Self {
        Self {
            category: RecordBindingErrorCategory::OriginMismatch,
        }
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

    use tempfile::TempDir;

    use super::*;

    fn pair() -> (SeqpacketSocket, SeqpacketSocket) {
        let (left, right) = uapi::seqpacket_pair().expect("create seqpacket pair");
        (
            SeqpacketSocket::from_owned(left).expect("adopt left socket"),
            SeqpacketSocket::from_owned(right).expect("adopt right socket"),
        )
    }

    #[test]
    fn connection_identity_capture_does_not_change_socket_flags() {
        for flags in [0, libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC] {
            let (left, _right) = uapi::seqpacket_pair_with_flags(flags).expect("create test pair");
            let before_status = uapi::get_status_flags(left.as_fd()).expect("initial status flags");
            let before_cloexec = uapi::is_cloexec(left.as_fd()).expect("initial FD flags");
            let identity = ConnectionPeerIdentity::from_socket(left.as_fd()).expect("capture peer");
            assert_eq!(identity.credentials().pid().get(), std::process::id());
            assert_eq!(identity.initial_info().pid(), std::process::id());
            assert_ne!(identity.socket_cookie().get(), 0);
            assert!(uapi::is_cloexec(identity.pidfd().as_fd()).expect("peer pidfd CLOEXEC"));
            assert_eq!(
                uapi::get_status_flags(left.as_fd()).expect("final status flags"),
                before_status
            );
            assert_eq!(
                uapi::is_cloexec(left.as_fd()).expect("final FD flags"),
                before_cloexec
            );
            assert!(uapi::require_seqpacket_identity(left.as_fd()).is_err());
        }
    }

    #[test]
    fn filesystem_connect_enables_record_identity_before_first_traffic() {
        let directory = TempDir::new().expect("create socket directory");
        let path = directory.path().join("control.sock");
        let mut listener = RecordSubjectListener::bind(&path, 1).expect("bind listener");
        let mut client = SeqpacketSocket::connect(&path).expect("connect client");
        let mut accepted = listener.accept().expect("accept client");

        accepted.send(b"ready").expect("send first record");
        let ready = client.receive(64).expect("receive first record subject");
        assert_eq!(ready.payload(), b"ready");
        assert_eq!(
            ready.subject().credentials().pid().get(),
            std::process::id()
        );
    }

    #[test]
    fn filesystem_connect_rejects_non_normalized_paths() {
        for path in [
            Path::new("relative.sock"),
            Path::new("/tmp/../control.sock"),
        ] {
            assert!(matches!(
                SeqpacketSocket::connect(path),
                Err(SeqpacketError::Kernel(Error::InvalidInput {
                    field: "sequenced-packet connection path",
                    ..
                }))
            ));
        }
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
    fn legacy_received_record_parts_remain_available_without_binding() {
        let (mut sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        sender.send(b"legacy").expect("send legacy record");

        let record = receiver.receive(64).expect("receive legacy record");
        let (payload, subject) = record.into_parts();

        assert_eq!(payload, b"legacy");
        assert_eq!(subject.initial_info().pid(), std::process::id());
        assert!(receiver.as_fd().is_ok());
    }

    #[test]
    fn received_record_binds_only_to_its_exact_socket() {
        let (mut sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        sender.send(b"bound").expect("send bound record");
        socket_binding::reset_current_query_count();
        let record = receiver.receive(64).expect("receive bound record");
        let peer = receiver.peer() as *const ConnectionPeerIdentity;
        assert_eq!(socket_binding::current_query_count(), 0);

        let bound = receiver.bind_received(record).expect("bind exact socket");

        assert_eq!(socket_binding::current_query_count(), 1);
        assert_eq!(bound.payload(), b"bound");
        assert_eq!(bound.subject().initial_info().pid(), std::process::id());
        assert_eq!(bound.peer() as *const ConnectionPeerIdentity, peer);
        let (payload, subject, retained_peer) = bound.into_parts();
        assert_eq!(payload, b"bound");
        assert_eq!(subject.initial_info().pid(), std::process::id());
        assert_eq!(retained_peer as *const ConnectionPeerIdentity, peer);
    }

    #[test]
    fn same_socket_duplicate_accepts_the_received_origin() {
        let (mut sender, mut receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        let duplicate_fd = uapi::duplicate_at_least(receiver.as_fd().expect("receiver fd"), 0)
            .expect("duplicate receiver");
        let mut duplicate = SeqpacketSocket::from_owned(duplicate_fd).expect("adopt duplicate");
        sender.send(b"duplicate").expect("send duplicate record");
        let record = receiver.receive(64).expect("receive through source");
        let duplicate_peer = duplicate.peer() as *const ConnectionPeerIdentity;

        let bound = duplicate
            .bind_received(record)
            .expect("bind through same-socket duplicate");

        assert_eq!(bound.payload(), b"duplicate");
        assert_eq!(
            bound.peer() as *const ConnectionPeerIdentity,
            duplicate_peer
        );
    }

    #[test]
    fn foreign_record_origin_closes_the_binding_socket() {
        let (mut first_sender, mut first_receiver) = pair();
        let (_second_sender, mut second_receiver) = pair();
        first_receiver
            .enable_record_subjects()
            .expect("enable first subjects");
        first_sender.send(b"foreign").expect("send foreign record");
        let record = first_receiver.receive(64).expect("receive foreign record");

        assert!(matches!(
            second_receiver.bind_received(record),
            Err(error) if error.category() == RecordBindingErrorCategory::OriginMismatch
        ));
        assert!(matches!(
            second_receiver.as_fd(),
            Err(SeqpacketError::Closed)
        ));
        assert_eq!(
            RecordBindingError::origin_mismatch().to_string(),
            "received record socket binding failed: record origin mismatch"
        );
    }

    #[test]
    fn binding_errors_expose_only_stable_redacted_categories() {
        let cases = [
            (
                RecordBindingError::closed(),
                RecordBindingErrorCategory::Closed,
                "received record socket binding failed: socket closed",
            ),
            (
                RecordBindingError::current_socket(),
                RecordBindingErrorCategory::CurrentSocket,
                "received record socket binding failed: socket currentness unavailable",
            ),
            (
                RecordBindingError::origin_mismatch(),
                RecordBindingErrorCategory::OriginMismatch,
                "received record socket binding failed: record origin mismatch",
            ),
        ];

        for (error, category, text) in cases {
            assert_eq!(error.category(), category);
            assert_eq!(error.to_string(), text);
            assert!(!format!("{error:?}").contains("SO_COOKIE"));
        }
    }

    #[test]
    fn opposite_endpoint_rejects_a_received_origin() {
        let (mut left, mut right) = pair();
        left.enable_record_subjects().expect("enable left subjects");
        right.send(b"opposite").expect("send from opposite");
        let record = left.receive(64).expect("receive on left");

        assert!(matches!(
            right.bind_received(record),
            Err(error) if error.category() == RecordBindingErrorCategory::OriginMismatch
        ));
        assert!(matches!(right.as_fd(), Err(SeqpacketError::Closed)));
    }

    #[test]
    fn closed_socket_rejects_and_drops_a_received_record() {
        let (mut sender, mut receiver) = pair();
        let (_binding_sender, mut binding_receiver) = pair();
        receiver
            .enable_record_subjects()
            .expect("enable record subjects");
        sender.send(b"closed").expect("send record");
        let record = receiver.receive(64).expect("receive record");
        binding_receiver.close();

        assert!(matches!(
            binding_receiver.bind_received(record),
            Err(error) if error.category() == RecordBindingErrorCategory::Closed
        ));
        assert!(matches!(
            binding_receiver.as_fd(),
            Err(SeqpacketError::Closed)
        ));
    }

    #[test]
    fn captures_and_retains_connection_establisher_identity() {
        let (socket, _peer) = pair();
        assert_eq!(socket.peer().credentials().pid().get(), std::process::id());
        assert_eq!(socket.peer().initial_info().pid(), std::process::id());
        assert_ne!(socket.peer().socket_cookie().get(), 0);
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
