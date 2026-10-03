//! Bounded descriptor replies with independent kernel-authorized record subjects.
//!
//! This is a separate carrier from holder/publisher ingress, which continues to
//! forbid `SCM_RIGHTS`. Each packet here requires one credential message, one
//! kernel-generated subject pidfd, and exactly the caller-selected number of
//! transferred descriptors, bounded to two (or the reply profile's zero/two).
//! A separate privileged mount-scope reply profile permits only zero or five
//! descriptors; it does not widen the controller reply profile. Descriptor
//! roles and application authority are validated by the higher-level protocol.
//!
//! The connection establisher is not authenticated as the response service:
//! socket activation can make that establisher PID 1. Services must instead
//! validate the nominated subject against the independently pinned connection
//! peer and protected service scope, then require later records to preserve the
//! same live session. A privileged sender may nominate another subject within
//! its kernel authority, so the carrier does not by itself identify the writer.
//!
//! Fixed retaining adapters share the same native sender and original receive
//! engine. Their negative fence retains the socket but denies every later I/O
//! loan after fatal failure; shutdown debt never proves peer exit or Drain.

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

use super::receive_custody::{ReceiveAttemptV1, SubjectProfileV1, receive_packet};
use super::socket_binding::ReceivedSocketOrigin;
use super::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, PendingSocketAdmissionV1,
    RetainedSeqpacketAdmissionErrorV1, RetainedSeqpacketReceiveErrorV1, SeqpacketError,
    admit_connected_peer, connect_pending_seqpacket, map_kernel_error,
};
use crate::Error;
use crate::uapi::{self, RawAncillary};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

// Resource inventories use the broker protocol's full response ceiling. Keep
// this carrier-local value explicit because the Linux boundary does not depend
// on the protocol crate.
const MAXIMUM_PACKET_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_TRANSFERRED_DESCRIPTORS: usize = 2;
const KERNEL_EXPORT_DESCRIPTORS: usize = 3;

/// Owns a configured nonblocking descriptor-reply channel without service authority.
#[derive(Debug)]
pub struct DescriptorSubjectSocket {
    fd: Option<OwnedFd>,
    peer: ConnectionPeerIdentity,
    retention: OriginalRetentionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetentionPhaseV1 {
    Legacy,
    Healthy,
    Failed,
}

#[derive(Debug)]
struct OriginalRetentionV1 {
    phase: RetentionPhaseV1,
    shutdown_attempted: bool,
    shutdown_failure: Option<std::io::Error>,
}

impl OriginalRetentionV1 {
    const fn legacy() -> Self {
        Self {
            phase: RetentionPhaseV1::Legacy,
            shutdown_attempted: false,
            shutdown_failure: None,
        }
    }

    fn end(&mut self, fd: &Option<OwnedFd>) {
        self.phase = RetentionPhaseV1::Failed;
        if self.shutdown_attempted {
            return;
        }

        self.shutdown_attempted = true;
        self.shutdown_failure = fd.as_ref().and_then(|fd| {
            rustix::net::shutdown(fd, rustix::net::Shutdown::Both)
                .err()
                .map(std::io::Error::from)
        });
    }
}

// The exclusive operation prearms a negative fence. Only this observation's
// full success or initial nonconsuming receive/send refusal may restore it.
struct OriginalObservationV1<'a> {
    fd: &'a Option<OwnedFd>,
    retention: &'a mut OriginalRetentionV1,
    settled: bool,
}

impl<'a> OriginalObservationV1<'a> {
    fn begin(
        fd: &'a Option<OwnedFd>,
        retention: &'a mut OriginalRetentionV1,
    ) -> Result<Self, SeqpacketError> {
        if retention.phase == RetentionPhaseV1::Failed || fd.is_none() {
            return Err(SeqpacketError::Closed);
        }

        retention.phase = RetentionPhaseV1::Failed;
        Ok(Self {
            fd,
            retention,
            settled: false,
        })
    }

    fn fd(&self) -> Result<BorrowedFd<'_>, SeqpacketError> {
        self.fd.as_ref().map(AsFd::as_fd).ok_or(SeqpacketError::Closed)
    }

    fn complete(&mut self) {
        self.retention.phase = RetentionPhaseV1::Healthy;
        self.settled = true;
    }
}

impl Drop for OriginalObservationV1<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.retention.end(self.fd);
        }
    }
}

enum SocketDispositionV1<'a> {
    Legacy {
        fd: &'a mut Option<OwnedFd>,
        retention: &'a mut OriginalRetentionV1,
    },
    Retained(OriginalObservationV1<'a>),
}

#[derive(Clone, Copy)]
enum SendDispositionV1 {
    Legacy,
    Retained,
}

impl<'a> SocketDispositionV1<'a> {
    fn begin(
        fd: &'a mut Option<OwnedFd>,
        retention: &'a mut OriginalRetentionV1,
        disposition: SendDispositionV1,
    ) -> Result<Self, SeqpacketError> {
        match disposition {
            SendDispositionV1::Retained => {
                Ok(Self::Retained(OriginalObservationV1::begin(fd, retention)?))
            }
            SendDispositionV1::Legacy => Ok(Self::Legacy { fd, retention }),
        }
    }

    fn fd(&self) -> Result<BorrowedFd<'_>, SeqpacketError> {
        match self {
            Self::Legacy { fd, retention } => {
                if retention.phase == RetentionPhaseV1::Failed {
                    return Err(SeqpacketError::Closed);
                }
                fd.as_ref().map(AsFd::as_fd).ok_or(SeqpacketError::Closed)
            }
            Self::Retained(observation) => observation.fd(),
        }
    }

    fn fatal(&mut self) {
        match self {
            Self::Legacy { fd, retention } => {
                if retention.phase == RetentionPhaseV1::Legacy {
                    fd.take();
                } else {
                    retention.end(fd);
                }
            }
            Self::Retained(observation) => observation.retention.end(observation.fd),
        }
    }

    fn complete(&mut self) {
        if let Self::Retained(observation) = self {
            observation.complete();
        }
    }
}

impl DescriptorSubjectSocket {
    /// Connects to one normalized absolute filesystem socket.
    ///
    /// Connection-peer correlation remains an explicit higher-level step; this
    /// carrier reports each record's independent kernel-nominated subject.
    ///
    /// # Errors
    ///
    /// Rejects a relative or non-normalized path, connection failure, or
    /// descriptor-subject socket adoption failure.
    pub fn connect(path: &Path) -> Result<Self, SeqpacketError> {
        Self::require_connection_path(path)?;
        Self::from_owned(uapi::connect_seqpacket(path)?)
    }

    /// Connects while retaining original socket custody on admission failure.
    ///
    /// Failure shuts down the same descriptor without exposing it for I/O or
    /// retry. It preserves the first cause separately from shutdown debt.
    ///
    /// # Errors
    ///
    /// Rejects the same paths, creation, connection, peer and reporting options
    /// as `connect`; any created socket remains owned by the returned error.
    pub fn connect_retaining(path: &Path) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::require_connection_path(path)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        Self::from_pending_retaining(connect_pending_seqpacket(path)?)
    }

    fn require_connection_path(path: &Path) -> Result<(), SeqpacketError> {
        let bytes = path.as_os_str().as_bytes();
        let normalized = path.is_absolute()
            && bytes.len() > 1
            && !bytes.contains(&0)
            && bytes[1..]
                .split(|byte| *byte == b'/')
                .all(|component| !component.is_empty() && !matches!(component, b"." | b".."))
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
        if !normalized {
            return Err(SeqpacketError::Kernel(Error::invalid(
                "descriptor-subject connection path",
                "must be a normalized absolute path",
            )));
        }

        Ok(())
    }

    /// Adopts a connected Unix sequenced-packet socket and enables subject reporting.
    ///
    /// Call this before sending the first request that can trigger a reply.
    /// Previously queued packets without complete subjects are rejected, never
    /// upgraded into subject-bearing records. The caller must exclusively own
    /// socket configuration and consumption, including any duplicate descriptors.
    ///
    /// # Errors
    ///
    /// Rejects an incorrect socket type or connection state, failure to query
    /// and pin the connection peer, or failure to set close-on-exec,
    /// nonblocking, credential, or pidfd-reporting options.
    pub fn from_owned(fd: OwnedFd) -> Result<Self, SeqpacketError> {
        let peer = admit_connected_peer(fd.as_fd())?;
        uapi::enable_seqpacket_identity(fd.as_fd())?;
        Ok(Self {
            fd: Some(fd),
            peer,
            retention: OriginalRetentionV1::legacy(),
        })
    }

    /// Adopts an original descriptor while retaining failed admission custody.
    ///
    /// The same checks and ordering as `from_owned` are used. Failure and
    /// unwind shut down the original before dropping its descriptor or peer.
    ///
    /// # Errors
    ///
    /// Returns the original descriptor, flag, peer or subject-option cause with
    /// owned socket custody and separate shutdown debt; no I/O loan escapes.
    pub fn from_owned_retaining(fd: OwnedFd) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::from_pending_retaining(PendingSocketAdmissionV1::new(fd))
    }

    pub(super) fn from_pending_retaining(
        mut pending: PendingSocketAdmissionV1,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        let admitted = pending.admit_peer().and_then(|()| pending.enable_subjects());
        if let Err(source) = admitted {
            return Err(pending.fail(source));
        }
        let (fd, peer) = pending.finish()?;
        Ok(Self {
            fd: Some(fd),
            peer,
            retention: OriginalRetentionV1::legacy(),
        })
    }

    /// Returns the process that established this connected channel.
    ///
    /// Socket activation commonly makes this PID 1, so callers must still
    /// validate every nominated subject against its protected live session.
    #[must_use]
    pub const fn peer(&self) -> &ConnectionPeerIdentity {
        &self.peer
    }

    /// Borrows the channel for readiness polling, not competing packet consumption.
    ///
    /// # Errors
    ///
    /// Rejects a channel closed after a fatal transport error.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, SeqpacketError> {
        if self.retention.phase == RetentionPhaseV1::Failed {
            return Err(SeqpacketError::Closed);
        }
        self.fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or(SeqpacketError::Closed)
    }

    /// Verifies the exact filesystem pathname bound to this connected endpoint.
    ///
    /// Abstract, unnamed, unterminated, and noncanonical local addresses are
    /// rejected rather than compared as filesystem paths.
    ///
    /// # Errors
    ///
    /// Returns an error when the channel is closed, `getsockname(2)` fails, or
    /// either input is not one normalized Unix filesystem address.
    pub fn require_local_filesystem_path(&self, expected: &Path) -> Result<(), SeqpacketError> {
        self.peer
            .require_local_filesystem_path(self.as_fd()?, expected)
    }

    /// Verifies the filesystem pathname of this connected endpoint's peer.
    ///
    /// # Errors
    ///
    /// Rejects a replaced socket, noncanonical path, or mismatched address.
    pub fn require_peer_filesystem_path(&self, expected: &Path) -> Result<(), SeqpacketError> {
        self.peer
            .require_peer_filesystem_path(self.as_fd()?, expected)
    }

    /// Irrevocably closes this one-shot channel.
    ///
    /// Higher-level multi-record protocols use this after any partial-transfer
    /// failure so hostile bytes cannot be followed by a fresh parser on the
    /// same stream.
    pub fn close(&mut self) {
        self.dispose_fatal();
    }

    /// Commits negative retention of this already owned original channel.
    ///
    /// This cannot reopen a failed channel or authenticate its application role.
    pub fn begin_original_retention_v1(&mut self) {
        if self.retention.phase == RetentionPhaseV1::Legacy {
            self.retention.phase = if self.fd.is_some() {
                RetentionPhaseV1::Healthy
            } else {
                RetentionPhaseV1::Failed
            };
        }
    }

    /// Reports irreversible negative state, never EOF or peer Drain.
    #[must_use]
    pub fn original_retention_failed_v1(&self) -> bool {
        self.retention.phase == RetentionPhaseV1::Failed
    }

    /// Borrows additional original-socket shutdown debt without releasing custody.
    #[must_use]
    pub fn original_shutdown_failure_v1(&self) -> Option<&std::io::Error> {
        self.retention.shutdown_failure.as_ref()
    }

    fn dispose_fatal(&mut self) {
        if self.retention.phase == RetentionPhaseV1::Legacy {
            self.fd.take();
        } else {
            self.retention.end(&self.fd);
        }
    }

    /// Provisions and verifies capacity for one bounded application packet.
    ///
    /// Linux doubles ordinary `SO_SNDBUF` and `SO_RCVBUF` requests and clamps
    /// them to node-wide maxima. This method deliberately does not use the
    /// privileged `SO_*BUFFORCE` variants. Protocols with large logical
    /// messages should select a small frame size that fits the kernel minimum,
    /// then use this check to make the dependency explicit on both endpoints.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-16-MiB packet size, a closed channel, socket
    /// option failure, or an effective buffer smaller than the requested
    /// packet. The send-side check includes Linux's Unix-socket 32-byte
    /// sequenced-packet reservation.
    pub fn provision_packet_capacity(
        &self,
        maximum_packet_bytes: usize,
    ) -> Result<(), SeqpacketError> {
        const UNIX_SEQPACKET_SEND_RESERVATION_BYTES: usize = 32;

        if maximum_packet_bytes == 0 || maximum_packet_bytes > MAXIMUM_PACKET_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let required_send_buffer = maximum_packet_bytes
            .checked_add(UNIX_SEQPACKET_SEND_RESERVATION_BYTES)
            .ok_or(SeqpacketError::InvalidMaximum)?;
        let fd = self.as_fd()?;

        rustix::net::sockopt::set_socket_send_buffer_size(fd, required_send_buffer).map_err(
            |source| {
                SeqpacketError::Kernel(Error::Syscall {
                    operation: "setsockopt(SO_SNDBUF)",
                    source: source.into(),
                })
            },
        )?;
        rustix::net::sockopt::set_socket_recv_buffer_size(fd, maximum_packet_bytes).map_err(
            |source| {
                SeqpacketError::Kernel(Error::Syscall {
                    operation: "setsockopt(SO_RCVBUF)",
                    source: source.into(),
                })
            },
        )?;

        let actual_send = rustix::net::sockopt::socket_send_buffer_size(fd).map_err(|source| {
            SeqpacketError::Kernel(Error::Syscall {
                operation: "getsockopt(SO_SNDBUF)",
                source: source.into(),
            })
        })?;
        let actual_receive =
            rustix::net::sockopt::socket_recv_buffer_size(fd).map_err(|source| {
                SeqpacketError::Kernel(Error::Syscall {
                    operation: "getsockopt(SO_RCVBUF)",
                    source: source.into(),
                })
            })?;
        if actual_send < required_send_buffer || actual_receive < maximum_packet_bytes {
            return Err(SeqpacketError::Kernel(Error::invalid(
                "descriptor-subject packet capacity",
                "effective socket buffers are below the bounded packet requirement",
            )));
        }
        Ok(())
    }

    /// Sends one bounded packet without any transferred descriptors.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized packet, a closed channel, transport errors,
    /// or a short send. Backpressure and interruption are retryable.
    pub fn send(&mut self, payload: &[u8]) -> Result<(), SeqpacketError> {
        self.send_with_disposition(payload, SendDispositionV1::Legacy)
    }

    /// Sends through the same native sender while retaining fatal original custody.
    ///
    /// # Errors
    ///
    /// Retains the original endpoint on refusal; only native backpressure or
    /// interruption permits retry. This is not a writer-authentication result.
    pub fn send_retaining(&mut self, payload: &[u8]) -> Result<(), SeqpacketError> {
        self.send_with_disposition(payload, SendDispositionV1::Retained)
    }

    fn send_with_disposition(
        &mut self,
        payload: &[u8],
        selected: SendDispositionV1,
    ) -> Result<(), SeqpacketError> {
        let mut disposition = SocketDispositionV1::begin(&mut self.fd, &mut self.retention, selected)?;
        if payload.is_empty() || payload.len() > MAXIMUM_PACKET_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = uapi::send_seqpacket(disposition.fd()?, payload).map_err(map_kernel_error);
        match result {
            Ok(written) if written == payload.len() => {
                disposition.complete();
                Ok(())
            }
            Ok(written) => {
                disposition.fatal();
                Err(SeqpacketError::PartialSend {
                    expected: payload.len(),
                    actual: written,
                })
            }
            Err(error) => {
                if error.is_fatal() {
                    disposition.fatal();
                } else {
                    disposition.complete();
                }
                Err(error)
            }
        }
    }

    /// Sends one bounded packet with one or two descriptors in exact order.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized packet, an empty or above-two descriptor
    /// table, a closed channel, transport failure, or short send. Backpressure
    /// and interruption preserve the channel; fatal errors close it.
    pub fn send_with_descriptors(
        &mut self,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), SeqpacketError> {
        self.send_descriptors_with_disposition(payload, descriptors, SendDispositionV1::Legacy)
    }

    /// Sends the existing one-to-two-descriptor profile with original retention.
    ///
    /// # Errors
    ///
    /// Rejects the same bounds/native sends, retaining fatal endpoint custody.
    /// This never widens the separate three-descriptor kernel-export profile.
    pub fn send_with_descriptors_retaining(
        &mut self,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), SeqpacketError> {
        self.send_descriptors_with_disposition(payload, descriptors, SendDispositionV1::Retained)
    }

    fn send_descriptors_with_disposition(
        &mut self,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
        selected: SendDispositionV1,
    ) -> Result<(), SeqpacketError> {
        let mut disposition = SocketDispositionV1::begin(&mut self.fd, &mut self.retention, selected)?;
        if payload.is_empty()
            || payload.len() > MAXIMUM_PACKET_BYTES
            || descriptors.is_empty()
            || descriptors.len() > MAXIMUM_TRANSFERRED_DESCRIPTORS
        {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let mut control_space = [MaybeUninit::uninit();
            rustix::cmsg_space!(ScmRights(MAXIMUM_TRANSFERRED_DESCRIPTORS))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
            disposition.fatal();
            return Err(SeqpacketError::Ancillary(
                "SCM_RIGHTS descriptor table exceeded its fixed buffer",
            ));
        }
        let result = sendmsg(
            disposition.fd()?,
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
        match result {
            Ok(written) if written == payload.len() => {
                disposition.complete();
                Ok(())
            }
            Ok(written) => {
                disposition.fatal();
                Err(SeqpacketError::PartialSend {
                    expected: payload.len(),
                    actual: written,
                })
            }
            Err(error) => {
                if error.is_fatal() {
                    disposition.fatal();
                } else {
                    disposition.complete();
                }
                Err(error)
            }
        }
    }

    /// Sends the closed kernel-export request with exactly three descriptors.
    ///
    /// This separate profile does not widen ordinary descriptor replies. The
    /// application must bind clone, mutable origin, and cgroup roles before
    /// sending and retain their custody until its acknowledgment is checked.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized packet, a closed channel, transport
    /// failure, or short send. Fatal errors close the channel.
    pub fn send_kernel_export_three(
        &mut self,
        payload: &[u8],
        descriptors: [BorrowedFd<'_>; KERNEL_EXPORT_DESCRIPTORS],
    ) -> Result<(), SeqpacketError> {
        if payload.is_empty() || payload.len() > MAXIMUM_PACKET_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let mut control_space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(KERNEL_EXPORT_DESCRIPTORS))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            self.dispose_fatal();
            return Err(SeqpacketError::Ancillary(
                "SCM_RIGHTS descriptor table exceeded its fixed buffer",
            ));
        }
        let result = sendmsg(
            self.as_fd()?,
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
        match result {
            Ok(written) if written == payload.len() => Ok(()),
            Ok(written) => {
                self.dispose_fatal();
                Err(SeqpacketError::PartialSend {
                    expected: payload.len(),
                    actual: written,
                })
            }
            Err(error) => {
                if error.is_fatal() {
                    self.dispose_fatal();
                }
                Err(error)
            }
        }
    }

    /// Receives the closed kernel-export request with exactly three descriptors.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, a missing or extra descriptor, malformed
    /// ancillary data, truncation, EOF, or kernel errors. Fatal errors close
    /// the socket and every received descriptor.
    pub fn receive_kernel_export_three(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_PACKET_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_inner(maximum_bytes, KERNEL_EXPORT_DESCRIPTORS, false);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.dispose_fatal();
        }
        result
    }

    /// Receives one bounded packet with an exact descriptor count and kernel subject.
    ///
    /// Preflight peeking validates subject/control data and packet size before
    /// allocating the payload. Its temporary pidfd and descriptor copies close
    /// before the real receive. Consumed records are independently revalidated.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-16-MiB packet ceiling, a descriptor count above
    /// two, malformed/missing/extra ancillary data, truncation, size drift, EOF,
    /// or kernel errors. Fatal receives close the socket and all adopted FDs;
    /// backpressure and interruption preserve it for readiness-driven retries.
    pub fn receive(
        &mut self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_PACKET_BYTES
            || expected_descriptors > MAXIMUM_TRANSFERRED_DESCRIPTORS
        {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_inner(maximum_bytes, expected_descriptors, false);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.dispose_fatal();
        }
        result
    }

    /// Binds an already received descriptor record to this exact socket endpoint.
    ///
    /// The record must have been consumed from this socket object or one of its
    /// duplicate descriptors. The returned wrapper owns every transferred
    /// descriptor and borrows this socket's exact retained peer, preventing
    /// competing mutable I/O through this owner while the result remains
    /// unresolved. The binding neither authenticates the writer or an
    /// application role nor equates the record subject with the connection peer.
    ///
    /// # Errors
    ///
    /// Closes this socket and drops the complete record and descriptor table
    /// when the socket is closed, its current kernel cookie cannot be read or
    /// differs from the retained binding, or the record originated on another
    /// socket object.
    pub fn bind_received<'socket>(
        &'socket mut self,
        record: ReceivedDescriptorRecord,
    ) -> Result<ConnectionBoundReceivedDescriptorRecord<'socket>, super::RecordBindingError> {
        self.bind_received_retaining(record)
            .map_err(|(error, _record)| error)
    }

    /// Binds a typed packet while returning all received custody on failure.
    ///
    /// This has the same socket-origin checks and fatal-close behavior as
    /// [`Self::bind_received`]. It does not clone the record subject or any FD.
    ///
    /// # Errors
    ///
    /// Returns the binding error together with the original complete packet
    /// after closing the socket when its origin or current binding is invalid.
    pub fn bind_received_retaining<'socket>(
        &'socket mut self,
        record: ReceivedDescriptorRecord,
    ) -> Result<
        ConnectionBoundReceivedDescriptorRecord<'socket>,
        (super::RecordBindingError, ReceivedDescriptorRecord),
    > {
        if let Err(error) = self.require_record_origin(&record) {
            self.dispose_fatal();
            return Err((error, record));
        }

        Ok(ConnectionBoundReceivedDescriptorRecord {
            record,
            peer: &self.peer,
        })
    }

    /// Checks a borrowed typed packet against this socket's current origin.
    ///
    /// This retains all packet and descriptor custody in the caller's slot.
    /// It establishes carrier continuity only, not application authority or
    /// equivalence between the nominated subject and the connection peer.
    ///
    /// # Errors
    ///
    /// Closes the socket for the same invalid origin or current-binding
    /// conditions as [`Self::bind_received_retaining`].
    pub fn validate_received_origin(
        &mut self,
        record: &ReceivedDescriptorRecord,
    ) -> Result<(), super::RecordBindingError> {
        if let Err(error) = self.require_record_origin(record) {
            self.dispose_fatal();
            return Err(error);
        }

        Ok(())
    }

    /// Receives a response with either no descriptors or exactly two descriptors.
    ///
    /// This closed alternative supports descriptor-free protocol errors. The
    /// higher-level decoder must require zero descriptors on errors and exactly
    /// two correctly ordered roles on success. One descriptor is always rejected.
    ///
    /// # Errors
    ///
    /// Returns the same bound, subject, transport, and fatal-close errors as
    /// [`Self::receive`], rejecting every descriptor count except zero and two.
    pub fn receive_reply(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        self.receive_reply_profile(maximum_bytes, 2)
    }

    /// Receives a reply with either no descriptors or exactly one descriptor.
    ///
    /// This closed profile supports SourceProvider errors and non-Acquire
    /// responses without descriptors, and successful Acquire responses with
    /// exactly one source-root descriptor. The higher-level protocol must bind
    /// that descriptor to its signed role and receipt.
    ///
    /// # Errors
    ///
    /// Returns the same bound, subject, transport, and fatal-close errors as
    /// [`Self::receive`], rejecting every descriptor count except zero and one.
    pub fn receive_optional_descriptor_reply(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        self.receive_reply_profile(maximum_bytes, 1)
    }

    /// Receives a privileged mount-scope reply with zero or five descriptors.
    ///
    /// The success profile carries a payload pidfd, cgroup, root directory,
    /// mount namespace, and user namespace, in that order. The caller must
    /// correlate the response's kernel-nominated subject and separately
    /// authenticate the application session/result before validating roles,
    /// scope, and authority or using any descriptor. This carrier alone neither
    /// identifies the Host broker nor authorizes namespace entry.
    /// Descriptor-free replies are reserved for protocol errors.
    ///
    /// # Errors
    ///
    /// Returns the same bound, subject, transport, and fatal-close errors as
    /// [`Self::receive`], rejecting every descriptor count except zero and five.
    pub fn receive_mount_scope_reply(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        self.receive_reply_profile(maximum_bytes, 5)
    }

    fn receive_reply_profile(
        &mut self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_PACKET_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_inner(maximum_bytes, expected_descriptors, true);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.dispose_fatal();
        }
        result
    }

    fn receive_inner(
        &self,
        maximum_bytes: usize,
        expected_descriptors: usize,
        allow_empty: bool,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        let mut probe = [0_u8; 1];
        let preview =
            uapi::recv_seqpacket(self.as_fd()?, &mut probe, libc::MSG_PEEK | libc::MSG_TRUNC)
                .map_err(map_kernel_error)?;
        if preview.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        drop(validate_ancillary(
            preview.ancillary,
            expected_descriptors,
            allow_empty,
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
            uapi::recv_seqpacket(self.as_fd()?, &mut payload, 0).map_err(map_kernel_error)?;
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
        let (subject, descriptors) =
            validate_ancillary(received.ancillary, expected_descriptors, allow_empty)?;
        let origin = self.peer.binding.received_origin();
        Ok(ReceivedDescriptorRecord {
            payload,
            subject,
            descriptors,
            origin,
        })
    }

    fn require_record_origin(
        &self,
        record: &ReceivedDescriptorRecord,
    ) -> Result<(), super::RecordBindingError> {
        let fd = self.as_fd().map_err(|_| super::RecordBindingError::closed())?;
        require_record_origin(fd, &self.peer, record)
    }
}

impl DescriptorSubjectSocket {
    /// Receives the fixed zero-descriptor profile with original lower custody.
    ///
    /// # Errors
    ///
    /// Returns the owning receive failure. Only an initial nonconsuming EAGAIN
    /// or EINTR can retry; fatal/partial errors retain and fence this endpoint.
    pub fn receive_zero_descriptors_retaining(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_retaining(
            maximum_bytes,
            SubjectProfileV1::Descriptors { expected: 0, allow_empty: false },
        )
    }

    /// Receives only zero or one descriptor through the original receive engine.
    ///
    /// # Errors
    ///
    /// Retains native/subject/framing failures and fences every fatal epoch.
    /// Application role and zero-descriptor error semantics remain caller checks.
    pub fn receive_optional_descriptor_reply_retaining(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_retaining(
            maximum_bytes,
            SubjectProfileV1::Descriptors { expected: 1, allow_empty: true },
        )
    }

    fn receive_profile_retaining(
        &mut self,
        maximum: usize,
        profile: SubjectProfileV1,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let mut observation = OriginalObservationV1::begin(&self.fd, &mut self.retention)
            .map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
        let result = (|| {
            if maximum == 0 || maximum > MAXIMUM_PACKET_BYTES {
                return Err(RetainedSeqpacketReceiveErrorV1::before_receive(
                    SeqpacketError::InvalidMaximum,
                ));
            }

            let fd = observation.fd().map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
            let attempt = ReceiveAttemptV1::capture(fd, self.peer.socket_cookie())?;
            let mut attempt = receive_packet(attempt, maximum, profile)?;
            let message = &mut attempt.messages[1];
            let Some(subject) = message.subject.take() else {
                return Err(attempt.reject(SeqpacketError::Ancillary("missing SCM_PIDFD")));
            };
            let record = ReceivedDescriptorRecord::from_parts(
                std::mem::take(&mut message.payload),
                subject,
                message.take_descriptors(),
                self.peer.binding.received_origin(),
            );
            attempt.disarm();
            Ok(record)
        })();

        let retryable = match &result {
            Ok(_) => true,
            Err(error) => error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted(),
        };
        if retryable {
            observation.complete();
        }
        result
    }

    /// Checks a caller-resident record without disposing packet or original socket.
    ///
    /// # Errors
    ///
    /// Fences the same endpoint on any binding refusal and returns its typed cause.
    /// This establishes carrier continuity only, not application currentness.
    pub fn validate_received_origin_retaining(
        &mut self,
        record: &ReceivedDescriptorRecord,
    ) -> Result<(), super::RecordBindingError> {
        let mut observation = OriginalObservationV1::begin(&self.fd, &mut self.retention)
            .map_err(|_| super::RecordBindingError::closed())?;
        let fd = observation.fd().map_err(|_| super::RecordBindingError::closed())?;
        require_record_origin(fd, &self.peer, record)?;
        observation.complete();
        Ok(())
    }
}

impl Drop for DescriptorSubjectSocket {
    fn drop(&mut self) {
        if self.retention.phase != RetentionPhaseV1::Legacy {
            self.retention.end(&self.fd);
        }
    }
}

fn require_record_origin(
    fd: BorrowedFd<'_>,
    peer: &ConnectionPeerIdentity,
    record: &ReceivedDescriptorRecord,
) -> Result<(), super::RecordBindingError> {
    peer.binding.require_current(fd)?;
    record.origin.require_binding(peer.binding)
}

/// Retains a received record's kernel subject and exact transferred descriptor sequence.
#[derive(Debug)]
pub struct ReceivedDescriptorRecord {
    payload: Vec<u8>,
    subject: KernelAuthorizedRecordSubject,
    descriptors: Vec<OwnedFd>,
    origin: ReceivedSocketOrigin,
}

/// Owns a descriptor record bound to the exact socket that consumed it.
///
/// This wrapper has no independent constructor. Its lifetime retains a borrow
/// of the receiving socket's pinned peer and prevents mutable socket operations
/// through that owner until the wrapper or the peer returned by
/// [`Self::into_parts`] is released. It provides carrier continuity only, not
/// writer authentication, descriptor authority, or subject/peer equivalence.
///
/// ```compile_fail
/// use aos_sandbox_linux::seqpacket::descriptor_subject::{
///     DescriptorSubjectSocket, ReceivedDescriptorRecord,
/// };
///
/// fn compete(socket: &mut DescriptorSubjectSocket, record: ReceivedDescriptorRecord) {
///     let (_, _, _, peer) = socket.bind_received(record).unwrap().into_parts();
///     socket.send(b"competing I/O").unwrap();
///     let _ = peer.credentials();
/// }
/// ```
///
/// ```compile_fail
/// use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
/// use aos_sandbox_linux::seqpacket::descriptor_subject::{
///     ConnectionBoundReceivedDescriptorRecord, ReceivedDescriptorRecord,
/// };
///
/// fn forge<'a>(
///     record: ReceivedDescriptorRecord,
///     peer: &'a ConnectionPeerIdentity,
/// ) -> ConnectionBoundReceivedDescriptorRecord<'a> {
///     ConnectionBoundReceivedDescriptorRecord { record, peer }
/// }
/// ```
#[derive(Debug)]
pub struct ConnectionBoundReceivedDescriptorRecord<'socket> {
    record: ReceivedDescriptorRecord,
    peer: &'socket ConnectionPeerIdentity,
}

impl<'socket> ConnectionBoundReceivedDescriptorRecord<'socket> {
    pub(super) fn new(
        record: ReceivedDescriptorRecord,
        peer: &'socket ConnectionPeerIdentity,
    ) -> Self {
        Self { record, peer }
    }

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

    /// Returns transferred descriptors in their exact ancillary order.
    #[must_use]
    pub fn descriptors(&self) -> &[OwnedFd] {
        self.record.descriptors()
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
        Vec<OwnedFd>,
        &'socket ConnectionPeerIdentity,
    ) {
        let (payload, subject, descriptors) = self.record.into_parts();
        (payload, subject, descriptors, self.peer)
    }
}

impl ReceivedDescriptorRecord {
    pub(super) fn from_parts(
        payload: Vec<u8>,
        subject: KernelAuthorizedRecordSubject,
        descriptors: Vec<OwnedFd>,
        origin: ReceivedSocketOrigin,
    ) -> Self {
        Self {
            payload,
            subject,
            descriptors,
            origin,
        }
    }

    pub(super) fn require_origin(
        &self,
        binding: super::socket_binding::ConnectedSocketBinding,
    ) -> Result<(), super::RecordBindingError> {
        self.origin.require_binding(binding)
    }

    /// Borrows the packet bytes without asserting application authority.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrows the subject nominated under the writer's kernel credential authority.
    #[must_use]
    pub const fn subject(&self) -> &KernelAuthorizedRecordSubject {
        &self.subject
    }

    /// Borrows transferred descriptors in their original ancillary order.
    #[must_use]
    pub fn descriptors(&self) -> &[OwnedFd] {
        &self.descriptors
    }

    /// Transfers ownership of the packet, subject pin, and descriptor sequence.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, KernelAuthorizedRecordSubject, Vec<OwnedFd>) {
        (self.payload, self.subject, self.descriptors)
    }
}

pub(super) fn validate_ancillary(
    ancillary: Vec<RawAncillary>,
    expected: usize,
    allow_empty: bool,
) -> Result<(KernelAuthorizedRecordSubject, Vec<OwnedFd>), SeqpacketError> {
    super::receive_custody::validate_legacy(ancillary,
        super::receive_custody::SubjectProfileV1::Descriptors { expected, allow_empty })
        .map(|(subject, descriptors, _)| (subject, descriptors))
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn retaining_strict_path_refusal_has_no_created_socket_or_shutdown_debt() {
        for path in [
            Path::new("relative.sock"),
            Path::new("/"),
            Path::new("/tmp//control.sock"),
            Path::new("/tmp/./control.sock"),
            Path::new("/tmp/control.sock/"),
        ] {
            let failure = DescriptorSubjectSocket::connect_retaining(path).unwrap_err();

            assert!(matches!(
                failure.cause(),
                SeqpacketError::Kernel(Error::InvalidInput {
                    field: "descriptor-subject connection path",
                    ..
                })
            ));
            assert!(!failure.retains_descriptor());
            assert!(!failure.shutdown_attempted());
            assert!(failure.shutdown_failure().is_none());
        }
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn already_failed_observation_cannot_begin_or_rearm() {
        let fd = None;
        let mut retention = OriginalRetentionV1::legacy();
        retention.phase = RetentionPhaseV1::Failed;

        assert!(OriginalObservationV1::begin(&fd, &mut retention).is_err());
        assert_eq!(retention.phase, RetentionPhaseV1::Failed);
    }

    #[test]
    fn terminal_state_and_first_shutdown_debt_are_irreversible() {
        let mut retention = OriginalRetentionV1::legacy();
        retention.shutdown_attempted = true;
        retention.shutdown_failure = Some(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let first = retention.shutdown_failure.as_ref().unwrap() as *const std::io::Error;

        retention.end(&None);
        retention.end(&None);

        assert_eq!(retention.phase, RetentionPhaseV1::Failed);
        assert_eq!(retention.shutdown_failure.as_ref().unwrap() as *const std::io::Error, first);
    }

    #[test]
    fn legacy_disposition_has_no_retained_shutdown_effect() {
        let mut fd = None;
        let mut retention = OriginalRetentionV1::legacy();

        {
            let _disposition = SocketDispositionV1::begin(
                &mut fd, &mut retention, SendDispositionV1::Legacy,
            ).unwrap();
        }

        assert_eq!(retention.phase, RetentionPhaseV1::Legacy);
        assert!(!retention.shutdown_attempted);
    }
}

#[cfg(test)]
mod tests;
