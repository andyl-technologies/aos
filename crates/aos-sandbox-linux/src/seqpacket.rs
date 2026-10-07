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
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use crate::Error;
use crate::pidfd::{PidFd, PidFdInfo};
use crate::uapi::{self, RawAncillary};

mod listener;
pub use listener::{
    ListenerAdmissionFailureRefV1, RecordSubjectListener,
    RecordSubjectListenerAdmissionAttemptV1,
};

mod socket_binding;
use socket_binding::{ConnectedSocketBinding, ReceivedSocketOrigin};

pub mod bounded;
pub mod descriptor_subject;

pub(crate) mod receive_custody;
pub use receive_custody::RetainedSeqpacketReceiveErrorV1;

/// Describes known source-level storage terms for an optional-descriptor receive.
///
/// These are logical payload and inline-owner sizes, not an allocation bound
/// or admission permit. Vector capacities, allocator overhead, malformed
/// ancillary storage, process observations and kernel resources remain
/// unpriced. A caller must independently price those and its whole receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionalDescriptorReceiveFootprintV1 {
    /// Maximum requested payload bytes across the preview and consumed samples.
    pub payload_bytes: usize,
    /// Inline size of the existing original-endpoint attempt owner.
    pub attempt_inline_bytes: usize,
    /// Logical inline size of the two sample owners, excluding vector capacity.
    pub sample_inline_bytes: usize,
    /// Inline size of the complete returned success-or-failure slot.
    pub result_inline_bytes: usize,
}

#[cfg(test)]
mod process_tests;

/// A nonblocking, close-on-exec Unix sequenced-packet socket.
pub struct SeqpacketSocket {
    fd: Option<OwnedFd>,
    peer: ConnectionPeerIdentity,
    retained_send_flight: Option<OwnedFd>,
}

impl std::fmt::Debug for SeqpacketSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Preserve the ordinary presentation without exposing failed custody.
        formatter
            .debug_struct("SeqpacketSocket")
            .field("fd", &self.fd)
            .field("peer", &self.peer)
            .finish()
    }
}

/// Owns one retained send refusal and any original sending descriptor.
///
/// The descriptor cannot be extracted or used for I/O. Its retention does not
/// establish delivery, peer exit, retry eligibility or drained effects.
pub struct RetainedSeqpacketSendErrorV1 {
    cause: SeqpacketError,
    descriptor: Option<OwnedFd>,
}

impl RetainedSeqpacketSendErrorV1 {
    /// Borrows the exact typed send refusal without replacing its cause.
    #[must_use]
    pub const fn cause(&self) -> &SeqpacketError {
        &self.cause
    }

    /// Reports original descriptor custody without exposing an I/O handle.
    #[must_use]
    pub fn retains_descriptor(&self) -> bool {
        self.descriptor.is_some()
    }
}

impl std::fmt::Debug for RetainedSeqpacketSendErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedSeqpacketSendErrorV1")
            .field("cause", &self.cause)
            .field("retains_descriptor", &self.retains_descriptor())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RetainedSeqpacketSendErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "original sequenced-packet send refused: {}", self.cause)
    }
}

impl std::error::Error for RetainedSeqpacketSendErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Clone, Copy)]
enum SeqpacketSendDispositionV1 {
    Legacy,
    Retained,
}

/// Owns an admission failure and any original socket created before that failure.
///
/// Private custody cannot be extracted, cloned or used for I/O. A failed
/// admission has attempted shutdown before returning; a shutdown failure is
/// retained separately and does not replace the first typed cause. Neither
/// shutdown nor dropping this error proves peer exit or all-owner drain.
pub struct RetainedSeqpacketAdmissionErrorV1 {
    source: SeqpacketError,
    attempt: Option<PendingSocketAdmissionV1>,
}

impl RetainedSeqpacketAdmissionErrorV1 {
    /// Borrows the original typed admission failure without replacing its cause.
    #[must_use]
    pub const fn cause(&self) -> &SeqpacketError {
        &self.source
    }

    /// Reports whether the failure still owns the created or supplied descriptor.
    #[must_use]
    pub fn retains_descriptor(&self) -> bool {
        self.attempt
            .as_ref()
            .is_some_and(|attempt| attempt.fd.is_some())
    }

    /// Reports whether shutdown was attempted on the original descriptor.
    #[must_use]
    pub fn shutdown_attempted(&self) -> bool {
        self.attempt
            .as_ref()
            .is_some_and(|attempt| attempt.ended)
    }

    /// Borrows shutdown debt without implying closure, termination or drain.
    #[must_use]
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.attempt
            .as_ref()
            .and_then(|attempt| attempt.shutdown_failure.as_ref())
    }

    pub(super) fn before_creation(source: SeqpacketError) -> Self {
        Self {
            source,
            attempt: None,
        }
    }
}

impl std::fmt::Debug for RetainedSeqpacketAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedSeqpacketAdmissionErrorV1")
            .field("retains_descriptor", &self.retains_descriptor())
            .field("shutdown_attempted", &self.shutdown_attempted())
            .field("shutdown_failed", &self.shutdown_failure().is_some())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RetainedSeqpacketAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original socket admission failed; any acquired custody is retained")
    }
}

impl std::error::Error for RetainedSeqpacketAdmissionErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Guards only original socket admission, never application-purpose authority.
pub(super) struct PendingSocketAdmissionV1 {
    fd: Option<OwnedFd>,
    peer: Option<ConnectionPeerIdentity>,
    armed: bool,
    ended: bool,
    shutdown_failure: Option<std::io::Error>,
}

/// Retains the returned originals of one selected offline helper socket pair.
///
/// This is transport DATA only, not child, approval, Session or TPM authority.
/// The caller keeps this owner resident on error or unwind. Prefixes which a
/// lower constructor does not return are not retroactively captured here.
pub struct NixOfflineSeqpacketPairV5 {
    attempted: bool,
    ready: bool,
    pending: Option<PendingSocketAdmissionV1>,
    socket: Option<SeqpacketSocket>,
    endpoint: Option<OwnedFd>,
    first_failure: Option<SeqpacketError>,
}

impl NixOfflineSeqpacketPairV5 {
    /// Parks empty fixed pair slots without creating or admitting a descriptor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempted: false,
            ready: false,
            pending: None,
            socket: None,
            endpoint: None,
            first_failure: None,
        }
    }

    /// Creates and admits one fixed nonblocking pair with record subjects.
    ///
    /// # Errors
    /// Retains the first actual creation, option or connected-peer cause and
    /// every returned original. Reuse and caught interruption remain closed.
    pub fn prepare(&mut self) -> Result<(), &SeqpacketError> {
        if self.attempted {
            self.ready = false;
            return Err(self.first_failure.get_or_insert(SeqpacketError::Closed));
        }
        self.attempted = true;
        match self.prepare_inner() {
            Ok(()) => {
                self.ready = true;
                Ok(())
            }
            Err(error) => {
                if let Some(pending) = self.pending.as_mut() {
                    pending.end_transport();
                }
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(SeqpacketError::Closed))
            }
        }
    }

    fn prepare_inner(&mut self) -> Result<(), SeqpacketError> {
        let (receiver, endpoint) = uapi::seqpacket_pair()?;
        self.pending = Some(PendingSocketAdmissionV1::new(receiver));
        self.endpoint = Some(endpoint);
        let pending = self.pending.as_mut().ok_or(SeqpacketError::Closed)?;
        pending.enable_subjects()?;
        uapi::enable_seqpacket_identity(
            self.endpoint.as_ref().ok_or(SeqpacketError::Closed)?.as_fd(),
        )?;
        pending.admit_peer()?;

        // Admission has completed. Move both receiver owners infallibly before
        // disarming; no post-return check drops either acquired original.
        let originals = (pending.fd.take(), pending.peer.take());
        let (fd, peer) = match originals {
            (Some(fd), Some(peer)) => (fd, peer),
            (fd, peer) => {
                pending.fd = fd;
                pending.peer = peer;
                return Err(SeqpacketError::Closed);
            }
        };
        pending.armed = false;
        self.socket = Some(SeqpacketSocket {
            fd: Some(fd),
            peer,
            retained_send_flight: None,
        });
        Ok(())
    }

    /// Transfers only the fully admitted child endpoint into the fixed launcher.
    ///
    /// # Errors
    /// Refuses a failed, incomplete, interrupted or previously transferred pair.
    pub fn take_child_endpoint(&mut self) -> Result<OwnedFd, SeqpacketError> {
        if !self.ready {
            return Err(SeqpacketError::Closed);
        }
        self.endpoint.take().ok_or(SeqpacketError::Closed)
    }

    /// Borrows the actual admitted parent socket without releasing pair custody.
    ///
    /// # Errors
    /// Refuses an incomplete or fenced pair.
    pub fn socket(&mut self) -> Result<&mut SeqpacketSocket, SeqpacketError> {
        if !self.ready {
            return Err(SeqpacketError::Closed);
        }
        self.socket.as_mut().ok_or(SeqpacketError::Closed)
    }

    /// Borrows the original first returned failure without cloning it.
    pub fn failure(&self) -> Option<&SeqpacketError> {
        self.first_failure.as_ref()
    }
}

impl Default for NixOfflineSeqpacketPairV5 {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingSocketAdmissionV1 {
    pub(super) fn new(fd: OwnedFd) -> Self {
        Self {
            fd: Some(fd),
            peer: None,
            armed: true,
            ended: false,
            shutdown_failure: None,
        }
    }

    fn borrow_fd(&self) -> Result<BorrowedFd<'_>, SeqpacketError> {
        self.fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or(SeqpacketError::Closed)
    }

    pub(super) fn require_inherited_subjects(&self) -> Result<(), SeqpacketError> {
        uapi::require_seqpacket_identity(self.borrow_fd()?).map_err(map_kernel_error)
    }

    pub(super) fn prepare_accepted_descriptor(&self) -> Result<(), SeqpacketError> {
        uapi::ensure_cloexec(self.borrow_fd()?).map_err(map_kernel_error)
    }

    pub(super) fn admit_peer(&mut self) -> Result<(), SeqpacketError> {
        self.peer = Some(admit_connected_peer(self.borrow_fd()?)?);
        Ok(())
    }

    pub(super) fn enable_subjects(&self) -> Result<(), SeqpacketError> {
        uapi::enable_seqpacket_identity(self.borrow_fd()?).map_err(SeqpacketError::from)
    }

    pub(super) fn fail(mut self, source: SeqpacketError) -> RetainedSeqpacketAdmissionErrorV1 {
        self.end_transport();
        RetainedSeqpacketAdmissionErrorV1 {
            source,
            attempt: Some(self),
        }
    }

    pub(super) fn finish(
        mut self,
    ) -> Result<(OwnedFd, ConnectionPeerIdentity), RetainedSeqpacketAdmissionErrorV1> {
        let Some(peer) = self.peer.take() else {
            return Err(self.fail(SeqpacketError::Closed));
        };
        let Some(fd) = self.fd.take() else {
            self.peer = Some(peer);
            return Err(self.fail(SeqpacketError::Closed));
        };

        // Both original owners move directly into the admitted socket. There
        // is no fallible work between this disarm and result construction.
        self.armed = false;
        Ok((fd, peer))
    }

    fn end_transport(&mut self) {
        if !self.armed || self.ended {
            return;
        }
        self.ended = true;
        if let Some(fd) = self.fd.as_ref() {
            self.shutdown_failure = rustix::net::shutdown(fd, rustix::net::Shutdown::Both)
                .err()
                .map(std::io::Error::from);
        }
    }
}

impl Drop for PendingSocketAdmissionV1 {
    fn drop(&mut self) {
        // The original socket and any completed peer pin remain resident until
        // shutdown is attempted, including during admission unwind.
        self.end_transport();
    }
}

fn admit_connected_peer(fd: BorrowedFd<'_>) -> Result<ConnectionPeerIdentity, SeqpacketError> {
    uapi::prepare_seqpacket(fd)?;
    ConnectionPeerIdentity::from_socket(fd)
}

pub(super) fn connect_pending_seqpacket(
    path: &Path,
) -> Result<PendingSocketAdmissionV1, RetainedSeqpacketAdmissionErrorV1> {
    let bytes = uapi::validate_seqpacket_connection_path(path)
        .map_err(SeqpacketError::from)
        .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
    let fd = uapi::unconnected_seqpacket_before_flags()
        .map_err(SeqpacketError::from)
        .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
    let pending = PendingSocketAdmissionV1::new(fd);

    let connected = (|| {
        uapi::ensure_cloexec(pending.borrow_fd()?)?;
        uapi::connect_seqpacket_borrowed(pending.borrow_fd()?, bytes)?;
        Ok::<_, SeqpacketError>(())
    })();
    if let Err(source) = connected {
        return Err(pending.fail(source));
    }
    Ok(pending)
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
        Self::require_connection_path(path)?;
        let socket = uapi::connect_seqpacket(path)?;
        Self::from_owned(socket)
    }

    /// Connects while retaining the original socket on admission failure.
    ///
    /// The error owns any created socket without exposing it for I/O or revival.
    /// Failure and unwind shut down that socket before its custody is dropped;
    /// shutdown is neither peer termination nor proof of drained effects.
    ///
    /// # Errors
    ///
    /// Returns the original typed path, creation, option, connection or peer
    /// failure together with any created socket and separate shutdown debt.
    pub fn connect_retaining(path: &Path) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::require_connection_path(path)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        Self::from_pending_retaining(connect_pending_seqpacket(path)?)
    }

    fn require_connection_path(path: &Path) -> Result<(), SeqpacketError> {
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

        Ok(())
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
        let peer = admit_connected_peer(fd.as_fd())?;
        Ok(Self {
            fd: Some(fd),
            peer,
            retained_send_flight: None,
        })
    }

    /// Adopts an original descriptor while retaining rejected admission custody.
    ///
    /// This has the same checks as `from_owned`, but failed input remains owned
    /// by the error after shutdown. It cannot be extracted or retried.
    ///
    /// # Errors
    ///
    /// Retains the first descriptor, flag or peer failure and separate shutdown
    /// debt. No error exposes a usable descriptor or application authority.
    pub fn from_owned_retaining(fd: OwnedFd) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::from_pending_retaining(PendingSocketAdmissionV1::new(fd))
    }

    pub(super) fn from_pending_retaining(
        mut pending: PendingSocketAdmissionV1,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        if let Err(source) = pending.admit_peer() {
            return Err(pending.fail(source));
        }
        let (fd, peer) = pending.finish()?;
        Ok(Self {
            fd: Some(fd),
            peer,
            retained_send_flight: None,
        })
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
        self.send_with_disposition(payload, SeqpacketSendDispositionV1::Legacy)
    }

    /// Sends once while retaining the original descriptor on every refusal.
    ///
    /// Only the same full successful send restores the original active slot.
    /// An unfinished or unwound call keeps its descriptor privately fenced in
    /// this socket; ordinary I/O and later retained calls cannot revive it.
    /// Neither a returned error nor a successful send proves peer drain.
    ///
    /// # Errors
    ///
    /// Returns the actual typed send cause with the original descriptor when
    /// acquired. Backpressure and interruption also permanently fence this
    /// selected attempt. A previously closed or unfinished socket is refused
    /// without taking any earlier failed flight's custody.
    pub fn send_retaining(&mut self, payload: &[u8]) -> Result<(), RetainedSeqpacketSendErrorV1> {
        if self.retained_send_flight.is_some() || self.fd.is_none() {
            return Err(RetainedSeqpacketSendErrorV1 {
                cause: SeqpacketError::Closed,
                descriptor: None,
            });
        }

        // The original owner is resident and normal I/O is revoked before the
        // first fallible payload/descriptor/native operation. Unwind cannot
        // restore this slot or dispose it through a temporary local owner.
        self.retained_send_flight = self.fd.take();
        match self.send_with_disposition(payload, SeqpacketSendDispositionV1::Retained) {
            Ok(()) => {
                self.fd = self.retained_send_flight.take();
                Ok(())
            }
            Err(cause) => Err(RetainedSeqpacketSendErrorV1 {
                cause,
                descriptor: self.retained_send_flight.take(),
            }),
        }
    }

    fn send_with_disposition(
        &mut self,
        payload: &[u8],
        disposition: SeqpacketSendDispositionV1,
    ) -> Result<(), SeqpacketError> {
        match disposition {
            SeqpacketSendDispositionV1::Legacy => Self::send_original(
                &mut self.fd,
                payload,
                OriginalSenderDispositionV1::Legacy,
            ),
            SeqpacketSendDispositionV1::Retained => Self::send_original(
                &mut self.retained_send_flight,
                payload,
                OriginalSenderDispositionV1::Retained,
            ),
        }
    }

    fn send_original(
        fd: &mut Option<OwnedFd>,
        payload: &[u8],
        disposition: OriginalSenderDispositionV1,
    ) -> Result<(), SeqpacketError> {
        if payload.is_empty() {
            return Err(SeqpacketError::EmptyRecord);
        }
        let original = fd.as_ref().map(AsFd::as_fd).ok_or(SeqpacketError::Closed)?;
        let sent = uapi::send_seqpacket(original, payload).map_err(map_kernel_error)?;
        if sent != payload.len() {
            disposition.end(fd);
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
        Self::send_original_with_descriptors(&mut self.fd, payload, descriptors, OriginalSenderDispositionV1::Legacy)
    }

    fn send_original_with_descriptors(
        fd: &mut Option<OwnedFd>,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
        disposition: OriginalSenderDispositionV1,
    ) -> Result<(), SeqpacketError> {
        if payload.is_empty() || descriptors.is_empty() || descriptors.len() > 5 {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
            disposition.end(fd);
            return Err(SeqpacketError::Ancillary(
                "SCM_RIGHTS descriptor table exceeded its fixed buffer",
            ));
        }
        let result = sendmsg(
            fd.as_ref().map(AsFd::as_fd).ok_or(SeqpacketError::Closed)?,
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
                    disposition.end(fd);
                }
                return Err(error);
            }
        };
        if written != payload.len() {
            disposition.end(fd);
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
        let result = self.receive_descriptor_inner(maximum_bytes, expected_descriptors, false);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.fd.take();
        }
        result
    }

    /// Receives one record while retaining all captured lower-layer failure custody.
    ///
    /// Unlike the legacy receive, every failed original attempt permanently
    /// shuts down this socket except an initial nonconsuming recvmsg EAGAIN or
    /// EINTR. Preview samples remain explicitly incomplete evidence.
    ///
    /// # Errors
    /// Returns an opaque owning error for framing, subject, kernel or capture
    /// failures. It exposes no descriptor, body, raw control or retry factory.
    pub fn receive_retaining(
        &mut self, maximum_bytes: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        let mut attempt = self.receive_retaining_attempt(maximum_bytes, receive_custody::SubjectProfileV1::Ordinary)?;
        let message = &mut attempt.messages[1];
        let Some(subject) = message.subject.take() else {
            let error = attempt.reject(SeqpacketError::Ancillary("missing SCM_PIDFD"));
            self.fd.take();
            return Err(error);
        };
        let record = ReceivedRecord {
            payload: std::mem::take(&mut message.payload), subject,
            origin: self.peer.binding.received_origin(),
        };
        attempt.disarm();
        Ok(record)
    }

    /// Receives an exact descriptor table with original lower-failure custody.
    ///
    /// # Errors
    /// Returns the owning strict receive error for invalid bounds, an inexact
    /// one-to-five-entry table, subject failure or any partial original attempt.
    pub fn receive_with_descriptors_retaining(
        &mut self, maximum_bytes: usize, expected_descriptors: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if expected_descriptors == 0 || expected_descriptors > 5 {
            let mut error = RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum);
            error.record_shutdown_failure(self.shutdown_retaining_failure());
            return Err(error);
        }
        let profile = receive_custody::SubjectProfileV1::Descriptors { expected: expected_descriptors, allow_empty: false };
        self.receive_descriptor_retaining_profile(maximum_bytes, profile)
    }

    // Both closed descriptor adapters use the same success-only transfer. The
    // sole receive engine returns exactly preview/consumed samples on success.
    fn receive_descriptor_retaining_profile(
        &mut self,
        maximum_bytes: usize,
        profile: receive_custody::SubjectProfileV1,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let mut attempt = self.receive_retaining_attempt(maximum_bytes, profile)?;
        let message = &mut attempt.messages[1];
        let Some(subject) = message.subject.take() else {
            let error = attempt.reject(SeqpacketError::Ancillary("missing SCM_PIDFD"));
            self.fd.take();
            return Err(error);
        };
        let record = descriptor_subject::ReceivedDescriptorRecord::from_parts(
            std::mem::take(&mut message.payload), subject, message.take_descriptors(),
            self.peer.binding.received_origin(),
        );
        attempt.disarm();
        Ok(record)
    }

    /// Checks a canary report's same original carrier without releasing rights.
    ///
    /// This is only socket-origin DATA. The Host must independently bind the
    /// record subject, actual launch, job and donated inspection objects.
    ///
    /// # Errors
    /// Refuses a changed socket or foreign report. The selected purpose owner
    /// must fence the operation and retain its socket, record and first cause;
    /// this borrowed check neither closes custody nor proves process drain.
    pub fn require_host_canary_report_original_v1(
        &mut self,
        record: &descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<(), SeqpacketError> {
        (|| {
            let fd = self.borrow_fd()?;
            let current = ConnectedSocketBinding::capture_peer(fd)?;
            if current != self.peer.binding {
                return Err(SeqpacketError::PeerIdentity("original canary carrier changed"));
            }
            record.require_origin(current).map_err(|_| {
                SeqpacketError::PeerIdentity("canary report belongs to another carrier")
            })
        })()
    }

    /// Compares a resident canary response with this original channel by borrow.
    ///
    /// This establishes transport continuity DATA only. The caller retains the
    /// response, actual subject and first failure before its purpose checks;
    /// neither the response nor the channel is discarded by this observation.
    ///
    /// # Errors
    /// Returns the same original-binding error as the existing record validator.
    pub fn require_host_canary_response_original_v1(
        &self,
        original: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_record_origin(original)
    }

    pub(crate) fn require_host_canary_cookie(&mut self, original: NonZeroU64)
        -> Result<(), SeqpacketError>
    {
        (|| {
            let current = ConnectedSocketBinding::capture_peer(self.borrow_fd()?)?;
            if current != self.peer.binding || current.socket_cookie() != original {
                return Err(SeqpacketError::PeerIdentity("original canary carrier changed"));
            }
            Ok(())
        })()
    }

    fn receive_retaining_attempt(
        &mut self, maximum: usize, profile: receive_custody::SubjectProfileV1,
    ) -> Result<receive_custody::ReceiveAttemptV1, RetainedSeqpacketReceiveErrorV1> {
        let mut result = (|| {
            if maximum == 0 { return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum)); }
            let fd = self.borrow_fd().map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
            let attempt = receive_custody::ReceiveAttemptV1::capture(fd, self.peer.socket_cookie())?;
            receive_custody::receive_packet(attempt, maximum, profile)
        })();
        if let Err(error) = &mut result {
            if !error.is_nonconsuming_would_block() && !error.is_nonconsuming_interrupted() {
                error.record_shutdown_failure(self.shutdown_retaining_failure());
            }
        }
        result
    }

    fn shutdown_retaining_failure(&mut self) -> Option<std::io::Error> {
        let failure = self.fd.as_ref().and_then(|fd|
            rustix::net::shutdown(fd, rustix::net::Shutdown::Both).err().map(std::io::Error::from));
        self.fd.take();
        failure
    }

    /// Receives one record carrying either no descriptor or exactly one descriptor.
    ///
    /// This profile lets a higher-level authenticated envelope select between
    /// ordinary and single-descriptor methods only after the packet has been
    /// consumed. The higher layer must reject any mismatch between the decoded
    /// method and the returned descriptor count before using the descriptor.
    ///
    /// # Errors
    ///
    /// Returns the ordinary bounded-record errors and rejects every descriptor
    /// count other than zero or one.
    pub fn receive_with_optional_descriptor(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, SeqpacketError> {
        if maximum_bytes == 0 {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_descriptor_inner(maximum_bytes, 1, true);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.fd.take();
        }
        result
    }

    /// Receives zero or one descriptor while retaining original failure custody.
    ///
    /// The existing strict engine owns both native samples, partial subjects,
    /// ancillary data and the duplicate endpoint through borrowed validation.
    /// Only a complete success transfers the consumed payload, subject and
    /// descriptor table. The caller still validates the authenticated method's
    /// descriptor roles; this carrier grants no receiving budget or authority.
    ///
    /// # Errors
    ///
    /// Returns the existing owning receive error for invalid bounds, framing,
    /// subject or native failures, including tables containing more than one
    /// descriptor. Screened custody remains resident in that error; forbidden
    /// or uninspected descriptors follow the existing disposal policy. Only an
    /// initial nonconsuming EAGAIN or EINTR preserves the existing retry class.
    pub fn receive_with_optional_descriptor_retaining(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let profile = receive_custody::SubjectProfileV1::Descriptors {
            expected: 1,
            allow_empty: true,
        };
        self.receive_descriptor_retaining_profile(maximum_bytes, profile)
    }

    /// Describes only known storage terms of the retaining optional receive.
    ///
    /// The preview requests one payload byte and the consumed sample requests
    /// at most `maximum_bytes`. Two logical sample owners and the complete
    /// result slot are counted separately from the attempt owner. These terms
    /// exclude allocation capacity and every unpriced cost documented on
    /// [`OptionalDescriptorReceiveFootprintV1`]; they cannot establish fit.
    /// Returns `None` for a zero bound or arithmetic overflow, without I/O.
    #[must_use]
    pub const fn optional_descriptor_receive_footprint_v1(
        maximum_bytes: usize,
    ) -> Option<OptionalDescriptorReceiveFootprintV1> {
        if maximum_bytes == 0 {
            return None;
        }
        let Some(payload_bytes) = maximum_bytes.checked_add(1) else {
            return None;
        };
        let Some(sample_inline_bytes) = std::mem::size_of::<receive_custody::CapturedMessageV1>()
            .checked_mul(2)
        else {
            return None;
        };

        Some(OptionalDescriptorReceiveFootprintV1 {
            payload_bytes,
            attempt_inline_bytes: std::mem::size_of::<receive_custody::ReceiveAttemptV1>(),
            sample_inline_bytes,
            result_inline_bytes: std::mem::size_of::<Result<
                descriptor_subject::ReceivedDescriptorRecord,
                RetainedSeqpacketReceiveErrorV1,
            >>(),
        })
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
        self.bind_received_descriptors_retaining(record)
            .map_err(|(error, _record)| error)
    }

    /// Binds a descriptor record while retaining its complete custody on error.
    ///
    /// The same original-socket validation and fatal-close behavior applies as
    /// in [`Self::bind_received_descriptors`]. No subject or descriptor is
    /// duplicated, and the failed record is never a current connection proof.
    ///
    /// # Errors
    ///
    /// Returns the binding error and original complete received record after
    /// closing this socket if its current binding or record origin is invalid.
    pub fn bind_received_descriptors_retaining<'socket>(
        &'socket mut self,
        record: descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<
        descriptor_subject::ConnectionBoundReceivedDescriptorRecord<'socket>,
        (RecordBindingError, descriptor_subject::ReceivedDescriptorRecord),
    > {
        if let Err(error) = self.require_descriptor_record_origin(&record) {
            self.fd.take();
            return Err((error, record));
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
        self.bind_received_retaining(record)
            .map_err(|(error, _record)| error)
    }

    /// Binds a received record while retaining its complete custody on error.
    ///
    /// This preserves [`Self::bind_received`]'s original-socket checks and
    /// fatal-close behavior. The returned failure record remains historical
    /// data, not writer authentication or a current connection proof.
    ///
    /// # Errors
    ///
    /// Returns the binding error and original received record after closing
    /// this socket if its current binding or record origin is invalid.
    pub fn bind_received_retaining<'socket>(
        &'socket mut self,
        record: ReceivedRecord,
    ) -> Result<ConnectionBoundReceivedRecord<'socket>, (RecordBindingError, ReceivedRecord)> {
        if let Err(error) = self.require_record_origin(&record) {
            self.fd.take();
            return Err((error, record));
        }

        Ok(ConnectionBoundReceivedRecord {
            record,
            peer: &self.peer,
        })
    }

    /// Compares a resident offline record with this original socket by borrow.
    ///
    /// The caller keeps the complete record and subject parked before this
    /// observation. Success establishes only same-socket continuity DATA, not
    /// a syscall writer, executed image, TPM result or protocol authority.
    ///
    /// # Errors
    /// Closes the original socket on the same binding failures as the consuming
    /// adapters. Neither the record nor its subject is moved, cloned or dropped.
    pub fn require_nix_offline_received_original_v5(
        &mut self,
        record: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_received_original(record)
    }

    /// Compares a parked output-registration record with this original socket.
    ///
    /// This observes carrier continuity DATA only. The caller retains the
    /// complete record and independently authenticates its subject and role.
    /// It establishes neither writer identity nor output admission authority.
    ///
    /// # Errors
    /// Closes this socket on its existing binding failures without moving,
    /// cloning or dropping the received record or its subject.
    pub fn require_output_registration_received_original_v1(
        &mut self,
        record: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_received_original(record)
    }

    /// Compares a parked Source settlement record with this original socket.
    ///
    /// This supplies carrier continuity DATA only. The owning caller retains
    /// the record and independently verifies its Storage subject and signer.
    ///
    /// # Errors
    /// Closes the socket on its existing origin failures without moving or
    /// disposing the parked record or subject.
    pub fn require_source_storage_received_original_v5(
        &mut self,
        record: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_received_original(record)
    }

    fn require_received_original(
        &mut self,
        record: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        if let Err(error) = self.require_record_origin(record) {
            self.fd.take();
            return Err(error);
        }
        Ok(())
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
        allow_empty: bool,
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
            allow_empty,
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

#[derive(Clone, Copy)]
enum OriginalSenderDispositionV1 {
    Legacy,
    Retained,
    GuestAncestorHost,
}

impl OriginalSenderDispositionV1 {
    fn end(self, fd: &mut Option<OwnedFd>) {
        match self {
            Self::Legacy => { fd.take(); }
            Self::Retained => {}
            Self::GuestAncestorHost => {
                if let Some(fd) = fd {
                    let _ = rustix::net::shutdown(fd, rustix::net::Shutdown::Both);
                }
            }
        }
    }
}

// A kernel-returned pin outside the calling PID namespace. This deliberately
// has no conversion into PidFd, PidFdInfo or a strict nominated subject.
#[derive(Debug)]
struct AncestorHostRecordPinV1 {
    fd: OwnedFd,
    identity: (u64, u64),
}

/// Retains a selected inherited Host channel without inventing a visible PID.
///
/// PID0, EREMOTE and the original pidfs inode are namespace-local continuity
/// DATA, not ancestry, writer authentication or application authority. Only
/// fixed Guest startup slots can be captured. Sealed provisioning, the approved
/// job and Host-side physical observations remain separate requirements.
#[must_use]
pub struct GuestAncestorHostChannelV1 {
    fd: Option<OwnedFd>,
    peer_pin: Option<OwnedFd>,
    credentials: Option<(u32, u32)>,
    pin: Option<(u64, u64)>,
    binding: Option<ConnectedSocketBinding>,
    attempted: bool,
    closed: bool,
    first_failure: Option<SeqpacketError>,
}

/// Owns a complete record from the same selected inherited Host pin.
///
/// There is no public constructor, descriptor accessor or strict subject. The
/// payload remains DATA until its actual selected consumer verifies the sealed
/// launch tuple and the original, never-renewed deadline.
#[derive(Debug)]
pub struct GuestAncestorHostRecordV1 {
    payload: Vec<u8>,
    pin: AncestorHostRecordPinV1,
    origin: ReceivedSocketOrigin,
}

impl GuestAncestorHostRecordV1 {
    /// Borrows the exact consumed payload without releasing its original pin.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl GuestAncestorHostChannelV1 {
    /// Creates empty resident slots without reading inherited descriptors.
    pub const fn new() -> Self {
        Self {
            fd: None,
            peer_pin: None,
            credentials: None,
            pin: None,
            binding: None,
            attempted: false,
            closed: true,
            first_failure: None,
        }
    }

    /// Captures only original Guest Agent FD3 through the inherited-FD engine.
    ///
    /// # Errors
    /// Retains the first actual duplicate, socket, cookie or kernel-pin failure.
    /// Failed and interrupted capture is permanent for this instance.
    pub fn capture_agent_original(&mut self) -> Result<(), &SeqpacketError> {
        let result = (|| {
            self.begin_capture()?;
            self.fd = Some(crate::inherited_fd::duplicate_inherited_descriptor(3)?);
            self.finish_capture()
        })();
        self.complete_capture(result)
    }

    /// Captures only the already retained fixed Guest report slot.
    ///
    /// # Errors
    /// Retains the first original-holder, duplicate or peer failure. This does
    /// not accept a caller-chosen descriptor or confer a report authority.
    pub fn capture_report_original(
        &mut self,
        original: &crate::inherited_fd::GuestCanaryReportOriginalV1,
    ) -> Result<(), &SeqpacketError> {
        let result = (|| {
            self.begin_capture()?;
            self.fd = Some(crate::inherited_fd::duplicate_descriptor(original.descriptor()?)?);
            self.finish_capture()
        })();
        self.complete_capture(result)
    }

    fn begin_capture(&mut self) -> Result<(), SeqpacketError> {
        if self.attempted {
            self.closed = true;
            return Err(SeqpacketError::Closed);
        }
        self.attempted = true;
        self.closed = true;
        Ok(())
    }

    fn finish_capture(&mut self) -> Result<(), SeqpacketError> {
        let fd = self.fd.as_ref().ok_or(SeqpacketError::Closed)?.as_fd();
        uapi::prepare_seqpacket(fd)?;
        self.binding = Some(ConnectedSocketBinding::capture_peer(fd)?);
        let credentials = uapi::peer_credentials(fd)?;
        self.credentials = Some((credentials.uid, credentials.gid));
        if credentials.pid != 0 {
            return Err(SeqpacketError::PeerIdentity("selected Host peer is not namespace-local PID0"));
        }
        // Park the real kernel return before CLOEXEC, ioctl, stat and polling.
        self.peer_pin = Some(uapi::peer_pidfd(fd)?);
        self.pin = Some(PidFd::require_ancestor_host_original(
            self.peer_pin.as_ref().ok_or(SeqpacketError::Closed)?.as_fd(),
        )?);
        self.require_original_inner()
    }

    fn complete_capture(&mut self, result: Result<(), SeqpacketError>) -> Result<(), &SeqpacketError> {
        match result {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.end_original();
                Err(self.first_failure.get_or_insert(cause))
            }
        }
    }

    fn require_original_inner(&self) -> Result<(), SeqpacketError> {
        let fd = self.fd.as_ref().ok_or(SeqpacketError::Closed)?.as_fd();
        let binding = self.binding.ok_or(SeqpacketError::Closed)?;
        if ConnectedSocketBinding::capture_peer(fd)? != binding {
            return Err(SeqpacketError::PeerIdentity("original ancestor Host socket changed"));
        }
        let credentials = uapi::peer_credentials(fd)?;
        if credentials.pid != 0 || Some((credentials.uid, credentials.gid)) != self.credentials {
            return Err(SeqpacketError::PeerIdentity("original ancestor Host credentials changed"));
        }
        let pin = self.peer_pin.as_ref().ok_or(SeqpacketError::Closed)?;
        if Some(PidFd::require_ancestor_host_original(pin.as_fd())?) != self.pin {
            return Err(SeqpacketError::PeerIdentity("original ancestor Host pidfs pin changed"));
        }
        if ConnectedSocketBinding::capture_peer(fd)? != binding {
            return Err(SeqpacketError::PeerIdentity("original ancestor Host socket changed"));
        }
        Ok(())
    }

    /// Compares two genuinely captured channels' same original kernel peer.
    ///
    /// # Errors
    /// Refuses closed, changed, exited or distinct original pins. This is
    /// continuity DATA; the two endpoint cookies need not be equal.
    pub fn require_same_host_original(&mut self, other: &mut Self) -> Result<(), SeqpacketError> {
        if self.closed || other.closed {
            return Err(SeqpacketError::Closed);
        }
        self.closed = true;
        other.closed = true;
        self.require_original_inner()?;
        other.require_original_inner()?;
        if self.credentials != other.credentials || self.pin != other.pin {
            return Err(SeqpacketError::PeerIdentity("selected channels name different original Host pins"));
        }
        self.closed = false;
        other.closed = false;
        Ok(())
    }

    /// Receives one bounded record with retained lower failure custody.
    ///
    /// # Errors
    /// Only an initial nonconsuming EAGAIN/EINTR can retry. Every other failure
    /// permanently ends this same socket before any retained originals drop.
    pub fn receive_retaining(&mut self, maximum: usize) -> Result<GuestAncestorHostRecordV1, RetainedSeqpacketReceiveErrorV1> {
        if self.closed {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed));
        }
        self.closed = true;
        let result = (|| {
            self.require_original_inner().map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
            if maximum == 0 {
                return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum));
            }
            let binding = self.binding.ok_or_else(|| RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed))?;
            let fd = self.fd.as_ref().ok_or_else(|| RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed))?.as_fd();
            let attempt = receive_custody::ReceiveAttemptV1::capture(fd, binding.socket_cookie())?;
            let profile = receive_custody::SubjectProfileV1::AncestorHost {
                credentials: self.credentials.ok_or_else(|| RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed))?,
                pin: self.pin.ok_or_else(|| RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed))?,
            };
            let mut attempt = receive_custody::receive_packet(attempt, maximum, profile)?;
            if let Err(cause) = self.require_original_inner() {
                return Err(attempt.reject(cause));
            }
            let message = &mut attempt.messages[1];
            let Some(pin) = message.ancestor.take() else {
                return Err(attempt.reject(SeqpacketError::Ancillary("missing ancestor Host pin")));
            };
            let record = GuestAncestorHostRecordV1 {
                payload: std::mem::take(&mut message.payload),
                pin,
                origin: binding.received_origin(),
            };
            attempt.disarm();
            Ok(record)
        })();
        match result {
            Ok(record) => {
                self.closed = false;
                Ok(record)
            }
            Err(mut cause) => {
                if cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted() {
                    self.closed = false;
                } else {
                    cause.record_shutdown_failure(self.end_original());
                }
                Err(cause)
            }
        }
    }

    /// Requires a complete record's same socket, original pin and liveness.
    ///
    /// # Errors
    /// Permanently fences a changed origin, dead pin or failed observation.
    pub fn require_record_original(&mut self, record: &GuestAncestorHostRecordV1) -> Result<(), SeqpacketError> {
        if self.closed {
            return Err(SeqpacketError::Closed);
        }
        self.closed = true;
        self.require_original_inner()?;
        let binding = self.binding.ok_or(SeqpacketError::Closed)?;
        record.origin.require_binding(binding)
            .map_err(|_| SeqpacketError::PeerIdentity("ancestor record socket origin changed"))?;
        if Some(record.pin.identity) != self.pin
            || PidFd::require_ancestor_host_original(record.pin.fd.as_fd())? != record.pin.identity
        {
            return Err(SeqpacketError::PeerIdentity("ancestor record pin changed"));
        }
        self.require_original_inner()?;
        self.closed = false;
        Ok(())
    }

    /// Sends a complete record on this selected original endpoint.
    ///
    /// # Errors
    /// Returns the existing atomic sender's errors, without retrying a consumed
    /// or partial send. A fatal error permanently fences this owner.
    pub fn send(&mut self, payload: &[u8]) -> Result<(), SeqpacketError> {
        self.send_selected(payload, None)
    }

    /// Sends the fixed first original-child report without exposing its FDs.
    ///
    /// This mechanically donates the actual pidfd/image/maps/stat/status from
    /// the captured local-child owner. It authenticates no job or image; the
    /// genuine bootstrap must bind the supplied original report header.
    ///
    /// # Errors
    /// Refuses wrong order, unavailable originals or native sender failure.
    /// Only nonconsuming backpressure/interruption may retry the same stage;
    /// fatal or post-send failure fences the same original-child owner.
    pub fn send_host_canary_child_first_v1(
        &mut self,
        originals: &mut crate::pidfd::HostCanaryLocalChildOriginalsV1,
        original_header: &[u8; 176],
    ) -> Result<(), SeqpacketError> {
        self.send_host_canary_child_stage(originals, original_header, 0)
    }

    /// Sends the fixed second context/user/mount/network/pid namespace report.
    ///
    /// # Errors
    /// Preserves the first report's ordering, custody and retry constraints;
    /// no additional child, namespace, FD role or header length is accepted.
    pub fn send_host_canary_child_second_v1(
        &mut self,
        originals: &mut crate::pidfd::HostCanaryLocalChildOriginalsV1,
        original_header: &[u8; 176],
    ) -> Result<(), SeqpacketError> {
        self.send_host_canary_child_stage(originals, original_header, 1)
    }

    fn send_host_canary_child_stage(
        &mut self,
        originals: &mut crate::pidfd::HostCanaryLocalChildOriginalsV1,
        original_header: &[u8; 176],
        stage: u8,
    ) -> Result<(), SeqpacketError> {
        originals.require_report_stage(stage)?;
        let mut header = *original_header;
        let kind = if stage == 0 { 7_u16 } else { 8_u16 };
        header[10..12].copy_from_slice(&kind.to_be_bytes());
        header[12..16].copy_from_slice(&176_u32.to_be_bytes());
        header[168..176].copy_from_slice(&(originals.local_child_pid()? as u64).to_be_bytes());

        let result = {
            let descriptors = if stage == 0 {
                originals.first_report_descriptors()?
            } else {
                originals.second_report_descriptors()?
            };
            self.send_with_descriptors(&header, &descriptors)
        };
        match result {
            Ok(()) => {
                originals.record_sent_stage(stage);
                originals.recheck_original()?;
                Ok(())
            }
            Err(cause @ (SeqpacketError::WouldBlock | SeqpacketError::Interrupted)) => Err(cause),
            Err(cause) => {
                originals.fence();
                Err(cause)
            }
        }
    }

    /// Donates exactly one to five real descriptors on this original endpoint.
    ///
    /// # Errors
    /// Preserves the existing sender's descriptor bounds, flags and failures.
    pub fn send_with_descriptors(&mut self, payload: &[u8], descriptors: &[BorrowedFd<'_>]) -> Result<(), SeqpacketError> {
        self.send_selected(payload, Some(descriptors))
    }

    fn send_selected(&mut self, payload: &[u8], descriptors: Option<&[BorrowedFd<'_>]>) -> Result<(), SeqpacketError> {
        if self.closed {
            return Err(SeqpacketError::Closed);
        }
        self.closed = true;
        self.require_original_inner()?;
        let result = match descriptors {
            Some(descriptors) => SeqpacketSocket::send_original_with_descriptors(&mut self.fd, payload, descriptors, OriginalSenderDispositionV1::GuestAncestorHost),
            None => SeqpacketSocket::send_original(&mut self.fd, payload, OriginalSenderDispositionV1::GuestAncestorHost),
        };
        if matches!(&result, Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)) {
            self.closed = false;
            return result;
        }
        result?;
        self.require_original_inner()?;
        self.closed = false;
        Ok(())
    }

    fn end_original(&mut self) -> Option<std::io::Error> {
        self.closed = true;
        self.fd.as_ref().and_then(|fd|
            rustix::net::shutdown(fd, rustix::net::Shutdown::Both).err().map(std::io::Error::from))
    }
}

impl Default for GuestAncestorHostChannelV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for GuestAncestorHostChannelV1 {
    fn drop(&mut self) {
        self.end_original();
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

    /// Requires this retained socket object's local filesystem address.
    ///
    /// # Errors
    ///
    /// Rejects a replaced socket, noncanonical path, or mismatched address.
    pub fn require_local_filesystem_path(
        &self,
        fd: BorrowedFd<'_>,
        expected: &Path,
    ) -> Result<(), SeqpacketError> {
        self.require_filesystem_path(fd, expected, false)
    }

    /// Requires this retained socket object's connected peer filesystem address.
    ///
    /// # Errors
    ///
    /// Rejects a replaced socket, noncanonical path, or mismatched address.
    pub fn require_peer_filesystem_path(
        &self,
        fd: BorrowedFd<'_>,
        expected: &Path,
    ) -> Result<(), SeqpacketError> {
        self.require_filesystem_path(fd, expected, true)
    }

    fn require_filesystem_path(
        &self,
        fd: BorrowedFd<'_>,
        expected: &Path,
        peer: bool,
    ) -> Result<(), SeqpacketError> {
        let expected = expected.as_os_str().as_bytes();
        if expected.len() <= 1
            || expected.contains(&0)
            || !expected.starts_with(b"/")
            || !expected[1..]
                .split(|byte| *byte == b'/')
                .all(|component| !component.is_empty() && !matches!(component, b"." | b".."))
        {
            return Err(SeqpacketError::PeerIdentity(
                "expected Unix filesystem path is noncanonical",
            ));
        }
        if ConnectedSocketBinding::capture_peer(fd)? != self.binding {
            return Err(SeqpacketError::PeerIdentity("socket object changed"));
        }
        let observed = if peer {
            uapi::unix_socket_peer_filesystem_path(fd)?
        } else {
            uapi::unix_socket_local_filesystem_path(fd)?
        };
        if observed != expected || ConnectedSocketBinding::capture_peer(fd)? != self.binding {
            return Err(SeqpacketError::PeerIdentity(
                "Unix filesystem address differs from retained socket",
            ));
        }
        Ok(())
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

pub(crate) fn map_kernel_error(error: Error) -> SeqpacketError {
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

pub(crate) fn validate_record_subject(
    ancillary: Vec<RawAncillary>,
) -> Result<KernelAuthorizedRecordSubject, SeqpacketError> {
    receive_custody::validate_legacy(ancillary, receive_custody::SubjectProfileV1::Ordinary)
        .map(|(subject, _, _)| subject)
}

fn checked_pid(pid: i32) -> Option<NonZeroU32> {
    u32::try_from(pid).ok().and_then(NonZeroU32::new)
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn retained_send_refusal_keeps_the_typed_native_classification() {
        // Pure error DATA; no socket, descriptor or peer is fabricated.
        let failure = RetainedSeqpacketSendErrorV1 {
            cause: SeqpacketError::PartialSend { expected: 4, actual: 3 },
            descriptor: None,
        };

        assert!(matches!(failure.cause(), SeqpacketError::PartialSend { expected: 4, actual: 3 }));
        assert!(!failure.retains_descriptor());
        assert!(std::error::Error::source(&failure)
            .and_then(|cause| cause.downcast_ref::<SeqpacketError>()).is_some());
    }

    #[test]
    fn closed_send_refusal_does_not_claim_descriptor_custody() {
        let failure = RetainedSeqpacketSendErrorV1 {
            cause: SeqpacketError::Closed,
            descriptor: None,
        };

        assert!(matches!(failure.cause(), SeqpacketError::Closed));
        assert!(!failure.retains_descriptor());
    }

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
    fn retaining_path_refusal_has_original_typed_cause_and_no_socket() {
        for path in [
            Path::new("relative.sock"),
            Path::new("/tmp/../control.sock"),
        ] {
            let failure = SeqpacketSocket::connect_retaining(path).unwrap_err();

            assert!(matches!(
                failure.cause(),
                SeqpacketError::Kernel(Error::InvalidInput {
                    field: "sequenced-packet connection path",
                    ..
                })
            ));
            assert!(!failure.retains_descriptor());
            assert!(!failure.shutdown_attempted());
            assert!(failure.shutdown_failure().is_none());
        }
    }

    #[test]
    fn retaining_oversized_path_fails_before_socket_creation() {
        let path = std::path::PathBuf::from(format!("/{}", "x".repeat(512)));
        let failure = SeqpacketSocket::connect_retaining(&path).unwrap_err();

        assert!(matches!(
            failure.cause(),
            SeqpacketError::Kernel(Error::InvalidInput {
                field: "sequenced-packet connection path",
                ..
            })
        ));
        assert!(!failure.retains_descriptor());
        assert!(!failure.shutdown_attempted());
        assert!(failure.shutdown_failure().is_none());
    }

    #[test]
    fn retaining_precreation_failure_preserves_the_same_error_source() {
        let failure = RetainedSeqpacketAdmissionErrorV1::before_creation(
            SeqpacketError::Kernel(Error::invalid("original admission", "pure refusal")),
        );
        let source = std::error::Error::source(&failure)
            .unwrap()
            .downcast_ref::<SeqpacketError>()
            .unwrap();

        assert!(std::ptr::eq(source, failure.cause()));
        assert!(!failure.retains_descriptor());
        assert!(!failure.shutdown_attempted());
        assert!(failure.shutdown_failure().is_none());
    }

    #[test]
    fn retaining_display_does_not_claim_precreation_descriptor_custody() {
        let failure = RetainedSeqpacketAdmissionErrorV1::before_creation(
            SeqpacketError::Closed,
        );

        assert_eq!(
            failure.to_string(),
            "original socket admission failed; any acquired custody is retained",
        );
        assert!(!failure.retains_descriptor());
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
    fn retaining_foreign_record_returns_exact_payload_and_subject_after_fatal_close() {
        let (mut sender, mut receiver) = pair();
        let (_other_sender, mut other_receiver) = pair();
        receiver.enable_record_subjects().expect("enable subjects");
        sender.send(b"retained foreign body").expect("send body");
        let record = receiver.receive(64).expect("receive original body");
        let original_subject = record.subject().initial_info();

        let (error, retained) = other_receiver
            .bind_received_retaining(record)
            .expect_err("reject foreign origin while retaining record");

        assert_eq!(error.category(), RecordBindingErrorCategory::OriginMismatch);
        assert_eq!(retained.payload(), b"retained foreign body");
        assert_eq!(retained.subject().initial_info(), original_subject);
        assert!(matches!(other_receiver.as_fd(), Err(SeqpacketError::Closed)));
    }

    #[test]
    fn retaining_foreign_descriptor_record_keeps_exact_received_fd_after_fatal_close() {
        let (mut sender, mut receiver) = pair();
        let (_other_sender, mut other_receiver) = pair();
        receiver.enable_record_subjects().expect("enable subjects");
        let file = tempfile::tempfile().expect("create private test descriptor");
        let expected = rustix::fs::fstat(file.as_fd()).expect("observe original descriptor");
        sender.send_with_descriptors(b"retained descriptor body", &[file.as_fd()])
            .expect("send descriptor body");
        let record = receiver.receive_with_descriptors(64, 1).expect("receive descriptor body");
        let original_subject = record.subject().initial_info();

        let (error, retained) = other_receiver
            .bind_received_descriptors_retaining(record)
            .expect_err("reject foreign descriptor origin while retaining record");

        assert_eq!(error.category(), RecordBindingErrorCategory::OriginMismatch);
        assert_eq!(retained.payload(), b"retained descriptor body");
        assert_eq!(retained.subject().initial_info(), original_subject);
        assert_eq!(retained.descriptors().len(), 1);
        let observed = rustix::fs::fstat(retained.descriptors()[0].as_fd())
            .expect("original received descriptor remains open");
        assert_eq!((observed.st_dev, observed.st_ino), (expected.st_dev, expected.st_ino));
        assert!(matches!(other_receiver.as_fd(), Err(SeqpacketError::Closed)));
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
    fn optional_descriptor_receive_admits_only_zero_or_one_right() {
        let (mut ordinary_sender, mut ordinary_receiver) = pair();
        ordinary_receiver
            .enable_record_subjects()
            .expect("enable ordinary record subjects");
        ordinary_sender
            .send(b"ordinary")
            .expect("send ordinary record");

        let ordinary = ordinary_receiver
            .receive_with_optional_descriptor(64)
            .expect("receive descriptor-free record");
        assert_eq!(ordinary.payload(), b"ordinary");
        assert!(ordinary.descriptors().is_empty());

        let (mut descriptor_sender, mut descriptor_receiver) = pair();
        descriptor_receiver
            .enable_record_subjects()
            .expect("enable descriptor record subjects");
        let file = std::fs::File::open("/dev/null").expect("open test descriptor");
        descriptor_sender
            .send_with_descriptors(b"publication", &[file.as_fd()])
            .expect("send single descriptor");

        let publication = descriptor_receiver
            .receive_with_optional_descriptor(64)
            .expect("receive single-descriptor record");
        assert_eq!(publication.payload(), b"publication");
        assert_eq!(publication.descriptors().len(), 1);

        let (mut excess_sender, mut excess_receiver) = pair();
        excess_receiver
            .enable_record_subjects()
            .expect("enable excess record subjects");
        excess_sender
            .send_with_descriptors(b"excess", &[file.as_fd(), file.as_fd()])
            .expect("send excess descriptors");

        assert!(matches!(
            excess_receiver.receive_with_optional_descriptor(64),
            Err(SeqpacketError::Ancillary(
                "inexact SCM_RIGHTS descriptor table"
            ))
        ));
        assert!(matches!(
            excess_receiver.as_fd(),
            Err(SeqpacketError::Closed)
        ));
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
