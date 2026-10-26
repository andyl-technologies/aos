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
//!
//! Network's closed child-origin carrier separately admits exactly nine rights.
//! Its later credentials-only PID1 replies borrow that initial authenticated
//! subject and the same channel; they never construct a fresh record subject.

use std::mem::MaybeUninit;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

use aos_linux_descriptors::Error;
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdInfo;
use crate::uapi::{self, RawAncillary};

mod listener;
pub mod initial_approval;
pub use listener::{
    ListenerAdmissionFailureRefV1, RecordSubjectListener,
    RecordSubjectListenerAdmissionAttemptV1,
};

mod pair;
pub use pair::RecordSubjectSeqpacketPairOriginalV2;

mod zero_rights;
use zero_rights::ZeroRightsNativeV1;
pub use zero_rights::SeqpacketRightsRestrictionOriginalV6;

mod connection_liveness;
pub use connection_liveness::SeqpacketShutdownOriginalV4;
pub use connection_liveness::SeqpacketOwnedShutdownOriginalV1;
pub use connection_liveness::SeqpacketSendAfterOriginalV1;
mod socket_binding;
use socket_binding::{ConnectedSocketBinding, ReceivedSocketOrigin};

mod network_worker;
mod network_worker_completion;
pub use network_worker::{NetworkWorkerNativeCutoffV4, NetworkWorkerRecordKindV4};

mod network_pid1_reply;
pub use network_pid1_reply::{
    NetworkPid1ReplyAffinityOriginalV2,
    NetworkPid1ReplyChannelV2, NetworkPid1ReplyOriginalV2,
    NetworkPid1ReplyProfileOriginalV2, NetworkPid1RequestOriginalV2,
};

pub mod bounded;
pub mod capture_stop;
pub mod descriptor_subject;

mod storage_session;
pub use storage_session::{
    LocalOwnershipSeqpacketEndAttemptV1, StorageSeqpacketEndAttemptV1, StorageSeqpacketSendAttemptV1, StorageSeqpacketSessionOriginV1,
};

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
    zero_rights: Option<ZeroRightsNativeV1>,
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
    peer_capture: Option<PeerCaptureAttemptV1>,
    armed: bool,
    ended: bool,
    shutdown_failure: Option<std::io::Error>,
}

impl PendingSocketAdmissionV1 {
    pub(super) fn new(fd: OwnedFd) -> Self {
        Self {
            fd: Some(fd),
            peer: None,
            peer_capture: None,
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
        aos_linux_descriptors::native::require_seqpacket_identity(self.borrow_fd()?).map_err(map_kernel_error)
    }

    pub(super) fn prepare_accepted_descriptor(&self) -> Result<(), SeqpacketError> {
        aos_linux_descriptors::native::ensure_cloexec(self.borrow_fd()?).map_err(map_kernel_error)
    }

    pub(super) fn admit_peer(&mut self) -> Result<(), SeqpacketError> {
        self.admit_peer_observed_v1(false)
    }

    pub(super) fn admit_peer_retaining_raw_v1(&mut self) -> Result<(), SeqpacketError> {
        self.admit_peer_observed_v1(true)
    }

    fn admit_peer_observed_v1(&mut self, retain_raw: bool) -> Result<(), SeqpacketError> {
        uapi::prepare_seqpacket(self.borrow_fd()?)?;
        self.peer_capture = Some(PeerCaptureAttemptV1::default());
        let fd = self.fd.as_ref().ok_or(SeqpacketError::Closed)?.as_fd();
        let capture = self.peer_capture.as_mut().ok_or(SeqpacketError::Closed)?;
        capture.capture_observed_v1(fd, retain_raw)?;
        self.peer = Some(capture.take_completed()?);
        Ok(())
    }

    pub(super) fn enable_subjects(&self) -> Result<(), SeqpacketError> {
        aos_linux_descriptors::native::enable_seqpacket_identity(self.borrow_fd()?).map_err(SeqpacketError::from)
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
    connect_pending_with_rights(path, false)
}

fn connect_pending_with_rights(
    path: &Path,
    zero_rights: bool,
) -> Result<PendingSocketAdmissionV1, RetainedSeqpacketAdmissionErrorV1> {
    connect_pending_with_gate_v4::<std::convert::Infallible>(path, zero_rights, None).0
}

pub(super) fn connect_pending_worker_guarded_v4<E>(
    path: &Path,
    before_native: &mut impl FnMut() -> std::result::Result<(), E>,
) -> (
    Result<PendingSocketAdmissionV1, RetainedSeqpacketAdmissionErrorV1>,
    Option<E>,
) {
    connect_pending_with_gate_v4(path, false, Some(before_native))
}

fn connect_pending_with_gate_v4<E>(
    path: &Path,
    zero_rights: bool,
    mut before_native: Option<&mut dyn FnMut() -> std::result::Result<(), E>>,
) -> (
    Result<PendingSocketAdmissionV1, RetainedSeqpacketAdmissionErrorV1>,
    Option<E>,
) {
    let mut gate_failure = None;
    let admission = (|| {
        let bytes = uapi::validate_seqpacket_connection_path(path)
            .map_err(SeqpacketError::from)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        let fd = uapi::unconnected_seqpacket_before_flags()
            .map_err(SeqpacketError::from)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        let pending = PendingSocketAdmissionV1::new(fd);

        let connected = (|| {
            aos_linux_descriptors::native::ensure_cloexec(pending.borrow_fd()?)?;
            if zero_rights {
                uapi::set_seqpacket_passrights(pending.borrow_fd()?, false)?;
            }
            if let Some(gate) = before_native.as_mut() {
                let (native, refused) =
                    uapi::connect_seqpacket_borrowed_guarded_v4(pending.borrow_fd()?, bytes, gate);
                gate_failure = refused;
                native?;
            } else {
                uapi::connect_seqpacket_borrowed(pending.borrow_fd()?, bytes)?;
            }
            Ok::<_, SeqpacketError>(())
        })();
        if let Err(source) = connected {
            return Err(pending.fail(source));
        }
        Ok(pending)
    })();
    (admission, gate_failure)
}

// Concrete socket facades select only their own actual returned layout.
// All pending/raw/peer native operands and the two FD slots are shared.
fn raw_admission_obligations_v3<Socket>() -> Option<(usize, usize)> {
    let carriers = std::mem::size_of::<PendingSocketAdmissionV1>()
        .checked_add(std::mem::size_of::<Result<Socket, RetainedSeqpacketAdmissionErrorV1>>())?
        .checked_add(std::mem::size_of::<Result<PidFdInfo, SeqpacketError>>())?
        .checked_add(std::mem::size_of::<libc::ucred>())?
        .checked_mul(3)?;
    let bytes = carriers.checked_add(2 * std::mem::size_of::<libc::sockaddr_un>())?
        .checked_add(2 * 256)?;
    Some((bytes, 2))
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

    /// Connects the fixed Storage worker while retaining raw peer-adoption input.
    ///
    /// Uses the same path, creation, option, connect and peer engine. The whole
    /// SO_PEERPIDFD remains owned if its typed admission fails. This mechanical
    /// carrier neither authenticates a worker role nor grants financial entry.
    ///
    /// # Errors
    /// Retains the original socket/raw peer and first native cause, with
    /// independent shutdown debt, without descriptor extraction or retry.
    pub fn connect_storage_worker_retaining_v3(path: &Path) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::require_connection_path(path)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        Self::from_pending_raw_peer_retaining_v1(connect_pending_seqpacket(path)?)
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
        let (receiver, endpoint) = aos_linux_descriptors::native::seqpacket_pair()?;
        aos_linux_descriptors::native::enable_seqpacket_identity(receiver.as_fd())?;
        aos_linux_descriptors::native::enable_seqpacket_identity(endpoint.as_fd())?;
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
            zero_rights: None,
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

    /// Adopts the fixed Storage worker socket while retaining raw peer input.
    ///
    /// This runs the same pending-socket admission checks. It retains the
    /// original SO_PEERPIDFD candidate if pidfd adoption fails; no descriptor
    /// or retry capability can be recovered from its negative result.
    ///
    /// # Errors
    /// Keeps rejected socket, raw peer descriptor and exact native causes.
    pub fn from_owned_storage_worker_retaining_v3(
        fd: OwnedFd,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::from_pending_raw_peer_retaining_v1(PendingSocketAdmissionV1::new(fd))
    }

    /// Prices the fixed worker's raw incoming socket-admission carrier.
    ///
    /// Uses the same pending/raw peer arithmetic with this actual socket and
    /// result layout. Cgroup/role checks and record reservoirs remain separate.
    #[must_use]
    pub fn storage_worker_admission_obligations_v3() -> Option<(usize, usize)> {
        raw_admission_obligations_v3::<Self>()
    }

    pub(super) fn from_pending_retaining(
        pending: PendingSocketAdmissionV1,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::from_pending_observed_v1(pending, false)
    }

    pub(super) fn from_pending_raw_peer_retaining_v1(
        pending: PendingSocketAdmissionV1,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::from_pending_observed_v1(pending, true)
    }

    fn from_pending_observed_v1(
        mut pending: PendingSocketAdmissionV1,
        retain_raw: bool,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        let admitted = if retain_raw { pending.admit_peer_retaining_raw_v1() }
            else { pending.admit_peer() };
        if let Err(source) = admitted {
            return Err(pending.fail(source));
        }
        let (fd, peer) = pending.finish()?;
        Ok(Self {
            fd: Some(fd),
            peer,
            retained_send_flight: None,
            zero_rights: None,
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
        match aos_linux_descriptors::native::enable_seqpacket_identity(self.borrow_fd()?) {
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
        let observed = storage_session::observe_original_send_v1(
            fd.as_ref().map(AsFd::as_fd), payload,
        );
        let result = observed.into_legacy_result();
        if matches!(&result, Err(SeqpacketError::PartialSend { .. })) {
            disposition.end(fd);
        }
        result
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
        let (observed, _) = storage_session::observe_original_descriptor_send_v4::<std::convert::Infallible>(
            fd.as_ref().map(AsFd::as_fd), payload, descriptors, None);
        let result = observed.into_legacy_result();
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            disposition.end(fd);
        }
        result
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
        self.receive_ordinary_retaining_with_control(maximum_bytes, uapi::ReceiveControlProfileV1::Standard)
    }

    /// Receives a zero-rights Host execution response through the same engine.
    ///
    /// Prepare, Accept, Apply and Query responses carry only kernel credentials
    /// and their subject pidfd; Apply's sealed specification FD is request-only.
    /// This selects the existing aligned authenticated control recipe without
    /// changing its ordinary subject checks or payload limit. It creates no
    /// Host role, financial original, connection or success proof.
    ///
    /// # Errors
    /// Retains malformed/truncated control, unexpected rights, subject or native
    /// failure. Only initial nonconsuming EAGAIN/EINTR permits the existing retry.
    pub fn receive_host_execution_response_retaining_v1(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_control(
            maximum_bytes, uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
        )
    }

    /// Receives a Storage preparation record through the ordinary strict engine.
    ///
    /// Credentials and a correlated kernel pidfd fit the fixed 80-byte control
    /// interval. SCM_RIGHTS and SCM_SECURITY remain forbidden by the ordinary
    /// profile. Excess ancillary data retains the original truncation or native
    /// failure. The caller supplies its existing protocol payload bound and
    /// independently admits this receive before observation.
    ///
    /// # Errors
    /// Retains complete native, ancillary, framing and subject failures. Only
    /// an initial nonconsuming EAGAIN or EINTR preserves retry eligibility.
    pub fn receive_storage_preparation_retaining_v1(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_control(
            maximum_bytes, uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
        )
    }

    pub(super) fn receive_zfs_worker_retaining_v1(
        &mut self,
        maximum: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_control(
            maximum, uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
        )
    }

    pub(super) fn zfs_worker_receive_obligations_v1(maximum: usize) -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(maximum)
    }


    /// Receives a local Ownership record through the same ordinary strict engine.
    ///
    /// The fixed 80-byte interval covers credentials and correlated pidfd;
    /// ordinary SCM_RIGHTS and SCM_SECURITY refusal is unchanged. The payload
    /// maximum is protocol DATA; no endpoint, process or funding is granted.
    ///
    /// # Errors
    /// Retains original native, subject and truncation failures. Only proven
    /// initial nonconsuming EAGAIN or EINTR permits another observation.
    pub fn receive_local_ownership_retaining_v1(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_control(
            maximum_bytes, uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
        )
    }

    fn receive_ordinary_retaining_with_control(
        &mut self,
        maximum_bytes: usize,
        control: uapi::ReceiveControlProfileV1,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_disposition(
            maximum_bytes, control, receive_custody::ReceiveFailureDispositionV4::Existing,
        )
    }

    /// Receives the original Guest monitor's zero-rights control or terminal query.
    ///
    /// This selects the same authenticated80 native recipe and preserves the
    /// original socket when its first custody duplication fails. It grants no
    /// monitor, execution, financial or control permission.
    ///
    /// # Errors
    /// Retains the actual native, record-subject, framing and ancillary prefix.
    pub fn receive_guest_monitor_request_retaining_v1(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_disposition(
            maximum_bytes, uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal,
        )
    }

    /// Captures the fixed original monitor registration with exactly one right.
    ///
    /// This is the same retained80 native/ancillary engine. It authenticates no
    /// monitor, child or role and grants no receiving budget.
    ///
    /// # Errors
    /// Preserves the whole actual native/subject/table prefix and the original
    /// socket on an initial custody-duplication failure.
    pub fn receive_guest_monitor_registration_retaining_v2(&mut self, maximum: usize)
        -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.receive_descriptor_with_disposition(maximum,
            receive_custody::SubjectProfileV1::Descriptors { expected: 1, allow_empty: false },
            uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal)
    }

    /// Receives the original relay pidfd or a descriptor-free pre-relay control.
    ///
    /// This fixed one-or-zero table shares the retained80 engine. The caller
    /// independently validates the measured root monitor and exact child.
    ///
    /// # Errors
    /// Retains every reached native, subject, descriptor and original socket.
    pub fn receive_guest_monitor_relay_or_control_retaining_v2(&mut self, maximum: usize)
        -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.receive_descriptor_with_disposition(maximum,
            receive_custody::SubjectProfileV1::Descriptors { expected: 1, allow_empty: true },
            uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal)
    }

    /// Receives root control DATA only under this socket's completed restriction.
    ///
    /// # Errors
    /// Refuses a missing, stale or foreign native mode proof before receiving,
    /// or retains the actual fixed80 receive failure. Application checks remain
    /// independently necessary after this mechanical receive.
    pub fn receive_registered_guest_monitor_control_retaining_v2(&mut self, maximum: usize,
        restriction: &SeqpacketRightsRestrictionOriginalV6)
        -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.require_rights_restriction_current_v6(restriction)
            .map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
        self.receive_guest_monitor_relay_or_control_retaining_v2(maximum)
    }

    /// Receives a terminal query only under the same completed restriction.
    ///
    /// # Errors
    /// Refuses stale or foreign mode custody before entry and retains every
    /// reached native/subject prefix of the unchanged fixed80 parser.
    pub fn receive_registered_guest_monitor_request_retaining_v2(&mut self, maximum: usize,
        restriction: &SeqpacketRightsRestrictionOriginalV6)
        -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.require_rights_restriction_current_v6(restriction)
            .map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
        self.receive_guest_monitor_request_retaining_v1(maximum)
    }

    /// Supplies the registered receive's native peak as passive cost DATA.
    ///
    /// The actual named receivers require a completed queue/mode proof before
    /// IO. The full80 parser and payload allocation remain byte provisioned.
    /// Returns `None` for invalid lengths or arithmetic overflow.
    #[must_use]
    pub fn registered_guest_monitor_receive_obligations_v2(maximum: usize) -> Option<(usize, usize)> {
        Self::closed_zero_rights_receive_obligations_v1(maximum)
    }

    /// Receives active Guest controls under the same completed rights restriction.
    ///
    /// This mechanical port grants no operation permission. The Agent still
    /// authenticates the original session, sequence, operation and runtime.
    ///
    /// # Errors
    /// Refuses stale or foreign mode custody before receiving, or retains the
    /// actual native/subject prefix of the unchanged authenticated80 engine.
    pub fn receive_agent_active_control_retaining_v2(&mut self, maximum: usize,
        restriction: &SeqpacketRightsRestrictionOriginalV6)
        -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.require_rights_restriction_current_v6(restriction)
            .map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
        self.receive_guest_monitor_request_retaining_v1(maximum)
    }

    /// Supplies the active Agent receiver's complete fixed80 native plane.
    ///
    /// This is passive DATA. The actual receiver independently requires its
    /// completed same-socket restriction before every native sample. Returns
    /// `None` for invalid lengths or checked arithmetic overflow.
    #[must_use]
    pub fn agent_active_control_receive_obligations_v2(maximum: usize) -> Option<(usize, usize)> {
        Self::closed_zero_rights_receive_obligations_v1(maximum)
    }

    /// Receives the selected normal Guest handshake through retained80 custody.
    ///
    /// Ordinary rights are forbidden by the record grammar, while the native
    /// hostile-prefix bound remains19 because Authorize still needs rights.
    /// No irreversible restriction or application permission is introduced.
    ///
    /// # Errors
    /// Retains the actual packet/native failure and original endpoint custody.
    pub fn receive_guest_initial_handshake_retaining_v2(&mut self, maximum: usize)
        -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.receive_guest_monitor_request_retaining_v1(maximum)
    }

    /// Supplies the selected Guest handshake's full native80 plane as cost DATA.
    ///
    /// Returns `None` for invalid lengths or checked arithmetic overflow.
    #[must_use]
    pub fn guest_initial_handshake_receive_obligations_v2(maximum: usize) -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(maximum)
    }

    /// Compares the actual registration's same-socket origin while retaining cookie IO.
    ///
    /// This DATA check neither authenticates its subject nor admits its child.
    ///
    /// # Errors
    /// Returns a binding refusal with the actual kernel cookie Result retained
    /// in the caller's same original slot. The socket and packet stay owned.
    pub fn require_guest_monitor_registration_origin_retaining_v2(&self,
        record: &descriptor_subject::ReceivedDescriptorRecord,
        native: &mut Option<Result<u64, aos_linux_descriptors::Error>>,
    ) -> Result<(), RecordBindingError> {
        let fd = self.fd.as_ref().map(AsFd::as_fd).ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current_with_originals_v1(fd, Some(native))?;
        record.require_origin(self.peer.binding)
    }

    /// Prices the actual fixed80 one-right registration and hostile native prefix.
    ///
    /// Returns `None` for invalid lengths or checked arithmetic overflow.
    #[must_use]
    pub fn guest_monitor_registration_obligations_v2(maximum: usize) -> Option<(usize, usize)> {
        let (bytes, ordinary_files) = Self::ordinary_authenticated_receive_obligations_v1(maximum)?;
        let bytes = bytes.checked_add(std::mem::size_of::<Result<descriptor_subject::ReceivedDescriptorRecord,
            RetainedSeqpacketReceiveErrorV1>>())?;
        // The successful preview can retain its one ordinary right in addition
        // to its subject pin before the consumed hostile native sample.
        Some((bytes, ordinary_files.checked_add(1)?))
    }

    fn receive_ordinary_retaining_with_disposition(
        &mut self,
        maximum_bytes: usize,
        control: uapi::ReceiveControlProfileV1,
        disposition: receive_custody::ReceiveFailureDispositionV4,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        let mut attempt = self.receive_retaining_with_disposition(
            maximum_bytes, receive_custody::SubjectProfileV1::Ordinary, control, disposition,
        )?;
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

    /// Receives a fixed normal startup report using its five-right schema.
    ///
    /// The same strict receiver retains both native samples and partial rights.
    /// This closes only ancillary geometry; the actual Host Launch must bind
    /// the report kind, subject, inherited carrier and protected request.
    ///
    /// # Errors
    /// Retains native, truncation, subject or table failures. Only the fixed
    /// one-, three- and five-right report shapes are accepted.
    pub fn receive_component_startup_report_retaining_v2(
        &mut self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !matches!(expected_descriptors, 1 | 3 | 5) {
            // No native receive was entered. Keep the original socket on its
            // caller rather than discarding it for an unsupported schema.
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum));
        }
        self.receive_descriptor_with_disposition(
            maximum_bytes,
            receive_custody::SubjectProfileV1::Descriptors {
                expected: expected_descriptors, allow_empty: false,
            },
            uapi::ReceiveControlProfileV1::ComponentStartupReport5,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal,
        )
    }

    /// Receives Network's fixed PID1 child-origin record and its nine native rights.
    ///
    /// This restricts the shared receiver's shape only. The actual child must
    /// verify PID1, its live Source, each descriptor role and the same prepaid F.
    ///
    /// # Errors
    /// Retains native, preview, subject, truncation and exact-nine-right failures.
    pub fn receive_network_child_origin_retaining_v2(
        &mut self,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_disposition(
            840,
            receive_custody::SubjectProfileV1::Descriptors {
                expected: 9, allow_empty: false,
            },
            uapi::ReceiveControlProfileV1::NetworkChildOrigin9,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal,
        )
    }

    /// Receives only Network's fixed PID1 prebirth acknowledgement carrier.
    ///
    /// The same original Source owner checks the actual PID1 subject, original
    /// request commitment and native Source state before any child acquisition.
    ///
    /// # Errors
    /// Retains native, preview, subject, truncation and forbidden-rights failures.
    pub fn receive_network_prebirth_prepared_retaining_v2(&mut self)
        -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.receive_ordinary_retaining_with_disposition(144,
            uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal)
    }

    /// Prices Network's exact fixed prebirth acknowledgement native carrier.
    #[must_use]
    pub fn network_prebirth_prepared_receive_obligations_v2() -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(144)
    }

    /// Receives Network's fixed pre-READY birth custody and its three rights.
    ///
    /// The real parent separately validates every native role and the same
    /// prepared Source. A receipt never proves leader death or Empty/Retired.
    ///
    /// # Errors
    /// Retains every native sample, partial right, subject and framing failure.
    pub fn receive_network_birth_handoff_retaining_v2(&mut self)
        -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>
    {
        self.receive_descriptor_with_disposition(160,
            receive_custody::SubjectProfileV1::Descriptors { expected: 3, allow_empty: false },
            uapi::ReceiveControlProfileV1::NetworkBirthHandoff3,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal)
    }

    /// Prices the exact three-right birth custody and its hostile native prefix.
    #[must_use]
    pub fn network_birth_handoff_receive_obligations_v2() -> Option<(usize, usize)> {
        let control = uapi::ReceiveControlProfileV1::NetworkBirthHandoff3;
        let bytes = Self::requested_receive_bytes(0, control, 2).checked_add(160)?
            .checked_add(std::mem::size_of::<Result<descriptor_subject::ReceivedDescriptorRecord,
                RetainedSeqpacketReceiveErrorV1>>())?;
        let hostile = control.bytes().checked_sub(std::mem::size_of::<libc::cmsghdr>())?
            / std::mem::size_of::<std::os::fd::RawFd>();
        Some((bytes, hostile.checked_add(2)?.checked_add(1)?.checked_add(3)?))
    }

    /// Prices the actual fixed Network child-origin receive and retained prefix.
    ///
    /// The native ancillary expression follows the exact nine-right schema.
    /// It grants neither a Source identity nor a financial subdivision.
    #[must_use]
    pub fn network_child_origin_receive_obligations_v2() -> Option<(usize, usize)> {
        let control = uapi::ReceiveControlProfileV1::NetworkChildOrigin9;
        let bytes = Self::requested_receive_bytes(0, control, 2)
            .checked_add(840)?
            .checked_add(std::mem::size_of::<Result<descriptor_subject::ReceivedDescriptorRecord,
                RetainedSeqpacketReceiveErrorV1>>())?;
        let hostile = control.bytes().checked_sub(std::mem::size_of::<libc::cmsghdr>())?
            / std::mem::size_of::<std::os::fd::RawFd>();
        let files = hostile.checked_add(2)?.checked_add(1)?.checked_add(9)?;
        Some((bytes, files))
    }

    /// Receives the fixed descriptor-free normal loaded-program report.
    ///
    /// # Errors
    /// Retains the unchanged authenticated80 parser's native, framing, subject
    /// and forbidden-rights failures, including an uncaptured original socket.
    pub fn receive_component_startup_program_retaining_v2(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_disposition(
            maximum_bytes,
            uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal,
        )
    }

    /// Prices the normal report's full native envelope and successful preview.
    ///
    /// No source extent grants receiving permission or changes a role budget.
    /// Returns `None` for unsupported schema widths or arithmetic overflow.
    #[must_use]
    pub fn component_startup_report_receive_obligations_v2(
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Option<(usize, usize)> {
        if maximum_bytes == 0 || !matches!(expected_descriptors, 1 | 3 | 5) {
            return None;
        }
        let control = uapi::ReceiveControlProfileV1::ComponentStartupReport5;
        let bytes = Self::requested_receive_bytes(0, control, 2)
            .checked_add(maximum_bytes)?
            .checked_add(std::mem::size_of::<Result<descriptor_subject::ReceivedDescriptorRecord,
                RetainedSeqpacketReceiveErrorV1>>())?;
        let hostile = control.bytes().checked_sub(std::mem::size_of::<libc::cmsghdr>())?
            / std::mem::size_of::<std::os::fd::RawFd>();
        // The consumed hostile sample can coexist with the successful exact
        // preview, its subject, and the original/duplicate endpoint pair.
        let files = hostile.checked_add(2)?.checked_add(1)?.checked_add(expected_descriptors)?;
        Some((bytes, files))
    }

    /// Prices the zero-right normal program report's same native envelope.
    ///
    /// Returns `None` for an invalid extent or checked arithmetic overflow.
    #[must_use]
    pub fn component_startup_program_receive_obligations_v2(maximum_bytes: usize)
        -> Option<(usize, usize)>
    {
        Self::ordinary_authenticated_receive_obligations_v1(maximum_bytes)
    }

    // Both closed descriptor adapters use the same success-only transfer. The
    // sole receive engine returns exactly preview/consumed samples on success.
    fn receive_descriptor_retaining_profile(
        &mut self,
        maximum_bytes: usize,
        profile: receive_custody::SubjectProfileV1,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_control(maximum_bytes, profile, uapi::ReceiveControlProfileV1::Standard)
    }

    fn receive_descriptor_with_control(
        &mut self,
        maximum_bytes: usize,
        profile: receive_custody::SubjectProfileV1,
        control: uapi::ReceiveControlProfileV1,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_disposition(
            maximum_bytes, profile, control, receive_custody::ReceiveFailureDispositionV4::Existing,
        )
    }

    fn receive_descriptor_with_disposition(
        &mut self,
        maximum_bytes: usize,
        profile: receive_custody::SubjectProfileV1,
        control: uapi::ReceiveControlProfileV1,
        disposition: receive_custody::ReceiveFailureDispositionV4,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let mut attempt = self.receive_retaining_with_disposition(
            maximum_bytes, profile, control, disposition,
        )?;
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
        self.receive_retaining_with_control(maximum, profile, uapi::ReceiveControlProfileV1::Standard)
    }

    fn receive_retaining_with_control(
        &mut self,
        maximum: usize,
        profile: receive_custody::SubjectProfileV1,
        control: uapi::ReceiveControlProfileV1,
    ) -> Result<receive_custody::ReceiveAttemptV1, RetainedSeqpacketReceiveErrorV1> {
        self.receive_retaining_with_disposition(
            maximum, profile, control, receive_custody::ReceiveFailureDispositionV4::Existing,
        )
    }

    fn receive_retaining_with_disposition(
        &mut self,
        maximum: usize,
        profile: receive_custody::SubjectProfileV1,
        control: uapi::ReceiveControlProfileV1,
        disposition: receive_custody::ReceiveFailureDispositionV4,
    ) -> Result<receive_custody::ReceiveAttemptV1, RetainedSeqpacketReceiveErrorV1> {
        let mut result = (|| {
            if maximum == 0 { return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum)); }
            let fd = self.borrow_fd().map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
            let attempt = receive_custody::ReceiveAttemptV1::capture_with_control(fd, self.peer.socket_cookie(), control)?;
            if let Some(original) = &self.zero_rights {
                if matches!(original.restore, Some(Err(_))) {
                    return Err(attempt.reject(SeqpacketError::Closed));
                }
                if original.restore.is_none() {
                    if let Err(cause) = uapi::require_seqpacket_zero_rights(fd) {
                        return Err(attempt.reject(SeqpacketError::from(cause)));
                    }
                }
            }
            receive_custody::receive_packet(attempt, maximum, profile)
        })();
        if let Err(error) = &mut result {
            if !error.is_nonconsuming_would_block() && !error.is_nonconsuming_interrupted() {
                if disposition == receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal
                    && error.needs_original_capture_v4()
                {
                    // Disable this same socket without discarding its only
                    // owner when the initial duplicate could not be acquired.
                    if let Some(endpoint) = self.fd.take() {
                        let shutdown = rustix::net::shutdown(&endpoint, rustix::net::Shutdown::Both)
                            .map_err(std::io::Error::from);
                        error.retain_uncaptured_original_v4(endpoint, shutdown);
                    }
                } else {
                    error.record_shutdown_failure(self.shutdown_retaining_failure());
                }
            }
        }
        result
    }

    fn shutdown_retaining_failure(&mut self) -> Option<std::io::Error> {
        let failure = self.fd.as_ref().and_then(|fd|
            Self::shutdown_owned_descriptor_v1(fd).err());
        self.fd.take();
        failure
    }

    fn shutdown_owned_descriptor_v1(fd: &OwnedFd) -> std::io::Result<()> {
        rustix::net::shutdown(fd, rustix::net::Shutdown::Both).map_err(std::io::Error::from)
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

    /// Receives the selected Mount/Network request's zero-or-one descriptor table.
    ///
    /// The fixed authenticated80 native engine retains both samples and every
    /// failed prefix. The authenticated method separately checks the exact
    /// role sequence; this carrier creates neither admission nor a budget.
    ///
    /// # Errors
    /// Retains native, ancillary, subject and excess-descriptor failures. If
    /// the first endpoint duplication fails, the error retains the original
    /// socket and its shutdown result while disabling further socket IO.
    pub fn receive_fixed_service_request_retaining_v4(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_disposition(
            maximum_bytes,
            receive_custody::SubjectProfileV1::Descriptors { expected: 1, allow_empty: true },
            uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal,
        )
    }

    /// Prices the same fixed service receiver's actual native backing and FD peak.
    ///
    /// The descriptor-bearing result coexists with both retained raw samples.
    /// Payload bounds do not grant receiving or semantic authority.
    #[must_use]
    pub fn fixed_service_request_receive_obligations_v4(maximum_bytes: usize) -> Option<(usize, usize)> {
        let (bytes, files) = Self::ordinary_authenticated_receive_obligations_v1(maximum_bytes)?;
        let bytes = bytes.checked_add(std::mem::size_of::<Result<
            descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1,
        >>())?;
        // A successful descriptor-bearing preview retains its one transferred
        // right beside the consumed sample's hostile raw-control FD peak.
        Some((bytes, files.checked_add(1)?))
    }

    /// Compares a parked fixed-service descriptor record with its original carrier.
    ///
    /// This borrowed native comparison transfers no record, right or authority.
    ///
    /// # Errors
    /// Refuses a closed socket, changed peer binding or foreign record origin.
    pub fn require_fixed_service_descriptor_received_original_v4(
        &self,
        record: &descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_descriptor_record_origin(record)
    }

    /// Receives the two ordered Capture pipe rights on the existing worker socket.
    ///
    /// The native custody engine preserves both samples, kernel subjects and
    /// hostile descriptor prefixes. This transport result grants no worker or
    /// pipe-role authority; the actual parent must verify its original worker.
    ///
    /// # Errors
    /// Retains native, ancillary, subject and inexact-table failures. Only a
    /// proven initial nonconsuming EAGAIN or EINTR permits retrying.
    pub fn receive_capture_worker_pipes_retaining_v3(
        &mut self,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_control(
            4096,
            receive_custody::SubjectProfileV1::Descriptors { expected: 2, allow_empty: false },
            uapi::ReceiveControlProfileV1::WorkerObserver,
        )
    }

    /// Bounds both actual samples of the fixed two-rights worker reply.
    #[must_use]
    pub fn capture_worker_pipes_obligations_v3() -> Option<(usize, usize)> {
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let bytes = Self::requested_receive_bytes(4096, control, 2)
            .checked_add(std::mem::size_of::<Result<descriptor_subject::ReceivedDescriptorRecord,
                RetainedSeqpacketReceiveErrorV1>>())?;
        let files = control.maximum_descriptor_slots().checked_mul(2)?;
        Some((bytes, files))
    }

    /// Receives the fixed Agent control/spec/Capture descriptor shapes.
    ///
    /// Only zero, one or three descriptors are admitted by this closed sibling
    /// of the same retained native engine. The authenticated upper frame still
    /// selects and verifies every descriptor role before any effect.
    ///
    /// # Errors
    /// Retains original native, subject and inexact-table failures. Only the
    /// existing nonconsuming EAGAIN/EINTR class permits a retry.
    pub fn receive_agent_authorize_retaining_v2(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_control(
            maximum_bytes, receive_custody::SubjectProfileV1::AgentAuthorizeV2,
            uapi::ReceiveControlProfileV1::AgentAuthorize,
        )
    }

    /// Prices both actual samples of the installed Agent Authorize receiver.
    ///
    /// Returns `None` for an invalid bound or representation overflow. This
    /// passive quote changes no descriptor grammar or application permission.
    #[must_use]
    pub fn agent_authorize_receive_obligations_v2(maximum: usize) -> Option<(usize, usize)> {
        if maximum == 0 || maximum > u32::MAX as usize { return None; }
        // New passive helper frames are distinct from native message backing.
        const INTERFACES: usize = 3 * std::mem::size_of::<usize>()
            + 3 * std::mem::size_of::<(usize, uapi::ReceiveControlProfileV1, usize)>()
            + 3 * std::mem::size_of::<Option<(usize, usize)>>()
            // Two checked_add calls and one checked_mul have distinct
            // receiver/argument tuples and returned Option planes.
            + 9 * std::mem::size_of::<(usize, usize)>()
            + 9 * std::mem::size_of::<Option<usize>>()
            // The actual maximum_descriptor_slots getter return is separate
            // from requested_receive_bytes' return and the two scalar locals.
            + 3 * std::mem::size_of::<usize>()
            + 3 * std::mem::size_of::<usize>()
            + std::mem::size_of::<uapi::ReceiveControlProfileV1>()
            + 2 * std::mem::size_of::<usize>();
        let control = uapi::ReceiveControlProfileV1::AgentAuthorize;
        let bytes = Self::requested_receive_bytes(maximum, control, 2)
            .checked_add(std::mem::size_of::<Result<descriptor_subject::ReceivedDescriptorRecord,
                RetainedSeqpacketReceiveErrorV1>>())?
            .checked_add(INTERFACES)?;
        Some((bytes, control.maximum_descriptor_slots().checked_mul(2)?))
    }

    /// Bounds raw installed rights/probe slots for one fixed Agent sample.
    ///
    /// A retaining receive can hold two actual samples; the caller adds that
    /// real coexistence and its own retained output/process owners separately.
    #[must_use]
    pub const fn maximum_agent_authorize_descriptor_slots_v2() -> usize {
        uapi::ReceiveControlProfileV1::AgentAuthorize.maximum_descriptor_slots()
    }

    /// Supplies the maximum owning roles of a verified Authorize receipt.
    ///
    /// The sole native parser permits zero, one or three ordinary rights and
    /// exactly one independently validated record-subject pidfd. Its raw
    /// ReceiveAttempt is disposed before returning this successful receipt.
    /// This passive bound grants no admission, mode or execution permission;
    /// failed native receives still require their complete raw-slot bound.
    #[must_use]
    pub const fn agent_authorize_verified_retained_files_v2() -> usize {
        3 + 1
    }

    /// Bounds descriptor slots reached by one fixed-control native receive.
    ///
    /// The existing raw control buffer can contain descriptor integers before
    /// the caller rejects forbidden or malformed ancillary data. Its complete
    /// byte count bounds every kernel-installed SCM_RIGHTS and SCM_PIDFD slot,
    /// even before parsing or later disposal. The additional two slots cover
    /// a retaining receive's duplicate endpoint and one transient proc-stat
    /// descriptor used by record/peer identity checks. This is conservative
    /// geometry DATA, not admission, custody, or an OS descriptor limit.
    ///
    /// This includes one raw recvmsg sample and its transient probes. Callers
    /// separately pay their existing endpoint/listener/startup descriptors and
    /// other samples that they retain concurrently. No future disposal is
    /// deducted from this peak. The value accepts no caller-selected maximum.
    #[must_use]
    pub const fn maximum_receive_descriptor_slots_v1() -> usize {
        uapi::ReceiveControlProfileV1::Standard.maximum_descriptor_slots()
    }

    /// Receives the fixed 128-byte, one-FD original service delivery profile.
    ///
    /// The raw control interval contains only the space required by credentials,
    /// one kernel pidfd and one transferred FD. Excess ancillary data follows
    /// the existing truncation, screening, subject and original-custody checks.
    /// The caller independently authenticates PID1, packet role and all three
    /// original files; this method grants no service or receiving authority.
    ///
    /// # Errors
    /// Retains original native, ancillary, subject and exact-table failures.
    pub fn receive_pid1_service_origin_descriptor_retaining_v1(
        &mut self,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_control(
            128,
            receive_custody::SubjectProfileV1::Descriptors { expected: 1, allow_empty: false },
            uapi::ReceiveControlProfileV1::Pid1ServiceOrigin,
        )
    }

    /// Returns requested heap/stack obligations and raw FD slots for this profile.
    ///
    /// The tuple contains requested source-level bytes and native descriptor
    /// slots across BOTH retained samples. It includes ancillary/evidence cells,
    /// bounded descriptor-link samples, and one endpoint/proc probe pair. Actual
    /// allocator slack, arbitrary error backtraces and kernel objects remain
    /// under the same independently admitted service hard backstop. The caller
    /// separately prices its original endpoint, peer and surrounding owners.
    #[must_use]
    pub fn pid1_service_origin_receive_obligations_v1() -> (usize, usize) {
        let control = uapi::ReceiveControlProfileV1::Pid1ServiceOrigin;
        let requested_bytes = Self::requested_receive_bytes(128, control, 2);
        let descriptor_slots = 2 * (control.bytes() / std::mem::size_of::<std::os::fd::RawFd>()) + 2;
        (requested_bytes, descriptor_slots)
    }

    /// Receives the Controller's versioned prepaid-range launch record.
    ///
    /// This uses the same one-right native custody engine as the independent
    /// service delivery. Only its closed payload width differs. The caller
    /// must authenticate PID1, the actual range grant and all native originals.
    ///
    /// # Errors
    /// Retains the original native, ancillary, subject and descriptor failures.
    pub fn receive_pid1_controller_range_descriptor_retaining_v2(
        &mut self,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_control(
            184,
            receive_custody::SubjectProfileV1::Descriptors { expected: 1, allow_empty: false },
            uapi::ReceiveControlProfileV1::Pid1ServiceOrigin,
        )
    }

    /// Bounds the closed Controller range record's native receiving geometry.
    ///
    /// Both native samples and the full hostile ancillary descriptor prefix
    /// remain priced. This DATA grants no recipient, range or receiving bank.
    #[must_use]
    pub fn pid1_controller_range_receive_obligations_v2() -> (usize, usize) {
        let control = uapi::ReceiveControlProfileV1::Pid1ServiceOrigin;
        let requested_bytes = Self::requested_receive_bytes(184, control, 2);
        let descriptor_slots = 2 * (control.bytes() / std::mem::size_of::<std::os::fd::RawFd>()) + 2;
        (requested_bytes, descriptor_slots)
    }

    /// Returns fixed strict Storage observer receive obligations as DATA.
    ///
    /// This prices the existing standard 512-byte control recipe with payload
    /// at most 4096 bytes and an exact descriptor-subject table of zero or two
    /// FDs. It changes no receive limit, parser, native order or admission.
    /// The tuple contains requested source-level bytes and simultaneous FD
    /// slots. The surrounding endpoint, peer and observer owners are separate.
    /// Allocator slack, kernel objects and arbitrary error backtraces remain
    /// under the independently admitted service hard backstop.
    #[must_use]
    pub fn storage_observer_receive_obligations_v1() -> (usize, usize) {
        let control = uapi::ReceiveControlProfileV1::Standard;
        // Rust 1.98.1 RawVec grows this non-byte/non-ZST Vec from empty to
        // at most four cells across its fixed two pushes. Preserve the old
        // allocation and native failure order rather than preallocating it.
        let requested_bytes = Self::requested_receive_bytes(4096, control, 4);
        // A failed preview never reaches consume. A successful strict preview
        // retains at most its two ordinary FDs and one typed subject pidfd;
        // the consumed syscall can then install all raw slots before rejection.
        let descriptor_slots = Self::maximum_receive_descriptor_slots_v1() + 3;
        (requested_bytes, descriptor_slots)
    }

    /// Bounds the fixed zero-rights Host response receive as passive DATA.
    ///
    /// The same authenticated control recipe admits kernel credentials and the
    /// record subject pidfd. Unexpected rights/security/unknown control remain
    /// errors, including their actual raw prefix and possible kernel truncation.
    /// Payload bounds and receiving payment remain the caller's obligations.
    /// Returns `None` for a zero payload bound or checked overflow.
    #[must_use]
    pub fn host_execution_response_receive_obligations_v1(maximum_bytes: usize) -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(maximum_bytes)
    }

    /// Returns requested Storage preparation receive bytes and FD slots as DATA.
    ///
    /// The maximum is the caller's existing protocol payload bound. Both native
    /// samples, two preallocated message cells and the owning result are priced;
    /// a successful ordinary preview retains one subject pin while the consumed
    /// sample can install every raw control slot before rejection. Endpoint,
    /// peer and caller state remain separate obligations. Allocator slack and
    /// kernel resources remain under the independently admitted hard backstop.
    /// Returns `None` for a zero bound or arithmetic overflow without I/O.
    #[must_use]
    pub fn storage_preparation_receive_obligations_v1(maximum_bytes: usize) -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(maximum_bytes)
    }

    /// Receives an Agent reply through the existing authenticated80 engine.
    ///
    /// # Errors
    /// Preserves whole native, subject, forbidden-control and framing failures.
    pub fn receive_host_agent_response_retaining_v2(
        &mut self,
        maximum: usize,
    ) -> Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_ordinary_retaining_with_control(
            maximum, uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
        )
    }

    /// Supplies the same authenticated80 native Agent reply footprint DATA.
    ///
    /// Returns `None` for a zero payload bound or checked overflow. The generic
    /// hostile-control bound remains19FDs; no closed native-mode credit applies.
    pub fn host_agent_response_receive_obligations_v2(maximum: usize) -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(maximum)
    }

    /// Prices the same retained Guest monitor native receive, as passive DATA.
    ///
    /// Returns `None` for a zero payload bound or checked arithmetic overflow.
    #[must_use]
    pub fn guest_monitor_receive_obligations_v1(maximum: usize) -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(maximum)
    }

    /// Returns the same strict local Ownership receive footprint as passive DATA.
    ///
    /// Native samples, original error custody and raw FD slots are included;
    /// the actual endpoint, peer and original payer remain separate obligations.
    /// Returns `None` for a zero bound or arithmetic overflow without IO.
    #[must_use]
    pub fn local_ownership_receive_obligations_v1(maximum_bytes: usize) -> Option<(usize, usize)> {
        Self::ordinary_authenticated_receive_obligations_v1(maximum_bytes)
    }

    fn ordinary_authenticated_receive_obligations_v1(maximum_bytes: usize) -> Option<(usize, usize)> {
        if maximum_bytes == 0 {
            return None;
        }
        let control = uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80;
        let bytes = Self::requested_receive_bytes(0, control, 2)
            .checked_add(maximum_bytes)?
            .checked_add(std::mem::size_of::<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>())?;
        // Any installed descriptor-bearing native cmsg consumes its own
        // header. Even wholly hostile rights cannot occupy those header bytes.
        // Keep the existing two native/endpoint slots and preview subject.
        let raw_files = control.bytes().checked_sub(std::mem::size_of::<libc::cmsghdr>())?
            / std::mem::size_of::<std::os::fd::RawFd>();
        let files = raw_files.checked_add(2)?.checked_add(1)?;
        Some((bytes, files))
    }

    // Only fixed closed wrappers select these nonauthorizing layout values.
    // Actual allocation/error/descriptor carriers remain owned by the shared
    // receiver; this arithmetic creates no receiving or funding authority.
    pub(crate) fn requested_receive_metadata_cells_v1(
        control: uapi::ReceiveControlProfileV1,
    ) -> Option<usize> {
        receive_custody::requested_receive_metadata_cells_v1(control)
    }

    pub(crate) fn requested_receive_bytes(
        maximum: usize,
        control: uapi::ReceiveControlProfileV1,
        sample_cells: usize,
    ) -> usize {
        std::mem::size_of::<receive_custody::ReceiveAttemptV1>()
            + sample_cells * std::mem::size_of::<receive_custody::CapturedMessageV1>()
            + maximum + 1
            + 2 * uapi::RawReceiveObservationV1::requested_dynamic_bytes(control)
            + 4097 + 32 + 2 * 256
    }

    /// Receives one original FD using the narrow PID1 control geometry.
    ///
    /// The payload bound is passive representation DATA. This uses the same
    /// retained receive engine as the fixed original delivery; the caller must
    /// independently validate its exact format, original peer and full flight.
    /// No packet width grants a role, descriptor factory or resource account.
    ///
    /// # Errors
    /// Retains invalid bounds, native, truncation, subject and table failures.
    pub fn receive_pid1_service_origin_payload_retaining_v1(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_control(
            maximum_bytes,
            receive_custody::SubjectProfileV1::Descriptors { expected: 1, allow_empty: false },
            uapi::ReceiveControlProfileV1::Pid1ServiceOrigin,
        )
    }

    /// Returns the narrow receive's requested bytes and descriptor slots.
    ///
    /// Only the consumed payload allocation varies with the supplied bound.
    /// The preview, native samples, probes and complete control interval match
    /// the existing fixed delivery. Surrounding owners remain separately paid.
    /// Returns `None` for zero or overflowing payload geometry, without I/O.
    #[must_use]
    pub fn pid1_service_origin_payload_receive_obligations_v1(
        maximum_bytes: usize,
    ) -> Option<(usize, usize)> {
        if maximum_bytes == 0 {
            return None;
        }
        let (fixed_bytes, descriptor_slots) = Self::pid1_service_origin_receive_obligations_v1();
        let requested_bytes = fixed_bytes.checked_sub(129)?
            .checked_add(maximum_bytes.checked_add(1)?)?;
        Some((requested_bytes, descriptor_slots))
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

    /// Compares a parked Storage preparation record without disposing its socket.
    ///
    /// The selected caller owns the complete record and original endpoint and
    /// must fence both in its failed owner after a refusal. This comparison
    /// supplies only carrier continuity, never writer or protocol authority.
    ///
    /// # Errors
    /// Returns the existing binding error for a closed, changed, or foreign
    /// original socket. It does not move, close, or clone either original.
    pub fn compare_storage_preparation_received_original_v1(
        &self,
        record: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_record_origin(record)
    }

    /// Retains the native cookie result while comparing the same parked record.
    ///
    /// # Errors
    /// Refuses a closed, changed or foreign socket or repeated native slot.
    /// Neither the actual record nor Socket is moved, closed or cloned.
    #[doc(hidden)]
    pub fn compare_storage_preparation_received_original_retaining_v4(
        &self, record: &ReceivedRecord, native: &mut Option<Result<u64, aos_linux_descriptors::Error>>,
    ) -> Result<(), RecordBindingError> {
        self.require_record_origin_with_originals_v4(record, Some(native))
    }

    /// Compares a parked fixed-worker record with its actual original socket.
    ///
    /// This observes transport continuity only. The Native worker owner must
    /// independently join the nominated process, held aggregate and payment.
    /// Neither original is moved or disposed on a refusal.
    ///
    /// # Errors
    /// Returns the existing binding error for a closed, changed or foreign
    /// socket; the caller retains that error and the whole actual record.
    pub fn compare_worker_received_original_v1(
        &self,
        record: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_record_origin(record)
    }

    /// Compares a retained Ownership record with this same original endpoint.
    ///
    /// This supplies carrier continuity DATA only; the actual paid service
    /// separately validates its subject, transcript MAC and local authority.
    ///
    /// # Errors
    /// Retains both originals in their caller on a closed or changed binding.
    pub fn compare_local_ownership_received_original_v1(
        &self, record: &ReceivedRecord,
    ) -> Result<(), RecordBindingError> {
        self.require_record_origin(record)
    }

    /// Returns common retained acceptance carrier obligations as DATA.
    ///
    /// Listener and upper role reservoirs remain separate. The shared peer
    /// checker formats only bounded kernel inspection messages and opens one
    /// accepted endpoint plus its same-socket SO_PEERPIDFD.
    #[must_use]
    pub const fn retained_accept_obligations_v1() -> (usize, usize) {
        (std::mem::size_of::<PendingSocketAdmissionV1>()
            + std::mem::size_of::<Result<Self, RetainedSeqpacketAdmissionErrorV1>>()
            + 1024, 2)
    }

    /// Returns retaining connection carrier obligations as passive DATA.
    ///
    /// The fresh connect and accepted endpoints use the same pending peer
    /// custody/kind checker and two descriptor slots. Unix socket addresses
    /// are fixed inline kernel structures, not a second allocated path model.
    #[must_use]
    pub const fn retained_connect_obligations_v1() -> (usize, usize) {
        Self::retained_accept_obligations_v1()
    }

    /// Counts fixed pending/peer capture and native constructor namespaces.
    ///
    /// This passive census grants no connection or application authority.
    #[must_use]
    pub const fn retained_connect_metadata_cells_v1() -> usize {
        // Pending6, peer4+credentials3+pidfd1+info13+binding1, partial
        // capture8+credentials3+pidfd1+info13+two bindings, returned error2,
        // socket/address/option and conversion temporaries8.
        6 + 4 + 3 + 1 + 5 + 8 + 1 + 8 + 3 + 1 + 5 + 8 + 2 + 2 + 8
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
        self.require_record_origin_with_originals_v4(record, None)
    }

    fn require_record_origin_with_originals_v4(&self, record: &ReceivedRecord,
        native: Option<&mut Option<Result<u64, aos_linux_descriptors::Error>>>,
    ) -> Result<(), RecordBindingError> {
        let fd = self
            .fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current_with_originals_v1(fd, native)?;
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
        let credentials = aos_linux_descriptors::native::peer_credentials(fd)?;
        self.credentials = Some((credentials.uid, credentials.gid));
        if credentials.pid != 0 {
            return Err(SeqpacketError::PeerIdentity("selected Host peer is not namespace-local PID0"));
        }
        // Park the real kernel return before CLOEXEC, ioctl, stat and polling.
        self.peer_pin = Some(aos_linux_descriptors::native::peer_pidfd(fd)?);
        self.pin = Some(crate::pidfd::require_ancestor_host_original(
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
        let credentials = aos_linux_descriptors::native::peer_credentials(fd)?;
        if credentials.pid != 0 || Some((credentials.uid, credentials.gid)) != self.credentials {
            return Err(SeqpacketError::PeerIdentity("original ancestor Host credentials changed"));
        }
        let pin = self.peer_pin.as_ref().ok_or(SeqpacketError::Closed)?;
        if Some(crate::pidfd::require_ancestor_host_original(pin.as_fd())?) != self.pin {
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
        self.receive_with_control(maximum, uapi::ReceiveControlProfileV1::Standard)
    }

    /// Receives only the fixed startup report's 200-byte private challenge.
    ///
    /// The existing ancestor-Host subject reducer is unchanged. Its selected
    /// native control reservoir covers credentials and one nominated pidfd;
    /// rights, duplicate/foreign control and truncation remain fatal.
    ///
    /// # Errors
    /// Retains native/subject/packet failures. Only initial nonconsuming
    /// EAGAIN/EINTR preserves the same original receiver's retry eligibility.
    pub(crate) fn receive_startup_report_retaining_v1(&mut self)
        -> Result<GuestAncestorHostRecordV1, RetainedSeqpacketReceiveErrorV1>
    {
        self.receive_with_control(200, uapi::ReceiveControlProfileV1::WorkerObserver)
    }

    pub(crate) fn startup_report_receive_obligations_v1() -> Option<(usize, usize)> {
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        Some((SeqpacketSocket::requested_receive_bytes(200, control, 2),
            control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 1))
    }

    fn receive_with_control(&mut self, maximum: usize, control: uapi::ReceiveControlProfileV1)
        -> Result<GuestAncestorHostRecordV1, RetainedSeqpacketReceiveErrorV1>
    {
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
            let attempt = receive_custody::ReceiveAttemptV1::capture_with_control(fd, binding.socket_cookie(), control)?;
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
            || crate::pidfd::require_ancestor_host_original(record.pin.fd.as_fd())? != record.pin.identity
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

// Ordinary and retained admission use the same checker/order. The retained
// Pending owner keeps this destination before SO_PEERPIDFD; a later kind/info
// or cookie refusal therefore cannot drop an acquired raw or typed process pin.
#[derive(Default)]
struct PeerCaptureAttemptV1 {
    entered: bool,
    complete: bool,
    binding: Option<ConnectedSocketBinding>,
    credentials: Option<PeerCredentials>,
    raw_pidfd: Option<OwnedFd>,
    pidfd: Option<PidFd>,
    info: Option<PidFdInfo>,
    after: Option<ConnectedSocketBinding>,
}

impl PeerCaptureAttemptV1 {
    fn capture_once(&mut self, fd: BorrowedFd<'_>) -> Result<(), SeqpacketError> {
        self.capture_observed_v1(fd, false)
    }

    fn capture_observed_v1(&mut self, fd: BorrowedFd<'_>, retain_raw: bool) -> Result<(), SeqpacketError> {
        if self.entered { return Err(SeqpacketError::Closed); }
        self.entered = true;
        uapi::validate_connected_seqpacket(fd)?;
        self.binding = Some(ConnectedSocketBinding::capture_peer(fd)?);
        self.credentials = Some(PeerCredentials::from_raw(aos_linux_descriptors::native::peer_credentials(fd)?)?);
        if retain_raw {
            aos_linux_descriptors::native::peer_pidfd_retaining_into_v1(fd, &mut self.raw_pidfd)?;
        } else {
            self.raw_pidfd = Some(aos_linux_descriptors::native::peer_pidfd(fd)?);
        }
        self.raw_pidfd.as_ref().ok_or(aos_linux_descriptors::Error::WrongDescriptorType {
            expected: "pidfd",
        })?;
        self.pidfd = Some(PidFd::adopt_owned_slot_v2(&mut self.raw_pidfd)?);
        self.info = Some(self.pidfd.as_ref().ok_or(SeqpacketError::Closed)?.info()?);
        self.after = Some(ConnectedSocketBinding::capture_peer(fd)?);
        if self.info.ok_or(SeqpacketError::Closed)?.pid()
            != self.credentials.ok_or(SeqpacketError::Closed)?.pid().get()
        {
            return Err(SeqpacketError::PeerIdentity("SO_PEERCRED and SO_PEERPIDFD identify different processes"));
        }
        if self.after != self.binding {
            return Err(SeqpacketError::PeerIdentity("SO_COOKIE changed during sequenced-packet peer capture"));
        }
        self.complete = true;
        Ok(())
    }

    fn take_completed(&mut self) -> Result<ConnectionPeerIdentity, SeqpacketError> {
        if !self.complete { return Err(SeqpacketError::Closed); }
        self.complete = false;
        Ok(ConnectionPeerIdentity {
            binding: self.binding.take().ok_or(SeqpacketError::Closed)?,
            credentials: self.credentials.take().ok_or(SeqpacketError::Closed)?,
            pidfd: self.pidfd.take().ok_or(SeqpacketError::Closed)?,
            initial_info: self.info.take().ok_or(SeqpacketError::Closed)?,
        })
    }
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
        let mut capture = PeerCaptureAttemptV1::default();
        capture.capture_once(fd)?;
        capture.take_completed()
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
    pub fn is_alive(&self) -> aos_linux_descriptors::Result<bool> {
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
    pub fn is_alive(&self) -> aos_linux_descriptors::Result<bool> {
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
        let (left, right) = aos_linux_descriptors::native::seqpacket_pair().expect("create seqpacket pair");
        (
            SeqpacketSocket::from_owned(left).expect("adopt left socket"),
            SeqpacketSocket::from_owned(right).expect("adopt right socket"),
        )
    }

    #[test]
    fn connection_identity_capture_does_not_change_socket_flags() {
        for flags in [0, libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC] {
            let (left, _right) = aos_linux_descriptors::native::seqpacket_pair_with_flags(flags).expect("create test pair");
            let before_status = aos_linux_descriptors::native::get_status_flags(left.as_fd()).expect("initial status flags");
            let before_cloexec = aos_linux_descriptors::native::is_cloexec(left.as_fd()).expect("initial FD flags");
            let identity = ConnectionPeerIdentity::from_socket(left.as_fd()).expect("capture peer");
            assert_eq!(identity.credentials().pid().get(), std::process::id());
            assert_eq!(identity.initial_info().pid(), std::process::id());
            assert_ne!(identity.socket_cookie().get(), 0);
            assert!(aos_linux_descriptors::native::is_cloexec(identity.pidfd().as_fd()).expect("peer pidfd CLOEXEC"));
            assert_eq!(
                aos_linux_descriptors::native::get_status_flags(left.as_fd()).expect("final status flags"),
                before_status
            );
            assert_eq!(
                aos_linux_descriptors::native::is_cloexec(left.as_fd()).expect("final FD flags"),
                before_cloexec
            );
            assert!(aos_linux_descriptors::native::require_seqpacket_identity(left.as_fd()).is_err());
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
        assert!(aos_linux_descriptors::native::is_cloexec(record.subject().pidfd().as_fd()).expect("inspect pidfd flags"));
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
        let duplicate_fd = aos_linux_descriptors::native::duplicate_at_least(receiver.as_fd().expect("receiver fd"), 0)
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
        assert!(aos_linux_descriptors::native::is_cloexec(socket.peer().pidfd().as_fd()).expect("inspect peer pidfd flags"));
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
    fn capture_worker_two_rights_preserves_order_and_rejects_an_excess_prefix() {
        let (mut sender, mut receiver) = pair();
        receiver.enable_record_subjects().unwrap();
        let (_, stdout) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (_, stderr) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let stdout_identity = rustix::fs::fstat(&stdout).unwrap();
        let stderr_identity = rustix::fs::fstat(&stderr).unwrap();
        sender.send_with_descriptors(b"mounted", &[stdout.as_fd(), stderr.as_fd()]).unwrap();

        let record = receiver.receive_capture_worker_pipes_retaining_v3().unwrap();

        assert_eq!(record.payload(), b"mounted");
        assert_eq!(record.descriptors().len(), 2);
        for (descriptor, expected) in record.descriptors().iter().zip([stdout_identity, stderr_identity]) {
            let actual = rustix::fs::fstat(descriptor).unwrap();
            assert_eq!((actual.st_dev, actual.st_ino), (expected.st_dev, expected.st_ino));
        }

        let (mut sender, mut receiver) = pair();
        receiver.enable_record_subjects().unwrap();
        sender.send_with_descriptors(b"hostile", &[stdout.as_fd(), stderr.as_fd(), stdout.as_fd()]).unwrap();

        let failure = receiver.receive_capture_worker_pipes_retaining_v3().unwrap_err();

        assert!(!failure.is_nonconsuming_would_block());
        assert!(!failure.is_nonconsuming_interrupted());
        assert!(std::error::Error::source(&failure).is_some());
        assert!(receiver.as_fd().is_err());
    }

    #[test]
    fn capture_agent_profile_admits_only_zero_one_or_three_rights() {
        for count in 0..=4 {
            let (mut sender, mut receiver) = pair();
            receiver.enable_record_subjects().unwrap();
            let file = std::fs::File::open("/dev/null").unwrap();
            if count == 0 {
                sender.send(b"agent").unwrap();
            } else {
                sender.send_with_descriptors(b"agent", &vec![file.as_fd(); count]).unwrap();
            }

            let result = receiver.receive_agent_authorize_retaining_v2(64);
            if matches!(count, 0 | 1 | 3) {
                assert_eq!(result.unwrap().descriptors().len(), count);
            } else {
                let failure = result.err().unwrap();
                assert!(!failure.is_nonconsuming_would_block());
                assert!(!failure.is_nonconsuming_interrupted());
                assert!(receiver.as_fd().is_err());
            }
        }
        #[cfg(target_pointer_width = "64")]
        assert_eq!(SeqpacketSocket::maximum_agent_authorize_descriptor_slots_v2(), 24);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(SeqpacketSocket::maximum_agent_authorize_descriptor_slots_v2(), 18);
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

        let pidfd_one = aos_linux_descriptors::native::pidfd_open(std::process::id()).expect("open first pidfd");
        let pidfd_two = aos_linux_descriptors::native::pidfd_open(std::process::id()).expect("open second pidfd");
        assert!(matches!(
            validate_record_subject(vec![
                RawAncillary::Credentials(credentials),
                RawAncillary::PidFd(aos_linux_descriptors::pidfd::PidFdAdmissionSlotV1::new(pidfd_one)),
                RawAncillary::PidFd(aos_linux_descriptors::pidfd::PidFdAdmissionSlotV1::new(pidfd_two)),
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
            aos_linux_descriptors::native::duplicate_at_least(file.as_fd(), 512).expect("duplicate test descriptor");
        let raw = owned.as_raw_fd();
        assert!(matches!(
            validate_record_subject(vec![RawAncillary::Rights(vec![owned])]),
            Err(SeqpacketError::Ancillary("SCM_RIGHTS is forbidden"))
        ));
        assert!(!aos_linux_descriptors::native::raw_fd_is_open(raw));
    }

    #[test]
    fn adopted_socket_and_received_pidfd_are_close_on_exec() {
        let (left, _right) = aos_linux_descriptors::native::seqpacket_pair().expect("create pair");
        let raw = left.as_raw_fd();
        let socket = SeqpacketSocket::from_owned(left).expect("adopt socket");
        assert_eq!(socket.as_fd().expect("borrow socket").as_raw_fd(), raw);
        assert!(aos_linux_descriptors::native::is_cloexec(socket.as_fd().expect("borrow socket")).expect("inspect flags"));
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

#[cfg(test)]
mod pid1_service_origin_transport_tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn fixed_service_profile_retains_one_real_transferred_descriptor() {
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(&[7; 128], &[original.as_fd()]).unwrap();

        let record = receiver.receive_pid1_service_origin_descriptor_retaining_v1().unwrap();

        assert_eq!(record.payload(), &[7; 128]);
        assert_eq!(record.descriptors().len(), 1);
        assert_eq!(record.subject().credentials().pid().get(), std::process::id());
        let transferred = rustix::fs::fstat(&record.descriptors()[0]).unwrap();
        let expected = rustix::fs::fstat(&original).unwrap();
        assert_eq!((transferred.st_dev, transferred.st_ino), (expected.st_dev, expected.st_ino));
    }

    #[test]
    fn fixed_service_refuses_excess_rights_while_ordinary_profile_keeps_its_width() {
        let original = std::fs::File::open("/dev/null").unwrap();
        let descriptors = [original.as_fd(), original.as_fd(), original.as_fd()];
        let (mut fixed, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send_with_descriptors(&[9; 128], &descriptors).unwrap();

        let rejected = fixed.receive_pid1_service_origin_descriptor_retaining_v1();

        assert!(rejected.is_err());
        assert!(fixed.as_fd().is_err());

        let (mut ordinary, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send_with_descriptors(&[9; 128], &descriptors).unwrap();

        let accepted = ordinary.receive_with_descriptors_retaining(128, 3).unwrap();

        assert_eq!(accepted.descriptors().len(), 3);
        assert_eq!(accepted.payload(), &[9; 128]);
    }
}

#[cfg(test)]
mod storage_preparation_transport_tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn preparation_profile_retains_real_ordinary_subject_and_payload() {
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send(b"HELLO:bounded").unwrap();

        let record = receiver.receive_storage_preparation_retaining_v1(4096).unwrap();

        assert_eq!(record.payload(), b"HELLO:bounded");
        assert_eq!(record.subject().credentials().pid().get(), std::process::id());
    }

    #[test]
    fn preparation_profile_rejects_rights_with_original_failure_custody() {
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(b"Prepare", &[original.as_fd()]).unwrap();

        let error = receiver.receive_storage_preparation_retaining_v1(4096).unwrap_err();

        assert!(!error.is_nonconsuming_would_block());
        assert!(!error.is_nonconsuming_interrupted());
        assert!(receiver.as_fd().is_err());
        assert!(matches!(std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::Ancillary("SCM_RIGHTS is forbidden"))));
    }

    #[test]
    fn preparation_excess_control_fences_only_selected_receiver() {
        let original = std::fs::File::open("/dev/null").unwrap();
        let rights = [original.as_fd(), original.as_fd(), original.as_fd()];
        let (mut selected, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send_with_descriptors(b"Prepare", &rights).unwrap();

        let rejected = selected.receive_storage_preparation_retaining_v1(4096);

        assert!(rejected.is_err());
        assert!(selected.as_fd().is_err());

        let (mut standard, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send_with_descriptors(b"unchanged", &rights).unwrap();

        let record = standard.receive_with_descriptors_retaining(4096, 3).unwrap();

        assert_eq!(record.descriptors().len(), 3);
        assert_eq!(record.payload(), b"unchanged");
    }
}

#[cfg(test)]
mod host_execution_response_control_tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn legitimate_host_response_keeps_the_same_kernel_subject() {
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send(b"Host:authenticated-response").unwrap();

        let response = receiver.receive_host_execution_response_retaining_v1(4096).unwrap();

        assert_eq!(response.payload(), b"Host:authenticated-response");
        assert_eq!(response.subject().credentials().pid().get(), std::process::id());
        assert!(response.subject().is_alive().unwrap());
        let (_, files) = SeqpacketSocket::host_execution_response_receive_obligations_v1(4096).unwrap();
        assert!(files < SeqpacketSocket::maximum_receive_descriptor_slots_v1());
    }

    #[test]
    fn excess_host_rights_keep_the_original_truncation_and_fence() {
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        let rights = [original.as_fd(); 32];
        // The production sender correctly refuses more than five rights.
        // This existing raw fixture reaches the hostile recvmsg/CTRUNC prefix.
        crate::uapi::send_seqpacket_rights(sender.as_fd().unwrap(), b"Host:forbidden-rights", &rights).unwrap();

        let error = receiver.receive_host_execution_response_retaining_v1(4096).unwrap_err();

        assert!(receiver.as_fd().is_err());
        assert!(!error.is_nonconsuming_would_block());
        assert!(!error.is_nonconsuming_interrupted());
        assert!(matches!(std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::ControlTruncated)));
        // The owning error stays resident until this actual negative test ends.
        assert!(std::error::Error::source(&error).is_some());
    }
}


#[cfg(test)]
mod storage_worker_inherited_admission_tests {
    use super::*;
    use std::os::fd::{AsFd as _, AsRawFd as _};

    #[test]
    fn rejected_worker_input_keeps_the_same_native_descriptor_and_cause() {
        let descriptor = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap();
        let number = descriptor.as_raw_fd();
        let before = rustix::fs::fstat(&descriptor).unwrap();

        let failure = SeqpacketSocket::from_owned_storage_worker_retaining_v3(descriptor)
            .unwrap_err();

        assert!(failure.retains_descriptor());
        assert!(failure.shutdown_attempted());
        let original = failure.attempt.as_ref().unwrap().fd.as_ref().unwrap();
        assert_eq!(original.as_raw_fd(), number);
        let after = rustix::fs::fstat(original.as_fd()).unwrap();
        assert_eq!((after.st_dev, after.st_ino), (before.st_dev, before.st_ino));
        // The later shutdown refusal has independent custody and cannot
        // replace the actual earlier socket-admission cause.
        assert!(failure.shutdown_failure().is_some());
        assert!(matches!(failure.cause(), SeqpacketError::Kernel(_)));
    }
}

#[cfg(test)]
mod network_activation_gate_tests {
    use super::*;
    use descriptor_subject::{DescriptorSubjectSocket, NetworkWorkerConnectionKindV4};

    #[test]
    fn refused_final_gate_keeps_original_socket_and_never_connects_the_listener() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-activation.sock");
        let listener = RecordSubjectListener::bind(&path, 4).unwrap();
        let mut attempts = 0;
        let (native, gate_failure) = connect_pending_worker_guarded_v4(&path, &mut || {
            attempts += 1;
            Err(17_u32)
        });
        let failure = native.err().unwrap();

        assert_eq!(attempts, 1);
        assert_eq!(gate_failure, Some(17));
        assert!(failure.retains_descriptor());
        assert!(failure.shutdown_attempted());
        assert!(matches!(
            rustix::net::accept(listener.as_fd()),
            Err(rustix::io::Errno::AGAIN)
        ));
        let original = failure.attempt.as_ref().unwrap().fd.as_ref().unwrap();
        assert!(rustix::fs::fstat(original).is_ok());
        assert!(
            rustix::fs::fcntl_getfl(original)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
    }

    #[test]
    fn positive_final_gate_connects_once_through_the_same_raw_peer_admission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-activation.sock");
        let mut listener = RecordSubjectListener::bind(&path, 4).unwrap();
        let mut attempts = 0;
        let (pending, gate_failure) = connect_pending_worker_guarded_v4(&path, &mut || {
            attempts += 1;
            Ok::<_, u32>(())
        });
        let client =
            DescriptorSubjectSocket::from_pending_retaining_raw_v2(pending.unwrap()).unwrap();
        let server = listener.accept_storage_root_export_retaining_v2().unwrap();

        assert_eq!(attempts, 1);
        assert_eq!(gate_failure, None);
        assert_eq!(client.peer().credentials().pid().get(), std::process::id());
        assert_eq!(server.peer().credentials().pid().get(), std::process::id());
        assert!(client.peer().is_alive().unwrap());
    }

    #[test]
    fn connection_recipe_is_fixed_and_precreation_refusal_does_not_consume_a_gate() {
        assert_eq!(
            NetworkWorkerConnectionKindV4::Preparation.path_v4(),
            Path::new("/run/aos/sandbox-network-worker/control.sock")
        );
        assert_eq!(
            NetworkWorkerConnectionKindV4::Observation.path_v4(),
            Path::new("/run/aos/sandbox-network-observation-worker/control.sock")
        );
        let mut attempts = 0;
        let too_long = Path::new(
            "/aos/network/activation/filename/that/is/intentionally/longer/than/the/native/unix/domain/socket/path/operand/ceiling/to/refuse",
        );
        let (native, refused) = connect_pending_worker_guarded_v4(too_long, &mut || {
            attempts += 1;
            Ok::<_, u32>(())
        });
        let failure = native.err().unwrap();

        assert_eq!(attempts, 0);
        assert_eq!(refused, None);
        assert!(!failure.retains_descriptor());
        assert_eq!(
            DescriptorSubjectSocket::network_worker_admission_obligations_v4::<u32>()
                .unwrap()
                .1,
            2
        );
    }
}

impl From<aos_linux_descriptors::unix_stream::StreamReportingErrorV1> for SeqpacketError {
    fn from(error: aos_linux_descriptors::unix_stream::StreamReportingErrorV1) -> Self {
        match error {
            aos_linux_descriptors::unix_stream::StreamReportingErrorV1::Closed => Self::Closed,
            aos_linux_descriptors::unix_stream::StreamReportingErrorV1::Native(source) => source.into(),
        }
    }
}
