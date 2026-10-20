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

mod worker_send;
mod root_export_receive;
mod guest_ssh;
mod network_observer_handoff;
mod network_worker_retirement;
mod network_worker_wait;

pub use network_worker_retirement::NetworkWorkerRetiredRecordDataV2;
pub use network_worker_wait::{NetworkWorkerBootstrapWaitOriginalV3, NetworkWorkerBootstrapWaitRefusalV3};

pub use guest_ssh::{GuestSshBootstrapOriginalV1, GuestSshListenerCustodyV1};

pub use worker_send::DescriptorWorkerNativeSendAttemptV1;
pub use root_export_receive::StorageRootExportRequestPreviewV2;

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
pub(super) const MAXIMUM_PACKET_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_TRANSFERRED_DESCRIPTORS: usize = 2;
const KERNEL_EXPORT_DESCRIPTORS: usize = 3;

/// Names the two fixed Network acquisition sockets without granting a role.
#[derive(Clone, Copy, Debug)]
pub enum NetworkWorkerConnectionKindV4 {
    /// Selects the existing fresh preparation worker endpoint.
    Preparation,
    /// Selects the existing fresh observation worker endpoint.
    Observation,
}

impl NetworkWorkerConnectionKindV4 {
    /// Returns the intrinsic activation pathname as passive layout DATA.
    #[must_use]
    pub fn path_v4(self) -> &'static Path {
        match self {
            Self::Preparation => Path::new("/run/aos/sandbox-network-worker/control.sock"),
            Self::Observation => {
                Path::new("/run/aos/sandbox-network-observation-worker/control.sock")
            }
        }
    }
}

/// Selects the fixed descriptor table of a worker observer record.
///
/// This carrier shape grants no worker identity, workspace ownership, receiving
/// payment or application permission. Consumers independently validate those.
#[derive(Clone, Copy, Debug)]
pub enum WorkerObserverRecordKindV1 {
    /// Requires zero descriptors for READY or an ordinary observation result.
    ReadyOrResult,
    /// Requires no rights for the existing bounded16KiB workspace-pin result.
    PinResult,
    /// Requires no rights for the fixed8192-byte maximum method31 worker request.
    GuestRootPublicationRequestV2,
    /// Requires no rights for the exact274-byte physical method31 result.
    GuestRootPublicationResultV2,
    /// Exact observation-only startup health response, no transferred rights.
    GuestRootStartupHealthV2,
    /// Permits one export descriptor or the existing zero-descriptor error reply.
    ExportReply,
    /// Requires the two original descriptors of the initial worker request.
    Request,
}

impl WorkerObserverRecordKindV1 {
    /// Returns only the existing fixed packet ceiling for this transport shape.
    #[must_use]
    pub const fn maximum_payload_bytes_v1(self) -> usize {
        match self {
            Self::PinResult => 16 * 1024,
            Self::GuestRootPublicationRequestV2 => 8192,
            Self::GuestRootPublicationResultV2 => 274,
            Self::GuestRootStartupHealthV2 => 8,
            _ => 4096,
        }
    }
}

/// Owns a configured nonblocking descriptor-reply channel without service authority.
#[derive(Debug)]
pub struct DescriptorSubjectSocket {
    fd: Option<OwnedFd>,
    peer: ConnectionPeerIdentity,
    retention: OriginalRetentionV1,
    zero_rights: Option<super::zero_rights::ZeroRightsNativeV1>,
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
    pub(crate) fn receive_guest_ssh_listeners_retaining_v1(&mut self,
        cutoff: super::NetworkWorkerNativeCutoffV4)
        -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>
    {
        // This reuses only a deny-only native clock DATA checker. No Network
        // role, worker, loan, purpose or financial permission crosses here.
        self.receive_profile_with_cutoff_v4(88, SubjectProfileV1::GuestSshListenersV1,
            uapi::ReceiveControlProfileV1::WorkerObserver, Some(cutoff))
    }

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

    /// Connects while retaining the exact raw peer pidfd on admission refusal.
    ///
    /// This mechanical sibling uses the same path/socket/peer/reporting engine
    /// as `connect_retaining`. The sole change selects its existing raw-native
    /// destination before SO_PEERPIDFD length/CLOEXEC/adoption checks. No socket,
    /// process pin, peer DATA or successful connection supplies role authority.
    ///
    /// # Errors
    /// Retains the original socket, reached raw/typed peer pin and actual first
    /// native cause after shutdown. It permits neither retry nor pin extraction.
    pub fn connect_retaining_raw_v2(path: &Path) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::require_connection_path(path)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        Self::from_pending_retaining_raw_v2(connect_pending_seqpacket(path)?)
    }

    /// Connects one fixed Network activation endpoint with a final native gate.
    ///
    /// The caller owns its genuine same-F source, child aggregate and paid
    /// native pool before entry. This mechanical carrier supplies no role or
    /// execution permission. The callback runs immediately before the existing
    /// nonblocking single connect syscall; no incomplete connect is retried.
    ///
    /// # Errors
    /// Retains the socket, raw peer pin, original native admission failure and
    /// shutdown debt. A restrictive callback failure is returned separately in
    /// its original type; no socket or effect escapes after that refusal.
    pub fn connect_network_worker_retaining_v4<E>(
        kind: NetworkWorkerConnectionKindV4,
        before_native: &mut impl FnMut() -> Result<(), E>,
    ) -> (Result<Self, RetainedSeqpacketAdmissionErrorV1>, Option<E>) {
        let (pending, gate_failure) =
            super::connect_pending_worker_guarded_v4(kind.path_v4(), before_native);
        (
            pending.and_then(Self::from_pending_retaining_raw_v2),
            gate_failure,
        )
    }

    /// Bounds the same fixed admission and inline restrictive gate returns.
    ///
    /// Heap backing owned by the caller's gate error and the genuine child
    /// receiving source remain separately prepaid by their real owners.
    #[must_use]
    pub fn network_worker_admission_obligations_v4<E>() -> Option<(usize, usize)> {
        let (native_bytes, files) = Self::retaining_raw_admission_obligations_v2()?;
        let gate_frames = std::mem::size_of::<Option<E>>()
            .checked_mul(4)?
            .checked_add(4 * std::mem::size_of::<&mut dyn FnMut() -> Result<(), E>>())?
            .checked_add(2 * std::mem::size_of::<Result<(), crate::Error>>())?;
        Some((native_bytes.checked_add(gate_frames)?, files))
    }

    /// Bounds that same retained raw admission before connect or accept.
    ///
    /// Covers the socket plus its one same-peer pidfd, pending/raw/typed result
    /// carriers, two native Unix-address operands and fixed kernel diagnostics.
    /// The kernel calls in this engine use fixed-size socket/credential/pidfs
    /// structures; their only owned diagnostic strings are fixed schema texts.
    /// Filesystem cgroup/role observations and record receive are separate.
    #[must_use]
    pub fn retaining_raw_admission_obligations_v2() -> Option<(usize, usize)> {
        super::raw_admission_obligations_v3::<Self>()
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
            zero_rights: None,
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
        pending: PendingSocketAdmissionV1,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::from_pending_with_peer_custody_v2(pending, false)
    }

    pub(super) fn from_pending_retaining_raw_v2(
        pending: PendingSocketAdmissionV1,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::from_pending_with_peer_custody_v2(pending, true)
    }

    fn from_pending_with_peer_custody_v2(
        mut pending: PendingSocketAdmissionV1,
        retain_raw: bool,
    ) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        let peer = if retain_raw {
            pending.admit_peer_retaining_raw_v1()
        } else {
            pending.admit_peer()
        };
        let admitted = peer.and_then(|()| pending.enable_subjects());
        if let Err(source) = admitted {
            return Err(pending.fail(source));
        }
        let (fd, peer) = pending.finish()?;
        Ok(Self {
            fd: Some(fd),
            peer,
            retention: OriginalRetentionV1::legacy(),
            zero_rights: None,
        })
    }

    /// Connects a descriptor-free reply channel with rights disabled before exposure.
    ///
    /// # Errors
    /// Retains the same pending socket, raw peer descriptor and native causes.
    pub fn connect_zero_rights_retaining_v6(path: &Path) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::require_connection_path(path).map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        let pending = super::connect_pending_with_rights(path, true)?;
        let mut socket = Self::from_pending_retaining_raw_v2(pending)?;
        socket.zero_rights = Some(super::zero_rights::ZeroRightsNativeV1 { restore: None, epoch: 0 });
        Ok(socket)
    }

    /// Restricts this held channel through the shared retained empty-queue recipe.
    ///
    /// # Errors
    /// Retains all native outcomes and fences the same socket on any refusal.
    pub fn restrict_incoming_rights_retaining_v6(&mut self, original: &mut super::SeqpacketRightsRestrictionOriginalV6) -> Result<(), SeqpacketError> {
        if original.entered() { return Err(SeqpacketError::Closed); }
        let epoch = self.zero_rights.as_ref().map_or(0, |mode| mode.epoch)
            .checked_add(1).ok_or(SeqpacketError::Closed)?;
        let mut observation = OriginalObservationV1::begin(&self.fd, &mut self.retention)?;
        self.zero_rights = Some(super::zero_rights::ZeroRightsNativeV1 { restore: Some(Err(SeqpacketError::Closed)), epoch });
        original.run(observation.fd()?, self.peer.socket_cookie(), epoch)?;
        self.zero_rights = Some(super::zero_rights::ZeroRightsNativeV1 { restore: None, epoch });
        observation.complete();
        Ok(())
    }

    /// Checks a completed same-socket restriction without native sampling.
    ///
    /// # Errors
    /// Refuses failed, different-socket or superseded restrictions.
    pub fn require_rights_restriction_current_v6(&self, original: &super::SeqpacketRightsRestrictionOriginalV6) -> Result<(), SeqpacketError> {
        if self.fd.is_none() || self.retention.phase == RetentionPhaseV1::Failed {
            return Err(SeqpacketError::Closed);
        }
        original.require_current(self.peer.socket_cookie(), self.zero_rights.as_ref())
    }

    /// Supplies the fixed authenticated reply peak only for actual native mode zero.
    #[must_use]
    pub fn zero_rights_receive_obligations_v6(&self, maximum: usize) -> Option<(usize, usize)> {
        if self.fd.is_none() || self.retention.phase == RetentionPhaseV1::Failed
            || self.zero_rights.as_ref()?.restore.is_some() { return None; }
        Self::storage_zero_rights_reply_obligations_v6(maximum)
    }

    /// Supplies the existing Storage authenticated80 bytes and native three-FD peak.
    ///
    /// Only an actual pre-exposure constructor or completed retained restriction
    /// permits this mode; the receiver rechecks the native option before capture.
    #[must_use]
    pub fn storage_zero_rights_reply_obligations_v6(maximum: usize) -> Option<(usize, usize)> {
        let (bytes, _) = Self::storage_held_output_reply_obligations_v2(maximum)?;
        Some((bytes, 3))
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

    /// Observes the same retained peer path for an independently owed post.
    ///
    /// Fatal transport refusal keeps the original descriptor while denying
    /// new IO loans. This observation still runs the existing socket-object
    /// and peer-address checks against that descriptor. It neither restores
    /// channel health nor permits another send, receive or descriptor loan.
    /// The enclosing original retains this result and its earlier cause.
    ///
    /// # Errors
    /// Rejects a missing retained descriptor, a native observation failure,
    /// a replaced socket object, or a noncanonical or mismatched peer path.
    pub fn observe_owed_peer_filesystem_path_v2(
        &self,
        expected: &Path,
    ) -> Result<(), SeqpacketError> {
        let fd = self.fd.as_ref().ok_or(SeqpacketError::Closed)?;
        self.peer.require_peer_filesystem_path(fd.as_fd(), expected)
    }

    /// Observes the same retained local path for an independently owed post.
    ///
    /// The original socket remains owned after fatal transport refusal. This
    /// nonadopting observation uses its existing local-address predicate without
    /// restoring health, lending the descriptor, or permitting another packet.
    /// Its enclosing owner retains this result alongside its earlier failure.
    ///
    /// # Errors
    /// Rejects a missing descriptor, native observation failure, replaced socket
    /// object, or a noncanonical or mismatched local filesystem address.
    pub fn observe_owed_local_filesystem_path_v2(
        &self,
        expected: &Path,
    ) -> Result<(), SeqpacketError> {
        let fd = self.fd.as_ref().ok_or(SeqpacketError::Closed)?;
        self.peer.require_local_filesystem_path(fd.as_fd(), expected)
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
        let result = worker_send::observe_descriptor_send_v1(
            disposition.fd()?, payload, descriptors,
        ).into_legacy_result();
        match result {
            Ok(()) => {
                disposition.complete();
                Ok(())
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

    /// Receives a bounded root-mount reply through the strict shared engine.
    ///
    /// The fixed control profile retains credentials, a correlated kernel
    /// pidfd and zero or one transferred descriptor. A zero-rights error reply
    /// remains representable; authenticated Storage origin and exact successful
    /// reply semantics remain caller obligations. This creates no role grant.
    ///
    /// # Errors
    /// Retains malformed/oversized payload, ancillary and subject failures and
    /// fences fatal IO. Only initial nonconsuming EAGAIN/EINTR may retry.
    pub fn receive_root_mount_reply_retaining_v2(
        &mut self, maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_with_control(maximum_bytes.min(4096),
            SubjectProfileV1::Descriptors { expected: 1, allow_empty: true },
            uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80)
    }

    /// Bounds that same native root-mount reply before receiving or allocation.
    ///
    /// Counts captured hostile control slots, both native samples, endpoint
    /// probes, and strict-preview rights/subject pins. The caller separately
    /// pays its held endpoint, reply subject and complete enclosing lifetime.
    /// This is passive representation DATA, never financial admission.
    #[must_use]
    pub fn root_mount_reply_obligations_v2(maximum_bytes: usize) -> Option<(usize, usize)> {
        if maximum_bytes == 0 || maximum_bytes > 4096 { return None; }
        let control = uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80;
        let bytes = super::SeqpacketSocket::requested_receive_bytes(maximum_bytes, control, 2)
            .checked_add(std::mem::size_of::<OriginalObservationV1<'_>>())?
            .checked_add(std::mem::size_of::<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>())?;
        let files = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 3;
        Some((bytes, files))
    }

    /// Receives a fixed held-output reply with only its kernel record subject.
    ///
    /// This closed zero-rights profile uses the existing credentials/pidfd
    /// control recipe. It authenticates no Storage role, output or payer.
    /// Ordinary Standard receive and every descriptor-bearing profile remain
    /// unchanged, including their accepted descriptor tables and native order.
    ///
    /// # Errors
    /// Retains the actual native/subject/CTRUNC/forbidden-rights prefix and
    /// fences fatal IO. Only initial nonconsuming EAGAIN/EINTR can retry.
    pub fn receive_storage_held_output_reply_retaining_v2(
        &mut self, maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_with_control(maximum_bytes,
            SubjectProfileV1::Descriptors { expected: 0, allow_empty: false },
            uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80)
    }

    /// Bounds that same fixed zero-rights reply before native entry.
    ///
    /// The actual compiled control width covers credentials plus two aligned
    /// RawFd cmsgs. A valid reply has only credentials and one kernel pidfd;
    /// all rights, security labels, duplicates and unknown control already
    /// refuse. Hostile captured slots and kernel-discarded CTRUNC tails retain
    /// the SAME original native/error classification, without a role grant.
    #[must_use]
    pub fn storage_held_output_reply_obligations_v2(maximum_bytes: usize) -> Option<(usize, usize)> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_PACKET_BYTES { return None; }
        let control = uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80;
        // This closed recipe preallocates exactly two actual message cells.
        let bytes = super::SeqpacketSocket::requested_receive_bytes(maximum_bytes, control, 2)
            .checked_add(std::mem::size_of::<OriginalObservationV1<'_>>())?
            .checked_add(std::mem::size_of::<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>())?;
        // Raw FD-sized control cells, duplicate endpoint/probe and successful
        // preview subject remain covered even when consumed control truncates.
        let files = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 1;
        Some((bytes, files))
    }

    /// Receives exactly two Capture pipes with their original kernel subject.
    ///
    /// The existing closed worker control recipe covers credentials, the
    /// kernel pidfd and two ordered rights. The caller must still authenticate
    /// Storage and verify both FIFO roles. This grants no execution authority.
    ///
    /// # Errors
    /// Retains the same native/subject/CTRUNC/ancillary failure prefix. Only
    /// initial nonconsuming EAGAIN/EINTR can retry this original endpoint.
    pub fn receive_storage_capture_pipes_retaining_v2(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_with_control(
            maximum_bytes,
            SubjectProfileV1::Descriptors { expected: 2, allow_empty: false },
            uapi::ReceiveControlProfileV1::WorkerObserver,
        )
    }

    /// Bounds that exact two-pipe native receive before IO, as passive DATA.
    #[must_use]
    pub fn storage_capture_pipes_obligations_v2(maximum_bytes: usize) -> Option<(usize, usize)> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_PACKET_BYTES {
            return None;
        }
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let bytes = super::SeqpacketSocket::requested_receive_bytes(maximum_bytes, control, 2)
            .checked_add(std::mem::size_of::<OriginalObservationV1<'_>>())?
            .checked_add(std::mem::size_of::<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>())?;
        let files = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 3;
        Some((bytes, files))
    }

    /// Receives zero or two reply descriptors with original native retention.
    ///
    /// This uses the same existing reply profile and standard ancillary engine.
    /// Application success must still validate both ordered descriptor roles;
    /// an error reply must have no descriptors. It grants no service identity.
    ///
    /// # Errors
    /// Retains the original native/subject/framing refusal and fences fatal IO.
    pub fn receive_reply_retaining_v1(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_retaining(maximum_bytes,
            SubjectProfileV1::Descriptors { expected: 2, allow_empty: true })
    }

    /// Supplies the existing standard two-pin receive storage and FD bound.
    ///
    /// This DATA grants no receiver, descriptor role or funding authority.
    #[must_use]
    pub fn runtime_scope_receive_obligations_v1(maximum_bytes: usize) -> Option<(usize, usize)> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_PACKET_BYTES { return None; }
        let control = uapi::ReceiveControlProfileV1::Standard;
        // Standard starts with an empty message Vec; its first push reserves
        // four actual CapturedMessage cells. This differs from closed profiles
        // whose two-cell backing is allocated before entry.
        let bytes = super::SeqpacketSocket::requested_receive_bytes(maximum_bytes, control, 4)
            .checked_add(std::mem::size_of::<OriginalObservationV1<'_>>())?
            .checked_add(std::mem::size_of::<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>())?;
        // A malformed preview may hold the full actual ancillary table. The
        // consumed valid result holds at most two rights and one subject pin.
        let files = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 3;
        Some((bytes, files))
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

    /// Receives a fixed worker observer record through the strict shared engine.
    ///
    /// READY/request/export use4096 bytes; the closed pin-result sibling uses
    /// the existing16KiB protocol ceiling. Control contains credentials, one
    /// correlated kernel pidfd and at most two rights (80 bytes on 64-bit Linux).
    /// Malformed excess ancillary data retains its native truncation/error and
    /// fences this original. Existing general 512-byte profiles are unchanged.
    ///
    /// # Errors
    /// Retains native, ancillary, exact-table and subject failures. Only an
    /// initial nonconsuming EAGAIN/EINTR may retry the original endpoint.
    pub fn receive_worker_observer_retaining_v1(
        &mut self,
        kind: WorkerObserverRecordKindV1,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let profile = match kind {
            WorkerObserverRecordKindV1::ReadyOrResult | WorkerObserverRecordKindV1::PinResult
                | WorkerObserverRecordKindV1::GuestRootPublicationRequestV2
                | WorkerObserverRecordKindV1::GuestRootPublicationResultV2
                | WorkerObserverRecordKindV1::GuestRootStartupHealthV2 =>
                SubjectProfileV1::Descriptors { expected: 0, allow_empty: false },
            WorkerObserverRecordKindV1::ExportReply =>
                SubjectProfileV1::Descriptors { expected: 1, allow_empty: true },
            WorkerObserverRecordKindV1::Request =>
                SubjectProfileV1::Descriptors { expected: 2, allow_empty: false },
        };
        self.receive_profile_with_control(
            kind.maximum_payload_bytes_v1(), profile, uapi::ReceiveControlProfileV1::WorkerObserver,
        )
    }

    /// Returns requested worker receive bytes and simultaneous FD slots as DATA.
    ///
    /// The fixed recipe covers either retained sample, partial native failures
    /// and the original adapter/result stack. Endpoint, peer and surrounding
    /// workspace owners remain separately priced by the genuine service payer.
    /// Allocator slack and kernel resources retain the same native backstop.
    #[must_use]
    pub fn worker_observer_receive_obligations_v1() -> (usize, usize) {
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let bytes = super::SeqpacketSocket::requested_receive_bytes(4096, control, 2)
            + std::mem::size_of::<OriginalObservationV1<'_>>()
            + std::mem::size_of::<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>();
        // Successful strict preview holds at most two rights+one subject pin.
        // Failed preview never reaches the consumed native observation.
        let files = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 3;
        (bytes, files)
    }

    /// Prices the selected fixed descriptor-worker record and retained raw failure.
    ///
    /// This passive shape grants no payer, descriptor role or worker authority.
    #[must_use]
    pub fn worker_descriptor_receive_obligations_v1(kind: WorkerObserverRecordKindV1) -> (usize, usize) {
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let bytes = super::SeqpacketSocket::requested_receive_bytes(kind.maximum_payload_bytes_v1(), control, 2)
            + std::mem::size_of::<OriginalObservationV1<'_>>()
            + std::mem::size_of::<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>();
        let files = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 3;
        (bytes, files)
    }

    /// Counts fixed raw receive, binding and original-retention destinations.
    ///
    /// No scalar supplied here grants receive or service permission.
    #[must_use]
    pub fn worker_descriptor_receive_metadata_cells_v1() -> Option<usize> {
        super::SeqpacketSocket::requested_receive_metadata_cells_v1(
            uapi::ReceiveControlProfileV1::WorkerObserver,
        )?.checked_add(3 + 4 + 2)
    }

    fn receive_profile_retaining(
        &mut self,
        maximum: usize,
        profile: SubjectProfileV1,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_with_control(maximum, profile, uapi::ReceiveControlProfileV1::Standard)
    }

    fn receive_profile_with_control(
        &mut self,
        maximum: usize,
        profile: SubjectProfileV1,
        control: uapi::ReceiveControlProfileV1,
    ) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_with_cutoff_v4(maximum, profile, control, None)
    }

    pub(super) fn receive_profile_with_cutoff_v4(
        &mut self,
        maximum: usize,
        profile: SubjectProfileV1,
        control: uapi::ReceiveControlProfileV1,
        cutoff: Option<super::NetworkWorkerNativeCutoffV4>,
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
            if let Some(mode) = &self.zero_rights {
                if mode.restore.is_some() {
                    return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed));
                }
                uapi::require_seqpacket_zero_rights(fd)
                    .map_err(SeqpacketError::from)
                    .map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
            }
            let attempt = ReceiveAttemptV1::capture_with_network_cutoff_v4(
                fd, self.peer.socket_cookie(), control, cutoff,
            )?;
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

    /// Moves Network's three birth donations while retaining packet and subject.
    ///
    /// This moves DATA custody only. The genuine Source borrower separately
    /// authenticates PID1 and joins the actual PIDFD, cgroup and events roles.
    /// An inexact table remains untouched, including every failed prefix.
    #[must_use]
    pub fn take_network_birth_handoff_descriptors_data_v2(&mut self) -> Option<Vec<OwnedFd>> {
        if self.descriptors.len() != 3 {
            return None;
        }
        Some(std::mem::take(&mut self.descriptors))
    }

    /// Moves the nine child-origin donations while retaining packet and PID1 pin.
    ///
    /// This is DATA custody only. The child factory must independently verify
    /// every actual role, original Source and prepaid native programme. An
    /// inexact table remains untouched, including every failed prefix.
    #[must_use]
    pub fn take_network_child_origin_descriptors_data_v2(&mut self) -> Option<Vec<OwnedFd>> {
        if self.descriptors.len() != 9 { return None; }
        Some(std::mem::take(&mut self.descriptors))
    }

    /// Moves the six exact O public-input carriers while retaining this record.
    ///
    /// This checks only the closed AOSNOH03 DATA geometry. The original native
    /// Source subject, payload and socket-origin stamp remain resident for
    /// independent posts; no credential role, lease, D or authority is adopted.
    /// Every malformed prefix remains untouched on this same record.
    #[must_use]
    pub fn take_network_observer_handoff_descriptors_data_v2(&mut self) -> Option<Vec<OwnedFd>> {
        let bytes = &self.payload;
        if bytes.len() < 528 || bytes[..8] != *b"AOSNOH03"
            || bytes[8..10] != 3_u16.to_be_bytes()
            || bytes[10..12] != 2_u16.to_be_bytes()
            || u32::from_be_bytes(bytes[12..16].try_into().ok()?) as usize != bytes.len()
            || bytes[188..192].iter().any(|byte| *byte != 0)
            || self.descriptors.len() != 6
        { return None; }
        let mut total = 528_usize;
        for offset in (152..188).step_by(4) {
            let length = usize::try_from(u32::from_be_bytes(
                bytes[offset..offset + 4].try_into().ok()?)).ok()?;
            total = total.checked_add(length)?;
        }
        if total != bytes.len() { return None; }
        Some(std::mem::take(&mut self.descriptors))
    }

    /// Moves the sole preparation descriptor while retaining its original packet.
    ///
    /// This is only a DATA ownership handoff. The caller must first complete
    /// authenticated method/role checks and pay the sealed-file reader.
    #[must_use]
    pub fn take_fixed_service_preparation_descriptor_data_v4(&mut self) -> Option<OwnedFd> {
        self.take_single_descriptor_data()
    }

    /// Moves the registration's sole descriptor as DATA, without adopting a child.
    ///
    /// The actual Guest caller separately joins the original root subject,
    /// typed pidfd, admitted child, installation and same socket.
    #[must_use]
    pub fn take_guest_monitor_child_descriptor_data_v2(&mut self) -> Option<OwnedFd> {
        self.take_single_descriptor_data()
    }

    fn take_single_descriptor_data(&mut self) -> Option<OwnedFd> {
        if self.descriptors.len() != 1 {
            return None;
        }
        self.descriptors.pop()
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


#[cfg(test)]
mod worker_observer_profile_tests {
    use super::*;
    use crate::seqpacket::SeqpacketSocket;

    #[test]
    fn fixed_worker_request_preserves_two_real_descriptors_and_full_payload() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/zero").unwrap();
        sender.send_with_descriptors(&[7; 4096], &[first.as_fd(), second.as_fd()]).unwrap();

        let record = receiver.receive_worker_observer_retaining_v1(
            WorkerObserverRecordKindV1::Request,
        ).unwrap();

        assert_eq!(record.payload(), &[7; 4096]);
        assert_eq!(record.descriptors().len(), 2);
        for (received, original) in record.descriptors().iter().zip([&first, &second]) {
            let received = rustix::fs::fstat(received).unwrap();
            let original = rustix::fs::fstat(original).unwrap();
            assert_eq!((received.st_dev, received.st_ino), (original.st_dev, original.st_ino));
        }
    }

    #[test]
    fn fixed_worker_rejects_excess_rights_and_fences_original_channel() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(&[9; 313], &[original.as_fd(); 5]).unwrap();

        let rejected = receiver.receive_worker_observer_retaining_v1(
            WorkerObserverRecordKindV1::ReadyOrResult,
        );

        assert!(rejected.is_err());
        assert!(receiver.as_fd().is_err());
    }

    #[test]
    fn fixed_export_retains_existing_zero_descriptor_error_reply() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send(&[3; 313]).unwrap();

        let record = receiver.receive_worker_observer_retaining_v1(
            WorkerObserverRecordKindV1::ExportReply,
        ).unwrap();

        assert_eq!(record.payload(), &[3; 313]);
        assert!(record.descriptors().is_empty());
    }
}

#[cfg(test)]
mod storage_held_output_control_tests {
    use std::os::fd::AsFd as _;
    use super::*;
    use crate::seqpacket::SeqpacketSocket;

    #[test]
    fn legitimate_held_reply_keeps_complete_payload_and_real_kernel_subject() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send(&[7; 248]).unwrap();

        let record = receiver.receive_storage_held_output_reply_retaining_v2(248).unwrap();

        assert_eq!(record.payload(), &[7; 248]);
        assert!(record.descriptors().is_empty());
        assert_eq!(record.subject().credentials().pid().get(), std::process::id());
        assert!(record.subject().is_alive().unwrap());
    }

    #[test]
    fn hostile_rights_reach_native_truncation_and_keep_the_fenced_error() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        // The raw native fixture deliberately bypasses the public sender's
        // five-right table limit, so this actually reaches hostile CTRUNC.
        crate::uapi::send_seqpacket_rights(sender.as_fd(), &[8; 248], &[original.as_fd(); 32]).unwrap();

        let error = receiver.receive_storage_held_output_reply_retaining_v2(248).unwrap_err();

        assert!(receiver.as_fd().is_err());
        assert!(!error.is_nonconsuming_would_block());
        assert!(!error.is_nonconsuming_interrupted());
        assert!(matches!(std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::ControlTruncated)));
    }
}

#[cfg(test)]
mod raw_admission_tests {
    use super::*;
    use crate::seqpacket::RecordSubjectListener;

    #[test]
    fn root_mount_client_and_server_share_actual_pinned_peer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("root-export.sock");
        let mut listener = RecordSubjectListener::bind(&path, 4).unwrap();

        let client = DescriptorSubjectSocket::connect_retaining_raw_v2(&path).unwrap();
        let server = listener.accept_storage_root_export_retaining_v2().unwrap();

        assert_eq!(client.peer().credentials().pid().get(), std::process::id());
        assert_eq!(server.peer().credentials().pid().get(), std::process::id());
        assert!(client.peer().is_alive().unwrap());
        assert!(server.peer().is_alive().unwrap());
        assert_eq!(DescriptorSubjectSocket::retaining_raw_admission_obligations_v2().unwrap().1, 2);
    }

    #[test]
    fn rejected_root_mount_path_keeps_original_precreation_taxonomy() {
        let failure = DescriptorSubjectSocket::connect_retaining_raw_v2(Path::new("relative.sock")).unwrap_err();

        assert!(!failure.retains_descriptor());
        assert!(!failure.shutdown_attempted());
        assert!(matches!(failure.cause(), SeqpacketError::Kernel(_)));
    }
}


#[cfg(test)]
mod root_mount_reply_tests {
    use super::*;
    use crate::seqpacket::SeqpacketSocket;

    #[test]
    fn root_reply_keeps_actual_transferred_file_and_complete_payload() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(&[7; 112], &[original.as_fd()]).unwrap();

        let record = receiver.receive_root_mount_reply_retaining_v2(112).unwrap();

        assert_eq!(record.payload(), &[7; 112]);
        assert_eq!(record.descriptors().len(), 1);
        let observed = rustix::fs::fstat(&record.descriptors()[0]).unwrap();
        let expected = rustix::fs::fstat(&original).unwrap();
        assert_eq!((observed.st_dev, observed.st_ino), (expected.st_dev, expected.st_ino));
    }

    #[test]
    fn excess_rights_fence_the_same_root_reply_channel() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(&[9; 112], &[original.as_fd(); 5]).unwrap();

        let rejected = receiver.receive_root_mount_reply_retaining_v2(112);

        assert!(rejected.is_err());
        assert!(receiver.as_fd().is_err());
        assert!(DescriptorSubjectSocket::root_mount_reply_obligations_v2(4097).is_none());
    }
}

#[cfg(test)]
mod storage_capture_pipe_control_tests {
    use super::*;
    use crate::seqpacket::SeqpacketSocket;
    use std::os::fd::AsFd as _;

    #[test]
    fn ordered_capture_pipes_keep_the_actual_rights_and_kernel_subject() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        let (_stdout_read, stdout_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (_stderr_read, stderr_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        sender.send_with_descriptors(&[7; 248], &[stdout_write.as_fd(), stderr_write.as_fd()]).unwrap();

        let record = receiver.receive_storage_capture_pipes_retaining_v2(248).unwrap();

        assert_eq!(record.payload(), &[7; 248]);
        assert_eq!(record.descriptors().len(), 2);
        assert_eq!(record.subject().credentials().pid().get(), std::process::id());
        for (received, sent) in record.descriptors().iter().zip([&stdout_write, &stderr_write]) {
            let actual = rustix::fs::fstat(received).unwrap();
            let original = rustix::fs::fstat(sent).unwrap();
            assert_eq!((actual.st_dev, actual.st_ino), (original.st_dev, original.st_ino));
            assert_eq!(rustix::fs::FileType::from_raw_mode(actual.st_mode), rustix::fs::FileType::Fifo);
        }
    }

    #[test]
    fn hostile_capture_rights_keep_the_actual_ctrunc_failure() {
        let (receiver, sender) = crate::uapi::seqpacket_pair().unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap();
        let original = std::fs::File::open("/dev/null").unwrap();
        crate::uapi::send_seqpacket_rights(sender.as_fd(), &[8; 248], &[original.as_fd(); 32]).unwrap();

        let failure = receiver.receive_storage_capture_pipes_retaining_v2(248).unwrap_err();

        assert!(receiver.as_fd().is_err());
        assert!(!failure.is_nonconsuming_would_block());
        assert!(!failure.is_nonconsuming_interrupted());
        assert!(matches!(std::error::Error::source(&failure)
            .and_then(|cause| cause.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::ControlTruncated)));
    }
}
