//! Systemd-activated admission boundary for existing Network resources.
//!
//! The broker authenticates the exact lifecycle dispatch before opening the
//! worker exchange. A fresh private-Network worker then canonical-decodes those
//! same bytes and correlates the sole transferred descriptor with the claimed
//! target identity. The worker receives no authority or journal credential and
//! performs no replay claim, namespace entry, or kernel mutation.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::{
    NamespaceFd, NamespaceIdentity, NamespaceKind, SingleThreadedProcess,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::lifecycle_worker_process::{
    NetworkLifecycleWorkerAdmittedV1, NetworkLifecycleWorkerBootstrapReadyV1,
    NetworkLifecycleWorkerChallengeV1, revalidate_lifecycle_worker_before_dispatch,
    validate_lifecycle_worker_ready, validate_same_lifecycle_worker,
};
use crate::lifecycle_worker_protocol::{
    MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES, NetworkLifecycleWorkerDispatchV1,
};
use crate::namespace_store::RetainedNetworkNamespace;
use crate::worker_process::{
    NetworkWorkerProcessError, validate_broker_peer, validate_broker_subject,
    validate_systemd_manager_peer,
};
use crate::worker_protocol::NetworkWorkerProtocolError;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const FRAME_MAGIC: &[u8; 8] = b"AOSNLF01";
const FRAME_VERSION: u16 = 1;
const FRAME_KIND: u8 = 4;
const MUTATION_ROLE: u8 = 1;
const FRAME_FIRST: u16 = 1;
const FRAME_FINAL: u16 = 2;
const FRAME_HEADER_BYTES: usize = 140;
const MAXIMUM_FRAME_BYTES: usize = 64 * 1024;
const MAXIMUM_FRAME_PAYLOAD_BYTES: usize = MAXIMUM_FRAME_BYTES - FRAME_HEADER_BYTES;
const MAXIMUM_CHALLENGE_BYTES: usize = 132;
const MAXIMUM_READY_BYTES: usize = 664;
const MAXIMUM_ACK_BYTES: usize = 164;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);
const NATURAL_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
const QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnretainedWorkerBoundary {
    Connect,
    ManagerPeer,
    ChallengeTransfer,
    ReadyTransfer,
    ReadyDecode,
    ReadyCorrelation,
    ReadyDescriptors,
    ReadyAuthority,
}

impl UnretainedWorkerBoundary {
    const fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::ManagerPeer => "manager peer",
            Self::ChallengeTransfer => "challenge transfer",
            Self::ReadyTransfer => "READY transfer",
            Self::ReadyDecode => "READY decode",
            Self::ReadyCorrelation => "READY correlation",
            Self::ReadyDescriptors => "READY descriptor count",
            Self::ReadyAuthority => "READY process authority",
        }
    }
}

struct UnretainedWorkerFailure {
    boundary: UnretainedWorkerBoundary,
    error: NetworkLifecycleWorkerRuntimeError,
}

trait LifecycleAdmissionOperations {
    type Connection;
    type ReadyRecord;
    type Ready;
    type Retained;
    type Admitted;

    fn connect(&mut self) -> Result<Self::Connection, NetworkLifecycleWorkerRuntimeError>;

    fn validate_manager_peer(
        &mut self,
        connection: &Self::Connection,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError>;

    fn transfer_challenge(
        &mut self,
        connection: &mut Self::Connection,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError>;

    fn receive_ready(
        &mut self,
        connection: &mut Self::Connection,
    ) -> Result<Self::ReadyRecord, NetworkLifecycleWorkerRuntimeError>;

    fn decode_ready(
        &mut self,
        record: &Self::ReadyRecord,
    ) -> Result<Self::Ready, NetworkLifecycleWorkerRuntimeError>;

    fn correlate_ready(
        &mut self,
        ready: &Self::Ready,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError>;

    fn validate_ready_descriptors(
        &mut self,
        record: &Self::ReadyRecord,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError>;

    fn retain_ready_authority(
        &mut self,
        record: Self::ReadyRecord,
        ready: Self::Ready,
    ) -> Result<Self::Retained, NetworkLifecycleWorkerRuntimeError>;

    fn close(&mut self, connection: &mut Self::Connection);

    fn complete_after_retention(
        &mut self,
        connection: &mut Self::Connection,
        retained: Self::Retained,
        fail_stopped: &mut bool,
    ) -> Result<Self::Admitted, NetworkLifecycleWorkerRuntimeError>;
}

impl UnretainedWorkerFailure {
    const fn new(
        boundary: UnretainedWorkerBoundary,
        error: NetworkLifecycleWorkerRuntimeError,
    ) -> Self {
        Self { boundary, error }
    }
}

/// Reports rejected lifecycle-worker admission or unproved process exit.
#[derive(Debug, thiserror::Error)]
pub enum NetworkLifecycleWorkerRuntimeError {
    /// A bounded admission record, frame, path, or transition was invalid.
    #[error("Network lifecycle worker runtime protocol is invalid: {0}")]
    Protocol(&'static str),
    /// The broker-side authenticated dispatch did not match retained custody.
    #[error("Network lifecycle worker dispatch authority did not match")]
    Authority,
    /// A lifecycle worker could not be proved completely stopped.
    #[error("Network lifecycle worker whole-unit quiescence failed: {0}")]
    Quiescence(String),
    /// The process and cgroup protocol rejected a peer or record.
    #[error(transparent)]
    Process(#[from] NetworkWorkerProcessError),
    /// The canonical lifecycle dispatch was rejected.
    #[error(transparent)]
    Worker(#[from] NetworkWorkerProtocolError),
    /// The bounded descriptor-subject transport failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// A typed Linux descriptor, namespace, cgroup, or process check failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A fixed procfs read failed.
    #[error("Network lifecycle worker local I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A local kernel I/O operation failed.
    #[error("Network lifecycle worker kernel I/O failed: {0}")]
    KernelIo(#[from] rustix::io::Errno),
}

/// Correlates successful admission after the worker process wholly exits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedNetworkLifecycleWorkerV1 {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    dispatch_digest: ObjectDigest,
    bootstrap_namespace: NamespaceIdentity,
    target_namespace: NamespaceIdentity,
}

impl AdmittedNetworkLifecycleWorkerV1 {
    /// Returns the request identity carried by the broker-authenticated dispatch.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the lifecycle effect digest carried by the exact dispatch.
    #[must_use]
    pub const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the digest of the exact canonical dispatch bytes transferred.
    #[must_use]
    pub const fn dispatch_digest(self) -> ObjectDigest {
        self.dispatch_digest
    }

    /// Returns the fresh worker bootstrap namespace identity.
    #[must_use]
    pub const fn bootstrap_namespace(self) -> NamespaceIdentity {
        self.bootstrap_namespace
    }

    /// Returns the target identity measured from the transferred descriptor.
    #[must_use]
    pub const fn target_namespace(self) -> NamespaceIdentity {
        self.target_namespace
    }
}

/// Admits exact lifecycle bytes and one retained target through a fresh worker.
pub struct SystemdNetworkLifecycleAdmissionExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: RetainedCgroupAnchor,
    worker_parent_cgroup: RetainedCgroupAnchor,
    host_namespace: NamespaceFd,
    fail_stopped: bool,
}

impl SystemdNetworkLifecycleAdmissionExecutor {
    /// Retains the trusted host namespace and fixed manager cgroup roots.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket path, substituted host namespace,
    /// or unavailable manager/control-slice cgroup.
    pub fn new(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
        host_namespace: NamespaceFd,
    ) -> Result<Self, NetworkLifecycleWorkerRuntimeError> {
        if !normalized_absolute_path(&socket_path) {
            return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
                "unsafe lifecycle worker socket path",
            ));
        }
        host_namespace.validate_current_network()?;
        Ok(Self {
            socket_path,
            systemd_manager_cgroup: cgroup_root.resolve(Path::new(SYSTEMD_MANAGER_CGROUP))?,
            worker_parent_cgroup: cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?,
            host_namespace,
            fail_stopped: false,
        })
    }

    /// Runs one admission-only exchange and proves whole-worker quiescence.
    ///
    /// The exact dispatch is authenticated against retained custody before the
    /// challenge or descriptor is sent. Success proves process/transport
    /// admission only; it does not authorize or report a lifecycle effect.
    ///
    /// # Errors
    ///
    /// Returns an error for dispatch or target mismatch, activation/record
    /// substitution, malformed framing, descriptor substitution, timeout, or
    /// unproved worker exit. Failure to prove cancellation permanently
    /// fail-stops this executor.
    pub fn admit_once(
        &mut self,
        authority: &NetworkAuthorityV1,
        dispatch: &NetworkLifecycleWorkerDispatchV1,
        target: &RetainedNetworkNamespace,
    ) -> Result<AdmittedNetworkLifecycleWorkerV1, NetworkLifecycleWorkerRuntimeError> {
        ensure_executor_available(self.fail_stopped)?;
        self.host_namespace.validate_current_network()?;
        let target_namespace = retype_network_namespace(target.as_fd())?;
        if target_namespace.identity() == self.host_namespace.identity() {
            return Err(NetworkLifecycleWorkerRuntimeError::Authority);
        }

        let dispatch_bytes = dispatch.encode()?;
        let exact_dispatch = NetworkLifecycleWorkerDispatchV1::decode(&dispatch_bytes)?;
        exact_dispatch.authenticate_target_association(
            authority,
            target.network_handle(),
            target_namespace.identity(),
        )?;
        let dispatch_digest = ObjectDigest::from_bytes(Sha256::digest(&dispatch_bytes).into());
        let challenge = NetworkLifecycleWorkerChallengeV1::new(
            random_nonce()?,
            dispatch_digest,
            dispatch.request_id(),
            dispatch.effect_digest(),
        )?;

        let mut admission = SystemdLifecycleAdmission {
            socket_path: &self.socket_path,
            systemd_manager_cgroup: &self.systemd_manager_cgroup,
            worker_parent_cgroup: &self.worker_parent_cgroup,
            host_namespace: &self.host_namespace,
            target_namespace: &target_namespace,
            dispatch_bytes: &dispatch_bytes,
            dispatch_digest,
            challenge,
        };
        execute_lifecycle_admission(&mut admission, &mut self.fail_stopped)
    }
}

struct SystemdLifecycleAdmission<'a> {
    socket_path: &'a Path,
    systemd_manager_cgroup: &'a RetainedCgroupAnchor,
    worker_parent_cgroup: &'a RetainedCgroupAnchor,
    host_namespace: &'a NamespaceFd,
    target_namespace: &'a NamespaceFd,
    dispatch_bytes: &'a [u8],
    dispatch_digest: ObjectDigest,
    challenge: NetworkLifecycleWorkerChallengeV1,
}

impl LifecycleAdmissionOperations for SystemdLifecycleAdmission<'_> {
    type Connection = DescriptorSubjectSocket;
    type ReadyRecord = ReceivedDescriptorRecord;
    type Ready = NetworkLifecycleWorkerBootstrapReadyV1;
    type Retained = (
        KernelAuthorizedRecordSubject,
        RetainedCgroupAnchor,
        NamespaceFd,
    );
    type Admitted = AdmittedNetworkLifecycleWorkerV1;

    fn connect(&mut self) -> Result<Self::Connection, NetworkLifecycleWorkerRuntimeError> {
        DescriptorSubjectSocket::connect(self.socket_path).map_err(Into::into)
    }

    fn validate_manager_peer(
        &mut self,
        connection: &Self::Connection,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
        validate_systemd_manager_peer(connection.peer(), self.systemd_manager_cgroup)
            .map_err(Into::into)
    }

    fn transfer_challenge(
        &mut self,
        connection: &mut Self::Connection,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
        send_record_before(
            connection,
            &self.challenge.encode(),
            deadline_after(TRANSFER_TIMEOUT)?,
        )
    }

    fn receive_ready(
        &mut self,
        connection: &mut Self::Connection,
    ) -> Result<Self::ReadyRecord, NetworkLifecycleWorkerRuntimeError> {
        receive_record_before(
            connection,
            MAXIMUM_READY_BYTES,
            0,
            deadline_after(TRANSFER_TIMEOUT)?,
        )
    }

    fn decode_ready(
        &mut self,
        record: &Self::ReadyRecord,
    ) -> Result<Self::Ready, NetworkLifecycleWorkerRuntimeError> {
        NetworkLifecycleWorkerBootstrapReadyV1::decode(record.payload()).map_err(Into::into)
    }

    fn correlate_ready(
        &mut self,
        ready: &Self::Ready,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
        if ready.challenge() != self.challenge {
            return Err(NetworkLifecycleWorkerRuntimeError::Authority);
        }
        Ok(())
    }

    fn validate_ready_descriptors(
        &mut self,
        record: &Self::ReadyRecord,
    ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
        if !record.descriptors().is_empty() {
            return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
                "lifecycle READY transferred a descriptor",
            ));
        }
        Ok(())
    }

    fn retain_ready_authority(
        &mut self,
        record: Self::ReadyRecord,
        ready: Self::Ready,
    ) -> Result<Self::Retained, NetworkLifecycleWorkerRuntimeError> {
        let (ready_bytes, ready_subject, ready_descriptors) = record.into_parts();
        drop((ready_bytes, ready_descriptors));
        let (worker_cgroup, bootstrap_namespace) = validate_lifecycle_worker_ready(
            &ready,
            &ready_subject,
            self.worker_parent_cgroup,
            self.host_namespace,
            self.target_namespace,
        )?;
        Ok((ready_subject, worker_cgroup, bootstrap_namespace))
    }

    fn close(&mut self, connection: &mut Self::Connection) {
        connection.close();
    }

    fn complete_after_retention(
        &mut self,
        connection: &mut Self::Connection,
        retained: Self::Retained,
        fail_stopped: &mut bool,
    ) -> Result<Self::Admitted, NetworkLifecycleWorkerRuntimeError> {
        let (ready_subject, worker_cgroup, bootstrap_namespace) = retained;
        let population = retain_population_or_fail_stop(&worker_cgroup, fail_stopped)?;

        let exchange = exchange_after_ready(
            connection,
            self.dispatch_bytes,
            self.challenge,
            self.target_namespace.as_fd(),
            &ready_subject,
            &worker_cgroup,
            &bootstrap_namespace,
            self.target_namespace.identity(),
        );
        finish_exchange(
            exchange,
            &ready_subject,
            &worker_cgroup,
            &population,
            fail_stopped,
        )?;

        Ok(AdmittedNetworkLifecycleWorkerV1 {
            request_id: self.challenge.request_id(),
            effect_digest: self.challenge.effect_digest(),
            dispatch_digest: self.dispatch_digest,
            bootstrap_namespace: bootstrap_namespace.identity(),
            target_namespace: self.target_namespace.identity(),
        })
    }
}

fn execute_lifecycle_admission<Operations>(
    operations: &mut Operations,
    fail_stopped: &mut bool,
) -> Result<Operations::Admitted, NetworkLifecycleWorkerRuntimeError>
where
    Operations: LifecycleAdmissionOperations,
{
    ensure_executor_available(*fail_stopped)?;
    let mut connection = match operations.connect() {
        Ok(connection) => connection,
        Err(error) => {
            return fail_unretained_worker(fail_stopped, UnretainedWorkerBoundary::Connect, error);
        }
    };

    let retained = (|| {
        operations
            .validate_manager_peer(&connection)
            .map_err(|error| {
                UnretainedWorkerFailure::new(UnretainedWorkerBoundary::ManagerPeer, error)
            })?;
        operations
            .transfer_challenge(&mut connection)
            .map_err(|error| {
                UnretainedWorkerFailure::new(UnretainedWorkerBoundary::ChallengeTransfer, error)
            })?;
        let ready_record = operations.receive_ready(&mut connection).map_err(|error| {
            UnretainedWorkerFailure::new(UnretainedWorkerBoundary::ReadyTransfer, error)
        })?;
        let ready = operations.decode_ready(&ready_record).map_err(|error| {
            UnretainedWorkerFailure::new(UnretainedWorkerBoundary::ReadyDecode, error)
        })?;
        operations.correlate_ready(&ready).map_err(|error| {
            UnretainedWorkerFailure::new(UnretainedWorkerBoundary::ReadyCorrelation, error)
        })?;
        operations
            .validate_ready_descriptors(&ready_record)
            .map_err(|error| {
                UnretainedWorkerFailure::new(UnretainedWorkerBoundary::ReadyDescriptors, error)
            })?;
        operations
            .retain_ready_authority(ready_record, ready)
            .map_err(|error| {
                UnretainedWorkerFailure::new(UnretainedWorkerBoundary::ReadyAuthority, error)
            })
    })();
    let retained = match retained {
        Ok(retained) => retained,
        Err(failure) => {
            operations.close(&mut connection);
            return fail_unretained_worker(fail_stopped, failure.boundary, failure.error);
        }
    };

    operations.complete_after_retention(&mut connection, retained, fail_stopped)
}

/// Runs one inherited admission-only lifecycle worker.
///
/// PID 1 supplies the connected socket and creates the process in a fresh
/// private Network namespace. The function first receives the broker's
/// challenge, correlates one exact target descriptor, sends an unkeyed
/// admission ACK, and returns immediately. It accepts no configuration or
/// authority path.
///
/// # Errors
///
/// Returns an error unless the process is single-threaded, both process user
/// identities are root, the broker and every record subject remain exact, all
/// records are canonical, the sole descriptor is a distinct Network namespace
/// matching the claimed dispatch target, and the acknowledgement is
/// transferred before exit.
pub fn run_inherited_network_lifecycle_admission_worker()
-> Result<(), NetworkLifecycleWorkerRuntimeError> {
    let worker = SingleThreadedProcess::verify()?;
    worker.disable_core_dumps()?;
    validate_initial_descriptor_table()?;
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }
    let cgroup_root = open_cgroup_root()?;
    let control_cgroup = cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?;
    let bootstrap_namespace = NamespaceFd::current_network()?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;
    validate_broker_peer(socket.peer(), &control_cgroup)?;

    let challenge_record = receive_record_before(
        &mut socket,
        MAXIMUM_CHALLENGE_BYTES,
        0,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    validate_broker_subject(socket.peer(), challenge_record.subject(), &control_cgroup)?;
    let challenge = NetworkLifecycleWorkerChallengeV1::decode(challenge_record.payload())?;

    let ready = NetworkLifecycleWorkerBootstrapReadyV1::new(
        challenge,
        bootstrap_namespace.identity(),
        current_cgroup()?,
    )?;
    send_record_before(
        &mut socket,
        &ready.encode()?,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;

    let (dispatch_bytes, target_namespace) = receive_dispatch_before(
        &mut socket,
        challenge,
        &control_cgroup,
        &bootstrap_namespace,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    let dispatch = NetworkLifecycleWorkerDispatchV1::decode(&dispatch_bytes)?;
    if dispatch.request_id() != challenge.request_id()
        || dispatch.effect_digest() != challenge.effect_digest()
        || dispatch.claimed_target_namespace().namespace_device()
            != target_namespace.identity().device
        || dispatch.claimed_target_namespace().namespace_inode()
            != target_namespace.identity().inode
    {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }
    bootstrap_namespace.validate_current_network()?;

    let admitted = NetworkLifecycleWorkerAdmittedV1::new(
        challenge,
        bootstrap_namespace.identity(),
        target_namespace.identity(),
    )?;
    send_record_before(
        &mut socket,
        &admitted.encode(),
        deadline_after(TRANSFER_TIMEOUT)?,
    )
}

fn exchange_after_ready(
    socket: &mut DescriptorSubjectSocket,
    dispatch: &[u8],
    challenge: NetworkLifecycleWorkerChallengeV1,
    target: BorrowedFd<'_>,
    ready_subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
    bootstrap_namespace: &NamespaceFd,
    target_identity: NamespaceIdentity,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    revalidate_lifecycle_worker_before_dispatch(ready_subject, worker_cgroup, bootstrap_namespace)?;
    let retyped_target = retype_network_namespace(target)?;
    if retyped_target.identity() != target_identity {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }
    send_dispatch_before(
        socket,
        dispatch,
        challenge,
        target,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    let acknowledgement = receive_record_before(
        socket,
        MAXIMUM_ACK_BYTES,
        0,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    validate_same_lifecycle_worker(
        ready_subject,
        acknowledgement.subject(),
        worker_cgroup,
        bootstrap_namespace,
    )?;
    if retype_network_namespace(target)?.identity() != target_identity {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }
    let admitted = NetworkLifecycleWorkerAdmittedV1::decode(acknowledgement.payload())?;
    if admitted.challenge() != challenge
        || admitted.bootstrap() != bootstrap_namespace.identity()
        || admitted.target() != target_identity
    {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }
    Ok(())
}

fn send_dispatch_before(
    socket: &mut DescriptorSubjectSocket,
    dispatch: &[u8],
    challenge: NetworkLifecycleWorkerChallengeV1,
    target: BorrowedFd<'_>,
    deadline: u64,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    if dispatch.is_empty() || dispatch.len() > MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle dispatch length is invalid",
        ));
    }
    let mut offset = 0;
    while offset < dispatch.len() {
        let end = dispatch
            .len()
            .min(offset.saturating_add(MAXIMUM_FRAME_PAYLOAD_BYTES));
        let frame = encode_frame(dispatch, challenge, offset, end)?;
        if offset == 0 {
            send_record_with_descriptors_before(socket, &frame, &[target], deadline)?;
        } else {
            send_record_before(socket, &frame, deadline)?;
        }
        offset = end;
    }
    ensure_before_deadline(deadline)
}

fn receive_dispatch_before(
    socket: &mut DescriptorSubjectSocket,
    challenge: NetworkLifecycleWorkerChallengeV1,
    control_cgroup: &RetainedCgroupAnchor,
    bootstrap_namespace: &NamespaceFd,
    deadline: u64,
) -> Result<(Vec<u8>, NamespaceFd), NetworkLifecycleWorkerRuntimeError> {
    let first = receive_record_before(socket, MAXIMUM_FRAME_BYTES, 1, deadline)?;
    validate_broker_subject(socket.peer(), first.subject(), control_cgroup)?;
    let (first_bytes, _first_subject, mut descriptors) = first.into_parts();
    let first_frame = decode_frame(&first_bytes)?;
    validate_initial_dispatch_frame(&first_frame, challenge)?;
    let descriptor = descriptors
        .pop()
        .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle target descriptor is absent",
        ))?;
    if !descriptors.is_empty() {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle dispatch transferred extra descriptors",
        ));
    }
    let target = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)?;
    if target.identity() == bootstrap_namespace.identity() {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }

    let mut dispatch = Vec::with_capacity(first_frame.total);
    dispatch.extend_from_slice(first_frame.payload);
    while dispatch.len() < first_frame.total {
        let record = receive_record_before(socket, MAXIMUM_FRAME_BYTES, 0, deadline)?;
        validate_broker_subject(socket.peer(), record.subject(), control_cgroup)?;
        let frame = decode_frame(record.payload())?;
        if frame.challenge != challenge
            || frame.flags & FRAME_FIRST != 0
            || frame.total != first_frame.total
            || frame.offset != dispatch.len()
        {
            return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
                "lifecycle continuation frame is inconsistent",
            ));
        }
        dispatch.extend_from_slice(frame.payload);
    }
    if ObjectDigest::from_bytes(Sha256::digest(&dispatch).into()) != challenge.dispatch_digest() {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }
    ensure_before_deadline(deadline)?;
    Ok((dispatch, target))
}

struct DecodedFrame<'a> {
    flags: u16,
    total: usize,
    offset: usize,
    challenge: NetworkLifecycleWorkerChallengeV1,
    payload: &'a [u8],
}

fn encode_frame(
    dispatch: &[u8],
    challenge: NetworkLifecycleWorkerChallengeV1,
    offset: usize,
    end: usize,
) -> Result<Vec<u8>, NetworkLifecycleWorkerRuntimeError> {
    if dispatch.is_empty()
        || dispatch.len() > MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES
        || offset >= end
        || end > dispatch.len()
        || end - offset > MAXIMUM_FRAME_PAYLOAD_BYTES
        || ObjectDigest::from_bytes(Sha256::digest(dispatch).into()) != challenge.dispatch_digest()
    {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle frame bounds or digest are invalid",
        ));
    }
    let mut flags = 0;
    if offset == 0 {
        flags |= FRAME_FIRST;
    }
    if end == dispatch.len() {
        flags |= FRAME_FINAL;
    }
    let mut frame = vec![0_u8; FRAME_HEADER_BYTES + end - offset];
    frame[..8].copy_from_slice(FRAME_MAGIC);
    frame[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
    frame[10] = FRAME_KIND;
    frame[11] = MUTATION_ROLE;
    frame[12..14].copy_from_slice(&flags.to_be_bytes());
    frame[16..20].copy_from_slice(&u32_length(dispatch.len())?.to_be_bytes());
    frame[20..24].copy_from_slice(&u32_length(offset)?.to_be_bytes());
    frame[24..28].copy_from_slice(&u32_length(end - offset)?.to_be_bytes());
    frame[28..60].copy_from_slice(&challenge.nonce());
    frame[60..92].copy_from_slice(challenge.dispatch_digest().as_bytes());
    frame[92..108].copy_from_slice(&challenge.request_id());
    frame[108..140].copy_from_slice(challenge.effect_digest().as_bytes());
    frame[140..].copy_from_slice(&dispatch[offset..end]);
    Ok(frame)
}

fn decode_frame(bytes: &[u8]) -> Result<DecodedFrame<'_>, NetworkLifecycleWorkerRuntimeError> {
    if bytes.len() <= FRAME_HEADER_BYTES || bytes.len() > MAXIMUM_FRAME_BYTES {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle frame length is invalid",
        ));
    }
    if bytes[..8] != *FRAME_MAGIC
        || bytes[8..10] != FRAME_VERSION.to_be_bytes()
        || bytes[10] != FRAME_KIND
        || bytes[11] != MUTATION_ROLE
        || bytes[14..16] != [0; 2]
    {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle frame header is invalid",
        ));
    }
    let flags = u16::from_be_bytes(copy_array(&bytes[12..14])?);
    let total = usize::try_from(u32::from_be_bytes(copy_array(&bytes[16..20])?))
        .map_err(|_| NetworkLifecycleWorkerRuntimeError::Protocol("frame total is invalid"))?;
    let offset = usize::try_from(u32::from_be_bytes(copy_array(&bytes[20..24])?))
        .map_err(|_| NetworkLifecycleWorkerRuntimeError::Protocol("frame offset is invalid"))?;
    let length = usize::try_from(u32::from_be_bytes(copy_array(&bytes[24..28])?))
        .map_err(|_| NetworkLifecycleWorkerRuntimeError::Protocol("frame length is invalid"))?;
    let challenge = NetworkLifecycleWorkerChallengeV1::new(
        copy_array(&bytes[28..60])?,
        ObjectDigest::from_bytes(copy_array(&bytes[60..92])?),
        copy_array(&bytes[92..108])?,
        ObjectDigest::from_bytes(copy_array(&bytes[108..140])?),
    )?;
    let end = offset
        .checked_add(length)
        .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle frame range overflowed",
        ))?;
    let first = flags & FRAME_FIRST != 0;
    let final_frame = flags & FRAME_FINAL != 0;
    if flags & !(FRAME_FIRST | FRAME_FINAL) != 0
        || total == 0
        || total > MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES
        || length == 0
        || length > MAXIMUM_FRAME_PAYLOAD_BYTES
        || bytes.len() != FRAME_HEADER_BYTES + length
        || end > total
        || first != (offset == 0)
        || final_frame != (end == total)
    {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle frame fields are invalid",
        ));
    }
    Ok(DecodedFrame {
        flags,
        total,
        offset,
        challenge,
        payload: &bytes[FRAME_HEADER_BYTES..],
    })
}

fn validate_initial_dispatch_frame(
    frame: &DecodedFrame<'_>,
    challenge: NetworkLifecycleWorkerChallengeV1,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    if frame.challenge != challenge || frame.offset != 0 {
        return Err(NetworkLifecycleWorkerRuntimeError::Authority);
    }
    Ok(())
}

fn finish_exchange(
    exchange: Result<(), NetworkLifecycleWorkerRuntimeError>,
    subject: &KernelAuthorizedRecordSubject,
    cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
    fail_stopped: &mut bool,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    match exchange {
        Ok(()) => match wait_for_quiescence(subject, population, NATURAL_EXIT_TIMEOUT) {
            Ok(()) => Ok(()),
            Err(natural_error) => {
                if let Err(cancellation_error) = quiesce_worker(subject, cgroup, population) {
                    *fail_stopped = true;
                    Err(NetworkLifecycleWorkerRuntimeError::Quiescence(format!(
                        "admitted worker remained live ({natural_error}); cancellation was not proved ({cancellation_error})"
                    )))
                } else {
                    Err(NetworkLifecycleWorkerRuntimeError::Quiescence(format!(
                        "admitted worker did not terminate naturally: {natural_error}"
                    )))
                }
            }
        },
        Err(error) => {
            if let Err(cancellation_error) = quiesce_worker(subject, cgroup, population) {
                *fail_stopped = true;
                return Err(NetworkLifecycleWorkerRuntimeError::Quiescence(format!(
                    "admission exchange failed ({error}); cancellation was not proved ({cancellation_error})"
                )));
            }
            Err(error)
        }
    }
}

fn fail_unretained_worker<T>(
    fail_stopped: &mut bool,
    boundary: UnretainedWorkerBoundary,
    error: NetworkLifecycleWorkerRuntimeError,
) -> Result<T, NetworkLifecycleWorkerRuntimeError> {
    *fail_stopped = true;
    Err(NetworkLifecycleWorkerRuntimeError::Quiescence(format!(
        "worker lifetime became unproved at the post-connect {} boundary ({error}); the systemd unit time limit is containment, not verified drain",
        boundary.label()
    )))
}

fn ensure_executor_available(fail_stopped: bool) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    if fail_stopped {
        Err(NetworkLifecycleWorkerRuntimeError::Quiescence(
            "lifecycle worker executor is fail-stopped".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn retain_population_or_fail_stop(
    cgroup: &RetainedCgroupAnchor,
    fail_stopped: &mut bool,
) -> Result<CgroupPopulationMonitor, NetworkLifecycleWorkerRuntimeError> {
    match cgroup.population_monitor() {
        Ok(population) => Ok(population),
        Err(error) => {
            let _ = cgroup.kill_all();
            *fail_stopped = true;
            Err(NetworkLifecycleWorkerRuntimeError::Quiescence(format!(
                "worker population monitor could not be retained: {error}"
            )))
        }
    }
}

fn quiesce_worker(
    subject: &KernelAuthorizedRecordSubject,
    cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    if !subject.pidfd().is_alive()? && cgroup_is_quiescent(population)? {
        return Ok(());
    }
    if let Err(error) = cgroup.kill_all() {
        if !subject.pidfd().is_alive()? && cgroup_is_quiescent(population)? {
            return Ok(());
        }
        return Err(error.into());
    }
    wait_for_quiescence(subject, population, QUIESCENCE_TIMEOUT)
}

fn wait_for_quiescence(
    subject: &KernelAuthorizedRecordSubject,
    population: &CgroupPopulationMonitor,
    timeout: Duration,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    let deadline = deadline_after(timeout)?;
    loop {
        if !subject.pidfd().is_alive()? && cgroup_is_quiescent(population)? {
            return Ok(());
        }
        if boottime_now_nanoseconds()? >= deadline {
            return Err(NetworkLifecycleWorkerRuntimeError::Quiescence(
                "lifecycle worker quiescence deadline elapsed".to_owned(),
            ));
        }
        std::thread::sleep(QUIESCENCE_POLL_INTERVAL);
    }
}

fn cgroup_is_quiescent(
    population: &CgroupPopulationMonitor,
) -> Result<bool, NetworkLifecycleWorkerRuntimeError> {
    Ok(matches!(
        population.state()?,
        CgroupPopulationState::Empty | CgroupPopulationState::Retired
    ))
}

fn retype_network_namespace(
    descriptor: BorrowedFd<'_>,
) -> Result<NamespaceFd, NetworkLifecycleWorkerRuntimeError> {
    let duplicate = rustix::io::dup(descriptor)?;
    NamespaceFd::from_owned(duplicate, NamespaceKind::Network).map_err(Into::into)
}

fn random_nonce() -> Result<[u8; 32], NetworkLifecycleWorkerRuntimeError> {
    let mut nonce = [0_u8; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        let received =
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())?;
        if received == 0 {
            return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
                "kernel random source returned no bytes",
            ));
        }
        filled += received;
    }
    if nonce == [0; 32] {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "kernel random source returned the reserved nonce",
        ));
    }
    Ok(nonce)
}

fn send_record_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    send_record_inner(socket, payload, &[], deadline)
}

fn send_record_with_descriptors_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: u64,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    send_record_inner(socket, payload, descriptors, deadline)
}

fn send_record_inner(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: u64,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    socket.provision_packet_capacity(payload.len())?;
    loop {
        ensure_before_deadline(deadline)?;
        let result = if descriptors.is_empty() {
            socket.send(payload)
        } else {
            socket.send_with_descriptors(payload, descriptors)
        };
        match result {
            Ok(()) => return ensure_before_deadline(deadline),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_before(socket.as_fd()?, rustix::event::PollFlags::OUT, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_record_before(
    socket: &mut DescriptorSubjectSocket,
    maximum: usize,
    descriptors: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, NetworkLifecycleWorkerRuntimeError> {
    socket.provision_packet_capacity(maximum)?;
    loop {
        ensure_before_deadline(deadline)?;
        match socket.receive(maximum, descriptors) {
            Ok(record) => {
                ensure_before_deadline(deadline)?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_before(socket.as_fd()?, rustix::event::PollFlags::IN, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait_before(
    descriptor: BorrowedFd<'_>,
    events: rustix::event::PollFlags,
    deadline: u64,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    loop {
        let now = boottime_now_nanoseconds()?;
        let remaining =
            deadline
                .checked_sub(now)
                .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
                    "lifecycle transfer deadline elapsed",
                ))?;
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| {
                NetworkLifecycleWorkerRuntimeError::Protocol("poll timeout seconds overflowed")
            })?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000).map_err(|_| {
                NetworkLifecycleWorkerRuntimeError::Protocol("poll timeout nanos overflowed")
            })?,
        };
        let mut pollfd = [rustix::event::PollFd::new(&descriptor, events)];
        match rustix::event::poll(&mut pollfd, Some(&timeout)) {
            Ok(0) => {
                return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
                    "lifecycle transfer deadline elapsed",
                ));
            }
            Ok(_) => return ensure_before_deadline(deadline),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn deadline_after(duration: Duration) -> Result<u64, NetworkLifecycleWorkerRuntimeError> {
    boottime_now_nanoseconds()?
        .checked_add(duration.as_nanos() as u64)
        .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle deadline overflowed",
        ))
}

fn ensure_before_deadline(deadline: u64) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    if boottime_now_nanoseconds()? < deadline {
        Ok(())
    } else {
        Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle transfer deadline elapsed",
        ))
    }
}

fn boottime_now_nanoseconds() -> Result<u64, NetworkLifecycleWorkerRuntimeError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| NetworkLifecycleWorkerRuntimeError::Protocol("invalid boottime seconds"))?;
    let nanoseconds = u64::try_from(now.tv_nsec)
        .map_err(|_| NetworkLifecycleWorkerRuntimeError::Protocol("invalid boottime nanos"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
            "boottime overflowed",
        ))
}

fn current_cgroup() -> Result<String, NetworkLifecycleWorkerRuntimeError> {
    let mut bytes = Vec::new();
    File::open("/proc/self/cgroup")?
        .take((MAXIMUM_CGROUP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_CGROUP_BYTES {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle worker cgroup text is too long",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        NetworkLifecycleWorkerRuntimeError::Protocol("lifecycle cgroup text is not UTF-8")
    })?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .map(str::to_owned)
        .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
            "unified lifecycle worker cgroup is absent",
        ))
}

fn validate_initial_descriptor_table() -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    let mut descriptors = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let name = entry?.file_name();
        let descriptor = name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
                "initial descriptor table contains a noncanonical entry",
            ))?;
        descriptors.push(descriptor);
    }
    descriptors.sort_unstable();
    validate_initial_descriptor_numbers(&descriptors)
}

fn validate_initial_descriptor_numbers(
    descriptors: &[u32],
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    // Reading /proc/self/fd temporarily adds exactly one descriptor. Systemd
    // must otherwise provide only stdin/stdout on the accepted socket and the
    // journal stream on stderr.
    if descriptors.len() != 4
        || descriptors.get(..3) != Some([0, 1, 2].as_slice())
        || descriptors[3] < 3
    {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle worker inherited an unexpected descriptor",
        ));
    }
    Ok(())
}

fn open_cgroup_root() -> Result<CgroupV2Root, NetworkLifecycleWorkerRuntimeError> {
    let descriptor = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    CgroupV2Root::from_owned(descriptor).map_err(Into::into)
}

fn normalized_absolute_path(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    path.is_absolute()
        && bytes.len() > 1
        && bytes.len() <= 4096
        && !bytes.contains(&0)
        && bytes[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && !matches!(component, b"." | b".."))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NetworkLifecycleWorkerRuntimeError> {
    bytes
        .try_into()
        .map_err(|_| NetworkLifecycleWorkerRuntimeError::Protocol("lifecycle frame is truncated"))
}

fn u32_length(value: usize) -> Result<u32, NetworkLifecycleWorkerRuntimeError> {
    u32::try_from(value).map_err(|_| {
        NetworkLifecycleWorkerRuntimeError::Protocol("lifecycle frame field is too large")
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn challenge(dispatch: &[u8]) -> NetworkLifecycleWorkerChallengeV1 {
        NetworkLifecycleWorkerChallengeV1::new(
            [1; 32],
            ObjectDigest::from_bytes(Sha256::digest(dispatch).into()),
            [2; 16],
            ObjectDigest::from_bytes([3; 32]),
        )
        .unwrap()
    }

    #[test]
    fn lifecycle_frames_are_bounded_canonical_and_challenge_bound() {
        let dispatch = vec![0x5a; MAXIMUM_FRAME_PAYLOAD_BYTES + 17];
        let challenge = challenge(&dispatch);
        let first = encode_frame(&dispatch, challenge, 0, MAXIMUM_FRAME_PAYLOAD_BYTES).unwrap();
        let second = encode_frame(
            &dispatch,
            challenge,
            MAXIMUM_FRAME_PAYLOAD_BYTES,
            dispatch.len(),
        )
        .unwrap();
        let first = decode_frame(&first).unwrap();
        let second = decode_frame(&second).unwrap();

        assert_eq!(first.flags, FRAME_FIRST);
        assert_eq!(second.flags, FRAME_FINAL);
        assert_eq!(first.challenge, challenge);
        assert_eq!(second.challenge, challenge);
        assert_eq!(first.payload.len(), MAXIMUM_FRAME_PAYLOAD_BYTES);
        assert_eq!(second.offset, first.payload.len());
        assert_eq!(second.payload.len(), 17);
    }

    #[test]
    fn frame_structure_and_correlated_transcript_substitution_fail_closed() {
        let dispatch = vec![7; 32];
        let challenge = challenge(&dispatch);
        let valid = encode_frame(&dispatch, challenge, 0, dispatch.len()).unwrap();
        for offset in 0..28 {
            let mut changed = valid.clone();
            changed[offset] ^= 0x80;
            assert!(decode_frame(&changed).is_err(), "offset {offset}");
        }
        for offset in 28..FRAME_HEADER_BYTES {
            let mut changed = valid.clone();
            changed[offset] ^= 0x80;
            let changed = decode_frame(&changed).unwrap();

            assert!(
                validate_initial_dispatch_frame(&changed, challenge).is_err(),
                "offset {offset}"
            );
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(decode_frame(&trailing).is_err());
        assert!(encode_frame(b"substitute", challenge, 0, 10).is_err());
    }

    #[test]
    fn only_normalized_absolute_lifecycle_socket_paths_are_accepted() {
        assert!(normalized_absolute_path(Path::new(
            "/run/aos/sandbox-network-lifecycle-worker/control.sock"
        )));
        for path in [
            "run/aos/lifecycle.sock",
            "/run//lifecycle.sock",
            "/run/../lifecycle.sock",
            "/run/./lifecycle.sock",
        ] {
            assert!(!normalized_absolute_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn admission_ack_requires_exact_transcript_and_distinct_target() {
        let dispatch = b"canonical lifecycle dispatch";
        let challenge = challenge(dispatch);
        let bootstrap = NamespaceIdentity {
            device: 5,
            inode: 6,
        };
        let target = NamespaceIdentity {
            device: 7,
            inode: 8,
        };
        let admitted = NetworkLifecycleWorkerAdmittedV1::new(challenge, bootstrap, target).unwrap();
        assert_eq!(admitted.challenge(), challenge);
        assert_eq!(admitted.bootstrap(), bootstrap);
        assert_eq!(admitted.target(), target);
        assert!(NetworkLifecycleWorkerAdmittedV1::new(challenge, bootstrap, bootstrap).is_err());
    }

    #[test]
    fn initial_descriptor_table_rejects_every_ambient_descriptor_shape() {
        assert!(validate_initial_descriptor_numbers(&[0, 1, 2, 3]).is_ok());
        for descriptors in [
            vec![0, 1, 2],
            vec![0, 1, 2, 3, 4],
            vec![0, 1, 3, 4],
            vec![0, 1, 1, 3],
            vec![1, 2, 3, 4],
        ] {
            assert!(
                validate_initial_descriptor_numbers(&descriptors).is_err(),
                "{descriptors:?}"
            );
        }
    }

    struct ScriptedLifecycleAdmission {
        failure: Option<UnretainedWorkerBoundary>,
        visited: Vec<UnretainedWorkerBoundary>,
        closed_connections: usize,
        target_transfers: usize,
    }

    impl ScriptedLifecycleAdmission {
        fn failing_at(boundary: UnretainedWorkerBoundary) -> Self {
            Self {
                failure: Some(boundary),
                visited: Vec::new(),
                closed_connections: 0,
                target_transfers: 0,
            }
        }

        fn visit(
            &mut self,
            boundary: UnretainedWorkerBoundary,
        ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
            self.visited.push(boundary);
            if self.failure == Some(boundary) {
                Err(NetworkLifecycleWorkerRuntimeError::Protocol(
                    "injected pre-retention failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    impl LifecycleAdmissionOperations for ScriptedLifecycleAdmission {
        type Connection = ();
        type ReadyRecord = ();
        type Ready = ();
        type Retained = ();
        type Admitted = ();

        fn connect(&mut self) -> Result<Self::Connection, NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::Connect)
        }

        fn validate_manager_peer(
            &mut self,
            _connection: &Self::Connection,
        ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::ManagerPeer)
        }

        fn transfer_challenge(
            &mut self,
            _connection: &mut Self::Connection,
        ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::ChallengeTransfer)
        }

        fn receive_ready(
            &mut self,
            _connection: &mut Self::Connection,
        ) -> Result<Self::ReadyRecord, NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::ReadyTransfer)
        }

        fn decode_ready(
            &mut self,
            _record: &Self::ReadyRecord,
        ) -> Result<Self::Ready, NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::ReadyDecode)
        }

        fn correlate_ready(
            &mut self,
            _ready: &Self::Ready,
        ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::ReadyCorrelation)
        }

        fn validate_ready_descriptors(
            &mut self,
            _record: &Self::ReadyRecord,
        ) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::ReadyDescriptors)
        }

        fn retain_ready_authority(
            &mut self,
            _record: Self::ReadyRecord,
            _ready: Self::Ready,
        ) -> Result<Self::Retained, NetworkLifecycleWorkerRuntimeError> {
            self.visit(UnretainedWorkerBoundary::ReadyAuthority)
        }

        fn close(&mut self, _connection: &mut Self::Connection) {
            self.closed_connections += 1;
        }

        fn complete_after_retention(
            &mut self,
            _connection: &mut Self::Connection,
            _retained: Self::Retained,
            _fail_stopped: &mut bool,
        ) -> Result<Self::Admitted, NetworkLifecycleWorkerRuntimeError> {
            self.target_transfers += 1;
            Ok(())
        }
    }

    #[test]
    fn actual_pre_retention_flow_closes_fail_stops_and_never_transfers_target() {
        let boundaries = [
            UnretainedWorkerBoundary::Connect,
            UnretainedWorkerBoundary::ManagerPeer,
            UnretainedWorkerBoundary::ChallengeTransfer,
            UnretainedWorkerBoundary::ReadyTransfer,
            UnretainedWorkerBoundary::ReadyDecode,
            UnretainedWorkerBoundary::ReadyCorrelation,
            UnretainedWorkerBoundary::ReadyDescriptors,
            UnretainedWorkerBoundary::ReadyAuthority,
        ];

        for boundary in boundaries {
            let mut admission = ScriptedLifecycleAdmission::failing_at(boundary);
            let mut fail_stopped = false;
            let result = execute_lifecycle_admission(&mut admission, &mut fail_stopped);
            let message = result.unwrap_err().to_string();

            assert!(fail_stopped, "{boundary:?}");
            assert!(message.contains(boundary.label()), "{message}");
            assert!(
                message.contains("injected pre-retention failure"),
                "{message}"
            );
            assert!(message.contains("not verified drain"), "{message}");
            assert_eq!(admission.target_transfers, 0, "{boundary:?}");
            assert_eq!(
                admission.closed_connections,
                usize::from(boundary != UnretainedWorkerBoundary::Connect),
                "{boundary:?}"
            );

            let visited = admission.visited.len();
            let retry = execute_lifecycle_admission(&mut admission, &mut fail_stopped);
            assert!(retry.is_err(), "{boundary:?}");
            assert_eq!(admission.visited.len(), visited, "{boundary:?}");
            assert_eq!(admission.target_transfers, 0, "{boundary:?}");
        }
    }

    #[test]
    fn successful_pre_retention_flow_reaches_one_target_transfer() {
        let mut admission = ScriptedLifecycleAdmission {
            failure: None,
            visited: Vec::new(),
            closed_connections: 0,
            target_transfers: 0,
        };
        let mut fail_stopped = false;

        execute_lifecycle_admission(&mut admission, &mut fail_stopped).unwrap();

        assert!(!fail_stopped);
        assert_eq!(admission.visited.len(), 8);
        assert_eq!(admission.closed_connections, 0);
        assert_eq!(admission.target_transfers, 1);
    }
}
