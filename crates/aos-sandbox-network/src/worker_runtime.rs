//! Systemd-activated runtime for one authenticated Network preparation.
//!
//! The capability-free broker authenticates PID 1 and a fresh private-network
//! worker before transferring an exact dispatch and its own retained Network
//! namespace. The request is split into bounded sequenced-packet frames; every
//! frame carries a kernel-generated process subject, while only the first frame
//! carries the host namespace descriptor. The worker independently opens all
//! protected authority, replay, and immutable-helper state before authenticating
//! and executing the request.
//!
//! A successful result is correlation evidence only. The broker returns the
//! target namespace descriptor only after the worker leader has exited and the
//! retained unit cgroup reports `populated 0`. A separate observation worker is
//! still required before committing or publishing the namespace.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aos_sandbox_core::{ObjectDigest, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use aos_sandbox_linux::pidfd::{NamespaceFd, SingleThreadedProcess};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::kernel_mutator::{FixedNetworkKernelMutator, NetworkKernelMutationError};
use crate::worker_process::{
    NetworkWorkerProcessError, NetworkWorkerReadyV1, NetworkWorkerResultV1, acknowledgement,
    decode_acknowledgement, validate_broker_peer, validate_broker_request, validate_broker_subject,
    validate_exact_worker_subject, validate_same_worker_execution, validate_systemd_manager_peer,
    validate_worker_ready,
};
use crate::worker_protocol::{
    MAXIMUM_NETWORK_WORKER_REQUEST_BYTES, NetworkPrepareWorkerDispatchV1,
    NetworkWorkerProtocolError,
};
use crate::{
    NetworkAdmissionError, NetworkLifecycleAdmissionCoordinator, NetworkNamespaceStoreError,
    NetworkNamespaceStoreName, NetworkWorkerReplayLedger, SystemdNetworkNamespaceStore,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const FRAME_MAGIC: &[u8; 8] = b"AOSNFRM1";
const FRAME_VERSION: u16 = 1;
const FRAME_FIRST: u16 = 1;
const FRAME_FINAL: u16 = 2;
const FRAME_HEADER_BYTES: usize = 56;
const MAXIMUM_FRAME_BYTES: usize = 64 * 1024;
const MAXIMUM_FRAME_PAYLOAD_BYTES: usize = MAXIMUM_FRAME_BYTES - FRAME_HEADER_BYTES;
const MAXIMUM_READY_BYTES: usize = 544;
const RESULT_BYTES: usize = 128;
const ACK_BYTES: usize = 10;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);
const NATURAL_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
const QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Reports rejected worker provenance, framing, authority, effects, or quiescence.
#[derive(Debug, thiserror::Error)]
pub enum NetworkWorkerRuntimeError {
    /// A bounded runtime record, path, clock, or state transition was invalid.
    #[error("Network worker runtime protocol is invalid: {0}")]
    Protocol(&'static str),
    /// The protected Network authority could not be opened.
    #[error("Network worker protected authority was rejected")]
    Authority,
    /// A worker that may have mutated could not be proved completely stopped.
    #[error("Network worker whole-unit quiescence failed: {0}")]
    Quiescence(String),
    /// The kernel-authorized process protocol rejected a peer or record.
    #[error(transparent)]
    Process(#[from] NetworkWorkerProcessError),
    /// The authenticated worker protocol rejected the dispatch or replay state.
    #[error(transparent)]
    Worker(#[from] NetworkWorkerProtocolError),
    /// The fixed kernel mutator rejected or failed the requested effect.
    #[error(transparent)]
    Mutation(#[from] NetworkKernelMutationError),
    /// The bounded sequenced-packet transport failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// A Linux descriptor, namespace, cgroup, or process check failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A procfs read failed.
    #[error("Network worker local I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A safe polling operation failed.
    #[error("Network worker polling failed: {0}")]
    Poll(#[from] rustix::io::Errno),
    /// Confirmed systemd namespace custody failed or became ambiguous.
    #[error(transparent)]
    NamespaceStore(#[from] NetworkNamespaceStoreError),
    /// Durable namespace-custody correlation could not be committed.
    #[error(transparent)]
    Broker(#[from] crate::NetworkBrokerError),
}

/// Names the fixed protected state and immutable artifacts of the effect worker.
#[derive(Clone, Debug)]
pub struct NetworkWorkerConfiguration {
    /// Root-owned protected Network authority directory.
    pub authority_directory: PathBuf,
    /// Root-owned exactly-once worker replay directory.
    pub replay_directory: PathBuf,
    /// Fixed AOS-built `ip` executable.
    pub ip: PathBuf,
    /// Fixed AOS-built `nft` executable.
    pub nft: PathBuf,
    /// Reviewed executable whose digest is committed by the kernel plan.
    pub enforcement_artifact: PathBuf,
    /// Fixed disarmed lease-gate loader executable.
    pub lease_gate_loader: PathBuf,
    /// Exact BPF object installed by the lease-gate loader.
    pub lease_gate_object: PathBuf,
}

/// Carries a prepared namespace only after the effect worker is wholly quiescent.
#[derive(Debug)]
pub struct PreparedNetworkWorkerOutput {
    namespace: NamespaceFd,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
}

impl PreparedNetworkWorkerOutput {
    /// Returns the retained, independently validated target namespace.
    #[must_use]
    pub const fn namespace(&self) -> &NamespaceFd {
        &self.namespace
    }

    /// Returns the correlated durable request identity.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the correlated durable effect digest.
    #[must_use]
    pub const fn effect_digest(&self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the correlated canonical kernel-plan digest.
    #[must_use]
    pub const fn kernel_plan_digest(&self) -> ObjectDigest {
        self.kernel_plan_digest
    }

    /// Returns the worker-observed current kernel boot ID.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Consumes the result and transfers target namespace custody.
    #[must_use]
    pub fn into_namespace(self) -> NamespaceFd {
        self.namespace
    }
}

/// Borrows the retained namespace and durable tuple of an ambiguous recovery.
///
/// This value carries observation authority only. It contains no worker
/// dispatch, effect permit, helper configuration, or namespace-store mutation
/// capability.
#[derive(Clone, Copy, Debug)]
pub struct RecoveredNetworkPreparationObservation<'a> {
    namespace: &'a NamespaceFd,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
}

impl<'a> RecoveredNetworkPreparationObservation<'a> {
    pub(crate) const fn new(
        namespace: &'a NamespaceFd,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        kernel_boot_id: [u8; 16],
    ) -> Self {
        Self {
            namespace,
            request_id,
            effect_digest,
            kernel_plan_digest,
            kernel_boot_id,
        }
    }

    /// Returns the exact restart-retained target namespace.
    #[must_use]
    pub const fn namespace(self) -> &'a NamespaceFd {
        self.namespace
    }

    /// Returns the correlated durable request identity.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the correlated durable effect digest.
    #[must_use]
    pub const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the durable canonical kernel-plan digest.
    #[must_use]
    pub const fn kernel_plan_digest(self) -> ObjectDigest {
        self.kernel_plan_digest
    }

    /// Returns the boot in which systemd retained namespace custody.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }
}

/// Executes authenticated preparation dispatches through systemd one-shot workers.
pub struct SystemdNetworkPrepareExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: RetainedCgroupAnchor,
    worker_parent_cgroup: RetainedCgroupAnchor,
    host_namespace: NamespaceFd,
    fail_stopped: bool,
}

impl SystemdNetworkPrepareExecutor {
    /// Retains the fixed host namespace and worker-service cgroup roots.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket path, substituted host namespace,
    /// or unavailable systemd-manager or control-slice cgroup.
    pub fn new(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
        host_namespace: NamespaceFd,
    ) -> Result<Self, NetworkWorkerRuntimeError> {
        if !normalized_absolute_path(&socket_path) {
            return Err(NetworkWorkerRuntimeError::Protocol(
                "unsafe Network worker socket path",
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

    /// Transfers one already-durable dispatch and proves whole-worker quiescence.
    ///
    /// The dispatch is sent at most once. Any failure after its first frame is
    /// an ambiguous effect outcome and must be resolved only by observation.
    ///
    /// # Errors
    ///
    /// Returns an error for activation or peer substitution, malformed frames,
    /// result mismatch, timeout, worker failure, or unproved whole-cgroup exit.
    /// Failure to prove cancellation permanently fail-stops this executor.
    pub fn execute_once(
        &mut self,
        dispatch: &NetworkPrepareWorkerDispatchV1,
        coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        namespace_store: &SystemdNetworkNamespaceStore,
    ) -> Result<PreparedNetworkWorkerOutput, NetworkWorkerRuntimeError> {
        if self.fail_stopped {
            return Err(NetworkWorkerRuntimeError::Quiescence(
                "Network worker executor is fail-stopped".to_owned(),
            ));
        }
        self.host_namespace.validate_current_network()?;
        let mut socket = DescriptorSubjectSocket::connect(&self.socket_path)?;
        validate_systemd_manager_peer(socket.peer(), &self.systemd_manager_cgroup)?;

        let ready_deadline = deadline_after(TRANSFER_TIMEOUT)?;
        let ready_record =
            receive_record_before(&mut socket, MAXIMUM_READY_BYTES, 1, ready_deadline)?;
        let ready = NetworkWorkerReadyV1::decode(ready_record.payload())?;
        let (ready_bytes, ready_subject, ready_descriptors) = ready_record.into_parts();
        drop(ready_bytes);
        let (worker_cgroup, target_namespace) = validate_worker_ready(
            &ready,
            &ready_subject,
            ready_descriptors,
            &self.worker_parent_cgroup,
            &self.host_namespace,
        )?;
        let population = match worker_cgroup.population_monitor() {
            Ok(population) => population,
            Err(error) => {
                let _ = worker_cgroup.kill_all();
                self.fail_stopped = true;
                return Err(NetworkWorkerRuntimeError::Quiescence(format!(
                    "worker population monitor could not be retained: {error}"
                )));
            }
        };

        let custody = (|| {
            let network_handle = *dispatch.kernel_plan().network_handle();
            let target_identity = target_namespace.identity();
            let kernel_boot_id = KernelBootId::current()?.into_bytes();
            coordinator.bind_effect_namespace_custody(
                dispatch.request_id(),
                dispatch.effect_digest(),
                network_handle,
                kernel_boot_id,
                target_identity.device,
                target_identity.inode,
                dispatch.kernel_plan().digest(),
            )?;
            confirm_namespace_custody(namespace_store, network_handle, &target_namespace)
        })();
        let exchange = exchange_after_confirmed_custody(custody, || {
            exchange_after_ready(
                &mut socket,
                dispatch,
                &self.host_namespace,
                &target_namespace,
                &ready_subject,
                &worker_cgroup,
            )
        });
        match exchange {
            Ok(result) => {
                let release = release_after_quiescence(
                    wait_for_quiescence(&ready_subject, &population, NATURAL_EXIT_TIMEOUT),
                    || output_from_result(target_namespace, result),
                );
                match release {
                    Ok(output) => Ok(output),
                    Err(natural_error) => {
                        if let Err(cancellation_error) =
                            quiesce_worker(&ready_subject, &worker_cgroup, &population)
                        {
                            self.fail_stopped = true;
                            Err(NetworkWorkerRuntimeError::Quiescence(format!(
                                "successful worker remained live ({natural_error}); cancellation was not proved ({cancellation_error})"
                            )))
                        } else {
                            Err(NetworkWorkerRuntimeError::Quiescence(format!(
                                "successful worker did not terminate naturally: {natural_error}"
                            )))
                        }
                    }
                }
            }
            Err(error) => {
                if let Err(cancellation_error) =
                    quiesce_worker(&ready_subject, &worker_cgroup, &population)
                {
                    self.fail_stopped = true;
                    return Err(NetworkWorkerRuntimeError::Quiescence(format!(
                        "worker exchange failed ({error}); cancellation was not proved ({cancellation_error})"
                    )));
                }
                Err(error)
            }
        }
    }
}

fn release_after_quiescence<T>(
    quiescence: Result<(), NetworkWorkerRuntimeError>,
    release: impl FnOnce() -> T,
) -> Result<T, NetworkWorkerRuntimeError> {
    quiescence?;
    Ok(release())
}

fn exchange_after_confirmed_custody<T>(
    custody: Result<(), NetworkWorkerRuntimeError>,
    exchange: impl FnOnce() -> Result<T, NetworkWorkerRuntimeError>,
) -> Result<T, NetworkWorkerRuntimeError> {
    custody?;
    exchange()
}

trait NamespaceCustodyStore {
    fn store_namespace(
        &self,
        name: &NetworkNamespaceStoreName,
        namespace: &NamespaceFd,
    ) -> Result<(), NetworkNamespaceStoreError>;

    fn retained_namespace_identity(
        &self,
        name: &NetworkNamespaceStoreName,
    ) -> Result<Option<NamespaceIdentity>, NetworkNamespaceStoreError>;
}

impl NamespaceCustodyStore for SystemdNetworkNamespaceStore {
    fn store_namespace(
        &self,
        name: &NetworkNamespaceStoreName,
        namespace: &NamespaceFd,
    ) -> Result<(), NetworkNamespaceStoreError> {
        self.store(name, namespace).map(|_| ())
    }

    fn retained_namespace_identity(
        &self,
        name: &NetworkNamespaceStoreName,
    ) -> Result<Option<NamespaceIdentity>, NetworkNamespaceStoreError> {
        self.retained_identity(name)
    }
}

fn confirm_namespace_custody(
    store: &impl NamespaceCustodyStore,
    network_handle: [u8; 32],
    target_namespace: &NamespaceFd,
) -> Result<(), NetworkWorkerRuntimeError> {
    let store_name = NetworkNamespaceStoreName::from_network_handle(network_handle)?;
    store.store_namespace(&store_name, target_namespace)?;
    if store.retained_namespace_identity(&store_name)? != Some(target_namespace.identity()) {
        return Err(NetworkWorkerRuntimeError::Quiescence(
            "confirmed namespace custody changed before dispatch".to_owned(),
        ));
    }
    Ok(())
}

/// Runs one inherited, root-privileged Network preparation worker.
///
/// PID 1 supplies the connected sequenced-packet socket as standard input and
/// creates the process in a fresh private Network namespace. The function
/// performs at most one replay-claimed mutation and waits for broker ACK before
/// returning.
///
/// # Errors
///
/// Returns an error unless protected configuration, every record subject,
/// descriptor role, current namespace, replay claim, freshness check, fixed
/// artifact, mutation step, result transfer, and acknowledgement all validate.
pub fn run_inherited_network_prepare_worker(
    configuration: NetworkWorkerConfiguration,
) -> Result<(), NetworkWorkerRuntimeError> {
    let worker = SingleThreadedProcess::verify()?;
    worker.disable_core_dumps()?;
    let authority =
        NetworkAuthorityV1::from_protected_directory(&configuration.authority_directory)
            .map_err(|_| NetworkWorkerRuntimeError::Authority)?;
    let mut replay = NetworkWorkerReplayLedger::open_root_owned(&configuration.replay_directory)?;
    let mutator = FixedNetworkKernelMutator::new(
        configuration.ip,
        configuration.nft,
        configuration.enforcement_artifact,
        configuration.lease_gate_loader,
        configuration.lease_gate_object,
    )?;
    let cgroup_root = open_cgroup_root()?;
    let control_cgroup = cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?;
    let target_namespace = NamespaceFd::current_network()?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;
    validate_broker_peer(socket.peer(), &control_cgroup)?;

    let ready = NetworkWorkerReadyV1::new(current_cgroup()?, target_namespace.identity())?;
    let deadline = deadline_after(TRANSFER_TIMEOUT)?;
    send_record_with_descriptors_before(
        &mut socket,
        &ready.encode()?,
        &[target_namespace.as_fd()],
        deadline,
    )?;
    let (dispatch_bytes, host_namespace) = receive_request_before(
        &mut socket,
        &control_cgroup,
        &target_namespace,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    let dispatch = NetworkPrepareWorkerDispatchV1::decode(&dispatch_bytes)?;
    let authenticated = dispatch.authenticate(&authority)?;
    let authorization =
        authenticated.authorize_mutation(&authority, &mut replay, &mut protected_clock)?;
    let prepared = mutator.install_default_drop(&authorization, &target_namespace)?;
    let activation = authorization.authorize_activation(&authority, &mut protected_clock)?;
    mutator.realize_prepared(
        prepared,
        &activation,
        &target_namespace,
        &host_namespace,
        &worker,
    )?;

    let result = NetworkWorkerResultV1::new(
        authorization.request_id(),
        authorization.effect_digest(),
        authorization.kernel_plan().digest(),
        KernelBootId::current()?.into_bytes(),
        target_namespace.identity(),
    )?;
    let response_deadline = deadline_after(TRANSFER_TIMEOUT)?;
    send_record_before(&mut socket, &result.encode(), response_deadline)?;
    let acknowledgement = receive_record_before(&mut socket, ACK_BYTES, 0, response_deadline)?;
    validate_broker_subject(socket.peer(), acknowledgement.subject(), &control_cgroup)?;
    decode_acknowledgement(acknowledgement.payload()).map_err(NetworkWorkerRuntimeError::from)
}

fn exchange_after_ready(
    socket: &mut DescriptorSubjectSocket,
    dispatch: &NetworkPrepareWorkerDispatchV1,
    host_namespace: &NamespaceFd,
    target_namespace: &NamespaceFd,
    ready_subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
) -> Result<NetworkWorkerResultV1, NetworkWorkerRuntimeError> {
    let bytes = dispatch.encode()?;
    let deadline = deadline_after(TRANSFER_TIMEOUT)?;
    send_request_before(socket, &bytes, host_namespace.as_fd(), deadline)?;
    let response = receive_record_before(socket, RESULT_BYTES, 0, deadline)?;
    validate_same_worker_execution(ready_subject, response.subject())?;
    validate_exact_worker_subject(response.subject(), worker_cgroup)?;
    let result = NetworkWorkerResultV1::decode(response.payload())?;
    if result.request_id() != dispatch.request_id()
        || result.effect_digest() != dispatch.effect_digest()
        || result.kernel_plan_digest() != dispatch.kernel_plan().digest()
        || result.kernel_boot_id() != KernelBootId::current()?.into_bytes()
        || result.namespace() != target_namespace.identity()
    {
        return Err(NetworkWorkerRuntimeError::Authority);
    }
    send_record_before(socket, &acknowledgement(), deadline)?;
    Ok(result)
}

fn output_from_result(
    namespace: NamespaceFd,
    result: NetworkWorkerResultV1,
) -> PreparedNetworkWorkerOutput {
    PreparedNetworkWorkerOutput {
        namespace,
        request_id: result.request_id(),
        effect_digest: result.effect_digest(),
        kernel_plan_digest: result.kernel_plan_digest(),
        kernel_boot_id: result.kernel_boot_id(),
    }
}

fn send_request_before(
    socket: &mut DescriptorSubjectSocket,
    request: &[u8],
    host_namespace: BorrowedFd<'_>,
    deadline: u64,
) -> Result<(), NetworkWorkerRuntimeError> {
    if request.is_empty() || request.len() > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker request length is invalid",
        ));
    }
    let digest: [u8; 32] = Sha256::digest(request).into();
    let mut offset = 0;
    while offset < request.len() {
        let end = request
            .len()
            .min(offset.saturating_add(MAXIMUM_FRAME_PAYLOAD_BYTES));
        let frame = encode_frame(request, digest, offset, end)?;
        if offset == 0 {
            send_record_with_descriptors_before(socket, &frame, &[host_namespace], deadline)?;
        } else {
            send_record_before(socket, &frame, deadline)?;
        }
        offset = end;
    }
    ensure_before_deadline(deadline)
}

fn receive_request_before(
    socket: &mut DescriptorSubjectSocket,
    control_cgroup: &RetainedCgroupAnchor,
    target_namespace: &NamespaceFd,
    deadline: u64,
) -> Result<(Vec<u8>, NamespaceFd), NetworkWorkerRuntimeError> {
    let first = receive_record_before(socket, MAXIMUM_FRAME_BYTES, 1, deadline)?;
    let (first_bytes, first_subject, descriptors) = first.into_parts();
    let first_frame = decode_frame(&first_bytes)?;
    if first_frame.offset != 0 || first_frame.flags & FRAME_FIRST == 0 {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "first Network worker frame is invalid",
        ));
    }
    let host_namespace = validate_broker_request(
        socket.peer(),
        &first_subject,
        descriptors,
        control_cgroup,
        target_namespace,
    )?;
    let mut request = Vec::with_capacity(first_frame.total);
    request.extend_from_slice(first_frame.payload);
    let expected_digest = first_frame.digest;

    while request.len() < first_frame.total {
        let record = receive_record_before(socket, MAXIMUM_FRAME_BYTES, 0, deadline)?;
        validate_broker_subject(socket.peer(), record.subject(), control_cgroup)?;
        let frame = decode_frame(record.payload())?;
        if frame.flags & FRAME_FIRST != 0
            || frame.total != first_frame.total
            || frame.offset != request.len()
            || frame.digest != expected_digest
        {
            return Err(NetworkWorkerRuntimeError::Protocol(
                "continuation Network worker frame is inconsistent",
            ));
        }
        request.extend_from_slice(frame.payload);
    }
    if Sha256::digest(&request).as_slice() != expected_digest {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame digest mismatched",
        ));
    }
    ensure_before_deadline(deadline)?;
    Ok((request, host_namespace))
}

struct DecodedFrame<'a> {
    flags: u16,
    total: usize,
    offset: usize,
    digest: [u8; 32],
    payload: &'a [u8],
}

fn encode_frame(
    request: &[u8],
    digest: [u8; 32],
    offset: usize,
    end: usize,
) -> Result<Vec<u8>, NetworkWorkerRuntimeError> {
    if request.is_empty()
        || request.len() > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES
        || offset >= end
        || end > request.len()
        || end - offset > MAXIMUM_FRAME_PAYLOAD_BYTES
    {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame bounds are invalid",
        ));
    }
    let mut flags = 0;
    if offset == 0 {
        flags |= FRAME_FIRST;
    }
    if end == request.len() {
        flags |= FRAME_FINAL;
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + end - offset);
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(&u32_length(request.len())?.to_be_bytes());
    frame.extend_from_slice(&u32_length(offset)?.to_be_bytes());
    frame.extend_from_slice(&u32_length(end - offset)?.to_be_bytes());
    frame.extend_from_slice(&digest);
    frame.extend_from_slice(&request[offset..end]);
    Ok(frame)
}

fn decode_frame(bytes: &[u8]) -> Result<DecodedFrame<'_>, NetworkWorkerRuntimeError> {
    if bytes.len() <= FRAME_HEADER_BYTES || bytes.len() > MAXIMUM_FRAME_BYTES {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame length is invalid",
        ));
    }
    if &bytes[..8] != FRAME_MAGIC || bytes[8..10] != FRAME_VERSION.to_be_bytes() {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame header is invalid",
        ));
    }
    let flags = u16::from_be_bytes(copy_array(&bytes[10..12])?);
    let total = usize::try_from(u32::from_be_bytes(copy_array(&bytes[12..16])?))
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("frame total does not fit usize"))?;
    let offset = usize::try_from(u32::from_be_bytes(copy_array(&bytes[16..20])?))
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("frame offset does not fit usize"))?;
    let length = usize::try_from(u32::from_be_bytes(copy_array(&bytes[20..24])?))
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("frame length does not fit usize"))?;
    let digest = copy_array(&bytes[24..56])?;
    let end = offset
        .checked_add(length)
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "frame range overflowed",
        ))?;
    let first = flags & FRAME_FIRST != 0;
    let final_frame = flags & FRAME_FINAL != 0;
    if flags & !(FRAME_FIRST | FRAME_FINAL) != 0
        || total == 0
        || total > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES
        || length == 0
        || length > MAXIMUM_FRAME_PAYLOAD_BYTES
        || bytes.len() != FRAME_HEADER_BYTES + length
        || end > total
        || first != (offset == 0)
        || final_frame != (end == total)
    {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame fields are invalid",
        ));
    }
    Ok(DecodedFrame {
        flags,
        total,
        offset,
        digest,
        payload: &bytes[FRAME_HEADER_BYTES..],
    })
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NetworkWorkerRuntimeError> {
    bytes
        .try_into()
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("Network worker frame is truncated"))
}

fn u32_length(value: usize) -> Result<u32, NetworkWorkerRuntimeError> {
    u32::try_from(value)
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("Network worker frame field is too large"))
}

fn send_record_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), NetworkWorkerRuntimeError> {
    send_record_inner(socket, payload, &[], deadline)
}

fn send_record_with_descriptors_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: u64,
) -> Result<(), NetworkWorkerRuntimeError> {
    send_record_inner(socket, payload, descriptors, deadline)
}

fn send_record_inner(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: u64,
) -> Result<(), NetworkWorkerRuntimeError> {
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
) -> Result<ReceivedDescriptorRecord, NetworkWorkerRuntimeError> {
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

fn quiesce_worker(
    subject: &KernelAuthorizedRecordSubject,
    cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
) -> Result<(), NetworkWorkerRuntimeError> {
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
) -> Result<(), NetworkWorkerRuntimeError> {
    let deadline = deadline_after(timeout)?;
    loop {
        if !subject.pidfd().is_alive()? && cgroup_is_quiescent(population)? {
            return Ok(());
        }
        let remaining = deadline
            .checked_sub(boottime_now_nanoseconds()?)
            .filter(|remaining| *remaining != 0)
            .ok_or(NetworkWorkerRuntimeError::Quiescence(
                "Network worker quiescence deadline elapsed".to_owned(),
            ))?;
        std::thread::sleep(Duration::from_nanos(remaining).min(QUIESCENCE_POLL_INTERVAL));
    }
}

fn cgroup_is_quiescent(
    population: &CgroupPopulationMonitor,
) -> Result<bool, NetworkWorkerRuntimeError> {
    Ok(matches!(
        population.state()?,
        CgroupPopulationState::Empty | CgroupPopulationState::Retired
    ))
}

fn wait_before(
    descriptor: BorrowedFd<'_>,
    events: rustix::event::PollFlags,
    deadline: u64,
) -> Result<(), NetworkWorkerRuntimeError> {
    loop {
        let remaining = deadline
            .checked_sub(boottime_now_nanoseconds()?)
            .filter(|remaining| *remaining != 0)
            .ok_or(NetworkWorkerRuntimeError::Protocol(
                "Network worker transfer deadline elapsed",
            ))?;
        let timeout = rustix::event::Timespec::try_from(Duration::from_nanos(remaining))
            .map_err(|_| NetworkWorkerRuntimeError::Protocol("invalid transfer deadline"))?;
        let mut descriptors = [rustix::event::PollFd::new(&descriptor, events)];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {
                return Err(NetworkWorkerRuntimeError::Protocol(
                    "Network worker transfer deadline elapsed",
                ));
            }
            Ok(_) => return ensure_before_deadline(deadline),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn deadline_after(duration: Duration) -> Result<u64, NetworkWorkerRuntimeError> {
    boottime_now_nanoseconds()?
        .checked_add(duration.as_nanos() as u64)
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "Network worker deadline overflowed",
        ))
}

fn ensure_before_deadline(deadline: u64) -> Result<(), NetworkWorkerRuntimeError> {
    if boottime_now_nanoseconds()? < deadline {
        Ok(())
    } else {
        Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker transfer deadline elapsed",
        ))
    }
}

fn boottime_now_nanoseconds() -> Result<u64, NetworkWorkerRuntimeError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("CLOCK_BOOTTIME seconds are invalid"))?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| {
        NetworkWorkerRuntimeError::Protocol("CLOCK_BOOTTIME nanoseconds are invalid")
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "CLOCK_BOOTTIME overflowed",
        ))
}

fn protected_clock() -> Result<RawPairedClockSample, NetworkAdmissionError> {
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
        .map_err(|_| NetworkAdmissionError::FenceRejected)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        KernelBootId::current()
            .map_err(|_| NetworkAdmissionError::FenceRejected)?
            .into_bytes(),
        realtime.tv_sec,
        boottime_now_nanoseconds().map_err(|_| NetworkAdmissionError::FenceRejected)?,
    )
    .map_err(|_| NetworkAdmissionError::FenceRejected)
}

fn current_cgroup() -> Result<String, NetworkWorkerRuntimeError> {
    let mut bytes = Vec::new();
    File::open("/proc/self/cgroup")?
        .take((MAXIMUM_CGROUP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_CGROUP_BYTES {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker cgroup text is too long",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("cgroup text is not UTF-8"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .map(str::to_owned)
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "unified Network worker cgroup is absent",
        ))
}

fn open_cgroup_root() -> Result<CgroupV2Root, NetworkWorkerRuntimeError> {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;

    use super::*;

    fn prepared_observation_output(
        plan_digest: ObjectDigest,
        boot_id: [u8; 16],
    ) -> PreparedNetworkWorkerOutput {
        PreparedNetworkWorkerOutput {
            namespace: NamespaceFd::current_network().unwrap(),
            request_id: [1; 16],
            effect_digest: ObjectDigest::from_bytes([2; 32]),
            kernel_plan_digest: plan_digest,
            kernel_boot_id: boot_id,
        }
    }

    #[test]
    fn prepared_observation_rejects_substituted_plan_boot_and_host() {
        let plan_digest = ObjectDigest::from_bytes([3; 32]);
        let boot_id = [4; 16];
        let prepared = prepared_observation_output(plan_digest, boot_id);
        let target = prepared.namespace().identity();
        let distinct_host = NamespaceIdentity {
            device: target.device,
            inode: target.inode.checked_add(1).unwrap(),
        };
        let validate = |digest, boot, host| {
            crate::namespace_observer::validate_prepared_observation_authority(
                digest,
                prepared.kernel_plan_digest(),
                prepared.kernel_boot_id(),
                prepared.namespace().identity(),
                boot,
                host,
            )
        };

        assert!(validate(plan_digest, boot_id, distinct_host).is_ok());
        assert!(validate(ObjectDigest::from_bytes([5; 32]), boot_id, distinct_host).is_err());
        assert!(validate(plan_digest, [6; 16], distinct_host).is_err());
        assert!(validate(plan_digest, boot_id, target).is_err());
    }

    #[test]
    fn request_frames_are_bounded_canonical_and_contiguous() {
        let request = vec![0x5a; MAXIMUM_FRAME_PAYLOAD_BYTES + 17];
        let digest = Sha256::digest(&request).into();
        let first = encode_frame(&request, digest, 0, MAXIMUM_FRAME_PAYLOAD_BYTES).unwrap();
        let second =
            encode_frame(&request, digest, MAXIMUM_FRAME_PAYLOAD_BYTES, request.len()).unwrap();
        let first = decode_frame(&first).unwrap();
        let second = decode_frame(&second).unwrap();

        assert_eq!(first.flags, FRAME_FIRST);
        assert_eq!(first.offset, 0);
        assert_eq!(first.payload.len(), MAXIMUM_FRAME_PAYLOAD_BYTES);
        assert_eq!(second.flags, FRAME_FINAL);
        assert_eq!(second.offset, first.payload.len());
        assert_eq!(second.payload.len(), 17);
        assert_eq!(first.total, request.len());
        assert_eq!(second.total, request.len());
    }

    #[test]
    fn frame_flags_lengths_and_ranges_fail_closed() {
        let request = vec![7; 32];
        let digest = Sha256::digest(&request).into();
        let valid = encode_frame(&request, digest, 0, request.len()).unwrap();
        for offset in [8, 10, 12, 16, 20] {
            let mut changed = valid.clone();
            changed[offset] ^= 0x80;
            assert!(decode_frame(&changed).is_err(), "offset {offset}");
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(decode_frame(&trailing).is_err());
        assert!(decode_frame(&valid[..FRAME_HEADER_BYTES]).is_err());
    }

    #[test]
    fn only_normalized_absolute_socket_paths_are_accepted() {
        assert!(normalized_absolute_path(Path::new(
            "/run/aos/network-worker.sock"
        )));
        for path in [
            "run/aos/network-worker.sock",
            "/run//network-worker.sock",
            "/run/../network-worker.sock",
            "/run/./network-worker.sock",
        ] {
            assert!(!normalized_absolute_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn namespace_store_failure_or_readback_mismatch_sends_no_effect_frame() {
        enum StoreMode {
            StoreFailure,
            Missing,
            Wrong,
            Matching,
        }

        struct FakeStore {
            mode: StoreMode,
        }

        impl NamespaceCustodyStore for FakeStore {
            fn store_namespace(
                &self,
                _name: &NetworkNamespaceStoreName,
                _namespace: &NamespaceFd,
            ) -> Result<(), NetworkNamespaceStoreError> {
                match self.mode {
                    StoreMode::StoreFailure => Err(NetworkNamespaceStoreError::Rejected),
                    StoreMode::Missing | StoreMode::Wrong | StoreMode::Matching => Ok(()),
                }
            }

            fn retained_namespace_identity(
                &self,
                _name: &NetworkNamespaceStoreName,
            ) -> Result<Option<NamespaceIdentity>, NetworkNamespaceStoreError> {
                match self.mode {
                    StoreMode::StoreFailure => unreachable!("store failure stops before readback"),
                    StoreMode::Missing => Ok(None),
                    StoreMode::Wrong => Ok(Some(NamespaceIdentity {
                        device: u64::MAX,
                        inode: u64::MAX,
                    })),
                    StoreMode::Matching => NamespaceFd::current_network()
                        .map(|namespace| Some(namespace.identity()))
                        .map_err(|error| NetworkNamespaceStoreError::Systemd(error.to_string())),
                }
            }
        }

        let target = NamespaceFd::current_network().unwrap();
        for mode in [
            StoreMode::StoreFailure,
            StoreMode::Missing,
            StoreMode::Wrong,
        ] {
            let effect_sent = Cell::new(false);
            let custody = confirm_namespace_custody(&FakeStore { mode }, [7; 32], &target);
            let result: Result<(), _> = exchange_after_confirmed_custody(custody, || {
                effect_sent.set(true);
                Ok(())
            });

            assert!(result.is_err());
            assert!(!effect_sent.get());
        }

        let effect_count = Cell::new(0);
        let custody = confirm_namespace_custody(
            &FakeStore {
                mode: StoreMode::Matching,
            },
            [7; 32],
            &target,
        );
        exchange_after_confirmed_custody(custody, || {
            effect_count.set(effect_count.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(effect_count.get(), 1);
    }

    #[test]
    fn worker_output_is_released_only_after_whole_unit_quiescence() {
        let released = Cell::new(0);
        let fail = release_after_quiescence::<()>(
            Err(NetworkWorkerRuntimeError::Quiescence(
                "unit remained populated".to_owned(),
            )),
            || released.set(released.get() + 1),
        );

        assert!(fail.is_err());
        assert_eq!(released.get(), 0);

        release_after_quiescence(Ok(()), || released.set(released.get() + 1)).unwrap();
        assert_eq!(released.get(), 1);
    }
}
