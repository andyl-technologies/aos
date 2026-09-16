//! Capability-separated Network preparation observation worker.
//!
//! The capability-free broker transfers its retained host and prepared target
//! Network namespace descriptors to a fresh systemd service. The worker accepts
//! only the canonical kernel plan bound to that durable preparation, enters the
//! supplied namespaces in a verified single-threaded process, and returns the
//! digest of two equal complete observations. It has no mutation dispatch,
//! authority key, replay ledger, or systemd descriptor-store access.

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{
    NamespaceFd, NamespaceIdentity, NamespaceKind, SingleThreadedProcess,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketError,
};

use crate::kernel_plan::{NetworkKernelPlanError, NetworkKernelPlanV1};
use crate::kernel_reader::{FixedBpfObservationReader, NetworkKernelReaderError};
use crate::namespace_catalog::{
    NetworkNamespaceObservedStateKindV1, NetworkNamespaceObservedStateV1,
};
use crate::namespace_observer::{
    NetworkKernelObservationReaders, NetworkNamespaceObserverError,
    observe_stable_destroyed_network_kernel, observe_stable_expected_network_kernel,
};
use crate::namespace_store::RetainedNetworkNamespace;
use crate::nftables_reader::FixedNftablesObservationReader;
use crate::rtnetlink_reader::FixedRtnetlinkObservationReader;
use crate::systemd_socket_instance::validate_systemd_socket_instance_fields;
use crate::worker_process::{
    NetworkWorkerProcessError, acknowledgement, decode_acknowledgement, validate_broker_subject,
    validate_same_worker_execution, validate_systemd_manager_peer,
};
use crate::worker_runtime::{
    NetworkWorkerRuntimeError, PreparedNetworkWorkerOutput, current_cgroup, deadline_after,
    normalized_absolute_path, open_cgroup_root, quiesce_worker, receive_record_before,
    send_record_before, send_record_with_descriptors_before, wait_for_quiescence,
};

const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const OBSERVER_CGROUP_PREFIX: &str =
    "aos.slice/aos-control.slice/aos-sandbox-network-observation-worker@";
const OBSERVER_CGROUP_SUFFIX: &str = ".service";
const READY_MAGIC: &[u8; 8] = b"AOSNORD1";
const REQUEST_MAGIC: &[u8; 8] = b"AOSNORQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSNORS1";
const WIRE_VERSION: u16 = 1;
const READY_KIND: u8 = 1;
const REQUEST_KIND: u8 = 2;
const RESPONSE_KIND: u8 = 3;
const READY_HEADER_BYTES: usize = 16;
const REQUEST_HEADER_BYTES: usize = 184;
const RESPONSE_BYTES: usize = 212;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const MAXIMUM_REQUEST_BYTES: usize = REQUEST_HEADER_BYTES + 512 * 1024;
const ACK_BYTES: usize = 10;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);
const NATURAL_EXIT_TIMEOUT: Duration = Duration::from_secs(1);

/// Reports rejected observation-worker transport, authority, or postconditions.
#[derive(Debug, thiserror::Error)]
pub enum NetworkObservationWorkerError {
    /// A bounded path, record, descriptor role, or identity was invalid.
    #[error("Network observation worker protocol is invalid: {0}")]
    Protocol(&'static str),
    /// The fixed worker process or cgroup identity was substituted.
    #[error(transparent)]
    Process(#[from] NetworkWorkerProcessError),
    /// The shared bounded worker transport or quiescence proof failed.
    #[error(transparent)]
    Runtime(#[from] NetworkWorkerRuntimeError),
    /// A transferred descriptor or namespace transition failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The bounded descriptor-capable sequenced-packet transport failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// The canonical kernel plan was invalid or changed.
    #[error(transparent)]
    Plan(#[from] NetworkKernelPlanError),
    /// A fixed read-only observation helper or artifact was invalid.
    #[error(transparent)]
    Reader(#[from] NetworkKernelReaderError),
    /// The complete stable kernel observation did not match the plan.
    #[error(transparent)]
    Observation(#[from] NetworkNamespaceObserverError),
    /// A bounded local procfs read failed.
    #[error("Network observation worker local I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A direct descriptor operation failed.
    #[error("Network observation worker descriptor operation failed: {0}")]
    Descriptor(#[from] rustix::io::Errno),
}

/// Names the immutable readers available to the read-only observation worker.
#[derive(Clone, Debug)]
pub struct NetworkObservationWorkerConfiguration {
    /// Fixed AOS-built `ip` executable.
    pub ip: PathBuf,
    /// Fixed AOS-built `nft` executable.
    pub nft: PathBuf,
    /// Reviewed enforcement loader whose digest is committed by the plan.
    pub enforcement_loader: PathBuf,
    /// Fixed read-only BPF graph observer.
    pub bpf_observer: PathBuf,
    /// Exact BPF object measured by the observer.
    pub lease_gate_object: PathBuf,
}

/// Carries one worker-authenticated stable observation commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedNetworkObservationV1 {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
    namespace: NamespaceIdentity,
    observed_state: NetworkNamespaceObservedStateV1,
    observation_digest: ObjectDigest,
}

impl PreparedNetworkObservationV1 {
    /// Returns the correlated durable request identity.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the correlated durable effect identity.
    #[must_use]
    pub const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the exact canonical kernel-plan commitment.
    #[must_use]
    pub const fn kernel_plan_digest(self) -> ObjectDigest {
        self.kernel_plan_digest
    }

    /// Returns the Linux boot in which the observation was made.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the exact observed target namespace identity.
    #[must_use]
    pub const fn namespace(self) -> NamespaceIdentity {
        self.namespace
    }

    /// Returns the exact closed lifecycle state proved by the snapshots.
    #[must_use]
    pub const fn observed_state(self) -> NetworkNamespaceObservedStateV1 {
        self.observed_state
    }

    /// Returns the digest of the two equal complete observations.
    #[must_use]
    pub const fn observation_digest(self) -> ObjectDigest {
        self.observation_digest
    }
}

/// Executes stable postcondition observation through a fresh systemd worker.
pub struct SystemdNetworkObservationExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: RetainedCgroupAnchor,
    worker_parent_cgroup: RetainedCgroupAnchor,
    host_namespace: NamespaceFd,
    fail_stopped: bool,
}

impl SystemdNetworkObservationExecutor {
    /// Retains the fixed worker socket, cgroup roots, and initial host namespace.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket path, invalid host namespace, or
    /// unavailable systemd-manager or control-slice cgroup custody.
    pub fn new(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
        host_namespace: NamespaceFd,
    ) -> Result<Self, NetworkObservationWorkerError> {
        if !normalized_absolute_path(&socket_path) {
            return Err(NetworkObservationWorkerError::Protocol(
                "unsafe Network observation-worker socket path",
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

    /// Observes one quiescent prepared namespace and proves worker termination.
    ///
    /// # Errors
    ///
    /// Returns an error for worker substitution, descriptor drift, malformed
    /// framing, an unequal or invalid kernel snapshot, or unproved cgroup
    /// quiescence. An inconclusive cancellation permanently fail-stops this owner.
    pub fn observe_once(
        &mut self,
        prepared: &PreparedNetworkWorkerOutput,
        plan: &NetworkKernelPlanV1,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        if self.fail_stopped {
            return Err(NetworkObservationWorkerError::Protocol(
                "Network observation executor is fail-stopped",
            ));
        }
        self.host_namespace.validate_current_network()?;
        let request = ObservationRequestV1::new(
            prepared.request_id(),
            prepared.effect_digest(),
            prepared.kernel_plan_digest(),
            prepared.kernel_boot_id(),
            prepared.namespace().identity(),
            NetworkNamespaceObservedStateV1::default_drop(),
            plan,
        )?;
        self.execute_observation(&request, prepared.namespace())
    }

    /// Observes one present lifecycle postcondition and proves worker exit.
    ///
    /// # Errors
    ///
    /// Returns an error for substituted execution identity or namespace
    /// custody, malformed framing, an unequal or invalid snapshot, or
    /// unproved whole-cgroup quiescence.
    pub fn observe_lifecycle_once(
        &mut self,
        execution: crate::ExecutedNetworkLifecycleWorkerV1,
        plan: &NetworkKernelPlanV1,
        kernel_boot_id: [u8; 16],
        expected_state: NetworkNamespaceObservedStateV1,
        target: &RetainedNetworkNamespace,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        if execution.target_namespace() != target.namespace().identity() {
            return protocol("lifecycle execution target custody changed");
        }
        let request = ObservationRequestV1::new(
            execution.request_id(),
            execution.effect_digest(),
            plan.digest(),
            kernel_boot_id,
            target.namespace().identity(),
            expected_state,
            plan,
        )?;
        self.execute_observation(&request, target.namespace())
    }

    /// Observes exact plan-owned kernel-object absence after Destroy execution.
    ///
    /// The retained target descriptor remains live for the complete read. This
    /// proves kernel cleanup only; the broker must still remove and read back
    /// the systemd descriptor-store pin before committing an Absent transition.
    ///
    /// # Errors
    ///
    /// Returns an error for substituted execution identity or namespace
    /// custody, any remaining owned object, unstable snapshots, malformed
    /// framing, or unproved whole-cgroup quiescence.
    pub fn observe_destroyed_once(
        &mut self,
        execution: crate::ExecutedNetworkLifecycleWorkerV1,
        plan: &NetworkKernelPlanV1,
        target: &RetainedNetworkNamespace,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        if execution.action() != crate::NetworkNamespaceLifecycleActionV1::Destroy
            || execution.desired_state().kind() != NetworkNamespaceObservedStateKindV1::Absent
            || execution.target_namespace() != target.namespace().identity()
        {
            return protocol("destroy observation custody is invalid");
        }
        let request = ObservationRequestV1::new(
            execution.request_id(),
            execution.effect_digest(),
            plan.digest(),
            execution.target_identity().kernel_boot_id(),
            target.namespace().identity(),
            NetworkNamespaceObservedStateV1::absent(),
            plan,
        )?;
        self.execute_observation(&request, target.namespace())
    }

    fn execute_observation(
        &mut self,
        request: &ObservationRequestV1,
        target_namespace: &NamespaceFd,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        if self.fail_stopped {
            return Err(NetworkObservationWorkerError::Protocol(
                "Network observation executor is fail-stopped",
            ));
        }
        self.host_namespace.validate_current_network()?;
        let mut socket = DescriptorSubjectSocket::connect(&self.socket_path)?;
        validate_systemd_manager_peer(socket.peer(), &self.systemd_manager_cgroup)?;

        let ready = receive_record_before(
            &mut socket,
            READY_HEADER_BYTES + MAXIMUM_CGROUP_BYTES,
            0,
            deadline_after(TRANSFER_TIMEOUT)?,
        )?;
        let ready_payload = ObservationReadyV1::decode(ready.payload())?;
        let worker_cgroup = validate_observer_subject(
            ready_payload.cgroup(),
            ready.subject(),
            &self.worker_parent_cgroup,
        )?;
        let population = worker_cgroup.population_monitor()?;

        let exchange = exchange_observation(
            &mut socket,
            request,
            self.host_namespace.as_fd(),
            target_namespace.as_fd(),
            ready.subject(),
            &worker_cgroup,
        );
        match exchange {
            Ok(observation) => {
                match wait_for_quiescence(ready.subject(), &population, NATURAL_EXIT_TIMEOUT) {
                    Ok(()) => Ok(observation),
                    Err(error) => {
                        if quiesce_worker(ready.subject(), &worker_cgroup, &population).is_err() {
                            self.fail_stopped = true;
                        }
                        Err(error.into())
                    }
                }
            }
            Err(error) => {
                if quiesce_worker(ready.subject(), &worker_cgroup, &population).is_err() {
                    self.fail_stopped = true;
                }
                Err(error)
            }
        }
    }
}

/// Runs one inherited, read-only Network observation worker.
///
/// # Errors
///
/// Returns an error unless the fixed broker, both descriptor roles, canonical
/// plan, immutable readers, stable observation, and final acknowledgement all
/// validate within the one-record service lifetime.
pub fn run_inherited_network_observation_worker(
    configuration: NetworkObservationWorkerConfiguration,
) -> Result<(), NetworkObservationWorkerError> {
    let worker = SingleThreadedProcess::verify()?;
    worker.disable_core_dumps()?;
    let readers = FixedObservationReaders::open(configuration)?;
    let cgroup_root = open_cgroup_root()?;
    let control_cgroup = cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;
    validate_observer_broker_peer(socket.peer(), &control_cgroup)?;

    let ready = ObservationReadyV1::new(current_cgroup()?)?;
    send_record_before(
        &mut socket,
        &ready.encode()?,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    let request_record = receive_record_before(
        &mut socket,
        MAXIMUM_REQUEST_BYTES,
        2,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    validate_broker_subject(socket.peer(), request_record.subject(), &control_cgroup)?;
    let (request_bytes, _subject, descriptors) = request_record.into_parts();
    let request = ObservationRequestV1::decode(&request_bytes)?;
    let (host_namespace, target_namespace) =
        validate_request_descriptors(socket.peer(), descriptors, request.namespace)?;
    host_namespace.enter(&worker)?;
    host_namespace.validate_current_network()?;

    let observation_digest =
        if request.expected_state.kind() == NetworkNamespaceObservedStateKindV1::Absent {
            observe_stable_destroyed_network_kernel(
                readers.for_plan(&request.plan),
                &request.plan,
                &target_namespace,
                request.kernel_plan_digest,
                request.kernel_boot_id,
                &host_namespace,
                &worker,
            )?
        } else {
            observe_stable_expected_network_kernel(
                readers.for_plan(&request.plan),
                &request.plan,
                &target_namespace,
                request.kernel_plan_digest,
                request.kernel_boot_id,
                request.expected_state,
                &host_namespace,
                &worker,
            )?
            .digest()
        };
    let response = PreparedNetworkObservationV1 {
        request_id: request.request_id,
        effect_digest: request.effect_digest,
        kernel_plan_digest: request.kernel_plan_digest,
        kernel_boot_id: request.kernel_boot_id,
        namespace: request.namespace,
        observed_state: request.expected_state,
        observation_digest,
    };
    let deadline = deadline_after(TRANSFER_TIMEOUT)?;
    send_record_before(&mut socket, &encode_response(response), deadline)?;
    let acknowledgement_record = receive_record_before(&mut socket, ACK_BYTES, 0, deadline)?;
    validate_broker_subject(
        socket.peer(),
        acknowledgement_record.subject(),
        &control_cgroup,
    )?;
    decode_acknowledgement(acknowledgement_record.payload())?;
    Ok(())
}

struct FixedObservationReaders {
    rtnetlink: FixedRtnetlinkObservationReader,
    nftables: FixedNftablesObservationReader,
    bpf: FixedBpfObservationReader,
}

impl FixedObservationReaders {
    fn open(
        configuration: NetworkObservationWorkerConfiguration,
    ) -> Result<Self, NetworkObservationWorkerError> {
        Ok(Self {
            rtnetlink: FixedRtnetlinkObservationReader::new(configuration.ip)?,
            nftables: FixedNftablesObservationReader::new(
                configuration.nft,
                configuration.enforcement_loader,
            )?,
            bpf: FixedBpfObservationReader::new(
                configuration.bpf_observer,
                configuration.lease_gate_object,
            )?,
        })
    }

    fn for_plan<'a>(&'a self, plan: &NetworkKernelPlanV1) -> NetworkKernelObservationReaders<'a> {
        let bpf = match plan.observation_expectation().kind() {
            NetworkKind::Isolated | NetworkKind::Host => None,
            NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => {
                Some(&self.bpf)
            }
        };
        NetworkKernelObservationReaders::new(&self.rtnetlink, &self.nftables, bpf)
    }
}

struct ObservationReadyV1 {
    cgroup: String,
}

impl ObservationReadyV1 {
    fn new(cgroup: String) -> Result<Self, NetworkObservationWorkerError> {
        validate_observer_cgroup(&cgroup)?;
        Ok(Self { cgroup })
    }

    fn cgroup(&self) -> &str {
        &self.cgroup
    }

    fn encode(&self) -> Result<Vec<u8>, NetworkObservationWorkerError> {
        validate_observer_cgroup(&self.cgroup)?;
        let cgroup = self.cgroup.as_bytes();
        let length = u16::try_from(cgroup.len())
            .map_err(|_| NetworkObservationWorkerError::Protocol("observer cgroup is too long"))?;
        let mut bytes = Vec::with_capacity(READY_HEADER_BYTES + cgroup.len());
        bytes.extend_from_slice(READY_MAGIC);
        bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes.push(READY_KIND);
        bytes.push(0);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(cgroup);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkObservationWorkerError> {
        if bytes.len() < READY_HEADER_BYTES
            || bytes.len() > READY_HEADER_BYTES + MAXIMUM_CGROUP_BYTES
            || &bytes[..8] != READY_MAGIC
            || u16::from_be_bytes(copy_array(&bytes[8..10])?) != WIRE_VERSION
            || bytes[10] != READY_KIND
            || bytes[11] != 0
            || bytes[14..16] != [0; 2]
        {
            return protocol("observation READY header is invalid");
        }
        let length = usize::from(u16::from_be_bytes(copy_array(&bytes[12..14])?));
        if length == 0 || bytes.len() != READY_HEADER_BYTES + length {
            return protocol("observation READY length is invalid");
        }
        let cgroup = std::str::from_utf8(&bytes[READY_HEADER_BYTES..])
            .map_err(|_| NetworkObservationWorkerError::Protocol("observer cgroup is not UTF-8"))?
            .to_owned();
        let ready = Self::new(cgroup)?;
        if ready.encode()? != bytes {
            return protocol("observation READY is not canonical");
        }
        Ok(ready)
    }
}

struct ObservationRequestV1 {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
    namespace: NamespaceIdentity,
    expected_state: NetworkNamespaceObservedStateV1,
    plan: NetworkKernelPlanV1,
}

impl ObservationRequestV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        kernel_boot_id: [u8; 16],
        namespace: NamespaceIdentity,
        expected_state: NetworkNamespaceObservedStateV1,
        plan: &NetworkKernelPlanV1,
    ) -> Result<Self, NetworkObservationWorkerError> {
        let request = Self {
            request_id,
            effect_digest,
            kernel_plan_digest,
            kernel_boot_id,
            namespace,
            expected_state,
            plan: plan.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), NetworkObservationWorkerError> {
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || self.kernel_plan_digest != self.plan.digest()
            || self.kernel_boot_id == [0; 16]
            || self.namespace.device == 0
            || self.namespace.inode == 0
        {
            return protocol("observation request identity is invalid");
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, NetworkObservationWorkerError> {
        self.validate()?;
        let total = REQUEST_HEADER_BYTES
            .checked_add(self.plan.as_bytes().len())
            .ok_or(NetworkObservationWorkerError::Protocol(
                "observation request length overflowed",
            ))?;
        let total_u32 = u32::try_from(total).map_err(|_| {
            NetworkObservationWorkerError::Protocol("observation request is too large")
        })?;
        let plan_length = u32::try_from(self.plan.as_bytes().len())
            .map_err(|_| NetworkObservationWorkerError::Protocol("kernel plan is too large"))?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes.push(REQUEST_KIND);
        bytes.push(0);
        bytes.extend_from_slice(&total_u32.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(self.effect_digest.as_bytes());
        bytes.extend_from_slice(self.kernel_plan_digest.as_bytes());
        bytes.extend_from_slice(&self.kernel_boot_id);
        bytes.extend_from_slice(&self.namespace.device.to_be_bytes());
        bytes.extend_from_slice(&self.namespace.inode.to_be_bytes());
        bytes.push(observed_state_code(self.expected_state.kind()));
        bytes.extend_from_slice(&[0; 3]);
        let (lease_digest, lease_generation, lease_deadline) = self
            .expected_state
            .lease()
            .unwrap_or((ObjectDigest::from_bytes([0; 32]), 0, 0));
        bytes.extend_from_slice(lease_digest.as_bytes());
        bytes.extend_from_slice(&lease_generation.to_be_bytes());
        bytes.extend_from_slice(&lease_deadline.to_be_bytes());
        bytes.extend_from_slice(&plan_length.to_be_bytes());
        bytes.extend_from_slice(self.plan.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkObservationWorkerError> {
        if bytes.len() < REQUEST_HEADER_BYTES
            || bytes.len() > MAXIMUM_REQUEST_BYTES
            || &bytes[..8] != REQUEST_MAGIC
            || u16::from_be_bytes(copy_array(&bytes[8..10])?) != WIRE_VERSION
            || bytes[10] != REQUEST_KIND
            || bytes[11] != 0
            || usize::try_from(u32::from_be_bytes(copy_array(&bytes[12..16])?)).ok()
                != Some(bytes.len())
            || bytes[129..132] != [0; 3]
        {
            return protocol("observation request header is invalid");
        }
        let plan_length = usize::try_from(u32::from_be_bytes(copy_array(&bytes[180..184])?))
            .map_err(|_| {
                NetworkObservationWorkerError::Protocol("kernel plan length is invalid")
            })?;
        if REQUEST_HEADER_BYTES.checked_add(plan_length) != Some(bytes.len()) {
            return protocol("observation request plan length differs");
        }
        let expected_state = decode_observed_state(
            bytes[128],
            ObjectDigest::from_bytes(copy_array(&bytes[132..164])?),
            u64::from_be_bytes(copy_array(&bytes[164..172])?),
            u64::from_be_bytes(copy_array(&bytes[172..180])?),
        )?;
        let request = Self {
            request_id: copy_array(&bytes[16..32])?,
            effect_digest: ObjectDigest::from_bytes(copy_array(&bytes[32..64])?),
            kernel_plan_digest: ObjectDigest::from_bytes(copy_array(&bytes[64..96])?),
            kernel_boot_id: copy_array(&bytes[96..112])?,
            namespace: NamespaceIdentity {
                device: u64::from_be_bytes(copy_array(&bytes[112..120])?),
                inode: u64::from_be_bytes(copy_array(&bytes[120..128])?),
            },
            expected_state,
            plan: NetworkKernelPlanV1::decode(&bytes[REQUEST_HEADER_BYTES..])?,
        };
        request.validate()?;
        if request.encode()? != bytes {
            return protocol("observation request is not canonical");
        }
        Ok(request)
    }
}

fn exchange_observation(
    socket: &mut DescriptorSubjectSocket,
    request: &ObservationRequestV1,
    host_namespace: std::os::fd::BorrowedFd<'_>,
    target_namespace: std::os::fd::BorrowedFd<'_>,
    ready_subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
    let deadline = deadline_after(TRANSFER_TIMEOUT)?;
    send_record_with_descriptors_before(
        socket,
        &request.encode()?,
        &[host_namespace, target_namespace],
        deadline,
    )?;
    let response_record = receive_record_before(socket, RESPONSE_BYTES, 0, deadline)?;
    validate_same_worker_execution(ready_subject, response_record.subject())?;
    validate_observer_subject_record(response_record.subject(), worker_cgroup)?;
    let response = decode_response(response_record.payload())?;
    if response.request_id != request.request_id
        || response.effect_digest != request.effect_digest
        || response.kernel_plan_digest != request.kernel_plan_digest
        || response.kernel_boot_id != request.kernel_boot_id
        || response.namespace != request.namespace
        || response.observed_state != request.expected_state
    {
        return protocol("observation response differs from the request");
    }
    send_record_before(socket, &acknowledgement(), deadline)?;
    Ok(response)
}

fn encode_response(response: PreparedNetworkObservationV1) -> [u8; RESPONSE_BYTES] {
    let mut bytes = [0_u8; RESPONSE_BYTES];
    bytes[..8].copy_from_slice(RESPONSE_MAGIC);
    bytes[8..10].copy_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes[10] = RESPONSE_KIND;
    bytes[12..16].copy_from_slice(&(RESPONSE_BYTES as u32).to_be_bytes());
    bytes[16..32].copy_from_slice(&response.request_id);
    bytes[32..64].copy_from_slice(response.effect_digest.as_bytes());
    bytes[64..96].copy_from_slice(response.kernel_plan_digest.as_bytes());
    bytes[96..112].copy_from_slice(&response.kernel_boot_id);
    bytes[112..120].copy_from_slice(&response.namespace.device.to_be_bytes());
    bytes[120..128].copy_from_slice(&response.namespace.inode.to_be_bytes());
    bytes[128] = observed_state_code(response.observed_state.kind());
    let (lease_digest, lease_generation, lease_deadline) = response
        .observed_state
        .lease()
        .unwrap_or((ObjectDigest::from_bytes([0; 32]), 0, 0));
    bytes[132..164].copy_from_slice(lease_digest.as_bytes());
    bytes[164..172].copy_from_slice(&lease_generation.to_be_bytes());
    bytes[172..180].copy_from_slice(&lease_deadline.to_be_bytes());
    bytes[180..212].copy_from_slice(response.observation_digest.as_bytes());
    bytes
}

fn decode_response(
    bytes: &[u8],
) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
    if bytes.len() != RESPONSE_BYTES
        || &bytes[..8] != RESPONSE_MAGIC
        || u16::from_be_bytes(copy_array(&bytes[8..10])?) != WIRE_VERSION
        || bytes[10] != RESPONSE_KIND
        || bytes[11] != 0
        || u32::from_be_bytes(copy_array(&bytes[12..16])?) != RESPONSE_BYTES as u32
        || bytes[129..132] != [0; 3]
    {
        return protocol("observation response header is invalid");
    }
    let response = PreparedNetworkObservationV1 {
        request_id: copy_array(&bytes[16..32])?,
        effect_digest: ObjectDigest::from_bytes(copy_array(&bytes[32..64])?),
        kernel_plan_digest: ObjectDigest::from_bytes(copy_array(&bytes[64..96])?),
        kernel_boot_id: copy_array(&bytes[96..112])?,
        namespace: NamespaceIdentity {
            device: u64::from_be_bytes(copy_array(&bytes[112..120])?),
            inode: u64::from_be_bytes(copy_array(&bytes[120..128])?),
        },
        observed_state: decode_observed_state(
            bytes[128],
            ObjectDigest::from_bytes(copy_array(&bytes[132..164])?),
            u64::from_be_bytes(copy_array(&bytes[164..172])?),
            u64::from_be_bytes(copy_array(&bytes[172..180])?),
        )?,
        observation_digest: ObjectDigest::from_bytes(copy_array(&bytes[180..212])?),
    };
    if response.request_id == [0; 16]
        || response.effect_digest.as_bytes() == &[0; 32]
        || response.kernel_plan_digest.as_bytes() == &[0; 32]
        || response.kernel_boot_id == [0; 16]
        || response.namespace.device == 0
        || response.namespace.inode == 0
        || response.observation_digest.as_bytes() == &[0; 32]
        || encode_response(response).as_slice() != bytes
    {
        return protocol("observation response identity is invalid");
    }
    Ok(response)
}

fn validate_request_descriptors(
    peer: &ConnectionPeerIdentity,
    descriptors: Vec<OwnedFd>,
    expected_target: NamespaceIdentity,
) -> Result<(NamespaceFd, NamespaceFd), NetworkObservationWorkerError> {
    if descriptors.len() != 2 {
        return protocol("observation request requires host and target namespace descriptors");
    }
    let mut descriptors = descriptors.into_iter();
    let host = NamespaceFd::from_owned(
        descriptors
            .next()
            .ok_or(NetworkObservationWorkerError::Protocol(
                "host namespace is absent",
            ))?,
        NamespaceKind::Network,
    )?;
    let target = NamespaceFd::from_owned(
        descriptors
            .next()
            .ok_or(NetworkObservationWorkerError::Protocol(
                "target namespace is absent",
            ))?,
        NamespaceKind::Network,
    )?;
    let peer_namespace = peer.pidfd().namespace(NamespaceKind::Network)?;
    if host.identity() != peer_namespace.identity()
        || host.identity() == target.identity()
        || target.identity() != expected_target
        || !peer.is_alive()?
    {
        return Err(NetworkObservationWorkerError::Process(
            NetworkWorkerProcessError::PeerMismatch,
        ));
    }
    Ok((host, target))
}

fn validate_observer_subject(
    cgroup: &str,
    subject: &KernelAuthorizedRecordSubject,
    worker_parent: &RetainedCgroupAnchor,
) -> Result<RetainedCgroupAnchor, NetworkObservationWorkerError> {
    validate_observer_cgroup(cgroup)?;
    let relative = Path::new(cgroup)
        .strip_prefix(CONTROL_SLICE_CGROUP)
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)?;
    let worker_cgroup = worker_parent.resolve_descendant(relative)?;
    validate_observer_subject_record(subject, &worker_cgroup)?;
    worker_parent.validate_current()?;
    Ok(worker_cgroup)
}

fn validate_observer_subject_record(
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkObservationWorkerError> {
    let credentials = subject.credentials();
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != credentials.pid().get()
        || info.thread_group_id() != credentials.pid().get()
        || !subject.is_alive()?
    {
        return Err(NetworkObservationWorkerError::Process(
            NetworkWorkerProcessError::PeerMismatch,
        ));
    }
    worker_cgroup.validate_current()?;
    Ok(())
}

fn validate_observer_broker_peer(
    peer: &ConnectionPeerIdentity,
    control_cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkObservationWorkerError> {
    crate::worker_process::validate_broker_peer(peer, control_cgroup)?;
    Ok(())
}

fn validate_observer_cgroup(cgroup: &str) -> Result<(), NetworkObservationWorkerError> {
    let Some(instance) = cgroup
        .strip_prefix(OBSERVER_CGROUP_PREFIX)
        .and_then(|value| value.strip_suffix(OBSERVER_CGROUP_SUFFIX))
    else {
        return Err(NetworkObservationWorkerError::Process(
            NetworkWorkerProcessError::PeerMismatch,
        ));
    };
    validate_systemd_socket_instance_fields(instance)
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)?;
    Ok(())
}

const fn observed_state_code(kind: NetworkNamespaceObservedStateKindV1) -> u8 {
    match kind {
        NetworkNamespaceObservedStateKindV1::DefaultDrop => 1,
        NetworkNamespaceObservedStateKindV1::Armed => 2,
        NetworkNamespaceObservedStateKindV1::Fenced => 3,
        NetworkNamespaceObservedStateKindV1::Absent => 4,
    }
}

fn decode_observed_state(
    kind: u8,
    lease_digest: ObjectDigest,
    lease_generation: u64,
    lease_deadline: u64,
) -> Result<NetworkNamespaceObservedStateV1, NetworkObservationWorkerError> {
    let no_lease =
        lease_digest.as_bytes() == &[0; 32] && lease_generation == 0 && lease_deadline == 0;
    match kind {
        1 if no_lease => Ok(NetworkNamespaceObservedStateV1::default_drop()),
        2 => NetworkNamespaceObservedStateV1::armed(lease_digest, lease_generation, lease_deadline)
            .map_err(|_| {
                NetworkObservationWorkerError::Protocol("observed lease state is invalid")
            }),
        3 => {
            NetworkNamespaceObservedStateV1::fenced(lease_digest, lease_generation, lease_deadline)
                .map_err(|_| {
                    NetworkObservationWorkerError::Protocol("observed lease state is invalid")
                })
        }
        4 if no_lease => Ok(NetworkNamespaceObservedStateV1::absent()),
        _ => protocol("observed lifecycle state is invalid"),
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NetworkObservationWorkerError> {
    bytes
        .try_into()
        .map_err(|_| NetworkObservationWorkerError::Protocol("observation record is truncated"))
}

fn protocol<T>(message: &'static str) -> Result<T, NetworkObservationWorkerError> {
    Err(NetworkObservationWorkerError::Protocol(message))
}
