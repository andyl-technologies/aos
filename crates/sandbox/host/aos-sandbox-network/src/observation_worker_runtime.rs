//! Capability-separated Network preparation observation worker.
//!
//! The capability-free broker transfers its retained host and prepared target
//! Network namespace descriptors to a fresh systemd service. The worker accepts
//! only the canonical kernel plan bound to that durable preparation, enters the
//! supplied namespaces in a verified single-threaded process, and returns the
//! digest of two equal complete observations. It has no mutation dispatch,
//! authority key, replay ledger, or systemd descriptor-store access.

mod retaining;
pub(crate) mod child_programme_v2;
pub use child_programme_v2::run_inherited_network_observation_worker_entry_v2;
mod request_fields_v2;
use request_fields_v2::ObservationRequestFieldsV2;

pub(crate) use retaining::{NetworkParentObservationInputV2, NetworkParentObservationOriginalV2};
pub(crate) mod read_admission_v2;

use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{
    NamespaceFd, NamespaceIdentity, NamespaceKind,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketError,
};

use crate::kernel_plan::{NetworkKernelPlanError, NetworkKernelPlanV1};
use crate::kernel_reader::NetworkKernelReaderError;
use crate::lifecycle_state::AmbiguousNetworkLifecycleRecoveryV1;
use crate::namespace_catalog::{
    NetworkNamespaceObservedStateKindV1, NetworkNamespaceObservedStateV1,
};
use crate::namespace_observer::{
    NetworkNamespaceObserverError,
};
use crate::namespace_store::RetainedNetworkNamespace;
use crate::worker_process::{
    NetworkWorkerProcessError, acknowledgement, decode_acknowledgement, validate_broker_subject,
    validate_same_worker_execution, validate_systemd_manager_peer,
};
use crate::worker_runtime::{
    NetworkWorkerRuntimeError, PreparedNetworkWorkerOutput, RecoveredNetworkPreparationObservation,
    deadline_after, open_cgroup_root, quiesce_worker,
    receive_record_before, send_record_before, send_record_with_descriptors_before,
    wait_for_quiescence,
};

use crate::worker_process::cgroup_recipe::{WorkerCgroupPlacementV4, WorkerCgroupRoleV4};

const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const READY_MAGIC: &[u8; 8] = b"AOSNORD2";
const REQUEST_MAGIC: &[u8; 8] = b"AOSNORQ2";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSNORS2";
const WIRE_VERSION: u16 = 2;
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
    fixed_service: bool,
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
        crate::worker_runtime::prepare_observation_local(socket_path, cgroup_root, host_namespace)
    }

    pub(crate) fn from_completed_opening_v4(
        completed: crate::worker_runtime::CompletedObservationOpeningV4,
    ) -> Self {
        let (socket_path, systemd_manager_cgroup, worker_parent_cgroup, host_namespace, fixed_service) = completed.into_parts();
        Self { socket_path, systemd_manager_cgroup, worker_parent_cgroup,
            host_namespace, fixed_service, fail_stopped: false }
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

    /// Re-observes one restart-retained ambiguous preparation.
    ///
    /// The recovery value is derived from the protected creation journal and
    /// exact retained namespace descriptor. This path carries no preparation
    /// dispatch authority and therefore cannot repeat the original effect.
    ///
    /// # Errors
    ///
    /// Returns an error for plan substitution, stale namespace custody,
    /// malformed framing, an unequal or invalid kernel snapshot, or unproved
    /// whole-cgroup quiescence.
    pub fn observe_preparation_recovery_once(
        &mut self,
        recovered: RecoveredNetworkPreparationObservation<'_>,
        plan: &NetworkKernelPlanV1,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        if recovered.kernel_plan_digest() != plan.digest() {
            return protocol("preparation recovery plan changed");
        }
        let request = ObservationRequestV1::new(
            recovered.request_id(),
            recovered.effect_digest(),
            recovered.kernel_plan_digest(),
            recovered.kernel_boot_id(),
            recovered.namespace().identity(),
            NetworkNamespaceObservedStateV1::default_drop(),
            plan,
        )?;
        self.execute_observation(&request, recovered.namespace())
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

    pub(crate) fn observe_recovery_once(
        &mut self,
        recovery: AmbiguousNetworkLifecycleRecoveryV1,
        plan: &NetworkKernelPlanV1,
        target: &RetainedNetworkNamespace,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        let authority = recovery.authority();
        let identity = authority.identity;
        if authority.kernel_plan_digest != plan.digest()
            || identity.network_handle() != target.network_handle()
            || identity.namespace_device() != target.identity().device
            || identity.namespace_inode() != target.identity().inode
        {
            return protocol("lifecycle recovery custody is invalid");
        }
        let request = ObservationRequestV1::new(
            recovery.request_id(),
            recovery.effect_digest(),
            plan.digest(),
            identity.kernel_boot_id(),
            target.identity(),
            recovery.desired_state(),
            plan,
        )?;
        self.execute_observation(&request, target.namespace())
    }

    fn execute_observation(
        &mut self,
        request: &ObservationRequestV1,
        target_namespace: &NamespaceFd,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        retaining::observe_local_v4(self, request, target_namespace)
    }
}

struct ObservationReadyV1 {
    cgroup: String,
}

impl ObservationReadyV1 {
    fn new(cgroup: String) -> Result<Self, NetworkObservationWorkerError> {
        Self::new_engine(cgroup, WorkerCgroupPlacementV4::Ordinary)
    }

    fn new_receiving_v4(cgroup: String) -> Result<Self, NetworkObservationWorkerError> {
        Self::new_engine(cgroup, WorkerCgroupPlacementV4::Receiving)
    }

    fn new_engine(
        cgroup: String,
        placement: WorkerCgroupPlacementV4,
    ) -> Result<Self, NetworkObservationWorkerError> {
        placement.require_path(&cgroup, WorkerCgroupRoleV4::Observation)?;
        Ok(Self { cgroup })
    }

    fn cgroup(&self) -> &str {
        &self.cgroup
    }

    fn encode(&self) -> Result<Vec<u8>, NetworkObservationWorkerError> {
        crate::worker_process::cgroup_recipe::require_constructed_ready_path(&self.cgroup, WorkerCgroupRoleV4::Observation)?;
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
        Self::decode_engine(bytes, WorkerCgroupPlacementV4::Ordinary)
    }

    fn decode_receiving_v4(bytes: &[u8]) -> Result<Self, NetworkObservationWorkerError> {
        Self::decode_engine(bytes, WorkerCgroupPlacementV4::Receiving)
    }

    fn decode_engine(
        bytes: &[u8],
        placement: WorkerCgroupPlacementV4,
    ) -> Result<Self, NetworkObservationWorkerError> {
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
        let ready = Self::new_engine(cgroup, placement)?;
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

    fn fields_data_v2(&self) -> ObservationRequestFieldsV2 {
        ObservationRequestFieldsV2 { request_id: self.request_id, effect_digest: self.effect_digest,
            kernel_plan_digest: self.kernel_plan_digest, kernel_boot_id: self.kernel_boot_id,
            namespace: self.namespace, expected_state: self.expected_state }
    }

    fn validate(&self) -> Result<(), NetworkObservationWorkerError> {
        self.fields_data_v2().validate(&self.plan)
    }

    fn encode(&self) -> Result<Vec<u8>, NetworkObservationWorkerError> {
        self.fields_data_v2().encode(&self.plan)
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

fn validate_request_namespace_roles(
    peer: &ConnectionPeerIdentity,
    host: &NamespaceFd,
    target: &NamespaceFd,
    peer_namespace: &NamespaceFd,
    expected_target: NamespaceIdentity,
) -> Result<(), NetworkObservationWorkerError> {
    if host.identity() != peer_namespace.identity()
        || host.identity() == target.identity()
        || target.identity() != expected_target
        || !peer.is_alive()?
    {
        return Err(NetworkObservationWorkerError::Process(
            NetworkWorkerProcessError::PeerMismatch,
        ));
    }
    Ok(())
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

fn validate_observer_cgroup(cgroup: &str) -> Result<(), NetworkObservationWorkerError> {
    WorkerCgroupPlacementV4::Ordinary.require_path(cgroup, WorkerCgroupRoleV4::Observation)?;
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

#[cfg(test)]
mod receiving_ready_tests {
    use super::*;

    #[test]
    fn v2_observer_refuses_legacy_headers_before_read_admission() {
        let mut ready = ObservationReadyV1::new(
            "aos.slice/aos-control.slice/aos-sandbox-network-observation-worker@0-984321-543_876-0.service".to_owned(),
        ).unwrap().encode().unwrap();
        ready[..8].copy_from_slice(b"AOSNORD1");
        ready[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(ObservationReadyV1::decode(&ready).is_err());

        let mut old_request = vec![0; REQUEST_HEADER_BYTES];
        old_request[..8].copy_from_slice(b"AOSNORQ1");
        old_request[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(ObservationRequestV1::decode(&old_request),
            Err(NetworkObservationWorkerError::Protocol("observation request header is invalid"))));

        let mut old_response = [0; RESPONSE_BYTES];
        old_response[..8].copy_from_slice(b"AOSNORS1");
        old_response[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(decode_response(&old_response),
            Err(NetworkObservationWorkerError::Protocol("observation response header is invalid"))));
    }

    #[test]
    fn observation_ready_chooses_one_expected_placement_without_ordinary_fallback() {
        let ordinary = "aos.slice/aos-control.slice/aos-sandbox-network-observation-worker@0-984321-543_876-0.service";
        let receiving = "aoscomponents.slice/aoscomponents-network.slice/aos-sandbox-network-observation-worker@0-984321-543_876-0.service";
        let old_bytes = ObservationReadyV1::new(ordinary.to_owned())
            .unwrap()
            .encode()
            .unwrap();
        let selected_bytes = ObservationReadyV1::new_receiving_v4(receiving.to_owned())
            .unwrap()
            .encode()
            .unwrap();

        assert_eq!(&old_bytes[..12], &selected_bytes[..12]);
        assert_eq!(selected_bytes.len(), READY_HEADER_BYTES + receiving.len());
        assert_eq!(
            ObservationReadyV1::decode_receiving_v4(&selected_bytes)
                .unwrap()
                .cgroup(),
            receiving
        );
        assert!(ObservationReadyV1::decode(&selected_bytes).is_err());
        assert!(ObservationReadyV1::decode_receiving_v4(&old_bytes).is_err());
        assert!(ObservationReadyV1::new(receiving.to_owned()).is_err());
        assert!(ObservationReadyV1::new_receiving_v4(ordinary.to_owned()).is_err());
        assert_eq!(
            ObservationReadyV1::decode(&old_bytes)
                .unwrap()
                .encode()
                .unwrap(),
            old_bytes
        );
    }
}

impl SystemdNetworkObservationExecutor {
    // Synchronous calls retain all live worker custody until completion. This
    // local check is only a conjunct of the independent whole-native census.
    pub(crate) fn inventory_local_custody_clear_v2(&self) -> bool {
        !self.fail_stopped && self.fixed_service
    }
}
