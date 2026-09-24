//! One-transaction typed systemd workers and pinned runtime observations.

pub mod shifted_payload_inspection;
mod systemd;

use std::collections::VecDeque;
use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Mutex;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{
    CgroupFreezerState, CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root,
    RetainedCgroupAnchor,
};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, PidFd};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_systemd::{
    ExactStartError, ExactStopError, ExactStopOutcome, ExactUnitClient, ExactUnitObservation,
    ExactUnitRole, ExactUnitState, ExactUnitTarget, FreezerState, GuardianStartError,
    GuardianUnitObservation, GuardianUnitSpec, JobResult, PayloadRootContinuityPolicyV1,
    PostUnrefUnitObservation, SandboxCgroupPath, SandboxUnitName, SandboxUnitObservation,
    SandboxUnitSpec, SystemdClient,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::plan::LaunchPins;
use crate::state::transition::{
    NamespaceProofSnapshot, ProcessProofSnapshot, RuntimeProofSnapshot,
};
use crate::{HostError, Result};

use self::shifted_payload_inspection::VerifiedShiftedPayloadInspectionV1;
use self::systemd::{open_payload_root, read_nested_pid};

#[cfg(test)]
use self::systemd::{LinuxPayloadInspector, parse_nested_pid, verify_supervisor_pins};

const MAXIMUM_PAYLOAD_CGROUPS: usize = 4096;
const MAXIMUM_PAYLOAD_PROCESSES: usize = 16_384;
const MAXIMUM_CGROUP_PROCS_BYTES: usize = 256 * 1024;
const MAXIMUM_PROC_STATUS_BYTES: usize = 256 * 1024;

/// Identifies one controller-assigned runtime without host paths or process IDs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HostRuntimeIdentity {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

impl HostRuntimeIdentity {
    pub(crate) const fn new(
        sandbox_id: [u8; 16],
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
        desired_generation: u64,
        assignment_digest: [u8; 32],
    ) -> Self {
        Self {
            sandbox_id,
            incarnation_id,
            assignment_epoch,
            desired_generation,
            assignment_digest,
        }
    }

    /// Returns the logical sandbox identifier.
    #[must_use]
    pub const fn sandbox_id(&self) -> &[u8; 16] {
        &self.sandbox_id
    }

    /// Returns the assigned runtime incarnation.
    #[must_use]
    pub const fn incarnation_id(&self) -> &[u8; 16] {
        &self.incarnation_id
    }

    /// Returns the controller assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the desired-state generation within the assignment.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the immutable assignment-semantics digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }
}

impl From<&ValidatedAssignmentFence> for HostRuntimeIdentity {
    fn from(fence: &ValidatedAssignmentFence) -> Self {
        Self::new(
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
        )
    }
}

/// Selects one closed host mutation.
#[derive(Debug)]
pub enum WorkerOperation {
    /// Starts the sole fully compiled transient-unit specification.
    Launch {
        /// Fixed systemd unit properties.
        spec: Box<SandboxUnitSpec>,
        /// Kernel pins retained across the complete asynchronous start.
        pins: LaunchPins,
    },
    /// Stops the incarnation-derived service and awaits its job.
    Stop,
    /// Freezes the verified payload subtree while leaving its supervisor live.
    Freeze,
    /// Thaws the verified payload subtree.
    Thaw,
    /// Sends the typed all-process `SIGKILL` operation.
    Kill,
}

/// Classifies a verified runtime observation for local protocol projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedRuntimeState {
    /// No unit with the incarnation-derived name is loaded.
    Absent,
    /// systemd is activating the runtime.
    Starting,
    /// The runtime is active and not frozen.
    Ready,
    /// The runtime's payload subtree is frozen.
    Frozen,
    /// systemd is deactivating the runtime.
    Stopping,
    /// The loaded unit is inactive.
    Exited,
    /// The loaded unit failed or returned an unrecognized active state.
    Failed,
}

/// Owns a pidfd-backed leader observation and its opaque local handle.
#[derive(Debug)]
pub struct PinnedLeader {
    handle: [u8; 32],
    pidfd: PidFd,
    cgroup: SandboxCgroupPath,
}

impl PinnedLeader {
    /// Returns the opaque handle bound to this exact invocation and cgroup.
    #[must_use]
    pub const fn handle(&self) -> &[u8; 32] {
        &self.handle
    }

    /// Borrows the pinned process for later namespace acquisition.
    #[must_use]
    pub const fn pidfd(&self) -> &PidFd {
        &self.pidfd
    }

    /// Duplicates the same supervisor pin for independent broker registries.
    pub(crate) fn try_clone(&self) -> Result<Self> {
        let descriptor = self
            .pidfd
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        Ok(Self {
            handle: self.handle,
            pidfd: PidFd::from_owned(descriptor)
                .map_err(|error| HostError::Worker(error.to_string()))?,
            cgroup: self.cgroup.clone(),
        })
    }
}

/// Retains the exact payload PID 1 and point-in-time root/namespace evidence.
///
/// This observation defeats numeric PID reuse and proves that the inspected
/// root descriptor named the pinned workspace when acquired. It becomes a
/// root-continuity proof only when launch verification also consumes the
/// closed [`PayloadRootContinuityPolicyV1`] witness and pins the reviewed
/// nspawn binary. The exact shifted-user mapping and pidfd access are checked
/// separately at bound start; this pin alone does not establish readiness.
#[derive(Debug)]
pub struct PinnedPayloadLeader {
    pidfd: PidFd,
    cgroup: BeneathRoot,
    relative_cgroup_hint: String,
    root: OwnedFd,
    network: NamespaceFd,
    mount: NamespaceFd,
    pid: NamespaceFd,
    user: NamespaceFd,
}

/// Retains proof that pidfd namespace inspection works in the current service.
///
/// This boot-local probe exercises the same Linux pidfs ioctls used by launch
/// verification while running under hostd's deployed systemd sandbox. It
/// deliberately targets the service process itself, so it proves kernel,
/// seccomp, and service-policy availability but not the separate ptrace access
/// check for a user-namespace-shifted payload.
#[derive(Debug)]
pub struct PidfdNamespaceAccessProbe {
    process: PidFd,
    mount: NamespaceFd,
    network: NamespaceFd,
    pid: NamespaceFd,
    user: NamespaceFd,
}

impl PidfdNamespaceAccessProbe {
    /// Probes all namespace ioctls required by the hardened host service.
    ///
    /// # Errors
    ///
    /// Returns an error when the kernel lacks required pidfs operations, the
    /// service sandbox blocks one, an ioctl returns a substituted process or
    /// namespace type, or the pinned process is not live after inspection.
    pub fn current_service() -> Result<Self> {
        let raw_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| HostError::Worker("host pid does not fit in u32".to_owned()))?;
        let pid = NonZeroU32::new(raw_pid)
            .ok_or_else(|| HostError::Worker("host pid is zero".to_owned()))?;
        let process = PidFd::open(pid).map_err(|error| HostError::Worker(error.to_string()))?;
        let before = process
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        validate_service_probe_identity(raw_pid, before.pid(), before.thread_group_id())?;

        let mount = process
            .namespace(NamespaceKind::Mount)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let network = process
            .namespace(NamespaceKind::Network)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let pid_namespace = process
            .namespace(NamespaceKind::Pid)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let user = process
            .namespace(NamespaceKind::User)
            .map_err(|error| HostError::Worker(error.to_string()))?;

        let after = process
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        validate_service_probe_identity(raw_pid, after.pid(), after.thread_group_id())?;
        if before != after {
            return Err(HostError::Worker(
                "host pidfd identity changed during namespace probe".to_owned(),
            ));
        }
        if !process
            .is_alive()
            .map_err(|error| HostError::Worker(error.to_string()))?
        {
            return Err(HostError::Worker(
                "host process exited during namespace probe".to_owned(),
            ));
        }

        Ok(Self {
            process,
            mount,
            network,
            pid: pid_namespace,
            user,
        })
    }

    /// Borrows the probed service-process pidfd.
    #[must_use]
    pub const fn process(&self) -> &PidFd {
        &self.process
    }

    /// Borrows the verified mount namespace descriptor.
    #[must_use]
    pub const fn mount(&self) -> &NamespaceFd {
        &self.mount
    }

    /// Borrows the verified network namespace descriptor.
    #[must_use]
    pub const fn network(&self) -> &NamespaceFd {
        &self.network
    }

    /// Borrows the verified PID namespace descriptor.
    #[must_use]
    pub const fn pid(&self) -> &NamespaceFd {
        &self.pid
    }

    /// Borrows the verified user namespace descriptor.
    #[must_use]
    pub const fn user(&self) -> &NamespaceFd {
        &self.user
    }
}

fn validate_service_probe_identity(expected: u32, pid: u32, thread_group: u32) -> Result<()> {
    if pid != expected || thread_group != expected {
        return Err(HostError::Worker(
            "host pidfd namespace probe returned a substituted process".to_owned(),
        ));
    }
    Ok(())
}

impl PinnedPayloadLeader {
    /// Borrows the payload process pin.
    #[must_use]
    pub const fn pidfd(&self) -> &PidFd {
        &self.pidfd
    }

    /// Borrows the launch-verified payload subtree anchor.
    #[must_use]
    pub(crate) fn cgroup(&self) -> BorrowedFd<'_> {
        self.cgroup.as_fd()
    }

    /// Reports whether another proof pins the same payload subtree object.
    #[must_use]
    pub(crate) fn has_same_cgroup(&self, other: &Self) -> bool {
        self.cgroup.identity() == other.cgroup.identity()
    }

    /// Returns the PID 1 cgroup hint relative to the payload subtree anchor.
    #[must_use]
    pub(crate) fn relative_cgroup_hint(&self) -> &str {
        &self.relative_cgroup_hint
    }

    /// Rechecks the retained payload proof immediately before descriptor use.
    pub(crate) fn recheck_kernel(&self, supervisor: &PinnedLeader) -> Result<()> {
        let supervisor_before = supervisor
            .pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let cgroup = CgroupV2Root::from_owned(
            self.cgroup
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| HostError::Worker(error.to_string()))?,
        )
        .map_err(|error| HostError::Worker(error.to_string()))?;
        let anchor = cgroup
            .resolve(Path::new("."))
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let payload_before = if self.relative_cgroup_hint.is_empty() {
            anchor.verify_exact_membership(&self.pidfd)
        } else {
            anchor.verify_descendant_membership(&self.pidfd, Path::new(&self.relative_cgroup_hint))
        }
        .map_err(|error| HostError::Worker(error.to_string()))?;
        if payload_before.thread_group_id() != payload_before.pid()
            || payload_before.parent_pid() != supervisor_before.pid()
            || read_nested_pid(
                NonZeroU32::new(payload_before.pid()).ok_or_else(|| {
                    HostError::Worker("payload pidfd returned PID zero".to_owned())
                })?,
            )? != 1
        {
            return Err(HostError::Worker(
                "retained payload process no longer satisfies its exact scope".to_owned(),
            ));
        }

        let current_root = open_payload_root(
            NonZeroU32::new(payload_before.pid())
                .ok_or_else(|| HostError::Worker("payload pidfd returned PID zero".to_owned()))?,
        )?;
        let current_root = rustix::fs::fstat(&current_root)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let retained_root =
            rustix::fs::fstat(&self.root).map_err(|error| HostError::Worker(error.to_string()))?;
        let current_network = self
            .pidfd
            .namespace(NamespaceKind::Network)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let current_mount = self
            .pidfd
            .namespace(NamespaceKind::Mount)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let current_user = self
            .pidfd
            .namespace(NamespaceKind::User)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let current_pid = self
            .pidfd
            .namespace(NamespaceKind::Pid)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if (current_root.st_dev, current_root.st_ino)
            != (retained_root.st_dev, retained_root.st_ino)
            || current_network.identity() != self.network.identity()
            || current_mount.identity() != self.mount.identity()
            || current_pid.identity() != self.pid.identity()
            || current_user.identity() != self.user.identity()
        {
            return Err(HostError::Worker(
                "retained payload root or namespaces changed".to_owned(),
            ));
        }

        let payload_after = self
            .pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let supervisor_after = supervisor
            .pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if payload_before != payload_after
            || supervisor_before != supervisor_after
            || !self
                .pidfd
                .is_alive()
                .map_err(|error| HostError::Worker(error.to_string()))?
            || !supervisor
                .pidfd
                .is_alive()
                .map_err(|error| HostError::Worker(error.to_string()))?
        {
            return Err(HostError::Worker(
                "retained payload identity changed during revalidation".to_owned(),
            ));
        }
        Ok(())
    }

    /// Borrows the point-in-time payload root descriptor.
    #[must_use]
    pub fn root(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.root.as_fd()
    }

    /// Returns the payload network namespace identity.
    #[must_use]
    pub fn network(&self) -> &NamespaceFd {
        &self.network
    }

    /// Returns the payload mount namespace identity.
    #[must_use]
    pub fn mount(&self) -> &NamespaceFd {
        &self.mount
    }

    /// Returns the launch-retained payload user namespace identity.
    #[must_use]
    pub fn user(&self) -> &NamespaceFd {
        &self.user
    }

    /// Returns the launch-retained payload PID namespace identity.
    #[must_use]
    pub fn pid(&self) -> &NamespaceFd {
        &self.pid
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PayloadCandidate {
    pid: NonZeroU32,
    cgroup_id: u64,
    relative_cgroup_hint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadEvidence {
    pid: NonZeroU32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: u64,
    nested_pid: u32,
    root_device: u64,
    root_inode: u64,
    network_device: u64,
    network_inode: u64,
}

trait PayloadInspectionBackend {
    type Proof;

    fn snapshot(&self) -> Result<Vec<PayloadCandidate>>;
    fn prove(&self, candidate: PayloadCandidate) -> Result<(PayloadEvidence, Option<Self::Proof>)>;
    fn is_alive(&self, proof: &Self::Proof) -> Result<bool>;
}

fn discover_payload_leader<B: PayloadInspectionBackend>(
    backend: &B,
    supervisor_pid: u32,
    expected_root: (u64, u64),
    expected_network: (u64, u64),
) -> Result<B::Proof> {
    let first = canonical_payload_snapshot(backend.snapshot()?)?;
    let mut selected = None;
    for candidate in first.iter().cloned() {
        let (evidence, proof) = backend.prove(candidate.clone())?;
        if evidence.pid != candidate.pid
            || evidence.thread_group_id != candidate.pid.get()
            || evidence.cgroup_id != candidate.cgroup_id
        {
            return Err(HostError::Worker(
                "payload process changed across cgroup and pidfd observation".to_owned(),
            ));
        }
        if evidence.nested_pid != 1 || evidence.parent_pid != supervisor_pid {
            continue;
        }
        let proof = proof.ok_or_else(|| {
            HostError::Worker("payload PID 1 proof omitted its descriptor pins".to_owned())
        })?;
        if selected.is_some() {
            return Err(HostError::Worker(
                "payload subtree has multiple direct nested PID 1 candidates".to_owned(),
            ));
        }
        if (evidence.root_device, evidence.root_inode) != expected_root {
            return Err(HostError::Worker(
                "payload PID 1 root differs from the pinned workspace".to_owned(),
            ));
        }
        if (evidence.network_device, evidence.network_inode) != expected_network {
            return Err(HostError::Worker(
                "payload PID 1 network namespace differs from its pin".to_owned(),
            ));
        }
        selected = Some(proof);
    }
    let proof = selected.ok_or_else(|| {
        HostError::Worker("payload subtree has no direct nested PID 1 candidate".to_owned())
    })?;
    let second = canonical_payload_snapshot(backend.snapshot()?)?;
    if first != second {
        return Err(HostError::Worker(
            "payload cgroup changed during leader discovery".to_owned(),
        ));
    }
    if !backend.is_alive(&proof)? {
        return Err(HostError::Worker(
            "payload PID 1 exited during identity validation".to_owned(),
        ));
    }
    Ok(proof)
}

fn recover_payload_leader<B: PayloadInspectionBackend>(
    backend: &B,
    supervisor_pid: u32,
    expected: RuntimeProofSnapshot,
) -> Result<B::Proof> {
    let first = canonical_payload_snapshot(backend.snapshot()?)?;
    let mut selected = None;
    for candidate in first.iter().cloned() {
        let (evidence, proof) = backend.prove(candidate.clone())?;
        if evidence.pid != candidate.pid
            || evidence.thread_group_id != candidate.pid.get()
            || evidence.cgroup_id != candidate.cgroup_id
        {
            return Err(HostError::Worker(
                "payload process changed across recovery observation".to_owned(),
            ));
        }
        if evidence.nested_pid != 1 || evidence.parent_pid != supervisor_pid {
            continue;
        }
        if evidence.pid.get() != expected.payload.pid
            || evidence.thread_group_id != expected.payload.thread_group_id
            || evidence.parent_pid != expected.payload.parent_pid
            || evidence.cgroup_id != expected.payload.cgroup_id
            || (evidence.network_device, evidence.network_inode)
                != (
                    expected.network_namespace.device,
                    expected.network_namespace.inode,
                )
        {
            return Err(HostError::Worker(
                "live payload PID 1 differs from the durable completed proof".to_owned(),
            ));
        }
        let proof = proof.ok_or_else(|| {
            HostError::Worker("recovered payload omitted its descriptor pins".to_owned())
        })?;
        if selected.is_some() {
            return Err(HostError::Worker(
                "payload recovery found multiple direct nested PID 1 candidates".to_owned(),
            ));
        }
        selected = Some(proof);
    }
    let proof = selected.ok_or_else(|| {
        HostError::Worker("payload recovery found no exact nested PID 1".to_owned())
    })?;
    let second = canonical_payload_snapshot(backend.snapshot()?)?;
    if first != second {
        return Err(HostError::Worker(
            "payload cgroup changed during recovery".to_owned(),
        ));
    }
    if !backend.is_alive(&proof)? {
        return Err(HostError::Worker(
            "payload PID 1 exited during recovery".to_owned(),
        ));
    }
    Ok(proof)
}

fn canonical_payload_snapshot(
    mut candidates: Vec<PayloadCandidate>,
) -> Result<Vec<PayloadCandidate>> {
    if candidates.len() > MAXIMUM_PAYLOAD_PROCESSES {
        return Err(HostError::Worker(
            "payload process snapshot exceeds its fixed bound".to_owned(),
        ));
    }
    candidates.sort_unstable();
    if candidates.iter().any(|candidate| candidate.cgroup_id == 0)
        || candidates.windows(2).any(|pair| pair[0].pid == pair[1].pid)
    {
        return Err(HostError::Worker(
            "payload process snapshot has an invalid or duplicate cgroup identity".to_owned(),
        ));
    }
    Ok(candidates)
}

/// Carries a verified one-transaction runtime observation.
#[derive(Debug)]
pub struct WorkerObservation {
    /// Closed runtime state.
    pub state: ObservedRuntimeState,
    /// systemd invocation identifier, when a loaded invocation exists.
    pub invocation_id: Option<[u8; 16]>,
    /// Pinned supervisor leader, present only after cgroup validation.
    pub leader: Option<PinnedLeader>,
    /// Launch-verified payload proof, present only after strong pin validation.
    pub payload: Option<PinnedPayloadLeader>,
}

/// Classifies one manager-sandwiched Guardian observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianObservedState {
    /// No unit with the incarnation-derived name is loaded.
    Absent,
    /// The exact Guardian is active and running.
    ActiveRunning,
    /// systemd is still activating the Guardian.
    Activating,
    /// The loaded Guardian became inactive.
    TerminalInactive,
    /// The loaded Guardian entered failed state.
    TerminalFailed,
    /// The manager returned another state that cannot be adopted.
    Other,
}

/// Carries the exact manager-retained Guardian binding and invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardianObservation {
    /// Exact manager-retained launch binding, when canonical and unique.
    pub binding: Option<[u8; 32]>,
    /// Current manager invocation identifier, when one exists.
    pub invocation_id: Option<[u8; 16]>,
    /// Closed projection of the manager's active and service substates.
    pub state: GuardianObservedState,
}

/// Returns both the terminal start-job result and its subsequent observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardianStartObservation {
    /// Whether the submitted start job completed with exact `done` result.
    pub job_done: bool,
    /// Fresh manager observation acquired after the terminal job result.
    pub observation: GuardianObservation,
}

/// Returns a fully revalidated Host 1.0 payload and kernel proof.
#[derive(Debug)]
pub struct BoundPayloadVerification {
    /// Exact binding observed from the manager after the job.
    pub binding: Option<[u8; 32]>,
    /// Exact invocation observed before and after kernel proof construction.
    pub invocation_id: [u8; 16],
    /// Fresh runtime observation retaining its pidfd and namespace pins.
    pub observation: WorkerObservation,
    /// Complete boot-local durable proof derived from those live pins.
    pub(crate) proof: RuntimeProofSnapshot,
    /// Fresh shifted-payload inspection exists only for an exact bound start.
    pub(crate) shifted_payload_inspection: Option<VerifiedShiftedPayloadInspectionV1>,
}

impl BoundPayloadVerification {
    /// Borrows the shifted-payload readback produced by an exact bound start.
    ///
    /// Observation-only recovery has no original bound spec to reconstruct
    /// the maps, so it returns `None` rather than replaying a stale record.
    #[must_use]
    pub const fn shifted_payload_inspection(&self) -> Option<&VerifiedShiftedPayloadInspectionV1> {
        self.shifted_payload_inspection.as_ref()
    }
}

/// Proves that this call submitted and observed a `done` payload start job.
#[derive(Debug)]
pub struct CurrentJobDone {
    /// Complete proof built after the current call's terminal job result.
    pub verification: BoundPayloadVerification,
}

/// Proves adoption through observation only, without submitting a start.
#[derive(Debug)]
pub struct RecoveredExactProof {
    /// Complete proof rebuilt from the currently active exact payload.
    pub verification: BoundPayloadVerification,
}

/// Carries the authenticated boot-local proof for observation-only recovery.
///
/// This token is opaque outside the host crate. Callers cannot manufacture or
/// inspect proof fields; only authenticated durable state creates it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedRuntimeProof {
    snapshot: RuntimeProofSnapshot,
}

impl CompletedRuntimeProof {
    pub(crate) const fn from_snapshot(snapshot: RuntimeProofSnapshot) -> Self {
        Self { snapshot }
    }

    pub(crate) const fn snapshot(self) -> RuntimeProofSnapshot {
        self.snapshot
    }
}

/// Projects the exact-stop result needed by the durable reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactWorkerStopOutcome {
    /// The exact unit reached the reference-held quiescent boundary.
    AwaitingAbsence(GuardianObservation),
    /// The exact manager object is still present or its job did not complete.
    Residual(GuardianObservation),
    /// The manager object was already absent before reference acquisition.
    Missing,
    /// The loaded manager object did not match the durable target.
    Foreign(GuardianObservation),
}

/// Executes one idempotent fixed-function host transaction.
#[async_trait]
pub trait HostWorker {
    /// Applies or reconciles one operation, then returns verified observation.
    /// Implementations must invoke `before_effect` after asynchronous
    /// preparation and immediately before each mutating backend call. An
    /// idempotent no-op reconciliation does not consume effect authority. The
    /// sole exception is mandatory kill/stop compensation after a launch or
    /// containment attempt has passed that guard: cleanup completes the
    /// already-admitted effect and cannot be disabled by later guard expiry.
    /// Rejecting a pre-existing unit is not an attempted launch, so containment
    /// of that unit first requires its own fresh effect-guard check.
    ///
    /// # Errors
    ///
    /// Returns an error when the effect guard denies a mutation, the system
    /// manager rejects the fixed operation, or the resulting unit, cgroup,
    /// invocation, or pidfd identity is invalid.
    async fn execute(
        &self,
        fence: &ValidatedAssignmentFence,
        operation: WorkerOperation,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<WorkerObservation>;

    /// Observes one incarnation without mutating it.
    ///
    /// # Errors
    ///
    /// Returns an error when systemd or descriptor validation fails.
    async fn observe(&self, identity: &HostRuntimeIdentity) -> Result<WorkerObservation>;

    /// Revalidates one retained launch proof against fresh runtime state.
    ///
    /// # Errors
    ///
    /// Returns an error unless the same invocation, supervisor, payload PID 1,
    /// root, namespaces, and exact payload subtree remain current.
    async fn refresh_payload_scope(
        &self,
        identity: &HostRuntimeIdentity,
        invocation_id: [u8; 16],
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
    ) -> Result<WorkerObservation>;

    /// Observes the exact Guardian unit without performing an effect.
    async fn observe_guardian(
        &self,
        _identity: &HostRuntimeIdentity,
    ) -> Result<GuardianObservation> {
        Err(HostError::Worker(
            "Guardian observation is not implemented by this worker".to_owned(),
        ))
    }

    /// Starts one already-persisted exact Guardian submission.
    async fn start_guardian(
        &self,
        _spec: &GuardianUnitSpec,
        _identity: &HostRuntimeIdentity,
        _before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<GuardianStartObservation> {
        Err(HostError::Worker(
            "Guardian start is not implemented by this worker".to_owned(),
        ))
    }

    /// Observes the manager-retained Host 1.0 payload binding and invocation.
    async fn observe_bound_payload(
        &self,
        _identity: &HostRuntimeIdentity,
    ) -> Result<GuardianObservation> {
        Err(HostError::Worker(
            "bound payload observation is not implemented by this worker".to_owned(),
        ))
    }

    /// Starts and fully verifies one already-committed Host 1.0 payload.
    async fn start_bound_payload(
        &self,
        _spec: &SandboxUnitSpec,
        _pins: &LaunchPins,
        _identity: &HostRuntimeIdentity,
        _guardian_invocation_id: [u8; 16],
        _before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<CurrentJobDone> {
        Err(HostError::Worker(
            "bound payload start is not implemented by this worker".to_owned(),
        ))
    }

    /// Rebuilds a complete exact payload proof without submitting an effect.
    async fn prove_bound_payload(
        &self,
        _spec: &SandboxUnitSpec,
        _pins: &LaunchPins,
        _identity: &HostRuntimeIdentity,
    ) -> Result<RecoveredExactProof> {
        Err(HostError::Worker(
            "bound payload recovery proof is not implemented by this worker".to_owned(),
        ))
    }

    /// Rebuilds live payload pins for one durably completed Guardian launch.
    ///
    /// Implementations must prove the exact saved Guardian and payload manager
    /// identities around reconstruction of a kernel proof equal to
    /// `expected_proof`. This is observation-only recovery and must not start,
    /// stop, or otherwise mutate either unit.
    ///
    /// # Errors
    ///
    /// Returns an error if either manager identity is absent, foreign, or not
    /// active-running, or if the reconstructed kernel proof differs from the
    /// authenticated durable proof.
    async fn recover_completed_payload(
        &self,
        _identity: &HostRuntimeIdentity,
        _binding: [u8; 32],
        _guardian_invocation_id: [u8; 16],
        _payload_invocation_id: [u8; 16],
        _expected_proof: CompletedRuntimeProof,
    ) -> Result<RecoveredExactProof> {
        Err(HostError::Worker(
            "completed payload recovery is not implemented by this worker".to_owned(),
        ))
    }

    /// Stops one durably authorized exact target while proving kernel quiescence.
    ///
    /// The caller's persisted `StopEffectIssued` transition is the authority
    /// linearization point. This method deliberately has no expiring guard:
    /// retries after that commit finish the same exact containment effect, and
    /// cannot broaden it to a different binding or invocation.
    ///
    /// # Errors
    ///
    /// Returns an error if the exact manager target cannot be retained or
    /// stopped, or kernel quiescence cannot be established.
    async fn stop_exact_unit(
        &self,
        _identity: &HostRuntimeIdentity,
        _role: ExactUnitRole,
        _binding: [u8; 32],
        _invocation_id: [u8; 16],
    ) -> Result<ExactWorkerStopOutcome> {
        Err(HostError::Worker(
            "exact unit stop is not implemented by this worker".to_owned(),
        ))
    }

    /// Observes authoritative manager and exact-cgroup absence after `UnrefUnit`.
    async fn observe_post_unref(
        &self,
        _identity: &HostRuntimeIdentity,
        _role: ExactUnitRole,
    ) -> Result<GuardianObservation> {
        Err(HostError::Worker(
            "post-Unref exact observation is not implemented by this worker".to_owned(),
        ))
    }
}

/// Creates a fresh system-bus connection for every fixed host transaction.
///
/// The broker retains durable request state, but a worker owns no authority
/// beyond one call and drops its generic D-Bus connection before returning.
#[derive(Debug)]
pub struct SystemdOneShotWorker {
    cgroup_root: BeneathRoot,
}

#[async_trait]
trait LaunchBackend {
    async fn observe(&self) -> Result<WorkerObservation>;
    async fn start(&self, spec: &SandboxUnitSpec) -> Result<()>;
    async fn kill(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
}

struct SystemdLaunchBackend<'a> {
    worker: &'a SystemdOneShotWorker,
    client: &'a SystemdClient,
    identity: &'a HostRuntimeIdentity,
    name: &'a SandboxUnitName,
}

#[async_trait]
impl LaunchBackend for SystemdLaunchBackend<'_> {
    async fn observe(&self) -> Result<WorkerObservation> {
        self.worker
            .observe_with_client(self.client, self.identity)
            .await
    }

    async fn start(&self, spec: &SandboxUnitSpec) -> Result<()> {
        ensure_done(
            &self
                .client
                .start_sandbox_unit(spec)
                .await
                .map_err(|error| worker_error(&error))?,
        )
    }

    async fn kill(&self) -> Result<()> {
        self.client
            .kill_sandbox_unit(self.name)
            .await
            .map_err(|error| worker_error(&error))
    }

    async fn stop(&self) -> Result<()> {
        ensure_done(
            &self
                .client
                .stop_sandbox_unit(self.name)
                .await
                .map_err(|error| worker_error(&error))?,
        )
    }
}

async fn reconcile_launch<B: LaunchBackend + Sync>(
    backend: &B,
    spec: &SandboxUnitSpec,
    pins: &LaunchPins,
    before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    verify_pins: &mut (
             dyn FnMut(&WorkerObservation, &LaunchPins) -> Result<PinnedPayloadLeader> + Send
         ),
) -> Result<WorkerObservation> {
    let initial = match backend.observe().await {
        Ok(observation) => observation,
        Err(error) => {
            // No forward effect has occurred in this call. An ambiguous
            // observation alone cannot turn an expired request into cleanup
            // authority over a possibly pre-existing unit.
            before_effect()?;
            return rollback_launch(backend, error).await;
        }
    };
    let attempted_launch = initial.state == ObservedRuntimeState::Absent;
    let mut observation = if attempted_launch {
        before_effect()?;
        if let Err(error) = backend.start(spec).await {
            return rollback_launch(backend, error).await;
        }
        match backend.observe().await {
            Ok(observation) => observation,
            Err(error) => return rollback_launch(backend, error).await,
        }
    } else {
        initial
    };

    let proof = validate_launch_observation(&observation, pins, verify_pins);
    match proof {
        Ok(payload) => {
            observation.payload = Some(payload);
            Ok(observation)
        }
        Err(error) => {
            if !attempted_launch {
                before_effect()?;
            }
            rollback_launch(backend, error).await
        }
    }
}

fn validate_launch_observation(
    observation: &WorkerObservation,
    pins: &LaunchPins,
    verify_pins: &mut (
             dyn FnMut(&WorkerObservation, &LaunchPins) -> Result<PinnedPayloadLeader> + Send
         ),
) -> Result<PinnedPayloadLeader> {
    if !matches!(
        observation.state,
        ObservedRuntimeState::Ready | ObservedRuntimeState::Frozen
    ) {
        return Err(HostError::Worker(
            "nspawn launch reconciled to a non-running state".to_owned(),
        ));
    }
    observation.leader.as_ref().ok_or_else(|| {
        HostError::Worker("started nspawn supervisor has no pinned leader".to_owned())
    })?;
    verify_pins(observation, pins)
}

async fn rollback_launch<B: LaunchBackend + Sync>(
    backend: &B,
    original: HostError,
) -> Result<WorkerObservation> {
    // The caller has already guarded either a launch attempt or this
    // containment attempt. This completes that admitted effect rather than
    // opening a caller-directed inverse operation; expiry cannot interrupt
    // cleanup once containment has begun.
    let kill_failed = backend.kill().await.is_err();
    let stop_failed = backend.stop().await.is_err();
    if kill_failed || stop_failed {
        // CollectMode may remove a failed unit before either cleanup method
        // reaches it. Reconcile only through a fresh absent observation; the
        // systemd backend also proves the exact kernel cgroup is gone. A lost
        // bus, a remaining cgroup, and every loaded unit state stay failures.
        if matches!(
            backend.observe().await,
            Ok(WorkerObservation {
                state: ObservedRuntimeState::Absent,
                ..
            })
        ) {
            return Err(original);
        }
        return Err(HostError::Worker(format!(
            "{original}; fail-stop cleanup incomplete (kill_failed={kill_failed}, stop_failed={stop_failed})"
        )));
    }
    Err(original)
}

fn classify_state(
    observation: &SandboxUnitObservation,
    payload_freezer: Option<CgroupFreezerState>,
) -> ObservedRuntimeState {
    match observation.active_state.as_str() {
        "activating" => ObservedRuntimeState::Starting,
        "active"
            if matches!(observation.freezer_state, FreezerState::Running)
                && payload_freezer == Some(CgroupFreezerState::Frozen) =>
        {
            ObservedRuntimeState::Frozen
        }
        "active"
            if matches!(observation.freezer_state, FreezerState::Running)
                && payload_freezer == Some(CgroupFreezerState::Thawed) =>
        {
            ObservedRuntimeState::Ready
        }
        "deactivating" => ObservedRuntimeState::Stopping,
        "inactive" => ObservedRuntimeState::Exited,
        _ => ObservedRuntimeState::Failed,
    }
}

fn ensure_done(outcome: &aos_systemd::JobOutcome) -> Result<()> {
    if outcome.result == JobResult::Done {
        Ok(())
    } else {
        Err(HostError::Worker(format!(
            "systemd job completed with {}",
            outcome.result.label()
        )))
    }
}

fn worker_error(error: &aos_systemd::Error) -> HostError {
    HostError::Worker(error.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{BTreeMap, VecDeque};
    use std::num::NonZeroU32;
    use std::os::fd::AsFd as _;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};
    use aos_systemd::{
        SandboxDescriptorPath, SandboxNspawnCommand, SandboxResolvedPaths, SandboxResources,
    };

    use super::*;

    #[test]
    fn payload_snapshot_reads_path_only_pins_after_directory_rename() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("payload");
        std::fs::create_dir_all(path.join("init.scope")).unwrap();
        std::fs::write(path.join("cgroup.procs"), b"1234\n").unwrap();
        std::fs::write(path.join("init.scope/cgroup.procs"), b"5678\n").unwrap();
        let descriptor = rustix::fs::open(
            &path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let root = BeneathRoot::from_owned(descriptor).unwrap();

        std::fs::rename(&path, temporary.path().join("retained")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("cgroup.procs"), b"9999\n").unwrap();

        let snapshot = LinuxPayloadInspector {
            payload_root: &root,
        }
        .snapshot()
        .unwrap();
        assert_eq!(
            snapshot
                .iter()
                .map(|entry| (entry.pid.get(), entry.relative_cgroup_hint.as_str()))
                .collect::<Vec<_>>(),
            [(1234, ""), (5678, "init.scope")]
        );
        assert_eq!(snapshot[0].cgroup_id, root.identity().inode);
    }

    struct FakeLaunchBackend {
        observations: Mutex<VecDeque<Result<WorkerObservation>>>,
        starts: AtomicUsize,
        kills: AtomicUsize,
        stops: AtomicUsize,
        fail_kill: bool,
        fail_stop: bool,
    }

    struct FakePayloadBackend {
        snapshots: Mutex<VecDeque<Vec<PayloadCandidate>>>,
        evidence: BTreeMap<u32, PayloadEvidence>,
        alive: bool,
    }

    impl PayloadInspectionBackend for FakePayloadBackend {
        type Proof = u32;

        fn snapshot(&self) -> Result<Vec<PayloadCandidate>> {
            self.snapshots
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| HostError::Worker("missing fake payload snapshot".to_owned()))
        }

        fn prove(
            &self,
            candidate: PayloadCandidate,
        ) -> Result<(PayloadEvidence, Option<Self::Proof>)> {
            self.evidence
                .get(&candidate.pid.get())
                .copied()
                .map(|evidence| (evidence, Some(candidate.pid.get())))
                .ok_or_else(|| HostError::Worker("fake payload pin failed".to_owned()))
        }

        fn is_alive(&self, _proof: &Self::Proof) -> Result<bool> {
            Ok(self.alive)
        }
    }

    fn payload_candidate(pid: u32, cgroup_id: u64) -> PayloadCandidate {
        PayloadCandidate {
            pid: NonZeroU32::new(pid).unwrap(),
            cgroup_id,
            relative_cgroup_hint: String::new(),
        }
    }

    fn payload_evidence(pid: u32, cgroup_id: u64, nested_pid: u32) -> PayloadEvidence {
        PayloadEvidence {
            pid: NonZeroU32::new(pid).unwrap(),
            thread_group_id: pid,
            parent_pid: 40,
            cgroup_id,
            nested_pid,
            root_device: 11,
            root_inode: 12,
            network_device: 13,
            network_inode: 14,
        }
    }

    fn payload_backend(
        snapshots: Vec<Vec<PayloadCandidate>>,
        evidence: Vec<PayloadEvidence>,
    ) -> FakePayloadBackend {
        FakePayloadBackend {
            snapshots: Mutex::new(snapshots.into()),
            evidence: evidence
                .into_iter()
                .map(|value| (value.pid.get(), value))
                .collect(),
            alive: true,
        }
    }

    #[async_trait]
    impl LaunchBackend for FakeLaunchBackend {
        async fn observe(&self) -> Result<WorkerObservation> {
            self.observations
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(HostError::Worker("missing fake observation".to_owned())))
        }

        async fn start(&self, _spec: &SandboxUnitSpec) -> Result<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn kill(&self) -> Result<()> {
            self.kills.fetch_add(1, Ordering::SeqCst);
            if self.fail_kill {
                Err(HostError::Worker("fake kill error".to_owned()))
            } else {
                Ok(())
            }
        }

        async fn stop(&self) -> Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            if self.fail_stop {
                Err(HostError::Worker("fake stop error".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    fn backend(observations: Vec<Result<WorkerObservation>>) -> FakeLaunchBackend {
        FakeLaunchBackend {
            observations: Mutex::new(observations.into()),
            starts: AtomicUsize::new(0),
            kills: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
            fail_kill: false,
            fail_stop: false,
        }
    }

    #[tokio::test]
    async fn failed_cleanup_requires_fresh_absence_without_masking_launch_error() {
        for (fail_kill, fail_stop) in [(true, false), (false, true), (true, true)] {
            for state in [
                ObservedRuntimeState::Absent,
                ObservedRuntimeState::Starting,
                ObservedRuntimeState::Ready,
                ObservedRuntimeState::Frozen,
                ObservedRuntimeState::Stopping,
                ObservedRuntimeState::Exited,
                ObservedRuntimeState::Failed,
            ] {
                let mut backend = backend(vec![Ok(observation(state, false))]);
                backend.fail_kill = fail_kill;
                backend.fail_stop = fail_stop;
                let error = rollback_launch(
                    &backend,
                    HostError::Worker("original launch failure".to_owned()),
                )
                .await
                .unwrap_err()
                .to_string();
                assert!(error.contains("original launch failure"));
                assert_eq!(
                    error.contains("cleanup incomplete"),
                    state != ObservedRuntimeState::Absent,
                    "{state:?}, kill={fail_kill}, stop={fail_stop}"
                );
                assert_eq!(backend.kills.load(Ordering::SeqCst), 1);
                assert_eq!(backend.stops.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[tokio::test]
    async fn cleanup_observation_failure_keeps_containment_indeterminate() {
        let mut backend = backend(vec![Err(HostError::Worker("lost bus".to_owned()))]);
        backend.fail_kill = true;
        assert!(
            rollback_launch(&backend, HostError::Worker("original failure".to_owned()))
                .await
                .unwrap_err()
                .to_string()
                .contains("cleanup incomplete")
        );
    }

    #[test]
    fn absent_runtime_requires_a_live_cgroup_filesystem() {
        let descriptor = std::fs::File::open("/").unwrap().into();
        let worker = SystemdOneShotWorker::new(BeneathRoot::from_owned(descriptor).unwrap());
        assert!(
            worker
                .verify_absent_cgroup(&SandboxUnitName::from_incarnation([0x71; 16]))
                .is_err()
        );
    }

    fn current_pins(executable_path: &str) -> LaunchPins {
        let executable = rustix::fs::open(
            executable_path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let workspace = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let network = rustix::fs::open(
            "/proc/self/ns/net",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let network = NamespaceFd::from_owned(network, NamespaceKind::Network).unwrap();
        let attachment_anchor = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        LaunchPins::for_tests(executable, workspace, network, attachment_anchor)
    }

    fn current_payload_proof() -> PinnedPayloadLeader {
        // Launch-ordering tests need an owned value from the private callback,
        // not a usable runtime proof. The ordinary filesystem anchor ensures
        // any accidental fresh-query recheck fails closed as non-cgroup2.
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        let cgroup = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let root = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let network = rustix::fs::open(
            "/proc/self/ns/net",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mount = rustix::fs::open(
            "/proc/self/ns/mnt",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        PinnedPayloadLeader {
            pidfd: PidFd::open(pid).unwrap(),
            cgroup: BeneathRoot::from_owned(cgroup).unwrap(),
            relative_cgroup_hint: String::new(),
            root,
            network: NamespaceFd::from_owned(network, NamespaceKind::Network).unwrap(),
            mount: NamespaceFd::from_owned(mount, NamespaceKind::Mount).unwrap(),
            pid: PidFd::open(pid)
                .unwrap()
                .namespace(NamespaceKind::Pid)
                .unwrap(),
            user: PidFd::open(pid)
                .unwrap()
                .namespace(NamespaceKind::User)
                .unwrap(),
        }
    }

    #[test]
    fn ordering_fixture_is_not_a_runtime_payload_proof() {
        let supervisor = observation(ObservedRuntimeState::Ready, true)
            .leader
            .unwrap();
        assert!(current_payload_proof().recheck_kernel(&supervisor).is_err());
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn stop_proof_rejects_recycled_leader_from_a_different_cgroup() {
        let cgroup_root = rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let hierarchy = CgroupV2Root::from_owned(cgroup_root).unwrap();
        let wrong_cgroup = hierarchy.resolve(Path::new(".")).unwrap();
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .unwrap();
        let relative = if relative.is_empty() { "." } else { relative };
        let actual_cgroup = hierarchy.resolve(Path::new(relative)).unwrap();
        let current_pid = NonZeroU32::new(std::process::id()).unwrap();

        assert_ne!(wrong_cgroup.kernel_id(), actual_cgroup.kernel_id());
        assert!(systemd::pin_stop_leader(&actual_cgroup, current_pid).is_ok());
        let error = systemd::pin_stop_leader(&wrong_cgroup, current_pid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pidfd does not name this cgroup"), "{error}");
        println!("AOS_STOP_PROOF_WRONG_CGROUP_OK");
    }

    fn observation(state: ObservedRuntimeState, leader: bool) -> WorkerObservation {
        let leader = leader.then(|| PinnedLeader {
            handle: [1; 32],
            pidfd: PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap(),
            cgroup: SandboxUnitName::from_incarnation([1; 16]).cgroup_path(),
        });
        WorkerObservation {
            state,
            invocation_id: Some([2; 16]),
            leader,
            payload: None,
        }
    }

    fn spec() -> SandboxUnitSpec {
        let executable = std::fs::File::open("/proc/self/exe").unwrap();
        let root = std::fs::File::open("/").unwrap();
        let network = std::fs::File::open("/proc/self/ns/net").unwrap();
        SandboxUnitSpec::new_nspawn(
            SandboxUnitName::from_incarnation([1; 16]),
            SandboxNspawnCommand::private_user_descriptor_v1(
                SandboxDescriptorPath::for_current_process(executable.as_fd()).unwrap(),
                [1; 16],
                65_536,
                65_536,
            )
            .unwrap(),
            SandboxResolvedPaths::from_descriptors(
                SandboxDescriptorPath::for_current_process(root.as_fd()).unwrap(),
                SandboxDescriptorPath::for_current_process(network.as_fd()).unwrap(),
            ),
            SandboxResources::new(1, 1, 1, 1).unwrap(),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .unwrap()
    }

    #[test]
    fn post_launch_rejects_executable_pin_substitution() {
        let executable = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let workspace = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let network = rustix::fs::open(
            "/proc/self/ns/net",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let network = NamespaceFd::from_owned(network, NamespaceKind::Network).unwrap();
        let attachment_anchor = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let pins = LaunchPins::for_tests(executable, workspace, network, attachment_anchor);
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        let leader = PinnedLeader {
            handle: [1; 32],
            pidfd: PidFd::open(pid).unwrap(),
            cgroup: SandboxUnitName::from_incarnation([1; 16]).cgroup_path(),
        };
        let cgroup_root = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let cgroup_root = BeneathRoot::from_owned(cgroup_root).unwrap();

        assert!(
            verify_supervisor_pins(
                &cgroup_root,
                &pins,
                &leader,
                spec().payload_root_continuity_policy(),
            )
            .is_err()
        );
        assert!(leader.pidfd.is_alive().unwrap());
    }

    #[test]
    fn payload_discovery_pins_one_direct_nested_pid_one() {
        let snapshot = vec![payload_candidate(41, 101), payload_candidate(42, 102)];
        let backend = payload_backend(
            vec![snapshot.clone(), snapshot],
            vec![payload_evidence(41, 101, 1), payload_evidence(42, 102, 7)],
        );

        assert_eq!(
            discover_payload_leader(&backend, 40, (11, 12), (13, 14)).unwrap(),
            41
        );
    }

    #[test]
    fn payload_discovery_rejects_churn_and_pid_reuse() {
        let first = vec![payload_candidate(41, 101)];
        let churn = payload_backend(
            vec![first.clone(), vec![payload_candidate(41, 103)]],
            vec![payload_evidence(41, 101, 1)],
        );
        assert!(discover_payload_leader(&churn, 40, (11, 12), (13, 14)).is_err());

        let mut reused = payload_evidence(41, 101, 1);
        reused.pid = NonZeroU32::new(99).unwrap();
        let mut reuse = payload_backend(vec![first.clone(), first], Vec::new());
        reuse.evidence.insert(41, reused);
        assert!(discover_payload_leader(&reuse, 40, (11, 12), (13, 14)).is_err());
    }

    #[test]
    fn payload_discovery_rejects_nonleader_process_churn() {
        let leader = payload_candidate(41, 101);
        let child = payload_candidate(42, 102);
        let backend = payload_backend(
            vec![vec![leader.clone(), child], vec![leader]],
            vec![payload_evidence(41, 101, 1), payload_evidence(42, 102, 7)],
        );

        assert!(matches!(
            discover_payload_leader(&backend, 40, (11, 12), (13, 14)),
            Err(HostError::Worker(message))
                if message == "payload cgroup changed during leader discovery"
        ));
    }

    #[test]
    fn payload_discovery_rejects_vanished_nonleader_without_resnapshot() {
        let leader = payload_candidate(41, 101);
        let child = payload_candidate(42, 102);
        let snapshot = vec![leader.clone(), child];
        let backend = payload_backend(
            vec![snapshot.clone(), snapshot],
            vec![payload_evidence(41, 101, 1)],
        );

        assert!(matches!(
            discover_payload_leader(&backend, 40, (11, 12), (13, 14)),
            Err(HostError::Worker(message)) if message == "fake payload pin failed"
        ));
        assert_eq!(backend.snapshots.lock().unwrap().len(), 1);
    }

    #[test]
    fn payload_discovery_rejects_ambiguous_or_substituted_identity() {
        let snapshot = vec![payload_candidate(41, 101), payload_candidate(42, 102)];
        let ambiguous = payload_backend(
            vec![snapshot.clone(), snapshot.clone()],
            vec![payload_evidence(41, 101, 1), payload_evidence(42, 102, 1)],
        );
        assert!(discover_payload_leader(&ambiguous, 40, (11, 12), (13, 14)).is_err());

        let duplicate = payload_backend(
            vec![
                vec![payload_candidate(41, 101), payload_candidate(41, 102)],
                Vec::new(),
            ],
            vec![payload_evidence(41, 101, 1)],
        );
        assert!(discover_payload_leader(&duplicate, 40, (11, 12), (13, 14)).is_err());

        let mut wrong_root = payload_evidence(41, 101, 1);
        wrong_root.root_inode = 99;
        let substituted = payload_backend(
            vec![vec![snapshot[0].clone()], vec![snapshot[0].clone()]],
            vec![wrong_root],
        );
        assert!(discover_payload_leader(&substituted, 40, (11, 12), (13, 14)).is_err());

        let mut wrong_network = payload_evidence(41, 101, 1);
        wrong_network.network_inode = 99;
        let substituted = payload_backend(
            vec![vec![snapshot[0].clone()], vec![snapshot[0].clone()]],
            vec![wrong_network],
        );
        assert!(discover_payload_leader(&substituted, 40, (11, 12), (13, 14)).is_err());

        let mut dead = payload_backend(
            vec![vec![snapshot[0].clone()], vec![snapshot[0].clone()]],
            vec![payload_evidence(41, 101, 1)],
        );
        dead.alive = false;
        assert!(discover_payload_leader(&dead, 40, (11, 12), (13, 14)).is_err());
    }

    #[test]
    fn nested_pid_parser_requires_exact_host_first_value() {
        let pid = NonZeroU32::new(41).unwrap();
        assert_eq!(
            parse_nested_pid(b"Name:\tinit\nNSpid:\t41\t1\n", pid).unwrap(),
            1
        );
        assert!(parse_nested_pid(b"NSpid:\t42\t1\n", pid).is_err());
        assert!(parse_nested_pid(b"NSpid:\t41\t1\nNSpid:\t41\t1\n", pid).is_err());
        assert!(parse_nested_pid(b"Name:\tinit\n", pid).is_err());
    }

    #[test]
    fn namespace_self_probe_rejects_pid_or_thread_group_substitution() {
        assert!(validate_service_probe_identity(41, 41, 41).is_ok());
        assert!(validate_service_probe_identity(41, 42, 41).is_err());
        assert!(validate_service_probe_identity(41, 41, 42).is_err());
    }

    #[tokio::test]
    async fn proof_failure_rolls_back_even_if_effect_guard_would_expire() {
        let backend = backend(vec![
            Ok(observation(ObservedRuntimeState::Absent, false)),
            Err(HostError::Worker(
                "post-start observation failed".to_owned(),
            )),
        ]);
        let mut guard_calls = 0;
        let mut guard = || {
            guard_calls += 1;
            if guard_calls == 1 {
                Ok(())
            } else {
                Err(HostError::Worker("expired effect guard".to_owned()))
            }
        };
        let mut verify = |_: &WorkerObservation, _: &LaunchPins| Ok(current_payload_proof());

        assert!(
            reconcile_launch(
                &backend,
                &spec(),
                &current_pins("/proc/self/exe"),
                &mut guard,
                &mut verify,
            )
            .await
            .is_err()
        );
        assert_eq!(guard_calls, 1);
        assert_eq!(backend.starts.load(Ordering::SeqCst), 1);
        assert_eq!(backend.kills.load(Ordering::SeqCst), 1);
        assert_eq!(backend.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn preexisting_failures_require_live_containment_authority() {
        for observation_fails in [false, true] {
            for guard_allows in [false, true] {
                let initial = if observation_fails {
                    Err(HostError::Worker("initial observation failed".to_owned()))
                } else {
                    Ok(observation(ObservedRuntimeState::Ready, true))
                };
                let backend = backend(vec![initial]);
                let mut guard_calls = 0;
                let mut guard = || {
                    guard_calls += 1;
                    if guard_allows {
                        Ok(())
                    } else {
                        Err(HostError::Worker("expired containment guard".to_owned()))
                    }
                };
                let mut verify = |_: &WorkerObservation, _: &LaunchPins| {
                    Err(HostError::Worker("pre-existing pin mismatch".to_owned()))
                };

                let result = reconcile_launch(
                    &backend,
                    &spec(),
                    &current_pins("/proc/self/exe"),
                    &mut guard,
                    &mut verify,
                )
                .await;
                assert!(result.is_err());
                assert_eq!(guard_calls, 1);
                assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
                assert_eq!(
                    backend.kills.load(Ordering::SeqCst),
                    usize::from(guard_allows)
                );
                assert_eq!(
                    backend.stops.load(Ordering::SeqCst),
                    usize::from(guard_allows)
                );
                if !guard_allows {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("expired containment guard")
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn missing_leader_and_preexisting_mismatch_are_fail_stopped() {
        let missing = backend(vec![
            Ok(observation(ObservedRuntimeState::Absent, false)),
            Ok(observation(ObservedRuntimeState::Ready, false)),
        ]);
        let mut guard = || Ok(());
        let mut verify = |_: &WorkerObservation, _: &LaunchPins| Ok(current_payload_proof());
        assert!(
            reconcile_launch(
                &missing,
                &spec(),
                &current_pins("/proc/self/exe"),
                &mut guard,
                &mut verify,
            )
            .await
            .is_err()
        );
        assert_eq!(missing.starts.load(Ordering::SeqCst), 1);
        assert_eq!(missing.kills.load(Ordering::SeqCst), 1);
        assert_eq!(missing.stops.load(Ordering::SeqCst), 1);

        let mismatch = backend(vec![Ok(observation(ObservedRuntimeState::Ready, true))]);
        let mut mismatch_proof = |_: &WorkerObservation, _: &LaunchPins| {
            Err(HostError::Worker("injected pin mismatch".to_owned()))
        };
        assert!(
            reconcile_launch(
                &mismatch,
                &spec(),
                &current_pins("/proc/self/exe"),
                &mut guard,
                &mut mismatch_proof,
            )
            .await
            .is_err()
        );
        assert_eq!(mismatch.starts.load(Ordering::SeqCst), 0);
        assert_eq!(mismatch.kills.load(Ordering::SeqCst), 1);
        assert_eq!(mismatch.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn preexisting_running_unit_requires_and_passes_exact_pin_proof() {
        let backend = backend(vec![Ok(observation(ObservedRuntimeState::Ready, true))]);
        let mut guard = || Err(HostError::Worker("must not start".to_owned()));
        let mut verify = |_: &WorkerObservation, _: &LaunchPins| Ok(current_payload_proof());
        let result = reconcile_launch(
            &backend,
            &spec(),
            &current_pins("/proc/self/exe"),
            &mut guard,
            &mut verify,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert!(result.unwrap().payload.is_some());
        assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
        assert_eq!(backend.kills.load(Ordering::SeqCst), 0);
        assert_eq!(backend.stops.load(Ordering::SeqCst), 0);
    }
}
