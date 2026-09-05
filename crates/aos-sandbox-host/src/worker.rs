//! One-transaction typed systemd workers and pinned runtime observations.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, PidFd};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_systemd::{
    FreezerState, JobResult, PayloadRootContinuityPolicyV1, SandboxCgroupPath, SandboxUnitName,
    SandboxUnitObservation, SandboxUnitSpec, SystemdClient,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::plan::LaunchPins;
use crate::{HostError, Result};

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
    /// Freezes the complete service cgroup.
    Freeze,
    /// Thaws the complete service cgroup.
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
    /// The runtime's complete service cgroup is frozen.
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
/// nspawn binary. Pidfd namespace access to a shifted payload remains a
/// separately probed deployment condition.
#[derive(Debug)]
pub struct PinnedPayloadLeader {
    pidfd: PidFd,
    cgroup: BeneathRoot,
    relative_cgroup_hint: String,
    root: OwnedFd,
    network: NamespaceFd,
    mount: NamespaceFd,
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
        if (current_root.st_dev, current_root.st_ino)
            != (retained_root.st_dev, retained_root.st_ino)
            || current_network.identity() != self.network.identity()
            || current_mount.identity() != self.mount.identity()
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

/// Executes one idempotent fixed-function host transaction.
#[async_trait]
pub trait HostWorker {
    /// Applies or reconciles one operation, then returns verified observation.
    /// Implementations must invoke `before_effect` after asynchronous
    /// preparation and immediately before each mutating backend call. An
    /// idempotent no-op reconciliation does not consume effect authority. The
    /// sole exception is mandatory kill/stop compensation after an attempted
    /// launch fails identity proof: that rollback completes the already-admitted
    /// effect and cannot be disabled by expiry of its ordinary forward guard.
    ///
    /// # Errors
    ///
    /// Returns an error when the system manager rejects the fixed operation or
    /// the resulting unit, cgroup, invocation, or pidfd identity is invalid.
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
}

/// Creates a fresh system-bus connection for every fixed host transaction.
///
/// The broker retains durable request state, but a worker owns no authority
/// beyond one call and drops its generic D-Bus connection before returning.
#[derive(Debug)]
pub struct SystemdOneShotWorker {
    cgroup_root: BeneathRoot,
}

impl SystemdOneShotWorker {
    /// Constructs a worker around a pre-opened cgroup-v2 mount root.
    #[must_use]
    pub const fn new(cgroup_root: BeneathRoot) -> Self {
        Self { cgroup_root }
    }

    async fn observe_with_client(
        &self,
        client: &SystemdClient,
        identity: &HostRuntimeIdentity,
    ) -> Result<WorkerObservation> {
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        let Some(observation) = client
            .observe_sandbox_unit(&name)
            .await
            .map_err(|error| worker_error(&error))?
        else {
            return Ok(WorkerObservation {
                state: ObservedRuntimeState::Absent,
                invocation_id: None,
                leader: None,
                payload: None,
            });
        };
        let state = classify_state(&observation);
        let leader = match observation.supervisor_pid {
            Some(pid) => Some(self.pin_leader(identity, &observation, pid)?),
            None if matches!(
                state,
                ObservedRuntimeState::Starting
                    | ObservedRuntimeState::Ready
                    | ObservedRuntimeState::Frozen
            ) =>
            {
                return Err(HostError::Worker(
                    "active sandbox unit has no supervisor MainPID".to_owned(),
                ));
            }
            None => None,
        };
        Ok(WorkerObservation {
            state,
            invocation_id: observation.invocation_id,
            leader,
            payload: None,
        })
    }

    fn pin_leader(
        &self,
        identity: &HostRuntimeIdentity,
        observation: &SandboxUnitObservation,
        pid: NonZeroU32,
    ) -> Result<PinnedLeader> {
        let invocation_id = observation.invocation_id.ok_or_else(|| {
            HostError::Worker("sandbox leader has no systemd invocation ID".to_owned())
        })?;
        let cgroup = observation.cgroup.as_ref().ok_or_else(|| {
            HostError::Worker("sandbox leader has no verified unit cgroup".to_owned())
        })?;
        let supervisor = cgroup.supervisor_subgroup();
        let supervisor_relative = supervisor.as_str().trim_start_matches('/');
        let supervisor = self
            .cgroup_root
            .resolve(Path::new(supervisor_relative), ResolveOptions::directory())
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let pidfd = PidFd::open(pid).map_err(|error| HostError::Worker(error.to_string()))?;
        let info = pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if info.pid() != pid.get() || info.thread_group_id() != pid.get() {
            return Err(HostError::Worker(
                "systemd MainPID is not the pinned thread-group leader".to_owned(),
            ));
        }
        let cgroup_id = info
            .cgroup_id()
            .ok_or_else(|| HostError::Worker("kernel omitted leader cgroup identity".to_owned()))?;
        if cgroup_id != supervisor.identity().inode {
            return Err(HostError::Worker(
                "pinned leader is outside the expected supervisor cgroup".to_owned(),
            ));
        }
        if !pidfd
            .is_alive()
            .map_err(|error| HostError::Worker(error.to_string()))?
        {
            return Err(HostError::Worker(
                "sandbox supervisor exited during identity validation".to_owned(),
            ));
        }

        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.host.leader.v1\0");
        digest.update(identity.incarnation_id());
        digest.update(invocation_id);
        digest.update(cgroup_id.to_le_bytes());
        digest.update(pid.get().to_le_bytes());
        Ok(PinnedLeader {
            handle: digest.finalize().into(),
            pidfd,
            cgroup: cgroup.clone(),
        })
    }
}

struct LinuxPayloadInspector<'a> {
    payload_root: &'a BeneathRoot,
}

impl PayloadInspectionBackend for LinuxPayloadInspector<'_> {
    type Proof = PinnedPayloadLeader;

    fn snapshot(&self) -> Result<Vec<PayloadCandidate>> {
        let duplicate = self
            .payload_root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let root = BeneathRoot::from_owned(duplicate)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let mut pending = VecDeque::from([(root, String::new())]);
        let mut candidates = Vec::new();
        let mut directories = 0_usize;
        while let Some((directory, relative_cgroup_hint)) = pending.pop_front() {
            directories = directories
                .checked_add(1)
                .ok_or_else(|| HostError::Worker("payload cgroup count overflow".to_owned()))?;
            if directories > MAXIMUM_PAYLOAD_CGROUPS {
                return Err(HostError::Worker(
                    "payload cgroup tree exceeds its fixed bound".to_owned(),
                ));
            }
            let cgroup_id = directory.identity().inode;
            let processes = directory
                .open_regular(Path::new("cgroup.procs"))
                .and_then(|file| file.read_bounded(MAXIMUM_CGROUP_PROCS_BYTES))
                .map_err(|error| HostError::Worker(error.to_string()))?;
            for pid in parse_cgroup_processes(&processes)? {
                if candidates.len() >= MAXIMUM_PAYLOAD_PROCESSES {
                    return Err(HostError::Worker(
                        "payload process snapshot exceeds its fixed bound".to_owned(),
                    ));
                }
                candidates.push(PayloadCandidate {
                    pid,
                    cgroup_id,
                    relative_cgroup_hint: relative_cgroup_hint.clone(),
                });
            }

            let entries = rustix::fs::Dir::read_from(directory.as_fd())
                .map_err(|error| HostError::Worker(error.to_string()))?;
            for entry in entries {
                let entry = entry.map_err(|error| HostError::Worker(error.to_string()))?;
                let name = entry.file_name().to_bytes();
                if matches!(name, b"." | b"..") {
                    continue;
                }
                match entry.file_type() {
                    rustix::fs::FileType::Directory => {
                        let name = std::str::from_utf8(name).map_err(|_| {
                            HostError::Worker("payload cgroup name is not UTF-8".to_owned())
                        })?;
                        let child = directory
                            .resolve(Path::new(name), ResolveOptions::directory())
                            .map_err(|error| HostError::Worker(error.to_string()))?;
                        let relative = if relative_cgroup_hint.is_empty() {
                            name.to_owned()
                        } else {
                            format!("{relative_cgroup_hint}/{name}")
                        };
                        if relative.len() > 4096 {
                            return Err(HostError::Worker(
                                "payload cgroup hint exceeds its fixed bound".to_owned(),
                            ));
                        }
                        pending.push_back((
                            BeneathRoot::from_resolved(child)
                                .map_err(|error| HostError::Worker(error.to_string()))?,
                            relative,
                        ));
                    }
                    rustix::fs::FileType::Unknown => {
                        return Err(HostError::Worker(
                            "payload cgroup returned an unknown directory-entry type".to_owned(),
                        ));
                    }
                    _ => {}
                }
            }
        }
        Ok(candidates)
    }

    fn prove(&self, candidate: PayloadCandidate) -> Result<(PayloadEvidence, Option<Self::Proof>)> {
        let pidfd =
            PidFd::open(candidate.pid).map_err(|error| HostError::Worker(error.to_string()))?;
        let info = pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let cgroup_id = info.cgroup_id().ok_or_else(|| {
            HostError::Worker("kernel omitted payload cgroup identity".to_owned())
        })?;
        let nested_pid = read_nested_pid(candidate.pid)?;
        if nested_pid != 1 {
            return Ok((
                PayloadEvidence {
                    pid: candidate.pid,
                    thread_group_id: info.thread_group_id(),
                    parent_pid: info.parent_pid(),
                    cgroup_id,
                    nested_pid,
                    root_device: 0,
                    root_inode: 0,
                    network_device: 0,
                    network_inode: 0,
                },
                None,
            ));
        }
        // Both `/proc/PID/root` traversal and PIDFD_GET_* namespace ioctls are
        // ptrace-policy gated. EPERM/EACCES propagate as a failed proof: this
        // boundary never falls back to a numeric PID, machined metadata, setns,
        // or a broad capability grant.
        let root = open_payload_root(candidate.pid)?;
        let root_identity =
            rustix::fs::fstat(&root).map_err(|error| HostError::Worker(error.to_string()))?;
        let network = pidfd
            .namespace(NamespaceKind::Network)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let mount = pidfd
            .namespace(NamespaceKind::Mount)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let network_identity = network.identity();
        let final_info = pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if final_info != info {
            return Err(HostError::Worker(
                "payload pidfd identity changed during proof".to_owned(),
            ));
        }
        Ok((
            PayloadEvidence {
                pid: candidate.pid,
                thread_group_id: info.thread_group_id(),
                parent_pid: info.parent_pid(),
                cgroup_id,
                nested_pid,
                root_device: root_identity.st_dev,
                root_inode: root_identity.st_ino,
                network_device: network_identity.device,
                network_inode: network_identity.inode,
            },
            Some(PinnedPayloadLeader {
                pidfd,
                cgroup: BeneathRoot::from_owned(
                    self.payload_root
                        .as_fd()
                        .try_clone_to_owned()
                        .map_err(|error| HostError::Worker(error.to_string()))?,
                )
                .map_err(|error| HostError::Worker(error.to_string()))?,
                relative_cgroup_hint: candidate.relative_cgroup_hint,
                root,
                network,
                mount,
            }),
        ))
    }

    fn is_alive(&self, proof: &Self::Proof) -> Result<bool> {
        proof
            .pidfd
            .is_alive()
            .map_err(|error| HostError::Worker(error.to_string()))
    }
}

fn parse_cgroup_processes(bytes: &[u8]) -> Result<Vec<NonZeroU32>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HostError::Worker("cgroup.procs is not UTF-8".to_owned()))?;
    let mut processes = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(HostError::Worker(
                "cgroup.procs contains a noncanonical PID".to_owned(),
            ));
        }
        let pid = line
            .parse::<u32>()
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| HostError::Worker("cgroup.procs contains an invalid PID".to_owned()))?;
        processes.push(pid);
    }
    Ok(processes)
}

fn read_nested_pid(pid: NonZeroU32) -> Result<u32> {
    let path = format!("/proc/{pid}/status");
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(error.to_string()))?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((MAXIMUM_PROC_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::Worker(error.to_string()))?;
    if bytes.len() > MAXIMUM_PROC_STATUS_BYTES {
        return Err(HostError::Worker(
            "payload proc status exceeds its fixed bound".to_owned(),
        ));
    }
    parse_nested_pid(&bytes, pid)
}

fn parse_nested_pid(bytes: &[u8], host_pid: NonZeroU32) -> Result<u32> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HostError::Worker("payload proc status is not UTF-8".to_owned()))?;
    let mut matches = text
        .lines()
        .filter_map(|line| line.strip_prefix("NSpid:\t"));
    let value = matches
        .next()
        .ok_or_else(|| HostError::Worker("payload proc status omitted NSpid".to_owned()))?;
    if matches.next().is_some() {
        return Err(HostError::Worker(
            "payload proc status repeated NSpid".to_owned(),
        ));
    }
    let values = value
        .split('\t')
        .map(|part| part.parse::<u32>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| HostError::Worker("payload proc status has invalid NSpid".to_owned()))?;
    if values.first() != Some(&host_pid.get()) {
        return Err(HostError::Worker(
            "payload proc status host PID contradicts its pidfd".to_owned(),
        ));
    }
    values
        .last()
        .copied()
        .ok_or_else(|| HostError::Worker("payload proc status has empty NSpid".to_owned()))
}

fn open_payload_root(pid: NonZeroU32) -> Result<OwnedFd> {
    let path = format!("/proc/{pid}/root");
    rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(error.to_string()))
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
        Err(error) => return rollback_launch(backend, error).await,
    };
    let mut observation = if initial.state == ObservedRuntimeState::Absent {
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
        Err(error) => rollback_launch(backend, error).await,
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
    // This is mandatory containment for an effect already attempted under a
    // valid launch grant, not a caller-directed inverse operation. Lease expiry
    // cannot turn failed identity proof into permission to keep running.
    let kill_failed = backend.kill().await.is_err();
    let stop_failed = backend.stop().await.is_err();
    if kill_failed || stop_failed {
        return Err(HostError::Worker(format!(
            "{original}; fail-stop cleanup incomplete (kill_failed={kill_failed}, stop_failed={stop_failed})"
        )));
    }
    Err(original)
}

#[async_trait]
impl HostWorker for SystemdOneShotWorker {
    async fn execute(
        &self,
        fence: &ValidatedAssignmentFence,
        operation: WorkerOperation,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<WorkerObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        let identity = HostRuntimeIdentity::from(fence);
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        match operation {
            WorkerOperation::Launch { spec, pins } => {
                let root_policy = spec.payload_root_continuity_policy();
                let backend = SystemdLaunchBackend {
                    worker: self,
                    client: &client,
                    identity: &identity,
                    name: &name,
                };
                let mut verify = |observation: &WorkerObservation, pins: &LaunchPins| {
                    let leader = observation.leader.as_ref().ok_or_else(|| {
                        HostError::Worker(
                            "started nspawn supervisor has no pinned leader".to_owned(),
                        )
                    })?;
                    verify_supervisor_pins(&self.cgroup_root, pins, leader, root_policy)
                };
                return reconcile_launch(&backend, &spec, &pins, before_effect, &mut verify).await;
            }
            operation => {
                let current = self.observe_with_client(&client, &identity).await?;
                match operation {
                    WorkerOperation::Stop | WorkerOperation::Kill
                        if current.state == ObservedRuntimeState::Absent =>
                    {
                        return Ok(current);
                    }
                    WorkerOperation::Stop => {
                        before_effect()?;
                        ensure_done(
                            &client
                                .stop_sandbox_unit(&name)
                                .await
                                .map_err(|error| worker_error(&error))?,
                        )?;
                    }
                    WorkerOperation::Freeze if current.state == ObservedRuntimeState::Frozen => {
                        return Ok(current);
                    }
                    WorkerOperation::Freeze => {
                        before_effect()?;
                        client
                            .freeze_sandbox_unit(&name)
                            .await
                            .map_err(|error| worker_error(&error))?;
                    }
                    WorkerOperation::Thaw if current.state == ObservedRuntimeState::Ready => {
                        return Ok(current);
                    }
                    WorkerOperation::Thaw => {
                        before_effect()?;
                        client
                            .thaw_sandbox_unit(&name)
                            .await
                            .map_err(|error| worker_error(&error))?;
                    }
                    WorkerOperation::Kill => {
                        before_effect()?;
                        client
                            .kill_sandbox_unit(&name)
                            .await
                            .map_err(|error| worker_error(&error))?;
                    }
                    WorkerOperation::Launch { .. } => {
                        return Err(HostError::Worker(
                            "launch operation escaped its reconciliation path".to_owned(),
                        ));
                    }
                }
            }
        }
        self.observe_with_client(&client, &identity).await
    }

    async fn observe(&self, identity: &HostRuntimeIdentity) -> Result<WorkerObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        self.observe_with_client(&client, identity).await
    }

    async fn refresh_payload_scope(
        &self,
        identity: &HostRuntimeIdentity,
        invocation_id: [u8; 16],
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
    ) -> Result<WorkerObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        let mut observation = self.observe_with_client(&client, identity).await?;
        if !matches!(
            observation.state,
            ObservedRuntimeState::Ready | ObservedRuntimeState::Frozen
        ) || observation.invocation_id != Some(invocation_id)
        {
            return Err(HostError::Worker(
                "retained payload invocation is no longer current".to_owned(),
            ));
        }
        let current_supervisor = observation.leader.as_ref().ok_or_else(|| {
            HostError::Worker("current runtime has no pinned supervisor".to_owned())
        })?;
        if current_supervisor.handle() != supervisor.handle()
            || current_supervisor
                .pidfd
                .info()
                .map_err(|error| HostError::Worker(error.to_string()))?
                != supervisor
                    .pidfd
                    .info()
                    .map_err(|error| HostError::Worker(error.to_string()))?
        {
            return Err(HostError::Worker(
                "retained payload supervisor is no longer current".to_owned(),
            ));
        }

        let current_payload = resolve_payload_root(&self.cgroup_root, &current_supervisor.cgroup)?;
        if current_payload.identity() != payload.cgroup.identity() {
            return Err(HostError::Worker(
                "payload subtree differs from its retained anchor".to_owned(),
            ));
        }
        let root = rustix::fs::fstat(payload.root.as_fd())
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let network = payload.network.identity();
        let inspector = LinuxPayloadInspector {
            payload_root: &payload.cgroup,
        };
        let supervisor_info = current_supervisor
            .pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let refreshed = discover_payload_leader(
            &inspector,
            supervisor_info.pid(),
            (root.st_dev, root.st_ino),
            (network.device, network.inode),
        )?;
        if refreshed
            .pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?
            != payload
                .pidfd
                .info()
                .map_err(|error| HostError::Worker(error.to_string()))?
            || refreshed.mount.identity() != payload.mount.identity()
            || refreshed.relative_cgroup_hint != payload.relative_cgroup_hint
        {
            return Err(HostError::Worker(
                "payload PID 1 changed since launch verification".to_owned(),
            ));
        }
        refreshed.recheck_kernel(current_supervisor)?;
        observation.payload = Some(refreshed);
        Ok(observation)
    }
}

fn verify_supervisor_pins(
    cgroup_root: &BeneathRoot,
    pins: &LaunchPins,
    leader: &PinnedLeader,
    _root_policy: PayloadRootContinuityPolicyV1,
) -> Result<PinnedPayloadLeader> {
    // The unforgeable policy witness couples this point-in-time root check to
    // the immutable command which prevents PID 1 and descendants from later
    // replacing their root. Binary identity is checked below before the
    // payload observation is accepted.
    let pidfd = &leader.pidfd;
    let info = pidfd
        .info()
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let executable_path = format!("/proc/{}/exe", info.pid());
    let executable = rustix::fs::open(
        executable_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(error.to_string()))?;
    let expected = rustix::fs::fstat(pins.executable())
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let observed =
        rustix::fs::fstat(&executable).map_err(|error| HostError::Worker(error.to_string()))?;
    if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino) {
        return Err(HostError::Worker(
            "nspawn supervisor executable differs from its pin".to_owned(),
        ));
    }

    let network = pidfd
        .namespace(NamespaceKind::Network)
        .map_err(|error| HostError::Worker(error.to_string()))?;
    if network.identity() != pins.network().identity() {
        return Err(HostError::Worker(
            "nspawn supervisor network namespace differs from its pin".to_owned(),
        ));
    }
    let root = rustix::fs::fstat(pins.workspace())
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let network = pins.network().identity();
    let payload_root = resolve_payload_root(cgroup_root, &leader.cgroup)?;
    let inspector = LinuxPayloadInspector {
        payload_root: &payload_root,
    };
    let payload = discover_payload_leader(
        &inspector,
        info.pid(),
        (root.st_dev, root.st_ino),
        (network.device, network.inode),
    )?;
    // The nspawn supervisor deliberately remains outside the guest root, so
    // `/proc/<supervisor>/root` is not evidence for the container root. The
    // root guarantee here is instead the owned descriptor embedded in the
    // fixed `--directory=/proc/<hostd>/fd/N` argument and retained until this
    // post-start check. Guest-root comparison must wait for payload PID 1
    // discovery and pinning; treating the supervisor root as equivalent would
    // be a false proof.
    if !payload
        .pidfd()
        .is_alive()
        .map_err(|error| HostError::Worker(error.to_string()))?
    {
        return Err(HostError::Worker(
            "payload PID 1 exited during launch identity validation".to_owned(),
        ));
    }
    if !pidfd
        .is_alive()
        .map_err(|error| HostError::Worker(error.to_string()))?
    {
        return Err(HostError::Worker(
            "nspawn supervisor exited during launch identity validation".to_owned(),
        ));
    }
    payload.recheck_kernel(leader)?;
    Ok(payload)
}

fn resolve_payload_root(
    cgroup_root: &BeneathRoot,
    service: &SandboxCgroupPath,
) -> Result<BeneathRoot> {
    let payload = service.payload_subgroup();
    let relative = payload.as_str().trim_start_matches('/');
    let resolved = cgroup_root
        .resolve(Path::new(relative), ResolveOptions::directory())
        .map_err(|error| HostError::Worker(error.to_string()))?;
    BeneathRoot::from_resolved(resolved).map_err(|error| HostError::Worker(error.to_string()))
}

fn classify_state(observation: &SandboxUnitObservation) -> ObservedRuntimeState {
    match observation.active_state.as_str() {
        "activating" => ObservedRuntimeState::Starting,
        "active" if matches!(observation.freezer_state, FreezerState::Frozen) => {
            ObservedRuntimeState::Frozen
        }
        "active" => ObservedRuntimeState::Ready,
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

    struct FakeLaunchBackend {
        observations: Mutex<VecDeque<Result<WorkerObservation>>>,
        starts: AtomicUsize,
        kills: AtomicUsize,
        stops: AtomicUsize,
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
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn backend(observations: Vec<Result<WorkerObservation>>) -> FakeLaunchBackend {
        FakeLaunchBackend {
            observations: Mutex::new(observations.into()),
            starts: AtomicUsize::new(0),
            kills: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
        }
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
        LaunchPins::for_tests(executable, workspace, network)
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
        }
    }

    #[test]
    fn ordering_fixture_is_not_a_runtime_payload_proof() {
        let supervisor = observation(ObservedRuntimeState::Ready, true)
            .leader
            .unwrap();
        assert!(current_payload_proof().recheck_kernel(&supervisor).is_err());
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
        let pins = LaunchPins::for_tests(executable, workspace, network);
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
