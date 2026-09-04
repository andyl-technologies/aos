//! One-transaction typed systemd workers and pinned runtime observations.

use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::pidfd::{NamespaceKind, PidFd};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_systemd::{
    FreezerState, JobResult, SandboxUnitName, SandboxUnitObservation, SandboxUnitSpec,
    SystemdClient,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::plan::LaunchPins;
use crate::{HostError, Result};

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

    pub(crate) fn into_parts(self) -> ([u8; 32], PidFd) {
        (self.handle, self.pidfd)
    }
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
        let relative = format!("{}/supervisor", cgroup.as_str().trim_start_matches('/'));
        let cgroup = self
            .cgroup_root
            .resolve(Path::new(&relative), ResolveOptions::directory())
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
        if cgroup_id != cgroup.identity().inode {
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
        })
    }
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
    verify_pins: &mut (dyn FnMut(&WorkerObservation, &LaunchPins) -> Result<()> + Send),
) -> Result<WorkerObservation> {
    let initial = match backend.observe().await {
        Ok(observation) => observation,
        Err(error) => return rollback_launch(backend, error).await,
    };
    let observation = if initial.state == ObservedRuntimeState::Absent {
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
        Ok(()) => Ok(observation),
        Err(error) => rollback_launch(backend, error).await,
    }
}

fn validate_launch_observation(
    observation: &WorkerObservation,
    pins: &LaunchPins,
    verify_pins: &mut (dyn FnMut(&WorkerObservation, &LaunchPins) -> Result<()> + Send),
) -> Result<()> {
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
                    verify_supervisor_pins(pins, &leader.pidfd)
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
}

fn verify_supervisor_pins(pins: &LaunchPins, pidfd: &PidFd) -> Result<()> {
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
    // The nspawn supervisor deliberately remains outside the guest root, so
    // `/proc/<supervisor>/root` is not evidence for the container root. The
    // root guarantee here is instead the owned descriptor embedded in the
    // fixed `--directory=/proc/<hostd>/fd/N` argument and retained until this
    // post-start check. Guest-root comparison must wait for payload PID 1
    // discovery and pinning; treating the supervisor root as equivalent would
    // be a false proof.
    if !pidfd
        .is_alive()
        .map_err(|error| HostError::Worker(error.to_string()))?
    {
        return Err(HostError::Worker(
            "nspawn supervisor exited during launch identity validation".to_owned(),
        ));
    }
    Ok(())
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

    use std::collections::VecDeque;
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

    fn observation(state: ObservedRuntimeState, leader: bool) -> WorkerObservation {
        let leader = leader.then(|| PinnedLeader {
            handle: [1; 32],
            pidfd: PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap(),
        });
        WorkerObservation {
            state,
            invocation_id: Some([2; 16]),
            leader,
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
        let pidfd = PidFd::open(pid).unwrap();

        assert!(verify_supervisor_pins(&pins, &pidfd).is_err());
        assert!(pidfd.is_alive().unwrap());
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
        let mut verify = |_: &WorkerObservation, _: &LaunchPins| Ok(());

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
        let mut verify = |_: &WorkerObservation, _: &LaunchPins| Ok(());
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
        let mut verify = |_: &WorkerObservation, _: &LaunchPins| Ok(());
        let result = reconcile_launch(
            &backend,
            &spec(),
            &current_pins("/proc/self/exe"),
            &mut guard,
            &mut verify,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
        assert_eq!(backend.kills.load(Ordering::SeqCst), 0);
        assert_eq!(backend.stops.load(Ordering::SeqCst), 0);
    }
}
