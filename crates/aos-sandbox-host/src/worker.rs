//! One-transaction typed systemd workers and pinned runtime observations.

use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_systemd::{
    FreezerState, JobResult, SandboxUnitName, SandboxUnitObservation, SandboxUnitSpec,
    SystemdClient,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::{HostError, Result};

/// Selects one closed host mutation.
#[derive(Debug)]
pub enum WorkerOperation {
    /// Starts the sole fully compiled transient-unit specification.
    Launch(Box<SandboxUnitSpec>),
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
    /// idempotent no-op reconciliation does not consume effect authority.
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
    async fn observe(&self, fence: &ValidatedAssignmentFence) -> Result<WorkerObservation>;
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
        fence: &ValidatedAssignmentFence,
    ) -> Result<WorkerObservation> {
        let name = SandboxUnitName::from_incarnation(*fence.incarnation_id());
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
            Some(pid) => Some(self.pin_leader(fence, &observation, pid)?),
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
        fence: &ValidatedAssignmentFence,
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
        digest.update(fence.incarnation_id());
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
        let name = SandboxUnitName::from_incarnation(*fence.incarnation_id());
        let current = self.observe_with_client(&client, fence).await?;
        match operation {
            WorkerOperation::Launch(_) if current.state != ObservedRuntimeState::Absent => {
                return Ok(current);
            }
            WorkerOperation::Launch(spec) => {
                before_effect()?;
                ensure_done(
                    &client
                        .start_sandbox_unit(&spec)
                        .await
                        .map_err(|error| worker_error(&error))?,
                )?;
            }
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
        }
        self.observe_with_client(&client, fence).await
    }

    async fn observe(&self, fence: &ValidatedAssignmentFence) -> Result<WorkerObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        self.observe_with_client(&client, fence).await
    }
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
