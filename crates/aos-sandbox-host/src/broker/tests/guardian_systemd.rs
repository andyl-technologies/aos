//! Real systemd activation of the packaged per-assignment Guardian.

#![allow(
    clippy::disallowed_methods,
    reason = "The VM-only cleanup guard invokes the hermetic systemctl fixture."
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};
use aos_systemd::{ExactUnitRole, GuardianUnitSpec, SandboxUnitName, SandboxUnitSpec};
use async_trait::async_trait;
use rustix::fs::{Mode, OFlags, fstat, open};
use rustix::time::{ClockId, clock_gettime};

use super::*;
use crate::KERNEL_CLOCK_PROVENANCE;
use crate::plan::{
    GuardianConfig, LaunchPins, NspawnConfig, ResolvedIdentityAllocation, ResolvedLaunchResources,
    ResolvedNetwork, ResolvedWorkspace,
};
use crate::state::FileHostStateStore;
use crate::worker::{
    CompletedRuntimeProof, CurrentJobDone, ExactWorkerStopOutcome, GuardianObservation,
    GuardianObservedState, GuardianStartObservation, HostRuntimeIdentity, HostWorker,
    ObservedRuntimeState, PinnedLeader, PinnedPayloadLeader, RecoveredExactProof,
    SystemdOneShotWorker, WorkerObservation, WorkerOperation,
};

const EXPIRED_REQUEST_ID: [u8; 16] = [0x72; 16];
const EXPIRED_SANDBOX: u8 = 0x70;
const LIVE_REQUEST_ID: [u8; 16] = [0x76; 16];
const LIVE_SANDBOX: u8 = 0x74;
const DEATH_REQUEST_ID: [u8; 16] = [0x7a; 16];
const DEATH_SANDBOX: u8 = 0x78;
const REQUEST_LIFETIME_NANOSECONDS: u64 = 90_000_000_000;
const AUTHORITY_LIFETIME_SECONDS: i64 = 120;
const MAXIMUM_CLOCK_SKEW_SECONDS: u64 = 1;
const QUALIFICATION_WORKSPACE: &str = "/run/aos/sandbox-pins/workspaces/qualification";
const QUALIFICATION_NETWORK: &str = "/run/aos/sandbox-pins/netns/qualification";
const QUALIFICATION_UID_START: u32 = 655_360;

#[derive(Default)]
struct WorkerTrace {
    fail_after_guardian_ready: AtomicBool,
    guardian_observations: AtomicUsize,
    guardian_starts: AtomicUsize,
    payload_starts: AtomicUsize,
    events: Mutex<Vec<&'static str>>,
}

#[derive(Clone)]
struct QualificationWorker {
    trace: Arc<WorkerTrace>,
    nspawn_identity: (u64, u64),
}

impl QualificationWorker {
    fn new(nspawn_executable: &str) -> Self {
        let executable = open(
            nspawn_executable,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let identity = fstat(&executable).unwrap();

        Self {
            trace: Arc::new(WorkerTrace::default()),
            nspawn_identity: (identity.st_dev, identity.st_ino),
        }
    }

    fn with_trace(nspawn_executable: &str, trace: Arc<WorkerTrace>) -> Self {
        let mut worker = Self::new(nspawn_executable);
        worker.trace = trace;
        worker
    }

    fn record(&self, event: &'static str) {
        self.trace.events.lock().unwrap().push(event);
    }

    fn verify_nspawn_pin(&self, pins: &LaunchPins) {
        let identity = fstat(pins.executable()).unwrap();
        assert_eq!(
            (identity.st_dev, identity.st_ino),
            self.nspawn_identity,
            "payload launch did not retain the packaged nspawn executable"
        );
    }
}

#[async_trait]
impl HostWorker for QualificationWorker {
    async fn execute(
        &self,
        fence: &ValidatedAssignmentFence,
        operation: WorkerOperation,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<WorkerObservation> {
        systemd_worker()
            .execute(fence, operation, before_effect)
            .await
    }

    async fn observe(&self, identity: &HostRuntimeIdentity) -> Result<WorkerObservation> {
        systemd_worker().observe(identity).await
    }

    async fn refresh_payload_scope(
        &self,
        identity: &HostRuntimeIdentity,
        invocation_id: [u8; 16],
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
    ) -> Result<WorkerObservation> {
        systemd_worker()
            .refresh_payload_scope(identity, invocation_id, supervisor, payload)
            .await
    }

    async fn observe_guardian(
        &self,
        identity: &HostRuntimeIdentity,
    ) -> Result<GuardianObservation> {
        self.record("observe_guardian");
        let observation = self
            .trace
            .guardian_observations
            .fetch_add(1, Ordering::SeqCst);
        if observation == 1
            && self
                .trace
                .fail_after_guardian_ready
                .swap(false, Ordering::SeqCst)
        {
            return Err(HostError::Worker(
                "injected restart boundary after durable Guardian Ready".to_owned(),
            ));
        }
        systemd_worker().observe_guardian(identity).await
    }

    async fn start_guardian(
        &self,
        spec: &GuardianUnitSpec,
        identity: &HostRuntimeIdentity,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<GuardianStartObservation> {
        self.record("start_guardian");
        self.trace.guardian_starts.fetch_add(1, Ordering::SeqCst);
        let started = systemd_worker()
            .start_guardian(spec, identity, before_effect)
            .await?;
        self.record("guardian_ready");
        Ok(started)
    }

    async fn observe_bound_payload(
        &self,
        identity: &HostRuntimeIdentity,
    ) -> Result<GuardianObservation> {
        systemd_worker().observe_bound_payload(identity).await
    }

    async fn start_bound_payload(
        &self,
        spec: &SandboxUnitSpec,
        pins: &LaunchPins,
        identity: &HostRuntimeIdentity,
        guardian_invocation_id: [u8; 16],
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<CurrentJobDone> {
        self.verify_nspawn_pin(pins);
        self.record("start_payload_after_guardian_ready");
        self.trace.payload_starts.fetch_add(1, Ordering::SeqCst);
        let started = systemd_worker()
            .start_bound_payload(spec, pins, identity, guardian_invocation_id, before_effect)
            .await?;
        self.record("payload_ready");
        Ok(started)
    }

    async fn prove_bound_payload(
        &self,
        spec: &SandboxUnitSpec,
        pins: &LaunchPins,
        identity: &HostRuntimeIdentity,
    ) -> Result<RecoveredExactProof> {
        systemd_worker()
            .prove_bound_payload(spec, pins, identity)
            .await
    }

    async fn recover_completed_payload(
        &self,
        identity: &HostRuntimeIdentity,
        binding: [u8; 32],
        guardian_invocation_id: [u8; 16],
        payload_invocation_id: [u8; 16],
        expected_proof: CompletedRuntimeProof,
    ) -> Result<RecoveredExactProof> {
        systemd_worker()
            .recover_completed_payload(
                identity,
                binding,
                guardian_invocation_id,
                payload_invocation_id,
                expected_proof,
            )
            .await
    }

    async fn stop_exact_unit(
        &self,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
        binding: [u8; 32],
        invocation_id: [u8; 16],
    ) -> Result<ExactWorkerStopOutcome> {
        systemd_worker()
            .stop_exact_unit(identity, role, binding, invocation_id)
            .await
    }

    async fn observe_post_unref(
        &self,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
    ) -> Result<GuardianObservation> {
        systemd_worker().observe_post_unref(identity, role).await
    }
}

struct QualificationCatalog;

impl HostCatalog for QualificationCatalog {
    fn resolve(
        &self,
        _fence: &ValidatedAssignmentFence,
        plan: &aos_sandbox_protocol::ValidatedRuntimePlan,
    ) -> Result<ResolvedLaunchResources> {
        if plan.workspace_handle() != &[6; 32]
            || plan.network_handle() != &[7; 32]
            || plan.attachment_anchor_handle().is_some()
            || plan.uid_range_start() != QUALIFICATION_UID_START
            || plan.uid_range_size() != 65_536
        {
            return Err(HostError::Catalog(
                "qualification launch resources changed".to_owned(),
            ));
        }
        qualification_resources()
    }
}

struct LiveGuardianRequest {
    bytes: Vec<u8>,
    artifacts: ValidatedUntrustedAuthorizationArtifacts,
    clock: RawPairedClockSample,
    expires_seconds: i64,
    identity: HostRuntimeIdentity,
}

struct ExactUnitCleanup {
    systemctl: String,
    units: Vec<String>,
}

impl ExactUnitCleanup {
    fn new(systemctl: String, sandboxes: &[u8]) -> Self {
        let mut units = Vec::with_capacity(sandboxes.len() * 2);
        for sandbox in sandboxes {
            let name = SandboxUnitName::from_incarnation([sandbox.wrapping_add(1); 16]);
            units.push(name.as_str().to_owned());
            units.push(name.guardian().to_owned());
        }
        Self { systemctl, units }
    }
}

impl Drop for ExactUnitCleanup {
    fn drop(&mut self) {
        for unit in &self.units {
            let _ = Command::new(&self.systemctl).args(["stop", unit]).status();
            let _ = Command::new(&self.systemctl)
                .args(["reset-failed", unit])
                .status();
        }
        let _ = std::fs::remove_file(format!(
            "{QUALIFICATION_WORKSPACE}/var/qualification-generation"
        ));
        let _ = std::fs::remove_file(format!(
            "{QUALIFICATION_WORKSPACE}/var/qualification-reboot"
        ));
    }
}

#[tokio::test]
#[ignore = "requires the sandbox-host-worker fleet VM and its real system manager"]
async fn production_worker_enforces_guardian_before_payload_across_restart_and_death() {
    assert_eq!(
        std::env::var("AOS_SANDBOX_WORKER_QUALIFICATION").unwrap(),
        "1"
    );
    assert!(rustix::process::geteuid().is_root());

    let guardian_executable = std::env::var("AOS_SANDBOX_QUALIFICATION_GUARDIAN").unwrap();
    let nspawn_executable = std::env::var("AOS_SANDBOX_QUALIFICATION_NSPAWN").unwrap();
    let systemctl = std::env::var("AOS_SANDBOX_QUALIFICATION_SYSTEMCTL").unwrap();
    let _cleanup = ExactUnitCleanup::new(
        systemctl.clone(),
        &[EXPIRED_SANDBOX, DEATH_SANDBOX, LIVE_SANDBOX],
    );
    reset_payload_generation();

    let guardian = GuardianConfig::new(&guardian_executable, Duration::from_secs(30)).unwrap();
    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let expired_authority = fixture.protected_authority(credentials.path());

    let expired = live_guardian_request(&fixture, EXPIRED_REQUEST_ID[0], EXPIRED_SANDBOX);
    assert_absent(&expired.identity).await;
    let expired_state_directory = tempfile::tempdir().unwrap();
    let expired_store = private_state_store(&expired_state_directory);
    let expired_worker = QualificationWorker::new(&nspawn_executable);
    let expired_trace = expired_worker.trace.clone();
    let mut expired_broker = HostBroker::open(
        QualificationCatalog,
        expired_store.clone(),
        expired_worker,
        Some(qualification_nspawn(&nspawn_executable)),
        expired_authority,
    )
    .unwrap()
    .with_guardian(guardian.clone());
    let expired_clock = clock_at_plan_expiry(&expired);
    let mut expiry_samples = 0;
    let expired_result = expired_broker
        .apply_runtime(
            &expired.bytes,
            &expired.artifacts,
            ProtocolVersion::new(1, 5),
            peer(),
            policy(),
            || {
                expiry_samples += 1;
                Ok(match expiry_samples {
                    1..=3 => expired.clock,
                    4 | 5 => expired_clock,
                    _ => panic!("unexpected extra final-guard clock sample"),
                })
            },
        )
        .await
        .unwrap();
    let expired_runtime = RuntimeObservation::decode_from_slice(&expired_result).unwrap();
    assert_eq!(
        expired_runtime.state.as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
    assert_eq!(expiry_samples, 5);
    assert_eq!(expired_trace.guardian_starts.load(Ordering::SeqCst), 1);
    assert_eq!(expired_trace.payload_starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        expired_trace.events.lock().unwrap().as_slice(),
        [
            "observe_guardian",
            "start_guardian",
            "guardian_ready",
            "observe_guardian",
        ]
    );
    assert!(matches!(
        expired_store
            .load()
            .unwrap()
            .guardian_attempt(&EXPIRED_REQUEST_ID)
            .unwrap()
            .phase,
        GuardianLaunchPhase::Compensated { .. }
    ));
    wait_for_absence(&expired.identity).await;
    assert_eq!(payload_generation(), None);

    let death_authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let death = live_guardian_request(&fixture, DEATH_REQUEST_ID[0], DEATH_SANDBOX);
    assert_absent(&death.identity).await;
    let death_state_directory = tempfile::tempdir().unwrap();
    let death_store = private_state_store(&death_state_directory);
    let death_worker = QualificationWorker::new(&nspawn_executable);
    let death_trace = death_worker.trace.clone();
    let mut death_broker = HostBroker::open(
        QualificationCatalog,
        death_store.clone(),
        death_worker,
        Some(qualification_nspawn(&nspawn_executable)),
        death_authority,
    )
    .unwrap()
    .with_guardian(guardian.clone());
    let death_payload_unit = SandboxUnitName::from_incarnation(*death.identity.incarnation_id());
    let death_guardian_unit = death_payload_unit.guardian().to_owned();
    let mut death_samples = 0;
    let death_receipt = death_broker
        .apply_runtime(
            &death.bytes,
            &death.artifacts,
            ProtocolVersion::new(1, 5),
            peer(),
            policy(),
            || {
                death_samples += 1;
                if death_samples == 5 {
                    let killed = Command::new(&systemctl)
                        .args([
                            "kill",
                            "--kill-whom=main",
                            "--signal=SIGKILL",
                            &death_guardian_unit,
                        ])
                        .status()
                        .unwrap();
                    assert!(
                        killed.success(),
                        "failed to kill Guardian in the exact pre-submission window"
                    );
                }
                Ok(current_clock())
            },
        )
        .await
        .unwrap();
    assert_eq!(
        RuntimeObservation::decode_from_slice(&death_receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
    assert_eq!(death_samples, 5);
    assert_eq!(death_trace.guardian_starts.load(Ordering::SeqCst), 1);
    assert_eq!(death_trace.payload_starts.load(Ordering::SeqCst), 1);
    assert!(
        !death_trace
            .events
            .lock()
            .unwrap()
            .contains(&"payload_ready")
    );
    wait_for_absence(&death.identity).await;
    assert_eq!(payload_generation(), None);
    assert!(matches!(
        death_store
            .load()
            .unwrap()
            .guardian_attempt(&DEATH_REQUEST_ID)
            .unwrap()
            .phase,
        GuardianLaunchPhase::Compensated { .. }
    ));

    let live_authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let live = live_guardian_request(&fixture, LIVE_REQUEST_ID[0], LIVE_SANDBOX);
    assert_absent(&live.identity).await;
    let live_state_directory = tempfile::tempdir().unwrap();
    let live_store = private_state_store(&live_state_directory);
    let live_worker = QualificationWorker::new(&nspawn_executable);
    let live_trace = live_worker.trace.clone();
    live_trace
        .fail_after_guardian_ready
        .store(true, Ordering::SeqCst);
    let mut live_broker = HostBroker::open(
        QualificationCatalog,
        live_store.clone(),
        live_worker,
        Some(qualification_nspawn(&nspawn_executable)),
        live_authority,
    )
    .unwrap()
    .with_guardian(guardian.clone());
    let interrupted = live_broker
        .apply_runtime(
            &live.bytes,
            &live.artifacts,
            ProtocolVersion::new(1, 5),
            peer(),
            policy(),
            || Ok(current_clock()),
        )
        .await;
    assert!(matches!(
        interrupted,
        Err(HostError::Worker(message))
            if message == "injected restart boundary after durable Guardian Ready"
    ));
    assert_eq!(live_trace.guardian_starts.load(Ordering::SeqCst), 1);
    assert_eq!(live_trace.payload_starts.load(Ordering::SeqCst), 0);
    assert_eq!(payload_generation(), None);

    let interrupted_state = live_store.load().unwrap();
    let attempt = interrupted_state
        .guardian_attempt(&LIVE_REQUEST_ID)
        .unwrap();
    let guardian_invocation_before_restart = match &attempt.phase {
        GuardianLaunchPhase::GuardianReady {
            guardian_invocation,
        } => *guardian_invocation,
        phase => panic!("restart boundary was not durably Guardian Ready: {phase:?}"),
    };
    let binding = attempt.binding;
    let guardian_before_restart = systemd_worker()
        .observe_guardian(&live.identity)
        .await
        .unwrap();
    assert_eq!(guardian_before_restart.binding, Some(binding));
    assert_eq!(
        guardian_before_restart.invocation_id,
        Some(guardian_invocation_before_restart)
    );
    assert_eq!(
        guardian_before_restart.state,
        GuardianObservedState::ActiveRunning
    );
    assert_guardian_cgroup_present(&live.identity);
    assert_eq!(
        systemd_worker()
            .observe(&live.identity)
            .await
            .unwrap()
            .state,
        ObservedRuntimeState::Absent
    );

    drop(live_broker);
    let replay_store = FileHostStateStore::open(live_state_directory.path()).unwrap();
    let replay_authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let replay_worker = QualificationWorker::with_trace(&nspawn_executable, live_trace.clone());
    let mut replay_broker = HostBroker::open(
        QualificationCatalog,
        replay_store.clone(),
        replay_worker,
        Some(qualification_nspawn(&nspawn_executable)),
        replay_authority,
    )
    .unwrap()
    .with_guardian(guardian.clone());
    let receipt = replay_broker
        .apply_runtime(
            &live.bytes,
            &live.artifacts,
            ProtocolVersion::new(1, 5),
            peer(),
            policy(),
            || Ok(current_clock()),
        )
        .await
        .unwrap();
    let runtime = RuntimeObservation::decode_from_slice(&receipt).unwrap();
    assert_eq!(
        runtime.state.as_known(),
        Some(RuntimeState::RUNTIME_STATE_READY)
    );
    assert_eq!(live_trace.guardian_starts.load(Ordering::SeqCst), 1);
    assert_eq!(live_trace.payload_starts.load(Ordering::SeqCst), 1);
    wait_for_payload_generation(1).await;
    assert_eq!(
        live_trace.events.lock().unwrap().as_slice(),
        [
            "observe_guardian",
            "start_guardian",
            "guardian_ready",
            "observe_guardian",
            "observe_guardian",
            "start_payload_after_guardian_ready",
            "payload_ready",
        ]
    );

    let completed = replay_store.load().unwrap();
    let attempt = completed.guardian_attempt(&LIVE_REQUEST_ID).unwrap();
    let (guardian_invocation, payload_invocation) = match attempt.phase {
        GuardianLaunchPhase::Complete {
            guardian_invocation,
            payload_invocation,
            ..
        } => (*guardian_invocation, *payload_invocation),
        phase => panic!("restarted transaction did not complete: {phase:?}"),
    };
    assert_eq!(attempt.binding, binding);
    assert_ne!(guardian_invocation, [0; 16]);
    assert_ne!(payload_invocation, [0; 16]);
    assert_ne!(guardian_invocation, payload_invocation);
    assert_eq!(guardian_invocation, guardian_invocation_before_restart);

    let guardian_observation = systemd_worker()
        .observe_guardian(&live.identity)
        .await
        .unwrap();
    let payload_observation = systemd_worker()
        .observe_bound_payload(&live.identity)
        .await
        .unwrap();
    assert_eq!(guardian_observation.binding, Some(binding));
    assert_eq!(
        guardian_observation.invocation_id,
        Some(guardian_invocation)
    );
    assert_eq!(
        guardian_observation.state,
        GuardianObservedState::ActiveRunning
    );
    assert_eq!(payload_observation.binding, Some(binding));
    assert_eq!(payload_observation.invocation_id, Some(payload_invocation));
    assert_eq!(
        payload_observation.state,
        GuardianObservedState::ActiveRunning
    );
    assert_exact_systemd_binding(
        &systemctl,
        &live.identity,
        binding,
        guardian_invocation,
        payload_invocation,
    );

    let freeze = live_lifecycle_request(
        &fixture,
        LIVE_REQUEST_ID[0].wrapping_add(1),
        LIVE_SANDBOX,
        2,
        5,
        RuntimeAction::RUNTIME_ACTION_FREEZE,
    );
    let freeze_receipt = replay_broker
        .apply_runtime(
            &freeze.bytes,
            &freeze.artifacts,
            ProtocolVersion::new(1, 4),
            peer(),
            policy(),
            || Ok(current_clock()),
        )
        .await
        .unwrap();
    assert_eq!(
        RuntimeObservation::decode_from_slice(&freeze_receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_FROZEN)
    );
    assert_eq!(
        systemd_worker()
            .observe(&freeze.identity)
            .await
            .unwrap()
            .state,
        ObservedRuntimeState::Frozen
    );

    drop(replay_broker);
    let direct_scope_store = FileHostStateStore::open(live_state_directory.path()).unwrap();
    let direct_scope_authority =
        HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let direct_scope_worker =
        QualificationWorker::with_trace(&nspawn_executable, live_trace.clone());
    let mut direct_scope_broker = HostBroker::open(
        QualificationCatalog,
        direct_scope_store,
        direct_scope_worker,
        Some(qualification_nspawn(&nspawn_executable)),
        direct_scope_authority,
    )
    .unwrap()
    .with_guardian(guardian);
    assert!(direct_scope_broker.payload_pin(&freeze.identity).is_none());
    // `prepare_payload_scope` invokes this same lazy recovery before looking
    // up a scope handle; exercise it before any completed Launch replay.
    direct_scope_broker
        .recover_completed_runtime_scope(freeze.identity)
        .await
        .unwrap();
    direct_scope_broker
        .payload_pin(&freeze.identity)
        .unwrap()
        .recheck_kernel()
        .unwrap();

    let payload_unit = SandboxUnitName::from_incarnation(*live.identity.incarnation_id());
    let guardian_unit = payload_unit.guardian();
    let killed = Command::new(&systemctl)
        .args([
            "kill",
            "--kill-whom=main",
            "--signal=SIGKILL",
            guardian_unit,
        ])
        .status()
        .unwrap();
    assert!(killed.success(), "failed to kill exact Guardian unit");
    wait_for_absence(&freeze.identity).await;
    assert_eq!(payload_generation(), Some(1));

    let replayed_receipt = direct_scope_broker
        .apply_runtime(
            &live.bytes,
            &live.artifacts,
            ProtocolVersion::new(1, 5),
            peer(),
            policy(),
            || panic!("completed restart replay sampled the clock"),
        )
        .await
        .unwrap();
    assert_eq!(replayed_receipt, receipt);
    assert_eq!(live_trace.guardian_starts.load(Ordering::SeqCst), 1);
    assert_eq!(live_trace.payload_starts.load(Ordering::SeqCst), 1);
    assert_eq!(
        systemd_worker()
            .observe(&live.identity)
            .await
            .unwrap()
            .state,
        ObservedRuntimeState::Absent
    );

    println!("AOS_GUARDIAN_SYSTEMD_COMBINED_OK");
}

fn private_state_store(directory: &tempfile::TempDir) -> FileHostStateStore {
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    FileHostStateStore::open(directory.path()).unwrap()
}

fn qualification_nspawn(executable: &str) -> NspawnConfig {
    NspawnConfig::for_kernel_test(executable, Duration::from_secs(60), Duration::from_secs(15))
        .unwrap()
}

fn qualification_resources() -> Result<ResolvedLaunchResources> {
    let workspace_directory = open(
        QUALIFICATION_WORKSPACE,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let workspace_identity = fstat(&workspace_directory).unwrap();
    let workspace_source = BeneathRoot::from_owned(workspace_directory)
        .unwrap()
        .resolve(
            Path::new("."),
            aos_sandbox_linux::path::ResolveOptions::directory(),
        )
        .unwrap();
    let workspace_mount = DetachedMount::clone_from(&workspace_source, true).unwrap();
    let workspace = ResolvedWorkspace::from_pinned(
        QUALIFICATION_WORKSPACE.to_owned(),
        workspace_identity.st_dev,
        workspace_identity.st_ino,
        workspace_mount.as_fd().try_clone_to_owned().unwrap(),
    )
    .unwrap();

    let network = open(
        QUALIFICATION_NETWORK,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let network = NamespaceFd::from_owned(network, NamespaceKind::Network).unwrap();
    let network_identity = network.identity();
    let network = ResolvedNetwork::from_pinned(
        QUALIFICATION_NETWORK.to_owned(),
        network_identity.device,
        network_identity.inode,
        network,
    )
    .unwrap();

    Ok(ResolvedLaunchResources {
        workspace,
        network,
        identity: ResolvedIdentityAllocation {
            range_start: QUALIFICATION_UID_START,
            range_size: 65_536,
            catalog_generation: 1,
        },
        attachment_anchor: None,
    })
}

fn payload_generation() -> Option<u64> {
    let path = format!("{QUALIFICATION_WORKSPACE}/var/qualification-generation");
    match std::fs::read_to_string(path) {
        Ok(generation) => Some(generation.trim().parse().unwrap()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("payload generation cannot be read: {error}"),
    }
}

fn reset_payload_generation() {
    for child in ["qualification-generation", "qualification-reboot"] {
        let path = format!("{QUALIFICATION_WORKSPACE}/var/{child}");
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("payload fixture state cannot be reset: {error}"),
        }
    }
}

async fn wait_for_payload_generation(expected: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if payload_generation() == Some(expected) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "payload generation {expected} was not observed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_absence(identity: &HostRuntimeIdentity) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let worker = systemd_worker();
        let guardian_absent = worker
            .observe_guardian(identity)
            .await
            .is_ok_and(|observation| observation.state == GuardianObservedState::Absent);
        let payload_absent = worker
            .observe(identity)
            .await
            .is_ok_and(|observation| observation.state == ObservedRuntimeState::Absent);
        if guardian_absent && payload_absent {
            assert_guardian_cgroup_absent(identity);
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "exact Guardian/payload pair did not become absent"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn assert_exact_systemd_binding(
    systemctl: &str,
    identity: &HostRuntimeIdentity,
    binding: [u8; 32],
    guardian_invocation: [u8; 16],
    payload_invocation: [u8; 16],
) {
    let payload = SandboxUnitName::from_incarnation(*identity.incarnation_id());
    let guardian = payload.guardian();
    let binds_to = systemctl_property(systemctl, payload.as_str(), "BindsTo");
    let after = systemctl_property(systemctl, payload.as_str(), "After");
    assert!(binds_to.split_whitespace().any(|unit| unit == guardian));
    assert!(after.split_whitespace().any(|unit| unit == guardian));

    let binding_hex = crate::catalog::encode_hex(&binding);
    let guardian_environment = systemctl_property(systemctl, guardian, "Environment");
    let payload_environment = systemctl_property(systemctl, payload.as_str(), "Environment");
    assert!(guardian_environment.contains(&format!("AOS_GUARDIAN_LAUNCH_BINDING={binding_hex}")));
    assert!(payload_environment.contains(&format!("AOS_SANDBOX_LAUNCH_BINDING={binding_hex}")));
    assert_eq!(
        systemctl_property(systemctl, guardian, "InvocationID"),
        crate::catalog::encode_hex(&guardian_invocation)
    );
    assert_eq!(
        systemctl_property(systemctl, payload.as_str(), "InvocationID"),
        crate::catalog::encode_hex(&payload_invocation)
    );
}

fn systemctl_property(systemctl: &str, unit: &str, property: &str) -> String {
    let output = Command::new(systemctl)
        .args(["show", "--property", property, "--value", unit])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "systemctl could not read {property} for {unit}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

async fn assert_absent(identity: &HostRuntimeIdentity) {
    let worker = systemd_worker();
    assert_eq!(
        worker.observe_guardian(identity).await.unwrap().state,
        GuardianObservedState::Absent
    );
    assert_eq!(
        worker.observe(identity).await.unwrap().state,
        ObservedRuntimeState::Absent
    );
    assert_guardian_cgroup_absent(identity);
}

fn assert_guardian_cgroup_absent(identity: &HostRuntimeIdentity) {
    let root = system_cgroup_root();
    let relative = guardian_cgroup_path(identity);

    match root.resolve(&relative) {
        Err(aos_sandbox_linux::Error::Syscall { source, .. })
            if source.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) =>
        {
            root.resolve(Path::new(".")).unwrap();
        }
        Ok(_) => panic!("exact Guardian cgroup survived: {}", relative.display()),
        Err(error) => panic!(
            "exact Guardian cgroup absence could not be established for {}: {error}",
            relative.display()
        ),
    }
}

fn assert_guardian_cgroup_present(identity: &HostRuntimeIdentity) {
    let root = system_cgroup_root();
    let relative = guardian_cgroup_path(identity);
    root.resolve(&relative).unwrap_or_else(|error| {
        panic!(
            "active Guardian lacks its exact cgroup at {}: {error}",
            relative.display()
        )
    });
}

fn guardian_cgroup_path(identity: &HostRuntimeIdentity) -> PathBuf {
    let unit = SandboxUnitName::from_incarnation(*identity.incarnation_id());
    Path::new("aos.slice")
        .join("aos-assignment.slice")
        .join("aos-assignment-guardians.slice")
        .join(unit.guardian())
}

fn system_cgroup_root() -> CgroupV2Root {
    let descriptor = open(
        "/sys/fs/cgroup",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    CgroupV2Root::from_owned(descriptor).unwrap()
}

fn systemd_worker() -> SystemdOneShotWorker {
    let descriptor = open(
        "/sys/fs/cgroup",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    SystemdOneShotWorker::new(BeneathRoot::from_owned(descriptor).unwrap())
}

fn current_clock() -> RawPairedClockSample {
    let wall = clock_gettime(ClockId::Realtime);
    let boottime = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(boottime.tv_sec).unwrap();
    let nanoseconds = u64::try_from(boottime.tv_nsec).unwrap();
    let boottime_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .unwrap();
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE).unwrap(),
        KernelBootId::current().unwrap().into_bytes(),
        wall.tv_sec,
        boottime_nanoseconds,
    )
    .unwrap()
}

fn clock_at_plan_expiry(request: &LiveGuardianRequest) -> RawPairedClockSample {
    let elapsed_seconds = u64::try_from(
        request
            .expires_seconds
            .checked_sub(request.clock.wall_seconds())
            .unwrap(),
    )
    .unwrap();
    let boottime_nanoseconds = request
        .clock
        .boottime_nanoseconds()
        .checked_add(elapsed_seconds.checked_mul(1_000_000_000).unwrap())
        .unwrap();
    RawPairedClockSample::new_untrusted(
        request.clock.provenance(),
        request.clock.host_boot_id(),
        request.expires_seconds,
        boottime_nanoseconds,
    )
    .unwrap()
}

fn live_guardian_request(
    fixture: &AuthorityFixture,
    request_id: u8,
    sandbox_id: u8,
) -> LiveGuardianRequest {
    let clock = current_clock();
    let issued_seconds = clock.wall_seconds().checked_sub(1).unwrap();
    let expires_seconds = clock
        .wall_seconds()
        .checked_add(AUTHORITY_LIFETIME_SECONDS)
        .unwrap();
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes([sandbox_id; 16]),
        IncarnationId::from_bytes([sandbox_id.wrapping_add(1); 16]),
        AssignmentEpoch::new(1),
        DesiredGeneration::new(1),
        ObjectDigest::from_bytes([4; 32]),
    )
    .unwrap();
    let lease = OwnershipLease::new(
        LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap(),
        TEST_NODE,
        1,
        issued_seconds,
        expires_seconds,
        MAXIMUM_CLOCK_SKEW_SECONDS,
        [1; 16],
    )
    .unwrap();
    let ownership_lease = encode_ownership_lease(&lease);
    let ownership_lease_signature = signed_object_at(
        &ownership_lease,
        PortableMediaType::OwnershipLease,
        fixture.lease_scope,
        fixture.lease_signer.clone(),
        SignaturePurpose::OwnershipLease,
        &fixture.lease_policy_descriptor,
        &fixture.lease_key,
        issued_seconds,
        expires_seconds,
    );
    let lease_digest = descriptor_for_bytes(
        MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
        &ownership_lease,
    )
    .digest();
    let guardian_binding =
        GuardianPlanBinding::new(assignment, TEST_NODE, clock.host_boot_id(), 1, lease_digest)
            .unwrap();
    let guardian_plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Guardian,
        ProtocolId::Guardian,
        ProtocolVersion::new(1, 0),
        assignment,
        TEST_NODE,
        fixture.lease_signer.clone(),
        vec![
            BrokerGrant::new(
                BrokerVerb::GuardianArm,
                BrokerGrantTarget::Assignment,
                guardian_binding.commitment(),
                guardian_binding.encoded_len(),
                4,
            )
            .unwrap(),
        ],
        ObjectDigest::from_bytes([58; 32]),
        fixture.revocation_scope,
        issued_seconds,
        expires_seconds,
        Vec::new(),
    )
    .unwrap();
    let guardian_plan = encode_broker_authorization_plan(&guardian_plan);
    let guardian_plan_signature = signed_object_at(
        &guardian_plan,
        PortableMediaType::BrokerAuthorizationPlan,
        fixture.plan_scope,
        fixture.plan_signer.clone(),
        SignaturePurpose::BrokerAuthorization,
        &fixture.plan_policy_descriptor,
        &fixture.plan_key,
        issued_seconds,
        expires_seconds,
    );

    let mut base = ApplyRuntimeRequest::decode_from_slice(&request_at_protocol(
        request_id,
        sandbox_id,
        ProtocolVersion::new(1, 5),
    ))
    .unwrap();
    base.header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = clock
        .boottime_nanoseconds()
        .checked_add(REQUEST_LIFETIME_NANOSECONDS)
        .unwrap();
    let bytes = encode_host_guardian_companion_v1(
        &base.encode_to_vec(),
        &guardian_plan,
        &guardian_plan_signature,
    )
    .unwrap();
    let validated =
        decode_runtime_request(&bytes, peer(), policy(), clock.boottime_nanoseconds()).unwrap();
    let semantics =
        crate::authorization::semantics_v1::canonical_host_semantics_v1(&validated).unwrap();
    let host_plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 5),
        assignment,
        TEST_NODE,
        fixture.lease_signer.clone(),
        vec![
            BrokerGrant::new(
                semantics.verb(),
                semantics.target(),
                semantics.commitment(),
                u32::try_from(MAXIMUM_REQUEST_BYTES).unwrap(),
                0,
            )
            .unwrap(),
        ],
        ObjectDigest::from_bytes([59; 32]),
        fixture.revocation_scope,
        issued_seconds,
        expires_seconds,
        Vec::new(),
    )
    .unwrap();
    let broker_plan = encode_broker_authorization_plan(&host_plan);
    let broker_plan_signature = signed_object_at(
        &broker_plan,
        PortableMediaType::BrokerAuthorizationPlan,
        fixture.plan_scope,
        fixture.plan_signer.clone(),
        SignaturePurpose::BrokerAuthorization,
        &fixture.plan_policy_descriptor,
        &fixture.plan_key,
        issued_seconds,
        expires_seconds,
    );
    let artifacts = validated_artifacts(BrokerAuthorizationArtifactsV1 {
        broker_plan,
        broker_plan_signature,
        ownership_lease,
        ownership_lease_signature,
        ..Default::default()
    });

    LiveGuardianRequest {
        bytes,
        artifacts,
        clock,
        expires_seconds,
        identity: HostRuntimeIdentity::from(validated.fence()),
    }
}

fn live_lifecycle_request(
    fixture: &AuthorityFixture,
    request_id: u8,
    sandbox_id: u8,
    desired_generation: u64,
    assignment_digest: u8,
    action: RuntimeAction,
) -> LiveGuardianRequest {
    let clock = current_clock();
    let issued_seconds = clock.wall_seconds().checked_sub(1).unwrap();
    let expires_seconds = clock
        .wall_seconds()
        .checked_add(AUTHORITY_LIFETIME_SECONDS)
        .unwrap();
    let mut request = ApplyRuntimeRequest::decode_from_slice(&request_at_protocol(
        request_id,
        sandbox_id,
        ProtocolVersion::new(1, 4),
    ))
    .unwrap();
    request
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = clock
        .boottime_nanoseconds()
        .checked_add(REQUEST_LIFETIME_NANOSECONDS)
        .unwrap();
    let fence = request.fence.get_or_insert_default();
    fence.desired_generation = desired_generation;
    fence.assignment_digest = vec![assignment_digest; 32];
    request.action = action.into();
    request.launch_plan = None.into();
    let bytes = request.encode_to_vec();
    let validated =
        decode_runtime_request(&bytes, peer(), policy(), clock.boottime_nanoseconds()).unwrap();
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes(*validated.fence().sandbox_id()),
        IncarnationId::from_bytes(*validated.fence().incarnation_id()),
        AssignmentEpoch::new(validated.fence().assignment_epoch()),
        DesiredGeneration::new(validated.fence().desired_generation()),
        ObjectDigest::from_bytes(*validated.fence().assignment_digest()),
    )
    .unwrap();
    let lease = OwnershipLease::new(
        LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap(),
        TEST_NODE,
        2,
        issued_seconds,
        expires_seconds,
        MAXIMUM_CLOCK_SKEW_SECONDS,
        [2; 16],
    )
    .unwrap();
    let ownership_lease = encode_ownership_lease(&lease);
    let ownership_lease_signature = signed_object_at(
        &ownership_lease,
        PortableMediaType::OwnershipLease,
        fixture.lease_scope,
        fixture.lease_signer.clone(),
        SignaturePurpose::OwnershipLease,
        &fixture.lease_policy_descriptor,
        &fixture.lease_key,
        issued_seconds,
        expires_seconds,
    );
    let semantics =
        crate::authorization::semantics_v1::canonical_host_semantics_v1(&validated).unwrap();
    let host_plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 4),
        assignment,
        TEST_NODE,
        fixture.lease_signer.clone(),
        vec![
            BrokerGrant::new(
                semantics.verb(),
                semantics.target(),
                semantics.commitment(),
                u32::try_from(MAXIMUM_REQUEST_BYTES).unwrap(),
                0,
            )
            .unwrap(),
        ],
        ObjectDigest::from_bytes([59; 32]),
        fixture.revocation_scope,
        issued_seconds,
        expires_seconds,
        Vec::new(),
    )
    .unwrap();
    let broker_plan = encode_broker_authorization_plan(&host_plan);
    let broker_plan_signature = signed_object_at(
        &broker_plan,
        PortableMediaType::BrokerAuthorizationPlan,
        fixture.plan_scope,
        fixture.plan_signer.clone(),
        SignaturePurpose::BrokerAuthorization,
        &fixture.plan_policy_descriptor,
        &fixture.plan_key,
        issued_seconds,
        expires_seconds,
    );
    let artifacts = validated_artifacts(BrokerAuthorizationArtifactsV1 {
        broker_plan,
        broker_plan_signature,
        ownership_lease,
        ownership_lease_signature,
        ..Default::default()
    });

    LiveGuardianRequest {
        bytes,
        artifacts,
        clock,
        expires_seconds,
        identity: HostRuntimeIdentity::from(validated.fence()),
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_object_at(
    bytes: &[u8],
    media_type: PortableMediaType,
    scope: TrustScopeId,
    signer: KeyReference,
    purpose: SignaturePurpose,
    policy: &aos_sandbox_core::ObjectDescriptor,
    key: &SigningKey,
    issued_seconds: i64,
    expires_seconds: i64,
) -> Vec<u8> {
    let subject = descriptor_for_bytes(
        MediaType::new(media_type.as_str().to_owned()).unwrap(),
        bytes,
    );
    let statement = SignatureStatement::new(
        subject,
        scope,
        signer,
        purpose,
        issued_seconds,
        Some(expires_seconds),
        policy.clone(),
    )
    .unwrap();
    encode_signature(&sign_statement(statement, key).unwrap())
}
