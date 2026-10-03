//! Real systemd activation of the packaged per-assignment Guardian.

#![allow(
    clippy::disallowed_methods,
    reason = "The VM-only cleanup guard invokes the hermetic systemctl fixture."
)]

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use aos_sandbox_guardian::GuardianState;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, PidFd};
use aos_systemd::{ExactUnitRole, GuardianUnitSpec, SandboxUnitName, SandboxUnitSpec};
use async_trait::async_trait;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{Mode, OFlags, fstat, open};
use rustix::time::{
    ClockId, Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec, clock_gettime,
    timerfd_create, timerfd_settime,
};

use super::*;
use crate::KERNEL_CLOCK_PROVENANCE;
use crate::plan::{
    GuardianConfig, LaunchPins, NspawnConfig, ResolvedAttachmentAnchor, ResolvedIdentityAllocation,
    ResolvedLaunchResources, ResolvedNetwork, ResolvedWorkspace,
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
const FIRST_ISOLATION_REQUEST_ID: [u8; 16] = [0x7e; 16];
const FIRST_ISOLATION_SANDBOX: u8 = 0x7c;
const SECOND_ISOLATION_REQUEST_ID: [u8; 16] = [0x82; 16];
const SECOND_ISOLATION_SANDBOX: u8 = 0x80;
const EXPIRY_ATTEMPT_LIMIT: usize = 3;
const EXPIRING_REQUEST_IDS: [[u8; 16]; EXPIRY_ATTEMPT_LIMIT] = [[0x86; 16], [0x8a; 16], [0x8e; 16]];
const EXPIRING_SANDBOXES: [u8; EXPIRY_ATTEMPT_LIMIT] = [0x84, 0x88, 0x8c];
const REQUEST_LIFETIME_NANOSECONDS: u64 = 90_000_000_000;
const AUTHORITY_LIFETIME_SECONDS: i64 = 120;
const EXPIRING_LIFETIME_SECONDS: i64 = 20;
const MINIMUM_EXPIRY_OBSERVATION_NANOSECONDS: u64 = 5_000_000_000;
const POST_EXPIRY_PIDFD_WAIT_NANOSECONDS: u64 = 5_000_000_000;
const DEADLINE_POLL_INTERRUPT_LIMIT: usize = 8;
const MAXIMUM_CLOCK_SKEW_SECONDS: u64 = 1;
const QUALIFICATION_WORKSPACE: &str = "/run/aos/sandbox-pins/workspaces/qualification";
const QUALIFICATION_NETWORK: &str = "/run/aos/sandbox-pins/netns/qualification";
const QUALIFICATION_ANCHOR: &str =
    "/run/aos/sandbox-pins/workspaces/qualification/var/qualification-attachment-anchor";
const QUALIFICATION_UID_START: u32 = 655_360;
const SYSTEMD_PUBLIC_GUARDIAN_STATE_PREFIX: &str = "/var/lib/aos/lease-guards";
const SYSTEMD_PRIVATE_GUARDIAN_STATE_PREFIX: &str = "/var/lib/private/aos/lease-guards";
const GUARDIAN_STATE_FILE: &str = "authority-state";
const GUARDIAN_STATE_LOCK_FILE: &str = "authority-state.lock";
const SIBLING_ACCESS_PROBE_TEST: &str =
    "broker::tests::guardian_systemd::dynamic_identity_cannot_access_sibling_guardian_state";

static QUALIFICATION_WORKSPACE_MOUNT: OnceLock<Arc<OwnedFd>> = OnceLock::new();

#[derive(Default)]
struct WorkerTrace {
    fail_after_guardian_ready: AtomicBool,
    guardian_observations: AtomicUsize,
    guardian_start_jobs_done: AtomicUsize,
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
        if started.job_done {
            self.trace
                .guardian_start_jobs_done
                .fetch_add(1, Ordering::SeqCst);
        }
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
        fence: &ValidatedAssignmentFence,
        plan: &aos_sandbox_protocol::ValidatedRuntimePlan,
    ) -> Result<ResolvedLaunchResources> {
        if plan.workspace_handle() != &[6; 32]
            || plan.network_handle() != &[7; 32]
            || plan.attachment_anchor_handle() != &[12; 32]
            || plan.uid_range_start() != QUALIFICATION_UID_START
            || plan.uid_range_size() != 65_536
        {
            return Err(HostError::Catalog(
                "qualification launch resources changed".to_owned(),
            ));
        }
        qualification_resources(fence)
    }

    fn export_root_mount(&self, workspace: &ResolvedWorkspace) -> Result<DetachedMount> {
        let descriptor = workspace
            .pin()
            .try_clone_to_owned()
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        DetachedMount::from_inherited(descriptor)
            .map_err(|error| HostError::Catalog(error.to_string()))
    }
}

struct LiveGuardianRequest {
    bytes: Vec<u8>,
    artifacts: ValidatedUntrustedAuthorizationArtifacts,
    clock: RawPairedClockSample,
    expires_seconds: i64,
    identity: HostRuntimeIdentity,
}

struct ArmedGuardian {
    request: LiveGuardianRequest,
    _host_state_directory: tempfile::TempDir,
    trace: Arc<WorkerTrace>,
    binding: [u8; 32],
    invocation_id: [u8; 16],
}

struct LiveGuardianEvidence {
    unit: String,
    uid: u32,
    gid: u32,
    main_pid: NonZeroU32,
    cgroup: String,
    public_state: PathBuf,
    private_state: PathBuf,
    state_identity: (u64, u64),
    mount_namespace: (u64, u64),
    network_namespace: (u64, u64),
    ipc_namespace: (u64, u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpiryAttemptOutcome {
    Conclusive,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PidfdTimerRaceOutcome {
    PidfdOnly,
    TimerOnly,
    Simultaneous,
}

struct ExactUnitCleanup {
    systemctl: String,
    units: Vec<String>,
    incarnations: Vec<String>,
    finished: bool,
}

impl ExactUnitCleanup {
    fn new(systemctl: String, sandboxes: &[u8]) -> Self {
        let mut units = Vec::with_capacity(sandboxes.len() * 2);
        let mut incarnations = Vec::with_capacity(sandboxes.len());
        for sandbox in sandboxes {
            let incarnation = [sandbox.wrapping_add(1); 16];
            let name = SandboxUnitName::from_incarnation(incarnation);
            units.push(name.as_str().to_owned());
            units.push(name.guardian().to_owned());
            incarnations.push(crate::catalog::encode_hex(&incarnation));
        }

        let cleanup = Self {
            systemctl,
            units,
            incarnations,
            finished: false,
        };
        cleanup.remove_exact_artifacts_verified();
        cleanup
    }

    fn finish(mut self) {
        self.remove_exact_artifacts_verified();
        self.finished = true;
    }

    fn remove_exact_artifacts_verified(&self) {
        for unit in &self.units {
            let stop = Command::new(&self.systemctl)
                .args(["stop", unit])
                .output()
                .unwrap();
            let reset = Command::new(&self.systemctl)
                .args(["reset-failed", unit])
                .output()
                .unwrap();
            let load = Command::new(&self.systemctl)
                .args(["show", "--property=LoadState", "--value", unit])
                .output()
                .unwrap();
            assert!(
                load.status.success(),
                "could not classify final load state for {unit}: {}",
                String::from_utf8_lossy(&load.stderr)
            );
            let load_state = String::from_utf8(load.stdout).unwrap();
            let load_state = load_state.trim();

            Self::classify_cleanup_command("stop", unit, &stop, load_state);
            Self::classify_cleanup_command("reset-failed", unit, &reset, load_state);
            assert_eq!(
                load_state, "not-found",
                "exact transient unit remained loaded after cleanup: {unit}"
            );
        }
        for incarnation in &self.incarnations {
            let public_state = Path::new(SYSTEMD_PUBLIC_GUARDIAN_STATE_PREFIX).join(incarnation);
            let private_state = Path::new(SYSTEMD_PRIVATE_GUARDIAN_STATE_PREFIX).join(incarnation);
            Self::remove_file_verified(&public_state);
            Self::remove_directory_verified(&private_state);
        }
        for marker in ["qualification-generation", "qualification-reboot"] {
            let path = Path::new(QUALIFICATION_WORKSPACE).join("var").join(marker);
            Self::remove_file_verified(&path);
        }
    }

    fn classify_cleanup_command(
        operation: &str,
        unit: &str,
        output: &std::process::Output,
        final_load_state: &str,
    ) {
        if !output.status.success() {
            assert_eq!(
                final_load_state,
                "not-found",
                "systemctl {operation} failed for loaded unit {unit}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn remove_file_verified(path: &Path) {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("could not remove exact file {}: {error}", path.display()),
        }
        Self::assert_path_absent(path);
    }

    fn remove_directory_verified(path: &Path) {
        match std::fs::remove_dir_all(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "could not remove exact directory {}: {error}",
                path.display()
            ),
        }
        Self::assert_path_absent(path);
    }

    fn assert_path_absent(path: &Path) {
        let error = std::fs::symlink_metadata(path).unwrap_err();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::NotFound,
            "exact cleanup target survived at {}",
            path.display()
        );
    }

    fn remove_exact_artifacts_best_effort(&self) {
        for unit in &self.units {
            let _ = Command::new(&self.systemctl).args(["stop", unit]).output();
            let _ = Command::new(&self.systemctl)
                .args(["reset-failed", unit])
                .output();
        }
        for incarnation in &self.incarnations {
            let public_state = Path::new(SYSTEMD_PUBLIC_GUARDIAN_STATE_PREFIX).join(incarnation);
            let private_state = Path::new(SYSTEMD_PRIVATE_GUARDIAN_STATE_PREFIX).join(incarnation);
            let _ = std::fs::remove_file(public_state);
            let _ = std::fs::remove_dir_all(private_state);
        }
        for marker in ["qualification-generation", "qualification-reboot"] {
            let path = Path::new(QUALIFICATION_WORKSPACE).join("var").join(marker);
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for ExactUnitCleanup {
    fn drop(&mut self) {
        if !self.finished {
            self.remove_exact_artifacts_best_effort();
        }
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
    let cleanup = ExactUnitCleanup::new(
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
            ProtocolVersion::new(1, 0),
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
            ProtocolVersion::new(1, 0),
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
            ProtocolVersion::new(1, 0),
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
            ProtocolVersion::new(1, 0),
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
            "observe_guardian",
            "observe_guardian",
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
            ProtocolVersion::new(1, 0),
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
            ProtocolVersion::new(1, 0),
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

    cleanup.finish();
    println!("AOS_GUARDIAN_SYSTEMD_COMBINED_OK");
}

#[tokio::test]
#[ignore = "requires the sandbox-host-worker fleet VM and its real system manager"]
async fn production_guardian_runtime_isolation_and_expiry_are_enforced() {
    assert_eq!(
        std::env::var("AOS_SANDBOX_WORKER_QUALIFICATION").unwrap(),
        "1"
    );
    assert!(rustix::process::geteuid().is_root());

    let guardian_executable = std::env::var("AOS_SANDBOX_QUALIFICATION_GUARDIAN").unwrap();
    let nspawn_executable = std::env::var("AOS_SANDBOX_QUALIFICATION_NSPAWN").unwrap();
    let systemctl = std::env::var("AOS_SANDBOX_QUALIFICATION_SYSTEMCTL").unwrap();
    assert_packaged_systemd_version(&systemctl);

    let cleanup = ExactUnitCleanup::new(
        systemctl.clone(),
        &[
            FIRST_ISOLATION_SANDBOX,
            SECOND_ISOLATION_SANDBOX,
            EXPIRING_SANDBOXES[0],
            EXPIRING_SANDBOXES[1],
            EXPIRING_SANDBOXES[2],
        ],
    );
    reset_payload_generation();

    let guardian = GuardianConfig::new(&guardian_executable, Duration::from_secs(30)).unwrap();
    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();

    let first_authority = fixture.protected_authority(credentials.path());
    let first = arm_guardian_without_payload(
        &fixture,
        FIRST_ISOLATION_REQUEST_ID,
        FIRST_ISOLATION_SANDBOX,
        &nspawn_executable,
        guardian.clone(),
        first_authority,
    )
    .await;
    let second_authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let second = arm_guardian_without_payload(
        &fixture,
        SECOND_ISOLATION_REQUEST_ID,
        SECOND_ISOLATION_SANDBOX,
        &nspawn_executable,
        guardian.clone(),
        second_authority,
    )
    .await;

    let first_evidence = inspect_live_guardian(&systemctl, &first);
    let second_evidence = inspect_live_guardian(&systemctl, &second);
    assert_ne!(first_evidence.unit, second_evidence.unit);
    assert_ne!(first_evidence.main_pid, second_evidence.main_pid);
    assert_ne!(first_evidence.uid, second_evidence.uid);
    assert_ne!(first_evidence.gid, second_evidence.gid);
    assert_ne!(first_evidence.cgroup, second_evidence.cgroup);
    assert_ne!(first_evidence.private_state, second_evidence.private_state);
    assert_ne!(
        first_evidence.state_identity,
        second_evidence.state_identity
    );
    assert_ne!(
        first_evidence.mount_namespace,
        second_evidence.mount_namespace
    );
    assert_ne!(
        first_evidence.network_namespace,
        second_evidence.network_namespace
    );
    assert_ne!(first_evidence.ipc_namespace, second_evidence.ipc_namespace);

    let host_mount = namespace_identity(Path::new("/proc/1/ns/mnt"));
    let host_network = namespace_identity(Path::new("/proc/1/ns/net"));
    let host_ipc = namespace_identity(Path::new("/proc/1/ns/ipc"));
    for evidence in [&first_evidence, &second_evidence] {
        assert_ne!(evidence.mount_namespace, host_mount);
        assert_ne!(evidence.network_namespace, host_network);
        assert_ne!(evidence.ipc_namespace, host_ipc);
    }

    assert_sibling_state_access_denied(&first_evidence, &second_evidence);
    assert_sibling_state_access_denied(&second_evidence, &first_evidence);

    stop_guardian(&systemctl, &first_evidence.unit);
    wait_for_absence(&first.request.identity).await;
    stop_guardian(&systemctl, &second_evidence.unit);
    wait_for_absence(&second.request.identity).await;

    reset_payload_generation();
    qualify_guardian_expiry_with_retries(
        &fixture,
        credentials.path(),
        &nspawn_executable,
        guardian,
        &systemctl,
        &cleanup,
    )
    .await;

    cleanup.finish();
    println!("AOS_GUARDIAN_SYSTEMD_ISOLATION_EXPIRY_OK");
}

async fn qualify_guardian_expiry_with_retries(
    fixture: &AuthorityFixture,
    credentials_directory: &Path,
    nspawn_executable: &str,
    guardian: GuardianConfig,
    systemctl: &str,
    cleanup: &ExactUnitCleanup,
) {
    for (request_id, sandbox_id) in EXPIRING_REQUEST_IDS.into_iter().zip(EXPIRING_SANDBOXES) {
        let authority = HostAuthorityV1::from_protected_directory(credentials_directory).unwrap();
        let outcome = run_guardian_expiry_attempt(
            fixture,
            request_id,
            sandbox_id,
            nspawn_executable,
            guardian.clone(),
            authority,
            systemctl,
        )
        .await;

        match outcome {
            ExpiryAttemptOutcome::Conclusive => return,
            ExpiryAttemptOutcome::Inconclusive => {
                // An ambiguous kernel snapshot proves neither success nor
                // failure. Remove every exact artifact before creating the
                // next identity.
                cleanup.remove_exact_artifacts_verified();
            }
        }
    }

    panic!("Guardian expiry remained inconclusive for all {EXPIRY_ATTEMPT_LIMIT} attempts");
}

async fn run_guardian_expiry_attempt(
    fixture: &AuthorityFixture,
    request_id: [u8; 16],
    sandbox_id: u8,
    nspawn_executable: &str,
    guardian: GuardianConfig,
    authority: HostAuthorityV1,
    systemctl: &str,
) -> ExpiryAttemptOutcome {
    assert_eq!(
        payload_generation(),
        None,
        "expiry attempt inherited a payload marker"
    );
    let expiring = live_guardian_request_with_lifetimes(
        fixture,
        request_id[0],
        sandbox_id,
        EXPIRING_LIFETIME_SECONDS,
        u64::try_from(EXPIRING_LIFETIME_SECONDS)
            .unwrap()
            .checked_mul(1_000_000_000)
            .unwrap(),
    );
    assert_absent(&expiring.identity).await;

    let state_directory = tempfile::tempdir().unwrap();
    let store = private_state_store(&state_directory);
    let worker = QualificationWorker::new(nspawn_executable);
    let trace = worker.trace.clone();
    let mut broker = HostBroker::open(
        QualificationCatalog,
        store.clone(),
        worker,
        Some(qualification_nspawn(nspawn_executable)),
        authority,
    )
    .unwrap()
    .with_guardian(guardian);
    let receipt = broker
        .apply_runtime(
            &expiring.bytes,
            &expiring.artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(current_clock()),
        )
        .await
        .unwrap();
    assert_eq!(
        RuntimeObservation::decode_from_slice(&receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_READY)
    );
    assert_eq!(trace.guardian_start_jobs_done.load(Ordering::SeqCst), 1);
    assert_eq!(trace.payload_starts.load(Ordering::SeqCst), 1);
    wait_for_payload_generation(1).await;

    let completed = store.load().unwrap();
    let attempt = completed.guardian_attempt(&request_id).unwrap();
    let (guardian_invocation, payload_invocation) = match attempt.phase {
        GuardianLaunchPhase::Complete {
            guardian_invocation,
            payload_invocation,
            ..
        } => (*guardian_invocation, *payload_invocation),
        phase => panic!("expiring transaction did not complete: {phase:?}"),
    };
    let worker = systemd_worker();
    let guardian_observation = worker.observe_guardian(&expiring.identity).await.unwrap();
    let payload_observation = worker
        .observe_bound_payload(&expiring.identity)
        .await
        .unwrap();
    assert_eq!(guardian_observation.binding, Some(attempt.binding));
    assert_eq!(
        guardian_observation.invocation_id,
        Some(guardian_invocation)
    );
    assert_eq!(
        guardian_observation.state,
        GuardianObservedState::ActiveRunning
    );
    assert_eq!(payload_observation.binding, Some(attempt.binding));
    assert_eq!(payload_observation.invocation_id, Some(payload_invocation));
    assert_eq!(
        payload_observation.state,
        GuardianObservedState::ActiveRunning
    );
    assert_exact_systemd_binding(
        systemctl,
        &expiring.identity,
        attempt.binding,
        guardian_invocation,
        payload_invocation,
    );

    let expiring_name = SandboxUnitName::from_incarnation(*expiring.identity.incarnation_id());
    let main_pid = systemctl_properties(systemctl, expiring_name.guardian(), &["MainPID"]);
    let main_pid = parse_nonzero_systemd_u32(&main_pid, "MainPID");
    let pinned_guardian = PidFd::open(main_pid).unwrap();
    assert!(pinned_guardian.is_alive().unwrap());

    let incarnation = crate::catalog::encode_hex(expiring.identity.incarnation_id());
    let state_path = Path::new(SYSTEMD_PUBLIC_GUARDIAN_STATE_PREFIX)
        .join(incarnation)
        .join(GUARDIAN_STATE_FILE);
    let guardian_state = GuardianState::decode(&std::fs::read(state_path).unwrap()).unwrap();
    assert_eq!(
        guardian_state.plan_expires_seconds(),
        expiring.expires_seconds
    );
    assert_eq!(
        guardian_state.authority_expires_seconds(),
        expiring.expires_seconds
    );
    assert_eq!(
        *guardian_state.host_boot_id(),
        expiring.clock.host_boot_id()
    );
    assert_eq!(guardian_state.desired_generation().get(), 1);
    assert_eq!(guardian_state.lease_generation(), 1);
    assert_eq!(
        systemctl_property(systemctl, expiring_name.guardian(), "MainPID"),
        main_pid.to_string()
    );

    // No stop is submitted here. The Guardian's absolute signed deadline must
    // keep this exact process alive until expiry, then make it exit so
    // systemd's BindsTo edge contains the live payload.
    let outcome = wait_for_pinned_guardian_deadline(
        &pinned_guardian,
        guardian_state.deadline_boottime_nanoseconds(),
    );
    if outcome == ExpiryAttemptOutcome::Inconclusive {
        return outcome;
    }

    wait_for_absence(&expiring.identity).await;
    assert_eq!(payload_generation(), Some(1));

    ExpiryAttemptOutcome::Conclusive
}

#[test]
#[ignore = "invoked under one DynamicUser identity by the fleet VM parent test"]
fn dynamic_identity_cannot_access_sibling_guardian_state() {
    assert_eq!(
        std::env::var("AOS_GUARDIAN_SIBLING_ACCESS_PROBE").unwrap(),
        "1"
    );
    let expected_uid = std::env::var("AOS_GUARDIAN_PROBE_UID")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let expected_gid = std::env::var("AOS_GUARDIAN_PROBE_GID")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    assert_eq!(rustix::process::geteuid().as_raw(), expected_uid);
    assert_eq!(rustix::process::getegid().as_raw(), expected_gid);
    assert_ne!(expected_uid, 0);
    assert_ne!(expected_gid, 0);
    assert_unprivileged_probe_credentials();

    let own_public_state =
        PathBuf::from(std::env::var_os("AOS_GUARDIAN_OWN_PUBLIC_STATE").unwrap());
    let own_private_state =
        PathBuf::from(std::env::var_os("AOS_GUARDIAN_OWN_PRIVATE_STATE").unwrap());
    let host_state_identity = (
        std::env::var("AOS_GUARDIAN_OWN_STATE_DEVICE")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        std::env::var("AOS_GUARDIAN_OWN_STATE_INODE")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
    );
    let idmapped_state_identity = assert_systemd_state_topology(
        &own_public_state,
        &own_private_state,
        expected_uid,
        expected_gid,
    );
    assert_eq!(idmapped_state_identity, host_state_identity);

    let sibling_state = PathBuf::from(std::env::var_os("AOS_GUARDIAN_SIBLING_STATE").unwrap());
    let read_error = std::fs::File::open(sibling_state.join(GUARDIAN_STATE_FILE)).unwrap_err();
    assert_state_inaccessible(read_error);

    let write_probe = PathBuf::from(std::env::var_os("AOS_GUARDIAN_WRITE_PROBE").unwrap());
    let write_error = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(write_probe)
        .unwrap_err();
    assert_state_inaccessible(write_error);
}

async fn arm_guardian_without_payload(
    fixture: &AuthorityFixture,
    request_id: [u8; 16],
    sandbox_id: u8,
    nspawn_executable: &str,
    guardian: GuardianConfig,
    authority: HostAuthorityV1,
) -> ArmedGuardian {
    let request = live_guardian_request(fixture, request_id[0], sandbox_id);
    assert_absent(&request.identity).await;
    let host_state_directory = tempfile::tempdir().unwrap();
    let store = private_state_store(&host_state_directory);
    let worker = QualificationWorker::new(nspawn_executable);
    let trace = worker.trace.clone();
    trace
        .fail_after_guardian_ready
        .store(true, Ordering::SeqCst);
    let mut broker = HostBroker::open(
        QualificationCatalog,
        store.clone(),
        worker,
        Some(qualification_nspawn(nspawn_executable)),
        authority,
    )
    .unwrap()
    .with_guardian(guardian);

    let interrupted = broker
        .apply_runtime(
            &request.bytes,
            &request.artifacts,
            ProtocolVersion::new(1, 0),
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
    assert_eq!(trace.guardian_starts.load(Ordering::SeqCst), 1);
    assert_eq!(trace.guardian_start_jobs_done.load(Ordering::SeqCst), 1);
    assert_eq!(trace.payload_starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        trace.events.lock().unwrap().as_slice(),
        [
            "observe_guardian",
            "start_guardian",
            "guardian_ready",
            "observe_guardian",
        ]
    );

    let state = store.load().unwrap();
    let attempt = state.guardian_attempt(&request_id).unwrap();
    let invocation_id = match &attempt.phase {
        GuardianLaunchPhase::GuardianReady {
            guardian_invocation,
        } => *guardian_invocation,
        phase => panic!("isolation fixture was not durably Guardian Ready: {phase:?}"),
    };
    let binding = attempt.binding;
    drop(broker);

    ArmedGuardian {
        request,
        _host_state_directory: host_state_directory,
        trace,
        binding,
        invocation_id,
    }
}

fn inspect_live_guardian(systemctl: &str, armed: &ArmedGuardian) -> LiveGuardianEvidence {
    let name = SandboxUnitName::from_incarnation(*armed.request.identity.incarnation_id());
    let unit = name.guardian().to_owned();
    let incarnation = crate::catalog::encode_hex(armed.request.identity.incarnation_id());
    let expected_state_directory = format!("aos/lease-guards/{incarnation}");
    let expected_cgroup = name.guardian_cgroup_path().as_str().to_owned();
    let properties = systemctl_properties(
        systemctl,
        &unit,
        &[
            "ActiveState",
            "SubState",
            "Type",
            "NotifyAccess",
            "DynamicUser",
            "RestrictSUIDSGID",
            "PrivateNetwork",
            "PrivateIPC",
            "StateDirectory",
            "Slice",
            "ControlGroup",
            "InvocationID",
            "Environment",
            "MainPID",
            "UID",
            "GID",
            "NRestarts",
        ],
    );
    assert_eq!(systemctl_value(&properties, "ActiveState"), "active");
    assert_eq!(systemctl_value(&properties, "SubState"), "running");
    assert_eq!(systemctl_value(&properties, "Type"), "notify");
    assert_eq!(systemctl_value(&properties, "NotifyAccess"), "main");
    assert_eq!(systemctl_value(&properties, "DynamicUser"), "yes");
    assert_eq!(systemctl_value(&properties, "RestrictSUIDSGID"), "yes");
    assert_eq!(systemctl_value(&properties, "PrivateNetwork"), "yes");
    assert_eq!(systemctl_value(&properties, "PrivateIPC"), "yes");
    assert_eq!(
        systemctl_value(&properties, "StateDirectory"),
        expected_state_directory
    );
    assert_eq!(
        systemctl_value(&properties, "Slice"),
        "aos-assignment-guardians.slice"
    );
    assert_eq!(
        systemctl_value(&properties, "ControlGroup"),
        expected_cgroup
    );
    assert_eq!(
        systemctl_value(&properties, "InvocationID"),
        crate::catalog::encode_hex(&armed.invocation_id)
    );
    assert!(
        systemctl_value(&properties, "Environment").contains(&format!(
            "AOS_GUARDIAN_LAUNCH_BINDING={}",
            crate::catalog::encode_hex(&armed.binding)
        ))
    );
    assert_eq!(systemctl_value(&properties, "NRestarts"), "0");
    assert_eq!(armed.trace.guardian_starts.load(Ordering::SeqCst), 1);
    assert_eq!(
        armed.trace.guardian_start_jobs_done.load(Ordering::SeqCst),
        1
    );

    let main_pid = parse_nonzero_systemd_u32(&properties, "MainPID");
    let uid = parse_systemd_u32(&properties, "UID");
    let gid = parse_systemd_u32(&properties, "GID");
    assert_ne!(uid, 0);
    assert_ne!(gid, 0);
    assert_process_identity(main_pid, uid, gid);

    let public_state = Path::new(SYSTEMD_PUBLIC_GUARDIAN_STATE_PREFIX).join(&incarnation);
    let private_state = Path::new(SYSTEMD_PRIVATE_GUARDIAN_STATE_PREFIX).join(&incarnation);
    let state_identity = assert_host_state_topology(&public_state, &private_state);
    let network_namespace =
        namespace_identity(&Path::new("/proc").join(main_pid.to_string()).join("ns/net"));
    let ipc_namespace =
        namespace_identity(&Path::new("/proc").join(main_pid.to_string()).join("ns/ipc"));
    let mount_namespace =
        namespace_identity(&Path::new("/proc").join(main_pid.to_string()).join("ns/mnt"));

    let final_properties = systemctl_properties(
        systemctl,
        &unit,
        &["ActiveState", "SubState", "InvocationID", "MainPID"],
    );
    assert_eq!(systemctl_value(&final_properties, "ActiveState"), "active");
    assert_eq!(systemctl_value(&final_properties, "SubState"), "running");
    assert_eq!(
        systemctl_value(&final_properties, "InvocationID"),
        crate::catalog::encode_hex(&armed.invocation_id)
    );
    assert_eq!(
        parse_nonzero_systemd_u32(&final_properties, "MainPID"),
        main_pid
    );
    assert_guardian_cgroup_present(&armed.request.identity);

    LiveGuardianEvidence {
        unit,
        uid,
        gid,
        main_pid,
        cgroup: expected_cgroup,
        public_state,
        private_state,
        state_identity,
        mount_namespace,
        network_namespace,
        ipc_namespace,
    }
}

fn assert_packaged_systemd_version(systemctl: &str) {
    let expected = std::env::var("AOS_SANDBOX_QUALIFICATION_SYSTEMD_VERSION").unwrap();
    assert_eq!(expected, "261.2");
    let output = Command::new(systemctl).arg("--version").output().unwrap();
    assert!(
        output.status.success(),
        "packaged systemctl --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().next(), Some("systemd 261 (261.2)"));
}

fn systemctl_properties(
    systemctl: &str,
    unit: &str,
    requested: &[&str],
) -> BTreeMap<String, String> {
    let mut command = Command::new(systemctl);
    command.args(["show", "--no-pager"]);
    for property in requested {
        command.arg(format!("--property={property}"));
    }
    let output = command.arg(unit).output().unwrap();
    assert!(
        output.status.success(),
        "systemctl could not inspect {unit}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let values = stdout
        .lines()
        .map(|line| {
            let (name, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("malformed systemctl property for {unit}: {line}"));
            (name.to_owned(), value.to_owned())
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        values.len(),
        requested.len(),
        "incomplete properties for {unit}"
    );
    for property in requested {
        assert!(
            values.contains_key(*property),
            "missing {property} for {unit}"
        );
    }
    values
}

fn systemctl_value<'a>(properties: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    properties
        .get(name)
        .unwrap_or_else(|| panic!("missing systemctl property {name}"))
}

fn parse_systemd_u32(properties: &BTreeMap<String, String>, name: &str) -> u32 {
    systemctl_value(properties, name)
        .parse::<u32>()
        .unwrap_or_else(|error| panic!("systemctl {name} is not a u32: {error}"))
}

fn parse_nonzero_systemd_u32(properties: &BTreeMap<String, String>, name: &str) -> NonZeroU32 {
    NonZeroU32::new(parse_systemd_u32(properties, name))
        .unwrap_or_else(|| panic!("systemctl {name} is zero"))
}

fn assert_process_identity(pid: NonZeroU32, uid: u32, gid: u32) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let observed_uids = proc_status_ids(&status, "Uid:");
    let observed_gids = proc_status_ids(&status, "Gid:");
    assert_eq!(observed_uids, [uid; 4]);
    assert_eq!(observed_gids, [gid; 4]);
}

fn proc_status_ids(status: &str, field: &str) -> [u32; 4] {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap_or_else(|| panic!("process status omitted {field}"));
    let values = value
        .split_ascii_whitespace()
        .map(|part| part.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    values
        .try_into()
        .unwrap_or_else(|_| panic!("process status {field} is not a four-ID tuple"))
}

fn assert_systemd_state_topology(
    public_state: &Path,
    private_state: &Path,
    uid: u32,
    gid: u32,
) -> (u64, u64) {
    assert_administrative_state_ancestors();

    let public_link = std::fs::symlink_metadata(public_state).unwrap();
    assert!(public_link.file_type().is_symlink());
    assert_eq!(public_link.uid(), 0);
    assert_eq!(public_link.gid(), 0);
    assert_exact_private_link(public_state);

    let public_target = std::fs::metadata(public_state).unwrap();
    let private = std::fs::symlink_metadata(private_state).unwrap();
    assert!(private.file_type().is_dir());
    assert_eq!(private.uid(), uid);
    assert_eq!(private.gid(), gid);
    assert_eq!(private.mode() & 0o7777, 0o700);
    assert_eq!(
        (public_target.dev(), public_target.ino()),
        (private.dev(), private.ino())
    );

    for child in [GUARDIAN_STATE_FILE, GUARDIAN_STATE_LOCK_FILE] {
        let metadata = std::fs::symlink_metadata(private_state.join(child)).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), gid);
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    (private.dev(), private.ino())
}

fn assert_host_state_topology(public_state: &Path, private_state: &Path) -> (u64, u64) {
    assert_administrative_state_ancestors();

    let public_link = std::fs::symlink_metadata(public_state).unwrap();
    assert!(public_link.file_type().is_symlink());
    assert_eq!(public_link.uid(), 0);
    assert_eq!(public_link.gid(), 0);
    assert_exact_private_link(public_state);

    let public_target = std::fs::metadata(public_state).unwrap();
    let private = std::fs::symlink_metadata(private_state).unwrap();
    assert!(private.file_type().is_dir());
    assert_eq!(private.mode() & 0o7777, 0o700);
    assert_eq!(
        (public_target.dev(), public_target.ino()),
        (private.dev(), private.ino())
    );
    (private.dev(), private.ino())
}

fn assert_administrative_state_ancestors() {
    for ancestor in [
        Path::new("/"),
        Path::new("/var"),
        Path::new("/var/lib"),
        Path::new("/var/lib/aos"),
        Path::new(SYSTEMD_PUBLIC_GUARDIAN_STATE_PREFIX),
        Path::new("/var/lib/private"),
        Path::new("/var/lib/private/aos"),
        Path::new(SYSTEMD_PRIVATE_GUARDIAN_STATE_PREFIX),
    ] {
        let metadata = std::fs::symlink_metadata(ancestor).unwrap();
        assert!(metadata.file_type().is_dir(), "{ancestor:?} is not direct");
        assert_eq!(metadata.uid(), 0, "{ancestor:?} is not root-owned");
        assert_eq!(metadata.gid(), 0, "{ancestor:?} is not root-group-owned");
        assert_eq!(
            metadata.mode() & 0o022,
            0,
            "{ancestor:?} is administratively writable"
        );
    }
}

fn assert_exact_private_link(public_state: &Path) {
    let incarnation = public_state.file_name().unwrap().to_string_lossy();
    assert_eq!(
        std::fs::read_link(public_state).unwrap(),
        PathBuf::from(format!("../../private/aos/lease-guards/{incarnation}"))
    );
}

fn namespace_identity(path: &Path) -> (u64, u64) {
    let descriptor = open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    let metadata = fstat(&descriptor).unwrap();
    (metadata.st_dev, metadata.st_ino)
}

fn assert_sibling_state_access_denied(
    actor: &LiveGuardianEvidence,
    sibling: &LiveGuardianEvidence,
) {
    let nsenter = std::env::var("AOS_SANDBOX_QUALIFICATION_NSENTER").unwrap();
    let setpriv = std::env::var("AOS_SANDBOX_QUALIFICATION_SETPRIV").unwrap();
    let executable = std::env::current_exe().unwrap();
    let write_probe = sibling
        .public_state
        .join(format!("cross-write-probe-{}", actor.uid));
    assert!(!write_probe.exists());

    let output = Command::new(nsenter)
        .arg(format!("--mount=/proc/{}/ns/mnt", actor.main_pid))
        .arg("--")
        .arg(setpriv)
        .arg("--reuid")
        .arg(actor.uid.to_string())
        .arg("--regid")
        .arg(actor.gid.to_string())
        .arg("--clear-groups")
        .arg("--inh-caps=-all")
        .arg("--ambient-caps=-all")
        .arg("--bounding-set=-all")
        .arg("--no-new-privs")
        .arg("--")
        .arg(executable)
        .args(["--ignored", "--exact", SIBLING_ACCESS_PROBE_TEST])
        .arg("--test-threads=1")
        .arg("--nocapture")
        .env("AOS_GUARDIAN_SIBLING_ACCESS_PROBE", "1")
        .env("AOS_GUARDIAN_PROBE_UID", actor.uid.to_string())
        .env("AOS_GUARDIAN_PROBE_GID", actor.gid.to_string())
        .env("AOS_GUARDIAN_OWN_PUBLIC_STATE", &actor.public_state)
        .env("AOS_GUARDIAN_OWN_PRIVATE_STATE", &actor.private_state)
        .env(
            "AOS_GUARDIAN_OWN_STATE_DEVICE",
            actor.state_identity.0.to_string(),
        )
        .env(
            "AOS_GUARDIAN_OWN_STATE_INODE",
            actor.state_identity.1.to_string(),
        )
        .env("AOS_GUARDIAN_SIBLING_STATE", &sibling.public_state)
        .env("AOS_GUARDIAN_WRITE_PROBE", &write_probe)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} could access {} state:\nstdout:\n{}\nstderr:\n{}",
        actor.unit,
        sibling.unit,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!write_probe.exists());
}

fn assert_unprivileged_probe_credentials() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap_or_else(|| panic!("probe status omitted {field}"));
        assert_eq!(value.trim(), "0000000000000000", "probe retained {field}");
    }
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .unwrap();
    assert!(groups.trim().is_empty());
    let no_new_privileges = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .unwrap();
    assert_eq!(no_new_privileges.trim(), "1");
}

fn assert_state_inaccessible(error: std::io::Error) {
    // Private mount namespaces may conceal the sibling path entirely; the
    // fallback DAC boundary exposes the path but denies access.
    assert!(
        error.kind() == std::io::ErrorKind::NotFound
            || error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(rustix::io::Errno::ACCESS.raw_os_error())
            || error.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error()),
        "sibling state failed for an unexpected reason: {error}"
    );
}

fn stop_guardian(systemctl: &str, unit: &str) {
    let status = Command::new(systemctl)
        .args(["stop", unit])
        .status()
        .unwrap();
    assert!(status.success(), "failed to stop {unit}");
}

fn private_state_store(directory: &tempfile::TempDir) -> FileHostStateStore {
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    FileHostStateStore::open(directory.path()).unwrap()
}

fn qualification_nspawn(executable: &str) -> NspawnConfig {
    NspawnConfig::for_kernel_test(executable, Duration::from_secs(60), Duration::from_secs(15))
        .unwrap()
}

fn qualification_resources(fence: &ValidatedAssignmentFence) -> Result<ResolvedLaunchResources> {
    // A durable launch replay must resolve the same kernel mount object, not a
    // fresh detached clone with a different mount ID.
    let workspace_mount = QUALIFICATION_WORKSPACE_MOUNT.get_or_init(|| {
        let workspace_directory = open(
            QUALIFICATION_WORKSPACE,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let workspace_source = BeneathRoot::from_owned(workspace_directory)
            .unwrap()
            .resolve(
                Path::new("."),
                aos_sandbox_linux::path::ResolveOptions::directory(),
            )
            .unwrap();
        let detached = DetachedMount::clone_from(&workspace_source, true).unwrap();

        Arc::new(detached.as_fd().try_clone_to_owned().unwrap())
    });
    let workspace_pin = workspace_mount.as_fd().try_clone_to_owned().unwrap();
    let workspace_identity = fstat(&workspace_pin).unwrap();
    let workspace = ResolvedWorkspace::from_pinned(
        QUALIFICATION_WORKSPACE.to_owned(),
        workspace_identity.st_dev,
        workspace_identity.st_ino,
        workspace_pin,
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

    std::fs::create_dir_all(QUALIFICATION_ANCHOR).unwrap();
    std::fs::set_permissions(QUALIFICATION_ANCHOR, std::fs::Permissions::from_mode(0o755)).unwrap();
    let anchor = open(
        QUALIFICATION_ANCHOR,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let anchor_identity = fstat(&anchor).unwrap();
    let anchor_mount_id = aos_sandbox_linux::inventory::MountId::from_fd(anchor.as_fd())
        .unwrap()
        .get();
    let anchor_directory = format!(
        "{}{}/{}/0000000000000001",
        aos_sandbox_protocol::ATTACHMENT_ANCHOR_PIN_PREFIX,
        crate::catalog::encode_hex(fence.sandbox_id()),
        crate::catalog::encode_hex(fence.incarnation_id()),
    );
    let attachment_anchor = ResolvedAttachmentAnchor::from_pinned(
        anchor_directory,
        anchor_identity.st_dev,
        anchor_identity.st_ino,
        anchor_mount_id,
        anchor,
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
        attachment_anchor,
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

fn wait_for_pinned_guardian_deadline(
    pidfd: &PidFd,
    deadline_nanoseconds: u64,
) -> ExpiryAttemptOutcome {
    assert_ne!(
        deadline_nanoseconds, 0,
        "Guardian deadline cannot arm a zero-valued timer"
    );
    let first_observation = current_boottime_nanoseconds();
    let remaining = deadline_nanoseconds
        .checked_sub(first_observation)
        .unwrap_or_else(|| panic!("Guardian deadline elapsed before liveness observation"));
    assert!(
        remaining >= MINIMUM_EXPIRY_OBSERVATION_NANOSECONDS,
        "Guardian deadline is too near for a robust liveness proof: {remaining}ns remain"
    );

    let deadline_timer = arm_absolute_boottime_timer(deadline_nanoseconds, "Guardian deadline");
    match poll_pidfd_and_timer(pidfd, &deadline_timer, "Guardian deadline") {
        PidfdTimerRaceOutcome::TimerOnly => {}
        PidfdTimerRaceOutcome::PidfdOnly => {
            panic!("pinned Guardian exited before its decoded exclusive deadline")
        }
        PidfdTimerRaceOutcome::Simultaneous => {
            return ExpiryAttemptOutcome::Inconclusive;
        }
    }
    drop(deadline_timer);

    let grace_deadline_nanoseconds = deadline_nanoseconds
        .checked_add(POST_EXPIRY_PIDFD_WAIT_NANOSECONDS)
        .unwrap_or_else(|| panic!("Guardian post-expiry pidfd deadline overflowed"));
    let grace_timer =
        arm_absolute_boottime_timer(grace_deadline_nanoseconds, "Guardian post-expiry grace");
    match poll_pidfd_and_timer(pidfd, &grace_timer, "Guardian post-expiry grace") {
        PidfdTimerRaceOutcome::PidfdOnly => ExpiryAttemptOutcome::Conclusive,
        PidfdTimerRaceOutcome::TimerOnly => {
            panic!("pinned Guardian did not exit within its post-expiry grace period")
        }
        PidfdTimerRaceOutcome::Simultaneous => ExpiryAttemptOutcome::Inconclusive,
    }
}

fn arm_absolute_boottime_timer(absolute_nanoseconds: u64, purpose: &str) -> OwnedFd {
    assert_ne!(
        absolute_nanoseconds, 0,
        "{purpose} cannot arm a zero-valued timer"
    );
    let seconds = i64::try_from(absolute_nanoseconds / 1_000_000_000)
        .unwrap_or_else(|error| panic!("{purpose} seconds overflowed Timespec: {error}"));
    let nanoseconds = i64::try_from(absolute_nanoseconds % 1_000_000_000)
        .unwrap_or_else(|error| panic!("{purpose} nanoseconds overflowed Timespec: {error}"));
    let timer = timerfd_create(TimerfdClockId::Boottime, TimerfdFlags::CLOEXEC)
        .unwrap_or_else(|error| panic!("could not create {purpose} BOOTTIME timerfd: {error}"));
    timerfd_settime(
        &timer,
        TimerfdTimerFlags::ABSTIME,
        &Itimerspec {
            it_interval: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: Timespec {
                tv_sec: seconds,
                tv_nsec: nanoseconds,
            },
        },
    )
    .unwrap_or_else(|error| panic!("could not arm {purpose} BOOTTIME timerfd: {error}"));

    timer
}

fn poll_pidfd_and_timer(pidfd: &PidFd, timer: &OwnedFd, phase: &str) -> PidfdTimerRaceOutcome {
    let requested = PollFlags::IN | PollFlags::RDNORM;
    let mut descriptors = [
        PollFd::from_borrowed_fd(pidfd.as_fd(), requested),
        PollFd::new(timer, requested),
    ];
    let mut interruptions = 0;
    let ready_count = loop {
        match poll(&mut descriptors, None) {
            Ok(count) => break count,
            Err(error)
                if error == rustix::io::Errno::INTR
                    && interruptions + 1 < DEADLINE_POLL_INTERRUPT_LIMIT =>
            {
                interruptions += 1;
                for descriptor in &mut descriptors {
                    descriptor.clear_revents();
                }
            }
            Err(error) => panic!("{phase} poll failed: {error}"),
        }
    };
    assert_ne!(ready_count, 0, "{phase} poll returned no readiness");

    let pid_readiness = descriptors[0].revents();
    let timer_readiness = descriptors[1].revents();
    let pid_ready = validate_poll_readiness(
        "Guardian pidfd",
        pid_readiness,
        PollFlags::IN | PollFlags::RDNORM | PollFlags::HUP,
    );
    let timer_ready = validate_poll_readiness(
        &format!("{phase} timerfd"),
        timer_readiness,
        PollFlags::IN | PollFlags::RDNORM,
    );
    let observed_ready_count =
        usize::from(!pid_readiness.is_empty()) + usize::from(!timer_readiness.is_empty());
    assert_eq!(
        ready_count, observed_ready_count,
        "{phase} poll count did not match descriptor readiness"
    );

    match (pid_ready, timer_ready) {
        (true, false) => PidfdTimerRaceOutcome::PidfdOnly,
        (false, true) => PidfdTimerRaceOutcome::TimerOnly,
        (true, true) => PidfdTimerRaceOutcome::Simultaneous,
        (false, false) => panic!("{phase} poll returned no classified readiness"),
    }
}

fn validate_poll_readiness(object: &str, readiness: PollFlags, allowed: PollFlags) -> bool {
    assert!(
        !readiness.intersects(PollFlags::ERR | PollFlags::NVAL),
        "{object} reported invalid poll readiness: {readiness:?}"
    );
    assert!(
        readiness.difference(allowed).is_empty(),
        "{object} reported unexpected poll readiness: {readiness:?}"
    );
    readiness.intersects(allowed)
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
    let boottime_nanoseconds = current_boottime_nanoseconds();
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE).unwrap(),
        KernelBootId::current().unwrap().into_bytes(),
        wall.tv_sec,
        boottime_nanoseconds,
    )
    .unwrap()
}

fn current_boottime_nanoseconds() -> u64 {
    let boottime = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(boottime.tv_sec).unwrap();
    let nanoseconds = u64::try_from(boottime.tv_nsec).unwrap();
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
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
    live_guardian_request_with_lifetimes(
        fixture,
        request_id,
        sandbox_id,
        AUTHORITY_LIFETIME_SECONDS,
        REQUEST_LIFETIME_NANOSECONDS,
    )
}

fn live_guardian_request_with_lifetimes(
    fixture: &AuthorityFixture,
    request_id: u8,
    sandbox_id: u8,
    authority_lifetime_seconds: i64,
    request_lifetime_nanoseconds: u64,
) -> LiveGuardianRequest {
    let clock = current_clock();
    let issued_seconds = clock.wall_seconds().checked_sub(1).unwrap();
    let expires_seconds = clock
        .wall_seconds()
        .checked_add(authority_lifetime_seconds)
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
        ProtocolVersion::new(1, 0),
    ))
    .unwrap();
    base.header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = clock
        .boottime_nanoseconds()
        .checked_add(request_lifetime_nanoseconds)
        .unwrap();
    base.launch_plan.get_or_insert_default().uid_range_start = QUALIFICATION_UID_START;
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
        ProtocolVersion::new(1, 0),
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
        ProtocolVersion::new(1, 0),
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
        ProtocolVersion::new(1, 0),
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
