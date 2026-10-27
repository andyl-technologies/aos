//! Same-PID pure-worker ownership under a fixed source-built launcher.
//!
//! This owner supplies real process, cgroup, quota and bounded disk-file custody.
//! It does not authenticate an installation or create Source/accepted-bank
//! authority. Callers must choose measured immutable program/runtime paths and
//! keep logical job acceptance separate from this kernel cleanup receipt.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use rustix::time::{
    Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec, timerfd_create,
    timerfd_settime,
};
use thiserror::Error;

#[path = "linux_pure_worker/resources.rs"]
mod resources;
use resources::{Cgroup, Roots, Workspace};

#[path = "linux_pure_worker/program.rs"]
mod program;
pub use program::{LinuxPureWorkerProgram, LinuxPureWorkerProgramIdentity};

#[path = "linux_pure_worker/supervision.rs"]
mod supervision;
use supervision::{launch_loop, supervise};

#[path = "linux_pure_worker/buffers.rs"]
mod buffers;
pub use buffers::{LinuxPureWorkerBufferCapacityData, LinuxPureWorkerDirectBuffers};

/// Selects independently provisioned cgroup and disk-backed project-quota roots.
#[derive(Clone, Debug)]
pub struct LinuxPureWorkerConfiguration {
    /// Dedicated delegated cgroup-v2 directory with cpu/memory/pids enabled.
    pub cgroup_root: PathBuf,
    /// Empty supervisor-owned mode0700 ext4 project-quota directory.
    pub run_root: PathBuf,
    /// Exclusively operator-reserved project identifier for this single slot.
    pub project_id: u32,
    /// Dedicated non-root host UID, with no hostile same-UID peers.
    pub child_user_id: u32,
    /// Dedicated non-root host GID, distinct from the supervisor.
    pub child_group_id: u32,
}

/// Supplies admitted limits, not construction demand or an allocation grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxPureWorkerLimits {
    /// Hard cgroup memory ceiling covering the attached helper and worker.
    pub memory_bytes: u64,
    /// Hard worker address-space ceiling installed before its ELF loader.
    pub address_space_bytes: u64,
    /// Hard whole-process CPU seconds; process/thread creation is denied.
    pub cpu_seconds: u64,
    /// Hard worker descriptor ceiling, including loader temporary descriptors.
    pub descriptors: u64,
    /// Hard aggregate disk quota, installed before input export.
    pub disk_bytes: u64,
    /// Hard inode and cumulative cleanup-entry bound.
    pub inodes: u64,
    /// Maximum independently copied request bytes.
    pub input_bytes: u64,
    /// Worker parser element limit passed as a trusted operational argument.
    pub elements: u64,
    /// Worker aggregate canonical-bank limit.
    pub bank_bytes: u64,
    /// Worker closed diagnostic payload limit.
    pub diagnostic_bytes: u64,
    /// Independently bounded stdout bytes including framing, stored on disk.
    pub stdout_bytes: usize,
    /// Independently bounded stderr, in addition to aggregate disk quota.
    pub stderr_bytes: usize,
    /// Operational watchdog, never a simulation timestamp or reap deadline.
    pub wall_seconds: u64,
}

impl LinuxPureWorkerLimits {
    /// Checks the closed operational limits without reserving or launching work.
    ///
    /// # Errors
    /// Refuses zero, inconsistent or unrepresentable process/storage bounds.
    /// Validation is DATA-only and creates no admission or resource owner.
    pub fn validate(&self) -> Result<(), LinuxPureWorkerError> {
        if self.memory_bytes == 0
            || self.address_space_bytes == 0
            || self.cpu_seconds == 0
            || self.descriptors < 16
            || self.disk_bytes < 1024
            || self.inodes == 0
            || self.inodes > 65_536
            || self.input_bytes == 0
            || self.elements == 0
            || self.bank_bytes == 0
            || self.diagnostic_bytes == 0
            || self.stdout_bytes == 0
            || self.stderr_bytes == 0
            || self.wall_seconds == 0
            || self.wall_seconds > i64::MAX as u64
        {
            return Err(LinuxPureWorkerError::Configuration);
        }
        Ok(())
    }
}

/// Reports configuration/admission errors without creating any native authority.
#[derive(Debug, Error)]
pub enum LinuxPureWorkerError {
    /// A configuration cannot represent the selected closed profile.
    #[error("invalid pure-worker configuration")]
    Configuration,
    /// The single physical slot remains owned by a live or quarantined attempt.
    #[error("pure-worker cleanup slot is busy")]
    Busy,
    /// Input export or launch was requested in the wrong irreversible phase.
    #[error("pure-worker phase refuses the operation")]
    Phase,
    /// Export exceeded its admitted actual byte extent.
    #[error("pure-worker input exceeds its admitted limit")]
    InputLimit,
    /// Required Linux controls or the supervisor wait policy are unavailable.
    #[error("pure-worker host controls are unavailable")]
    HostControlsUnavailable,
    /// A native filesystem/process setup operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A real ext4 quota transaction failed with partial ownership retained.
    #[error(transparent)]
    ProjectQuota(#[from] aos_linux_project_quota::LinuxProjectQuotaError),
}

/// Identifies a sticky operational failure of the same physical attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxPureWorkerFailure {
    /// Setup or trusted helper execution failed.
    Setup,
    /// Caller irreversibly cancelled acceptance.
    Cancelled,
    /// Independent request export failed or exceeded its admitted extent.
    InputExport,
    /// Kernel operational timer expired.
    Timeout,
    /// Stdout exceeded its independent retained-byte limit.
    StdoutLimit,
    /// Stderr exceeded its independent byte limit.
    StderrLimit,
    /// Bounded output storage could not reserve actual received bytes.
    OutputAllocation,
    /// A stream operation failed.
    OutputIo,
    /// The child returned nonzero or died from a signal/resource exhaustion.
    ChildExit,
    /// An owned wait operation failed without proving reap.
    Wait,
    /// An opened installation guard was revoked or replaced.
    ProgramChanged,
}

/// Retains actual bounded output after waited reap and durable resource cleanup.
#[derive(Debug)]
pub struct LinuxPureWorkerOutcome {
    /// PID returned by the original successful std spawn, for diagnostics only.
    pub child_id: Option<u32>,
    /// Actual same-cgroup memory.events oom_kill increase, absent before configuration.
    pub memory_oom_kills: Option<u64>,
    /// Actual direct-child wait status, absent only when spawn itself failed.
    pub status: Option<ExitStatus>,
    /// Bounded complete or partial stdout, never treated as accepted banks here.
    pub stdout: Vec<u8>,
    /// Bounded complete or partial diagnostics.
    pub stderr: Vec<u8>,
    /// Original sticky operational failure, never overwritten by cleanup retries.
    pub failure: Option<LinuxPureWorkerFailure>,
}

/// Owns one independently admitted single-slot namespace.
pub struct LinuxPureWorkerFactory {
    roots: Arc<Roots>,
    program: LinuxPureWorkerProgram,
    busy: Arc<AtomicBool>,
}

impl LinuxPureWorkerFactory {
    /// Returns this implementation's fixed closed CLI/control profile DATA.
    pub fn profile_id(&self) -> &'static str {
        "pure-worker-v1"
    }

    /// Copies the actual configured host UID and GID enforced by this factory.
    pub fn child_credentials(&self) -> (u32, u32) {
        (
            self.roots.configuration.child_user_id,
            self.roots.configuration.child_group_id,
        )
    }

    /// Returns the actual opened installation bound to this factory.
    pub fn program_identity(&self) -> LinuxPureWorkerProgramIdentity {
        self.program.identity()
    }

    /// Authenticates and locks actual delegated roots without launching a child.
    ///
    /// # Errors
    /// Refuses unavailable controllers/quotas, dirty or nonprivate roots,
    /// incompatible wait policy, unsafe program paths or another root owner.
    /// The configured UID/GID must be operator-dedicated to this supervisor;
    /// hostile same-UID peers and administrator mutation are outside the profile.
    /// This profile uses Landlock/seccomp, not a user or PID namespace.
    pub fn open(
        configuration: LinuxPureWorkerConfiguration,
        program: LinuxPureWorkerProgram,
    ) -> Result<Self, LinuxPureWorkerError> {
        check_wait_policy()?;
        program.verify_current()?;
        let roots = Arc::new(Roots::open(configuration)?);
        Ok(Self {
            roots,
            program,
            busy: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Reserves both supervisor workers before quota/export/spawn effects.
    ///
    /// # Errors
    /// Refuses invalid limits, a busy slot, timer allocation or supervisor-thread
    /// startup. No quota or child exists before both threads accept ownership.
    pub fn reserve(
        &self,
        limits: LinuxPureWorkerLimits,
    ) -> Result<LinuxPureWorkerAttempt, LinuxPureWorkerError> {
        limits.validate()?;
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(LinuxPureWorkerError::Busy);
        }
        let timer = match timerfd_create(
            TimerfdClockId::Monotonic,
            TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
        ) {
            Ok(fd) => File::from(fd),
            Err(error) => {
                self.busy.store(false, Ordering::Release);
                return Err(io::Error::from(error).into());
            }
        };
        let shared = Arc::new(Shared {
            identity: Arc::new(AttemptIdentity),
            state: Mutex::new(State::new(
                self.roots.clone(),
                self.program.clone(),
                limits,
                timer,
            )),
            changed: Condvar::new(),
            busy: self.busy.clone(),
        });
        let launcher = shared.clone();
        if let Err(error) = thread::Builder::new()
            .name("pure-worker-launch".into())
            .spawn(move || launch_loop(launcher))
        {
            self.busy.store(false, Ordering::Release);
            return Err(error.into());
        }
        let cleanup = shared.clone();
        if let Err(error) = thread::Builder::new()
            .name("pure-worker-supervisor".into())
            .spawn(move || supervise(cleanup))
        {
            let mut state = lock(&shared);
            state.cancelled = true;
            state.launch_closed = true;
            shared.changed.notify_all();
            self.busy.store(false, Ordering::Release);
            return Err(error.into());
        }
        Ok(LinuxPureWorkerAttempt { shared })
    }
}

#[derive(Debug)]
struct AttemptIdentity;

/// Identifies one original reserved attempt without issuing admission authority.
#[derive(Clone, Debug)]
pub struct LinuxPureWorkerAttemptIdentity(Arc<AttemptIdentity>);

impl PartialEq for LinuxPureWorkerAttemptIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for LinuxPureWorkerAttemptIdentity {}

/// Seals actual same-attempt wait, empty-group and cleanup completion.
///
/// This token cannot be cloned or deserialized. It carries bounded DATA but
/// never validates its schema or grants Source/native permission by itself.
pub struct LinuxPureWorkerCompletion {
    shared: Arc<Shared>,
    outcome: LinuxPureWorkerOutcome,
}

impl LinuxPureWorkerCompletion {
    /// Checks original attempt/program instances and permanent cancellation.
    ///
    /// # Errors
    /// Refuses a foreign identity, cancelled result or revoked opened program.
    pub fn verify_original(
        &self,
        attempt: &LinuxPureWorkerAttemptIdentity,
        program: &LinuxPureWorkerProgramIdentity,
    ) -> Result<(), LinuxPureWorkerError> {
        let state = lock(&self.shared);
        if !Arc::ptr_eq(&self.shared.identity, &attempt.0)
            || !state.program.same_identity(program)
            || !state.released
            || state.cancelled
            || state.failure.is_some()
        {
            return Err(LinuxPureWorkerError::Phase);
        }
        state.program.verify_current()
    }

    /// Borrows actual inert output while retaining the nonforgeable receipt.
    pub fn outcome(&self) -> &LinuxPureWorkerOutcome {
        &self.outcome
    }

    /// Consumes this receipt and moves the same actual inert buffers to its caller.
    pub fn into_outcome(self) -> LinuxPureWorkerOutcome {
        self.outcome
    }
}

/// Retains the same attempt through export, cancellation and cleanup.
///
/// Its [`Write`] implementation exports only to this attempt's quota-owned
/// independent input. It refuses writes before preparation or after sealing,
/// cancellation or launch; a write failure permanently revokes acceptance.
pub struct LinuxPureWorkerAttempt {
    shared: Arc<Shared>,
}

impl LinuxPureWorkerAttempt {
    /// Returns the fixed closed CLI/control profile selected for this attempt.
    pub fn profile_id(&self) -> &'static str {
        "pure-worker-v1"
    }

    /// Copies the actual configured host UID and GID bound to this attempt.
    pub fn child_credentials(&self) -> (u32, u32) {
        let state = lock(&self.shared);
        (
            state.roots.configuration.child_user_id,
            state.roots.configuration.child_group_id,
        )
    }

    /// Returns this reserved occurrence's opaque identity before Source binding.
    pub fn identity(&self) -> LinuxPureWorkerAttemptIdentity {
        LinuxPureWorkerAttemptIdentity(self.shared.identity.clone())
    }

    /// Returns the actual std-spawned PID for diagnostics, never wait authority.
    pub fn child_id(&self) -> Option<u32> {
        lock(&self.shared).child_id
    }

    /// Copies the immutable worker identity claim bound to this attempt.
    pub fn worker_digest(&self) -> [u8; 32] {
        lock(&self.shared).program.worker_digest()
    }

    /// Copies the immutable algorithm identity claim bound to this attempt.
    pub fn algorithm_digest(&self) -> [u8; 32] {
        lock(&self.shared).program.algorithm_digest()
    }

    /// Copies the actual immutable admitted limits bound to this attempt.
    pub fn limits(&self) -> LinuxPureWorkerLimits {
        lock(&self.shared).limits
    }

    /// Returns the same opened program instance bound to this attempt.
    pub fn program_identity(&self) -> LinuxPureWorkerProgramIdentity {
        lock(&self.shared).program.identity()
    }

    /// Takes a sealed success receipt only after wait, empty group and cleanup.
    ///
    /// # Errors
    /// Refuses cancellation, unsuccessful exit, revoked program or repeated transfer.
    /// Returns None while physical cleanup remains active or quarantined.
    pub fn take_completion(
        &mut self,
    ) -> Result<Option<LinuxPureWorkerCompletion>, LinuxPureWorkerError> {
        let mut state = lock(&self.shared);
        if !state.released {
            return Ok(None);
        }
        if state.taken
            || state.cancelled
            || state.failure.is_some()
            || !state.status.is_some_and(|s| s.success())
        {
            return Err(LinuxPureWorkerError::Phase);
        }
        if let Err(error) = state.program.verify_current() {
            state.fail(LinuxPureWorkerFailure::ProgramChanged);
            return Err(error);
        }
        state.taken = true;
        let outcome = LinuxPureWorkerOutcome {
            child_id: state.child_id,
            memory_oom_kills: state.memory_oom_kills,
            status: state.status.take(),
            stdout: std::mem::take(&mut state.stdout),
            stderr: std::mem::take(&mut state.stderr),
            failure: None,
        };
        Ok(Some(LinuxPureWorkerCompletion {
            shared: self.shared.clone(),
            outcome,
        }))
    }

    /// Installs actual quota before returning permission to export input bytes.
    ///
    /// # Errors
    /// Refuses phase, directory or quota setup failures; all created partial
    /// owners remain in the pre-reserved supervisor on error or caller drop.
    pub fn prepare_input(&mut self) -> Result<(), LinuxPureWorkerError> {
        let mut state = lock(&self.shared);
        if state.workspace.is_some() || state.cancelled {
            return Err(LinuxPureWorkerError::Phase);
        }
        let result = (|| {
            let roots = state.roots.clone();
            let limits = state.limits;
            roots.create_workspace(&mut state.workspace)?;
            let workspace = state
                .workspace
                .as_mut()
                .ok_or(LinuxPureWorkerError::Phase)?;
            workspace.install_quota(limits)?;
            let input = workspace.create_input()?;
            state.input = Some(input);
            Ok(())
        })();
        if result.is_err() {
            state.fail(LinuxPureWorkerFailure::Setup);
            self.shared.changed.notify_all();
        }
        result
    }

    /// Writes actual independent input within the original admitted byte limit.
    ///
    /// # Errors
    /// Refuses excessive extent, a sealed/started/cancelled phase or filesystem
    /// failure. The first typed cause remains available through
    /// [`Self::take_input_error`]; the I/O indication uses only `ErrorKind`.
    /// Partial written input stays quota-owned for cleanup.
    pub fn write_input(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut state = lock(&self.shared);
        let result = (|| {
            if state.started || state.cancelled || state.sealed {
                return Err(LinuxPureWorkerError::Phase);
            }
            let next = state
                .input_count
                .checked_add(bytes.len() as u64)
                .ok_or(LinuxPureWorkerError::InputLimit)?;
            if next > state.limits.input_bytes {
                return Err(LinuxPureWorkerError::InputLimit);
            }
            state
                .input
                .as_mut()
                .ok_or(LinuxPureWorkerError::Phase)?
                .write_all(bytes)?;
            state.input_count = next;
            Ok(())
        })();
        if let Err(error) = result {
            let indication = retain_input_error(&mut state, error);
            self.shared.changed.notify_all();
            return Err(indication);
        }
        Ok(())
    }

    /// Moves the first actual export cause without reviving input or acceptance.
    ///
    /// The `Write` indication contains only an `ErrorKind`; the complete typed
    /// cause stays in this attempt until explicitly transferred by this method.
    /// Partial input remains owned by the same quota and cleanup supervisor.
    pub fn take_input_error(&mut self) -> Option<LinuxPureWorkerError> {
        lock(&self.shared).input_error.take()
    }

    /// Seals the copied file and starts the fixed installed helper/worker pair.
    ///
    /// # Errors
    /// Refuses phase, changed input extent, cgroup/timer or descriptor setup.
    /// The caller still owns this attempt and every partial cleanup authority.
    pub fn start(&mut self) -> Result<(), LinuxPureWorkerError> {
        let mut state = lock(&self.shared);
        if state.started || state.cancelled || state.input_count == 0 {
            return Err(LinuxPureWorkerError::Phase);
        }
        let result = (|| {
            state
                .input
                .take()
                .ok_or(LinuxPureWorkerError::Phase)?
                .sync_all()?;
            let workspace = state
                .workspace
                .as_ref()
                .ok_or(LinuxPureWorkerError::Phase)?;
            let input = workspace.open_readonly_input(state.input_count)?;
            state.out = Some(workspace.create_output("stdout")?);
            let workspace = state
                .workspace
                .as_ref()
                .ok_or(LinuxPureWorkerError::Phase)?;
            state.err = Some(workspace.create_output("stderr")?);
            state.sealed = true;
            let roots = state.roots.clone();
            let limits = state.limits;
            roots.create_group(&mut state.group)?;
            state
                .group
                .as_mut()
                .ok_or(LinuxPureWorkerError::Phase)?
                .configure(limits)?;
            let mut command = state.command()?;
            command
                .stdin(Stdio::from(input))
                .stdout(Stdio::from(
                    state
                        .out
                        .as_ref()
                        .ok_or(LinuxPureWorkerError::Phase)?
                        .try_clone()?,
                ))
                .stderr(Stdio::from(
                    state
                        .err
                        .as_ref()
                        .ok_or(LinuxPureWorkerError::Phase)?
                        .try_clone()?,
                ));
            timerfd_settime(
                &state.timer,
                TimerfdTimerFlags::empty(),
                &Itimerspec {
                    it_interval: Timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    it_value: Timespec {
                        tv_sec: limits.wall_seconds as i64,
                        tv_nsec: 0,
                    },
                },
            )
            .map_err(io::Error::from)?;
            state.command = Some(command);
            state.started = true;
            self.shared.changed.notify_all();
            Ok(())
        })();
        if result.is_err() {
            state.fail(LinuxPureWorkerFailure::Setup);
            self.shared.changed.notify_all();
        }
        result
    }

    /// Irreversibly revokes success acceptance while physical cleanup continues.
    pub fn cancel(&self) {
        let mut state = lock(&self.shared);
        state.cancelled = true;
        state.fail(LinuxPureWorkerFailure::Cancelled);
        self.shared.changed.notify_all();
    }

    /// Takes bounded inert output only after real wait, empty group and cleanup.
    ///
    /// # Errors
    /// Refuses a repeated outcome transfer. Returns None while the exact slot
    /// remains active or quarantined; it never fabricates a cleanup deadline.
    pub fn take_outcome(&mut self) -> Result<Option<LinuxPureWorkerOutcome>, LinuxPureWorkerError> {
        let mut state = lock(&self.shared);
        if !state.released {
            return Ok(None);
        }
        if state.taken {
            return Err(LinuxPureWorkerError::Phase);
        }
        state.taken = true;
        Ok(Some(LinuxPureWorkerOutcome {
            child_id: state.child_id,
            memory_oom_kills: state.memory_oom_kills,
            status: state.status.take(),
            stdout: std::mem::take(&mut state.stdout),
            stderr: std::mem::take(&mut state.stderr),
            failure: state.failure,
        }))
    }
}

impl Write for LinuxPureWorkerAttempt {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_input(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = lock(&self.shared);
        let result = (|| {
            if state.started || state.cancelled || state.sealed {
                return Err(LinuxPureWorkerError::Phase);
            }
            state
                .input
                .as_mut()
                .ok_or(LinuxPureWorkerError::Phase)?
                .flush()?;
            Ok(())
        })();
        if let Err(error) = result {
            let indication = retain_input_error(&mut state, error);
            self.shared.changed.notify_all();
            return Err(indication);
        }
        Ok(())
    }
}

impl Drop for LinuxPureWorkerAttempt {
    fn drop(&mut self) {
        let mut state = lock(&self.shared);
        if !state.released {
            state.cancelled = true;
            state.fail(LinuxPureWorkerFailure::Cancelled);
            self.shared.changed.notify_all();
        }
    }
}

struct Shared {
    identity: Arc<AttemptIdentity>,
    state: Mutex<State>,
    changed: Condvar,
    busy: Arc<AtomicBool>,
}
struct State {
    roots: Arc<Roots>,
    program: LinuxPureWorkerProgram,
    limits: LinuxPureWorkerLimits,
    workspace: Option<Workspace>,
    group: Option<Cgroup>,
    input: Option<File>,
    input_count: u64,
    input_error: Option<LinuxPureWorkerError>,
    sealed: bool,
    started: bool,
    launch_closed: bool,
    launch_in_flight: bool,
    command: Option<Command>,
    child: Option<Child>,
    child_id: Option<u32>,
    memory_oom_kills: Option<u64>,
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    out: Option<File>,
    err: Option<File>,
    outputs_collected: bool,
    timer: File,
    cancelled: bool,
    failure: Option<LinuxPureWorkerFailure>,
    released: bool,
    taken: bool,
}

impl State {
    fn new(
        roots: Arc<Roots>,
        program: LinuxPureWorkerProgram,
        limits: LinuxPureWorkerLimits,
        timer: File,
    ) -> Self {
        Self {
            roots,
            program,
            limits,
            workspace: None,
            group: None,
            input: None,
            input_count: 0,
            input_error: None,
            sealed: false,
            started: false,
            launch_closed: false,
            launch_in_flight: false,
            command: None,
            child: None,
            child_id: None,
            memory_oom_kills: None,
            status: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            out: None,
            err: None,
            outputs_collected: false,
            timer,
            cancelled: false,
            failure: None,
            released: false,
            taken: false,
        }
    }
    fn fail(&mut self, failure: LinuxPureWorkerFailure) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
        self.cancelled = true;
    }
    fn command(&self) -> Result<Command, LinuxPureWorkerError> {
        let group = self.group.as_ref().ok_or(LinuxPureWorkerError::Phase)?;
        let (device, inode) = group.identity()?;
        let config = &self.roots.configuration;
        let mut command = self.program.command()?;
        command.env_clear();
        command
            .arg("--pure-worker-v1")
            .arg(&group.path)
            .args(
                [
                    device,
                    inode,
                    u64::from(config.child_user_id),
                    u64::from(config.child_group_id),
                    self.limits.cpu_seconds,
                    self.limits.memory_bytes,
                    self.limits.address_space_bytes,
                    self.limits.descriptors,
                    self.limits.stdout_bytes.max(self.limits.stderr_bytes) as u64,
                ]
                .map(|v| v.to_string()),
            )
            .arg(self.program.worker_path())
            .args(
                [
                    self.program.worker_device()?.0,
                    self.program.worker_device()?.1,
                ]
                .map(|v| v.to_string()),
            )
            .args(
                [
                    self.limits.input_bytes,
                    self.limits.elements,
                    self.limits.bank_bytes,
                    self.limits.diagnostic_bytes,
                ]
                .map(|v| v.to_string()),
            )
            .arg(hex_digest(self.program.worker_digest()))
            .arg(hex_digest(self.program.algorithm_digest()))
            .arg("--")
            .args(self.program.runtime_roots());
        Ok(command)
    }
}

fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 15)]));
    }
    text
}

fn retain_input_error(state: &mut State, error: LinuxPureWorkerError) -> io::Error {
    let kind = match &error {
        LinuxPureWorkerError::Io(cause) => cause.kind(),
        LinuxPureWorkerError::InputLimit => io::ErrorKind::InvalidData,
        LinuxPureWorkerError::Phase => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    if state.input_error.is_none() {
        state.input_error = Some(error);
    }
    state.fail(LinuxPureWorkerFailure::InputExport);
    io::Error::from(kind)
}

fn lock(shared: &Shared) -> MutexGuard<'_, State> {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn check_wait_policy() -> Result<(), LinuxPureWorkerError> {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: this read-only query supplies writable storage for one sigaction,
    // installs no handler, and uses a null new-action pointer. No signal-global
    // state is changed; successful return initializes the entire old action.
    let result = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the successful query above initialized this concrete C structure.
    let action = unsafe { action.assume_init() };
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(LinuxPureWorkerError::HostControlsUnavailable);
    }
    Ok(())
}

#[cfg(test)]
#[path = "linux_pure_worker/tests.rs"]
mod tests;
