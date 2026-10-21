//! Bounded execution of one fixed executable in a fresh process group.
//!
//! This primitive supplies exact `posix_spawn(3)` argv, an empty environment,
//! `/dev/null` standard input, descriptor closure above standard error,
//! concurrent bounded output capture, and one monotonic deadline. The fresh
//! process group makes prompt cooperative cleanup possible, but is not a
//! process-tree containment boundary: callers that require that guarantee must
//! run the entire caller and child lifetime in a separately enforced cgroup.

use std::ffi::{CString, OsString};
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};
use std::time::Duration;

use aos_linux_descriptors::pidfd::PidFd;
use crate::uapi;
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;

mod child_lifetime;
mod guest_ssh;
pub(crate) use guest_ssh::GuestSshProcessOriginalV1;
pub use child_lifetime::{ExecutionChildLifetimeOriginalV1, ExecutionChildLifetimeClosedV1,
    require_child_lifetime_data_v1};

mod run_original;
pub(crate) use run_original::task_directory_representation_bytes_v3;
pub use run_original::{
    FixedProcessRunOriginalV3, FixedProcessRunRefusalV3,
    run_fixed_descriptor_process_retaining_v4,
    run_fixed_descriptor_process_observing_network_fork_retaining_v4,
    run_fixed_process_retaining_v3, run_fixed_process_observing_storage_fork_retaining_v3, run_fixed_capture_process_retaining_v3,
};

mod spawn_original;
pub use spawn_original::FixedProcessSpawnFailureV2;

mod storage_fork;
pub use storage_fork::{NetworkWorkerForkObservationV4, StorageWorkerForkObservationV1};
use storage_fork::WorkerForkObservationBorrowV4;

mod worker_inherited_limit;
pub use worker_inherited_limit::{
    StorageWorkerInheritedLimitOriginalV1, StorageWorkerInheritedLimitRefusalV1,
};

mod capture;
mod session;
pub use capture::{
    FixedProcessCaptureObservationV1, FixedProcessCapturePartsV1, FixedProcessCaptureV1,
    FixedProcessCapturedStreamV1, FixedProcessDispatchV1, FixedProcessRetainedSessionError,
    FixedProcessRetainedSessionOutcome, FixedProcessStopV1,
};

pub use session::{
    ExchangeStep, FixedLiveChild, FixedProcessControlInterest, FixedProcessControlReadiness,
    FixedProcessSessionError, FixedProcessSessionExchange, FixedProcessSessionOutcome,
    FixedProcessSessionRequest, run_fixed_process_session,
    FixedNixOfflineSessionOwnerV1,
    run_fixed_process_session_retained_v1,
    run_fixed_process_session_from_executable_descriptor,
    run_fixed_process_session_from_executable_descriptor_retained_v1,
    run_fixed_process_session_from_nix_offline_executable_descriptor_retained_v1,
    FixedProcessBoottimeCutV1, FixedProcessDrivenCauseV1, FixedProcessDrivenDebtV1,
    FixedProcessDrivenInputsV1, FixedProcessDrivenPartsV1, FixedProcessDrivenProgressV1, FixedProcessDrivenSessionV1,
    FixedProcessDrivingLoanV1, FixedProcessPreparedInvocationV1, FixedProcessWaitViewV1,
    prepare_fixed_process_driven_invocation_v1,
};

pub(crate) mod capture_cut;
pub use capture_cut::FixedProcessCaptureCutV3;

const MAXIMUM_EXECUTABLE_BYTES: usize = 4096;
const MAXIMUM_ARGUMENTS: usize = 64;
const MAXIMUM_ARGUMENT_BYTES: usize = 64 * 1024;
const DUPLICATE_FD_MINIMUM: libc::c_int = 64;
pub(crate) const MAXIMUM_INHERITED_DESCRIPTORS: usize = 4;

/// Permanently disables core dumps for the calling process.
///
/// Privileged short-lived workers call this before accepting retained
/// descriptors or crossing namespace boundaries. The setting is process-wide
/// and intentionally has no restoration operation.
///
/// # Errors
///
/// Returns an error if Linux cannot disable or verify process dumpability.
pub fn disable_core_dumps() -> Result<()> {
    uapi::disable_process_dumpability()
}

/// Observes the calling process's current native descriptor limits.
///
/// This read-only observation grants no worker role or resource authority.
///
/// # Errors
///
/// Returns the actual native error if Linux refuses the fixed limit query.
pub fn observe_nofile_limit_v1() -> Result<rustix::process::Rlimit> {
    uapi::observe_nofile_limit_v1()
}

/// Configures one exact, bounded child invocation.
#[derive(Clone, Copy, Debug)]
pub struct FixedProcessRequest<'a> {
    /// Absolute executable path used without `PATH` lookup.
    pub executable: &'a Path,
    /// Exact argument sequence after `argv[0]`.
    pub arguments: &'a [OsString],
    /// Monotonic budget before cancellation begins while awaiting exit and output closure.
    pub timeout: Duration,
    /// Maximum captured standard-output bytes.
    pub maximum_stdout_bytes: usize,
    /// Maximum captured standard-error bytes.
    pub maximum_stderr_bytes: usize,
}

/// Adds explicit standard input and bounded descriptor roles to one invocation.
#[derive(Clone, Copy, Debug)]
pub struct FixedProcessDescriptorRequest<'a> {
    /// Common fixed executable, argument, deadline, and output policy.
    pub process: FixedProcessRequest<'a>,
    /// Optional standard input; `/dev/null` is used when absent.
    ///
    /// The caller owns this descriptor's producer and content. This API does
    /// not impose an input byte limit; the overall child supervision timeout
    /// bounds how long the child may wait or read before cancellation begins.
    pub stdin: Option<BorrowedFd<'a>>,
    /// Descriptors mapped contiguously to child FDs 3 through 6.
    pub inherited: &'a [BorrowedFd<'a>],
}

/// Reports the normally completed fixed child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedProcessOutput {
    /// Normal exit code, or `None` when a signal terminated the leader.
    pub exit_code: Option<i32>,
    /// Terminating signal, or `None` after a normal exit.
    pub signal: Option<i32>,
    /// Complete bounded standard output.
    pub stdout: Vec<u8>,
    /// Complete bounded standard error.
    pub stderr: Vec<u8>,
}

/// Classifies completion or fail-stop cancellation of a fixed invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixedProcessOutcome {
    /// The leader exited and both output streams reached end-of-file in time.
    Completed(FixedProcessOutput),
    /// The budget elapsed; the process group was killed and the leader was reaped.
    TimedOut,
    /// A stream crossed its configured byte ceiling; the group was killed.
    OutputLimitExceeded,
}

/// Runs one executable with a closed environment and bounded output.
///
/// The child is placed in a new process group before `execve`. Cancellation
/// signals that group and reaps its leader. A process can leave a process group,
/// so a privileged caller must additionally provide cgroup containment when
/// descendants must remain bounded after caller failure.
///
/// The calling process must have exactly one thread and retain the default
/// `SIGCHLD` disposition without `SA_NOCLDWAIT`. The function checks both
/// conditions before spawning. Exclusive reaping keeps the unreaped leader's
/// numeric PID and process-group ID unavailable for reuse throughout cleanup.
/// Cancellation starts when the monotonic budget expires, but a subsequent
/// blocking reap can finish later if the kernel has not made the leader
/// waitable yet. Callers must not treat the budget as a strict whole-call
/// wall-clock bound.
///
/// # Errors
///
/// Returns an error unless the caller exclusively owns child reaping as an
/// exactly single-threaded process with default `SIGCHLD` behavior. Also
/// returns an error for invalid path/argv/limits, pipe or descriptor setup,
/// `posix_spawn` (including its preserved `execve` errno), output I/O, signal,
/// or wait failures.
pub fn run_fixed_process(request: FixedProcessRequest<'_>) -> Result<FixedProcessOutcome> {
    validate_exclusive_reaping_owner()?;
    run_fixed_process_owned(request, None, &[])
}

/// Runs one fixed executable with explicit standard input and bounded roles.
///
/// `inherited[0]` appears only as child FD 3, `inherited[1]` as FD 4, and so
/// on. All descriptors above the final mapped role are closed in the child.
/// The same single-thread, child-reaping, timeout, output, and process-group
/// guarantees as [`run_fixed_process`] apply.
///
/// # Errors
///
/// Returns an error under the conditions documented by [`run_fixed_process`],
/// or when more than four inherited descriptor roles are requested.
pub fn run_fixed_process_with_descriptors(
    request: FixedProcessDescriptorRequest<'_>,
) -> Result<FixedProcessOutcome> {
    if request.inherited.len() > MAXIMUM_INHERITED_DESCRIPTORS {
        return Err(Error::invalid(
            "fixed process inherited descriptors",
            "exceeds the four-descriptor ceiling",
        ));
    }
    validate_exclusive_reaping_owner()?;
    run_fixed_process_owned(request.process, request.stdin, request.inherited)
}

fn run_fixed_process_owned(
    request: FixedProcessRequest<'_>,
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
) -> Result<FixedProcessOutcome> {
    let invocation = PreparedInvocation::new(request)?;
    let spawned = invocation.spawn(stdin, inherited)?;
    supervise(spawned, request)
}

fn validate_exclusive_reaping_owner() -> Result<()> {
    let mut original = run_original::ReapingOriginalV3::new();
    validate_exclusive_reaping_owner_into(&mut original)
}

fn validate_exclusive_reaping_owner_into(
    original: &mut run_original::ReapingOriginalV3,
) -> Result<()> {
    uapi::validate_child_reaping_disposition()?;

    original.tasks = Some(std::fs::read_dir("/proc/self/task").map_err(|source| Error::Syscall {
        operation: "open process task directory",
        source,
    })?);
    let tasks = original.tasks.as_mut().ok_or_else(|| Error::invalid(
        "fixed process task directory", "capture is absent",
    ))?;
    original.first = tasks.next().transpose().map_err(|source| Error::Syscall {
        operation: "read process task directory",
        source,
    })?;
    original.second = tasks.next().transpose().map_err(|source| Error::Syscall {
        operation: "read process task directory",
        source,
    })?;
    if original.first.is_none() || original.second.is_some() {
        return Err(Error::invalid(
            "fixed process reaping ownership",
            "requires an exactly single-threaded calling process",
        ));
    }
    Ok(())
}

struct PreparedInvocation {
    executable: CString,
    argument_zero: CString,
    arguments: Vec<CString>,
}

#[derive(Clone, Copy)]
enum SpawnExecution<'a> {
    Path,
    Descriptor(BorrowedFd<'a>),
    PendingDescriptor(
        BorrowedFd<'a>,
        uapi::FixedDescriptorExecRecipeV1,
        Option<FixedProcessBoottimeCutV1>,
    ),
}

impl PreparedInvocation {
    fn new(request: FixedProcessRequest<'_>) -> Result<Self> {
        validate_request(request)?;
        let executable = CString::new(request.executable.as_os_str().as_bytes())
            .map_err(|_| Error::invalid("fixed process executable", "must not contain NUL"))?;
        let argument_zero = CString::new(request.executable.as_os_str().as_bytes())
            .map_err(|_| Error::invalid("fixed process argument zero", "must not contain NUL"))?;
        let arguments = request
            .arguments
            .iter()
            .map(|argument| {
                CString::new(argument.as_os_str().as_bytes())
                    .map_err(|_| Error::invalid("fixed process argument", "must not contain NUL"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            executable,
            argument_zero,
            arguments,
        })
    }

    fn spawn(
        &self,
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<SpawnedProcess> {
        self.spawn_internal(stdin, inherited, SpawnExecution::Path, None)
    }

    fn spawn_from_executable_descriptor(
        &self,
        executable: BorrowedFd<'_>,
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<SpawnedProcess> {
        self.spawn_internal(stdin, inherited, SpawnExecution::Descriptor(executable), None)
    }

    fn begin_from_executable_descriptor(
        &self,
        executable: BorrowedFd<'_>,
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<SpawnedProcess> {
        self.spawn_internal(
            stdin,
            inherited,
            SpawnExecution::PendingDescriptor(
                executable,
                uapi::FixedDescriptorExecRecipeV1::LockedNorootV1,
                None,
            ),
            None,
        )
    }

    fn begin_from_executable_descriptor_at_cut(
        &self,
        executable: BorrowedFd<'_>,
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
        cut: FixedProcessBoottimeCutV1,
    ) -> Result<SpawnedProcess> {
        self.spawn_internal(
            stdin,
            inherited,
            SpawnExecution::PendingDescriptor(
                executable, uapi::FixedDescriptorExecRecipeV1::LockedNorootV1, Some(cut),
            ),
            None,
        )
    }

    fn begin_from_nix_offline_executable_descriptor(
        &self,
        executable: BorrowedFd<'_>,
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<SpawnedProcess> {
        self.spawn_internal(
            stdin,
            inherited,
            SpawnExecution::PendingDescriptor(
                executable,
                uapi::FixedDescriptorExecRecipeV1::NixOfflineNnpV1,
                None,
            ),
            None,
        )
    }

    fn spawn_internal(
        &self,
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
        execution: SpawnExecution<'_>,
        storage_observation: Option<&mut StorageWorkerForkObservationV1>,
    ) -> Result<SpawnedProcess> {
        let mut original = spawn_original::FixedProcessSpawnFailureV2::new();
        match spawn_original::spawn_into_original_v2(
            self, stdin, inherited, execution, storage_observation, &mut original,
        ) {
            Ok(spawned) => Ok(spawned),
            Err(()) => Err(original.into_ordinary_error()),
        }
    }
}

struct SpawnedProcess {
    guard: ChildGuard,
    stdout: OwnedFd,
    stderr: OwnedFd,
    exec_status: Option<uapi::FixedExecStatusReader>,
}

struct OutputStream {
    descriptor: OwnedFd,
    bytes: Vec<u8>,
    maximum: usize,
    closed: bool,
}

const FIXED_OUTPUT_CHUNK_BYTES_V3: usize = 8192;

impl OutputStream {
    fn new(descriptor: OwnedFd, maximum: usize) -> Result<Self> {
        Self::new_retaining(descriptor, maximum, None)
    }

    fn new_retaining(
        descriptor: OwnedFd,
        maximum: usize,
        retained: Option<&mut Option<OwnedFd>>,
    ) -> Result<Self> {
        if let Err(error) = set_nonblocking(&descriptor) {
            if let Some(retained) = retained {
                *retained = Some(descriptor);
            }
            return Err(error);
        }
        Ok(Self {
            descriptor,
            bytes: Vec::with_capacity(maximum.min(8192)),
            maximum,
            closed: false,
        })
    }

    fn drain(&mut self) -> Result<bool> {
        self.drain_retaining(None)
    }

    fn drain_retaining(
        &mut self,
        mut rejected: Option<&mut Option<([u8; 8192], usize)>>,
    ) -> Result<bool> {
        self.drain_capture_retaining_v3(rejected, None)
    }

    fn drain_capture_retaining_v3(
        &mut self,
        mut rejected: Option<&mut Option<([u8; 8192], usize)>>,
        mut capture: Option<(FixedProcessCaptureCutV3, &mut capture_cut::CaptureProcessCutOriginalV3)>,
    ) -> Result<bool> {
        let mut chunk = [0_u8; FIXED_OUTPUT_CHUNK_BYTES_V3];
        loop {
            if let Some((cut, original)) = capture.as_mut() { original.observe(*cut)?; }
            let native = rustix::io::read(&self.descriptor, &mut chunk);
            if let Some((_, original)) = capture.as_mut() { original.retain_read_v3(native); }
            let after = match capture.as_mut() {
                Some((cut, original)) => original.observe(*cut).map(|_| ()),
                None => Ok(()),
            };
            if after.is_err() {
                match native {
                    Ok(count) => {
                        // Retain the actual positive prefix before selecting
                        // the failed after sample, including a zero-byte EOF.
                        if let Some(rejected) = rejected.as_deref_mut() {
                            *rejected = Some((chunk, count));
                        }
                        return Err(capture_cut::marker());
                    }
                    Err(error) if capture_cut::read_errno_is_primary_v3(error) =>
                        return Err(kernel_error("read fixed process output", error)),
                    Err(_) => return Err(capture_cut::marker()),
                }
            }
            match native {
                Ok(0) => {
                    self.closed = true;
                    return Ok(false);
                }
                Ok(count) => {
                    let exceeds = self
                        .bytes
                        .len()
                        .checked_add(count)
                        .is_none_or(|length| length > self.maximum);
                    if exceeds {
                        if let Some(rejected) = rejected.as_deref_mut() {
                            *rejected = Some((chunk, count));
                        }
                        return Ok(true);
                    }
                    self.bytes.extend_from_slice(&chunk[..count]);
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::AGAIN) => return Ok(false),
                Err(error) => return Err(kernel_error("read fixed process output", error)),
            }
        }
    }
}

fn supervise(
    spawned: SpawnedProcess,
    request: FixedProcessRequest<'_>,
) -> Result<FixedProcessOutcome> {
    supervise_retaining(spawned, request, None)
}

fn supervise_retaining(
    spawned: SpawnedProcess,
    request: FixedProcessRequest<'_>,
    retained: Option<&mut run_original::SupervisionOriginalV3>,
) -> Result<FixedProcessOutcome> {
    supervise_capture_retaining_v3(spawned, request, retained, None)
}

fn supervise_capture_retaining_v3(
    spawned: SpawnedProcess,
    request: FixedProcessRequest<'_>,
    mut retained: Option<&mut run_original::SupervisionOriginalV3>,
    capture: Option<FixedProcessCaptureCutV3>,
) -> Result<FixedProcessOutcome> {
    let started = monotonic_now();
    let mut guard = spawned.guard;
    let mut stdout = match OutputStream::new_retaining(
        spawned.stdout,
        request.maximum_stdout_bytes,
        retained.as_deref_mut().map(|original| &mut original.stdout_pending),
    ) {
        Ok(stdout) => stdout,
        Err(error) => {
            if let Some(original) = retained {
                original.guard = Some(guard);
                original.stderr_pending = Some(spawned.stderr);
                original.exec_status = spawned.exec_status;
            }
            return Err(error);
        }
    };
    let mut stderr = match OutputStream::new_retaining(
        spawned.stderr,
        request.maximum_stderr_bytes,
        retained.as_deref_mut().map(|original| &mut original.stderr_pending),
    ) {
        Ok(stderr) => stderr,
        Err(error) => {
            if let Some(original) = retained {
                original.stdout = Some(stdout);
                original.guard = Some(guard);
                original.exec_status = spawned.exec_status;
            }
            return Err(error);
        }
    };
    let mut leader_exited = false;
    let mut stdout_rejected = None;
    let mut stderr_rejected = None;
    let retain_chunks = retained.is_some();
    let mut capture_clock = capture_cut::CaptureProcessCutOriginalV3::default();

    let result = (|| {
        loop {
            let capture_remaining = match capture {
                Some(cut) => Some(capture_clock.observe(cut)?),
                None => None,
            };
            if leader_exited && stdout.closed && stderr.closed {
                // The unreaped leader pins the process-group ID while any residual
                // same-group descendants are killed before ownership is released.
                let status = guard.cancel_and_reap()?;
                if let Some(cut) = capture { capture_clock.observe(cut)?; }
                return Ok(FixedProcessOutcome::Completed(FixedProcessOutput {
                    exit_code: status.exit_code,
                    signal: status.signal,
                    stdout: std::mem::take(&mut stdout.bytes),
                    stderr: std::mem::take(&mut stderr.bytes),
                }));
            }

            let elapsed = monotonic_now().saturating_sub(started);
            let Some(remaining) = request.timeout.checked_sub(elapsed) else {
                guard.cancel_and_reap()?;
                return Ok(FixedProcessOutcome::TimedOut);
            };
            let remaining = capture_remaining.map_or(remaining, |absolute| remaining.min(absolute));
            let timeout = rustix::event::Timespec::try_from(remaining)
                .map_err(|_| Error::invalid("fixed process timeout", "does not fit timespec"))?;
            let leader_ready = {
                let pidfd = guard.pidfd()?.as_fd();
                let stdout_fd = stdout.descriptor.as_fd();
                let stderr_fd = stderr.descriptor.as_fd();
                let mut descriptors = Vec::with_capacity(3);
                let leader_index = (!leader_exited).then(|| {
                    descriptors.push(rustix::event::PollFd::new(
                        &pidfd,
                        rustix::event::PollFlags::IN,
                    ));
                    descriptors.len() - 1
                });
                if !stdout.closed {
                    descriptors.push(rustix::event::PollFd::new(
                        &stdout_fd,
                        rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
                    ));
                }
                if !stderr.closed {
                    descriptors.push(rustix::event::PollFd::new(
                        &stderr_fd,
                        rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
                    ));
                }
                // Descriptor setup is complete. Reobserve the same original
                // cut here so none of that time becomes a newly armed wait.
                let timeout = match capture {
                    Some(cut) => rustix::event::Timespec::try_from(
                        capture_cut::limit_wait_v3(remaining, capture_clock.observe(cut)?))
                        .map_err(|_| Error::invalid("fixed process timeout", "does not fit timespec"))?,
                    None => timeout,
                };
                let native = rustix::event::poll(&mut descriptors, Some(&timeout));
                if capture.is_some() {
                    capture_clock.retain_poll_v3(native, &descriptors);
                }
                let after = match capture {
                    Some(cut) => capture_clock.observe(cut).map(|_| ()),
                    None => Ok(()),
                };
                if let Err(error) = native {
                    if capture_cut::poll_errno_is_primary_v3(error) {
                        return Err(kernel_error("poll fixed process", error));
                    }
                }
                after?;
                match native {
                    Ok(_) => leader_index.is_some_and(|index| {
                        descriptors[index]
                            .revents()
                            .contains(rustix::event::PollFlags::IN)
                    }),
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(error) => return Err(kernel_error("poll fixed process", error)),
                }
            };
            if leader_ready && !leader_exited {
                leader_exited = true;
                // Once the leader is known exited, stop residual same-group
                // descendants before waiting for their inherited pipes to close.
                guard.cancel()?;
            }
            if !stdout.closed && stdout.drain_capture_retaining_v3(retain_chunks.then_some(&mut stdout_rejected),
                capture.map(|cut| (cut, &mut capture_clock)))? {
                guard.cancel_and_reap()?;
                return Ok(FixedProcessOutcome::OutputLimitExceeded);
            }
            if !stderr.closed && stderr.drain_capture_retaining_v3(retain_chunks.then_some(&mut stderr_rejected),
                capture.map(|cut| (cut, &mut capture_clock)))? {
                guard.cancel_and_reap()?;
                return Ok(FixedProcessOutcome::OutputLimitExceeded);
            }
        }
    })();
    // A cutoff refusal denies further positive reads/waits, but the same
    // already-owned child still owes its original negative containment. Keep
    // both the first clock cause and any cleanup error before returning.
    let cleanup = if capture.is_some() && capture_clock.failure().is_some() && guard.armed {
        Some(guard.cancel_and_reap())
    } else { None };
    if let Some(original) = retained {
        original.capture_clock = capture_clock;
        original.capture_cleanup = cleanup;
        original.stdout_rejected = stdout_rejected;
        original.stderr_rejected = stderr_rejected;
        original.stderr = Some(stderr);
        original.stdout = Some(stdout);
        original.guard = Some(guard);
        original.exec_status = spawned.exec_status;
    }
    result
}

#[derive(Clone, Copy)]
struct ProcessStatus {
    exit_code: Option<i32>,
    signal: Option<i32>,
}

fn wait_blocking(pid: rustix::process::Pid) -> Result<ProcessStatus> {
    decode_status(wait_status_blocking(pid)?)
}

fn wait_status_blocking(pid: rustix::process::Pid) -> Result<rustix::process::WaitStatus> {
    loop {
        match wait_status_once(pid, rustix::process::WaitOptions::empty()) {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => continue,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(kernel_error("reap fixed process", error)),
        }
    }
}

/// Sole exact-child syscall adapter; no option selects another child or reaper.
fn wait_status_once(
    pid: rustix::process::Pid,
    options: rustix::process::WaitOptions,
) -> rustix::io::Result<Option<rustix::process::WaitStatus>> {
    rustix::process::waitpid(Some(pid), options)
        .map(|observation| observation.map(|(_, status)| status))
}

fn decode_status(status: rustix::process::WaitStatus) -> Result<ProcessStatus> {
    if status.exited() {
        Ok(ProcessStatus {
            exit_code: status.exit_status(),
            signal: None,
        })
    } else if status.signaled() {
        Ok(ProcessStatus {
            exit_code: None,
            signal: status.terminating_signal(),
        })
    } else {
        Err(Error::invalid(
            "fixed process status",
            "wait returned neither exit nor signal termination",
        ))
    }
}

struct ChildGuard {
    pid: rustix::process::Pid,
    pidfd: Option<PidFd>,
    armed: bool,
    leader_only: bool,
}

#[cfg(test)]
std::thread_local! {
    static INJECT_CLEANUP_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct CleanupFailureInjection;

#[cfg(test)]
impl Drop for CleanupFailureInjection {
    fn drop(&mut self) {
        INJECT_CLEANUP_FAILURE.with(|injection| injection.set(false));
    }
}

#[cfg(test)]
fn inject_cleanup_failure_once() -> CleanupFailureInjection {
    INJECT_CLEANUP_FAILURE.with(|injection| {
        assert!(!injection.replace(true), "cleanup failure already injected");
    });
    CleanupFailureInjection
}

#[cfg(test)]
fn take_cleanup_failure_injection() -> bool {
    INJECT_CLEANUP_FAILURE.with(std::cell::Cell::take)
}

impl ChildGuard {
    const fn new(pid: rustix::process::Pid) -> Self {
        Self {
            pid,
            pidfd: None,
            armed: true,
            leader_only: false,
        }
    }

    // The SSH subtree's separate cgroup original owns descendant cleanup.
    // Its actual unreaped child grants only this direct leader fallback.
    const fn new_owned_leader(pid: rustix::process::Pid) -> Self {
        Self { pid, pidfd: None, armed: true, leader_only: true }
    }

    fn attach_pidfd(&mut self, pidfd: PidFd) {
        self.pidfd = Some(pidfd);
    }

    fn pidfd(&self) -> Result<&PidFd> {
        self.pidfd
            .as_ref()
            .ok_or_else(|| Error::invalid("fixed process pidfd", "was not attached"))
    }

    fn reap(&mut self) -> Result<ProcessStatus> {
        let status = wait_blocking(self.pid)?;
        self.armed = false;
        Ok(status)
    }

    fn cancel_and_reap(&mut self) -> Result<ProcessStatus> {
        self.cancel()?;
        #[cfg(test)]
        if take_cleanup_failure_injection() {
            return Err(Error::invalid(
                "fixed process cleanup test injection",
                "failed before reap",
            ));
        }
        self.reap()
    }

    fn cancel(&self) -> Result<()> {
        self.cancel_with_disposition(CleanupDisposition::LegacyReturn)
    }

    fn cancel_with_disposition(&self, mut disposition: CleanupDisposition<'_>) -> Result<()> {
        if !self.leader_only {
            disposition.observe(kill_group(self.pid))?;
        }
        disposition.observe(kill_leader(self.pid, self.pidfd.as_ref()))?;
        Ok(())
    }
}

/// Keeps old short-circuit/drop semantics and retained diagnostics on one
/// actual group/leader signaling sequence, without an injected callback.
enum CleanupDisposition<'a> {
    LegacyReturn,
    LegacyDrop,
    Retained {
        first: &'a mut Option<Error>,
        capture: &'a mut capture::FixedProcessCaptureV1,
    },
}

impl CleanupDisposition<'_> {
    fn observe(&mut self, result: Result<()>) -> Result<()> {
        match self {
            Self::LegacyReturn => result,
            Self::LegacyDrop => Ok(()),
            Self::Retained { first, capture } => {
                capture::record_cleanup_result(result, first, capture);
                Ok(())
            }
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cancel_with_disposition(CleanupDisposition::LegacyDrop);
            let _ = wait_blocking(self.pid);
        }
        #[cfg(test)]
        INJECT_CLEANUP_FAILURE.with(|injection| injection.set(false));
    }
}

fn kill_leader(pid: rustix::process::Pid, pidfd: Option<&PidFd>) -> Result<()> {
    let result = if let Some(pidfd) = pidfd {
        rustix::process::pidfd_send_signal(pidfd.as_fd(), rustix::process::Signal::KILL)
    } else {
        // The child remains unreaped, so its numeric PID cannot be recycled.
        rustix::process::kill_process(pid, rustix::process::Signal::KILL)
    };
    match result {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(kernel_error("kill fixed process leader", error)),
    }
}

fn kill_group(pid: rustix::process::Pid) -> Result<()> {
    // The leader remains an unreaped child while this can run, so its PID and
    // process-group ID cannot be recycled to an unrelated process.
    match rustix::process::kill_process_group(pid, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(kernel_error("kill fixed process group", error)),
    }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)
        .map_err(|error| kernel_error("inspect fixed process output flags", error))?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| kernel_error("set fixed process output nonblocking", error))
}

fn validate_request(request: FixedProcessRequest<'_>) -> Result<()> {
    validate_executable_path(request.executable)?;
    if request.arguments.len() > MAXIMUM_ARGUMENTS {
        return Err(Error::ObservationLimitExceeded {
            object: "fixed process arguments",
            limit: MAXIMUM_ARGUMENTS,
        });
    }
    let argument_bytes = request.arguments.iter().try_fold(0_usize, |total, value| {
        total.checked_add(value.as_os_str().as_bytes().len())
    });
    if argument_bytes.is_none_or(|bytes| bytes > MAXIMUM_ARGUMENT_BYTES) {
        return Err(Error::ObservationLimitExceeded {
            object: "fixed process argument bytes",
            limit: MAXIMUM_ARGUMENT_BYTES,
        });
    }
    if request.timeout.is_zero() {
        return Err(Error::invalid("fixed process timeout", "must be nonzero"));
    }
    Ok(())
}

fn validate_executable_path(executable: &Path) -> Result<()> {
    let bytes = executable.as_os_str().as_bytes();
    let normalized = executable
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_EXECUTABLE_BYTES
        || !executable.is_absolute()
        || !normalized
    {
        return Err(Error::invalid(
            "fixed process executable",
            "must be a normalized absolute path within 4096 bytes",
        ));
    }
    Ok(())
}

fn duplicate_high(descriptor: BorrowedFd<'_>) -> Result<OwnedFd> {
    rustix::io::fcntl_dupfd_cloexec(descriptor, DUPLICATE_FD_MINIMUM)
        .map_err(|error| kernel_error("duplicate fixed process descriptor", error))
}

fn kernel_error(operation: &'static str, error: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(error.raw_os_error()),
    }
}

fn monotonic_now() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::fd::{AsRawFd as _, BorrowedFd};

    use super::*;

    fn test_process(test: &str, timeout: Duration, maximum: usize) -> FixedProcessOutcome {
        let executable = std::env::current_exe().unwrap();
        let arguments = ["--exact", test, "--nocapture"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        run_fixed_process_owned(
            FixedProcessRequest {
                executable: &executable,
                arguments: &arguments,
                timeout,
                maximum_stdout_bytes: maximum,
                maximum_stderr_bytes: maximum,
            },
            None,
            &[],
        )
        .unwrap()
    }

    #[test]
    fn captures_both_streams_and_exit_status() {
        let outcome = test_process(
            "process::tests::child_writes_both_streams",
            Duration::from_secs(2),
            4096,
        );
        let FixedProcessOutcome::Completed(output) = outcome else {
            panic!("fixture did not complete")
        };
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.signal, None);
        assert!(output.stdout.windows(3).any(|bytes| bytes == b"out"));
        assert!(output.stderr.windows(3).any(|bytes| bytes == b"err"));
    }

    #[test]
    fn deadline_kills_and_reaps_the_process_group() {
        assert_eq!(
            test_process(
                "process::tests::child_waits",
                Duration::from_millis(25),
                4096,
            ),
            FixedProcessOutcome::TimedOut
        );
    }

    #[test]
    fn output_ceiling_cancels_before_unbounded_allocation() {
        assert_eq!(
            test_process(
                "process::tests::child_writes_past_limit",
                Duration::from_secs(2),
                1024,
            ),
            FixedProcessOutcome::OutputLimitExceeded
        );
    }

    #[test]
    fn normal_leader_exit_cleans_pipe_holding_group_descendant() {
        let outcome = test_process(
            "process::tests::child_spawns_pipe_holding_descendant",
            Duration::from_secs(2),
            4096,
        );
        let FixedProcessOutcome::Completed(output) = outcome else {
            panic!("residual same-group descendant prevented completion")
        };
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.signal, None);
    }

    #[test]
    fn missing_executable_preserves_spawn_error() {
        let error = run_fixed_process_owned(
            FixedProcessRequest {
                executable: Path::new("/definitely/absent/aos-test-program"),
                arguments: &[],
                timeout: Duration::from_secs(1),
                maximum_stdout_bytes: 1,
                maximum_stderr_bytes: 1,
            },
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Syscall { source, .. } if source.raw_os_error() == Some(libc::ENOENT)
        ));
    }

    #[test]
    fn descriptor_role_ceiling_is_checked_before_spawning() {
        let descriptor = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let inherited = [descriptor.as_fd(); MAXIMUM_INHERITED_DESCRIPTORS + 1];
        let error = run_fixed_process_with_descriptors(FixedProcessDescriptorRequest {
            process: FixedProcessRequest {
                executable: Path::new("/definitely/absent/aos-test-program"),
                arguments: &[],
                timeout: Duration::from_secs(1),
                maximum_stdout_bytes: 1,
                maximum_stderr_bytes: 1,
            },
            stdin: None,
            inherited: &inherited,
        })
        .unwrap_err();

        assert!(matches!(
            error,
            Error::InvalidInput {
                field: "fixed process inherited descriptors",
                ..
            }
        ));
    }

    #[test]
    fn descriptor_roles_are_alias_safe_ordered_and_exclusive() {
        let executable = std::env::current_exe().unwrap();
        let status = std::process::Command::new(executable)
            .args([
                "--ignored",
                "--exact",
                "process::tests::isolated_descriptor_mapping_case",
                "--nocapture",
            ])
            .env("AOS_FIXED_PROCESS_DESCRIPTOR_CASE", "outer")
            .status()
            .unwrap();

        assert!(status.success(), "isolated descriptor mapping case failed");
    }

    #[test]
    fn public_api_rejects_a_process_with_competing_threads() {
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let child_release = release.clone();
        let competing_thread = std::thread::spawn(move || child_release.wait());

        let error = run_fixed_process(FixedProcessRequest {
            executable: Path::new("/definitely/absent/aos-test-program"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 1,
            maximum_stderr_bytes: 1,
        })
        .unwrap_err();
        release.wait();
        competing_thread.join().unwrap();

        assert!(matches!(
            error,
            Error::InvalidInput {
                field: "fixed process reaping ownership",
                ..
            }
        ));
    }

    #[test]
    fn public_api_rejects_nondefault_sigchld_in_isolated_processes() {
        let executable = std::env::current_exe().unwrap();
        for disposition in ["ignore", "no-cld-wait"] {
            let status = std::process::Command::new(&executable)
                .args([
                    "--ignored",
                    "--exact",
                    "process::tests::isolated_nondefault_sigchld_case",
                    "--nocapture",
                ])
                .env("AOS_FIXED_PROCESS_SIGCHLD_CASE", disposition)
                .status()
                .unwrap();
            assert!(status.success(), "isolated {disposition} case failed");
        }
    }

    #[test]
    #[ignore = "launched alone by the isolated SIGCHLD disposition test"]
    fn isolated_nondefault_sigchld_case() {
        let disposition = std::env::var("AOS_FIXED_PROCESS_SIGCHLD_CASE").unwrap();
        // SAFETY: this ignored test runs alone in a disposable subprocess, and
        // initializes the complete Linux sigaction before installing it.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_sigaction = if disposition == "ignore" {
                libc::SIG_IGN
            } else {
                libc::SIG_DFL
            };
            action.sa_flags = if disposition == "no-cld-wait" {
                libc::SA_NOCLDWAIT
            } else {
                0
            };
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()),
                0
            );
        }

        let error = run_fixed_process(FixedProcessRequest {
            executable: Path::new("/definitely/absent/aos-test-program"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 1,
            maximum_stderr_bytes: 1,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidInput {
                field: "fixed process reaping ownership",
                message,
            } if message.contains("default SIGCHLD")
        ));
    }

    #[test]
    #[ignore = "launched alone by the descriptor mapping test"]
    fn isolated_descriptor_mapping_case() {
        if std::env::var_os("AOS_FIXED_PROCESS_DESCRIPTOR_CASE").as_deref()
            != Some(std::ffi::OsStr::new("outer"))
        {
            return;
        }

        let source_a = pipe_containing(b'a');
        let source_b = pipe_containing(b'b');
        let source_c = pipe_containing(b'c');
        let source_a = duplicate_high(source_a.as_fd()).unwrap();
        let source_b = duplicate_high(source_b.as_fd()).unwrap();
        let source_c = duplicate_high(source_c.as_fd()).unwrap();

        // Deliberately put caller sources in targets that earlier mappings
        // overwrite. Repeating FD 4 also proves each logical role is retained.
        for (source, target) in [
            (source_a.as_raw_fd(), 0),
            (source_b.as_raw_fd(), 3),
            (source_c.as_raw_fd(), 4),
            (source_a.as_raw_fd(), 7),
        ] {
            // SAFETY: each source is live, each fixed target is nonnegative,
            // and this test runs in a disposable isolated process.
            assert_eq!(unsafe { libc::dup2(source, target) }, target);
        }
        // SAFETY: F_GETFD takes no pointer, and FD 7 was established above.
        assert_eq!(unsafe { libc::fcntl(7, libc::F_GETFD) }, 0);
        // SAFETY: the dup2 calls above established these descriptors, which
        // remain live through the synchronous invocation.
        let stdin = unsafe { BorrowedFd::borrow_raw(3) };
        let inherited = unsafe {
            [
                BorrowedFd::borrow_raw(4),
                BorrowedFd::borrow_raw(0),
                BorrowedFd::borrow_raw(3),
                BorrowedFd::borrow_raw(4),
            ]
        };
        let executable = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored".into(),
            "--exact".into(),
            "process::tests::descriptor_mapping_child_case".into(),
            "--nocapture".into(),
        ];
        let outcome = run_fixed_process_owned(
            FixedProcessRequest {
                executable: &executable,
                arguments: &arguments,
                timeout: Duration::from_secs(2),
                maximum_stdout_bytes: 4096,
                maximum_stderr_bytes: 4096,
            },
            Some(stdin),
            &inherited,
        )
        .unwrap();

        let FixedProcessOutcome::Completed(output) = outcome else {
            panic!("descriptor child did not complete")
        };
        assert_eq!(output.exit_code, Some(0), "{:?}", output.stderr);
        assert_eq!(output.signal, None);
    }

    #[test]
    #[ignore = "launched only as the fixed descriptor child"]
    fn descriptor_mapping_child_case() {
        assert!(same_object(0, 5));
        assert!(same_object(3, 6));
        assert_eq!(read_all(0), b"b");
        assert_eq!(read_all(3), b"c");
        assert_eq!(read_all(4), b"a");

        // SAFETY: F_GETFD takes no pointer and accepts any integer descriptor;
        // probing the deliberately closed role is the purpose of this call.
        assert_eq!(unsafe { libc::fcntl(7, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    fn pipe_containing(byte: u8) -> OwnedFd {
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        assert_eq!(rustix::io::write(&write, &[byte]).unwrap(), 1);
        drop(write);
        read
    }

    fn read_all(raw_fd: i32) -> Vec<u8> {
        // SAFETY: the descriptor child calls this only for its fixed live roles.
        let descriptor = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        let mut output = Vec::new();
        let mut buffer = [0_u8; 16];
        loop {
            match rustix::io::read(descriptor, &mut buffer).unwrap() {
                0 => return output,
                count => output.extend_from_slice(&buffer[..count]),
            }
        }
    }

    fn same_object(left: i32, right: i32) -> bool {
        // SAFETY: the descriptor child calls this only for its fixed live roles.
        let left = unsafe { BorrowedFd::borrow_raw(left) };
        // SAFETY: the descriptor child calls this only for its fixed live roles.
        let right = unsafe { BorrowedFd::borrow_raw(right) };
        let left = rustix::fs::fstat(left).unwrap();
        let right = rustix::fs::fstat(right).unwrap();
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    #[test]
    fn child_writes_both_streams() {
        use std::io::Write as _;

        std::io::stdout().write_all(b"out").unwrap();
        std::io::stderr().write_all(b"err").unwrap();
    }

    #[test]
    fn child_waits() {
        std::thread::sleep(Duration::from_secs(10));
    }

    #[test]
    fn child_writes_past_limit() {
        use std::io::Write as _;

        let bytes = vec![b'x'; 4096];
        std::io::stdout().write_all(&bytes).unwrap();
    }

    #[test]
    #[allow(
        clippy::zombie_processes,
        reason = "the outer fixed-process supervisor owns and reaps the process-group leader"
    )]
    fn child_spawns_pipe_holding_descendant() {
        let executable = std::env::current_exe().unwrap();
        let _descendant = std::process::Command::new(executable)
            .args([
                "--exact",
                "process::tests::pipe_holding_descendant",
                "--nocapture",
            ])
            .spawn()
            .unwrap();
    }

    #[test]
    fn pipe_holding_descendant() {
        std::thread::sleep(Duration::from_secs(10));
    }
}
