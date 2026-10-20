//! Owns the exact native prefix of the shared fixed process runner.
//!
//! Empty custody grants no execution authority. A fixed caller funds the
//! invocation and owns child containment before entry. A failed attempt keeps
//! its original task-directory reader, spawn setup, child and output streams;
//! it cannot be disposed as a positive process completion.

use super::*;

/// Marks refusal without consuming the caller's native attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("fixed process operation refused; the original native attempt remains retained")]
pub struct FixedProcessRunRefusalV3;

/// Retains one fixed invocation and its original native failure or outcome.
///
/// Successful process output is moved once. The caller must settle its own
/// comparisons and owed posts before disposing this attempt positively.
/// Dropping an unresolved attempt aborts before its native prefix is released.
pub struct FixedProcessRunOriginalV3 {
    reaping: ReapingOriginalV3,
    invocation: Option<PreparedInvocation>,
    spawn: FixedProcessSpawnFailureV2,
    supervision: SupervisionOriginalV3,
    outcome: Option<FixedProcessOutcome>,
    error: Option<Error>,
    entered: bool,
    disposed: bool,
}

impl FixedProcessRunOriginalV3 {
    /// Creates empty native custody without entering any process operation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reaping: ReapingOriginalV3::new(), invocation: None,
            spawn: FixedProcessSpawnFailureV2::new(),
            supervision: SupervisionOriginalV3::new(),
            outcome: None, error: None, entered: false, disposed: false,
        }
    }

    /// Borrows the first actual native failure while its prefix stays owned.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        match self.error.as_ref() {
            Some(error) if capture_cut::is_marker(error) => self.supervision.capture_clock.failure().or(Some(error)),
            error => error,
        }.or_else(|| self.spawn.failure())
    }

    /// Borrows the actual outcome without cloning its output buffers.
    #[must_use]
    pub fn outcome(&self) -> Option<&FixedProcessOutcome> {
        self.outcome.as_ref()
    }

    /// Moves the actual successful output after the child and both EOFs settled.
    ///
    /// # Errors
    /// Refuses absent, failed, canceled, already-taken or disposed attempts.
    pub fn take_completed_output_v3(&mut self)
        -> std::result::Result<FixedProcessOutput, FixedProcessRunRefusalV3>
    {
        if self.disposed || self.failure().is_some()
            || !matches!(self.outcome, Some(FixedProcessOutcome::Completed(_)))
        {
            return Err(FixedProcessRunRefusalV3);
        }
        match self.outcome.take() {
            Some(FixedProcessOutcome::Completed(output)) => Ok(output),
            _ => Err(FixedProcessRunRefusalV3),
        }
    }

    /// Releases completed native temporaries after the caller's positive posts.
    ///
    /// This does not refund any resource debt or prove the caller's protocol.
    ///
    /// # Errors
    /// Refuses failure, untaken output, an armed child, incomplete streams or repeated disposal.
    pub fn dispose_after_completed_posts_v3(&mut self)
        -> std::result::Result<(), FixedProcessRunRefusalV3>
    {
        if !self.entered || self.disposed || self.failure().is_some()
            || self.outcome.is_some()
            || self.spawn.has_armed_child()
            || self.supervision.guard.as_ref().is_none_or(|guard| guard.armed)
            || self.supervision.stdout.as_ref().is_none_or(|stream| !stream.closed)
            || self.supervision.stderr.as_ref().is_none_or(|stream| !stream.closed)
        {
            return Err(FixedProcessRunRefusalV3);
        }
        self.supervision.retire_completed();
        self.invocation = None;
        self.disposed = true;
        Ok(())
    }

    /// Counts native files retained after positive status and before disposal.
    ///
    /// The shared fixed runner has already closed its task directory, spawn
    /// setup aliases and inherited copies. Its actual successful supervision
    /// keeps one attached leader PIDFD and the two completed output readers.
    /// This pending semantic-result tail is neither financial credit nor a
    /// process-table, source or execution allowance. Failed prefixes have a
    /// different, separately priced envelope.
    #[must_use]
    pub const fn completed_pending_disposal_files_data_v3() -> usize {
        // These are the three retained supervision roles, not a native cap.
        ["leader PIDFD", "stdout reader", "stderr reader"].len()
    }

    /// Returns checked retained command/output representation bytes.
    ///
    /// This covers compiled custody, both canonical executable strings, argv
    /// storage and both bounded stream capacities. It grants no process fit.
    /// The caller also pays its borrowed request, containment and the platform
    /// platform-specific process internals before entry. The task-directory
    /// allocation envelope is included for the qualified GNU x86-64 provider;
    /// other providers refuse this calculation.
    #[must_use]
    pub fn representation_bytes_v3(request: FixedProcessRequest<'_>) -> Option<usize> {
        let argument_bytes = request.arguments.iter().try_fold(0usize, |sum, argument| {
            sum.checked_add(argument.as_os_str().as_bytes().len().checked_add(1)?)
        })?;
        Self::representation_from_lengths_v3(
            request.executable.as_os_str().as_bytes().len(), request.arguments.len(),
            argument_bytes, request.maximum_stdout_bytes, request.maximum_stderr_bytes,
        )
    }

    /// Bounds bytes actually read from both closed output streams.
    ///
    /// The sole native drain stops at the first read crossing a ceiling. Each
    /// stream therefore contributes its retained ceiling and at most one actual
    /// native chunk, including that rejected chunk. This is passive cost DATA,
    /// never permission to drain arbitrary output or repeat an invocation.
    #[must_use]
    pub fn bounded_output_bytes_v3(stdout: usize, stderr: usize) -> Option<usize> {
        stdout.checked_add(super::FIXED_OUTPUT_CHUNK_BYTES_V3)?
            .checked_add(stderr)?.checked_add(super::FIXED_OUTPUT_CHUNK_BYTES_V3)
    }

    /// Bounds one invocation under the sole existing fixed argv/path limits.
    ///
    /// The stream ceilings come from the fixed caller's existing recipe. This
    /// passive envelope creates no worker, caller role or resource credit.
    #[must_use]
    pub fn bounded_representation_bytes_v3(
        maximum_stdout_bytes: usize,
        maximum_stderr_bytes: usize,
    ) -> Option<usize> {
        Self::representation_from_lengths_v3(
            MAXIMUM_EXECUTABLE_BYTES, MAXIMUM_ARGUMENTS,
            MAXIMUM_ARGUMENT_BYTES.checked_add(MAXIMUM_ARGUMENTS)?,
            maximum_stdout_bytes, maximum_stderr_bytes,
        )
    }

    /// Prices the same representation from borrowed command lengths.
    ///
    /// `argument_bytes` includes one trailing NUL per argument. This passive
    /// calculation performs no allocation and establishes no execution fit.
    #[must_use]
    pub fn representation_from_lengths_v3(
        executable_bytes: usize,
        argument_count: usize,
        argument_bytes: usize,
        maximum_stdout_bytes: usize,
        maximum_stderr_bytes: usize,
    ) -> Option<usize> {
        let path = executable_bytes.checked_add(1)?;
        // Geometric growth may keep the old allocation beside its replacement.
        // Three ceilings dominate that overlap, including the argv headers.
        // Resident destination plus the constructor, caller and Vec-transfer
        // carriers can coexist before their final moves are optimized away.
        std::mem::size_of::<Self>().checked_mul(4)?
            .checked_add(path.checked_mul(2)?)?
            .checked_add(argument_bytes)?
            // Qualified RawVec reserves at least four CString elements for
            // a nonempty fallible collection, even for a single argument.
            .checked_add(argument_count.max(4).checked_mul(3)?
                .checked_mul(std::mem::size_of::<CString>())?)?
            .checked_add(maximum_stdout_bytes.checked_mul(3)?)?
            .checked_add(maximum_stderr_bytes.checked_mul(3)?)?
            .checked_add(2usize.checked_mul(std::mem::size_of::<Option<([u8; 8192], usize)>>())?)?
            .checked_add(8192)?
            .checked_add(task_directory_representation_bytes_v3()?)?
            .checked_add(3usize.checked_mul(std::mem::size_of::<rustix::event::PollFd<'static>>())?)
    }

    /// Reports the canonical temporary single-thread directory allocation.
    ///
    /// A finite programme may use one maximum for this storage only when it
    /// proves that every positive directory original retires before the next
    /// entry and that a failed entry prevents all subsequent helpers. Resident
    /// originals, error backing and existing financial debits remain separate.
    #[must_use]
    pub fn task_directory_transient_bytes_data_v3() -> Option<usize> {
        task_directory_representation_bytes_v3()
    }

    /// Counts the actual Path-spawn setup descriptors before its fork census.
    ///
    /// This includes the original null/pipe descriptors and high aliases.
    /// The caller separately adds its held table, the census scanner and
    /// any original stdin or inherited donor descriptors. It grants no spawn
    /// permission and does not change the installed descriptor limit.
    #[must_use]
    pub fn path_spawn_setup_files_data_v3(
        supplied_stdin: bool,
        inherited: usize,
    ) -> Option<usize> {
        super::spawn_original::path_setup_files_data_v3(supplied_stdin, inherited)
    }

    /// Prices the same runner with its actual bounded descriptor-table overlap.
    ///
    /// This adds the retained owning duplicates and temporary borrowed-FD
    /// table to the existing command/output representation. Input descriptors,
    /// containment and platform process internals remain separately owed.
    #[must_use]
    pub fn descriptor_representation_bytes_v4(
        request: FixedProcessDescriptorRequest<'_>,
    ) -> Option<usize> {
        if request.inherited.len() > MAXIMUM_INHERITED_DESCRIPTORS {
            return None;
        }
        Self::representation_bytes_v3(request.process)?
            .checked_add(
                request
                    .inherited
                    .len()
                    .checked_mul(2)?
                    .checked_mul(std::mem::size_of::<OwnedFd>())?,
            )?
            .checked_add(
                request
                    .inherited
                    .len()
                    .checked_mul(2)?
                    .checked_mul(std::mem::size_of::<BorrowedFd<'static>>())?,
            )
    }

}

// Qualified Rust 1.98.1 Unix ReadDir shares one Arc<InnerReadDir> between
// the reader and both retained entries. GNU libc 2.39 opendir allocates one
// DIR header plus min(max(st_blksize, 32768), 1048576) bytes. These are
// allocation requests; process allocator arenas remain platform enclosure.
pub(crate) fn task_directory_representation_bytes_v3() -> Option<usize> {
    if !cfg!(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")) {
        return None;
    }

    // The qualified DIR has fd, int lock, three size_t fields, off_t and
    // errcode. Its trailing buffer rounds the header to long-double alignment.
    let alignment = std::mem::align_of::<libc::max_align_t>();
    let fields = 3usize.checked_mul(std::mem::size_of::<libc::c_int>())?
        .checked_add(3usize.checked_mul(std::mem::size_of::<usize>())?)?
        .checked_add(std::mem::size_of::<libc::off_t>())?;
    let dir_header = fields.checked_add(alignment.checked_sub(1)?)?
        .checked_div(alignment)?.checked_mul(alignment)?;

    // Arc owns two atomic counts, one DIR pointer and the root PathBuf.
    // Entries clone the Arc without allocating another owner. NAME_MAX+NUL
    // covers both copied names even when the second entry causes refusal.
    let shared_owner = std::mem::size_of::<std::path::PathBuf>()
        .checked_add(3usize.checked_mul(std::mem::size_of::<usize>())?)?;
    let names = usize::try_from(libc::NAME_MAX).ok()?.checked_add(1)?
        .checked_mul(2)?;
    dir_header.checked_add(1_048_576)?
        .checked_add(shared_owner)?
        .checked_add(b"/proc/self/task".len())?
        .checked_add(names)?
        // The qualified short-path conversion uses a 384-byte stack buffer.
        .checked_add(384)
}

impl Default for FixedProcessRunOriginalV3 {
    fn default() -> Self { Self::new() }
}

impl Drop for FixedProcessRunOriginalV3 {
    fn drop(&mut self) {
        if self.entered && !self.disposed { std::process::abort(); }
    }
}

pub(super) struct ReapingOriginalV3 {
    // Ordinary locals dropped second entry, first entry, then reader.
    pub(super) second: Option<std::fs::DirEntry>,
    pub(super) first: Option<std::fs::DirEntry>,
    pub(super) tasks: Option<std::fs::ReadDir>,
}

impl ReapingOriginalV3 {
    pub(super) fn new() -> Self { Self { second: None, first: None, tasks: None } }

    fn retire_positive(&mut self) {
        self.second = None;
        self.first = None;
        self.tasks = None;
    }
}

pub(super) struct SupervisionOriginalV3 {
    pub(super) capture_clock: capture_cut::CaptureProcessCutOriginalV3,
    pub(super) capture_cleanup: Option<Result<ProcessStatus>>,
    pub(super) stdout_rejected: Option<([u8; 8192], usize)>,
    pub(super) stderr_rejected: Option<([u8; 8192], usize)>,
    pub(super) stderr: Option<OutputStream>,
    pub(super) stdout: Option<OutputStream>,
    pub(super) guard: Option<ChildGuard>,
    pub(super) stderr_pending: Option<OwnedFd>,
    pub(super) stdout_pending: Option<OwnedFd>,
    pub(super) exec_status: Option<uapi::FixedExecStatusReader>,
}

impl SupervisionOriginalV3 {
    fn new() -> Self {
        Self { capture_clock: capture_cut::CaptureProcessCutOriginalV3::default(), capture_cleanup: None, stdout_rejected: None, stderr_rejected: None,
            stderr: None, stdout: None, guard: None, stderr_pending: None,
            stdout_pending: None, exec_status: None }
    }

    fn retire_completed(&mut self) {
        self.stderr = None;
        self.stdout = None;
        self.guard = None;
        self.exec_status = None;
    }
}

/// Runs the sole fixed spawn and supervision engine into caller-owned custody.
///
/// The caller supplies an existing exclusive-reaping and containment context;
/// this mechanical entry neither creates a role nor pays a resource ledger.
///
/// # Errors
/// Refuses reentry or any original validation, task, spawn, I/O, signal or wait
/// failure. `original.failure()` borrows the actual cause after refusal.
pub fn run_fixed_process_retaining_v3(
    request: FixedProcessRequest<'_>,
    original: &mut FixedProcessRunOriginalV3,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    run_fixed_process_with_fork_original_v3(request, None, original)
}

/// Runs the same retained process engine with the fixed Storage fork census.
///
/// The census remains on the existing signal-fenced spawn frontier. Both
/// destinations are mechanical native custody, without worker or payer grants.
///
/// # Errors
/// Refuses any original task, request, census, spawn or supervision failure.
/// Both original causes and every reached native prefix remain caller-owned.
pub fn run_fixed_process_observing_storage_fork_retaining_v3(
    request: FixedProcessRequest<'_>,
    observation: &mut StorageWorkerForkObservationV1,
    original: &mut FixedProcessRunOriginalV3,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    run_fixed_process_with_fork_original_v3(request, Some(observation), original)
}

/// Runs the same Storage child with immutable mechanical BOOTTIME/WALL cuts.
///
/// The original Source/clock-domain/worker owner remains mandatory. These
/// denial DATA never authorize a process, extend a timeout or pay a resource.
///
/// # Errors
/// Retains every original task, setup, spawn, absolute-clock, IO and cleanup
/// failure. The first actual cause remains available through the original.
pub fn run_fixed_capture_process_retaining_v3(
    request: FixedProcessRequest<'_>,
    observation: &mut StorageWorkerForkObservationV1,
    original: &mut FixedProcessRunOriginalV3,
    capture: FixedProcessCaptureCutV3,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    run_fixed_process_capture_engine_v3(request, Some(observation), original, Some(capture))
}

/// Runs the same retained fixed engine with explicit stdin and inherited roles.
///
/// The caller owns genuine containment, paid representation and the original
/// authority horizon before entry. The supplied absolute BOOTTIME/WALL cut is
/// restrictive mechanical DATA, as in the existing Capture caller; it grants
/// no Storage or Network role. Exact descriptor destinations remain FD3..FD6.
///
/// # Errors
/// Refuses more than four roles, repeated entry, or any original validation,
/// task, duplicate, spawn, absolute-clock, IO, signal or wait failure. Every
/// entered native prefix and the first actual cause stay on the same original.
pub fn run_fixed_descriptor_process_retaining_v4(
    request: FixedProcessDescriptorRequest<'_>,
    original: &mut FixedProcessRunOriginalV3,
    absolute_cut: FixedProcessCaptureCutV3,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    run_fixed_descriptor_process_capture_engine_v4(request, None, original, Some(absolute_cut))
}

/// Runs the same descriptor engine with the Network worker's complete census.
///
/// The caller retains its genuine worker/source/aggregate owners. The census
/// counts both native descriptor tables at clone; it supplies no permission or
/// financial credit. Original cutoff DATA clamp the same spawn and IO engine.
///
/// # Errors
/// Refuses reentry, descriptor/argv validation, incomplete census, spawn,
/// supervision or original cutoff failure, retaining every reached prefix.
pub fn run_fixed_descriptor_process_observing_network_fork_retaining_v4(
    request: FixedProcessDescriptorRequest<'_>,
    observation: &mut NetworkWorkerForkObservationV4,
    original: &mut FixedProcessRunOriginalV3,
    absolute_cut: FixedProcessCaptureCutV3,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    run_fixed_descriptor_process_capture_engine_v4(
        request,
        Some(WorkerForkObservationBorrowV4::Network(observation)),
        original,
        Some(absolute_cut),
    )
}

fn run_fixed_process_with_fork_original_v3(
    request: FixedProcessRequest<'_>,
    observation: Option<&mut StorageWorkerForkObservationV1>,
    original: &mut FixedProcessRunOriginalV3,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    run_fixed_process_capture_engine_v3(request, observation, original, None)
}

fn run_fixed_process_capture_engine_v3(
    request: FixedProcessRequest<'_>,
    observation: Option<&mut StorageWorkerForkObservationV1>,
    original: &mut FixedProcessRunOriginalV3,
    capture: Option<FixedProcessCaptureCutV3>,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    run_fixed_descriptor_process_capture_engine_v4(
        FixedProcessDescriptorRequest {
            process: request,
            stdin: None,
            inherited: &[],
        },
        observation.map(WorkerForkObservationBorrowV4::Storage),
        original,
        capture,
    )
}

fn run_fixed_descriptor_process_capture_engine_v4(
    request: FixedProcessDescriptorRequest<'_>,
    observation: Option<WorkerForkObservationBorrowV4<'_>>,
    original: &mut FixedProcessRunOriginalV3,
    capture: Option<FixedProcessCaptureCutV3>,
) -> std::result::Result<(), FixedProcessRunRefusalV3> {
    if original.entered {
        return Err(FixedProcessRunRefusalV3);
    }
    original.entered = true;
    let result = (|| -> Result<()> {
        if request.inherited.len() > MAXIMUM_INHERITED_DESCRIPTORS {
            return Err(Error::invalid(
                "fixed process inherited descriptors",
                "exceeds the four-descriptor ceiling",
            ));
        }
        validate_exclusive_reaping_owner_into(&mut original.reaping)?;
        // This check is a complete primitive: later invocation does not borrow
        // its task-directory reader or directory entries.
        original.reaping.retire_positive();
        run_after_reaping_descriptor_capture_v4(request, observation, original, capture)?;
        Ok(())
    })();
    if let Err(error) = result {
        original.error = Some(error);
    }
    if original.failure().is_some() {
        Err(FixedProcessRunRefusalV3)
    } else {
        Ok(())
    }
}

fn run_after_reaping_v3(
    request: FixedProcessRequest<'_>,
    original: &mut FixedProcessRunOriginalV3,
) -> Result<()> {
    run_after_reaping_with_fork_v3(request, None, original)
}

fn run_after_reaping_with_fork_v3(
    request: FixedProcessRequest<'_>,
    observation: Option<&mut StorageWorkerForkObservationV1>,
    original: &mut FixedProcessRunOriginalV3,
) -> Result<()> {
    run_after_reaping_capture_v3(request, observation, original, None)
}

fn run_after_reaping_capture_v3(
    request: FixedProcessRequest<'_>,
    observation: Option<&mut StorageWorkerForkObservationV1>,
    original: &mut FixedProcessRunOriginalV3,
    capture: Option<FixedProcessCaptureCutV3>,
) -> Result<()> {
    run_after_reaping_descriptor_capture_v4(
        FixedProcessDescriptorRequest {
            process: request,
            stdin: None,
            inherited: &[],
        },
        observation.map(WorkerForkObservationBorrowV4::Storage),
        original,
        capture,
    )
}

fn run_after_reaping_descriptor_capture_v4(
    request: FixedProcessDescriptorRequest<'_>,
    observation: Option<WorkerForkObservationBorrowV4<'_>>,
    original: &mut FixedProcessRunOriginalV3,
    capture: Option<FixedProcessCaptureCutV3>,
) -> Result<()> {
    original.invocation = Some(PreparedInvocation::new(request.process)?);
    let invocation = original
        .invocation
        .as_ref()
        .ok_or_else(|| Error::invalid("fixed process invocation", "capture is absent"))?;
    let spawned = match spawn_original::spawn_into_original_worker_capture_v4(
        invocation,
        request.stdin,
        request.inherited,
        SpawnExecution::Path,
        observation,
        &mut original.spawn,
        capture,
    ) {
        Ok(spawned) => spawned,
        Err(()) => return Ok(()),
    };
    original.outcome = Some(supervise_capture_retaining_v3(
        spawned,
        request.process,
        Some(&mut original.supervision),
        capture,
    )?);
    Ok(())
}

#[cfg(all(test, feature = "kernel-tests"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn descriptor_roster_refuses_before_task_or_spawn_io_and_keeps_first_cause() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let inherited = [file.as_fd(); MAXIMUM_INHERITED_DESCRIPTORS + 1];
        let process = FixedProcessRequest {
            executable: Path::new("/aos/absent-descriptor-roster-fixture"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 64,
            maximum_stderr_bytes: 64,
        };
        let request = FixedProcessDescriptorRequest {
            process,
            stdin: Some(file.as_fd()),
            inherited: &inherited,
        };
        let boot = uapi::boottime_nanoseconds().unwrap();
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        let cut = FixedProcessCaptureCutV3::new(boot + 1_000_000_000, wall + 1).unwrap();
        let mut original = FixedProcessRunOriginalV3::new();

        assert!(run_fixed_descriptor_process_retaining_v4(request, &mut original, cut).is_err());
        assert!(original.reaping.tasks.is_none());
        assert!(original.invocation.is_none());
        let cause = std::ptr::from_ref(original.failure().unwrap());
        assert!(run_fixed_descriptor_process_retaining_v4(request, &mut original, cut).is_err());
        assert_eq!(cause, std::ptr::from_ref(original.failure().unwrap()));
        // This exact boundary refused before any child or spawn setup existed.
        original.disposed = true;
    }

    #[test]
    fn retained_missing_executable_keeps_spawn_setup_and_same_cause_on_reentry() {
        let request = FixedProcessRequest {
            executable: Path::new("/aos/absent-retained-fixed-process-native-test"),
            arguments: &[], timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 4096, maximum_stderr_bytes: 4096,
        };
        let mut original = FixedProcessRunOriginalV3::new();
        original.entered = true;
        // This exercises the exact production body after its independently
        // checked reaping frontier, without depending on test harness threads.
        run_after_reaping_v3(request, &mut original).unwrap();

        let cause = std::ptr::from_ref(original.failure().unwrap());
        assert!(!original.spawn.has_armed_child());
        assert!(original.invocation.is_some());
        assert!(original.take_completed_output_v3().is_err());
        assert!(original.dispose_after_completed_posts_v3().is_err());
        assert!(run_fixed_process_retaining_v3(request, &mut original).is_err());
        assert_eq!(std::ptr::from_ref(original.failure().unwrap()), cause);

        // No child exists in this rejected-exec case. Tests explicitly close
        // their inspected setup; production failure custody remains protected.
        original.disposed = true;
    }

    #[test]
    fn selected_output_limit_keeps_exact_offending_native_chunk_and_reader() {
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        assert_eq!(rustix::io::write(&write, b"actual-over-limit-output").unwrap(), 24);
        drop(write);
        let descriptor = read.as_raw_fd();
        let mut stream = OutputStream::new(read, 3).unwrap();
        let mut rejected = None;

        assert!(stream.drain_retaining(Some(&mut rejected)).unwrap());

        let (bytes, count) = rejected.as_ref().unwrap();
        assert_eq!(&bytes[..*count], b"actual-over-limit-output");
        assert!(stream.bytes.is_empty());
        assert!(!stream.closed);
        assert_eq!(stream.descriptor.as_raw_fd(), descriptor);
        assert!(rustix::fs::fcntl_getfl(&stream.descriptor).is_ok());
    }
}
