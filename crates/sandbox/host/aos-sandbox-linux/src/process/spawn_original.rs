//! Retains the original setup descriptors on the shared fixed-spawn engine.
//!
//! Empty custody is mechanical native storage, not execution authority. The
//! fixed purpose owner must fund its compiled representation and descriptor
//! overlap before entry. This closes setup from /dev/null through typed pidfd
//! handoff; caller reaping/proc-task validation and raw exec helper internals
//! remain their own provider windows. A retained armed child is negative debt,
//! never an Ended or no-effect observation.

use super::*;

/// Owns a failed native setup and its exact first cause without descriptor escape.
pub struct FixedProcessSpawnFailureV2 {
    raw_pidfd: Option<OwnedFd>,
    guard: Option<ChildGuard>,
    exec_status: Option<uapi::FixedExecStatusReader>,
    executable: Option<OwnedFd>,
    inherited: Vec<OwnedFd>,
    supplied_stdin: Option<OwnedFd>,
    stderr_high: Option<OwnedFd>,
    stdout_high: Option<OwnedFd>,
    null_high: Option<OwnedFd>,
    stderr_write: Option<OwnedFd>,
    stderr_read: Option<OwnedFd>,
    stdout_write: Option<OwnedFd>,
    stdout_read: Option<OwnedFd>,
    null: Option<OwnedFd>,
    error: Option<Error>,
    capture_clock: capture_cut::CaptureProcessCutOriginalV3,
    capture_cleanup: Option<Result<ProcessStatus>>,
    entered: bool,
}

impl FixedProcessSpawnFailureV2 {
    pub(super) fn new() -> Self {
        Self {
            guard: None, exec_status: None, raw_pidfd: None, executable: None,
            inherited: Vec::new(), supplied_stdin: None, stderr_high: None,
            stdout_high: None, null_high: None, stderr_read: None, stderr_write: None,
            stdout_read: None, stdout_write: None, null: None, error: None, capture_clock: capture_cut::CaptureProcessCutOriginalV3::default(), capture_cleanup: None, entered: false,
        }
    }

    /// Borrows the original native refusal while setup descriptors stay resident.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        match self.error.as_ref() {
            Some(error) if capture_cut::is_marker(error) => self.capture_clock.failure().or(Some(error)),
            error => error,
        }
    }

    pub(super) fn has_armed_child(&self) -> bool {
        self.guard.as_ref().is_some_and(|guard| guard.armed)
    }

    pub(super) fn into_ordinary_error(mut self) -> Error {
        let error = match self.error.take() {
            Some(error) => error,
            None => std::process::abort(),
        };
        drop(self);
        error
    }

    fn retire_success_setup(&mut self) {
        // The exact child/readers have already moved into SpawnedProcess.
        // These are the original shadowed/borrow-only parent setup aliases,
        // which ordinary spawn released when its closure returned.
        drop(self.executable.take());
        self.inherited.clear();
        drop(self.supplied_stdin.take());
        drop(self.stderr_write.take());
        drop(self.stdout_write.take());
        drop(self.null.take());
    }
}

impl std::fmt::Debug for FixedProcessSpawnFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("FixedProcessSpawnFailureV2")
            .field("error", &self.error).field("armed_child", &self.has_armed_child())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for FixedProcessSpawnFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.error {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("fixed spawn setup is incomplete"),
        }
    }
}

impl std::error::Error for FixedProcessSpawnFailureV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.as_ref().map(|error| error as _)
    }
}

// These are the exact owning setup fields populated by spawn_body_v2
// before capture_before_path_spawn. Path execution adds no executable alias.
pub(super) fn path_setup_files_data_v3(
    supplied_stdin: bool,
    inherited: usize,
) -> Option<usize> {
    if inherited > MAXIMUM_INHERITED_DESCRIPTORS {
        return None;
    }
    [
        "null", "stdout_read", "stdout_write", "stderr_read",
        "stderr_write", "null_high", "stdout_high", "stderr_high",
    ].len()
        .checked_add(usize::from(supplied_stdin))?
        .checked_add(inherited)
}

fn held<T>(slot: &Option<T>) -> &T {
    match slot { Some(value) => value, None => std::process::abort() }
}

fn take<T>(slot: &mut Option<T>) -> T {
    match slot.take() { Some(value) => value, None => std::process::abort() }
}

pub(super) fn spawn_into_original_v2(
    invocation: &PreparedInvocation,
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
    execution: SpawnExecution<'_>,
    storage_observation: Option<&mut StorageWorkerForkObservationV1>,
    original: &mut FixedProcessSpawnFailureV2,
) -> std::result::Result<SpawnedProcess, ()> {
    spawn_into_original_capture_v3(invocation, stdin, inherited, execution, storage_observation, original, None)
}

pub(super) fn spawn_into_original_capture_v3(
    invocation: &PreparedInvocation,
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
    execution: SpawnExecution<'_>,
    storage_observation: Option<&mut StorageWorkerForkObservationV1>,
    original: &mut FixedProcessSpawnFailureV2,
    capture: Option<FixedProcessCaptureCutV3>,
) -> std::result::Result<SpawnedProcess, ()> {
    spawn_into_original_worker_capture_v4(
        invocation,
        stdin,
        inherited,
        execution,
        storage_observation.map(WorkerForkObservationBorrowV4::Storage),
        original,
        capture,
    )
}

pub(super) fn spawn_into_original_worker_capture_v4(
    invocation: &PreparedInvocation,
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
    execution: SpawnExecution<'_>,
    observation: Option<WorkerForkObservationBorrowV4<'_>>,
    original: &mut FixedProcessSpawnFailureV2,
    capture: Option<FixedProcessCaptureCutV3>,
) -> std::result::Result<SpawnedProcess, ()> {
    if original.entered {
        return Err(());
    }
    original.entered = true;
    match spawn_body_v2(
        invocation,
        stdin,
        inherited,
        execution,
        observation,
        original,
        capture,
    ) {
        Ok(spawned) => {
            original.retire_success_setup();
            Ok(spawned)
        }
        Err(error) => {
            original.error = Some(error);
            if capture.is_some() && original.capture_clock.failure().is_some() {
                if let Some(guard) = original.guard.as_mut().filter(|guard| guard.armed) {
                    original.capture_cleanup = Some(guard.cancel_and_reap());
                }
            }
            Err(())
        }
    }
}

fn spawn_body_v2(
    invocation: &PreparedInvocation,
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
    execution: SpawnExecution<'_>,
    observation: Option<WorkerForkObservationBorrowV4<'_>>,
    original: &mut FixedProcessSpawnFailureV2,
    capture: Option<FixedProcessCaptureCutV3>,
) -> Result<SpawnedProcess> {
    original.null = Some(rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ).map_err(|error| kernel_error("open(/dev/null)", error))?);
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|error| kernel_error("pipe(fixed stdout)", error))?;
    original.stdout_read = Some(read);
    original.stdout_write = Some(write);
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|error| kernel_error("pipe(fixed stderr)", error))?;
    original.stderr_read = Some(read);
    original.stderr_write = Some(write);
    original.null_high = Some(duplicate_high(held(&original.null).as_fd())?);
    original.stdout_high = Some(duplicate_high(held(&original.stdout_write).as_fd())?);
    original.stderr_high = Some(duplicate_high(held(&original.stderr_write).as_fd())?);
    original.supplied_stdin = stdin.map(duplicate_high).transpose()?;
    original.inherited = Vec::with_capacity(inherited.len());
    for descriptor in inherited {
        original.inherited.push(duplicate_high(*descriptor)?);
    }
    original.executable = match execution {
        SpawnExecution::Path => None,
        SpawnExecution::Descriptor(descriptor)
        | SpawnExecution::PendingDescriptor(descriptor, _, _) => Some(duplicate_high(descriptor)?),
    };

    let mut spawn = || {
        let stdin = original.supplied_stdin.as_ref()
            .map_or_else(|| held(&original.null_high).as_fd(), |descriptor| descriptor.as_fd());
        let inherited = original.inherited.iter().map(|descriptor| descriptor.as_fd())
            .collect::<Vec<_>>();
        if let Some(cut) = capture { original.capture_clock.observe(cut)?; }
        let native = (|| -> Result<_> {
            Ok(match (execution, original.executable.as_ref()) {
            (SpawnExecution::PendingDescriptor(_, recipe, cut), Some(executable)) => {
                if let Some(cut) = cut { cut.check()?; }
                let pending = uapi::begin_fixed_execveat_with_recipe(
                    executable.as_fd(), &invocation.argument_zero, &invocation.arguments,
                    stdin, held(&original.stdout_high).as_fd(), held(&original.stderr_high).as_fd(),
                    &inherited, recipe,
                )?;
                let (mut raw_guard, status) = pending.into_parts();
                let guard = ChildGuard::new(raw_guard.pid()?);
                raw_guard.disarm();
                (guard, Some(status))
            }
            (_, Some(executable)) => {
                let pid = uapi::fork_execveat_fixed_without_authority(
                    executable.as_fd(), &invocation.argument_zero, &invocation.arguments,
                    stdin, held(&original.stdout_high).as_fd(), held(&original.stderr_high).as_fd(),
                    &inherited,
                )?;
                (ChildGuard::new(pid), None)
            }
            (_, None) => {
                let pid = uapi::posix_spawn_fixed_capture_v3(
                    &invocation.executable, &invocation.argument_zero, &invocation.arguments,
                    stdin, held(&original.stdout_high).as_fd(), held(&original.stderr_high).as_fd(),
                    &inherited, capture.map(|cut| (cut, &mut original.capture_clock)),
                )?;
                (ChildGuard::new(pid), None)
            }
            })
        })();
        match native {
            Ok((guard, exec_status)) => {
                // Park every owning return before the independently owed
                // after-clock, including raw exec status and child custody.
                original.guard = Some(guard);
                original.exec_status = exec_status;
            }
            Err(error) => {
                if let Some(cut) = capture { let _ = original.capture_clock.observe(cut); }
                return Err(error);
            }
        }
        if let Some(cut) = capture { original.capture_clock.observe(cut)?; }
        drop(inherited);
        drop(original.null_high.take());
        drop(original.stdout_high.take());
        drop(original.stderr_high.take());
        if original.exec_status.is_none() {
            let raw_pid = u32::try_from(held(&original.guard).pid.as_raw_nonzero().get())
                .ok().and_then(NonZeroU32::new)
                .ok_or_else(|| Error::invalid("fixed process PID", "must be a positive u32"))?;
            original.raw_pidfd = Some(aos_linux_descriptors::native::pidfd_open(raw_pid.get())?);
            let pidfd = PidFd::adopt_owned_slot_v2(&mut original.raw_pidfd)?;
            match original.guard.as_mut() {
                Some(guard) => guard.attach_pidfd(pidfd),
                None => std::process::abort(),
            }
        }
        Ok(SpawnedProcess {
            guard: take(&mut original.guard),
            stdout: take(&mut original.stdout_read),
            stderr: take(&mut original.stderr_read),
            exec_status: original.exec_status.take(),
        })
    };
    match observation {
        Some(mut observation) => crate::startup_fd_table::with_blocked_signals(|| {
            observation.capture_before_path_spawn()?;
            spawn()
        }),
        None => spawn(),
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn network_census_refusal_retains_the_actual_shared_spawn_setup() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::spawn_original::tests::network_census_spawn_case",
                "--nocapture",
            ])
            .env("AOS_NETWORK_CENSUS_SPAWN_CASE_V4", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn network_census_spawn_case() {
        if std::env::var_os("AOS_NETWORK_CENSUS_SPAWN_CASE_V4").is_none() {
            return;
        }
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(127),
                maximum: Some(128),
            },
        )
        .unwrap();
        let request = FixedProcessRequest {
            executable: Path::new("/aos/no-spawn-after-network-census-refusal"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 64,
            maximum_stderr_bytes: 64,
        };
        let invocation = PreparedInvocation::new(request).unwrap();
        let mut census = NetworkWorkerForkObservationV4::new();
        let mut original = FixedProcessSpawnFailureV2::new();
        assert!(
            spawn_into_original_worker_capture_v4(
                &invocation,
                None,
                &[],
                SpawnExecution::Path,
                Some(WorkerForkObservationBorrowV4::Network(&mut census)),
                &mut original,
                None,
            )
            .is_err()
        );
        assert!(!original.has_armed_child());
        let returned = original.failure().unwrap();
        let saved = census.failure_for_returned_v4(returned).unwrap()
            as *const dyn std::error::Error as *const ();
        for descriptor in [
            &original.null,
            &original.stdout_read,
            &original.stdout_write,
            &original.stderr_read,
            &original.stderr_write,
            &original.null_high,
            &original.stdout_high,
            &original.stderr_high,
        ] {
            assert!(rustix::fs::fstat(descriptor.as_ref().unwrap().as_fd()).is_ok());
        }
        assert!(
            spawn_into_original_worker_capture_v4(
                &invocation,
                None,
                &[],
                SpawnExecution::Path,
                None,
                &mut original,
                None,
            )
            .is_err()
        );
        assert_eq!(
            census
                .failure_for_returned_v4(original.failure().unwrap())
                .unwrap() as *const dyn std::error::Error as *const (),
            saved
        );
    }

    #[test]
    fn descriptor_absolute_cut_keeps_same_stdin_and_partial_inherited_aliases() {
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/null").unwrap();
        let inherited = [first.as_fd(), second.as_fd()];
        let request = FixedProcessRequest {
            executable: Path::new("/aos/absent-descriptor-cut-fixture"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 64,
            maximum_stderr_bytes: 64,
        };
        let invocation = PreparedInvocation::new(request).unwrap();
        let boot = uapi::boottime_nanoseconds().unwrap();
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        let cut = FixedProcessCaptureCutV3::new(boot.saturating_sub(1).max(1), wall + 60).unwrap();
        let mut original = FixedProcessSpawnFailureV2::new();

        assert!(
            spawn_into_original_capture_v3(
                &invocation,
                Some(first.as_fd()),
                &inherited,
                SpawnExecution::Path,
                None,
                &mut original,
                Some(cut)
            )
            .is_err()
        );
        assert!(capture_cut::is_marker(original.failure().unwrap()));
        assert!(original.guard.is_none());
        assert_eq!(original.inherited.len(), 2);
        let source = rustix::fs::fstat(&first).unwrap();
        let held_stdin = original.supplied_stdin.as_ref().unwrap();
        assert_ne!(held_stdin.as_raw_fd(), first.as_raw_fd());
        assert_eq!(rustix::fs::fstat(held_stdin).unwrap().st_ino, source.st_ino);
        for (held, source) in original.inherited.iter().zip([&first, &second]) {
            assert_ne!(held.as_raw_fd(), source.as_raw_fd());
            let held_stat = rustix::fs::fstat(held).unwrap();
            let source_stat = rustix::fs::fstat(source).unwrap();
            assert_eq!(
                (held_stat.st_dev, held_stat.st_ino),
                (source_stat.st_dev, source_stat.st_ino)
            );
        }
        let cause = std::ptr::from_ref(original.failure().unwrap());
        assert!(
            spawn_into_original_capture_v3(
                &invocation,
                Some(first.as_fd()),
                &inherited,
                SpawnExecution::Path,
                None,
                &mut original,
                Some(cut)
            )
            .is_err()
        );
        assert_eq!(cause, std::ptr::from_ref(original.failure().unwrap()));
        assert_eq!(original.inherited.len(), 2);
    }

    #[test]
    fn expired_capture_cut_refuses_before_the_actual_spawn_and_keeps_setup() {
        let request = FixedProcessRequest {
            executable: Path::new("/aos/absent-capture-cut-fixture"),
            arguments: &[], timeout: Duration::from_secs(60),
            maximum_stdout_bytes: 4096, maximum_stderr_bytes: 4096,
        };
        let invocation = PreparedInvocation::new(request).unwrap();
        let boot = uapi::boottime_nanoseconds().unwrap();
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        let cuts = [
            FixedProcessCaptureCutV3::new(boot.saturating_sub(1).max(1), wall + 60).unwrap(),
            FixedProcessCaptureCutV3::new(boot.checked_add(60_000_000_000).unwrap(), wall - 1).unwrap(),
        ];
        for cut in cuts {
            let mut original = FixedProcessSpawnFailureV2::new();

            let result = spawn_into_original_capture_v3(&invocation, None, &[],
                SpawnExecution::Path, None, &mut original, Some(cut));

            assert!(result.is_err());
            assert!(capture_cut::is_marker(original.failure().unwrap()));
            assert!(original.guard.is_none());
            assert!(original.stdout_read.is_some());
            assert!(original.stderr_read.is_some());
            assert!(original.stdout_high.is_some());
            assert!(original.stderr_high.is_some());
        }
    }

    #[test]
    fn missing_executable_keeps_actual_pipe_and_high_alias_prefix_on_reentry() {
        let request = FixedProcessRequest {
            executable: Path::new("/aos/absent-capture-helper-for-native-custody-test"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 4096,
            maximum_stderr_bytes: 4096,
        };
        let invocation = PreparedInvocation::new(request).unwrap();
        let mut original = FixedProcessSpawnFailureV2::new();
        assert!(spawn_into_original_v2(
            &invocation, None, &[], SpawnExecution::Path, None, &mut original,
        ).is_err());

        let cause = std::ptr::from_ref(original.failure().unwrap());
        let stdout = original.stdout_read.as_ref().unwrap().as_raw_fd();
        let stderr = original.stderr_read.as_ref().unwrap().as_raw_fd();
        assert_ne!(stdout, stderr);
        for descriptor in [
            &original.null, &original.stdout_read, &original.stdout_write,
            &original.stderr_read, &original.stderr_write, &original.null_high,
            &original.stdout_high, &original.stderr_high,
        ] {
            assert!(rustix::fs::fcntl_getfl(descriptor.as_ref().unwrap()).is_ok());
        }
        assert!(!original.has_armed_child());

        assert!(spawn_into_original_v2(
            &invocation, None, &[], SpawnExecution::Path, None, &mut original,
        ).is_err());
        assert_eq!(std::ptr::from_ref(original.failure().unwrap()), cause);
        assert_eq!(original.stdout_read.as_ref().unwrap().as_raw_fd(), stdout);
        assert_eq!(original.stderr_read.as_ref().unwrap().as_raw_fd(), stderr);
    }
}
