//! Combined Linux process and storage ownership for one QEMU attempt.
//!
//! This module is the only public Linux facade that can satisfy a complete
//! attempt host-resource boundary. It pairs one sealed cgroup process owner
//! with one pinned ext4 project-quota/run-directory owner, exposes only the
//! child launch and cancellation capabilities, and orders storage cleanup
//! strictly after process reap. Failed cleanup transfers both authorities to a
//! detached nondroppable worker; dropping its observation handle cannot release
//! either authority.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::Duration;

use crate::linux_attempt_process::{
    LinuxQemuAttemptCancellationSignal, LinuxQemuAttemptProcessConfig,
    LinuxQemuAttemptProcessFactory, LinuxQemuAttemptProcessOwner,
};
use crate::linux_attempt_storage::{
    LinuxQemuAttemptStorageConfig, LinuxQemuAttemptStorageError, LinuxQemuAttemptStorageFactory,
    LinuxQemuAttemptStorageOwner,
};
use crate::{
    LinuxQemuHotForkChildProcessAuthority, QemuChildProcessContract, QemuHotForkChildProcessBasis,
    QemuHotForkChildProcessOwner, QemuLaunchResourceRequirements, QemuNodeChannelError,
    QemuNodeChild, QemuPreparedRunDirectory, QemuVmRealizationError,
};
use crucible_linux_resource::LinuxProjectQuotaError;

const HOST_QUARANTINE_MIN_RETRY: Duration = Duration::from_millis(10);
const HOST_QUARANTINE_MAX_RETRY: Duration = Duration::from_secs(1);
const HOST_QUARANTINE_RUNNING: u8 = 0;
const HOST_QUARANTINE_RELEASED: u8 = 1;
const HOST_QUARANTINE_PARKED: u8 = 2;

/// Validated configuration for one combined Linux QEMU attempt namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxQemuAttemptHostConfig {
    process: LinuxQemuAttemptProcessConfig,
    storage: LinuxQemuAttemptStorageConfig,
}

impl LinuxQemuAttemptHostConfig {
    /// Validates one paired cgroup and project-quota namespace.
    ///
    /// The same daemon-incarnation name and distinct non-root child credentials
    /// are sealed into both allocators. Validation completes before either path
    /// is accessed.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Executor`] when any namespace,
    /// credential, task, project-ID, timeout, or inode bound is invalid.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cgroup_root: impl Into<PathBuf>,
        run_root: impl Into<PathBuf>,
        attempt_namespace: impl Into<String>,
        first_project_id: u32,
        project_id_count: u32,
        child_user_id: u32,
        child_group_id: u32,
        maximum_tasks: u32,
        maximum_inodes: u64,
        finish_timeout: Duration,
    ) -> Result<Self, QemuVmRealizationError> {
        let attempt_namespace = attempt_namespace.into();
        let process = LinuxQemuAttemptProcessConfig::new(
            cgroup_root,
            attempt_namespace.clone(),
            child_user_id,
            child_group_id,
            maximum_tasks,
            finish_timeout,
        )?;
        let storage = LinuxQemuAttemptStorageConfig::new(
            run_root,
            attempt_namespace,
            first_project_id,
            project_id_count,
            child_user_id,
            child_group_id,
            maximum_inodes,
        )
        .map_err(|error| map_storage_error("configure QEMU attempt storage", &error))?;
        Ok(Self { process, storage })
    }

    /// Returns the delegated cgroup-v2 root.
    #[must_use]
    pub fn cgroup_root(&self) -> &Path {
        self.process.cgroup_root()
    }

    /// Returns the private ext4 attempt run root.
    #[must_use]
    pub fn run_root(&self) -> &Path {
        self.storage.run_root()
    }

    /// Returns the shared daemon-incarnation namespace.
    #[must_use]
    pub fn attempt_namespace(&self) -> &str {
        self.process.attempt_namespace()
    }

    /// Returns the distinct unprivileged QEMU user identifier.
    #[must_use]
    pub const fn child_user_id(&self) -> u32 {
        self.process.child_user_id()
    }

    /// Returns the distinct unprivileged QEMU group identifier.
    #[must_use]
    pub const fn child_group_id(&self) -> u32 {
        self.process.child_group_id()
    }

    /// Returns the hard cgroup task ceiling.
    #[must_use]
    pub const fn maximum_tasks(&self) -> u32 {
        self.process.maximum_tasks()
    }

    /// Returns the hard attempt artifact-entry and inode ceiling.
    #[must_use]
    pub const fn maximum_inodes(&self) -> u64 {
        self.storage.maximum_inodes()
    }
}

/// Exclusive allocator for paired Linux QEMU process and storage owners.
#[derive(Debug)]
#[must_use = "the host allocator locks both namespaces for its lifetime"]
pub struct LinuxQemuAttemptHostFactory {
    process: LinuxQemuAttemptProcessFactory,
    storage: LinuxQemuAttemptStorageFactory,
    poisoned: bool,
}

impl LinuxQemuAttemptHostFactory {
    /// Opens, validates, and locks both configured host-resource roots.
    ///
    /// # Errors
    ///
    /// Returns a stable executor error for an invalid root policy and an
    /// availability error for host I/O or namespace contention.
    pub fn open(config: LinuxQemuAttemptHostConfig) -> Result<Self, QemuVmRealizationError> {
        let storage = LinuxQemuAttemptStorageFactory::open(config.storage)
            .map_err(|error| map_storage_error("open QEMU attempt-storage root", &error))?;
        let process = LinuxQemuAttemptProcessFactory::open(config.process)?;
        Ok(Self {
            process,
            storage,
            poisoned: false,
        })
    }

    /// Installs one indivisible process and writable-storage owner.
    ///
    /// Storage is installed before the cgroup contract can be exposed. Any
    /// partial failure transfers retained authority to nondroppable cleanup and
    /// poisons this allocator rather than permitting a mismatched retry.
    ///
    /// # Errors
    ///
    /// Returns a stable or availability error when either exact resource owner
    /// cannot be installed. A cleanup-transfer failure returns
    /// [`QemuVmRealizationError::ReapQuarantined`] after leaking the complete
    /// authority fail-closed.
    pub fn begin(
        &mut self,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Result<LinuxQemuAttemptHostOwner, QemuVmRealizationError> {
        if self.poisoned || self.process.is_poisoned() {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "create QEMU attempt host owner",
                message: String::from("combined host-resource allocator is poisoned"),
            });
        }

        let storage = match self.storage.begin(maximum_writable_bytes) {
            Ok(storage) => storage,
            Err(error) => {
                let mapped = map_storage_error("create QEMU attempt storage", error.source_error());
                if let Some(storage) = error.into_owner() {
                    self.poisoned = true;
                    transfer_setup_cleanup(None, Some(storage))?;
                }
                return Err(mapped);
            }
        };
        let process = match self.process.begin(
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
        ) {
            Ok(process) => process,
            Err(error) => {
                self.poisoned = true;
                transfer_setup_cleanup(None, Some(storage))?;
                return Err(error);
            }
        };

        Ok(LinuxQemuAttemptHostOwner {
            process: Some(process),
            storage: Some(storage),
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            quarantine: None,
            terminal: false,
        })
    }

    /// Returns whether a retained partial setup closed this allocator.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

/// Indivisible Linux process and writable-storage authority for one attempt.
#[derive(Debug)]
#[must_use = "finish the host owner or transfer it to nondroppable quarantine"]
pub struct LinuxQemuAttemptHostOwner {
    process: Option<LinuxQemuAttemptProcessOwner>,
    storage: Option<LinuxQemuAttemptStorageOwner>,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_writable_bytes: u64,
    quarantine: Option<LinuxQemuAttemptHostQuarantine>,
    terminal: bool,
}

trait AttemptProcessCleanup {
    fn finish_process(&mut self) -> Result<(), QemuVmRealizationError>;
}

trait AttemptStorageCleanup: Sized {
    fn cleanup_storage(self) -> Result<(), (Self, QemuVmRealizationError)>;
}

impl AttemptProcessCleanup for LinuxQemuAttemptProcessOwner {
    fn finish_process(&mut self) -> Result<(), QemuVmRealizationError> {
        self.finish()
    }
}

impl AttemptStorageCleanup for LinuxQemuAttemptStorageOwner {
    fn cleanup_storage(self) -> Result<(), (Self, QemuVmRealizationError)> {
        self.cleanup_and_release().map_err(|error| {
            let mapped = map_storage_error("release QEMU attempt storage", error.source_error());
            (error.into_owner(), mapped)
        })
    }
}

fn finish_owned_resources<P, S>(
    process: &mut Option<P>,
    storage: &mut Option<S>,
) -> Result<(), QemuVmRealizationError>
where
    P: AttemptProcessCleanup,
    S: AttemptStorageCleanup,
{
    if let Some(process) = process.as_mut() {
        process.finish_process()?;
    }
    *process = None;

    if let Some(owner) = storage.take()
        && let Err((owner, error)) = owner.cleanup_storage()
    {
        *storage = Some(owner);
        return Err(error);
    }
    Ok(())
}

impl LinuxQemuAttemptHostOwner {
    /// Returns the exact CPU, memory, and aggregate writable-byte ceiling.
    #[must_use]
    pub const fn resource_ceiling(&self) -> (u32, u64, u64) {
        (
            self.maximum_vcpus,
            self.maximum_resident_bytes,
            self.maximum_writable_bytes,
        )
    }

    /// Returns the exact pinned aggregate attempt-root path for diagnostics.
    ///
    /// Callers must not reopen this path as authority. Later launch composition
    /// consumes generation capabilities derived from the descriptor-pinned
    /// aggregate storage authority retained here.
    ///
    /// # Errors
    ///
    /// Returns an executor error after storage authority moved to quarantine.
    pub fn run_directory(&self) -> Result<&Path, QemuVmRealizationError> {
        self.storage
            .as_ref()
            .map(LinuxQemuAttemptStorageOwner::path)
            .ok_or_else(|| missing_authority("read QEMU attempt run directory"))
    }

    /// Returns the sealed child launch contract while the owner is active.
    ///
    /// # Errors
    ///
    /// Returns an operational error after cancellation or terminal cleanup.
    pub fn process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.process
            .as_ref()
            .ok_or_else(|| missing_authority("lend QEMU child process contract"))?
            .process_contract()
    }

    /// Provisions and lends the descriptor-pinned run-directory authority.
    ///
    /// The exact launch profile is admitted before the retained storage owner
    /// creates a fresh monotone generation directory and its empty exact-VMState
    /// destination. Raw attempt-root and quota authority never leave this
    /// combined owner. Every issued generation shares the one aggregate quota
    /// and remains inside the owner's bounded cleanup tree.
    ///
    /// # Errors
    ///
    /// Returns a stable executor error when the launch basis, retained storage
    /// identity, monotone generation sequence, or VMState policy fails. Host
    /// I/O failures are reported as unavailable.
    pub fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        if self.terminal {
            return Err(missing_authority("prepare QEMU attempt run directory"));
        }
        let (process, storage) = match (&self.process, &mut self.storage) {
            (Some(process), Some(storage)) => (process, storage),
            _ => return Err(missing_authority("prepare QEMU attempt run directory")),
        };
        let contract = process.process_contract()?;
        storage
            .prepare_generation_run_directory(requirements, contract)
            .map_err(|error| map_storage_error("prepare QEMU attempt run directory", &error))
    }

    /// Duplicates the narrow sticky process-cancellation capability.
    ///
    /// # Errors
    ///
    /// Returns an operational error after terminal cleanup or descriptor
    /// duplication failure.
    pub fn cancellation_signal(
        &self,
    ) -> Result<LinuxQemuAttemptCancellationSignal, QemuVmRealizationError> {
        self.process
            .as_ref()
            .ok_or_else(|| missing_authority("duplicate QEMU cancellation signal"))?
            .cancellation_signal()
    }

    /// Verifies that both host authorities remain live at an operational boundary.
    ///
    /// # Errors
    ///
    /// Returns an executor error after cancellation, cleanup, or quarantine.
    pub fn check_operational_boundary(&self) -> Result<(), QemuVmRealizationError> {
        if self.terminal || self.storage.is_none() {
            return Err(missing_authority("check QEMU attempt host resources"));
        }
        self.process_contract().map(|_| ())
    }

    /// Retains a failed launch's nonduplicable direct-child wait authority.
    pub fn retain_failed_child(&mut self, child: QemuNodeChild) {
        if let Some(process) = self.process.as_mut() {
            process.retain_failed_child(child);
        } else {
            let _leaked = Box::leak(Box::new(child));
        }
    }

    /// Reaps every process, then removes artifacts and releases storage.
    ///
    /// # Errors
    ///
    /// Returns an operational error while retaining both owners for exact
    /// quarantine transfer. Success attests process reap before storage release.
    pub fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.terminal {
            return match self
                .quarantine
                .as_ref()
                .map(LinuxQemuAttemptHostQuarantine::status)
            {
                Some(LinuxQemuAttemptHostQuarantineStatus::Released) | None => Ok(()),
                Some(
                    LinuxQemuAttemptHostQuarantineStatus::Running
                    | LinuxQemuAttemptHostQuarantineStatus::Parked,
                ) => Err(QemuVmRealizationError::ReapQuarantined {
                    operation: "finish QEMU attempt host resources",
                    message: String::from("combined cleanup remains in quarantine"),
                }),
            };
        }
        finish_owned_resources(&mut self.process, &mut self.storage)?;
        self.terminal = true;
        Ok(())
    }

    /// Transfers both enforcement authorities to nondroppable quarantine.
    pub fn quarantine(&mut self) {
        if self.terminal {
            return;
        }
        let state = LinuxQemuAttemptHostQuarantineState {
            process: self.process.take(),
            storage: self.storage.take(),
        };
        match start_quarantine_worker(state) {
            Ok(quarantine) => self.quarantine = Some(quarantine),
            Err((_source, Some(state))) => {
                let _leaked = Box::leak(Box::new(state));
            }
            Err((_source, None)) => {}
        }
        self.terminal = true;
    }
}

impl QemuHotForkChildProcessOwner for LinuxQemuAttemptHostOwner {
    type Authority = LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        if self.terminal || self.storage.is_none() {
            return Err(QemuNodeChannelError::new(
                "retain forked child process",
                "combined attempt host authority is terminal",
            ));
        }
        self.process
            .as_mut()
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "retain forked child process",
                    "combined attempt host retains no process authority",
                )
            })?
            .retain_hot_fork_child(basis)
    }
}

impl Drop for LinuxQemuAttemptHostOwner {
    fn drop(&mut self) {
        self.quarantine();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxQemuAttemptHostQuarantineStatus {
    Running,
    Released,
    Parked,
}

#[derive(Debug)]
struct LinuxQemuAttemptHostQuarantine {
    status: Arc<AtomicU8>,
}

impl LinuxQemuAttemptHostQuarantine {
    fn status(&self) -> LinuxQemuAttemptHostQuarantineStatus {
        match self.status.load(Ordering::Acquire) {
            HOST_QUARANTINE_RELEASED => LinuxQemuAttemptHostQuarantineStatus::Released,
            HOST_QUARANTINE_PARKED => LinuxQemuAttemptHostQuarantineStatus::Parked,
            _ => LinuxQemuAttemptHostQuarantineStatus::Running,
        }
    }
}

#[derive(Debug)]
struct LinuxQemuAttemptHostQuarantineState {
    process: Option<LinuxQemuAttemptProcessOwner>,
    storage: Option<LinuxQemuAttemptStorageOwner>,
}

trait HostQuarantineWork: Send + 'static {
    type Error;

    fn reap_and_release(&mut self) -> Result<(), Self::Error>;
}

impl HostQuarantineWork for LinuxQemuAttemptHostQuarantineState {
    type Error = QemuVmRealizationError;

    fn reap_and_release(&mut self) -> Result<(), Self::Error> {
        finish_owned_resources(&mut self.process, &mut self.storage)
    }
}

fn transfer_setup_cleanup(
    process: Option<LinuxQemuAttemptProcessOwner>,
    storage: Option<LinuxQemuAttemptStorageOwner>,
) -> Result<(), QemuVmRealizationError> {
    let state = LinuxQemuAttemptHostQuarantineState { process, storage };
    match start_quarantine_worker(state) {
        Ok(quarantine) => {
            drop(quarantine);
            Ok(())
        }
        Err((source, Some(state))) => {
            let _leaked = Box::leak(Box::new(state));
            Err(QemuVmRealizationError::ReapQuarantined {
                operation: "transfer partial QEMU host setup to quarantine",
                message: source.to_string(),
            })
        }
        Err((source, None)) => Err(QemuVmRealizationError::ReapQuarantined {
            operation: "transfer partial QEMU host setup to quarantine",
            message: source.to_string(),
        }),
    }
}

fn start_quarantine_worker<W>(
    work: W,
) -> Result<LinuxQemuAttemptHostQuarantine, (io::Error, Option<W>)>
where
    W: HostQuarantineWork,
{
    let authority = Arc::new(std::sync::Mutex::new(Some(work)));
    let worker_authority = Arc::clone(&authority);
    let status = Arc::new(AtomicU8::new(HOST_QUARANTINE_RUNNING));
    let worker_status = Arc::clone(&status);
    let spawn = thread::Builder::new()
        .name(String::from("crucible-qemu-host-quarantine"))
        .spawn(move || {
            let mut work = {
                let mut authority = match worker_authority.lock() {
                    Ok(authority) => authority,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match authority.take() {
                    Some(work) => work,
                    None => return,
                }
            };
            let mut retry = HOST_QUARANTINE_MIN_RETRY;
            loop {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    work.reap_and_release()
                })) {
                    Ok(Ok(())) => {
                        worker_status.store(HOST_QUARANTINE_RELEASED, Ordering::Release);
                        return;
                    }
                    Ok(Err(_)) => {
                        thread::sleep(retry);
                        retry = retry.saturating_mul(2).min(HOST_QUARANTINE_MAX_RETRY);
                    }
                    Err(_) => {
                        worker_status.store(HOST_QUARANTINE_PARKED, Ordering::Release);
                        loop {
                            thread::park();
                        }
                    }
                }
            }
        });
    if let Err(source) = spawn {
        let work = match Arc::try_unwrap(authority) {
            Ok(authority) => match authority.into_inner() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            },
            Err(authority) => {
                let _leaked = Arc::into_raw(authority);
                None
            }
        };
        return Err((source, work));
    }
    drop(authority);
    Ok(LinuxQemuAttemptHostQuarantine { status })
}

fn missing_authority(operation: &'static str) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: String::from("combined attempt host authority is terminal"),
    }
}

fn map_storage_error(
    operation: &'static str,
    error: &LinuxQemuAttemptStorageError,
) -> QemuVmRealizationError {
    let unavailable = matches!(
        error,
        LinuxQemuAttemptStorageError::NamespaceLocked { .. }
            | LinuxQemuAttemptStorageError::ProjectIdsExhausted
            | LinuxQemuAttemptStorageError::Io { .. }
            | LinuxQemuAttemptStorageError::ProjectQuota(LinuxProjectQuotaError::Io { .. })
    );
    if unavailable {
        QemuVmRealizationError::ExecutorUnavailable {
            operation,
            message: error.to_string(),
        }
    } else {
        QemuVmRealizationError::Executor {
            operation,
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    #![allow(clippy::expect_used)]

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use rustix::process::geteuid;

    use super::*;
    use crate::spawn::QemuChildCredentials;

    fn test_child_id() -> u32 {
        (100_000..100_128)
            .find(|candidate| QemuChildCredentials::new(*candidate, *candidate).is_ok())
            .expect("one test child identity must differ from supervisor credentials")
    }

    #[test]
    fn configuration_is_exact_and_rejects_before_path_access() {
        let child_id = test_child_id();
        let config = LinuxQemuAttemptHostConfig::new(
            "/missing/cgroup",
            "/missing/storage",
            "daemon_1",
            10_000,
            8,
            child_id,
            child_id,
            64,
            4096,
            Duration::from_secs(1),
        )
        .expect("valid host configuration does not access paths");
        assert_eq!(config.cgroup_root(), Path::new("/missing/cgroup"));
        assert_eq!(config.run_root(), Path::new("/missing/storage"));
        assert_eq!(config.attempt_namespace(), "daemon_1");
        assert_eq!(config.child_user_id(), child_id);
        assert_eq!(config.child_group_id(), child_id);
        assert_eq!(config.maximum_tasks(), 64);
        assert_eq!(config.maximum_inodes(), 4096);

        assert!(
            LinuxQemuAttemptHostConfig::new(
                "/missing/cgroup",
                "/missing/storage",
                "daemon",
                1,
                1,
                geteuid().as_raw(),
                child_id,
                1,
                1,
                Duration::from_secs(1),
            )
            .is_err()
        );
    }

    struct FakeQuarantineWork {
        attempts: Arc<AtomicUsize>,
        completed: Arc<AtomicBool>,
        remaining_failures: usize,
    }

    struct PanickingQuarantineWork {
        dropped: Arc<AtomicBool>,
    }

    struct FakeProcessCleanup {
        events: Arc<Mutex<Vec<&'static str>>>,
        fail_once: bool,
    }

    struct FakeStorageCleanup {
        events: Arc<Mutex<Vec<&'static str>>>,
        fail_once: bool,
    }

    impl AttemptProcessCleanup for FakeProcessCleanup {
        fn finish_process(&mut self) -> Result<(), QemuVmRealizationError> {
            self.events.lock().expect("event log").push("process");
            if self.fail_once {
                self.fail_once = false;
                return Err(QemuVmRealizationError::ExecutorUnavailable {
                    operation: "finish fake process",
                    message: String::from("retry process reap"),
                });
            }
            Ok(())
        }
    }

    impl AttemptStorageCleanup for FakeStorageCleanup {
        fn cleanup_storage(mut self) -> Result<(), (Self, QemuVmRealizationError)> {
            self.events.lock().expect("event log").push("storage");
            if self.fail_once {
                self.fail_once = false;
                return Err((
                    self,
                    QemuVmRealizationError::ExecutorUnavailable {
                        operation: "finish fake storage",
                        message: String::from("retry storage cleanup"),
                    },
                ));
            }
            Ok(())
        }
    }

    impl HostQuarantineWork for FakeQuarantineWork {
        type Error = ();

        fn reap_and_release(&mut self) -> Result<(), Self::Error> {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            if self.remaining_failures != 0 {
                self.remaining_failures -= 1;
                return Err(());
            }
            self.completed.store(true, Ordering::Release);
            Ok(())
        }
    }

    impl HostQuarantineWork for PanickingQuarantineWork {
        type Error = ();

        fn reap_and_release(&mut self) -> Result<(), Self::Error> {
            panic!("forced combined quarantine invariant panic");
        }
    }

    impl Drop for PanickingQuarantineWork {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn retry_delay_is_bounded_and_dropped_observation_cannot_stop_work() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicBool::new(false));
        let quarantine = start_quarantine_worker(FakeQuarantineWork {
            attempts: Arc::clone(&attempts),
            completed: Arc::clone(&completed),
            remaining_failures: 2,
        })
        .map_err(|(error, _)| error)
        .expect("start combined quarantine worker");
        let status = Arc::clone(&quarantine.status);
        drop(quarantine);

        for _ in 0..100 {
            if completed.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(attempts.load(Ordering::Acquire), 3);
        assert_eq!(status.load(Ordering::Acquire), HOST_QUARANTINE_RELEASED);
    }

    #[test]
    fn invariant_panic_parks_without_dropping_combined_authority() {
        let dropped = Arc::new(AtomicBool::new(false));
        let quarantine = start_quarantine_worker(PanickingQuarantineWork {
            dropped: Arc::clone(&dropped),
        })
        .map_err(|(error, _)| error)
        .expect("start combined quarantine worker");

        for _ in 0..100 {
            if quarantine.status() == LinuxQemuAttemptHostQuarantineStatus::Parked {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            quarantine.status(),
            LinuxQemuAttemptHostQuarantineStatus::Parked
        );
        drop(quarantine);
        thread::sleep(Duration::from_millis(20));
        assert!(!dropped.load(Ordering::Acquire));
    }

    #[test]
    fn storage_cleanup_waits_for_reap_and_each_failure_retains_exact_retry() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut process = Some(FakeProcessCleanup {
            events: Arc::clone(&events),
            fail_once: true,
        });
        let mut storage = Some(FakeStorageCleanup {
            events: Arc::clone(&events),
            fail_once: true,
        });

        assert!(finish_owned_resources(&mut process, &mut storage).is_err());
        assert!(process.is_some());
        assert!(storage.is_some());
        assert_eq!(*events.lock().expect("event log"), ["process"]);

        assert!(finish_owned_resources(&mut process, &mut storage).is_err());
        assert!(process.is_none());
        assert!(storage.is_some());
        assert_eq!(
            *events.lock().expect("event log"),
            ["process", "process", "storage"]
        );

        finish_owned_resources(&mut process, &mut storage).expect("exact cleanup retry");
        assert!(process.is_none());
        assert!(storage.is_none());
        assert_eq!(
            *events.lock().expect("event log"),
            ["process", "process", "storage", "storage"]
        );
    }
}
