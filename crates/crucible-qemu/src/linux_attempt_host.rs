//! Combined Linux process and storage ownership for one QEMU attempt.
//!
//! This module is the only public Linux facade that can satisfy a complete
//! attempt host-resource boundary. It pairs one sealed cgroup process owner
//! with one pinned ext4 project-quota/run-directory owner, exposes only the
//! child launch and cancellation capabilities, and orders storage cleanup
//! strictly after process reap. Ordinary failed cleanup transfers both authorities
//! to a detached nondroppable worker. The private original-bound route retains
//! those authorities in its existing paid roster for guarded cleanup retry.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod configuration;
pub use configuration::LinuxQemuAttemptHostConfig;

mod native_resources;
#[cfg(feature = "private-measurement-domain")]
pub(crate) mod parent_setup;
#[cfg(feature = "private-measurement-domain")]
pub(crate) use parent_setup::OriginalParentSetup;
#[cfg(feature = "private-measurement-domain")]
mod original_actor;
#[cfg(feature = "private-measurement-domain")]
mod original_host;
#[cfg(feature = "private-measurement-domain")]
mod original_roster;
use native_resources::NativeResourceState;
#[cfg(feature = "private-measurement-domain")]
pub use native_resources::OriginalNativeControlRetirement;
pub use native_resources::{LinuxQemuNativeResourceController, LinuxQemuNativeResourceError};
#[cfg(feature = "private-measurement-domain")]
pub use original_actor::{
    OriginalActorAccountCustody, OriginalActorAccountError, OriginalActorCatalogAccounts,
    OriginalActorCatalogPurpose, OriginalActorDecodeOwner, OriginalActorServicePolicy,
    OriginalCatalogAuditError, OriginalCatalogPhysicalAudit, OriginalGuestServiceHandle,
    OriginalGuestServiceOwner,
};
#[cfg(feature = "private-measurement-domain")]
pub use original_host::OriginalNativePhysicalRetirement;
#[cfg(feature = "private-measurement-domain")]
pub(crate) use original_roster::NativeAccountAttempt;
#[cfg(feature = "private-measurement-domain")]
pub use original_roster::{OriginalNativeAccountFactoryBinding, OriginalNativeAccountRoster};
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

/// Exclusive allocator for paired Linux QEMU process and storage owners.
#[derive(Debug)]
#[must_use = "the host allocator locks both namespaces for its lifetime"]
pub struct LinuxQemuAttemptHostFactory {
    process: LinuxQemuAttemptProcessFactory,
    storage: LinuxQemuAttemptStorageFactory,
    poisoned: bool,
    #[cfg(feature = "private-measurement-domain")]
    original_accounts: Option<OriginalNativeAccountFactoryBinding>,
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
            #[cfg(feature = "private-measurement-domain")]
            original_accounts: None,
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
        self.begin_with_checkpoint_root(
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            None,
        )
    }

    /// Installs resources born presealed to one supervisor-selected checkpoint.
    ///
    /// The caller must obtain `exact_checkpoint_root` from its current durable
    /// resume-selection claim. The returned process contract has no operation
    /// that can add or replace this root after construction.
    ///
    /// # Errors
    ///
    /// Returns a stable or availability error under the same conditions as
    /// [`Self::begin`].
    pub fn begin_exact_checkpoint(
        &mut self,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
        exact_checkpoint_root: crucible::ContentHash,
    ) -> Result<LinuxQemuAttemptHostOwner, QemuVmRealizationError> {
        self.begin_with_checkpoint_root(
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            Some(exact_checkpoint_root),
        )
    }

    fn begin_with_checkpoint_root(
        &mut self,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
        exact_checkpoint_root: Option<crucible::ContentHash>,
    ) -> Result<LinuxQemuAttemptHostOwner, QemuVmRealizationError> {
        if self.poisoned || self.process.is_poisoned() {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "create QEMU attempt host owner",
                message: String::from("combined host-resource allocator is poisoned"),
            });
        }

        #[cfg(feature = "private-measurement-domain")]
        if self.original_accounts.is_some() {
            return self.begin_original_with_checkpoint_root(
                maximum_vcpus,
                maximum_resident_bytes,
                maximum_writable_bytes,
                exact_checkpoint_root,
            );
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
            exact_checkpoint_root,
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
            native_resources: None,
            #[cfg(feature = "private-measurement-domain")]
            original_retirement_pinned: false,
            #[cfg(feature = "private-measurement-domain")]
            original_account: None,
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
    native_resources: Option<Arc<NativeResourceState>>,
    #[cfg(feature = "private-measurement-domain")]
    original_retirement_pinned: bool,
    #[cfg(feature = "private-measurement-domain")]
    original_account: Option<original_roster::NativeAccountAttempt>,
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

fn finish_native_owned_resources(
    process: &mut Option<LinuxQemuAttemptProcessOwner>,
    storage: &mut Option<LinuxQemuAttemptStorageOwner>,
    native_resources: &mut Option<Arc<NativeResourceState>>,
) -> Result<(), QemuVmRealizationError> {
    if let Some(process) = process.as_mut() {
        process.finish()?;
    }
    *process = None;
    if let Some(state) = native_resources.as_ref() {
        NativeResourceState::drain(state);
    }
    *native_resources = None;
    finish_owned_resources(process, storage)
}

impl LinuxQemuAttemptHostOwner {
    /// Joins the outer Parent using its same retained original process end.
    ///
    /// Native controllers belong to separately admitted attempt roles; the
    /// Parent path never creates one and refuses any foreign control alias.
    /// The caller retains this owner and its loan on every uncertain outcome.
    ///
    /// # Errors
    /// Refuses native aliases, an unfinished watcher, original expiry or storage
    /// cleanup failure without transferring custody to a new cleanup worker.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn finish_under_original_parent(
        &mut self,
        original: &crucible_linux_resource::host_services::process_birth::OriginalParentAttempt,
        setup: &mut crate::linux_attempt_host::OriginalParentSetup,
    ) -> Result<(), QemuVmRealizationError> {
        if setup.has_retained_cleanup()
            || self.native_resources.is_some()
            || self.original_retirement_pinned
            || self.quarantine.is_some()
            || self.original_account.is_some()
        {
            return Err(missing_authority(
                "original Parent has foreign native or quarantine aliases",
            ));
        }
        if let Some(process) = self.process.as_mut() {
            process.finish_under_original_parent(original, setup)?;
        }
        self.process = None;
        original
            .check_original()
            .map_err(|error| QemuVmRealizationError::Executor {
                operation: "original Parent storage cleanup",
                message: error.to_string(),
            })?;
        let cleanup = finish_owned_resources(&mut self.process, &mut self.storage);
        let post = original.check_original();
        cleanup?;
        post.map_err(|error| QemuVmRealizationError::Executor {
            operation: "original Parent storage cleanup",
            message: error.to_string(),
        })?;
        self.terminal = true;
        Ok(())
    }

    /// Lends weak concrete resource control for this exact live attempt.
    ///
    /// # Errors
    /// Refuses retired or uncertain physical authority and failed descriptor
    /// pinning. The returned handle cannot outlive cleanup or raise a ceiling.
    pub fn native_resource_controller(
        &mut self,
    ) -> Result<LinuxQemuNativeResourceController, QemuVmRealizationError> {
        self.check_operational_boundary()?;
        if self.native_resources.is_none() {
            let memory = self
                .process
                .as_ref()
                .ok_or_else(|| missing_authority("pin native memory controller"))?
                .memory_control();
            #[cfg(feature = "private-measurement-domain")]
            let memory = match self.original_account.as_ref() {
                Some(original) => original.after(memory),
                None => memory,
            };
            let memory = memory?;
            let quota = self
                .storage
                .as_mut()
                .ok_or_else(|| missing_authority("pin native quota controller"))?
                .quota_controller()
                .map_err(|error| map_storage_error("pin native quota controller", &error));
            #[cfg(feature = "private-measurement-domain")]
            let quota = match self.original_account.as_ref() {
                Some(original) => original.after(quota),
                None => quota,
            };
            let quota = quota?;
            self.native_resources = Some(NativeResourceState::new(
                memory,
                quota,
                self.maximum_resident_bytes,
                self.maximum_writable_bytes,
            ));
        }
        #[cfg(feature = "private-measurement-domain")]
        if self.original_account.is_some() && !self.original_retirement_pinned {
            let pin = self.retain_original_native_control().map_err(|source| {
                QemuVmRealizationError::ModelCopy {
                    source: Box::new(source),
                }
            })?;
            if let Some(original) = self.original_account.as_ref() {
                original
                    .retain_control(pin)
                    .map_err(original_roster::original_error)?;
            }
        }
        let result = self
            .native_resources
            .as_ref()
            .map(NativeResourceState::controller)
            .ok_or_else(|| missing_authority("lend native resource controller"));
        #[cfg(feature = "private-measurement-domain")]
        if let Some(original) = self.original_account.as_ref() {
            return original.after(result);
        }
        result
    }

    fn retire_native_resources(&mut self) {
        if let Some(state) = &self.native_resources {
            NativeResourceState::close(state);
        }
    }

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

    /// Seals the quota-bound root for supervisor metadata and QEMU generations.
    ///
    /// The returned path names a private supervisor metadata directory under
    /// the pinned quota root. The retained owner performs descriptor-relative
    /// cleanup. The child may traverse the root to its generation directory,
    /// but cannot inspect this metadata directory or mutate root entries.
    ///
    /// # Errors
    ///
    /// Returns an executor error when storage authority is unavailable or the
    /// ownership and mode transition cannot be installed and verified.
    pub fn seal_supervisor_workspace(&mut self) -> Result<PathBuf, QemuVmRealizationError> {
        self.storage
            .as_mut()
            .ok_or_else(|| missing_authority("seal QEMU attempt workspace"))?
            .seal_supervisor_workspace()
            .map_err(|error| map_storage_error("seal QEMU attempt workspace", &error))
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
        #[cfg(feature = "private-measurement-domain")]
        if let Some(original) = self.original_account.as_ref() {
            original
                .require_original()
                .map_err(original_roster::original_error)?;
        }
        if self.terminal
            || self.storage.is_none()
            || self
                .native_resources
                .as_ref()
                .is_some_and(|state| !NativeResourceState::available(state))
        {
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
        #[cfg(feature = "private-measurement-domain")]
        if let Some(original) = self.original_account.as_ref() {
            if self.terminal {
                return original.after(Err(QemuVmRealizationError::ReapQuarantined {
                    operation: "finish original QEMU attempt host resources",
                    message: String::from(
                        "the same external roster retains unresolved physical ownership",
                    ),
                }));
            }
            return self.finish_original_accounts();
        }
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
        self.retire_native_resources();
        finish_native_owned_resources(
            &mut self.process,
            &mut self.storage,
            &mut self.native_resources,
        )?;
        self.terminal = true;
        Ok(())
    }

    /// Transfers both enforcement authorities to nondroppable quarantine.
    pub fn quarantine(&mut self) {
        if self.terminal {
            return;
        }
        self.retire_native_resources();
        #[cfg(feature = "private-measurement-domain")]
        if let Some(original) = self.original_account.as_ref() {
            let owners = original_roster::RetainedNativeHost {
                process: self.process.take(),
                storage: self.storage.take(),
                native_resources: self.native_resources.take(),
                unconfigured: None,
            };
            // The actual owners move into the same generation slot. A poisoned
            // slot retains the complete tuple, rather than dropping a process
            // owner into the ordinary worker. No new task/control is created.
            let _retained = original.retain_unsettled(owners);
            self.terminal = true;
            return;
        }
        let state = LinuxQemuAttemptHostQuarantineState {
            process: self.process.take(),
            storage: self.storage.take(),
            native_resources: self.native_resources.take(),
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
    native_resources: Option<Arc<NativeResourceState>>,
}

trait HostQuarantineWork: Send + 'static {
    type Error;

    fn reap_and_release(&mut self) -> Result<(), Self::Error>;
}

impl HostQuarantineWork for LinuxQemuAttemptHostQuarantineState {
    type Error = QemuVmRealizationError;

    fn reap_and_release(&mut self) -> Result<(), Self::Error> {
        finish_native_owned_resources(
            &mut self.process,
            &mut self.storage,
            &mut self.native_resources,
        )
    }
}

fn transfer_setup_cleanup(
    process: Option<LinuxQemuAttemptProcessOwner>,
    storage: Option<LinuxQemuAttemptStorageOwner>,
) -> Result<(), QemuVmRealizationError> {
    let state = LinuxQemuAttemptHostQuarantineState {
        process,
        storage,
        native_resources: None,
    };
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

// Fixture policy reserves an explicit finite descriptor ceiling independently of vCPU count.
#[cfg(test)]
const TEST_HOST_FILE_DESCRIPTORS: u64 = 1_024;

// Host-side pager workers and sockets have independent finite fixture entitlements.
#[cfg(test)]
const TEST_HOST_SERVICE_TASKS: u64 = 4;
#[cfg(test)]
const TEST_HOST_SERVICE_FILE_DESCRIPTORS: u64 = 32;

// Operational services retain their own authored memory budgets outside QEMU.
#[cfg(test)]
const TEST_HOST_SERVICE_RESIDENT_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(test)]
const TEST_WATCHER_SERVICE_RESIDENT_BYTES: u64 = 1024 * 1024;

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
            TEST_HOST_FILE_DESCRIPTORS,
            TEST_HOST_SERVICE_TASKS,
            TEST_HOST_SERVICE_FILE_DESCRIPTORS,
            TEST_HOST_SERVICE_RESIDENT_BYTES,
            TEST_WATCHER_SERVICE_RESIDENT_BYTES,
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
                TEST_HOST_FILE_DESCRIPTORS,
                TEST_HOST_SERVICE_TASKS,
                TEST_HOST_SERVICE_FILE_DESCRIPTORS,
                TEST_HOST_SERVICE_RESIDENT_BYTES,
                TEST_WATCHER_SERVICE_RESIDENT_BYTES,
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
