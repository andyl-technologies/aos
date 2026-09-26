//! Exact host-resource composition for one local QEMU attempt.
//!
//! The host factory behind this module owns one indivisible authority covering
//! the child-process containment contract and every writable artifact reachable
//! by that child. The daemon wraps that authority with signal-driven execution
//! cancellation and an exact scheduler-quantum counter. Keeping process and
//! filesystem ownership in one type prevents a caller from accidentally pairing
//! a cgroup from one attempt with a quota or run directory from another.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crucible::{NodeId, SchedulerOperationalFailureClass};
use crucible_api::{LifecycleApiError, ProductionVmNodeGeneration, ProductionVmNodeLease};
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{
    LinuxQemuAttemptCancellationSignal, LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory,
    LinuxQemuAttemptHostOwner, QemuChildProcessContract, QemuHotForkChildProcessBasis,
    QemuHotForkChildProcessOwner, QemuLaunchResourceRequirements, QemuNodeChannelError,
    QemuNodeChild, QemuPreparedRunDirectory, QemuVmRealizationError,
};

use crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure;
use crate::executor_supervisor::{
    ExecutionCancellationHook, ExecutionCancellationHookRegistration, SelectedExactCheckpointRoot,
};
use crate::{
    ExecutionCancellation, QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory, QemuExecutionQuantumCounter,
};

/// Maximum distinct scheduler nodes retained by one attempt generation owner.
pub const MAX_QEMU_ATTEMPT_GENERATION_NODES: usize = 65_536;

/// Maximum simultaneously retained process generations for one scheduler node.
///
/// Terminal replacement deliberately stages one successor before the active
/// child exits. No third generation may enter until one of those two exact
/// leases is released or the process-free staged successor is rolled back.
const MAX_QEMU_ATTEMPT_GENERATIONS_PER_NODE: usize = 2;

/// Sticky process-cancellation capability owned independently of a host guard.
///
/// Implementations must make cancellation visible to an already-minted child
/// and close future child minting before returning success. The operation must
/// be idempotent because registration and cancellation can race.
pub trait QemuAttemptCancellationSignal: Send + Sync + 'static {
    /// Publishes sticky cancellation to the attempt process boundary.
    ///
    /// # Errors
    ///
    /// Returns an operational error when cancellation could not be made visible
    /// to every existing and future child process.
    fn signal(&self) -> Result<(), QemuVmRealizationError>;
}

/// Indivisible host authority for one attempt's process and writable storage.
///
/// A conforming owner installs exact CPU, resident-memory, aggregate writable-
/// byte, and process ceilings before lending its child contract. Its writable
/// quota covers the pinned VMState container, overlays, logs, and every other
/// artifact the child can mutate. Normal release is legal only after process
/// reap; quarantine retains both process and filesystem enforcement.
pub trait QemuAttemptHostResourceOwner {
    /// Independent cancellation capability registered with the supervisor.
    type CancellationSignal: QemuAttemptCancellationSignal;

    /// Returns the exact resource basis installed by this owner.
    #[must_use]
    fn resource_limits(&self) -> AttemptResourceLimits;

    /// Returns the sealed child-process launch contract.
    ///
    /// # Errors
    ///
    /// Returns an operational error after terminal cleanup has closed launch
    /// authority or when the contract cannot be authenticated.
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError>;

    /// Provisions and lends the descriptor-pinned run-directory capability.
    ///
    /// # Errors
    ///
    /// Returns an operational error when launch admission, retained aggregate
    /// storage authentication, or fresh generation-directory provisioning
    /// fails.
    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError>;

    /// Duplicates the narrow sticky process-cancellation capability.
    ///
    /// # Errors
    ///
    /// Returns an operational error when cancellation authority cannot be
    /// retained independently for the execution signal.
    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError>;

    /// Checks host-enforced limits at one bounded operational boundary.
    ///
    /// # Errors
    ///
    /// Returns a terminal resource error after a hard ceiling is exhausted, or
    /// an availability error when enforcement state cannot be authenticated.
    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Retains a failed launch's nonduplicable direct-child wait authority.
    fn retain_failed_launch_child(&mut self, child: QemuNodeChild);

    /// Reaps every process and releases the aggregate filesystem reservation.
    ///
    /// This operation must be idempotent. Success attests that process reap
    /// completed before filesystem and cgroup release. An error retains every
    /// authority needed by [`Self::quarantine`].
    ///
    /// # Errors
    ///
    /// Returns an operational error when complete release cannot be attested.
    fn finish(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Transfers process and writable-storage enforcement to quarantine.
    ///
    /// This operation is infallible and idempotent. It must never release the
    /// filesystem reservation before the quarantine owner attests process reap.
    fn quarantine(&mut self);
}

/// Factory installing one indivisible host-resource authority.
pub trait QemuAttemptHostResourceFactory {
    /// Exact owner returned for one accepted attempt.
    type Owner: QemuAttemptHostResourceOwner;

    /// Installs every hard host ceiling before process launch becomes possible.
    ///
    /// # Errors
    ///
    /// Returns an operational error when CPU, memory, aggregate writable bytes,
    /// process supervision, or cleanup ownership cannot be installed exactly.
    /// Failure must leave no process or unowned reservation behind.
    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError>;
}

/// Internal extension that pre-seals a supervisor-selected checkpoint root.
pub(crate) trait QemuAttemptSelectedHostResourceFactory:
    QemuAttemptHostResourceFactory
{
    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    >;
}

/// Cloneable bounded access to one exclusive host-resource allocator.
///
/// A production Linux allocator owns one cgroup and project-quota namespace
/// for its complete lifetime, while the fixed executor pool gives each worker
/// an independently owned execution model. This facade lets those workers
/// share the one allocator without duplicating namespace authority. The mutex
/// is held only while one attempt owner is allocated; guest execution and
/// cleanup remain outside it in the returned owner.
pub struct SharedQemuAttemptHostResourceFactory<H> {
    host: Arc<Mutex<H>>,
}

impl<H> SharedQemuAttemptHostResourceFactory<H> {
    /// Wraps one already-open exclusive allocator for fixed-worker sharing.
    #[must_use]
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(Mutex::new(host)),
        }
    }

    /// Returns the number of fixed-worker handles retaining the allocator.
    #[must_use]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.host)
    }
}

impl<H> Clone for SharedQemuAttemptHostResourceFactory<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
        }
    }
}

impl<H> QemuAttemptHostResourceFactory for SharedQemuAttemptHostResourceFactory<H>
where
    H: QemuAttemptHostResourceFactory,
{
    type Owner = H::Owner;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        self.host
            .lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "allocate shared QEMU attempt host resources",
                message: String::from("host-resource allocator lock is poisoned"),
            })?
            .begin(resources)
    }
}

impl<H> QemuAttemptSelectedHostResourceFactory for SharedQemuAttemptHostResourceFactory<H>
where
    H: QemuAttemptSelectedHostResourceFactory,
{
    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        let mut host = match self.host.lock() {
            Ok(host) => host,
            Err(_) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        QemuVmRealizationError::ExecutorUnavailable {
                            operation: "allocate shared QEMU attempt host resources",
                            message: String::from("host-resource allocator lock is poisoned"),
                        },
                        selected_checkpoint,
                    ),
                );
            }
        };
        host.begin_selected(resources, selected_checkpoint)
    }
}

/// Concrete Linux allocator for one indivisible QEMU process/storage owner.
#[derive(Debug)]
pub struct LinuxQemuAttemptHostResourceFactory {
    host: LinuxQemuAttemptHostFactory,
}

impl LinuxQemuAttemptHostResourceFactory {
    /// Opens and exclusively owns the configured cgroup and storage roots.
    ///
    /// # Errors
    ///
    /// Returns a stable executor error for invalid host policy and an
    /// availability error for I/O or namespace contention.
    pub fn open(config: LinuxQemuAttemptHostConfig) -> Result<Self, QemuVmRealizationError> {
        LinuxQemuAttemptHostFactory::open(config).map(|host| Self { host })
    }

    /// Wraps an already-open exact Linux host allocator.
    #[must_use]
    pub const fn new(host: LinuxQemuAttemptHostFactory) -> Self {
        Self { host }
    }
}

/// Concrete Linux process/storage owner with its exact campaign resource basis.
#[derive(Debug)]
#[must_use = "finish the Linux QEMU host owner or transfer it to quarantine"]
pub struct LinuxQemuAttemptHostResourceOwner {
    resources: AttemptResourceLimits,
    host: LinuxQemuAttemptHostOwner,
}

impl LinuxQemuAttemptHostResourceOwner {
    /// Returns the exact pinned aggregate attempt-root path for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an executor error after the storage owner moved to quarantine.
    pub fn run_directory(&self) -> Result<&Path, QemuVmRealizationError> {
        self.host.run_directory()
    }
}

impl QemuAttemptCancellationSignal for LinuxQemuAttemptCancellationSignal {
    fn signal(&self) -> Result<(), QemuVmRealizationError> {
        LinuxQemuAttemptCancellationSignal::signal(self)
    }
}

impl QemuAttemptHostResourceFactory for LinuxQemuAttemptHostResourceFactory {
    type Owner = LinuxQemuAttemptHostResourceOwner;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        let host = self.host.begin(
            resources.maximum_vcpus(),
            resources.maximum_resident_bytes(),
            resources.maximum_disk_bytes(),
        )?;
        if host.resource_ceiling()
            != (
                resources.maximum_vcpus(),
                resources.maximum_resident_bytes(),
                resources.maximum_disk_bytes(),
            )
        {
            let mut host = host;
            host.quarantine();
            return Err(QemuVmRealizationError::Executor {
                operation: "install Linux QEMU host resources",
                message: String::from("combined Linux owner returned a different resource basis"),
            });
        }
        Ok(LinuxQemuAttemptHostResourceOwner { resources, host })
    }
}

impl QemuAttemptSelectedHostResourceFactory for LinuxQemuAttemptHostResourceFactory {
    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        let host = match selected_checkpoint.as_ref() {
            Some(selected_checkpoint) => self.host.begin_exact_checkpoint(
                resources.maximum_vcpus(),
                resources.maximum_resident_bytes(),
                resources.maximum_disk_bytes(),
                selected_checkpoint.process_contract_root(),
            ),
            None => self.host.begin(
                resources.maximum_vcpus(),
                resources.maximum_resident_bytes(),
                resources.maximum_disk_bytes(),
            ),
        };
        let host = match host {
            Ok(host) => host,
            Err(error) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        error,
                        selected_checkpoint,
                    ),
                );
            }
        };
        if host.resource_ceiling()
            != (
                resources.maximum_vcpus(),
                resources.maximum_resident_bytes(),
                resources.maximum_disk_bytes(),
            )
        {
            let mut host = host;
            host.quarantine();
            return Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::Executor {
                        operation: "install Linux QEMU host resources",
                        message: String::from(
                            "combined Linux owner returned a different resource basis",
                        ),
                    },
                    selected_checkpoint,
                ),
            );
        }
        Ok((
            LinuxQemuAttemptHostResourceOwner { resources, host },
            selected_checkpoint,
        ))
    }
}

impl QemuAttemptHostResourceOwner for LinuxQemuAttemptHostResourceOwner {
    type CancellationSignal = LinuxQemuAttemptCancellationSignal;

    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.host.process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host.prepare_generation_run_directory(requirements)
    }

    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError> {
        self.host.cancellation_signal()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.host.check_operational_boundary()
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.host.retain_failed_child(child);
    }

    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.host.finish()
    }

    fn quarantine(&mut self) {
        self.host.quarantine();
    }
}

impl QemuHotForkChildProcessOwner for LinuxQemuAttemptHostResourceOwner {
    type Authority = crucible_qemu::LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        self.host.retain_hot_fork_child(basis)
    }
}

mod generation_resource;
mod retained_workspace;

pub use generation_resource::*;
pub(crate) use retained_workspace::RetainedLinuxQemuAttemptWorkspace;

/// Factory adding signal-driven cancellation and quantum accounting to a host owner.
pub struct ComposedQemuAttemptResourceGuardFactory<H> {
    host: H,
}

impl<H> Clone for ComposedQemuAttemptResourceGuardFactory<H>
where
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
        }
    }
}

impl<H> ComposedQemuAttemptResourceGuardFactory<H> {
    /// Creates a resource-guard factory over one host-resource allocator.
    #[must_use]
    pub const fn new(host: H) -> Self {
        Self { host }
    }
}

/// One exact attempt resource guard composed from a host owner.
#[must_use = "finish the QEMU resource guard or transfer it to quarantine"]
pub struct ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    quantum_counter: QemuExecutionQuantumCounter,
    cancellation_failure: Arc<Mutex<Option<String>>>,
    cancellation_registration: Option<ExecutionCancellationHookRegistration>,
    host: H,
    terminal: bool,
}

impl<H> fmt::Debug for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComposedQemuAttemptResourceGuard")
            .field("resources", &self.resources)
            .field("quantum_counter", &self.quantum_counter)
            .field("host", &self.host)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl<H> QemuAttemptResourceGuardFactory for ComposedQemuAttemptResourceGuardFactory<H>
where
    H: QemuAttemptSelectedHostResourceFactory,
{
    type Guard = ComposedQemuAttemptResourceGuard<H::Owner>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure> {
        let (mut host, selected_checkpoint) =
            self.host.begin_selected(resources, selected_checkpoint)?;
        if host.resource_limits() != resources {
            return Err(release_failed_begin_with_claim(
                &mut host,
                QemuVmRealizationError::Executor {
                    operation: "install QEMU host resources",
                    message: String::from(
                        "host resource owner did not install the exact admitted limits",
                    ),
                },
                selected_checkpoint,
            ));
        }

        let signal = match host.cancellation_signal() {
            Ok(signal) => signal,
            Err(error) => {
                return Err(release_failed_begin_with_claim(
                    &mut host,
                    error,
                    selected_checkpoint,
                ));
            }
        };
        let cancellation_failure = Arc::new(Mutex::new(None));
        let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(ProcessCancellationHook {
            signal,
            failure: Arc::clone(&cancellation_failure),
        });
        let cancellation_registration = match cancellation.register_hook(hook) {
            Ok(registration) => registration,
            Err(message) => {
                return Err(release_failed_begin_with_claim(
                    &mut host,
                    QemuVmRealizationError::Executor {
                        operation: "install QEMU cancellation hook",
                        message: String::from(message),
                    },
                    selected_checkpoint,
                ));
            }
        };

        let mut guard = ComposedQemuAttemptResourceGuard {
            resources,
            cancellation,
            quantum_counter: QemuExecutionQuantumCounter::new(resources),
            cancellation_failure,
            cancellation_registration: Some(cancellation_registration),
            host,
            terminal: false,
        };
        if let Err(error) = guard.check_operational_boundary() {
            return match guard.finish() {
                Ok(()) => Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        error,
                        selected_checkpoint,
                    ),
                ),
                Err(cleanup) => {
                    Err(QemuAttemptResourceGuardBeginFailure::after_checkpoint_claim(cleanup))
                }
            };
        }
        let _spent_selected_checkpoint_claim = selected_checkpoint;
        Ok(guard)
    }
}

impl<H> QemuAttemptOperationalBoundary for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.terminal {
            return Err(QemuVmRealizationError::Executor {
                operation: "check QEMU attempt resources",
                message: String::from("attempt resource guard is already terminal"),
            });
        }
        if let Some(message) = cancellation_failure(&self.cancellation_failure)? {
            return Err(QemuVmRealizationError::Executor {
                operation: "signal QEMU process cancellation",
                message,
            });
        }
        if self.cancellation.is_canceled() {
            return Err(QemuVmRealizationError::Canceled {
                operation: "QEMU attempt resource boundary",
            });
        }
        self.host.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.check_operational_boundary()?;
        self.quantum_counter.charge()
    }
}

impl<H> QemuAttemptResourceGuard for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.terminal {
            return Ok(());
        }
        self.cancellation_registration = None;
        match self.host.finish() {
            Ok(()) => {
                self.terminal = true;
                Ok(())
            }
            Err(error) => {
                self.host.quarantine();
                self.terminal = true;
                Err(QemuVmRealizationError::ReapQuarantined {
                    operation: "release QEMU attempt host resources",
                    message: error.to_string(),
                })
            }
        }
    }

    fn quarantine(&mut self) {
        if self.terminal {
            return;
        }
        self.cancellation_registration = None;
        self.host.quarantine();
        self.terminal = true;
    }
}

impl<H> QemuAttemptProcessResourceGuard for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.host.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host.prepare_generation_run_directory(requirements)
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.host.retain_failed_launch_child(child);
    }
}

impl<H> QemuHotForkChildProcessOwner for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner + QemuHotForkChildProcessOwner,
{
    type Authority = H::Authority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        if self.terminal {
            return Err(QemuNodeChannelError::new(
                "retain forked child process",
                "attempt resource guard is already terminal",
            ));
        }
        self.host.retain_hot_fork_child(basis)
    }
}

impl<H> Drop for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn drop(&mut self) {
        self.quarantine();
    }
}

fn generation_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

fn attempt_operational_error(
    operation: &'static str,
    error: QemuVmRealizationError,
) -> LifecycleApiError {
    let class = match &error {
        QemuVmRealizationError::ExecutorUnavailable { .. } => {
            SchedulerOperationalFailureClass::Retryable
        }
        QemuVmRealizationError::Canceled { .. } => SchedulerOperationalFailureClass::Canceled,
        QemuVmRealizationError::ReapQuarantined { .. }
        | QemuVmRealizationError::Store { .. }
        | QemuVmRealizationError::Executor { .. }
        | QemuVmRealizationError::InvalidCheckpoint { .. }
        | QemuVmRealizationError::InvalidAncestor { .. }
        | QemuVmRealizationError::ReplayOracleMismatch { .. } => {
            SchedulerOperationalFailureClass::Terminal
        }
    };
    LifecycleApiError::AttemptOperational {
        class,
        message: format!("{operation}: {error}"),
    }
}

fn terminal_attempt_operational_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::AttemptOperational {
        class: SchedulerOperationalFailureClass::Terminal,
        message: message.into(),
    }
}

struct ProcessCancellationHook<S> {
    signal: S,
    failure: Arc<Mutex<Option<String>>>,
}

impl<S> fmt::Debug for ProcessCancellationHook<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessCancellationHook")
            .finish_non_exhaustive()
    }
}

impl<S> ExecutionCancellationHook for ProcessCancellationHook<S>
where
    S: QemuAttemptCancellationSignal,
{
    fn signal(&self) {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.signal.signal()));
        let message = match result {
            Ok(Ok(())) => return,
            Ok(Err(error)) => error.to_string(),
            Err(_) => String::from("process cancellation callback panicked"),
        };
        let mut failure = match self.failure.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if failure.is_none() {
            *failure = Some(message);
        }
    }
}

fn cancellation_failure(
    failure: &Mutex<Option<String>>,
) -> Result<Option<String>, QemuVmRealizationError> {
    failure
        .lock()
        .map(|failure| failure.clone())
        .map_err(|_| QemuVmRealizationError::Executor {
            operation: "read QEMU cancellation hook state",
            message: String::from("cancellation hook diagnostic state is poisoned"),
        })
}

fn release_failed_begin_with_claim<H>(
    host: &mut H,
    original: QemuVmRealizationError,
    selected_checkpoint: Option<SelectedExactCheckpointRoot>,
) -> QemuAttemptResourceGuardBeginFailure
where
    H: QemuAttemptHostResourceOwner,
{
    match host.finish() {
        Ok(()) => QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
            original,
            selected_checkpoint,
        ),
        Err(cleanup) => {
            host.quarantine();
            QemuAttemptResourceGuardBeginFailure::after_checkpoint_claim(
                QemuVmRealizationError::ReapQuarantined {
                    operation: "roll back QEMU host resource installation",
                    message: cleanup.to_string(),
                },
            )
        }
    }
}

#[cfg(test)]
mod tests;
