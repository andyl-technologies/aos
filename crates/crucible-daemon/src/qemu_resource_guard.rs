//! Exact host-resource composition for one local QEMU attempt.
//!
//! The host factory behind this module owns one indivisible authority covering
//! the child-process containment contract and every writable artifact reachable
//! by that child. The daemon wraps that authority with signal-driven execution
//! cancellation and an exact scheduler-quantum counter. Keeping process and
//! filesystem ownership in one type prevents a caller from accidentally pairing
//! a cgroup from one attempt with a quota or run directory from another.

use std::fmt;
use std::sync::{Arc, Mutex};

use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{QemuChildProcessContract, QemuNodeChild, QemuVmRealizationError};

use crate::executor_supervisor::{
    ExecutionCancellationHook, ExecutionCancellationHookRegistration,
};
use crate::{
    ExecutionCancellation, QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory, QemuExecutionQuantumCounter,
};

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

/// Factory adding signal-driven cancellation and quantum accounting to a host owner.
pub struct ComposedQemuAttemptResourceGuardFactory<H> {
    host: H,
}

impl<H> ComposedQemuAttemptResourceGuardFactory<H> {
    /// Creates a resource-guard factory over one host-resource allocator.
    #[must_use]
    pub const fn new(host: H) -> Self {
        Self { host }
    }

    /// Returns the retained host-resource allocator.
    #[must_use]
    pub const fn host(&self) -> &H {
        &self.host
    }

    /// Returns mutable access to the retained host-resource allocator.
    #[must_use]
    pub const fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Consumes the wrapper and returns its host-resource allocator.
    #[must_use]
    pub fn into_host(self) -> H {
        self.host
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
    H: QemuAttemptHostResourceFactory,
{
    type Guard = ComposedQemuAttemptResourceGuard<H::Owner>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        let mut host = self.host.begin(resources)?;
        if host.resource_limits() != resources {
            return Err(release_failed_begin(
                &mut host,
                QemuVmRealizationError::Executor {
                    operation: "install QEMU host resources",
                    message: String::from(
                        "host resource owner did not install the exact admitted limits",
                    ),
                },
            ));
        }

        let signal = match host.cancellation_signal() {
            Ok(signal) => signal,
            Err(error) => return Err(release_failed_begin(&mut host, error)),
        };
        let cancellation_failure = Arc::new(Mutex::new(None));
        let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(ProcessCancellationHook {
            signal,
            failure: Arc::clone(&cancellation_failure),
        });
        let cancellation_registration = match cancellation.register_hook(hook) {
            Ok(registration) => registration,
            Err(message) => {
                return Err(release_failed_begin(
                    &mut host,
                    QemuVmRealizationError::Executor {
                        operation: "install QEMU cancellation hook",
                        message: String::from(message),
                    },
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
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
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

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.host.retain_failed_launch_child(child);
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

fn release_failed_begin<H>(host: &mut H, original: QemuVmRealizationError) -> QemuVmRealizationError
where
    H: QemuAttemptHostResourceOwner,
{
    match host.finish() {
        Ok(()) => original,
        Err(cleanup) => {
            host.quarantine();
            QemuVmRealizationError::ReapQuarantined {
                operation: "roll back QEMU host resource installation",
                message: cleanup.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests;
