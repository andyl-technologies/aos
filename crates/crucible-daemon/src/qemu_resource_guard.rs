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

use crucible::NodeId;
use crucible_api::{LifecycleApiError, ProductionVmNodeGeneration, ProductionVmNodeLease};
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{
    LinuxQemuAttemptCancellationSignal, LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory,
    LinuxQemuAttemptHostOwner, QemuChildProcessContract, QemuLaunchCommand, QemuNodeChild,
    QemuPreparedRunDirectory, QemuVmRealizationError,
};

use crate::executor_supervisor::{
    ExecutionCancellationHook, ExecutionCancellationHookRegistration,
};
use crate::{
    ExecutionCancellation, QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory, QemuExecutionQuantumCounter,
};

/// Maximum distinct scheduler nodes retained by one attempt generation owner.
pub const MAX_QEMU_ATTEMPT_GENERATION_NODES: usize = 65_536;

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
        command: &QemuLaunchCommand,
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

    /// Returns the retained exact Linux host allocator.
    pub const fn host(&self) -> &LinuxQemuAttemptHostFactory {
        &self.host
    }

    /// Returns mutable access to the retained exact Linux host allocator.
    pub const fn host_mut(&mut self) -> &mut LinuxQemuAttemptHostFactory {
        &mut self.host
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
        command: &QemuLaunchCommand,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host.prepare_generation_run_directory(command)
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

    fn prepare_generation_run_directory(
        &mut self,
        command: &QemuLaunchCommand,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host.prepare_generation_run_directory(command)
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

/// Attempt-wide guard owner with exact linear process-generation leases.
///
/// The owner seals one resource guard behind a bounded generation registry.
/// Each scheduler node may advance only to a strictly newer positive generation,
/// while the live set contains at most one lease per active process. Finished
/// leases leave only one latest-generation integer per scenario node. Dropping
/// an unfinished lease poisons aggregate release; dropping this owner transfers
/// the underlying guard to quarantine.
#[must_use = "finish the generation owner or transfer its guard to quarantine"]
pub struct QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    guard: G,
    generations: Arc<Mutex<QemuAttemptGenerationState>>,
    terminal: bool,
    terminal_failure: Option<String>,
}

impl<G> fmt::Debug for QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuAttemptGenerationResourceOwner")
            .field("guard", &self.guard)
            .field("terminal", &self.terminal)
            .field("terminal_failure", &self.terminal_failure)
            .finish_non_exhaustive()
    }
}

impl<G> QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    /// Seals one live attempt guard behind a bounded generation registry.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when `maximum_nodes` is zero
    /// or exceeds [`MAX_QEMU_ATTEMPT_GENERATION_NODES`]. The supplied guard is
    /// quarantined before rejection.
    pub fn new(mut guard: G, maximum_nodes: usize) -> Result<Self, LifecycleApiError> {
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            guard.quarantine();
            return Err(generation_error(format!(
                "QEMU attempt generation-node bound {maximum_nodes} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
            )));
        }
        Ok(Self {
            guard,
            generations: Arc::new(Mutex::new(QemuAttemptGenerationState {
                maximum_nodes,
                latest: BTreeMap::new(),
                active: BTreeSet::new(),
                abandoned: false,
            })),
            terminal: false,
            terminal_failure: None,
        })
    }

    /// Registers one strictly newer node generation and returns its linear lease.
    ///
    /// Registration is failure-atomic. A new node is retained only when the
    /// fixed distinct-node bound has room, and a known node must advance beyond
    /// its last issued generation. The lease must be finished only after its
    /// exact QEMU child has been reaped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after terminal cleanup,
    /// registry poison, prior lease abandonment, node-bound exhaustion, or a
    /// duplicate/stale generation.
    pub fn register_generation(
        &mut self,
        identity: ProductionVmNodeGeneration,
    ) -> Result<QemuAttemptGenerationLease, LifecycleApiError> {
        if self.terminal {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        if state.abandoned {
            return Err(generation_error(
                "a QEMU attempt generation lease was abandoned",
            ));
        }
        let node = identity.node().clone();
        if state.active.iter().any(|active| active.node() == &node) {
            return Err(generation_error(format!(
                "QEMU node `{}` already has an active generation lease",
                node.name
            )));
        }
        if let Some(latest) = state.latest.get(&node) {
            if identity.generation() <= *latest {
                return Err(generation_error(format!(
                    "QEMU node `{}` generation {} does not advance beyond {latest}",
                    node.name,
                    identity.generation()
                )));
            }
        } else if state.latest.len() >= state.maximum_nodes {
            return Err(generation_error(format!(
                "QEMU attempt generation-node bound {} is exhausted",
                state.maximum_nodes
            )));
        }
        if !state.active.insert(identity.clone()) {
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} is already active",
                node.name,
                identity.generation()
            )));
        }
        state.latest.insert(node, identity.generation());
        drop(state);
        Ok(QemuAttemptGenerationLease {
            identity,
            generations: Arc::clone(&self.generations),
            finished: false,
        })
    }

    /// Finishes the aggregate guard after every exact generation lease released.
    ///
    /// An abandoned or still-active lease causes immediate quarantine; aggregate
    /// CPU, memory, disk, and quantum ownership is never released from that
    /// state. The operation is idempotent after a successful finish.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when a lease remains active or
    /// abandoned, the registry is poisoned, or underlying guard cleanup fails.
    pub fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if self.terminal {
            return self
                .terminal_failure
                .as_ref()
                .map_or(Ok(()), |message| Err(generation_error(message.clone())));
        }
        let release_allowed = self
            .generations
            .lock()
            .map(|state| !state.abandoned && state.active.is_empty())
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"));
        match release_allowed {
            Ok(true) => {}
            Ok(false) => {
                let message = String::from(
                    "QEMU attempt aggregate release has an active or abandoned generation",
                );
                self.guard.quarantine();
                self.terminal = true;
                self.terminal_failure = Some(message.clone());
                return Err(generation_error(message));
            }
            Err(error) => {
                let message = error.to_string();
                self.guard.quarantine();
                self.terminal = true;
                self.terminal_failure = Some(message);
                return Err(error);
            }
        }
        let result = self.guard.finish();
        self.terminal = true;
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let message = format!("finish QEMU attempt aggregate resources: {error}");
                self.terminal_failure = Some(message.clone());
                Err(generation_error(message))
            }
        }
    }

    /// Transfers the aggregate guard to quarantine without releasing resources.
    pub fn quarantine(&mut self) {
        if self.terminal {
            return;
        }
        self.guard.quarantine();
        self.terminal = true;
        self.terminal_failure = Some(String::from(
            "QEMU attempt aggregate resources were transferred to quarantine",
        ));
    }
}

impl<G> QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Provisions one fresh generation directory under the aggregate guard.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after aggregate cleanup or
    /// when the guard rejects launch admission or storage provisioning.
    pub fn prepare_generation_run_directory(
        &mut self,
        command: &QemuLaunchCommand,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        if self.terminal {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard
            .prepare_generation_run_directory(command)
            .map_err(|error| {
                generation_error(format!("prepare QEMU generation directory: {error}"))
            })
    }

    /// Returns the sealed attempt process contract for guarded generation spawn.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after aggregate cleanup or
    /// when the guard cannot authenticate the retained process contract.
    pub fn child_process_contract(&self) -> Result<&QemuChildProcessContract, LifecycleApiError> {
        if self.terminal {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.child_process_contract().map_err(|error| {
            generation_error(format!("lend QEMU generation process contract: {error}"))
        })
    }

    /// Retains an unreaped child from a failed generation launch.
    pub fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.guard.retain_failed_launch_child(child);
    }

    /// Charges one scheduler quantum before generation guest progress.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] on cancellation, terminal
    /// ownership, or exact quantum/resource exhaustion.
    pub fn charge_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        if self.terminal {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.charge_execution_quantum().map_err(|error| {
            generation_error(format!("charge QEMU generation execution quantum: {error}"))
        })
    }
}

impl<G> Drop for QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        self.quarantine();
    }
}

#[derive(Debug)]
struct QemuAttemptGenerationState {
    maximum_nodes: usize,
    latest: BTreeMap<NodeId, u64>,
    active: BTreeSet<ProductionVmNodeGeneration>,
    abandoned: bool,
}

/// Linear release token for one exact production VM process generation.
#[must_use = "finish the generation lease only after exact QEMU reap"]
pub struct QemuAttemptGenerationLease {
    identity: ProductionVmNodeGeneration,
    generations: Arc<Mutex<QemuAttemptGenerationState>>,
    finished: bool,
}

impl fmt::Debug for QemuAttemptGenerationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuAttemptGenerationLease")
            .field("identity", &self.identity)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl ProductionVmNodeLease for QemuAttemptGenerationLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if self.finished {
            return Ok(());
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        if !state.active.remove(&self.identity) {
            state.abandoned = true;
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} has no active lease",
                self.identity.node().name,
                self.identity.generation()
            )));
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for QemuAttemptGenerationLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        match self.generations.lock() {
            Ok(mut state) => state.abandoned = true,
            Err(poisoned) => poisoned.into_inner().abandoned = true,
        }
    }
}

fn generation_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
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
