//! Linux source-parent, pidfd, private-channel, and installed-node ownership.

use super::*;

mod reconciliation;

/// Production backend failure while retaining source and target authorities.
#[derive(Debug, Error)]
pub enum LinuxQemuHotForkReconciliationError {
    /// Source-QEMU channel or resource-stage reconciliation failed.
    #[error(transparent)]
    Source(#[from] QemuNodeChannelError),
    /// The private child QMP endpoint failed exact authentication.
    #[error(transparent)]
    ChildQmp(#[from] QemuHotForkChildQmpHandshakeError),
    /// Target pidfd, watcher, or cgroup cleanup failed.
    #[error(transparent)]
    Target(#[from] QemuVmRealizationError),
    /// An acknowledged source response contradicted the retained exact basis.
    #[error("source QEMU contradicted the retained hot-fork lifecycle basis")]
    BasisMismatch,
    /// The in-process source-template owner was poisoned by an unwind.
    #[error("source QEMU ownership lock is poisoned")]
    SourceOwnerPoisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxSourceReleasePhase {
    CloseChildChannel,
    PluginEndpoints,
    ChildConsole,
    ChildQmp,
    Diagnostics,
    PrivateRing,
    Complete,
}

enum LinuxQemuHotForkSourceOwner {
    Detached(Box<Mutex<Option<QemuNode>>>),
    World {
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        node: NodeId,
    },
}

enum LinuxQemuHotForkSourceLoan<'a> {
    Detached(&'a mut QemuNode),
    World(QemuNodeSetPreparedHotForkSource<'a>),
}

impl LinuxQemuHotForkSourceLoan<'_> {
    fn process_identity(&self) -> Result<QemuProcessIdentity, QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.process_identity().map_err(|error| {
                QemuNodeChannelError::new("authenticate hot-fork source process", error.to_string())
            }),
            Self::World(source) => Ok(source.process_identity().clone()),
        }
    }

    fn query_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.query_hot_fork_child_process(generation),
            Self::World(source) => source.query_child_process(generation),
        }
    }

    fn release_plugin_endpoints(&mut self) -> Result<(), QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.release_hot_fork_plugin_endpoints(),
            Self::World(source) => source.release_plugin_endpoints(),
        }
    }

    fn release_child_console(&mut self) -> Result<(), QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.release_hot_fork_child_console(),
            Self::World(source) => source.release_child_console(),
        }
    }

    fn release_child_qmp(&mut self) -> Result<(), QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.release_hot_fork_child_qmp(),
            Self::World(source) => source.release_child_qmp(),
        }
    }

    fn release_child_diagnostics(
        &mut self,
        consumer: &mut QemuHotForkChildDiagnosticConsumer,
    ) -> Result<crucible_qemu::QemuHotForkChildDiagnosticCapture, QemuNodeChannelError> {
        match self {
            Self::Detached(source) => {
                source.release_hot_fork_child_diagnostics_with_consumer(consumer)
            }
            Self::World(source) => source.release_child_diagnostics(consumer),
        }
    }

    fn release_private_ring(&mut self) -> Result<(), QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.release_hot_fork_private_ring_mapping().map(drop),
            Self::World(source) => source.release_private_ring(),
        }
    }

    fn release_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.release_hot_fork_child_process(generation),
            Self::World(source) => source.release_child_process(generation),
        }
    }

    fn release_child_process_contract(
        &mut self,
    ) -> Result<crucible_qemu::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.release_hot_fork_child_process_contract(),
            Self::World(source) => source.release_child_process_contract(),
        }
    }

    fn release_child_files(
        &mut self,
    ) -> Result<crucible_qemu::QmpHotForkChildFilesState, QemuNodeChannelError> {
        match self {
            Self::Detached(source) => source.release_hot_fork_child_files(),
            Self::World(source) => source.release_child_files(),
        }
    }
}

struct LinuxQemuHotForkProcessOwner {
    source: LinuxQemuHotForkSourceOwner,
    process: LinuxQemuHotForkChildProcessAuthority,
    reaped: AtomicBool,
}

impl LinuxQemuHotForkProcessOwner {
    fn with_source<T>(
        &self,
        operation: impl FnOnce(&mut LinuxQemuHotForkSourceLoan<'_>) -> Result<T, QemuNodeChannelError>,
    ) -> Result<T, LinuxQemuHotForkReconciliationError> {
        match &self.source {
            LinuxQemuHotForkSourceOwner::Detached(source) => {
                let mut source = source
                    .lock()
                    .map_err(|_source| LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned)?;
                let mut source = LinuxQemuHotForkSourceLoan::Detached(
                    source
                        .as_mut()
                        .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?,
                );
                operation(&mut source).map_err(Into::into)
            }
            LinuxQemuHotForkSourceOwner::World { source_world, node } => {
                let mut source_world = source_world
                    .lock()
                    .map_err(|_source| LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned)?;
                let source = source_world.retained_source(node).map_err(|error| {
                    LinuxQemuHotForkReconciliationError::Source(QemuNodeChannelError::new(
                        "borrow production hot-fork source",
                        error.to_string(),
                    ))
                })?;
                let mut source = LinuxQemuHotForkSourceLoan::World(source);
                operation(&mut source).map_err(Into::into)
            }
        }
    }

    fn observe_child(
        &self,
    ) -> Result<QmpHotForkChildProcessState, LinuxQemuHotForkReconciliationError> {
        let state = self.with_source(|source| {
            source.query_child_process(self.process.basis().request().child_process_generation())
        })?;
        if state.generation() != self.process.basis().request().child_process_generation()
            || state.child_process_id() != self.process.basis().child_process_id()
        {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        if state.phase() != QmpHotForkChildProcessPhase::Running {
            self.reaped.store(true, Ordering::Release);
        }
        Ok(state)
    }
}

/// Process-control loan joining a hot-fork pidfd to source-parent status.
///
/// Cloning this value duplicates no pidfd, cgroup, or wait authority. Every
/// clone points at the same outer lifecycle owner, which remains responsible
/// for releasing the source status record and target resources after modeled
/// execution has stopped.
#[derive(Clone)]
pub struct LinuxQemuHotForkNodeProcessControl {
    owner: Arc<LinuxQemuHotForkProcessOwner>,
}

impl fmt::Debug for LinuxQemuHotForkNodeProcessControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkNodeProcessControl")
            .field("basis", &self.owner.process.basis())
            .field("reaped", &self.owner.reaped.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl LinuxQemuHotForkNodeProcessControl {
    fn new(owner: Arc<LinuxQemuHotForkProcessOwner>) -> Self {
        Self { owner }
    }

    fn observe_exit(&self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        let state = self.owner.observe_child().map_err(|source| {
            QemuShutdownTargetError::new(
                "query source-owned hot-fork child status",
                source.to_string(),
            )
        })?;
        match state.phase() {
            QmpHotForkChildProcessPhase::Running => Ok(None),
            QmpHotForkChildProcessPhase::Exited => {
                Ok(Some(ExitStatus::from_raw(i32::from(state.status()) << 8)))
            }
            QmpHotForkChildProcessPhase::Signaled if state.status() != 0 => {
                Ok(Some(ExitStatus::from_raw(i32::from(state.status()))))
            }
            QmpHotForkChildProcessPhase::Signaled => Err(QemuShutdownTargetError::new(
                "query source-owned hot-fork child status",
                "source parent reported a zero terminating signal",
            )),
        }
    }

    fn wait_until(&self, timeout: Duration) -> Result<bool, QemuShutdownTargetError> {
        let deadline = ProcessDeadline::after(timeout).ok_or_else(|| {
            QemuShutdownTargetError::new(
                "wait for source-owned hot-fork child",
                "child wait deadline overflowed",
            )
        })?;
        loop {
            if self.observe_exit()?.is_some() {
                return Ok(true);
            }
            if deadline.expired() {
                return Ok(false);
            }
            deadline.pause(Duration::from_millis(1));
        }
    }
}

impl QemuNodeExternalProcessControl for LinuxQemuHotForkNodeProcessControl {
    fn hot_fork_process_basis(&self) -> QemuHotForkChildProcessBasis {
        self.owner.process.basis()
    }

    fn process_id(&self) -> u32 {
        self.owner.process.basis().child_process_id()
    }

    fn reaped(&self) -> bool {
        self.owner.reaped.load(Ordering::Acquire)
    }

    fn try_wait_natural_exit(&mut self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        self.observe_exit()
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.owner.process.terminate().map_err(|source| {
            QemuShutdownTargetError::new("terminate retained hot-fork child", source.to_string())
        })
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.owner.process.kill().map_err(|source| {
            QemuShutdownTargetError::new("kill retained hot-fork child", source.to_string())
        })
    }

    fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        self.wait_until(timeout).map(|exited| {
            if exited {
                QemuChildWait::Exited
            } else {
                QemuChildWait::StillRunning
            }
        })
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.wait_until(timeout).map(|reaped| {
            if reaped {
                QemuReap::Reaped
            } else {
                QemuReap::StillAlive
            }
        })
    }
}

/// Concrete source-QEMU, pidfd, cgroup, and private-channel owner.
pub struct LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    process_owner: Arc<LinuxQemuHotForkProcessOwner>,
    template_identity: Option<QemuHotForkTemplateIdentity>,
    template_configuration: ContentHash,
    template_event_log_offset: EventLogOffset,
    input: CrucibleAttemptExecution,
    world_assembly: Option<QemuHotForkWorldAssemblyToken>,
    child_event_log: EventLog,
    target: G,
    basis: QemuHotForkChildProcessBasis,
    pending_child_qmp: Option<crucible_qemu::QemuHotForkChildQmpHostEndpoint>,
    scheduler_node: Option<QemuHotForkSchedulerNodeContinuation>,
    installed_node: Option<QemuNode>,
    installed_node_id: Option<NodeId>,
    diagnostics_consumer: QemuHotForkChildDiagnosticConsumer,
    host_continuation: Option<QemuHotForkHostContinuation>,
    source_release: LinuxSourceReleasePhase,
    diagnostics: Option<crucible_qemu::QemuHotForkChildDiagnosticCapture>,
    /// Target run directory whose VMState container the child adopted.
    ///
    /// Retained for the child's lifetime and released before the target
    /// guard's storage cleanup, so the pinned descriptors never outlive the
    /// attempt storage they authenticate.
    run_directory: Option<crucible_qemu::QemuPreparedRunDirectory>,
}

pub(super) struct LinuxQemuHotForkWorldLaunchSource {
    pub(super) source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    pub(super) node: NodeId,
    pub(super) configuration: ContentHash,
    pub(super) event_log: EventLog,
}

/// Narrow live-child capability retained by one hot-fork reconciliation owner.
///
/// The capability keeps the diagnostic consumer and non-releasing operational
/// guard inseparable from the child QMP and plugin continuations. Every
/// operational-boundary check or quantum charge first drains all currently
/// available diagnostics. Direct QMP access is for bounded control exchange;
/// guest progress must remain behind the operational methods.
pub struct LinuxQemuHotForkLiveChild<'a> {
    input: &'a CrucibleAttemptExecution,
    diagnostics: &'a mut QemuHotForkChildDiagnosticConsumer,
    event_log: &'a mut EventLog,
    operational: &'a mut dyn crate::QemuAttemptOperationalBoundary,
}

impl fmt::Debug for LinuxQemuHotForkLiveChild<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkLiveChild")
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

impl LinuxQemuHotForkLiveChild<'_> {
    /// Returns the exact resolved semantic input retained at child creation.
    #[must_use]
    pub const fn execution_input(&self) -> &CrucibleAttemptExecution {
        self.input
    }

    /// Borrows the branch-private clone of the source event-log prefix.
    #[must_use]
    pub fn event_log_mut(&mut self) -> &mut EventLog {
        self.event_log
    }

    /// Drains all currently available branch-private diagnostic bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Executor`] when the exact bounded
    /// diagnostic stream cannot be retained without truncation.
    pub fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        self.diagnostics
            .drain_available()
            .map_err(diagnostic_drain_realization_error)
    }
}

impl crate::QemuAttemptOperationalBoundary for LinuxQemuHotForkLiveChild<'_> {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        self.operational.resource_limits()
    }

    fn cancellation(&self) -> &crate::ExecutionCancellation {
        self.operational.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.drain_diagnostics()?;
        self.operational.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.drain_diagnostics()?;
        self.operational.charge_execution_quantum()
    }
}

fn diagnostic_drain_realization_error(source: QemuNodeChannelError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "drain branch-private hot-fork child diagnostics",
        message: source.to_string(),
    }
}

impl<G> fmt::Debug for LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkReconciliationBackend")
            .field("basis", &self.basis)
            .field("world_assembly", &self.world_assembly.is_some())
            .field("pending_child_qmp", &self.pending_child_qmp.is_some())
            .field("scheduler_node_admitted", &self.scheduler_node.is_some())
            .field("scheduler_node_installed", &self.installed_node.is_some())
            .field("installed_node_id", &self.installed_node_id)
            .field("diagnostics_consumer", &self.diagnostics_consumer)
            .field("host_continuation", &self.host_continuation.is_some())
            .field("source_release", &self.source_release)
            .field("diagnostics", &self.diagnostics.is_some())
            .field("run_directory", &self.run_directory.is_some())
            .finish_non_exhaustive()
    }
}

impl<G> LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    pub(super) fn from_launch(
        source: QemuNode,
        template_identity: QemuHotForkTemplateIdentity,
        input: CrucibleAttemptExecution,
        world_assembly: Option<QemuHotForkWorldAssemblyToken>,
        target: G,
        launch: QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>,
        run_directory: crucible_qemu::QemuPreparedRunDirectory,
    ) -> Self {
        let (_parent, process, child_qmp, diagnostics_consumer, host_continuation) =
            launch.into_parts();
        let basis = process.basis();
        let process_owner = Arc::new(LinuxQemuHotForkProcessOwner {
            source: LinuxQemuHotForkSourceOwner::Detached(Box::new(Mutex::new(Some(source)))),
            process,
            reaped: AtomicBool::new(false),
        });
        let child_event_log = template_identity.fork_event_log();
        let template_configuration = template_identity.configuration();
        let template_event_log_offset = template_identity.event_log().offset();
        Self {
            process_owner,
            template_identity: Some(template_identity),
            template_configuration,
            template_event_log_offset,
            input,
            world_assembly,
            child_event_log,
            target,
            basis,
            pending_child_qmp: Some(child_qmp),
            scheduler_node: None,
            installed_node: None,
            installed_node_id: None,
            diagnostics_consumer,
            host_continuation: Some(host_continuation),
            source_release: LinuxSourceReleasePhase::CloseChildChannel,
            diagnostics: None,
            run_directory: Some(run_directory),
        }
    }

    pub(super) fn from_world_launch(
        source: LinuxQemuHotForkWorldLaunchSource,
        input: CrucibleAttemptExecution,
        world_assembly: QemuHotForkWorldAssemblyToken,
        target: G,
        launch: QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>,
        run_directory: crucible_qemu::QemuPreparedRunDirectory,
    ) -> Self {
        let template_event_log_offset = source.event_log.offset();
        let child_event_log = source.event_log;
        let (_parent, process, child_qmp, diagnostics_consumer, host_continuation) =
            launch.into_parts();
        let basis = process.basis();
        let process_owner = Arc::new(LinuxQemuHotForkProcessOwner {
            source: LinuxQemuHotForkSourceOwner::World {
                source_world: source.source_world,
                node: source.node,
            },
            process,
            reaped: AtomicBool::new(false),
        });

        Self {
            process_owner,
            template_identity: None,
            template_configuration: source.configuration,
            template_event_log_offset,
            input,
            world_assembly: Some(world_assembly),
            child_event_log,
            target,
            basis,
            pending_child_qmp: Some(child_qmp),
            scheduler_node: None,
            installed_node: None,
            installed_node_id: None,
            diagnostics_consumer,
            host_continuation: Some(host_continuation),
            source_release: LinuxSourceReleasePhase::CloseChildChannel,
            diagnostics: None,
            run_directory: Some(run_directory),
        }
    }

    fn live_child_mut(&mut self) -> Option<LinuxQemuHotForkLiveChild<'_>> {
        Some(LinuxQemuHotForkLiveChild {
            input: &self.input,
            diagnostics: &mut self.diagnostics_consumer,
            event_log: &mut self.child_event_log,
            operational: &mut self.target,
        })
    }

    fn with_source_mut<T>(
        &self,
        operation: impl FnOnce(&mut LinuxQemuHotForkSourceLoan<'_>) -> Result<T, QemuNodeChannelError>,
    ) -> Result<T, LinuxQemuHotForkReconciliationError> {
        self.process_owner.with_source(operation)
    }

    /// Returns the bounded final child diagnostic capture after source release.
    #[must_use]
    pub const fn diagnostics(&self) -> Option<&crucible_qemu::QemuHotForkChildDiagnosticCapture> {
        self.diagnostics.as_ref()
    }

    /// Creates a non-owning modeled-node process-control loan.
    #[must_use]
    pub fn node_process_control(&self) -> LinuxQemuHotForkNodeProcessControl {
        LinuxQemuHotForkNodeProcessControl::new(Arc::clone(&self.process_owner))
    }

    fn world_child_source_basis(
        &self,
    ) -> Result<QemuHotForkWorldChildSourceBasis, LinuxQemuHotForkReconciliationError> {
        let process = self.with_source_mut(|source| {
            source.process_identity().map_err(|error| {
                QemuNodeChannelError::new("authenticate hot-fork source process", error.to_string())
            })
        })?;
        Ok(QemuHotForkWorldChildSourceBasis {
            node: self
                .installed_node_id
                .clone()
                .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?,
            configuration: self.template_configuration,
            event_log_offset: self.template_event_log_offset,
            process,
        })
    }

    /// Installs the admitted branch-private continuation as one scheduler node.
    ///
    /// This operation consumes no source-parent, pidfd, or target-resource
    /// ownership. The installed node receives only a shared non-owning process
    /// control loan; terminal release remains ordered by this backend.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed basis error when admission has not produced one
    /// exact continuation or a node is already installed. A process-basis
    /// mismatch restores the unchanged continuation for quarantine or retry.
    pub fn install_scheduler_node(
        &mut self,
        node: NodeId,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
    ) -> Result<(), LinuxQemuHotForkReconciliationError> {
        if self.installed_node.is_some() {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        let continuation = self
            .scheduler_node
            .take()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        match continuation.into_qemu_node(
            node.clone(),
            self.node_process_control(),
            shutdown_policy,
            async_policy,
            crash_detector,
        ) {
            Ok(installed_node) => {
                self.installed_node = Some(installed_node);
                self.installed_node_id = Some(node);
                Ok(())
            }
            Err(error) => {
                let (continuation, _process, source) = error.into_parts();
                self.scheduler_node = Some(continuation);
                Err(LinuxQemuHotForkReconciliationError::Source(source))
            }
        }
    }

    /// Borrows the exact installed process-neutral scheduler node.
    #[must_use]
    pub fn installed_scheduler_node_mut(&mut self) -> Option<&mut QemuNode> {
        self.installed_node.as_mut()
    }

    /// Consumes a reconciled backend into its reusable exact source template.
    ///
    /// # Errors
    ///
    /// Returns the unchanged backend when a modeled-node process-control loan
    /// still exists or the source ownership lock cannot be recovered exactly.
    pub fn into_source(mut self) -> Result<QemuPreparedHotForkTemplate<QemuNode>, Box<Self>> {
        if Arc::strong_count(&self.process_owner) != 1 {
            return Err(Box::new(self));
        }
        let source =
            Arc::get_mut(&mut self.process_owner).and_then(|owner| match &mut owner.source {
                LinuxQemuHotForkSourceOwner::Detached(source) => {
                    source.get_mut().ok().and_then(Option::take)
                }
                LinuxQemuHotForkSourceOwner::World { .. } => None,
            });
        let Some(source) = source else {
            return Err(Box::new(self));
        };
        let Some(template_identity) = self.template_identity.take() else {
            return Err(Box::new(self));
        };
        Ok(QemuPreparedHotForkTemplate::from_reconciled_parts(
            source,
            template_identity,
        ))
    }
}

type LinuxQemuHotForkWorldReconciliation<G> =
    QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>;

/// Shared post-shutdown owner for every adopted child reconciliation.
///
/// Adoption leases transfer their exact reconciliation into this set only
/// after the production lifecycle has reaped the corresponding `QemuNode` and
/// the source parent has authenticated the same terminal process record.
pub(crate) struct LinuxQemuHotForkWorldReconciliationSet<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    expected: BTreeSet<NodeId>,
    reconciliations: Arc<Mutex<BTreeMap<NodeId, LinuxQemuHotForkWorldReconciliation<G>>>>,
}

impl<G> Clone for LinuxQemuHotForkWorldReconciliationSet<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    fn clone(&self) -> Self {
        Self {
            expected: self.expected.clone(),
            reconciliations: Arc::clone(&self.reconciliations),
        }
    }
}

impl<G> LinuxQemuHotForkWorldReconciliationSet<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    pub(crate) fn new(expected: BTreeSet<NodeId>) -> Self {
        Self {
            expected,
            reconciliations: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn reconcile_execution_disposition(
        &mut self,
        disposition: crate::AttemptExecutionDisposition,
    ) -> Result<crate::AttemptExecutionReconciliationStep, LifecycleApiError> {
        let mut reconciliations = self.reconciliations.lock().map_err(|_| {
            hot_fork_adoption_error("hot-fork world reconciliation registry is poisoned")
        })?;
        let actual = reconciliations.keys().cloned().collect::<BTreeSet<_>>();
        if actual != self.expected {
            return Err(hot_fork_adoption_error(
                "hot-fork world reconciliation registry differs from its adopted child roster",
            ));
        }
        let Some(node) = reconciliations.keys().next().cloned() else {
            return Ok(crate::AttemptExecutionReconciliationStep::Complete);
        };
        let step = reconciliations
            .get_mut(&node)
            .ok_or_else(|| {
                hot_fork_adoption_error("hot-fork world reconciliation disappeared during lookup")
            })?
            .reconcile_execution_disposition(disposition)
            .map_err(|error| {
                hot_fork_adoption_error(format!(
                    "reconcile adopted hot-fork child `{}`: {error}",
                    node.name
                ))
            })?;
        if step == crate::AttemptExecutionReconciliationStep::Complete {
            reconciliations.remove(&node);
            self.expected.remove(&node);
        }
        if self.expected.is_empty() {
            Ok(crate::AttemptExecutionReconciliationStep::Complete)
        } else {
            Ok(crate::AttemptExecutionReconciliationStep::Progressed)
        }
    }

    pub(crate) fn validate_operational_handoff(&self) -> Result<(), LifecycleApiError> {
        let reconciliations = self.reconciliations.lock().map_err(|_| {
            hot_fork_adoption_error("hot-fork world reconciliation registry is poisoned")
        })?;
        let actual = reconciliations.keys().cloned().collect::<BTreeSet<_>>();
        if actual != self.expected
            || reconciliations.values().any(|reconciliation| {
                reconciliation.phase() != QemuHotForkReconciliationPhase::AwaitingPublication
            })
        {
            return Err(hot_fork_adoption_error(
                "hot-fork world operational handoff is incomplete after lifecycle shutdown",
            ));
        }
        Ok(())
    }

    pub(crate) fn quarantine(&mut self) {
        match self.reconciliations.lock() {
            Ok(mut reconciliations) => {
                for reconciliation in reconciliations.values_mut() {
                    reconciliation.quarantine();
                }
            }
            Err(poisoned) => {
                let mut reconciliations = poisoned.into_inner();
                for reconciliation in reconciliations.values_mut() {
                    reconciliation.quarantine();
                }
            }
        }
    }
}

struct LinuxQemuHotForkWorldNodeLease<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    identity: ProductionVmNodeGeneration,
    reconciliation: Option<LinuxQemuHotForkWorldReconciliation<G>>,
    completed: LinuxQemuHotForkWorldReconciliationSet<G>,
}

impl<G> Drop for LinuxQemuHotForkWorldNodeLease<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        let Some(mut reconciliation) = self.reconciliation.take() else {
            return;
        };

        // An adoption can be rejected after this lease has entered an opaque
        // API construction transaction. Keep the exact source-parent record,
        // child authority, target share, and run directory alive after moving
        // them to fail-closed quarantine.
        reconciliation.quarantine();
        std::mem::forget(reconciliation);
    }
}

impl<G> ProductionVmNodeLease for LinuxQemuHotForkWorldNodeLease<G>
where
    G: crate::QemuAttemptResourceGuard + Send + 'static,
{
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        let Some(reconciliation) = self.reconciliation.as_mut() else {
            return Ok(());
        };
        for _ in 0..32 {
            // crucible-lint: allow host-nondeterminism-state -- Reconciliation polls source-owned process cleanup only; the result cannot alter modeled execution.
            match reconciliation.reconcile_step().map_err(|error| {
                hot_fork_adoption_error(format!(
                    "reconcile reaped adopted child `{}`: {error}",
                    self.identity.node().name
                ))
            })? {
                QemuHotForkReconciliationStep::AwaitingPublication => {
                    let mut completed = self.completed.reconciliations.lock().map_err(|_| {
                        hot_fork_adoption_error(
                            "hot-fork world reconciliation registry is poisoned",
                        )
                    })?;
                    if completed.contains_key(self.identity.node()) {
                        return Err(hot_fork_adoption_error(
                            "hot-fork world already retained this child reconciliation",
                        ));
                    }
                    let reconciliation = self.reconciliation.take().ok_or_else(|| {
                        hot_fork_adoption_error(
                            "adopted child reconciliation disappeared before transfer",
                        )
                    })?;
                    completed.insert(self.identity.node().clone(), reconciliation);
                    return Ok(());
                }
                QemuHotForkReconciliationStep::ChildRunning => {
                    return Err(hot_fork_adoption_error(format!(
                        "production lifecycle reported reaped child `{}` while its source parent still reports it running",
                        self.identity.node().name
                    )));
                }
                QemuHotForkReconciliationStep::ChildDiagnosticsDrained
                | QemuHotForkReconciliationStep::Advanced(_) => {}
                QemuHotForkReconciliationStep::Complete => {
                    return Err(hot_fork_adoption_error(
                        "adopted child reached complete reconciliation before publication",
                    ));
                }
            }
        }
        Err(hot_fork_adoption_error(
            "adopted child operational reconciliation exceeded its finite step bound",
        ))
    }
}

impl<G>
    QemuHotForkAttemptReconciliation<
        LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
    >
where
    G: crate::QemuAttemptResourceGuard + Send + 'static,
{
    /// Consumes a completely assembled child into the production adoption API.
    ///
    /// The returned value exposes no detachable node or reconciliation tuple.
    /// Its lease keeps source-parent, target, run-directory, and publication
    /// authority together until the production lifecycle reaps the node.
    pub(crate) fn into_world_node_adoption(
        mut self,
        identity: ProductionVmNodeGeneration,
        completed: LinuxQemuHotForkWorldReconciliationSet<QemuHotForkWorldNodeTarget<G>>,
    ) -> Result<ProductionVmHotForkNodeAdoption, LifecycleApiError> {
        if let Err(error) = self.require_phase(
            "adopt assembled hot-fork scheduler node",
            QemuHotForkReconciliationPhase::Live,
        ) {
            return retain_failed_world_adoption(self, error.to_string());
        }
        let Some(backend) = self.backend.as_mut() else {
            return retain_failed_world_adoption(self, "hot-fork child backend is unavailable");
        };
        if backend.installed_node_id.as_ref() != Some(identity.node())
            || backend.target.identity() != &identity
        {
            return retain_failed_world_adoption(
                self,
                "hot-fork child identity differs from its installed node or target reservation",
            );
        }
        let Some(run_directory) = backend
            .run_directory
            .as_ref()
            .map(|directory| directory.path())
        else {
            return retain_failed_world_adoption(
                self,
                "hot-fork child lost its pinned run-directory authority",
            );
        };
        let run_directory = run_directory.to_path_buf();
        let Some(node) = backend.installed_node.take() else {
            return retain_failed_world_adoption(
                self,
                "hot-fork child lost its installed scheduler node",
            );
        };
        let lease = LinuxQemuHotForkWorldNodeLease {
            identity: identity.clone(),
            reconciliation: Some(self),
            completed,
        };
        ProductionVmHotForkNodeAdoption::new(identity, node, lease, run_directory)
    }
}

fn retain_failed_world_adoption<G>(
    mut reconciliation: QemuHotForkAttemptReconciliation<
        LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
    >,
    message: impl Into<String>,
) -> Result<ProductionVmHotForkNodeAdoption, LifecycleApiError>
where
    G: crate::QemuAttemptResourceGuard,
{
    reconciliation.quarantine();
    std::mem::forget(reconciliation);
    Err(hot_fork_adoption_error(message))
}

fn hot_fork_adoption_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

impl<G> QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>
where
    G: crate::QemuAttemptResourceGuard,
{
    /// Borrows the admitted live-child capability while the child is live.
    ///
    /// The capability joins private QMP, plugin/host-I/O continuation,
    /// diagnostics service, and the non-releasing resource boundary. Modeled
    /// execution must charge progress through this value, which drains the
    /// branch-private diagnostic stream before every operational boundary.
    #[must_use]
    pub fn live_child_mut(&mut self) -> Option<LinuxQemuHotForkLiveChild<'_>> {
        if self.phase != QemuHotForkReconciliationPhase::Live {
            return None;
        }
        self.backend.as_mut()?.live_child_mut()
    }

    /// Installs the admitted continuation as an externally parented QEMU node.
    ///
    /// # Errors
    ///
    /// Returns an invalid-phase error before child admission or a backend
    /// error while retaining every source, target, and continuation authority.
    pub fn install_scheduler_node(
        &mut self,
        node: NodeId,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
    ) -> Result<(), Box<QemuHotForkAttemptReconciliationError<LinuxQemuHotForkReconciliationError>>>
    {
        self.require_phase(
            "install hot-fork scheduler node",
            QemuHotForkReconciliationPhase::Live,
        )
        .map_err(Box::new)?;
        self.backend_mut()
            .map_err(Box::new)?
            .install_scheduler_node(node, shutdown_policy, async_policy, crash_detector)
            .map_err(|source| {
                Box::new(QemuHotForkAttemptReconciliationError::Operation {
                    operation: "install hot-fork scheduler node",
                    source,
                })
            })
    }

    /// Borrows the installed process-neutral QEMU node while the child is live.
    #[must_use]
    pub fn installed_scheduler_node_mut(&mut self) -> Option<&mut QemuNode> {
        if self.phase != QemuHotForkReconciliationPhase::Live {
            return None;
        }
        self.backend.as_mut()?.installed_scheduler_node_mut()
    }

    /// Returns the authenticated source basis for atomic world admission.
    ///
    /// The basis is available only while the exact child remains live and its
    /// process-neutral scheduler node has been installed. This prevents a
    /// world transaction from admitting a raw fork result whose private host
    /// continuation has not completed child-channel authentication.
    ///
    /// # Errors
    ///
    /// Returns a phase or backend error when the child is not ready for world
    /// admission or the retained source process can no longer be authenticated.
    pub fn world_child_source_basis(
        &self,
    ) -> Result<
        QemuHotForkWorldChildSourceBasis,
        Box<QemuHotForkAttemptReconciliationError<LinuxQemuHotForkReconciliationError>>,
    > {
        self.require_phase(
            "authenticate hot-fork child for world admission",
            QemuHotForkReconciliationPhase::Live,
        )
        .map_err(Box::new)?;
        let backend = self.backend_ref().map_err(Box::new)?;
        if backend.installed_node.is_none() {
            return Err(Box::new(
                QemuHotForkAttemptReconciliationError::InvalidPhase {
                    operation: "authenticate installed hot-fork scheduler node",
                    phase: self.phase,
                },
            ));
        }
        backend.world_child_source_basis().map_err(|source| {
            Box::new(QemuHotForkAttemptReconciliationError::Operation {
                operation: "authenticate hot-fork source basis",
                source,
            })
        })
    }

    /// Returns the exact atomic world assembly for which this child launched.
    ///
    /// Legacy single-node launches return `None` and therefore cannot be
    /// admitted into an atomic multi-node world.
    #[must_use]
    pub fn world_assembly_token(&self) -> Option<&QemuHotForkWorldAssemblyToken> {
        self.backend
            .as_ref()
            .and_then(|backend| backend.world_assembly.as_ref())
    }
}
