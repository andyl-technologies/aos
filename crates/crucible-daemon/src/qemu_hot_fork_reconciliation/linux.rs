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

struct LinuxQemuHotForkSourceOwner {
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    node: NodeId,
}

struct LinuxQemuHotForkSourceLoan<'a>(QemuNodeSetPreparedHotForkSource<'a>);

impl LinuxQemuHotForkSourceLoan<'_> {
    fn process_identity(&self) -> Result<QemuProcessIdentity, QemuNodeChannelError> {
        Ok(self.0.process_identity().clone())
    }

    fn query_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QemuNodeChannelError> {
        self.0.query_child_process(generation)
    }

    fn release_plugin_endpoints(&mut self) -> Result<(), QemuNodeChannelError> {
        self.0.release_plugin_endpoints()
    }

    fn release_child_console(&mut self) -> Result<(), QemuNodeChannelError> {
        self.0.release_child_console()
    }

    fn release_child_qmp(&mut self) -> Result<(), QemuNodeChannelError> {
        self.0.release_child_qmp()
    }

    fn release_child_diagnostics(
        &mut self,
        consumer: &mut QemuHotForkChildDiagnosticConsumer,
    ) -> Result<crucible_qemu::QemuHotForkChildDiagnosticCapture, QemuNodeChannelError> {
        self.0.release_child_diagnostics(consumer)
    }

    fn release_private_ring(&mut self) -> Result<(), QemuNodeChannelError> {
        self.0.release_private_ring()
    }

    fn release_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QemuNodeChannelError> {
        self.0.release_child_process(generation)
    }

    fn release_child_process_contract(
        &mut self,
    ) -> Result<crucible_qemu::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.0.release_child_process_contract()
    }

    fn release_child_files(
        &mut self,
    ) -> Result<crucible_qemu::QmpHotForkChildFilesState, QemuNodeChannelError> {
        self.0.release_child_files()
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
        let mut source_world = self
            .source
            .source_world
            .lock()
            .map_err(|_source| LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned)?;
        let source = source_world
            .retained_source(&self.source.node)
            .map_err(|error| {
                LinuxQemuHotForkReconciliationError::Source(QemuNodeChannelError::new(
                    "borrow production hot-fork source",
                    error.to_string(),
                ))
            })?;
        let mut source = LinuxQemuHotForkSourceLoan(source);
        operation(&mut source).map_err(Into::into)
    }

    fn observe_child(
        &self,
    ) -> Result<QmpHotForkChildProcessState, LinuxQemuHotForkReconciliationError> {
        let state = self.with_source(|source| {
            source.query_child_process(
                self.process
                    .basis()
                    .request()
                    .child_process_contract_generation(),
            )
        })?;
        if state.generation()
            != self
                .process
                .basis()
                .request()
                .child_process_contract_generation()
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
    template_configuration: ContentHash,
    template_event_log_offset: EventLogOffset,
    world_assembly: QemuHotForkWorldAssemblyToken,
    target: G,
    basis: QemuHotForkChildProcessBasis,
    pending_child_qmp: Option<crucible_qemu::QemuHotForkChildQmpHostEndpoint>,
    scheduler_node: Option<QemuHotForkSchedulerNodeContinuation>,
    installed_node: Option<QemuNode>,
    installed_node_id: Option<NodeId>,
    diagnostics_consumer: QemuHotForkChildDiagnosticConsumer,
    detached_resources: Option<QemuHotForkDetachedChildResources>,
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

impl<G> fmt::Debug for LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkReconciliationBackend")
            .field("basis", &self.basis)
            .field("world_assembly", &self.world_assembly)
            .field("pending_child_qmp", &self.pending_child_qmp.is_some())
            .field("scheduler_node_admitted", &self.scheduler_node.is_some())
            .field("scheduler_node_installed", &self.installed_node.is_some())
            .field("installed_node_id", &self.installed_node_id)
            .field("diagnostics_consumer", &self.diagnostics_consumer)
            .field("detached_resources", &self.detached_resources.is_some())
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
    pub(super) fn from_world_launch(
        source: LinuxQemuHotForkWorldLaunchSource,
        world_assembly: QemuHotForkWorldAssemblyToken,
        target: G,
        launch: QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>,
        detached_resources: QemuHotForkDetachedChildResources,
        run_directory: crucible_qemu::QemuPreparedRunDirectory,
    ) -> Self {
        let template_event_log_offset = source.event_log.offset();
        let (_parent, process, child_qmp, diagnostics_consumer, host_continuation) =
            launch.into_parts();
        let basis = process.basis();
        let process_owner = Arc::new(LinuxQemuHotForkProcessOwner {
            source: LinuxQemuHotForkSourceOwner {
                source_world: source.source_world,
                node: source.node,
            },
            process,
            reaped: AtomicBool::new(false),
        });

        Self {
            process_owner,
            template_configuration: source.configuration,
            template_event_log_offset,
            world_assembly,
            target,
            basis,
            pending_child_qmp: Some(child_qmp),
            scheduler_node: None,
            installed_node: None,
            installed_node_id: None,
            diagnostics_consumer,
            detached_resources: Some(detached_resources),
            host_continuation: Some(host_continuation),
            source_release: LinuxSourceReleasePhase::CloseChildChannel,
            diagnostics: None,
            run_directory: Some(run_directory),
        }
    }

    fn with_source_mut<T>(
        &self,
        operation: impl FnOnce(&mut LinuxQemuHotForkSourceLoan<'_>) -> Result<T, QemuNodeChannelError>,
    ) -> Result<T, LinuxQemuHotForkReconciliationError> {
        self.process_owner.with_source(operation)
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

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        let reconciliation = self.reconciliation.as_ref().ok_or_else(|| {
            hot_fork_adoption_error("hot-fork child no longer retains its reconciliation owner")
        })?;
        let directory = reconciliation
            .backend
            .as_ref()
            .and_then(|backend| backend.run_directory.as_ref())
            .ok_or_else(|| {
                hot_fork_adoption_error("hot-fork child lost its pinned run-directory authority")
            })?;
        directory
            .open_root_overlay_for_checkpoint()
            .map_err(|error| {
                hot_fork_adoption_error(format!("open pinned hot-fork checkpoint overlay: {error}"))
            })
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
        let Some(run_directory) = backend.run_directory.as_ref() else {
            return retain_failed_world_adoption(
                self,
                "hot-fork child lost its pinned run-directory authority",
            );
        };
        if let Err(error) = run_directory.validate_hot_fork_adoption() {
            return retain_failed_world_adoption(
                self,
                format!("hot-fork child run-directory handoff failed: {error}"),
            );
        }
        let run_directory = run_directory.path().to_path_buf();
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

    /// Returns the authenticated child basis and required world assembly token.
    pub(crate) fn world_child_admission_basis(
        &self,
    ) -> Result<
        (
            QemuHotForkWorldChildSourceBasis,
            &QemuHotForkWorldAssemblyToken,
        ),
        Box<QemuHotForkAttemptReconciliationError<LinuxQemuHotForkReconciliationError>>,
    > {
        let basis = self.world_child_source_basis()?;
        let backend = self.backend_ref().map_err(Box::new)?;
        Ok((basis, &backend.world_assembly))
    }
}
