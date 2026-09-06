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
    ChildQmp,
    Diagnostics,
    PrivateRing,
    Complete,
}

struct LinuxQemuHotForkProcessOwner {
    source: Mutex<Option<QemuNode>>,
    process: LinuxQemuHotForkChildProcessAuthority,
    reaped: AtomicBool,
}

impl LinuxQemuHotForkProcessOwner {
    fn observe_child(
        &self,
    ) -> Result<QmpHotForkChildProcessState, LinuxQemuHotForkReconciliationError> {
        let mut source = self
            .source
            .lock()
            .map_err(|_source| LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned)?;
        let source = source
            .as_mut()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        let state = source.query_hot_fork_child_process(
            self.process.basis().request().child_process_generation(),
        )?;
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
    template_identity: QemuHotForkTemplateIdentity,
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
            source: Mutex::new(Some(source)),
            process,
            reaped: AtomicBool::new(false),
        });
        let child_event_log = template_identity.fork_event_log();
        Self {
            process_owner,
            template_identity,
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
        operation: impl FnOnce(&mut QemuNode) -> Result<T, QemuNodeChannelError>,
    ) -> Result<T, LinuxQemuHotForkReconciliationError> {
        let mut source = self
            .process_owner
            .source
            .lock()
            .map_err(|_source| LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned)?;
        operation(
            source
                .as_mut()
                .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?,
        )
        .map_err(Into::into)
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
            configuration: self.template_identity.configuration(),
            event_log_offset: self.template_identity.event_log().offset(),
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
        let source = Arc::get_mut(&mut self.process_owner)
            .and_then(|owner| owner.source.get_mut().ok())
            .and_then(Option::take);
        let Some(source) = source else {
            return Err(Box::new(self));
        };
        Ok(QemuPreparedHotForkTemplate::from_reconciled_parts(
            source,
            self.template_identity,
        ))
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
