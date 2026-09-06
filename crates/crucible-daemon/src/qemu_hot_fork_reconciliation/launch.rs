//! Failure-retaining single-node and aggregate-world fork transactions.
//!
//! Every fork provisions the target attempt's run directory first and lends
//! its empty VMState container to the source as the child's private copy, so
//! the child never shares a writable native file with the retained template.

use crucible_qemu::{
    DEFAULT_VMSTATE_NODE_NAME, QemuChildProcessContract, QemuHotForkChildFileDestination,
    QemuLaunchResourceRequirements, QemuPreparedRunDirectory, QemuSpawnError,
    QmpHotForkChildFileRoot, ROOT_DRIVE_ID,
};

use super::linux::LinuxQemuHotForkWorldLaunchSource;
use super::*;
use crate::QemuAttemptOperationalBoundary;

/// Forks `source` into `target` with the target's provisioned VMState container
/// and optional root overlay as the child's private copies.
fn with_private_file_destinations<T>(
    run_directory: &QemuPreparedRunDirectory,
    launch_resources: QemuLaunchResourceRequirements,
    operation: impl FnOnce(&[QemuHotForkChildFileDestination<'_>]) -> Result<T, QemuHotForkLaunchError>,
) -> Result<T, QemuHotForkLaunchError> {
    let rejected = |operation: &'static str, message: String| QemuHotForkLaunchError::Rejected {
        source: QemuNodeChannelError::new(operation, message),
    };
    let vmstate_root = QmpHotForkChildFileRoot::node_name(DEFAULT_VMSTATE_NODE_NAME)
        .map_err(|source| rejected("select hot-fork VMState root", source.to_string()))?;
    let vmstate_destination = run_directory
        .hot_fork_child_file_destination()
        .map_err(|source| rejected("lend target VMState container", source.to_string()))?;
    let overlay_root = launch_resources
        .has_root_overlay()
        .then(|| QmpHotForkChildFileRoot::device(ROOT_DRIVE_ID))
        .transpose()
        .map_err(|source| rejected("select hot-fork root-overlay drive", source.to_string()))?;
    let overlay_destination = overlay_root
        .as_ref()
        .map(|_root| run_directory.hot_fork_root_overlay_destination())
        .transpose()
        .map_err(|source| rejected("lend target root-overlay container", source.to_string()))?;
    let mut destinations = Vec::with_capacity(1 + usize::from(overlay_root.is_some()));
    destinations.push(QemuHotForkChildFileDestination::new(
        &vmstate_root,
        vmstate_destination,
    ));
    if let (Some(root), Some(destination)) = (&overlay_root, overlay_destination) {
        destinations.push(QemuHotForkChildFileDestination::new(root, destination));
    }
    operation(&destinations)
}

fn fork_with_private_files<O, F>(
    source: &mut QemuNode,
    run_directory: &QemuPreparedRunDirectory,
    launch_resources: QemuLaunchResourceRequirements,
    target: &mut O,
    contract_for: F,
) -> Result<QemuHotForkChildLaunch<O::Authority>, QemuHotForkLaunchError>
where
    O: QemuHotForkChildProcessOwner,
    F: for<'a> FnOnce(&'a O) -> Result<&'a QemuChildProcessContract, QemuNodeChannelError>,
{
    let rejected = |operation: &'static str, message: String| QemuHotForkLaunchError::Rejected {
        source: QemuNodeChannelError::new(operation, message),
    };
    let vmstate_root = QmpHotForkChildFileRoot::node_name(DEFAULT_VMSTATE_NODE_NAME)
        .map_err(|source| rejected("select hot-fork VMState root", source.to_string()))?;
    let destination = run_directory
        .hot_fork_child_file_destination()
        .map_err(|source| rejected("lend target VMState container", source.to_string()))?;
    let destinations = [QemuHotForkChildFileDestination::new(
        &vmstate_root,
        destination,
    )];
    source.fork_prepared_hot_fork_template_with_files_into(
        target,
        contract_for,
        &destinations,
        launch_resources.minimum_writable_bytes(),
    )
}

/// Forks through a narrow source-world loan while the target guard is lent.
///
/// The caller establishes the only nested lock order used by this path:
/// aggregate target first, source world second. `contract_for` may inspect the
/// already-borrowed target guard but must never query or lock the source world.
fn fork_source_world_with_private_files<O, F>(
    source: &mut QemuNodeSetPreparedHotForkSource<'_>,
    run_directory: &QemuPreparedRunDirectory,
    launch_resources: QemuLaunchResourceRequirements,
    target: &mut O,
    contract_for: F,
) -> Result<QemuHotForkChildLaunch<O::Authority>, QemuHotForkLaunchError>
where
    O: QemuHotForkChildProcessOwner + QemuAttemptOperationalBoundary,
    F: for<'a> FnOnce(&'a O) -> Result<&'a QemuChildProcessContract, QemuNodeChannelError>,
{
    let maximum_child_file_bytes = target.resource_limits().maximum_disk_bytes();
    with_private_file_destinations(run_directory, launch_resources, |destinations| {
        source.fork_with_files_into(target, contract_for, destinations, maximum_child_file_bytes)
    })
}

/// Launch failure retaining the reusable source and target attempt owner.
pub struct LinuxQemuHotForkAttemptLaunchError<G> {
    source: Box<QemuHotForkLaunchError>,
    template: Box<QemuPreparedHotForkTemplate<QemuNode>>,
    target: Box<G>,
}

impl<G> fmt::Debug for LinuxQemuHotForkAttemptLaunchError<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkAttemptLaunchError")
            .field("source", &self.source)
            .field("template_configuration", &self.template.configuration())
            .finish_non_exhaustive()
    }
}

impl<G> fmt::Display for LinuxQemuHotForkAttemptLaunchError<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "launch retained-template hot fork failed: {}",
            self.source
        )
    }
}

impl<G> Error for LinuxQemuHotForkAttemptLaunchError<G>
where
    G: 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl<G> LinuxQemuHotForkAttemptLaunchError<G> {
    /// Recovers the exact launch failure, source template, and target owner.
    pub fn into_parts(
        self,
    ) -> (
        QemuHotForkLaunchError,
        QemuPreparedHotForkTemplate<QemuNode>,
        G,
    ) {
        (*self.source, *self.template, *self.target)
    }
}

/// Failure to launch one child through an aggregate World resource owner.
#[derive(Debug, Error)]
pub enum LinuxQemuHotForkWorldAttemptLaunchFailure {
    /// The aggregate target owner rejected reservation or launch access.
    #[error("aggregate hot-fork World resource admission failed: {0}")]
    Target(#[source] QemuVmRealizationError),
    /// QEMU rejected or failed the retained-template fork transaction.
    #[error(transparent)]
    Launch(#[from] QemuHotForkLaunchError),
    /// An explicit no-child rejection could not roll back its reservation.
    #[error(
        "hot-fork launch was rejected before child creation, but target rollback failed: {rollback}"
    )]
    RejectedRollback {
        /// Original explicit no-child fork rejection.
        launch: QemuHotForkLaunchError,
        /// Aggregate target-reservation rollback failure.
        #[source]
        rollback: QemuVmRealizationError,
    },
    /// QEMU forked the child, but its branch-private files could not be sealed.
    #[error("forked child file authentication failed after QEMU success: {0}")]
    ChildFileSeal(#[source] QemuSpawnError),
}

/// Aggregate-World launch failure retaining the exact source template.
#[must_use = "recover or quarantine the returned source template"]
pub struct LinuxQemuHotForkWorldAttemptLaunchError {
    source: Box<LinuxQemuHotForkWorldAttemptLaunchFailure>,
    template: Box<QemuPreparedHotForkTemplate<QemuNode>>,
}

/// Aggregate-World launch failure retaining the complete source-world owner.
#[must_use = "recover or quarantine the returned source world"]
pub struct LinuxQemuHotForkSourceWorldAttemptLaunchError {
    source: Box<LinuxQemuHotForkWorldAttemptLaunchFailure>,
    owner: Box<LinuxQemuHotForkSourceWorldFailureOwner>,
}

/// Complete authority retained after a source-world launch failure.
///
/// Explicit no-child failures can be recovered with
/// [`Self::into_recoverable_parts`]. Ambiguous and post-fork failures retain
/// the source lifecycle, prepared destination, and child launch authority as
/// one process-lifetime quarantine if this owner is dropped.
#[must_use = "recover a proven no-child failure or retain its quarantine owner"]
pub struct LinuxQemuHotForkSourceWorldFailureOwner {
    source_world: Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>>,
    run_directory: Option<Box<QemuPreparedRunDirectory>>,
    stranded_launch: Option<Box<QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>>>,
    unresolved_child: bool,
}

struct LinuxQemuHotForkSourceWorldQuarantine {
    _source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    _run_directory: Option<Box<QemuPreparedRunDirectory>>,
    _stranded_launch: Option<Box<QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>>>,
}

enum SourceWorldChildLaunchError {
    Fork(QemuHotForkLaunchError),
    ChildFileSeal {
        source: QemuSpawnError,
        launch: Box<QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>>,
    },
}

impl fmt::Debug for LinuxQemuHotForkSourceWorldAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkSourceWorldAttemptLaunchError")
            .field("source", &self.source)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for LinuxQemuHotForkSourceWorldAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "launch retained source-world child failed: {}",
            self.source
        )
    }
}

impl Error for LinuxQemuHotForkSourceWorldAttemptLaunchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl LinuxQemuHotForkSourceWorldAttemptLaunchError {
    /// Recovers the exact failure and its complete authority owner.
    pub fn into_parts(
        self,
    ) -> (
        LinuxQemuHotForkWorldAttemptLaunchFailure,
        LinuxQemuHotForkSourceWorldFailureOwner,
    ) {
        (*self.source, *self.owner)
    }
}

impl fmt::Debug for LinuxQemuHotForkSourceWorldFailureOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkSourceWorldFailureOwner")
            .field(
                "source_owner_count",
                &self.source_world.as_ref().map(Arc::strong_count),
            )
            .field("run_directory", &self.run_directory.is_some())
            .field("stranded_launch", &self.stranded_launch.is_some())
            .field("unresolved_child", &self.unresolved_child)
            .finish_non_exhaustive()
    }
}

impl LinuxQemuHotForkSourceWorldFailureOwner {
    fn new(
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        run_directory: Option<QemuPreparedRunDirectory>,
        stranded_launch: Option<QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>>,
        unresolved_child: bool,
    ) -> Self {
        Self {
            source_world: Some(source_world),
            run_directory: run_directory.map(Box::new),
            stranded_launch: stranded_launch.map(Box::new),
            unresolved_child,
        }
    }

    /// Borrows the complete production source-world owner while it is retained.
    #[must_use]
    pub const fn source_world(&self) -> Option<&Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        self.source_world.as_ref()
    }

    /// Reports whether the target destination directory was provisioned.
    #[must_use]
    pub fn has_run_directory(&self) -> bool {
        self.run_directory.is_some()
    }

    /// Reports whether QEMU returned a successful child launch before failure.
    #[must_use]
    pub fn has_stranded_launch(&self) -> bool {
        self.stranded_launch.is_some()
    }

    /// Recovers authority after a proven no-child failure.
    ///
    /// # Errors
    ///
    /// Returns this owner unchanged when QEMU may have created a child. Dropping
    /// that returned owner transfers every retained capability into quarantine.
    pub fn into_recoverable_parts(
        mut self,
    ) -> Result<
        (
            Arc<Mutex<ProductionVmHotForkSourceWorld>>,
            Option<QemuPreparedRunDirectory>,
        ),
        Self,
    > {
        if self.unresolved_child {
            return Err(self);
        }
        let Some(source_world) = self.source_world.take() else {
            return Err(self);
        };
        let run_directory = self.run_directory.take().map(|directory| *directory);
        Ok((source_world, run_directory))
    }
}

impl Drop for LinuxQemuHotForkSourceWorldFailureOwner {
    fn drop(&mut self) {
        if !self.unresolved_child {
            return;
        }
        let Some(source_world) = self.source_world.take() else {
            return;
        };
        let quarantine = LinuxQemuHotForkSourceWorldQuarantine {
            _source_world: source_world,
            _run_directory: self.run_directory.take(),
            _stranded_launch: self.stranded_launch.take(),
        };
        let _retained_for_process_lifetime = Box::leak(Box::new(quarantine));
    }
}

impl fmt::Debug for LinuxQemuHotForkWorldAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkWorldAttemptLaunchError")
            .field("source", &self.source)
            .field("template_configuration", &self.template.configuration())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for LinuxQemuHotForkWorldAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "launch retained-template World child failed: {}",
            self.source
        )
    }
}

impl Error for LinuxQemuHotForkWorldAttemptLaunchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl LinuxQemuHotForkWorldAttemptLaunchError {
    /// Recovers the exact launch failure and retained source template.
    pub fn into_parts(
        self,
    ) -> (
        LinuxQemuHotForkWorldAttemptLaunchFailure,
        QemuPreparedHotForkTemplate<QemuNode>,
    ) {
        (*self.source, *self.template)
    }
}

impl<G> QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>
where
    G: crate::QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    /// Forks a retained source directly into one target reconciliation owner.
    ///
    /// The source derives the exact fork request from QEMU's retained template
    /// and child-resource reports. This operation obtains the target's sealed
    /// process contract, installs it into the exact prepared template, and
    /// rolls it back after an explicit pre-fork rejection. Callers therefore
    /// cannot omit or substitute the target containment basis or inject any
    /// generation value. No successful launch token is exposed outside the
    /// owner. Post-fork failures return both authorities in their already-
    /// quarantined state for caller-directed cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuHotForkAttemptLaunchError`] with the source and target
    /// authorities when QEMU rejects the request or launch ownership cannot be
    /// established exactly.
    pub fn launch(
        attempt: QemuHotForkAttemptBasis,
        input: &CrucibleAttemptExecution,
        template: QemuPreparedHotForkTemplate<QemuNode>,
        target: G,
    ) -> Result<Self, LinuxQemuHotForkAttemptLaunchError<G>> {
        Self::launch_inner(attempt, input, template, target, None)
    }

    fn launch_inner(
        attempt: QemuHotForkAttemptBasis,
        input: &CrucibleAttemptExecution,
        template: QemuPreparedHotForkTemplate<QemuNode>,
        mut target: G,
        world_assembly: Option<QemuHotForkWorldAssemblyToken>,
    ) -> Result<Self, LinuxQemuHotForkAttemptLaunchError<G>> {
        let (mut source_node, template_identity) = template.into_parts();
        let run_directory =
            match target.prepare_generation_run_directory(template_identity.launch_resources()) {
                Ok(run_directory) => run_directory,
                Err(source) => {
                    return Err(LinuxQemuHotForkAttemptLaunchError {
                        source: Box::new(QemuHotForkLaunchError::Rejected {
                            source: QemuNodeChannelError::new(
                                "prepare target hot-fork run directory",
                                source.to_string(),
                            ),
                        }),
                        template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                            source_node,
                            template_identity,
                        )),
                        target: Box::new(target),
                    });
                }
            };
        let launched = fork_with_private_files(
            &mut source_node,
            &run_directory,
            template_identity.launch_resources(),
            &mut target,
            |target| {
                target.child_process_contract().map_err(|source| {
                    QemuNodeChannelError::new(
                        "obtain target hot-fork process contract",
                        source.to_string(),
                    )
                })
            },
        );
        match launched {
            Ok(launch) => Ok(Self::new(
                attempt,
                LinuxQemuHotForkReconciliationBackend::from_launch(
                    source_node,
                    template_identity,
                    input.clone(),
                    world_assembly,
                    target,
                    launch,
                    run_directory,
                ),
            )),
            Err(source) => Err(LinuxQemuHotForkAttemptLaunchError {
                source: Box::new(source),
                template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                    source_node,
                    template_identity,
                )),
                target: Box::new(target),
            }),
        }
    }
}

impl<G>
    QemuHotForkAttemptReconciliation<
        LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
    >
where
    G: crate::QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    /// Forks one node through the exact aggregate World target owner.
    ///
    /// The node target is reserved before QEMU can create a child. An explicit
    /// pre-fork rejection rolls that reservation back; every ambiguous or
    /// post-fork failure quarantines the complete aggregate owner. Success
    /// retains only a per-node release share in the reconciliation backend, so
    /// no child can independently release CPU, memory, storage, cancellation,
    /// or execution-quantum enforcement for the rest of the World.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuHotForkWorldAttemptLaunchError`] with the exact source
    /// template after target reservation, fork, or rollback failure. The target
    /// owner remains with the caller and is either reusable after a proven
    /// no-child rejection or terminally quarantined.
    pub fn launch_for_world(
        attempt: QemuHotForkAttemptBasis,
        input: &CrucibleAttemptExecution,
        template: QemuPreparedHotForkTemplate<QemuNode>,
        target: &mut QemuHotForkWorldResourceOwner<G>,
        node_generation: ProductionVmNodeGeneration,
        world_assembly: QemuHotForkWorldAssemblyToken,
    ) -> Result<Self, LinuxQemuHotForkWorldAttemptLaunchError> {
        let node_target = match target.reserve_node(node_generation) {
            Ok(node_target) => node_target,
            Err(source) => {
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Target(source)),
                    template: Box::new(template),
                });
            }
        };
        let (mut source_node, template_identity) = template.into_parts();
        let launch_resources = template_identity.launch_resources();
        let launched = target.with_guard_mut(|guard| {
            let run_directory = guard
                .prepare_generation_run_directory(launch_resources)
                .map_err(|source| QemuHotForkLaunchError::Rejected {
                    source: QemuNodeChannelError::new(
                        "prepare aggregate target hot-fork run directory",
                        source.to_string(),
                    ),
                })?;
            let launch = fork_with_private_files(
                &mut source_node,
                &run_directory,
                launch_resources,
                guard,
                |guard| {
                    guard.child_process_contract().map_err(|source| {
                        QemuNodeChannelError::new(
                            "obtain aggregate target hot-fork process contract",
                            source.to_string(),
                        )
                    })
                },
            )?;
            Ok((launch, run_directory))
        });
        let (launch, run_directory) = match launched {
            Ok(Ok(launch)) => launch,
            Ok(Err(source @ QemuHotForkLaunchError::Rejected { .. })) => {
                let failure = match node_target.abort_without_child() {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source),
                    Err(rollback) => {
                        target.quarantine();
                        LinuxQemuHotForkWorldAttemptLaunchFailure::RejectedRollback {
                            launch: source,
                            rollback,
                        }
                    }
                };
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(failure),
                    template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                        source_node,
                        template_identity,
                    )),
                });
            }
            Ok(Err(source)) => {
                let mut node_target = node_target;
                crate::QemuAttemptResourceGuard::quarantine(&mut node_target);
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source)),
                    template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                        source_node,
                        template_identity,
                    )),
                });
            }
            Err(source) => {
                let rollback = node_target.abort_without_child();
                let failure = match rollback {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Target(source),
                    Err(rollback) => {
                        target.quarantine();
                        LinuxQemuHotForkWorldAttemptLaunchFailure::Target(
                            QemuVmRealizationError::Executor {
                                operation: "roll back aggregate hot-fork target reservation",
                                message: format!(
                                    "launch access failed: {source}; rollback failed: {rollback}"
                                ),
                            },
                        )
                    }
                };
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(failure),
                    template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                        source_node,
                        template_identity,
                    )),
                });
            }
        };

        Ok(Self::new(
            attempt,
            LinuxQemuHotForkReconciliationBackend::from_launch(
                source_node,
                template_identity,
                input.clone(),
                Some(world_assembly),
                node_target,
                launch,
                run_directory,
            ),
        ))
    }

    /// Forks one node from a complete production source world.
    ///
    /// The complete lifecycle, source nodes, generation leases, run
    /// directories, and run lock remain inside `source_world`. Success moves
    /// this shared owner into the child reconciliation; callers may retain
    /// clones for sibling launches, but cannot recover the lifecycle while any
    /// child owns a strong reference. The sole nested lock order is aggregate
    /// target then source world during the fork transaction. The process-
    /// contract callback reads only the already-borrowed target guard.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuHotForkSourceWorldAttemptLaunchError`] with the
    /// complete source-world owner after source authentication, target
    /// reservation, fork, or rollback failure. Explicit no-child rejection
    /// rolls back the node reservation; ambiguous and post-fork failure
    /// quarantine the aggregate target while retaining source-side stages.
    pub fn launch_from_source_world(
        attempt: QemuHotForkAttemptBasis,
        input: &CrucibleAttemptExecution,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        source_node: NodeId,
        target: &mut QemuHotForkWorldResourceOwner<G>,
        node_generation: ProductionVmNodeGeneration,
        world_assembly: QemuHotForkWorldAssemblyToken,
    ) -> Result<Self, LinuxQemuHotForkSourceWorldAttemptLaunchError> {
        let source_error = |operation: &'static str, message: String| {
            LinuxQemuHotForkSourceWorldAttemptLaunchError {
                source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Target(
                    QemuVmRealizationError::Executor { operation, message },
                )),
                owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                    Arc::clone(&source_world),
                    None,
                    None,
                    false,
                )),
            }
        };
        if node_generation.node() != &source_node {
            return Err(source_error(
                "bind production hot-fork source generation",
                format!(
                    "source node `{}` differs from target generation node `{}`",
                    source_node.name,
                    node_generation.node().name
                ),
            ));
        }
        let (configuration, event_log, launch_resources) = {
            let mut world = source_world.lock().map_err(|_source| {
                source_error(
                    "lock production hot-fork source world",
                    String::from("source-world ownership lock is poisoned"),
                )
            })?;
            let source = world.prepared_source(&source_node).map_err(|error| {
                source_error("authenticate production hot-fork source", error.to_string())
            })?;
            (
                source.configuration(),
                source.fork_event_log(),
                source.launch_resources(),
            )
        };
        let node_target = match target.reserve_node(node_generation) {
            Ok(node_target) => node_target,
            Err(source) => {
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Target(source)),
                    owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                        source_world,
                        None,
                        None,
                        false,
                    )),
                });
            }
        };
        let launched = target.with_guard_mut(|guard| {
            let mut run_directory = guard
                .prepare_generation_run_directory(launch_resources)
                .map_err(|source| QemuHotForkLaunchError::Rejected {
                    source: QemuNodeChannelError::new(
                        "prepare aggregate target hot-fork run directory",
                        source.to_string(),
                    ),
                })?;
            let launch = match source_world.lock() {
                Err(_source) => Err(QemuHotForkLaunchError::Rejected {
                    source: QemuNodeChannelError::new(
                        "lock production hot-fork source world",
                        "source-world ownership lock is poisoned",
                    ),
                }),
                Ok(mut world) => match world.prepared_source(&source_node) {
                    Err(error) => Err(QemuHotForkLaunchError::Rejected {
                        source: QemuNodeChannelError::new(
                            "authenticate production hot-fork source",
                            error.to_string(),
                        ),
                    }),
                    Ok(mut source) => fork_source_world_with_private_files(
                        &mut source,
                        &run_directory,
                        launch_resources,
                        guard,
                        |guard| {
                            guard.child_process_contract().map_err(|source| {
                                QemuNodeChannelError::new(
                                    "obtain aggregate target hot-fork process contract",
                                    source.to_string(),
                                )
                            })
                        },
                    ),
                },
            };
            let launch = match launch {
                Ok(launch) => match run_directory.seal_hot_fork_child_file_transfer(&launch) {
                    Ok(()) => Ok(launch),
                    Err(source) => Err(SourceWorldChildLaunchError::ChildFileSeal {
                        source,
                        launch: Box::new(launch),
                    }),
                },
                Err(source) => {
                    run_directory.invalidate_hot_fork_child_file_transfer();
                    Err(SourceWorldChildLaunchError::Fork(source))
                }
            };
            Ok((launch, run_directory))
        });
        let (launch, run_directory) = match launched {
            Ok(Ok((Ok(launch), run_directory))) => (launch, run_directory),
            Ok(Ok((
                Err(SourceWorldChildLaunchError::Fork(
                    source @ QemuHotForkLaunchError::Rejected { .. },
                )),
                run_directory,
            ))) => {
                let failure = match node_target.abort_without_child() {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source),
                    Err(rollback) => {
                        target.quarantine();
                        LinuxQemuHotForkWorldAttemptLaunchFailure::RejectedRollback {
                            launch: source,
                            rollback,
                        }
                    }
                };
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(failure),
                    owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                        source_world,
                        Some(run_directory),
                        None,
                        false,
                    )),
                });
            }
            Ok(Ok((Err(SourceWorldChildLaunchError::Fork(source)), run_directory))) => {
                let mut node_target = node_target;
                crate::QemuAttemptResourceGuard::quarantine(&mut node_target);
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source)),
                    owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                        source_world,
                        Some(run_directory),
                        None,
                        true,
                    )),
                });
            }
            Ok(Ok((
                Err(SourceWorldChildLaunchError::ChildFileSeal { source, launch }),
                run_directory,
            ))) => {
                let mut node_target = node_target;
                crate::QemuAttemptResourceGuard::quarantine(&mut node_target);
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::ChildFileSeal(
                        source,
                    )),
                    owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                        source_world,
                        Some(run_directory),
                        Some(*launch),
                        true,
                    )),
                });
            }
            Ok(Err(source @ QemuHotForkLaunchError::Rejected { .. })) => {
                let failure = match node_target.abort_without_child() {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source),
                    Err(rollback) => {
                        target.quarantine();
                        LinuxQemuHotForkWorldAttemptLaunchFailure::RejectedRollback {
                            launch: source,
                            rollback,
                        }
                    }
                };
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(failure),
                    owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                        source_world,
                        None,
                        None,
                        false,
                    )),
                });
            }
            Ok(Err(source)) => {
                let mut node_target = node_target;
                crate::QemuAttemptResourceGuard::quarantine(&mut node_target);
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source)),
                    owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                        source_world,
                        None,
                        None,
                        true,
                    )),
                });
            }
            Err(source) => {
                let rollback = node_target.abort_without_child();
                let failure = match rollback {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Target(source),
                    Err(rollback) => {
                        target.quarantine();
                        LinuxQemuHotForkWorldAttemptLaunchFailure::Target(
                            QemuVmRealizationError::Executor {
                                operation: "roll back aggregate hot-fork target reservation",
                                message: format!(
                                    "launch access failed: {source}; rollback failed: {rollback}"
                                ),
                            },
                        )
                    }
                };
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(failure),
                    owner: Box::new(LinuxQemuHotForkSourceWorldFailureOwner::new(
                        source_world,
                        None,
                        None,
                        false,
                    )),
                });
            }
        };

        Ok(Self::new(
            attempt,
            LinuxQemuHotForkReconciliationBackend::from_world_launch(
                LinuxQemuHotForkWorldLaunchSource {
                    source_world,
                    node: source_node,
                    configuration,
                    event_log,
                },
                input.clone(),
                world_assembly,
                node_target,
                launch,
                run_directory,
            ),
        ))
    }
}

#[cfg(test)]
#[path = "launch/tests.rs"]
mod tests;
