//! Failure-retaining single-node and aggregate-world fork transactions.
//!
//! Every fork provisions the target attempt's run directory first and lends
//! its empty VMState container to the source as the child's private copy, so
//! the child never shares a writable native file with the retained template.

use crucible_qemu::{
    DEFAULT_VMSTATE_NODE_NAME, QemuChildProcessContract, QemuHotForkChildFileDestination,
    QemuLaunchResourceRequirements, QemuNodeSetPreparedHotForkSource, QemuPreparedRunDirectory,
    QemuSpawnError, QmpHotForkChildFileRoot, ROOT_DRIVE_ID,
};

use super::linux::LinuxQemuHotForkWorldLaunchSource;
use super::*;
use crate::QemuAttemptOperationalBoundary;

#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const CHILD_RESOURCE_ALIAS_TRIGGER: &str = "crucible.destructive-recovery.child-resource-alias";

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
        #[cfg(feature = "destructive-recovery-faults")]
        let destination = if child_resource_alias_requested() {
            vmstate_destination
        } else {
            destination
        };
        destinations.push(QemuHotForkChildFileDestination::new(root, destination));
    }
    operation(&destinations)
}

#[cfg(feature = "destructive-recovery-faults")]
fn child_resource_alias_requested() -> bool {
    std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT).as_deref()
        == Some(std::ffi::OsStr::new(CHILD_RESOURCE_ALIAS_TRIGGER))
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

/// Failure to launch one child through an aggregate World resource owner.
#[derive(Debug, Error)]
pub enum LinuxQemuHotForkWorldAttemptLaunchFailure {
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
    /// QEMU forked the child, but the source could not detach and rearm exactly.
    #[error("forked child source rearm failed after QEMU success: {0}")]
    SourceRearm(#[source] crucible_qemu::QemuHotForkSourceRearmError),
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
    SourceRearm {
        source: crucible_qemu::QemuHotForkSourceRearmError,
        launch: Box<QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>>,
    },
}

fn fork_seal_and_rearm_prepared_source<G>(
    source: &mut QemuNodeSetPreparedHotForkSource<'_>,
    run_directory: &mut QemuPreparedRunDirectory,
    launch_resources: QemuLaunchResourceRequirements,
    target: &mut G,
) -> Result<
    (
        QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>,
        QemuHotForkDetachedChildResources,
    ),
    SourceWorldChildLaunchError,
>
where
    G: crate::QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    let mut launch = match fork_source_world_with_private_files(
        source,
        run_directory,
        launch_resources,
        target,
        |target| {
            target.child_process_contract().map_err(|source| {
                QemuNodeChannelError::new(
                    "obtain aggregate target hot-fork process contract",
                    source.to_string(),
                )
            })
        },
    ) {
        Ok(launch) => launch,
        Err(source) => {
            run_directory.invalidate_hot_fork_child_file_transfer();
            return Err(SourceWorldChildLaunchError::Fork(source));
        }
    };

    if let Err(source) = run_directory.seal_hot_fork_child_file_transfer(&launch) {
        return Err(SourceWorldChildLaunchError::ChildFileSeal {
            source,
            launch: Box::new(launch),
        });
    }
    let detached = match source.rearm_after_child(&mut launch) {
        Ok(detached) => detached,
        Err(source) => {
            return Err(SourceWorldChildLaunchError::SourceRearm {
                source,
                launch: Box::new(launch),
            });
        }
    };

    Ok((launch, detached))
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

impl<G>
    QemuHotForkAttemptReconciliation<
        LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
    >
where
    G: crate::QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    /// Forks one already-authenticated source loan on a concurrent world worker.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuHotForkSourceWorldAttemptLaunchError`] when child
    /// launch, source rollback, or ownership transfer cannot complete.
    pub fn launch_from_prepared_source(
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        source_node: NodeId,
        mut source: QemuNodeSetPreparedHotForkSource<'_>,
        mut target: QemuHotForkWorldNodeTarget<G>,
        mut run_directory: QemuPreparedRunDirectory,
        world_assembly: QemuHotForkWorldAssemblyToken,
    ) -> Result<Self, LinuxQemuHotForkSourceWorldAttemptLaunchError> {
        let configuration = source.configuration();
        let event_log = source.fork_event_log();
        let launch_resources = source.launch_resources();
        let launched = fork_seal_and_rearm_prepared_source(
            &mut source,
            &mut run_directory,
            launch_resources,
            &mut target,
        );
        let (launch, detached_resources) = match launched {
            Ok(launched) => launched,
            Err(SourceWorldChildLaunchError::Fork(
                source @ QemuHotForkLaunchError::Rejected { .. },
            )) => {
                let failure = match target.abort_without_child() {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source),
                    Err(rollback) => LinuxQemuHotForkWorldAttemptLaunchFailure::RejectedRollback {
                        launch: source,
                        rollback,
                    },
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
            Err(SourceWorldChildLaunchError::Fork(source)) => {
                crate::QemuAttemptResourceGuard::quarantine(&mut target);
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
            Err(SourceWorldChildLaunchError::ChildFileSeal { source, launch }) => {
                crate::QemuAttemptResourceGuard::quarantine(&mut target);
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
            Err(SourceWorldChildLaunchError::SourceRearm { source, launch }) => {
                crate::QemuAttemptResourceGuard::quarantine(&mut target);
                return Err(LinuxQemuHotForkSourceWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::SourceRearm(
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
        };

        Ok(Self::new(
            LinuxQemuHotForkReconciliationBackend::from_world_launch(
                LinuxQemuHotForkWorldLaunchSource {
                    source_world,
                    node: source_node,
                    configuration,
                    event_log,
                },
                world_assembly,
                target,
                launch,
                detached_resources,
                run_directory,
            ),
        ))
    }
}
