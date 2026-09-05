//! Failure-retaining single-node and aggregate-world fork transactions.

use super::*;

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
}

/// Aggregate-World launch failure retaining the exact source template.
#[must_use = "recover or quarantine the returned source template"]
pub struct LinuxQemuHotForkWorldAttemptLaunchError {
    source: Box<LinuxQemuHotForkWorldAttemptLaunchFailure>,
    template: Box<QemuPreparedHotForkTemplate<QemuNode>>,
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
        match source_node.fork_prepared_hot_fork_template_into(&mut target, |target| {
            target.child_process_contract().map_err(|source| {
                QemuNodeChannelError::new(
                    "obtain target hot-fork process contract",
                    source.to_string(),
                )
            })
        }) {
            Ok(launch) => Ok(Self::new(
                attempt,
                LinuxQemuHotForkReconciliationBackend::from_launch(
                    source_node,
                    template_identity,
                    input.clone(),
                    world_assembly,
                    target,
                    launch,
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
        let launched = target.with_guard_mut(|guard| {
            source_node.fork_prepared_hot_fork_template_into(guard, |guard| {
                guard.child_process_contract().map_err(|source| {
                    QemuNodeChannelError::new(
                        "obtain aggregate target hot-fork process contract",
                        source.to_string(),
                    )
                })
            })
        });
        let launch = match launched {
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
            ),
        ))
    }
}
