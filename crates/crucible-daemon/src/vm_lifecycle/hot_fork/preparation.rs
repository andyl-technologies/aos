//! Prepares a source while its existing Loop Box and capture metadata stay owned.
//!
//! The containing Main integration can retain this value before calling `run`.
//! Refusal closes preparation but leaves the exact Box, received tokens, disk
//! custody and typed first error here. This module issues no role or Original.

use super::*;

/// Preserves the typed cause of the first source-preparation refusal.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProductionVmHotForkSourcePreparationError {
    /// A scheduler capture, validation or disk operation refused.
    #[error("{operation}: {source}")]
    Scheduler {
        /// Names the actual operation that returned this cause.
        operation: &'static str,
        /// Retains the original error without formatting or copying it.
        #[source]
        source: SchedulerError,
    },
    /// A backend template operation refused.
    #[error("{operation}: {source}")]
    Backend {
        /// Names the actual operation that returned this cause.
        operation: &'static str,
        /// Retains the original backend error.
        #[source]
        source: crucible::BackendError,
    },
    /// Metadata preparation could not reserve its actual token capacity.
    #[error("reserve retained source preparation tokens: {0}")]
    Allocation(#[source] std::collections::TryReserveError),
    /// The same retained input failed an ownership or phase invariant.
    #[error("{0}")]
    State(&'static str),
}

use ProductionVmHotForkSourcePreparationError as First;

pub(crate) struct SourceWorldPreparation {
    pub(super) world: ProductionVmHotForkSourceWorld,
    retained_disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) first: Option<First>,
    current_node: Option<NodeId>,
    current_disk: Option<Arc<ProductionVmHotForkDiskCustody>>,
    promote: bool,
    attempted: bool,
    complete: bool,
    rollback_requested: bool,
    force_current_unreconciled: bool,
    unreconciled_nodes: Vec<NodeId>,
    rollback_diagnostics: BTreeMap<NodeId, String>,
}

/// Keeps the complete capture metadata with a failed preparation's Loop Box.
pub(super) struct FailedPreparationMetadata {
    pub(super) continuation: Option<ProductionVmHotForkWorldContinuation>,
    pub(super) prepared: Vec<QemuNodeSetPreparedHotForkTemplate>,
    pub(super) disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) retained_disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) node: Option<NodeId>,
    pub(super) current_disk: Option<Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) cleanup_observer: Option<Arc<dyn ProductionHotForkCleanupObserver>>,
}

impl SourceWorldPreparation {
    /// Moves a preheld, already paid Loop Box without allocating another body.
    pub(super) fn new(
        lifecycle: Box<ProductionVmLifecycleLoop>,
        retained_disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
        promote: bool,
    ) -> Self {
        Self {
            world: ProductionVmHotForkSourceWorld {
                lifecycle: Some(lifecycle),
                continuation: None,
                prepared: Vec::new(),
                disk_custody: BTreeMap::new(),
                cleanup_observer: None,
            },
            retained_disk_custody,
            first: None,
            current_node: None,
            current_disk: None,
            promote,
            attempted: false,
            complete: false,
            rollback_requested: false,
            force_current_unreconciled: false,
            unreconciled_nodes: Vec::new(),
            rollback_diagnostics: BTreeMap::new(),
        }
    }

    /// Delegates both owning entry points to the same borrowed engine.
    pub(super) fn prepare_owned(
        lifecycle: ProductionVmLifecycleLoop,
        retained_disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
        promote: bool,
    ) -> Result<ProductionVmHotForkSourceWorld, ProductionVmHotForkSourceWorldPreparationFailure>
    {
        // The existing Source Loop Box precedes the first preparation effect.
        let mut preparation = Self::new(Box::new(lifecycle), retained_disk_custody, promote);
        if preparation.run().is_err() {
            return Err(preparation.into_failure());
        }
        preparation.into_world().map_err(Self::into_failure)
    }

    /// Borrows this same owner for its single preparation attempt.
    ///
    /// The raw cause is saved before rollback or diagnostic formatting. A
    /// refused attempt cannot issue another preparation by calling this again.
    pub(crate) fn run(&mut self) -> Result<(), ()> {
        if self.attempted {
            return Err(());
        }
        self.attempted = true;
        if let Err(first) = self.prepare() {
            self.first = Some(first);
            self.retain_current_disk();
            self.rollback_after_refusal();
            return Err(());
        }
        self.complete = true;
        Ok(())
    }

    fn lifecycle(&mut self) -> Result<&mut ProductionVmLifecycleLoop, First> {
        self.world.lifecycle.as_deref_mut().ok_or(First::State(
            "prepared source world lost its actual Loop Box",
        ))
    }

    fn prepare(&mut self) -> Result<(), First> {
        let continuation = self
            .lifecycle()?
            .capture_hot_fork_world_continuation()
            .map_err(|source| First::Scheduler {
                operation: "capture source world continuation",
                source,
            })?;
        // Save the actual captured continuation before any node mutation.
        self.world.continuation = Some(continuation);
        let retained_nodes = self
            .world
            .continuation
            .as_ref()
            .ok_or(First::State("captured source continuation is absent"))?
            .nodes()
            .iter()
            .filter(|boundary| {
                boundary.service_state() != ProductionVmHotForkNodeServiceState::PermanentlyFailed
            })
            .map(|boundary| boundary.node().clone())
            .collect::<Vec<_>>();

        if self.promote {
            validate_retained_source_ownership(self.lifecycle()?, &retained_nodes).map_err(
                |source| First::Scheduler {
                    operation: "validate reconstructed child ownership",
                    source,
                },
            )?;
            for node in &retained_nodes {
                self.current_node = Some(node.clone());
                if let Err(source) = self
                    .lifecycle()?
                    .inner
                    .backend_mut()
                    .adopt_hot_fork_child_as_template_source(node)
                {
                    self.unreconciled_nodes = retained_nodes.clone();
                    return Err(First::Backend {
                        operation: "re-adopt reconstructed child",
                        source,
                    });
                }
            }
            if let Err(first) = self.validate_boundaries("revalidate re-adopted child world") {
                self.unreconciled_nodes = retained_nodes;
                return Err(first);
            }
            self.current_node = None;
        }

        validate_retained_source_ownership(self.lifecycle()?, &retained_nodes).map_err(
            |source| First::Scheduler {
                operation: "validate retained source ownership",
                source,
            },
        )?;
        if self
            .retained_disk_custody
            .keys()
            .any(|node| !retained_nodes.contains(node))
        {
            self.unreconciled_nodes = self.retained_disk_custody.keys().cloned().collect();
            return Err(First::State(
                "retained disk custody names a source outside the current world",
            ));
        }
        self.world
            .prepared
            .try_reserve_exact(retained_nodes.len())
            .map_err(First::Allocation)?;
        let configuration = self
            .world
            .continuation
            .as_ref()
            .ok_or(First::State("captured source continuation is absent"))?
            .configuration()
            .id();
        let event_log = self.lifecycle()?.inner.loop_impl().event_log().clone();
        for node in &retained_nodes {
            let launch_resources = match self.lifecycle()?.launch_configs.get(node) {
                Some(config) => config.resource_requirements(),
                None => {
                    self.rollback_requested = true;
                    return Err(First::State("retained source has no launch profile"));
                }
            };
            self.current_node = Some(node.clone());
            self.rollback_requested = true;
            self.force_current_unreconciled = true;
            // A failed reacquisition must not discard its previous file owner.
            let prior = self.retained_disk_custody.get(node).cloned();
            let disk = match prior {
                Some(custody) => self
                    .lifecycle()?
                    .reacquire_sealed_hot_fork_disk(node, &custody)
                    .map(|(custody, binding)| Some((Arc::new(custody), binding))),
                None => self
                    .lifecycle()?
                    .prepare_sealed_hot_fork_disk(node)
                    .map(|disk| disk.map(|(custody, binding)| (Arc::new(custody), binding))),
            }
            .map_err(|source| First::Scheduler {
                operation: "seal retained source disk",
                source,
            })?;
            self.force_current_unreconciled = disk.is_some();
            let binding_storage = match disk {
                Some((custody, binding)) => {
                    // The output owner is inline before map or Box allocation.
                    self.current_disk = Some(custody);
                    let custody = self.current_disk.as_ref().cloned().ok_or(First::State(
                        "returned disk custody disappeared before retention",
                    ))?;
                    self.world
                        .disk_custody
                        .insert(node.clone(), Arc::clone(&custody));
                    self.world
                        .continuation
                        .as_mut()
                        .ok_or(First::State("captured source continuation is absent"))?
                        .disk_bases
                        .insert(node.clone(), custody.basis().clone());
                    Some(binding)
                }
                None => None,
            };
            self.retained_disk_custody.remove(node);
            let token = self
                .lifecycle()?
                .inner
                .backend_mut()
                .prepare_retained_hot_fork_template(
                    node,
                    configuration,
                    event_log.clone(),
                    launch_resources,
                    binding_storage.as_slice(),
                    MAXIMUM_HOT_FORK_RING_IMAGE_BYTES,
                )
                .map_err(|source| First::Backend {
                    operation: "prepare retained source template",
                    source,
                })?;
            let generation = token.template_generation();
            // A returned token remains owned even when graph authentication fails.
            self.world.prepared.push(token);
            if let Some(custody) = self.current_disk.as_ref().cloned() {
                custody
                    .authenticate_source_graph(self.lifecycle()?, node, generation)
                    .map_err(|source| First::Scheduler {
                        operation: "authenticate retained source graph",
                        source,
                    })?;
            }
            self.retain_current_disk();
            self.current_node = None;
            self.current_disk = None;
            self.rollback_requested = false;
            self.force_current_unreconciled = false;
        }

        self.rollback_requested = true;
        self.validate_boundaries("revalidate prepared source world")?;
        self.world
            .validate_source_ownership()
            .map_err(|source| First::Scheduler {
                operation: "validate complete prepared source ownership",
                source,
            })?;
        self.rollback_requested = false;
        Ok(())
    }

    fn retain_current_disk(&mut self) {
        if let (Some(custody), Some(lifecycle)) = (
            self.current_disk.as_ref(),
            self.world.lifecycle.as_deref_mut(),
        ) {
            // Preserve the existing Loop mutation order: graph authentication
            // precedes this alias on success; refusal retains it before rollback.
            lifecycle
                .retained_hot_fork_disk_owners
                .push(Box::new(Arc::clone(custody)));
        }
    }

    fn validate_boundaries(&mut self, operation: &'static str) -> Result<(), First> {
        let after = self
            .lifecycle()?
            .hot_fork_node_boundaries()
            .map_err(|source| First::Scheduler { operation, source })?;
        let continuation = self
            .world
            .continuation
            .as_ref()
            .ok_or(First::State("captured source continuation is absent"))?;
        if after != continuation.nodes {
            return Err(First::State("prepared source world changed after capture"));
        }
        Ok(())
    }

    fn rollback_after_refusal(&mut self) {
        if !self.rollback_requested {
            return;
        }
        let mut targets = self
            .world
            .prepared
            .iter()
            .map(|token| HotForkRollbackTarget {
                node: token.node().clone(),
                template_generation: if self.current_node.as_ref() == Some(token.node()) {
                    None
                } else {
                    Some(token.template_generation())
                },
            })
            .collect::<Vec<_>>();
        if let Some(node) = &self.current_node
            && !targets.iter().any(|target| &target.node == node)
        {
            targets.push(HotForkRollbackTarget {
                node: node.clone(),
                template_generation: None,
            });
        }
        let Some(lifecycle) = self.world.lifecycle.as_deref_mut() else {
            return;
        };
        let mut rollback = rollback_hot_fork_sources(lifecycle, &targets);
        if self.force_current_unreconciled
            && let Some(node) = &self.current_node
            && !rollback.nodes.contains(node)
        {
            rollback.nodes.push(node.clone());
        }
        if let (
            Some(First::Scheduler {
                operation: "seal retained source disk",
                source,
            }),
            Some(node),
        ) = (self.first.as_ref(), self.current_node.as_ref())
        {
            // Diagnostic formatting follows storage of the original typed cause.
            rollback
                .diagnostics
                .insert(node.clone(), source.to_string());
        }
        self.unreconciled_nodes = rollback.nodes;
        self.rollback_diagnostics = rollback.diagnostics;
    }

    /// Moves a fully prepared world without a callback, allocation or new Box.
    pub(crate) fn into_world(self) -> Result<ProductionVmHotForkSourceWorld, Self> {
        if !self.complete
            || self.first.is_some()
            || self.world.lifecycle.is_none()
            || self.world.continuation.is_none()
            || !self.retained_disk_custody.is_empty()
            || self.current_disk.is_some()
        {
            return Err(self);
        }
        Ok(self.world)
    }

    /// Moves the exact failed Box, capture metadata and original error together.
    pub(crate) fn into_failure(mut self) -> ProductionVmHotForkSourceWorldPreparationFailure {
        let metadata = FailedPreparationMetadata {
            continuation: self.world.continuation.take(),
            prepared: std::mem::take(&mut self.world.prepared),
            disk_custody: std::mem::take(&mut self.world.disk_custody),
            retained_disk_custody: std::mem::take(&mut self.retained_disk_custody),
            node: self.current_node.take(),
            current_disk: self.current_disk.take(),
            cleanup_observer: self.world.cleanup_observer.take(),
        };
        ProductionVmHotForkSourceWorldPreparationFailure {
            retained_source: None,
            lifecycle: self.world.lifecycle.take(),
            message: String::new(),
            first: self
                .first
                .take()
                .or(Some(First::State("source preparation did not complete"))),
            metadata: Some(metadata),
            unreconciled_nodes: std::mem::take(&mut self.unreconciled_nodes),
            rollback_diagnostics: std::mem::take(&mut self.rollback_diagnostics),
        }
    }
}
