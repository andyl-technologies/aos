//! Prepares a source while its existing Loop Box and capture metadata stay owned.
//!
//! The containing Main integration can retain this value before calling `run`.
//! Refusal closes preparation but leaves the exact Box, received tokens, disk
//! custody and typed first error here. This module issues no role or Original.

use super::*;

/// Preserves the typed cause of the first source-preparation refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionVmHotForkSourcePreparationError {
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
        source: crucible_engine::BackendError,
    },
    /// Metadata preparation could not reserve its actual token capacity.
    #[error("reserve retained source preparation tokens: {0}")]
    Allocation(#[source] std::collections::TryReserveError),
    /// The actual same Source work boundary refused before an effect.
    #[error("source work boundary: {0}")]
    Original(#[source] LifecycleApiError),
    /// Event evidence at the prepared exact boundary failed authentication.
    #[error("authenticate exact source event identity: {0}")]
    EventIdentity(#[source] crucible_engine::EngineError),
    /// The exact prepared boundary differs from the authenticated request.
    #[error("prepared exact source differs from its authenticated boundary")]
    BoundaryMismatch,
    /// A successful effect was followed by the independently retained post.
    #[error("source work postcheck refused")]
    PostRefused,
    /// The same retained input failed an ownership or phase invariant.
    #[error("{0}")]
    State(&'static str),
}

use ProductionVmHotForkSourcePreparationError as First;

/// Keeps the actual capture refusal and its independent same-work post.
///
/// This diagnostic owns no World, token or cleanup authority. The original
/// Main Pending retains it while its whole preparer owns every partial field.
#[derive(Debug, Default)]
pub struct ProductionVmHotForkSourcePreparationHistory {
    first: Option<First>,
    post: Option<LifecycleApiError>,
}

impl ProductionVmHotForkSourcePreparationHistory {
    /// Borrows the original typed refusal independently of any later post.
    pub fn first_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first.as_ref() {
            Some(First::Scheduler { source, .. }) => Some(source),
            Some(First::Backend { source, .. }) => Some(source),
            Some(First::Allocation(source)) => Some(source),
            Some(First::Original(source)) => Some(source),
            Some(First::EventIdentity(source)) => Some(source),
            Some(First::PostRefused) | None => self
                .post
                .as_ref()
                .map(|post| post as &dyn std::error::Error),
            Some(first) => Some(first),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.first.is_none() && self.post.is_none()
    }
}

impl std::fmt::Display for ProductionVmHotForkSourcePreparationHistory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Source preparation: {:?}; same work post: {:?}",
            self.first, self.post
        )
    }
}

impl std::error::Error for ProductionVmHotForkSourcePreparationHistory {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first_error()
    }
}

pub(crate) enum SourcePreparationBoundary<'a> {
    Canonical,
    Exact {
        requested: ContentHash,
        selected: &'a crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
        production: &'a ProductionVmExactHotForkSourceBoundary,
    },
}

pub(crate) struct SourceWorldPreparation {
    pub(super) world: ProductionVmHotForkSourceWorld,
    retained_disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) first: Option<First>,
    current_node: Option<NodeId>,
    current_disk: Option<Arc<ProductionVmHotForkDiskCustody>>,
    current_binding: Option<crucible_qemu_host::QmpHotForkBlockSnapshotBinding>,
    work_post: Option<LifecycleApiError>,
    checked_work: bool,
    promote: bool,
    attempted: bool,
    complete: bool,
    rollback_requested: bool,
    force_current_unreconciled: bool,
    unreconciled_nodes: Vec<NodeId>,
    rollback_diagnostics: BTreeMap<NodeId, String>,
}

/// Keeps the complete capture metadata with a failed preparation's Loop Box.
#[derive(Default)]
pub(super) struct FailedPreparationMetadata {
    pub(super) continuation: Option<ProductionVmHotForkWorldContinuation>,
    pub(super) prepared: Vec<QemuNodeSetPreparedHotForkTemplate>,
    pub(super) disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) retained_disk_custody: BTreeMap<NodeId, Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) node: Option<NodeId>,
    pub(super) current_disk: Option<Arc<ProductionVmHotForkDiskCustody>>,
    pub(super) cleanup_observer: Option<Arc<dyn ProductionHotForkCleanupObserver>>,
    #[cfg(feature = "private-measurement-domain")]
    pub(super) managed_parent_park_history:
        Option<crate::managed_qemu_hot_fork_source_world_pool::ManagedParentParkGate>,
}

impl SourceWorldPreparation {
    /// Moves a preheld, already paid Loop Box without allocating another body.
    pub(in crate::vm_lifecycle) fn new(
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
                #[cfg(target_os = "linux")]
                retirement: None,
                #[cfg(feature = "private-measurement-domain")]
                managed_parent_park_history: None,
                target_backends_lent: false,
            },
            retained_disk_custody,
            first: None,
            current_node: None,
            current_disk: None,
            current_binding: None,
            work_post: None,
            checked_work: false,
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
        self.run_once(true)
    }

    /// Runs the same engine while its whole owner is already installed in Main.
    pub(crate) fn run_in_main(
        &mut self,
        boundary: SourcePreparationBoundary<'_>,
    ) -> Result<(), ()> {
        self.checked_work = true;
        self.run_once(false)?;
        if let Err(first) = self.validate_requested_boundary(boundary) {
            self.first = Some(first);
            self.complete = false;
            return Err(());
        }
        Ok(())
    }

    fn run_once(&mut self, rollback_here: bool) -> Result<(), ()> {
        if self.attempted {
            return Err(());
        }
        self.attempted = true;
        if let Err(first) = self.prepare() {
            self.first = Some(first);
            if rollback_here {
                self.retain_current_disk();
                self.rollback_after_refusal();
            }
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
        self.work_step(|preparation| {
            let continuation = preparation
                .lifecycle()?
                .capture_hot_fork_world_continuation()
                .map_err(|source| First::Scheduler {
                    operation: "capture source world continuation",
                    source,
                })?;
            preparation.world.continuation = Some(continuation);
            Ok(())
        })?;
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
            self.validate_ownership(&retained_nodes, "validate reconstructed child ownership")?;
            for node in &retained_nodes {
                self.current_node = Some(node.clone());
                let adopted = self.work_step(|preparation| {
                    preparation
                        .lifecycle()?
                        .inner
                        .backend_mut()
                        .adopt_hot_fork_child_as_template_source(node)
                        .map(|_| ())
                        .map_err(|source| First::Backend {
                            operation: "re-adopt reconstructed child",
                            source,
                        })
                });
                if let Err(first) = adopted {
                    self.unreconciled_nodes = retained_nodes.clone();
                    return Err(first);
                }
            }
            if let Err(first) = self.validate_boundaries("revalidate re-adopted child world") {
                self.unreconciled_nodes = retained_nodes;
                return Err(first);
            }
            self.current_node = None;
        }

        self.validate_ownership(&retained_nodes, "validate retained source ownership")?;
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
            self.work_step(|preparation| {
                let disk = match prior {
                    Some(custody) => preparation
                        .lifecycle()?
                        .reacquire_sealed_hot_fork_disk(node, &custody)
                        .map(|(custody, binding)| Some((Arc::new(custody), binding))),
                    None => preparation
                        .lifecycle()?
                        .prepare_sealed_hot_fork_disk(node)
                        .map(|disk| disk.map(|(custody, binding)| (Arc::new(custody), binding))),
                }
                .map_err(|source| First::Scheduler {
                    operation: "seal retained source disk",
                    source,
                })?;
                preparation.force_current_unreconciled = disk.is_some();
                if let Some((custody, binding)) = disk {
                    preparation.current_disk = Some(custody);
                    preparation.current_binding = Some(binding);
                }
                Ok(())
            })?;
            if let Some(custody) = self.current_disk.as_ref().cloned() {
                self.world
                    .disk_custody
                    .insert(node.clone(), Arc::clone(&custody));
                self.world
                    .continuation
                    .as_mut()
                    .ok_or(First::State("captured source continuation is absent"))?
                    .disk_bases
                    .insert(node.clone(), custody.basis().clone());
            }
            self.retained_disk_custody.remove(node);
            self.work_step(|preparation| {
                let lifecycle = preparation
                    .world
                    .lifecycle
                    .as_deref_mut()
                    .ok_or(First::State("same source Loop Box is absent"))?;
                let token = lifecycle
                    .inner
                    .backend_mut()
                    .prepare_retained_hot_fork_template(
                        node,
                        configuration,
                        event_log.clone(),
                        launch_resources,
                        preparation.current_binding.as_slice(),
                        MAXIMUM_HOT_FORK_RING_IMAGE_BYTES,
                    )
                    .map_err(|source| First::Backend {
                        operation: "prepare retained source template",
                        source,
                    })?;
                preparation.world.prepared.push(token);
                Ok(())
            })?;
            let token = self
                .world
                .prepared
                .last()
                .ok_or(First::State("returned source token is absent"))?;
            let generation = token.template_generation();
            if let Some(custody) = self.current_disk.as_ref().cloned() {
                self.work_step(|preparation| {
                    custody
                        .authenticate_source_graph(preparation.lifecycle()?, node, generation)
                        .map_err(|source| First::Scheduler {
                            operation: "authenticate retained source graph",
                            source,
                        })
                })?;
            }
            self.retain_current_disk();
            self.current_node = None;
            self.current_disk = None;
            self.current_binding = None;
            self.rollback_requested = false;
            self.force_current_unreconciled = false;
        }

        self.rollback_requested = true;
        self.validate_boundaries("revalidate prepared source world")?;
        self.work_step(|preparation| {
            preparation
                .world
                .validate_source_ownership()
                .map_err(|source| First::Scheduler {
                    operation: "validate complete prepared source ownership",
                    source,
                })
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
        self.work_step(|preparation| {
            let after = preparation
                .lifecycle()?
                .hot_fork_node_boundaries()
                .map_err(|source| First::Scheduler { operation, source })?;
            let continuation = preparation
                .world
                .continuation
                .as_ref()
                .ok_or(First::State("captured source continuation is absent"))?;
            if after != continuation.nodes {
                return Err(First::State("prepared source world changed after capture"));
            }
            Ok(())
        })
    }

    fn validate_ownership(
        &mut self,
        nodes: &[NodeId],
        operation: &'static str,
    ) -> Result<(), First> {
        self.work_step(|preparation| {
            validate_retained_source_ownership(preparation.lifecycle()?, nodes)
                .map_err(|source| First::Scheduler { operation, source })
        })
    }

    fn work_step(
        &mut self,
        effect: impl FnOnce(&mut Self) -> Result<(), First>,
    ) -> Result<(), First> {
        if !self.checked_work {
            return effect(self);
        }
        let (result, post) = observe_source_work(
            self,
            |preparation| {
                preparation
                    .lifecycle()
                    .map_err(|_| LifecycleApiError::ConstructionCustodyUnavailable)?
                    .node_launcher
                    .check_operational_boundary()
            },
            effect,
        );
        if let Some(post) = post {
            self.work_post.get_or_insert(post);
        }
        result
    }

    fn validate_requested_boundary(
        &mut self,
        boundary: SourcePreparationBoundary<'_>,
    ) -> Result<(), First> {
        self.work_step(|preparation| {
            let SourcePreparationBoundary::Exact {
                requested,
                selected,
                production,
            } = boundary
            else {
                return Ok(());
            };
            let continuation = preparation
                .world
                .continuation
                .as_ref()
                .ok_or(First::BoundaryMismatch)?;
            let proof_matches = selected
                .proof()
                .matches_checkpoint(continuation.configuration(), continuation.scheduler())
                .map_err(First::EventIdentity)?;
            if continuation.configuration().id() != requested
                || selected.configuration() != continuation.configuration()
                || !proof_matches
                || !production.matches(continuation)
            {
                return Err(First::BoundaryMismatch);
            }
            Ok(())
        })
    }

    pub(crate) fn take_history(&mut self) -> ProductionVmHotForkSourcePreparationHistory {
        ProductionVmHotForkSourcePreparationHistory {
            first: self.first.take(),
            post: self.work_post.take(),
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
            && self.first.is_none()
            && self.work_post.is_none()
            && self.world.lifecycle.is_some()
            && self.world.continuation.is_some()
            && self.retained_disk_custody.is_empty()
            && self.current_disk.is_none()
            && self.current_node.is_none()
            && self.current_binding.is_none()
    }

    pub(in crate::vm_lifecycle) fn lifecycle_for_return(
        &mut self,
    ) -> Result<&mut ProductionVmLifecycleLoop, LifecycleApiError> {
        if !self.is_complete() {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        self.world
            .lifecycle
            .as_deref_mut()
            .ok_or(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    pub(in crate::vm_lifecycle) fn retry_body(
        &mut self,
    ) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        self.world.retry_source_retirement_body()
    }

    pub(in crate::vm_lifecycle) fn take_post_body(
        &mut self,
    ) -> Result<
        Option<crate::ProductionVmConstructionPostBody>,
        crate::ProductionVmConstructionCleanupError,
    > {
        self.world.take_source_retirement_post_body()
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
            #[cfg(feature = "private-measurement-domain")]
            managed_parent_park_history: self.world.managed_parent_park_history.take(),
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

fn observe_source_work<S>(
    state: &mut S,
    mut check: impl FnMut(&mut S) -> Result<(), LifecycleApiError>,
    effect: impl FnOnce(&mut S) -> Result<(), First>,
) -> (Result<(), First>, Option<LifecycleApiError>) {
    let result = match check(state) {
        Ok(()) => effect(state),
        Err(first) => Err(First::Original(first)),
    };
    let post = check(state).err();
    let result = if post.is_some() {
        result.and(Err(First::PostRefused))
    } else {
        result
    };
    (result, post)
}

#[cfg(test)]
#[path = "preparation/work_tests.rs"]
mod work_tests;
