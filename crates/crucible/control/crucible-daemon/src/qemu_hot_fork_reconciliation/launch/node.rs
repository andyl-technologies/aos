//! Keeps each selected Target launch in its Source-paid, preborn row.
//!
//! Scoped workers borrow these rows. A fork, seal or rearm refusal leaves the
//! original target, directory and any created child here; producing an error
//! does not allocate another ownership box or remove a sibling's state.

use super::*;
use crate::QemuAttemptProcessResourceGuard;
use crucible_host_resources::host_supervision::HostOperationSupervisor;

/// Holds one selected node's actual construction state before any Target work.
///
/// The generic bound describes storage only. Native fork authority is required
/// by `launch`, not by ordinary Source geometry or metadata preparation.
pub(crate) struct TargetNodeConstruction<G: crate::QemuAttemptResourceGuard> {
    pub(crate) node: NodeId,
    source: crate::qemu_resource_guard::QemuGenerationStorageSelection,
    pub(crate) target: Option<QemuHotForkWorldNodeTarget<G>>,
    pub(crate) run_directory: Option<QemuPreparedRunDirectory>,
    pub(crate) supervisor: Option<HostOperationSupervisor>,
    pub(crate) assembly: Option<QemuHotForkWorldAssemblyToken>,
    launch_source: Option<TargetLaunchOrigin>,
    pub(crate) launch: Option<QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>>,
    pub(crate) detached: Option<QemuHotForkDetachedChildResources>,
    pub(crate) child:
        Option<QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>>,
    pub(crate) first: Option<LinuxQemuHotForkWorldAttemptLaunchFailure>,
    pub(crate) first_rollback: Option<QemuVmRealizationError>,
    worker_panic: Option<Box<dyn std::any::Any + Send>>,
    source_generation: Option<u64>,
    service_state: Option<crate::ProductionVmHotForkNodeServiceState>,
    world_adopted: bool,
    attempted: bool,
    proven_no_child: bool,
    #[cfg(test)]
    launch_nanoseconds: Option<u64>,
}

// This is only the durable origin metadata. The actual event log is borrowed
// from the same prepared Source inside its worker; no placeholder store is born.
struct TargetLaunchOrigin {
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    node: NodeId,
}

struct RowHistory<'a, G: crate::QemuAttemptResourceGuard>(&'a TargetNodeConstruction<G>);

impl<G: crate::QemuAttemptResourceGuard> std::fmt::Debug for RowHistory<'_, G> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let row = self.0;
        let panic_message = row.worker_panic.as_ref().and_then(|payload| {
            payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&'static str>().copied())
        });
        formatter
            .debug_struct("TargetLaunchHistory")
            .field("node", &row.node)
            .field("launch", &row.first)
            .field("rollback", &row.first_rollback)
            .field("worker_panicked", &row.worker_panic.is_some())
            .field("panic_message", &panic_message)
            .finish()
    }
}

impl<G: crate::QemuAttemptResourceGuard> TargetNodeConstruction<G> {
    /// Measures the actual row payload and copied identities without allocation.
    pub(crate) fn control_bytes<'a>(
        nodes: impl Iterator<Item = &'a NodeId>,
    ) -> Result<u64, LifecycleApiError> {
        Self::layout(nodes).map(|(_, _, bytes)| bytes)
    }

    /// Prepares only closed selected metadata under its existing World payment.
    pub(crate) fn prepare<'a>(
        nodes: impl Clone + Iterator<Item = &'a NodeId>,
        source: &crate::QemuAttemptGenerationStorage,
    ) -> Result<Vec<Self>, LifecycleApiError> {
        let (count, mut remaining_names, _) = Self::layout(nodes.clone())?;
        let mut rows: Vec<Self> = Vec::new();
        rows.try_reserve_exact(count)
            .map_err(|source| geometry(format!("reserve Target launch rows: {source}")))?;
        for node in nodes {
            if rows.len() == count || rows.last().is_some_and(|row| row.node >= *node) {
                return Err(geometry(
                    "Target launch selection changed during preparation",
                ));
            }
            remaining_names = remaining_names
                .checked_sub(node.name.len())
                .ok_or_else(|| geometry("Target launch identity extent changed"))?;
            let mut name = String::new();
            name.try_reserve_exact(node.name.len())
                .map_err(|source| geometry(format!("reserve Target launch identity: {source}")))?;
            name.push_str(&node.name);
            rows.push(Self {
                node: NodeId { name },
                source: source.selection(),
                target: None,
                run_directory: None,
                supervisor: None,
                assembly: None,
                launch_source: None,
                launch: None,
                detached: None,
                child: None,
                first: None,
                first_rollback: None,
                worker_panic: None,
                source_generation: None,
                service_state: None,
                world_adopted: false,
                attempted: false,
                proven_no_child: false,
                #[cfg(test)]
                launch_nanoseconds: None,
            });
        }
        if rows.len() != count || remaining_names != 0 {
            return Err(geometry("Target launch selection extent changed"));
        }
        Ok(rows)
    }

    /// Moves selected construction ownership into the other prepaid buffer.
    ///
    /// Every row and origin is checked before the first move. A foreign or
    /// occupied destination returns false without consuming either buffer;
    /// success performs only swaps and preserves each actual owned payload.
    pub(crate) fn exchange_preborn(scratch: &mut [Self], retained: &mut [Self]) -> bool {
        if scratch.is_empty()
            || scratch.len() != retained.len()
            || !scratch.iter().zip(retained.iter()).all(|(left, right)| {
                left.node == right.node
                    && left.source.same_selection(&right.source)
                    && right.is_vacant()
                    && right.source_generation.is_none()
                    && right.service_state.is_none()
            })
        {
            return false;
        }
        for (scratch, retained) in scratch.iter_mut().zip(retained.iter_mut()) {
            std::mem::swap(scratch, retained);
        }
        true
    }

    /// Authenticates only this row's original selected registry allocation.
    pub(crate) fn belongs_to(
        &self,
        source: &crate::qemu_resource_guard::QemuGenerationStorageSelection,
    ) -> bool {
        self.source.same_selection(source)
    }

    /// Observes whether every owned launch field has actually been moved/closed.
    pub(crate) fn is_vacant(&self) -> bool {
        self.target.is_none()
            && self.run_directory.is_none()
            && self.supervisor.is_none()
            && self.assembly.is_none()
            && self.launch_source.is_none()
            && self.launch.is_none()
            && self.detached.is_none()
            && self.child.is_none()
            && self.first.is_none()
            && self.first_rollback.is_none()
            && self.worker_panic.is_none()
    }

    /// Retains the actual existing panic payload in the selected row.
    ///
    /// The common worker transaction first requires a pristine selected row and
    /// starts exactly one worker per row. No cleanup or replacement allocation
    /// occurs here; actual node and target fields remain in the same row.
    pub(crate) fn record_worker_panic(&mut self, payload: Box<dyn std::any::Any + Send>) {
        self.worker_panic = Some(payload);
    }

    pub(crate) fn worker_panic(&self) -> Option<&(dyn std::any::Any + Send)> {
        self.worker_panic.as_deref()
    }

    /// Retains the actual immutable semantic boundary before logical admission.
    pub(crate) fn bind_boundary(
        &mut self,
        state: crate::ProductionVmHotForkNodeServiceState,
        generation: u64,
    ) -> bool {
        if self.source_generation.is_some() || self.service_state.is_some() || !self.is_vacant() {
            return false;
        }
        self.source_generation = Some(generation);
        self.service_state = Some(state);
        true
    }

    pub(crate) fn source_generation(&self) -> Option<u64> {
        self.source_generation
    }

    pub(crate) fn is_live_boundary(&self) -> bool {
        matches!(
            self.service_state,
            Some(
                crate::ProductionVmHotForkNodeServiceState::Running
                    | crate::ProductionVmHotForkNodeServiceState::PoweredOff
            )
        )
    }

    /// Returns total and maximum fork duration for a fully adopted live roster.
    ///
    /// Missing samples and arithmetic overflow remain unavailable evidence.
    /// The overall ready timer separately includes admission and staging work.
    #[cfg(test)]
    pub(crate) fn launch_timing_summary(rows: &[Self]) -> Option<(u64, u64)> {
        let mut count = 0;
        let mut total = 0_u64;
        let mut maximum = 0;
        for row in rows.iter().filter(|row| row.is_live_boundary()) {
            if !row.was_world_adopted() {
                return None;
            }
            let elapsed = row.launch_nanoseconds?;
            total = total.checked_add(elapsed)?;
            maximum = maximum.max(elapsed);
            count += 1;
        }
        (count > 0).then_some((total, maximum))
    }

    /// Records only the completed transfer to an actual scheduler adoption.
    pub(crate) fn record_world_adoption(&mut self) {
        self.world_adopted = true;
    }

    /// Observes logical adoption, independently of native retirement.
    pub(crate) fn was_world_adopted(&self) -> bool {
        self.world_adopted
    }

    /// Binds only the same retained Source before the worker starts.
    ///
    /// The Source guard and original supervision remain in their canonical
    /// owners. This metadata neither issues a permit nor creates a child.
    pub(crate) fn bind_origin(
        &mut self,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    ) -> bool {
        if self.launch_source.is_some() || self.attempted || self.child.is_some() {
            return false;
        }
        self.launch_source = Some(TargetLaunchOrigin {
            source_world,
            node: self.node.clone(),
        });
        true
    }

    /// Borrows the actual first launch or rollback cause from this row.
    pub(crate) fn first_failure(&self) -> Option<crate::LifecycleFailureRef<'_>> {
        self.first
            .as_ref()
            .map(crate::LifecycleFailureRef::TargetLaunch)
            .or_else(|| {
                self.first_rollback
                    .as_ref()
                    .map(crate::LifecycleFailureRef::Realization)
            })
    }

    /// Observes retained reports without inferring a physical close.
    pub(crate) fn has_history(&self) -> bool {
        self.first.is_some() || self.first_rollback.is_some() || self.worker_panic.is_some()
    }

    /// Borrows every independent report; formatting allocates no new owner.
    pub(crate) fn history(&self) -> impl std::fmt::Debug + '_ {
        RowHistory(self)
    }

    /// Resets only vacant metadata after the caller's exact terminal receipts.
    ///
    /// This creates no permission to fork. A new Target still needs the genuine
    /// retained Source permit and its independently admitted Preparation.
    pub(crate) fn reset_returned(&mut self) -> bool {
        if !self.is_vacant() {
            return false;
        }
        self.source_generation = None;
        self.service_state = None;
        self.world_adopted = false;
        self.attempted = false;
        self.proven_no_child = false;
        #[cfg(test)]
        {
            self.launch_nanoseconds = None;
        }
        true
    }

    /// Retries only locally known child/no-child ownership in this same row.
    ///
    /// An interrupted fork or stranded created child is retained. Missing
    /// output is never inferred to mean no child, and a worker panic cannot
    /// authorize disposal of the original node or physical target.
    pub(crate) fn retry_owned_cleanup(
        &mut self,
        members: &mut crate::qemu_lifecycle_launcher::TargetConstructionStorage,
    ) -> bool {
        if self.worker_panic.is_some() || self.launch.is_some() || self.detached.is_some() {
            return false;
        }
        if let Some(child) = self.child.as_mut() {
            if !members.rollback_child(&self.node, child) {
                return false;
            }
            drop(self.child.take());
        }
        if self.target.is_some() {
            if self.attempted && !self.proven_no_child {
                return false;
            }
            let returned = members.with_member_cleanup(&self.node, || {
                let Some(target) = self.target.as_mut() else {
                    return false;
                };
                match target.abort_without_child_retained() {
                    Ok(()) => {
                        // Exact no-child/local return preceded this disposal.
                        // Neither a Source nor an aggregate mutex is held.
                        drop(self.target.take());
                        drop(self.run_directory.take());
                        drop(self.launch_source.take());
                        drop(self.supervisor.take());
                        drop(self.assembly.take());
                        true
                    }
                    Err(first) => {
                        self.first_rollback.get_or_insert(first);
                        false
                    }
                }
            });
            if !returned {
                return false;
            }
        }
        self.target.is_none()
            && self.run_directory.is_none()
            && self.launch_source.is_none()
            && self.supervisor.is_none()
            && self.assembly.is_none()
    }

    /// Disposes only observed history after the caller's exact role returns.
    ///
    /// The protected terminal Main owner invokes this outside all Source and
    /// registry locks. A failed ownership observation retains the entire row.
    pub(crate) fn dispose_returned_history(&mut self) -> bool {
        if self.target.is_some()
            || self.run_directory.is_some()
            || self.supervisor.is_some()
            || self.assembly.is_some()
            || self.launch_source.is_some()
            || self.launch.is_some()
            || self.detached.is_some()
            || self.child.is_some()
            || self.worker_panic.is_some()
        {
            return false;
        }
        drop(self.first.take());
        drop(self.first_rollback.take());
        self.reset_returned()
    }

    /// Reports an explicit no-child response, independently of rollback success.
    pub(crate) fn proven_no_child(&self) -> bool {
        self.proven_no_child
    }

    fn layout<'a>(
        nodes: impl Iterator<Item = &'a NodeId>,
    ) -> Result<(usize, usize, u64), LifecycleApiError> {
        let mut count = 0_usize;
        let mut names = 0_usize;
        let mut previous = None;
        for node in nodes {
            if previous.is_some_and(|previous: &NodeId| previous >= node) {
                return Err(geometry(
                    "Target launch nodes are duplicated or out of order",
                ));
            }
            count = count
                .checked_add(1)
                .filter(|count| *count <= crate::MAX_QEMU_ATTEMPT_GENERATION_NODES)
                .ok_or_else(|| geometry("Target launch selection is exhausted"))?;
            names = names
                .checked_add(node.name.len())
                .ok_or_else(|| geometry("Target launch identity extent overflows"))?;
            previous = Some(node);
        }
        if count == 0 {
            return Err(geometry("Target launch selection is empty"));
        }
        let payload = std::alloc::Layout::array::<Self>(count)
            .map_err(|_| geometry("Target launch row extent overflows"))?;
        let bytes = payload
            .size()
            .checked_add(
                names
                    .checked_mul(2)
                    .ok_or_else(|| geometry("Target origin names overflow"))?,
            )
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| geometry("Target launch extent overflows"))?;
        Ok((count, names, bytes))
    }
}

impl<G> TargetNodeConstruction<G>
where
    G: crate::QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    /// Measures the actual worker without allocating a parallel sample buffer.
    #[cfg(test)]
    // crucible-lint: allow clippy-disallowed-method -- qualification-only host timing cannot enter modeled state.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn launch_measured(&mut self, source: QemuNodeSetPreparedHotForkSource<'_>) {
        if self.attempted {
            return;
        }
        let started = std::time::Instant::now();
        self.launch(source);
        if self.attempted {
            self.launch_nanoseconds =
                Some(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
    }

    /// Runs the existing fork/seal/rearm order with all owners already in-row.
    ///
    /// No target or private directory moves to a fallible stack-only carrier.
    /// Actual QEMU refusal remains typed here; callers inspect it after all
    /// scoped workers finish and the original Source NodeSet is restored.
    pub(crate) fn launch(&mut self, mut source: QemuNodeSetPreparedHotForkSource<'_>) {
        if self.attempted || self.first.is_some() || self.child.is_some() {
            return;
        }
        let (Some(target), Some(directory), Some(assembly), Some(origin)) = (
            self.target.as_mut(),
            self.run_directory.as_mut(),
            self.assembly.as_ref(),
            self.launch_source.as_ref(),
        ) else {
            return;
        };
        if target.identity().node() != &self.node || origin.node != self.node {
            return;
        }
        self.attempted = true;
        let configuration = source.configuration();
        let event_log = source.fork_event_log();
        let requirements = source.launch_resources();
        let component_ram = {
            #[cfg(test)]
            {
                target.component_ram_facts
            }
            #[cfg(not(test))]
            {
                false
            }
        };
        let ram_prepared = match (
            target.host_ram_registration(),
            target.host_operation_supervisor(),
            target.host_ram_custody(),
        ) {
            (Some(registration), Some(supervisor), Some(custody)) => directory
                .retain_ram_launch_custody(custody.clone())
                .map_err(|first| {
                    QemuNodeChannelError::new(
                        "retain child RAM directory custody",
                        first.to_string(),
                    )
                })
                .and_then(|()| {
                    if component_ram {
                        return Ok(());
                    }
                    source.prepare_child_ram(
                        registration.clone(),
                        supervisor.clone(),
                        directory,
                        custody.clone(),
                    )
                }),
            (None, None, None) => Ok(()),
            _ => Err(QemuNodeChannelError::new(
                "prepare child RAM",
                "target RAM admission and supervisor disagree",
            )),
        };
        let launched = ram_prepared
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })
            .and_then(|()| {
                fork_source_world_with_private_files(
                    &mut source,
                    directory,
                    requirements,
                    target,
                    |target| {
                        target.child_process_contract().map_err(|first| {
                            QemuNodeChannelError::new(
                                "obtain aggregate target hot-fork process contract",
                                first.to_string(),
                            )
                        })
                    },
                )
            });
        match launched {
            Ok(launch) => self.launch = Some(launch),
            Err(first) => {
                directory.invalidate_hot_fork_child_file_transfer();
                self.proven_no_child = matches!(first, QemuHotForkLaunchError::Rejected { .. });
                self.first = Some(LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(first));
                return;
            }
        }
        let Some(launch) = self.launch.as_mut() else {
            return;
        };
        if let Err(first) = directory.seal_hot_fork_child_file_transfer(launch) {
            self.first = Some(LinuxQemuHotForkWorldAttemptLaunchFailure::ChildFileSeal(
                first,
            ));
            return;
        }
        match source.rearm_after_child(launch) {
            Ok(detached) => self.detached = Some(detached),
            Err(first) => {
                self.first = Some(LinuxQemuHotForkWorldAttemptLaunchFailure::SourceRearm(
                    first,
                ));
                return;
            }
        }
        // Every following move is infallible. The concrete process-control Arc
        // birth belongs to the selected World query, separately from these rows.
        let parts = (
            self.target.take(),
            self.run_directory.take(),
            self.launch.take(),
            self.detached.take(),
            self.launch_source.take(),
        );
        let (target, directory, launch, detached, origin) = match parts {
            (Some(target), Some(directory), Some(launch), Some(detached), Some(origin)) => {
                (target, directory, launch, detached, origin)
            }
            (target, directory, launch, detached, origin) => {
                self.target = target;
                self.run_directory = directory;
                self.launch = launch;
                self.detached = detached;
                self.launch_source = origin;
                return;
            }
        };
        let origin = LinuxQemuHotForkWorldLaunchSource {
            source_world: origin.source_world,
            node: origin.node,
            configuration,
            event_log,
        };
        self.child = Some(QemuHotForkAttemptReconciliation::new(
            LinuxQemuHotForkReconciliationBackend::from_world_launch(
                origin,
                assembly.clone(),
                target,
                launch,
                detached,
                directory,
            ),
        ));
        self.assembly = None;
    }
}

fn geometry(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
