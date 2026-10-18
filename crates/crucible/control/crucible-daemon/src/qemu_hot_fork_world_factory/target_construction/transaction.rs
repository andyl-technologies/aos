//! Stages and launches selected children while their original Main body owns them.
//!
//! Scoped workers borrow the same preborn rows. A refusal leaves setup state,
//! created children, independent causes and the original checkout in Pending;
//! no error path creates another owner or treats publication as physical return.

use super::super::target_operations::WorldTargetOperations;
use super::*;

impl<F> PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    /// Keeps preflight failure in this same Main-owned body before returning.
    ///
    /// Returns `None` when the original launch inputs are absent. A unit
    /// refusal reports either an existing failure or this preflight's failure;
    /// the concrete cause remains in this body across the caller's borrow cut.
    pub(crate) fn prepare_launch_basis<T>(
        &mut self,
        apply: impl FnOnce(
            &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
            &crate::ProductionVmHotForkWorldContinuation,
        ) -> Result<T, TargetSetupFailure>,
    ) -> Option<Result<T, ()>> {
        if self.first_failure().is_some() {
            return Some(Err(()));
        }
        let result = apply(
            self.source_world.as_ref()?,
            self.launch_continuation.as_ref()?,
        );
        Some(result.map_err(|first| {
            self.first_setup = Some(first);
        }))
    }

    /// Consumes only this constructor's retained continuation for its launch.
    pub(crate) fn launch_prepared<O: WorldTargetOperations<F>>(
        &mut self,
        operations: &O,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        limits: AttemptResourceLimits,
        ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        shutdown: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
    ) -> bool {
        let Some(continuation) = self.launch_continuation.take() else {
            return self.refuse_setup("Target launch continuation is absent");
        };
        self.launch_selected(
            operations,
            input,
            context,
            continuation,
            limits,
            ram,
            shutdown,
            async_policy,
        )
    }

    /// Runs the shared staging, fork, admission and assembly order in-place.
    ///
    /// Main has already installed this actual Pending. Selected row payloads
    /// were funded by the retained Source World, and all existing fallible
    /// metadata reservations precede the first logical Target reservation.
    pub(crate) fn launch_selected<O: WorldTargetOperations<F>>(
        &mut self,
        operations: &O,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        continuation: crate::ProductionVmHotForkWorldContinuation,
        limits: AttemptResourceLimits,
        ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        shutdown: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
    ) -> bool {
        if self.first_failure().is_some() || self.assembly.is_some() || !self.take_source_storage()
        {
            return false;
        }
        let Some(rows) = self.nodes.as_mut() else {
            return false;
        };
        if !rows.iter().all(TargetNodeConstruction::is_vacant) {
            return self.refuse_setup("Target launch rows are already occupied");
        }
        let mut live = 0_usize;
        for boundary in continuation.nodes() {
            let Ok(index) = rows.binary_search_by(|row| row.node.cmp(boundary.node())) else {
                return self.refuse_setup("Target continuation contains an unselected member");
            };
            if !rows[index].bind_boundary(boundary.service_state(), boundary.generation()) {
                return self.refuse_setup("Target continuation repeats a selected member");
            }
            if boundary.service_state() != ProductionVmHotForkNodeServiceState::PermanentlyFailed {
                live += 1;
            }
        }
        if let Err(first) = self.adoptions.try_reserve_exact(live) {
            self.first_setup = Some(TargetSetupFailure::Adoptions(first));
            return false;
        }
        self.reconciliations = Some(LinuxQemuHotForkWorldReconciliationSet::new(
            continuation
                .nodes()
                .iter()
                .filter(|boundary| {
                    boundary.service_state()
                        != ProductionVmHotForkNodeServiceState::PermanentlyFailed
                })
                .map(|boundary| boundary.node().clone())
                .collect(),
        ));
        if !self.exchange_preborn_rows() {
            return false;
        }
        // Metadata contention may defer this original header return until the
        // exact terminal parent projection. It never grants native work.
        self.try_return_scratch_rows();
        // The assembly, its continuation and all later admitted children now
        // remain fields of the same Main owner before any native operation.
        self.assembly = Some(QemuHotForkWorldAssembly::new(continuation));
        if !self.prepare_selected_members()
            || !self.begin_world(limits, context.cancellation().clone())
        {
            return false;
        }
        let Some(guard) = self.guard.as_mut() else {
            return false;
        };
        if guard.resource_limits() != limits
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            return self.refuse_setup("Target resource contract differs from its admitted request");
        }
        if let Err(first) = operations.bind_world(guard, ram, input) {
            self.first_setup.get_or_insert(first);
            return false;
        }
        let (Some(members), Some(source)) = (self.members.as_ref(), self.source_world.as_ref())
        else {
            return false;
        };
        let Some(guard) = self.guard.take() else {
            return false;
        };
        self.resources = Some(QemuHotForkWorldResourceOwner::from_prepared_target(
            guard,
            members,
            Arc::clone(source),
        ));
        if !self.stage_selected_rows(operations, context, ram) {
            return false;
        }
        if !self.take_source_backends() {
            return false;
        }
        let worked = match (
            self.source_backends.as_mut(),
            self.nodes.as_mut(),
            self.worker_geometry,
        ) {
            (Some(backends), Some(rows), Some(geometry)) => {
                backends.nodes.with_prepared_hot_fork_sources_concurrent(
                    &backends.prepared,
                    rows,
                    geometry,
                    |row| &row.node,
                    |source, row| {
                        #[cfg(test)]
                        row.launch_measured(source);
                        #[cfg(not(test))]
                        row.launch(source);
                    },
                    TargetNodeConstruction::record_worker_panic,
                )
            }
            _ => return false,
        };
        if let Err(first) = worked {
            self.first_setup = Some(TargetSetupFailure::Workers(first));
        }
        // All started workers have joined. Restore only metadata before any
        // Source-parent reconciliation callback can observe the child.
        if !self.restore_source_backends() || self.first_failure().is_some() {
            return false;
        }
        self.admit_selected_children(shutdown, async_policy)
            && self.publish_selected_world()
            && self.prepare_scheduler_adoptions()
    }

    /// Authenticates each adoption with every intermediate owner still in Main.
    fn prepare_scheduler_adoptions(&mut self) -> bool {
        loop {
            if self.adoptions.len() == self.adoptions.capacity() {
                // A full vector is valid only when no child remains to adopt.
                if self.complete.as_ref().is_some_and(|world| world.is_empty()) {
                    return true;
                }
                return self.refuse_setup("Target adoption extent differs from its paid roster");
            }
            let (Some(world), Some(completed)) =
                (self.complete.as_mut(), self.reconciliations.as_ref())
            else {
                return false;
            };
            match world.begin_node_adoption(&mut self.adopting_child, &mut self.adopting_identity) {
                Ok(true) => {}
                Ok(false) => return true,
                Err(first) => {
                    self.first_setup.get_or_insert(first.into());
                    return false;
                }
            }
            let Some(identity) = self.adopting_identity.take() else {
                return false;
            };
            let Some(rows) = self.nodes.as_mut() else {
                self.adopting_identity = Some(identity);
                return false;
            };
            let Ok(index) = rows.binary_search_by(|row| row.node.cmp(identity.node())) else {
                self.adopting_identity = Some(identity);
                return false;
            };
            if rows[index].was_world_adopted() {
                self.adopting_identity = Some(identity);
                return false;
            }
            match PendingTargetChild::<F::Guard>::into_world_node_adoption(
                &mut self.adopting_child,
                identity,
                completed.clone(),
            ) {
                Ok(adoption) => {
                    self.adoptions.push(adoption);
                    rows[index].record_world_adoption();
                }
                Err((identity, first)) => {
                    self.adopting_identity = Some(identity);
                    self.first_setup.get_or_insert(first.into());
                    return false;
                }
            }
        }
    }

    /// Transfers the complete world without moving an incomplete owning value.
    fn publish_selected_world(&mut self) -> bool {
        let Some(assembly) = self.assembly.as_mut() else {
            return false;
        };
        match assembly.publish() {
            Ok(complete) => {
                self.complete = Some(complete);
                // Successful publication empties the assembly and disarms its
                // quarantine destructor. The same children now live in complete.
                drop(self.assembly.take());
                true
            }
            Err(first) => {
                self.first_setup.get_or_insert(first.into());
                false
            }
        }
    }

    /// Moves selected state between the two already paid allocations.
    fn exchange_preborn_rows(&mut self) -> bool {
        let (Some(scratch), Some(retained)) = (self.nodes.as_mut(), self.spare_rows.as_mut())
        else {
            return false;
        };
        if !TargetNodeConstruction::exchange_preborn(scratch, retained) {
            return false;
        }
        std::mem::swap(&mut self.nodes, &mut self.spare_rows);
        true
    }

    fn try_return_scratch_rows(&mut self) {
        let source = self
            .source_selector
            .typed::<crate::qemu_lifecycle_launcher::PendingSourceConstruction<F>>();
        // Target prepared -> Source prepared is the sole nested order. The
        // closure moves only vacant metadata; no callback, Drop or IO occurs.
        let returned = source.with_prepared(|source| {
            let Some(rows) = self.spare_rows.take() else {
                return;
            };
            if let Err(rows) = source.return_target_nodes(rows) {
                self.spare_rows = Some(rows);
            }
        });
        let _ = returned;
    }

    fn refuse_setup(&mut self, message: impl Into<String>) -> bool {
        self.first_setup.get_or_insert_with(|| {
            TargetSetupFailure::Assembly(LifecycleApiError::LoopFactory {
                message: message.into(),
            })
        });
        false
    }

    fn prepare_selected_members(&mut self) -> bool {
        use crate::qemu_lifecycle_launcher::TargetMemberAdmission;
        let (Some(rows), Some(members), Some(owner)) = (
            self.nodes.as_ref(),
            self.members.as_mut(),
            self.source_world.as_ref(),
        ) else {
            return false;
        };
        for row in rows {
            if !row.is_live_boundary() {
                continue;
            }
            let Ok(mut source) = owner.try_lock() else {
                self.first_preparation = Some(
                    LifecycleApiError::LoopFactory {
                        message: String::from(
                            "Target retains its unavailable Source ownership lock",
                        ),
                    }
                    .into(),
                );
                return false;
            };
            if members.native_identity().is_none() {
                match source.native_world_identity() {
                    Ok(identity) if members.bind_native_identity(identity) => {}
                    Ok(_) => {
                        self.first_preparation = Some(
                            LifecycleApiError::LoopFactory {
                                message: String::from("Target World coordinates changed"),
                            }
                            .into(),
                        );
                        return false;
                    }
                    Err(first) => {
                        self.first_preparation = Some(first);
                        return false;
                    }
                }
            }
            match members
                .prepare_member(&row.node, || source.prepare_fork_target_for_node(&row.node))
            {
                Ok(TargetMemberAdmission::Ready) => {}
                Ok(TargetMemberAdmission::Retained) => return false,
                Err(first) => {
                    self.first_preparation = Some(first);
                    return false;
                }
            }
        }
        true
    }

    fn stage_selected_rows<O: WorldTargetOperations<F>>(
        &mut self,
        operations: &O,
        context: &AttemptExecutionContext,
        ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
    ) -> bool {
        let (Some(rows), Some(resources), Some(source), Some(assembly)) = (
            self.nodes.as_mut(),
            self.resources.as_mut(),
            self.source_world.as_ref(),
            self.assembly.as_ref(),
        ) else {
            return false;
        };
        let token = assembly.child_launch_token();
        for row in rows {
            if !row.is_live_boundary() {
                continue;
            }
            let Some(generation) = row
                .source_generation()
                .and_then(|generation| generation.checked_add(1))
            else {
                self.first_setup = Some(TargetSetupFailure::Assembly(
                    LifecycleApiError::LoopFactory {
                        message: format!(
                            "source generation for `{}` cannot advance",
                            row.node.name
                        ),
                    },
                ));
                return false;
            };
            let identity = match ProductionVmNodeGeneration::new(row.node.clone(), generation) {
                Ok(identity) => identity,
                Err(first) => {
                    self.first_setup = Some(first.into());
                    return false;
                }
            };
            let target = match resources.reserve_process_node(identity) {
                Ok(target) => target,
                Err(first) => {
                    self.first_setup = Some(first.into());
                    return false;
                }
            };
            row.target = Some(target);
            let requirements = match source.try_lock() {
                Ok(source) => source.prepared_launch_resources(&row.node),
                Err(_) => {
                    self.first_setup = Some(TargetSetupFailure::Assembly(
                        LifecycleApiError::LoopFactory {
                            message: String::from(
                                "Source ownership lock is unavailable during Target staging",
                            ),
                        },
                    ));
                    return false;
                }
            };
            let requirements = match requirements {
                Ok(requirements) => requirements,
                Err(first) => {
                    self.first_setup = Some(first.into());
                    return false;
                }
            };
            let Some(target) = row.target.as_mut() else {
                return false;
            };
            match operations.prepare_member(
                target,
                context,
                ram,
                &row.node,
                generation,
                requirements,
            ) {
                Ok(supervisor) => row.supervisor = Some(supervisor),
                Err(first) => {
                    self.first_setup.get_or_insert(first);
                    return false;
                }
            }
            match operations.prepare_directory(source, target, requirements) {
                Ok(directory) => row.run_directory = Some(directory),
                Err(first) => {
                    self.first_setup = Some(first.into());
                    return false;
                }
            }
            row.assembly = Some(token.clone());
            if !row.bind_origin(Arc::clone(source)) {
                return false;
            }
        }
        true
    }

    fn take_source_backends(&mut self) -> bool {
        let (Some(owner), Some(lease), Some(members)) = (
            self.source_world.as_ref(),
            self.source.as_ref(),
            self.members.as_ref(),
        ) else {
            return false;
        };
        let Ok(mut source) = owner.try_lock() else {
            return false;
        };
        if !lease.identity().matches(&source) {
            return false;
        }
        self.source_backends = source.take_target_source_backends(members);
        self.source_backends.is_some()
    }

    fn admit_selected_children(
        &mut self,
        shutdown: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
    ) -> bool {
        let (Some(rows), Some(assembly)) = (self.nodes.as_mut(), self.assembly.as_mut()) else {
            return false;
        };
        for row in rows {
            if !row.is_live_boundary() {
                continue;
            }
            let Some(child) = row.child.as_mut() else {
                return false;
            };
            if let Err(first) = child.admit_child() {
                self.first_setup = Some(first.into());
                return false;
            }
            let Some(supervisor) = row.supervisor.as_ref() else {
                return false;
            };
            if let Err(first) = child.install_scheduler_node(
                row.node.clone(),
                shutdown,
                async_policy,
                QemuCrashDetector::new(row.node.name.clone()),
                Some(supervisor.clone()),
            ) {
                self.first_setup = Some(first.into());
                return false;
            }
            let Some(child) = row.child.take() else {
                return false;
            };
            if let Err(refusal) = assembly.admit_child(row.node.clone(), child) {
                let (_, child, first) = refusal.into_parts();
                row.child = Some(child);
                self.first_setup = Some(first.into());
                return false;
            }
            // The assembly now owns this same child and supervisor. Drop only
            // the redundant metadata alias, outside all Source/native locks.
            drop(row.supervisor.take());
        }
        true
    }
}
