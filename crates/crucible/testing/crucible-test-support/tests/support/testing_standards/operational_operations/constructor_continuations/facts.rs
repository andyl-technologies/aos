//! Shares existing native-Original and canonical publication facts.

use super::{Companion, Contract};

const TARGET: &Contract = super::super::host_physical_custody::TARGET_WORLD;
const _: () = assert!(TARGET.companions.len() == 1);
pub(super) const TARGET_OWNER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
    required: TARGET.required,
};
pub(super) const TARGET_BODIES: Companion = Companion {
    path: TARGET.companions[0].path,
    required: TARGET.companions[0].required,
};
pub(super) const TARGET_LOAN: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
    required: &[(
        r#"pub fn retained_cleanup(
        &self,
    ) -> Result<Arc<HostOperationGuard>, QemuForkTargetConstructionError> {
        if self.returned {
            return Err(OriginalActorAccountError::Unavailable.into());
        }
        let roster = self
            .attempt
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.attempt.index)
            .filter(|slot| slot.active == Some(self.attempt.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if slot.fork_target.occupied != Some(self.epoch)
            || slot.fork_target.reserved_process_generation != Some(self.process_generation)
        {
            return Err(OriginalActorAccountError::Unavailable.into());
        }
        let cleanup = slot
            .fork_target
            .cleanup
            .as_ref()
            .map(Arc::clone)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        drop(state);
        cleanup.guard().map_err(Into::into)
    }"#,
        1,
    )],
};
pub(super) const TARGET_NATIVE: &[Companion] = &[TARGET_OWNER, TARGET_BODIES, TARGET_LOAN];

pub(super) const WORLD: &[Companion] = super::super::retained_continuations::WORLD_COMPANIONS;
const PUBLICATION: &Contract = &super::super::production_publication::CONTRACTS[0];
pub(super) const PUBLICATION_FACT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/publication.rs",
    required: PUBLICATION.required,
};
pub(super) const BACKEND_FACT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
    required: &[
        (
            r#"let mut phase = self.phase.try_lock().map_err(phase_lock_error)?; if self.physically_closed.load(Ordering::Acquire) { return Ok(()); }"#,
            1,
        ),
        (r#"Phase::Partial(partial) => retire_partial(partial)?,"#, 1),
        (
            r#"Phase::Complete(lifecycle) => retire_complete(lifecycle)?,"#,
            1,
        ),
        (
            r#"self.physically_closed.store(true, Ordering::Release);"#,
            1,
        ),
    ],
};

pub(super) const MEMBERS: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/target_construction.rs",
    required: &[
        (
            r#"pub(crate) fn settle_child<G: crate::QemuAttemptResourceGuard>(
        &mut self,
        node: &NodeId,
        child: &mut crate::QemuHotForkAttemptReconciliation<
            crate::LinuxQemuHotForkReconciliationBackend<G>,
        >,
        disposition: crate::AttemptExecutionDisposition,
    ) -> bool {
        use crate::qemu_hot_fork_reconciliation::QemuHotForkReconciliationPhase as Phase;
        let Ok(index) = self.members.binary_search_by(|row| row.node.cmp(node)) else {
            return false;
        };
        let row = &mut self.members[index];
        let Some(loan) = row.cleanup.as_ref() else {
            return false;
        };
        if child.phase() == Phase::Reconciled {
            return true;
        }
        let cleanup = match loan.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                row.first_cleanup.get_or_insert(first);
                return false;
            }
        };
        let work = if child.phase() == Phase::Reconciled {
            Ok(())
        } else if child.phase() == Phase::AwaitingPublication {
            child
                .reconcile_execution_disposition(disposition)
                .map(|_| ())
        } else if !row.termination_requested {
            child
                .request_termination()
                .map(|()| row.termination_requested = true)
        } else {
            child.reconcile_step().map(|_| ())
        };
        let complete = child.phase() == Phase::Reconciled;
        let post = cleanup.wait_slice();
        if let Err(first) = work {
            row.first_reconciliation.get_or_insert(first);
        }
        if let Err(first) = post {
            row.first_cleanup.get_or_insert(
                crucible_qemu_host::QemuForkTargetConstructionError::Original(first.into()),
            );
        }
        complete
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn with_member_cleanup(
        &mut self,
        node: &NodeId,
        step: impl FnOnce() -> bool,
    ) -> bool {
        let Ok(index) = self.members.binary_search_by(|row| row.node.cmp(node)) else {
            return false;
        };
        let row = &mut self.members[index];
        let Some(loan) = row.cleanup.as_ref() else {
            return false;
        };
        let cleanup = match loan.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                row.first_cleanup.get_or_insert(first);
                return false;
            }
        };
        let work = step();
        let post = cleanup.wait_slice();
        if let Err(first) = post {
            row.first_cleanup.get_or_insert(
                crucible_qemu_host::QemuForkTargetConstructionError::Original(first.into()),
            );
        }
        // The actual work result is independent of its observed post refusal.
        // The first raw post stays in the same paid member while exact native
        // role/window receipts still determine eventual physical return.
        work
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn retry_native_loans(&mut self) -> bool {
        for row in &mut self.members {
            // An unused permit is the same genuine prebirth role. Dropping it
            // admits no physical work; its retained loan still authenticates
            // whether the exact role returned, including a failed Drop fast cut.
            drop(row.permit.take());
            let Some(loan) = row.cleanup.as_mut() else {
                continue;
            };
            if loan.is_physically_returned() {
                continue;
            }
            if let Err(first) = loan.try_finish() {
                // Retry never issues a World/window/account claim: physical
                // owners remain in the same canonical roster or actual G.
                // Preserve each row's first diagnostic; it is not return proof.
                row.first_cleanup.get_or_insert(first);
            }
        }
        self.can_restore_to_source()
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn retry_native_bodies(&mut self) -> Result<(), QemuVmRealizationError> {
        use crate::qemu_resource_guard::QemuAttemptHostResourceOwner;
        if self.native_hosts.needs_host_cleanup() {
            let identity = self
                .native_identity
                .ok_or(QemuVmRealizationError::CleanupRetained {
                    operation: "retain partial Target World identity",
                })?;
            let aggregate =
                self.native_hosts
                    .aggregate
                    .ok_or(QemuVmRealizationError::CleanupRetained {
                        operation: "retain partial Target World geometry",
                    })?;
            self.native_hosts.installed = Some(self.native_hosts.take_host(identity, aggregate));
        }
        match self.native_hosts.installed.as_mut() {
            Some(host) => host.finish(),
            None => Ok(()),
        }
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn can_restore_to_source(&self) -> bool {
        self.members.iter().all(|row| {
            #[cfg(target_os = "linux")]
            if row.permit.is_some()
                || row
                    .cleanup
                    .as_ref()
                    .is_some_and(|loan| !loan.is_physically_returned())
                || (row.entered && row.cleanup.is_none())
            {
                return false;
            }
            !row.entered || cfg!(target_os = "linux")
        })
    }"#,
            1,
        ),
    ],
};

pub(super) const SOURCE_CLEANUP: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction/cleanup.rs",
    required: &[
        (
            r#"pub(super) fn finish_under_world_cleanup(&mut self) -> Result<(), CleanupError> {
        let world = self.world.as_ref().ok_or(CleanupError::Retained(
            "entered World has no delivered cleanup loan",
        ))?;
        let cleanup = match world.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                self.history.cleanup_first.get_or_insert(first);
                return Err(CleanupError::Retained("same World Cleanup is unavailable"));
            }
        };
        let (attempt, first, post) =
            observe_saved_world_cleanup(&cleanup, || self.finish_native_members());
        if let Some(first) = first {
            self.history.cleanup_first.get_or_insert(first.into());
        }
        if let Err(post) = post {
            self.history.cleanup_post.get_or_insert(post);
        }
        attempt
    }"#,
            1,
        ),
        (
            r#"fn finish_native_members(&mut self) -> Result<(), CleanupError> {
        let factory =
            self.factory
                .as_mut()
                .ok_or(crate::ProductionVmConstructionCleanupError::Retained(
                    "pending Source lost its actual factory",
                ))?;
        let members = if self.members_closed {
            Ok(())
        } else {
            let world = self.world.as_ref().ok_or(
                crate::ProductionVmConstructionCleanupError::Retained(
                    "entered World has no delivered cleanup loan",
                ),
            )?;
            factory.retry_native_world_construction(world)
        };
        match members {
            Ok(()) => {
                self.members_closed = true;
                if let Some(guard) = self.returned_guard.as_mut() {
                    guard.finish()?;
                }
                self.returned_guard = None;
                self.generation_storage = None;
                self.body_cleanup_complete = true;
                Ok(())
            }
            Err(first) => {
                self.record_first(first);
                Err(crate::ProductionVmConstructionCleanupError::Retained(
                    "same World construction member cleanup remains retained",
                ))
            }
        }
    }"#,
            1,
        ),
        (
            r#"fn observe_saved_world_cleanup<T>(
    cleanup: &HostOperationGuard,
    attempt: impl FnOnce() -> Result<T, CleanupError>,
) -> (
    Result<T, CleanupError>,
    Option<HostSupervisionError>,
    Result<(), HostSupervisionError>,
) {
    let (result, first) = match cleanup.wait_slice() {
        Ok(_) => (attempt(), None),
        Err(first) => (
            Err(CleanupError::Retained(
                "same World Cleanup refused retirement effects",
            )),
            Some(first),
        ),
    };
    let post = cleanup.wait_slice().map(|_| ());
    (result, first, post)
}"#,
            1,
        ),
    ],
};

pub(super) const MAIN_AFTER_BODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_service.rs",
    required: &[
        (
            r#"if prepared.epoch != self.key.epoch || slot.epoch.load(Ordering::Acquire) != self.key.epoch || slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch || slot.is(CleanupPhase::Free) { return Err(unavailable("same actual body destruction is not observed")); }"#,
            1,
        ),
        (
            r#"let owner = prepared.owner.as_mut().ok_or_else(|| unavailable("same postbody owner is absent"))?; Ok(apply(owner.as_mut()))"#,
            1,
        ),
    ],
};
pub(super) const MAIN_RETIREMENT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_retirement.rs",
    required: &[
        (
            r#"if slot.epoch.load(Ordering::Acquire) != self.key.epoch { return Err(PreparedSourceRefusal::RoleUnavailable); } self.request_retirement(); let attempted = retry_slot(slot, Some(self.key.epoch)); if slot.is(CleanupPhase::TerminalReady) { return Ok(true); }"#,
            1,
        ),
        (
            r#"if !self.report_reference { return Err(self); } match terminal::take_terminal_body_with_reports(&self.key, &mut self.access, &mut self.receiver,) { Ok(body) => { self.report_reference = false; Ok(body) } Err(_) => Err(self), }"#,
            1,
        ),
    ],
};

pub(super) const RESERVATION: Companion = Companion {
    path: PUBLICATION.companions[1].path,
    required: PUBLICATION.companions[1].required,
};

pub(super) const QUEUE: Companion = Companion {
    path: PUBLICATION.companions[2].path,
    required: PUBLICATION.companions[2].required,
};

pub(super) const BODY_DRIVER: Companion = Companion {
    path: PUBLICATION.companions[11].path,
    required: PUBLICATION.companions[11].required,
};

pub(super) const REPORT_PINS: Companion = Companion {
    path: PUBLICATION.companions[15].path,
    required: PUBLICATION.companions[15].required,
};

pub(super) const WORLD_0: Companion = Companion {
    path: WORLD[0].path,
    required: WORLD[0].required,
};

pub(super) const WORLD_1: Companion = Companion {
    path: WORLD[1].path,
    required: WORLD[1].required,
};

pub(super) const WORLD_2: Companion = Companion {
    path: WORLD[2].path,
    required: WORLD[2].required,
};

pub(super) const WORLD_3: Companion = Companion {
    path: WORLD[3].path,
    required: WORLD[3].required,
};

pub(super) const WORLD_4: Companion = Companion {
    path: WORLD[4].path,
    required: WORLD[4].required,
};

pub(super) const RECEIPT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs",
    required: &[
        (
            r#"let attempted = retry_slot(slot, Some(self.epoch)); let observed = self.observe_slot(slot)?; if observed == ProductionVmCleanupStage::Complete { return Ok(observed); } attempted?; Ok(observed)"#,
            1,
        ),
        (
            r#"if slot.controls_closed_epoch.load(Ordering::Acquire) >= self.epoch { self.observed = ProductionVmCleanupStage::Complete; let mut cell = slot.cell.try_lock().map_err(|_| refusal("completed handoff history is borrowed or poisoned"))?; if cell.epoch != self.epoch || cell.owner.is_some() || cell.controls.is_some() { return Err(refusal("completed handoff retains a different actual body")); } if self.first_failure.is_none() { self.first_failure = cell.first_failure.take(); } }"#,
            1,
        ),
        (
            r#"match terminal::take_terminal_body(&key) { Ok(body) => { self.report_reference = false; self.observed = ProductionVmCleanupStage::Complete; self.terminal_history = Some(body); true } Err(_) => false, }"#,
            1,
        ),
    ],
};

// A failed aggregate attempt transfers physical custody into the original
// host/Target roster. It is not permission to repeat an aggregate finish.
pub(super) const AGGREGATE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_hot_fork_world_resource.rs",
    required: &[
        (
            r#"if state.retirement != WorldResourceRetirement::Active { return Err(QemuHotForkWorldReleaseReadinessError::Terminal); }"#,
            1,
        ),
        (
            r#"let result = state.guard.finish(); state.retirement = if result.is_ok() { WorldResourceRetirement::Returned } else { WorldResourceRetirement::Retained }; result"#,
            1,
        ),
        (
            r#"if state.issued != state.released || (state.lifecycle_launcher_required && !state.lifecycle_launcher_finished) || state.auxiliary_lifecycle_active || !state.guard.recover_target_construction_storage(storage) { return false; } state.retirement = WorldResourceRetirement::Returned; true"#,
            1,
        ),
    ],
};
pub(super) const COMPOSED: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard.rs",
    required: &[
        (
            r#"let result = finish_host_raw(&mut self.host, self.original_native_registry.as_ref()); self.retirement = if result.is_ok() { ComposedResourceRetirement::Returned } else { ComposedResourceRetirement::Quarantined }; result"#,
            1,
        ),
        (
            r#"let result = match registry { Some(registry) => host.finish_with_original_registry(registry), None => host.finish(), }; result.map_err(|error| { host.quarantine(); crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure::quarantined(error) })"#,
            1,
        ),
    ],
};
