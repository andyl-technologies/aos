//! Binds queue-to-backend handoffs rather than permitting global cleanup.

use super::super::Companion;

pub(super) const DRIVER_OWNER: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/driver.rs",
    required: &[
        (
            r#"if expected_epoch.is_some_and(|expected| expected != epoch)"#,
            1,
        ),
        (
            r#"slot.body_destroyed_epoch.store(epoch, Ordering::Release);"#,
            1,
        ),
        (r#"retry_body_and_controls(slot, epoch)?;"#, 1),
        (r#"cell.control_failure.get_or_insert(first);"#, 1),
        (r#"drop(cell.controls.take());"#, 1),
        (r#"body.worlds_physically_returned()"#, 1),
        (r#"if no_world || native_returned"#, 1),
        (
            r#"service.panic_payload = Some(payload); slot.publish(CleanupPhase::DestructionRefused);"#,
            1,
        ),
    ],
};

pub(super) const TARGET: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_hot_fork_world_factory/target_construction.rs",
    required: &[
        (r#"if self.pre_body_closed { return Ok(()); }"#, 1),
        (r#"self.pre_body_closed = true;"#, 1),
        (r#"if self.physically_returned { return true; }"#, 1),
        (r#"self.body_destroyed = true;"#, 1),
        (
            r#"if !self.retry_node_rows() || !self.retry_rollback_children() || !self.retry_aggregate()"#,
            1,
        ),
        (r#"if !members.retry_native_loans()"#, 1),
    ],
};

pub(super) const FILE_ONLY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation/tests/file_cell.rs",
    required: &[
        (r#"require_file_only(slot)?;"#, 4),
        (
            r#"service.role.is_some() || service.start.is_some() || service.return_body.is_some()"#,
            1,
        ),
        (
            r#"prepared.owner.is_some() || cell.controls_bound || cell.controls.is_some()"#,
            1,
        ),
        (
            r#"slot.body_destroyed_epoch.load(Ordering::Acquire) < receipt.epoch"#,
            1,
        ),
        (
            r#"slot.controls_closed_epoch.load(Ordering::Acquire) < receipt.epoch"#,
            1,
        ),
    ],
};

pub(super) const ATTACHED_BODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/packaged_qemu_executor/attached_retirement.rs",
    required: &[
        (r#"if !self.service_returned"#, 2),
        (r#"if self.dispatcher_closed { return Ok(()); }"#, 1),
        (r#"self.post.get_or_insert(post);"#, 4),
        (r#"self.source_closed = true;"#, 1),
        (r#"*slot = Some(body);"#, 1),
    ],
};

pub(super) const MAIN_ATTACHMENT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/campaign_process/attached_retirement.rs",
    required: &[
        (r#".is_none_or(|actual| !Arc::ptr_eq(actual, main))"#, 1),
        (
            r#"actor.attached_started.swap(true, std::sync::atomic::Ordering::AcqRel)"#,
            1,
        ),
        (
            r#"*slot = Some(RetainedExecutorConstruction::Attached(body));"#,
            1,
        ),
        (r#"let original = match main.retained_cleanup()"#, 1),
        (
            r#"if !body.physically_retired() { return Err(retained_attached_report(main)); }"#,
            1,
        ),
        (
            r#"let returned = slot.take(); drop(slot); drop(returned);"#,
            1,
        ),
    ],
};

pub(super) const PACKAGED_BODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/packaged_qemu_executor/original_retirement.rs",
    required: &[
        (r#"original.wait_slice()?;"#, 1),
        (
            r#"let workers = self.service.try_retire_original(original).err();"#,
            1,
        ),
        (r#"if self.service.physically_retired()"#, 2),
        (r#"self.source_physically_retired = true;"#, 1),
        (r#"post: dispatch.post,"#, 1),
    ],
};

pub(super) const CONSTRUCTION_FINISH: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/campaign_process/retained_construction.rs",
    required: &[
        (r#"if !physically_closed"#, 1),
        (r#"drop(slot);"#, 2),
        (r#"drop(returned);"#, 1),
    ],
};

pub(super) const DISPATCHER: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/packaged_qemu_executor/retirement.rs",
    required: &[(
        r#"pub(crate) fn retire_dispatcher(
        original: &HostOperationGuard, prerequisites_closed: bool, physically_closed: &mut bool,
        attempt: impl FnOnce() -> (Result<(), QemuVmRealizationError>, bool),
    ) -> DispatcherRetirement {
        let mut result = DispatcherRetirement::default();
        if prerequisites_closed && !*physically_closed {
            result.before = original.wait_slice().err();
            if result.before.is_none() {
                let (work, observed_closed) = attempt();
                *physically_closed = observed_closed; result.failure = work.err();
            }
        }
        result.post = original.wait_slice().err(); result
    }"#,
        1,
    )],
};

pub(super) const AFTER_BODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_service.rs",
    required: &[
        (r#"pub(super) fn with_erased_after_body<R>("#, 1),
        (r#"prepared.epoch != self.key.epoch"#, 3),
        (
            r#"slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch"#,
            4,
        ),
        (r#"Ok(apply(owner.as_mut()))"#, 1),
    ],
};
