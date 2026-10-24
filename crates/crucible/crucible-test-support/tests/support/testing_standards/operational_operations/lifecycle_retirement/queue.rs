//! Binds queue attempts to one epoch, physical phases and retained first causes.

use super::super::Contract;

pub(super) const DRIVER: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/driver",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"if expected_epoch.is_some_and(|expected| expected != epoch)"#,
            1,
        ),
        (
            r#"if !slot.retirement_requested.load(Ordering::Acquire)"#,
            1,
        ),
        (
            r#"PhaseAttempt::claim(slot, CleanupPhase::Reserved, CleanupPhase::RetryingPrepared)"#,
            1,
        ),
        (
            r#"if slot.is(CleanupPhase::DestructionRefused) { return attempted; }"#,
            1,
        ),
        (
            r#"let _restored = self.slot.claim(self.borrowed, self.before);"#,
            1,
        ),
        (
            r#"slot.body_destroyed_epoch.store(epoch, Ordering::Release);"#,
            1,
        ),
        (
            r#"slot.body_destroyed_epoch.store(epoch, Ordering::Release); } retry_body_and_controls(slot, epoch)?;"#,
            1,
        ),
        (
            r#"slot.controls_closed_epoch.store(epoch, Ordering::Release); slot.publish(CleanupPhase::PostBodyPending);"#,
            1,
        ),
        (
            r#"service.epoch != epoch || service.queued_owner.is_some() || service.queued_owner_borrowed"#,
            2,
        ),
        (
            r#"cell.epoch != epoch || cell.owner.is_some() || cell.incoming_post_body.is_some()"#,
            1,
        ),
        (r#"if !body.matches_world_controls(controls)"#, 1),
        (r#"cell.control_failure.get_or_insert(first);"#, 1),
        (r#"drop(cell.controls.take());"#, 1),
        (
            r#"if body.worlds_physically_returned() { slot.worlds_returned_epoch.store(epoch, Ordering::Release); }"#,
            1,
        ),
        (r#"if no_world || native_returned"#, 1),
        (
            r#"service.panic_payload = Some(payload); slot.publish(CleanupPhase::DestructionRefused);"#,
            1,
        ),
        (
            r#"let attempted = prepared_driver::retry_prepared(slot, epoch)"#,
            1,
        ),
        (r#"let attempted = retry_post_body(slot, epoch)"#, 1),
        (r#"let attempted = retry_queued_body(slot, epoch)"#, 1),
        (r#"queued_owner::retry(slot, epoch)"#, 1),
        (r#"prepared_driver::retry_prepared(slot, epoch)"#, 2),
        (r#"let returned = body.retry_returns()"#, 1),
        (
            r#"if !transport_receiver::retry_transport_return(slot, &mut service, epoch)"#,
            1,
        ),
        (r#"start.retry_adopted_aliases_before_world_cleanup()"#, 1),
        (r#"start.retry_adopted_aliases_after_world_cleanup()"#, 1),
        (r#"start.retry_before_world_cleanup()"#, 1),
        (r#"start.retry_after_world_cleanup()"#, 1),
    ],
    expressions: &[
        (r#"prepared_driver::retry_prepared(slot, epoch)"#, 2),
        (r#"retry_body_and_controls(slot, epoch)"#, 1),
        (r#"retry_post_body(slot, epoch)"#, 1),
        (r#"retry_queued_body(slot, epoch)"#, 1),
        (r#"queued_owner::retry(slot, epoch)"#, 1),
        (r#"retry_returns()"#, 1),
        (
            r#"transport_receiver::retry_transport_return(slot, &mut service, epoch)"#,
            1,
        ),
        (r#"retry_adopted_aliases_before_world_cleanup()"#, 1),
        (r#"retry_adopted_aliases_after_world_cleanup()"#, 1),
        (r#"retry_before_world_cleanup()"#, 1),
        (r#"retry_after_world_cleanup()"#, 1),
    ],
    identifiers: &[
        ("retry_slot", 1),
        ("retry_prepared", 2),
        ("retry_body_and_controls", 2),
        ("retry_post_body", 2),
        ("retry_queued_body", 2),
        ("retry", 1),
        ("retry_returns", 1),
        ("retry_transport_return", 1),
        ("retry_adopted_aliases_before_world_cleanup", 1),
        ("retry_adopted_aliases_after_world_cleanup", 1),
        ("retry_before_world_cleanup", 1),
        ("retry_after_world_cleanup", 1),
    ],
    companions: &[
        super::BACKEND,
        super::SOURCE,
        super::SERVICE,
        super::RECEIVER,
    ],
};

pub(super) const QUEUED: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/queued_owner",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"service.queued_owner = Some(owner); service.queued_owner_borrowed = false;"#,
            1,
        ),
        (
            r#"let mut borrowed = QueuedOwner::borrow(slot, epoch)?;"#,
            1,
        ),
        (r#"if !complete"#, 1),
        (
            r#"Ok(Ok(())) => control(slot).owner_cleanup_complete = true,"#,
            1,
        ),
        (
            r#"Ok(Err(crate::ProductionVmConstructionCleanupError::SharedAliasesPending))"#,
            1,
        ),
        (r#"record_first(slot, first);"#, 2),
        (
            r#"control(slot).panic_payload = Some(payload); slot.publish(CleanupPhase::DestructionRefused);"#,
            2,
        ),
        (r#"if !transferred"#, 1),
        (
            r#"cell.incoming_post_body = incoming; cell.owner_post_body_taken = true;"#,
            1,
        ),
        (r#"if !terminal::destroy_payload(slot, owner)"#, 1),
        (
            r#"slot.body_destroyed_epoch.store(epoch, Ordering::Release); drop(cell);"#,
            1,
        ),
        (
            r#"Some(previous) => previous.with_later_failure(first),"#,
            1,
        ),
        (
            r#"match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.retry_cleanup()"#,
            1,
        ),
    ],
    expressions: &[
        (r#"fn retry(slot: &CleanupSlot, epoch: u64)"#, 1),
        (r#"retry_cleanup()"#, 1),
    ],
    identifiers: &[("retry", 1), ("retry_cleanup", 1)],
    companions: &[super::BACKEND],
};

pub(super) const PREPARED_DRIVER: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/prepared_driver",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"let Some(owner) = owner.downcast_mut::<T>() else { return PreparedAttempt::WrongType; };"#,
            1,
        ),
        (r#"if prepared.panic_payload.is_some()"#, 1),
        (r#"if !prepared.body_closed"#, 1),
        (r#"(operations.retry)(owner.as_mut())"#, 1),
        (
            r#"Ok(PreparedAttempt::Closed) => prepared.body_closed = true,"#,
            1,
        ),
        (
            r#"crate::ProductionVmConstructionCleanupError::retain_first(&mut prepared.cleanup_failure, first,);"#,
            2,
        ),
        (
            r#"prepared.panic_payload = Some(payload); slot.publish(CleanupPhase::DestructionRefused);"#,
            2,
        ),
        (r#"if prepared.epoch != epoch"#, 1),
        (r#"if !prepared.post_body_taken"#, 1),
        (
            r#"prepared.pending_post_body = body; prepared.post_body_taken = true;"#,
            1,
        ),
        (r#"match owner.retry_cleanup()"#, 1),
    ],
    expressions: &[
        (r#"retry_cleanup()"#, 1),
        (r#"retry_body_in_place(slot, &mut prepared)"#, 1),
    ],
    identifiers: &[
        ("retry", 5),
        ("retry_cleanup", 1),
        ("retry_body_in_place", 2),
        ("retry_prepared", 1),
    ],
    companions: &[super::BACKEND],
};

pub(super) const PREPARED_SERVICE: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/prepared_service",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"slot.epoch.load(Ordering::Acquire) != self.key.epoch || prepared.epoch != self.key.epoch"#,
            2,
        ),
        (
            r#"!(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared))"#,
            2,
        ),
        (
            r#"|| prepared.owner.is_none() || prepared.post_body_taken"#,
            1,
        ),
        (r#"slot.request_retirement();"#, 2),
        (r#"Ok(prepared.body_closed)"#, 1),
        (
            r#"super::prepared_driver::retry_body_in_place(slot, &mut prepared)"#,
            1,
        ),
        (r#"self.service_main_handle().retry_prepared_body()"#, 1),
    ],
    expressions: &[
        (
            r#"super::prepared_driver::retry_body_in_place(slot, &mut prepared)"#,
            1,
        ),
        (r#"retry_prepared_body()"#, 1),
    ],
    identifiers: &[("retry_prepared_body", 3), ("retry_body_in_place", 1)],
    companions: &[super::BACKEND],
};

pub(super) const POST_BODY: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/post_body",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"for body in self.returns.iter_mut().flatten()"#, 1),
        (r#"if target.is_physically_returned()"#, 1),
        (r#"self.observe_return(); if !self.returned"#, 1),
        (
            r#"if let Err(first) = self.loan.try_finish_after_members_returned() { self.first.get_or_insert(first); }"#,
            1,
        ),
        (
            r#"if !self.returned || self.observer_returned || self.observer_panic_payload.is_some()"#,
            1,
        ),
        (r#"Ok(Ok(())) => self.observer_returned = true,"#, 1),
        (r#"self.observer_first.get_or_insert(first);"#, 1),
        (
            r#"Err(payload) => self.observer_panic_payload = Some(payload),"#,
            1,
        ),
        (r#"NativeReturn::World(world) => world.retry()"#, 1),
        (r#"let _returned = target.retry_after_body()"#, 1),
    ],
    expressions: &[
        (r#"retry()"#, 1),
        (r#"retry_after_body()"#, 1),
        (r#"fn retry(&mut self)"#, 1),
    ],
    identifiers: &[("retry_returns", 1), ("retry", 2), ("retry_after_body", 1)],
    companions: &[super::SOURCE],
};

pub(super) const TARGET_RETURN: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/target_post_body",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"if self.physically_returned { return true; }"#, 1),
        (
            r#"self.physically_returned = self.selector.with_erased_after_body(|owner|"#,
            1,
        ),
        (r#"(self.returned)(owner)"#, 2),
        (
            r#"let _attempted = (self.retry)(owner); (self.returned)(owner)"#,
            1,
        ),
        (
            r#"owner.downcast_mut::<T>().is_some_and(TargetConstructionPostBody::retry_after_body)"#,
            1,
        ),
    ],
    expressions: &[],
    identifiers: &[("retry_after_body", 3), ("retry", 5)],
    companions: &[super::TARGET, super::AFTER_BODY],
};

pub(super) const TRANSPORT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup/transport_receiver",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"if service.epoch != epoch || slot.epoch.load(Ordering::Acquire) != epoch"#,
            1,
        ),
        (
            r#"return service.completed_transport_sequence == service.transport_sequence;"#,
            1,
        ),
        (
            r#"if slot.transport_return_sequence.load(Ordering::Acquire) < *sequence"#,
            1,
        ),
        (
            r#"receiver.record_alias_destruction(); if !receiver.try_return() { return false; }"#,
            1,
        ),
        (
            r#"service.completed_transport_sequence = *sequence; drop(service.transport_receiver.take());"#,
            1,
        ),
        (
            r#"if !retry_transport_return(slot, &mut service, self.key.epoch)"#,
            1,
        ),
    ],
    expressions: &[(
        r#"retry_transport_return(slot, &mut service, self.key.epoch)"#,
        1,
    )],
    identifiers: &[("retry_transport_return", 2)],
    companions: &[super::RECEIVER],
};

pub(super) const QUEUE: Contract = Contract {
    package: "crucible-daemon",
    target: "src/lifecycle_cleanup",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"for (index, slot) in self.slots.iter().enumerate()"#, 1),
        (r#"let epoch = slot.epoch.load(Ordering::Acquire);"#, 1),
        (
            r#"if slot.epoch.load(Ordering::Acquire) == epoch && slot.is(CleanupPhase::Reserved)"#,
            1,
        ),
        (
            r#"if slot.report_references.load(Ordering::Acquire) == 1 { slot.export_abandoned.store(true, Ordering::Release); }"#,
            1,
        ),
        (
            r#"slot.is(CleanupPhase::TerminalReady) && slot.report_references.load(Ordering::Acquire) == 0"#,
            1,
        ),
        (r#"match terminal::take_terminal_body(&key)"#, 1),
        (r#"let _attempt = retry_slot(slot, Some(epoch))"#, 1),
    ],
    expressions: &[(r#"retry_slot(slot, Some(epoch))"#, 1)],
    identifiers: &[("retry_slot", 2), ("retry_pending", 1)],
    companions: &[super::DRIVER_OWNER],
};
