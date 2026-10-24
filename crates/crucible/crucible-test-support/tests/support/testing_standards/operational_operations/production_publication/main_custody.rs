//! Binds canonical Main custody from fixed birth through actual final disposal.
//!
//! Publication pins the same epoch without creating work authority. Callbacks
//! release publication locks, body destruction precedes containing credit, and
//! external returns and reports prevent role reuse until their actual disposal.

use super::Companion;

/// Binds canonical token ownership, epoch checks, and external-return publication.
pub(super) const RESERVATION: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/reservation.rs",
    required: &[
        (
            r#"pub(super) struct CleanupReservation {
    queue: Weak<LifecycleCleanupQueue>, index: usize, epoch: u64,
    observed: ProductionVmCleanupStage,
    first_failure: Option<crate::ProductionVmConstructionCleanupError>,
    terminal_history: Option<crate::ProductionVmConstructionPostBody>, report_reference: bool,
}"#,
            1,
        ),
        (
            r#"let Some(queue) = self.cell.queue.upgrade() else { return Err(controls); };
let Some(slot) = queue.slots.get(self.cell.index) else { return Err(controls); };"#,
            1,
        ),
        (
            r#"let Some(mut cell) = borrow_reserved_cell(slot, self.cell.epoch) else { return Err(controls); };
if cell.controls.is_some() { return Err(controls); }
cell.controls = Some(controls); cell.controls_bound = true; Ok(())"#,
            1,
        ),
        (
            r#"if !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared)) { return None; }
let cell = slot.cell.try_lock().ok()?;
if cell.epoch != epoch || cell.owner.is_some() || cell.handoff
    || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared)) {
    return None;
}
Some(cell)"#,
            1,
        ),
        (
            r#"impl ProductionVmCleanupReservation for CleanupReservation {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;
    type ReturnDestination = SourceBodyReturn;"#,
            1,
        ),
        (
            r#"let Some(queue) = self.queue.upgrade() else { return Err((self, owner)); };
let Some(slot) = queue.slots.get(self.index) else { return Err((self, owner)); };
self.publish_owner(slot, owner).map(|receipt| {
    receipt as Box<dyn ProductionVmCleanupHandoff<
        Failure = crate::ProductionVmConstructionCleanupError,
        PostBody = crate::ProductionVmConstructionPostBody,
    >,>
})"#,
            1,
        ),
        (r#"self.publish_owner_mode(slot, owner, false)"#, 1),
        (r#"self.publish_owner_mode(slot, owner, true)"#, 1),
        (
            r#"if slot.epoch.load(Ordering::Acquire) != self.epoch { return Err((self, owner)); }
let was_quarantined = returned && slot.claim(CleanupPhase::DestructionRefused, CleanupPhase::Publishing);
let claimed = was_quarantined
    || slot.claim(CleanupPhase::Reserved, CleanupPhase::Publishing)
    || (returned && slot.claim(CleanupPhase::RetryingPrepared, CleanupPhase::Publishing));
if !claimed { return Err((self, owner)); }"#,
            1,
        ),
        (
            r#"let (mut cell, poisoned) = match slot.cell.lock() {
    Ok(cell) => (cell, false),
    Err(poison) if returned => (poison.into_inner(), true),
    Err(_) => { slot.publish(CleanupPhase::DestructionRefused); return Err((self, owner)); }
};
if cell.epoch != self.epoch || cell.owner.is_some() || cell.handoff
    || slot.external_return_reserved.load(Ordering::Acquire) {
    slot.publish(CleanupPhase::DestructionRefused); return Err((self, owner));
}
if !report_refs::register(slot, self.epoch) {
    slot.publish(CleanupPhase::DestructionRefused); return Err((self, owner));
}
self.report_reference = true; slot.request_retirement();
cell.owner = Some(owner); cell.handoff = true;"#,
            1,
        ),
        (
            r#"drop(cell);
if poisoned || was_quarantined { slot.publish(CleanupPhase::DestructionRefused); }
else if !slot.claim(CleanupPhase::Publishing, CleanupPhase::Queued) {
    slot.publish(CleanupPhase::DestructionRefused);
}
Ok(self)"#,
            1,
        ),
        (
            r#"if slot.epoch.load(Ordering::Acquire) != self.epoch
    || cell.epoch != self.epoch
    || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared))
    || cell.owner.is_some() || cell.handoff
    || slot.external_return_reserved.load(Ordering::Acquire)
    || self.report_reference || !report_refs::register(slot, self.epoch) {
    return Err(self);
}
self.report_reference = true;
slot.external_return_reserved.store(true, Ordering::Release);
let index = self.index; let epoch = self.epoch; drop(cell);
Ok(SourceBodyReturn::new(queue, index, epoch, self))"#,
            1,
        ),
        (
            r#"let Some(queue) = self.queue.upgrade() else { return Err(self); };
let Some(slot) = queue.slots.get(self.index) else { return Err(self); };
let mut cell = match slot.cell.lock() {
    Ok(cell) => cell,
    Err(_) => return Err(self),
};"#,
            1,
        ),
        (
            r#"pub(super) fn new_world_reservation(
    queue: &Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
) -> WorldLifecycleCleanupReservation {
    WorldLifecycleCleanupReservation {
        reservation: Box::new(CleanupReservation {
            queue: Weak::clone(queue),
            index,
            epoch,
            observed: ProductionVmCleanupStage::BodyRetained,
            first_failure: None,
            terminal_history: None,
            report_reference: false,
        }),
        cell: ReservedWorldCell {
            queue: Weak::clone(queue),
            index,
            epoch,
        },
    }
}"#,
            1,
        ),
        (
            r#"pub(crate) fn is_reserved(&self) -> bool {
        let Some(queue) = self.cell.queue.upgrade() else {
            return false;
        };
        let Some(slot) = queue.slots.get(self.cell.index) else {
            return false;
        };
        let Some(cell) = borrow_reserved_cell(slot, self.cell.epoch) else {
            return false;
        };
        cell.controls.is_some()
    }"#,
            1,
        ),
    ],
};

/// Binds admission pricing and atomic role transitions.
pub(super) const QUEUE: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup.rs",
    required: &[
        (
            r#"let constructors = prepared_constructor_control_bytes()?
    .checked_mul(u64::try_from(slots).map_err(|_| refusal(""))?)
    .ok_or_else(|| refusal(""))?;"#,
            1,
        ),
        (
            r#"u64::try_from(bytes).ok().and_then(|bytes| bytes.checked_add(constructors))"#,
            1,
        ),
        (
            r#"fn prepared_constructor_control_bytes() -> Result<u64, LifecycleApiError> {
    type SourceFactory = crate::ComposedQemuAttemptResourceGuardFactory<
        crate::SharedQemuAttemptHostResourceFactory<crate::LinuxQemuAttemptHostResourceFactory>,
    >;
    let source = crate::qemu_lifecycle_launcher::PendingSourceConstruction::<SourceFactory>::control_bytes()?;
    let target = crate::qemu_hot_fork_world_factory::target_construction::PendingTargetConstruction::<SourceFactory,>::control_bytes()?;
    Ok(source.max(target))
}"#,
            1,
        ),
        (
            r#"fn claim(&self, from: CleanupPhase, to: CleanupPhase) -> bool {
    self.phase.compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire).is_ok()
}"#,
            1,
        ),
        (
            r#"fn publish(&self, phase: CleanupPhase) {
    self.phase.store(phase as u8, Ordering::Release);
}"#,
            1,
        ),
        (r#"slot.cell.lock()"#, 0),
        (r#"slot.claim(CleanupPhase::Reserved"#, 0),
        (r#"slot.claim(CleanupPhase::Publishing"#, 0),
    ],
};

/// Binds genuine Main verification and fixed-body installation before publication.
pub(super) const PREPARED_BIRTH: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/prepared_producer.rs",
    required: &[
        (
            r#"pub struct SourceMainProducer { queue: Weak<LifecycleCleanupQueue>, }"#,
            1,
        ),
        (
            r#"pub(crate) fn source_main_producer(&self) -> SourceMainProducer {
    SourceMainProducer { queue: Weak::clone(&self.queue), }
}"#,
            1,
        ),
        (
            r#"if let Err(first) = queue._pool.verify_retained_main() {
    return Err((input, ServiceMainPreclaimError::Main(first)));
}"#,
            1,
        ),
        (
            r#"if constructor_bytes < minimum_body || constructor_bytes > queue.constructor_bytes {
    return Err((input, role(""),));
}"#,
            1,
        ),
        (
            r#"for (index, slot) in queue.slots.iter().enumerate() {
    if !slot.claim(CleanupPhase::Free, CleanupPhase::Reserving) { continue; }"#,
            1,
        ),
        (
            r#"if !prepared.is_empty() || !service.is_empty()
    || slot.external_return_reserved.load(Ordering::Acquire)
    || cell.owner.is_some() || cell.controls.is_some() || cell.first_failure.is_some()
    || cell.post_body.is_some() || cell.incoming_post_body.is_some()
    || cell.control_failure.is_some() || cell.retirement_input.is_some()
    || cell.retirement_input_reserved || cell.panic_payload.is_some()
    || cell.controls_bound || cell.handoff
    || slot.report_references.load(Ordering::Acquire) != report_refs::CLOSED
    || slot.external_receivers.load(Ordering::Acquire) != 0
    || !slot.is(CleanupPhase::Reserving) {
    slot.publish(CleanupPhase::DestructionRefused);
    return Err((input, role("")));
}"#,
            1,
        ),
        (
            r#"let Some(epoch) = cell.epoch.checked_add(1) else {
    slot.publish(CleanupPhase::DestructionRefused); return Err((input, role("")));
};"#,
            1,
        ),
        (
            r#"let reservation = reservation::new_world_reservation(&self.queue, index, epoch);
let key = reservation.service_preclaim(); let (owner, initial_service) = build(input, reservation);
*prepared = PreparedCell::installed(
    epoch, owner, projections, super::prepared_driver::PreparedBodyOperations::for_owner::<T>(),
);
*service = ServiceCell::installed(epoch, initial_service);
service.role = Some(prepared_role); cell.epoch = epoch; cell.handoff = false;"#,
            1,
        ),
        (
            r#"let handle = prepared_service::PreparedSourceHandle::from_key(key);
drop(cell); drop(service); drop(prepared);
slot.publish(CleanupPhase::Reserved); return Ok(handle);"#,
            1,
        ),
        (
            r#"pub(crate) fn verify_source_selector(
        &self,
        source: &prepared_service::PreparedSourceSelector,
    ) -> Result<(), ServiceMainPreclaimError> {
        if !Weak::ptr_eq(&self.queue, &source.key.queue) {
            return Err(role(                                                    ));
        }
        let queue = source.key.containing_queue()?;
        queue
            ._pool
            .verify_retained_main()
            .map_err(ServiceMainPreclaimError::Main)?;
        let slot = queue
            .slots
            .get(source.key.index)
            .ok_or_else(|| role(                                ))?;
        let service = slot
            .service
            .try_lock()
            .map_err(|_| role(                                                 ))?;
        if slot.epoch.load(Ordering::Acquire) != source.key.epoch
            || service.epoch != source.key.epoch
            || service.role != Some(PreparedRole::Source)
            || !slot.is(CleanupPhase::Reserved)
            || !slot.work_is_open()
            || !service
                .start
                .as_ref()
                .is_some_and(|start| start.matches_main_role(&source.key))
        {
            return Err(role(                                                      ));
        }
        Ok(())
    }"#,
            1,
        ),
    ],
};

/// Binds body destruction before containing World-credit closure.
pub(super) const BODY_DRIVER: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/driver.rs",
    required: &[
        (
            r#"let epoch = slot.epoch.load(Ordering::Acquire);
if expected_epoch.is_some_and(|expected| expected != epoch) { return Err(refusal("")); }"#,
            1,
        ),
        (
            r#"if slot.is(CleanupPhase::Reserved) {
    if !slot.retirement_requested.load(Ordering::Acquire) { return Err(refusal("")); }
    let _attempt = PhaseAttempt::claim(slot, CleanupPhase::Reserved, CleanupPhase::RetryingPrepared)
        .ok_or_else(|| refusal(""))?;"#,
            1,
        ),
        (
            r#"if let Some(_attempt) = PhaseAttempt::claim(slot, CleanupPhase::Queued, CleanupPhase::Retrying) {
    let attempted = retry_queued_body(slot, epoch); if attempted.is_err() { return attempted; }
}"#,
            1,
        ),
        (
            r#"if let Some(_attempt) = PhaseAttempt::claim(slot, CleanupPhase::OwnerDestroyed, CleanupPhase::Completing) {
    let attempted = close_controls(slot, epoch);
    if attempted.is_err() {
        if !slot.is(CleanupPhase::DestructionRefused) { slot.publish(CleanupPhase::OwnerDestroyed); }
        return attempted;
    }
    slot.controls_closed_epoch.store(epoch, Ordering::Release);
    slot.publish(CleanupPhase::PostBodyPending);
}"#,
            1,
        ),
        (r#"slot.cell.lock()"#, 1),
        (
            r#"let mut cell = slot.cell.lock().map_err(|_| refusal(""))?;"#,
            1,
        ),
        (
            r#"if cell.epoch != epoch || cell.owner.is_some() || cell.incoming_post_body.is_some() {
    slot.publish(CleanupPhase::DestructionRefused); return Err(refusal(""));
}"#,
            1,
        ),
        (
            r#"if cell.controls_bound != cell.controls.is_some() || cell.controls_bound != world_return {
        return Err(refusal(
                                                                        ,
        ));
    }"#,
            1,
        ),
        (
            r#"if let Some(controls) = cell.controls.as_mut()
    && let Err(first) = controls.close_after_owner_destruction() {
    cell.control_failure.get_or_insert(first); return Err(refusal(""));
}
drop(cell.controls.take()); Ok(())"#,
            1,
        ),
    ],
};

/// Binds callback exclusion and restoration of the same original body.
pub(super) const QUEUED_OWNER: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/queued_owner.rs",
    required: &[
        (
            r#"let Some(owner) = service.queued_owner.take() else {
    slot.publish(CleanupPhase::DestructionRefused); return Err(refusal(""));
};
service.queued_owner_borrowed = true; drop(cell); drop(service);
let borrowed = Self { slot, owner: Some(owner), };"#,
            1,
        ),
        (
            r#"service.queued_owner = Some(owner); service.queued_owner_borrowed = false;"#,
            1,
        ),
        (
            r#"std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.retry_cleanup()))"#,
            1,
        ),
        (
            r#"std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.take_post_body()))"#,
            1,
        ),
        (
            r#"if !slot.claim(CleanupPhase::Retrying, CleanupPhase::Destroying) {
        return Err(refusal(
                                                                    ,
        ));
    }
    let owner = match borrowed.into_destruction() {
        Ok(owner) => owner,
        Err(_borrowed) => return Err(refusal(                                                  )),
    };


    if !terminal::destroy_payload(slot, owner) {
        return Err(refusal(                                                  ));
    }
    let cell = control(slot);
    if cell.epoch != epoch || cell.owner.is_some() {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal(                                                 ));
    }
    slot.body_destroyed_epoch.store(epoch, Ordering::Release);
    drop(cell);
    if !slot.claim(CleanupPhase::Destroying, CleanupPhase::OwnerDestroyed) {
        return Err(refusal(
                                                                ,
        ));
    }"#,
            1,
        ),
        (r#"slot.cell.lock()"#, 2),
    ],
};

/// Binds consumption of the unique pre-export return destination.
pub(super) const EXTERNAL_RETURN: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/body_return.rs",
    required: &[
        (
            r#"pub struct SourceBodyReturn {
    queue: Arc<LifecycleCleanupQueue>, index: usize, epoch: u64,
    reservation: Box<reservation::CleanupReservation>,
}"#,
            1,
        ),
        (
            r#"pub(super) fn new(
        queue: Arc<LifecycleCleanupQueue>,
        index: usize,
        epoch: u64,
        reservation: Box<reservation::CleanupReservation>,
    ) -> Self {
        Self {
            queue,
            index,
            epoch,
            reservation,
        }
    }"#,
            1,
        ),
        (
            r#"let Self {
            queue,
            index,
            epoch: _,
            reservation,
        } = self;
        let slot = &queue.slots[index];
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) => (poison.into_inner(), true),
        };



        cell.owner = Some(owner);
        cell.handoff = true;
        slot.external_return_reserved
            .store(false, Ordering::Release);
        if poisoned {
            crate::ProductionVmConstructionCleanupError::retain_first(
                &mut cell.first_failure,
                crate::ProductionVmConstructionCleanupError::Poisoned,
            );
        }
        slot.request_retirement();
        let _published = slot
            .phase
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |phase| {
                Some(
                    if poisoned || phase == CleanupPhase::DestructionRefused as u8 {
                        CleanupPhase::DestructionRefused as u8
                    } else {
                        CleanupPhase::Queued as u8
                    },
                )
            });
        drop(cell);



        drop(queue);
        reservation
    }"#,
            1,
        ),
    ],
};

/// Binds role reuse to final disposal of every outside reference.
pub(super) const REPORT_PINS: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/report_refs.rs",
    required: &[
        (
            r#"pub(super) fn register(slot: &CleanupSlot, epoch: u64) -> bool {
    if slot
        .report_references
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
            (state < MAX_REFERENCES).then(|| state + 1)
        })
        .is_err()
    {
        return false;
    }
    let actual_epoch = slot.epoch.load(Ordering::Acquire);
    if actual_epoch != epoch
        || slot.is(CleanupPhase::Free)
        || slot.is(CleanupPhase::Reserving)
        || slot.is(CleanupPhase::TerminalOwned)
        || slot.is(CleanupPhase::TerminalDisposing)
    {


        release(slot, actual_epoch, false);
        return false;
    }
    true
}"#,
            1,
        ),
        (
            r#"pub(super) fn release(slot: &CleanupSlot, epoch: u64, terminal_disposed: bool) {
    if slot.epoch.load(Ordering::Acquire) != epoch {
        slot.publish(CleanupPhase::DestructionRefused);
        return;
    }
    if terminal_disposed {
        if !slot.claim(CleanupPhase::TerminalOwned, CleanupPhase::TerminalDisposing) {
            slot.publish(CleanupPhase::DestructionRefused);
            return;
        }
        slot.terminal_disposed.store(true, Ordering::Release);
    }
    let returned =
        slot.report_references
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state > 0 && state < CLOSED).then(|| state - 1)
            });
    match returned {
        Ok(1)
            if slot.terminal_disposed.load(Ordering::Acquire)
                && slot.is(CleanupPhase::TerminalDisposing) =>
        {
            if slot
                .report_references
                .compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.completed_epoch.store(epoch, Ordering::Release);
                slot.publish(CleanupPhase::Free);
            }
        }
        Ok(_) => {}
        Err(_) => slot.publish(CleanupPhase::DestructionRefused),
    }
}"#,
            1,
        ),
        (
            r#"pub(super) const CLOSED: usize = 1usize << (usize::BITS - 1);"#,
            1,
        ),
        (r#"const MAX_REFERENCES: usize = CLOSED - 1;"#, 1),
    ],
};

/// Binds copies of the original Main selection and refusal of an absent owner.
pub(super) const MAIN_SELECTION: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/prepared_service.rs",
    required: &[
        (
            r#"pub(crate) fn handle(&self) -> ServiceMainHandle {
    ServiceMainHandle { key: self.copy_selection(), }
}"#,
            1,
        ),
        (
            r#"pub(super) fn copy_selection(&self) -> Self {
    Self { queue: Weak::clone(&self.queue), index: self.index, epoch: self.epoch, }
}"#,
            1,
        ),
        (
            r#"pub(super) fn containing_queue(
    &self,
) -> Result<Arc<LifecycleCleanupQueue>, ServiceMainPreclaimError> {
    self.queue.upgrade().ok_or_else(|| unavailable(""))
}"#,
            1,
        ),
    ],
};
