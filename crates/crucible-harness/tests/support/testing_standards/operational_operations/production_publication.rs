//! Binds same-owner custody republication without treating it as cleanup.
//!
//! Only the declaration is masked after exact same-pair, canonical-cell and
//! caller-receipt obligations match. Native authority is not established here.

use super::{Companion, Contract};

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/construction/publication",
    required: &[
        (
            r#"pub fn retry_reserved_publication(
        &mut self,
    ) -> Result<
        Option<
            Box<
                dyn crucible_api::ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                    >,
            >,
        >,
        &'static str,
    > {"#,
            1,
        ),
        (
            r#"let FailureStorage::Rejected { returned, .. } = &mut self.storage else {
    return Err("");
};"#,
            1,
        ),
        (
            r#"let returned = returned.get_mut().map_err(|_| "")?;
let Some((reservation, owner)) = returned.take() else {
    return Ok(None);
};"#,
            1,
        ),
        (
            r#"match reservation.retain(owner) {
    Ok(handoff) => Ok(Some(handoff)),
    Err((reservation, owner)) => {
        *returned = Some((reservation, owner));
        Err("")
    }
}"#,
            1,
        ),
        (
            r#"match reservation.retain(custody) {
    Ok(handoff) => Ok((first, handoff)),
    Err((reservation, owner)) => Err(Self {
        storage: FailureStorage::Rejected {
            first,
            returned: std::sync::Mutex::new(Some((reservation, owner))),
        },
        additional: None,
    }),
}"#,
            1,
        ),
        (
            r#"match reservation.retain(self) {
    Ok(handoff) => Ok(handoff),
    Err((reservation, owner)) => Err(ProductionVmConstructionFailure {
        storage: FailureStorage::Rejected {
            first: LifecycleApiError::ConstructionCustodyUnavailable,
            returned: std::sync::Mutex::new(Some((reservation, owner))),
        },
        additional: None,
    }),
}"#,
            1,
        ),
        (r#"reservation.retain("#, 3),
        (r#"custody.first.take()"#, 1),
        (
            r#"let Some(first) = custody.first.take() else {
    custody.reservation = Some(reservation);
    return Err(Self { storage: FailureStorage::Preallocated(custody), additional: None, });
};"#,
            1,
        ),
        (r#"first.to_string("#, 0),
        (r#"self.storage ="#, 0),
        (r#"self.additional ="#, 0),
        (r#"returned.replace("#, 0),
        (r#"std::mem::replace("#, 0),
        (r#"ProductionVmCleanupStage::Complete"#, 0),
        (r#".retry_cleanup("#, 0),
        (r#".complete("#, 0),
        (r#"Box::new("#, 0),
        (r#"Arc::new("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#"thread::"#, 0),
        (r#"loop"#, 0),
        (r#"while"#, 0),
        (r#"for"#, 1),
        (r#"mem::forget("#, 0),
        (r#"Box::leak("#, 0),
        (
            r#"let Some(reservation) = custody.reservation.take() else {
    return Err(Self { storage: FailureStorage::Preallocated(custody), additional: None, });
};"#,
            1,
        ),
        (
            r#"let Some(reservation) = self.reservation.take() else {
    return Err(self.into_failure(LifecycleApiError::ConstructionCustodyUnavailable));
};"#,
            1,
        ),
        (
            r#"and_then(|launcher| launcher.take_cleanup_reservation())"#,
            2,
        ),
        (r#"lifecycle.node_launcher.take_cleanup_reservation()"#, 2),
    ],
    expressions: &[],
    identifiers: &[("retry_reserved_publication", 1)],
    companions: &[
        Companion {
            path: "crates/crucible-api/src/cleanup_owner.rs",
            required: &[
                (
                    r#"pub trait ProductionVmCleanupReservation: Send { type Failure: std::error::Error + Send + 'static;"#,
                    1,
                ),
                (
                    r#"fn retain(
    self: Box<Self>,
    owner: Box<dyn ProductionVmCleanupOwner<Failure = Self::Failure>>,
) -> Result<
    Box<dyn ProductionVmCleanupHandoff<Failure = Self::Failure>>,
    (Box<dyn ProductionVmCleanupReservation<Failure = Self::Failure>>,
     Box<dyn ProductionVmCleanupOwner<Failure = Self::Failure>>,),
>;"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible-daemon/src/lifecycle_cleanup/reservation.rs",
            required: &[
                (
                    r#"pub(super) struct CleanupReservation {
    queue: Weak<LifecycleCleanupQueue>, index: usize, epoch: u64,
    observed: ProductionVmCleanupStage, first_failure: Option<crate::ProductionVmConstructionCleanupError>,
}"#,
                    1,
                ),
                (
                    r#"pub(crate) fn reserve_for_world(
        &self,
        controls: AuthenticatedNativeWorldControlLease,
    ) -> Result<
        Box<
            dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
            >,
        >,
        (AuthenticatedNativeWorldControlLease, LifecycleApiError),
    > { self.reserve_with(controls, |cell, controls| cell.controls = Some(controls)) }"#,
                    1,
                ),
                (
                    r#"let epoch = initialize_reserved_slot(slot, input, attach)?;
return Ok(Box::new(CleanupReservation {
    queue: Weak::clone(&self.queue), index, epoch,
    observed: ProductionVmCleanupStage::BodyRetained, first_failure: None,
}));"#,
                    1,
                ),
                (
                    r#"impl ProductionVmCleanupReservation for CleanupReservation {
    type Failure = crate::ProductionVmConstructionCleanupError;"#,
                    1,
                ),
                (
                    r#"let Some(queue) = self.queue.upgrade() else {
            return Err((self, owner));
        };
        let Some(slot) = queue.slots.get(self.index) else {
            return Err((self, owner));
        };
        self.publish_owner(slot, owner).map(|receipt| {
            receipt
                as Box<
                    dyn ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                    >,
                >
        })"#,
                    1,
                ),
                (
                    r#"if !slot.claim(CleanupPhase::Reserved, CleanupPhase::Publishing) {
    return Err((self, owner));
}"#,
                    1,
                ),
                (
                    r#"let mut cell = match slot.cell.lock() {
    Ok(cell) => cell,
    Err(_) => { slot.publish(CleanupPhase::DestructionRefused); return Err((self, owner)); }
};
if cell.epoch != self.epoch || cell.owner.is_some() {
    slot.publish(CleanupPhase::DestructionRefused); return Err((self, owner));
}"#,
                    1,
                ),
                (
                    r#"cell.owner = Some(owner); cell.handoff = true; drop(cell);
slot.publish(CleanupPhase::Queued); Ok(self)"#,
                    1,
                ),
                (r#"if cell.owner.is_some() || cell.controls.is_some() {"#, 1),
                (
                    r#"cell.epoch = epoch; cell.first_failure = None; cell.handoff = false;
attach(&mut cell, input); drop(cell); slot.publish(CleanupPhase::Reserved); Ok(epoch)"#,
                    1,
                ),
                (r#"let epoch = match cell.epoch.checked_add(1) {"#, 1),
                (r#"if !slot.is(CleanupPhase::Reserving) {"#, 1),
                (
                    r#"if !slot.claim(CleanupPhase::Free, CleanupPhase::Reserving) { continue; }"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible-daemon/src/lifecycle_cleanup.rs",
            required: &[
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
                (
                    r#"fn retry_slot(slot: &CleanupSlot, expected_epoch: Option<u64>) -> Result<(), LifecycleApiError> {
    if slot.is(CleanupPhase::Free) || slot.is(CleanupPhase::Closed) { return Ok(()); }
    if slot.claim(CleanupPhase::OwnerDestroyed, CleanupPhase::Completing) {
        let (mut cell, poisoned) = match slot.cell.lock() {"#,
                    1,
                ),
                (
                    r#"if !slot.claim(CleanupPhase::Queued, CleanupPhase::Retrying) {
    return Err(refusal(""));
}
let (mut cell, poisoned) = match slot.cell.lock() {"#,
                    1,
                ),
                (r#"slot.cell.lock()"#, 3),
                (r#"slot.claim(CleanupPhase::Reserved"#, 0),
                (r#"slot.claim(CleanupPhase::Publishing"#, 0),
                (
                    r#"let returned = close_controls_retaining_failure(&mut cell);
publish_return(slot, returned.is_ok()); return returned;
}
if !slot.claim(CleanupPhase::Queued, CleanupPhase::Retrying) {"#,
                    1,
                ),
                (
                    r#"let destroyed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(owner)));
let mut cell = match slot.cell.lock() {"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible-daemon/src/qemu_campaign_lifecycle/source_construction/retained.rs",
            required: &[
                (
                    r#"Api {
        owner: crate::ProductionVmConstructionFailure,
        handoff: Option<
            Box<
                dyn ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                >,
            >,
        >,
    },"#,
                    1,
                ),
                (
                    r#"Self::Api { owner, handoff } => (handoff, owner.retry_reserved_publication()?),"#,
                    1,
                ),
                (
                    r#"let Some(receipt) = published else { return Err(""); };
*slot = Some(receipt); Ok(false)"#,
                    1,
                ),
                (
                    r#"if let Some(handoff) = self.handoff_mut()
    && !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete)) {
    return Err(self);
}"#,
                    1,
                ),
                (
                    r#"if let Some(owner) = self.retained_install.as_mut() {
    if owner.handoff_mut().is_none() {
        match owner.retry_publication() {
            Ok(false) => {}
            Ok(true) => { return self.take_completed_install_history(); }
            Err(_) => return Err(owner.report()),
        }
    }
}"#,
                    1,
                ),
                (
                    r#"let Some(receipt) = owner.handoff_mut() else { return Err(owner.report()); };
let attempt = receipt.retry(); let stage = receipt.stage();
if !matches!(stage, Ok(ProductionVmCleanupStage::Complete)) {"#,
                    1,
                ),
                (
                    r#"pub(super) fn require_install_vacancy(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
    if self.lifecycle_outstanding {
        return Err(QemuAttemptProductionVmLifecycleError::SourceInstallRetained {
            diagnostic: String::from(""),
        },);
    }
    self.retry_retained_source_installation()
}"#,
                    1,
                ),
                (
                    r#"Self::Api { owner, handoff: Some(mut handoff), } => match owner.into_published_error() {
    Ok(first) => SourceCleanupHistory { first: Some(SourceInstallationFirst::Api(first)),"#,
                    1,
                ),
                (
                    r#"Err(owner) => { return Err(Self::Api { owner, handoff: Some(handoff), }); }"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction.rs",
            required: &[
                (
                    r#"factory: Some(factory), world: Some(world), reservation: None,"#,
                    1,
                ),
                (
                    r#"match factory.reserve_world_lifecycle_cleanup(controls) {
    Ok(reservation) => { self.reservation = Some(reservation); Ok(()) }
    Err((controls, source)) => { self.controls = Some(controls); Err(source) }
}"#,
                    1,
                ),
                (
                    r#"let Some(reservation) = self.reservation.take() else {
    self.factory = Some(factory); return Err(self);
};"#,
                    1,
                ),
                (
                    r#"Ok((guard, storage, factory, reservation, custody, world))"#,
                    1,
                ),
                (
                    r#"|| self.construction_custody.is_none() || self.world.is_none() { return Err(self); }"#,
                    1,
                ),
                (
                    r#"let Some(world) = self.world.take() else {
    self.returned_guard = Some(guard);
    self.generation_storage = Some(storage);
    self.factory = Some(factory);
    self.reservation = Some(reservation);
    self.construction_custody = Some(custody);
    return Err(self);
};
Ok((guard, storage, factory, reservation, custody, world))"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
            required: &[
                (
                    r#"let mut owner = PendingSourceConstruction::new_prepaid(factory, loan, controls);
let result = owner.reserve_cleanup().and_then(|()| {"#,
                    1,
                ),
                (r#"pending = Some(owner); result"#, 1),
                (r#"self.require_install_vacancy()?;"#, 1),
                (
                    r#"let (guard, expected, pending) = self.begin_retained_native_world_guard(context, source, config)?;"#,
                    1,
                ),
                (
                    r#"let (guard, storage, factory, reservation, custody, world) = match pending.into_launcher_parts(guard) {"#,
                    1,
                ),
                (
                    r#".with_cleanup_reservation(reservation).with_construction_custody(custody).with_world_cleanup_loan(world),"#,
                    1,
                ),
                (
                    r#"let mut factory = Some(self.resources.retain_fork_target_factory().ok_or_else(|| {"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible-daemon/src/qemu_lifecycle_launcher.rs",
            required: &[
                (
                    r#"pub(crate) fn with_cleanup_reservation(
        mut self,
        reservation: Box<
            dyn crucible_api::ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                >,
        >,
    ) -> Self { self.cleanup_reservation = Some(reservation); self }"#,
                    1,
                ),
                (
                    r#"fn take_cleanup_reservation(
        &mut self,
    ) -> Option<
        Box<
            dyn crucible_api::ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                >,
        >,
    > { self.cleanup_reservation.take() }"#,
                    1,
                ),
                (
                    r#"pub(crate) fn with_world_cleanup_loan(
        mut self,
        world: crucible_linux_resource::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Self { self._world_cleanup_loan = Some(world); self }"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible-daemon/src/qemu_resource_guard.rs",
            required: &[(
                r#"let Some(cleanup) = self.cleanup.as_ref() else {
    return Err((controls, QemuVmRealizationError::ExecutorUnavailable {
        operation: "", message: String::from(""),
    },));
};
cleanup.reserve_for_world(controls).map_err(|(controls, error)| {"#,
                1,
            )],
        },
    ],
}];

#[cfg(test)]
#[path = "production_publication/tests.rs"]
mod tests;
