//! Retains complete lifecycle owners in Main-prepaid, epoch-bound cleanup cells.
//!
//! Main owns the queue outside the shared factory graph. Factories and handoff
//! reservations are weak, including when a Target retains its parent Source.
//! Atomic phase arbitration keeps publication independent of queue scans. A cell
//! returns only after actual owner destruction and containing-body charge return.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crucible_control_api::{LifecycleApiError, ProductionVmCleanupHandoff, ProductionVmCleanupOwner, ProductionVmCleanupReservation, ProductionVmCleanupStage};
use crucible_host_resources::host_services::process_birth::{
    AuthenticatedNativePoolPurpose, AuthenticatedNativeWorldControlLease,
};

mod body_return;
mod input_return;
pub use input_return::ServiceInputReturn;
mod driver;
pub use body_return::SourceBodyReturn;

mod prepared_driver;
mod prepared_producer;
mod queued_owner;
mod report_refs;
mod work_gate;
use driver::retry_slot;
mod target_post_body;
mod terminal;
mod transport_receiver;
pub(crate) use prepared_producer::PreparedRole;
pub use prepared_producer::SourceMainProducer;
pub(crate) use target_post_body::TargetConstructionPostBody;
pub(crate) use transport_receiver::ServiceMainReceiverHandle;

mod prepared_retirement;
pub use prepared_retirement::{
    PreparedSourceFailure, PreparedSourceRefusal, PreparedSourceRetirement,
};
mod post_body;
pub use post_body::ProductionVmConstructionPostBody;

mod prepared_service;
pub(crate) use prepared_service::{
    PreparedSourceHandle, PreparedSourceProjections, ServiceMainHandle,
};
pub use prepared_service::{PreparedSourceSelector, ServiceMainReceiver};

mod reservation;
use reservation::CleanupReservation;
pub use reservation::WorldLifecycleCleanupReservation;
#[cfg(test)]
pub(crate) use reservation::component_owner_history_for_test;
pub(crate) use reservation::{ServiceMainPreclaim, ServiceMainPreclaimError};

/// Owns fixed cleanup storage beneath the actual containing Main pool.
pub(crate) struct LifecycleCleanupQueue {
    slots: Vec<CleanupSlot>,
    constructor_bytes: u64,
    _pool: AuthenticatedNativePoolPurpose,
}

/// Lends nonowning access without a queue -> owner -> factory cycle.
#[derive(Clone)]
pub(crate) struct LifecycleCleanupHandle {
    queue: Weak<LifecycleCleanupQueue>,
}

struct CleanupSlot {
    epoch: AtomicU64,
    retirement_requested: AtomicBool,
    external_return_reserved: AtomicBool,
    export_abandoned: AtomicBool,
    work_gate: work_gate::WorkGate,
    external_receivers: AtomicUsize,
    transport_return_sequence: AtomicU64,
    report_references: AtomicUsize,
    terminal_disposed: AtomicBool,
    phase: AtomicU8,
    body_destroyed_epoch: AtomicU64,
    controls_closed_epoch: AtomicU64,
    worlds_returned_epoch: AtomicU64,
    completed_epoch: AtomicU64,
    prepared: Mutex<prepared_service::PreparedCell>,
    service: Mutex<prepared_service::ServiceCell>,
    cell: Mutex<CleanupCell>,
}

struct CleanupCell {
    epoch: u64,
    owner: Option<
        Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
    >,
    controls: Option<AuthenticatedNativeWorldControlLease>,
    controls_bound: bool,
    retirement_input: Option<crate::packaged_qemu_executor::ServiceRetirementInput>,
    retirement_input_reserved: bool,
    panic_payload: Option<Box<dyn std::any::Any + Send>>,
    first_failure: Option<crate::ProductionVmConstructionCleanupError>,
    handoff: bool,
    post_body: Option<ProductionVmConstructionPostBody>,
    incoming_post_body: Option<ProductionVmConstructionPostBody>,
    owner_cleanup_complete: bool,
    owner_post_body_taken: bool,
    control_failure:
        Option<crucible_host_resources::host_services::process_birth::ServiceBirthError>,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanupPhase {
    Free,
    Reserving,
    Reserved,
    Publishing,
    Queued,
    Retrying,
    RetryingPrepared,
    PostBodyPending,
    Returning,
    Destroying,
    OwnerDestroyed,
    #[cfg(test)]
    Closed,
    Completing,
    TerminalReady,
    TerminalOwned,
    TerminalDisposing,
    DestructionRefused,
}

impl CleanupSlot {
    /// Creates fixed empty metadata without issuing a Main or native purpose.
    fn empty() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            retirement_requested: AtomicBool::new(false),
            external_return_reserved: AtomicBool::new(false),
            export_abandoned: AtomicBool::new(false),
            work_gate: work_gate::WorkGate::new(),
            external_receivers: AtomicUsize::new(0),
            transport_return_sequence: AtomicU64::new(0),
            report_references: AtomicUsize::new(report_refs::CLOSED),
            terminal_disposed: AtomicBool::new(false),
            phase: AtomicU8::new(CleanupPhase::Free as u8),
            body_destroyed_epoch: AtomicU64::new(0),
            controls_closed_epoch: AtomicU64::new(0),
            worlds_returned_epoch: AtomicU64::new(0),
            completed_epoch: AtomicU64::new(0),
            prepared: Mutex::new(prepared_service::PreparedCell::empty()),
            service: Mutex::new(prepared_service::ServiceCell::empty()),
            cell: Mutex::new(CleanupCell {
                epoch: 0,
                owner: None,
                controls: None,
                controls_bound: false,
                retirement_input: None,
                retirement_input_reserved: false,
                panic_payload: None,
                first_failure: None,
                handoff: false,
                post_body: None,
                incoming_post_body: None,
                owner_cleanup_complete: false,
                owner_post_body_taken: false,
                control_failure: None,
            }),
        }
    }

    /// Selects only an unissued component header for ownership controls.
    #[cfg(test)]
    fn unissued_for_test(epoch: u64, phase: CleanupPhase) -> Self {
        let mut slot = Self::empty();
        slot.epoch.store(epoch, Ordering::Release);
        slot.report_references.store(0, Ordering::Release);
        slot.phase.store(phase as u8, Ordering::Release);
        slot.service = Mutex::new(prepared_service::ServiceCell::installed(epoch, None));
        slot.cell.get_mut().unwrap().epoch = epoch;
        slot
    }

    fn claim(&self, from: CleanupPhase, to: CleanupPhase) -> bool {
        self.phase
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn publish(&self, phase: CleanupPhase) {
        self.phase.store(phase as u8, Ordering::Release);
    }

    fn is(&self, phase: CleanupPhase) -> bool {
        self.phase.load(Ordering::Acquire) == phase as u8
    }
}

impl LifecycleCleanupQueue {
    /// Prices fixed cells, reservation bodies and their preborn constructors.
    ///
    /// The producer derives the count from occupied Source/primary/auxiliary
    /// roles and includes this extent in the SAME Main before queue birth.
    /// Each role can hold one configured Linux Source constructor, its existing
    /// carrier and one native-admission report until its exact cell returns.
    pub(crate) fn control_bytes(slots: usize) -> Result<u64, LifecycleApiError> {
        if slots == 0 {
            return Err(refusal("cleanup ownership capacity is absent"));
        }
        let cells = std::alloc::Layout::array::<CleanupSlot>(slots)
            .map_err(|_| refusal("cleanup cell extent overflows"))?;
        let handles = std::alloc::Layout::array::<CleanupReservation>(slots)
            .map_err(|_| refusal("cleanup reservation extent overflows"))?;
        let (shared, _) = std::alloc::Layout::new::<(usize, usize)>()
            .extend(std::alloc::Layout::new::<Self>())
            .map_err(|_| refusal("cleanup shared owner extent overflows"))?;
        let constructors = prepared_constructor_control_bytes()?
            .checked_mul(u64::try_from(slots).map_err(|_| refusal("cleanup role count overflows"))?)
            .ok_or_else(|| refusal("Main Source constructor extent overflows"))?;
        let bytes = shared
            .pad_to_align()
            .size()
            .checked_add(cells.size())
            .and_then(|bytes| bytes.checked_add(handles.size()))
            .ok_or_else(|| refusal("cleanup containing extent overflows"))?;
        u64::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(constructors))
            .ok_or_else(|| refusal("cleanup containing extent is not representable"))
    }

    /// Constructs the one queue after the real containing producer paid it.
    pub(crate) fn new_prepaid(
        pool: AuthenticatedNativePoolPurpose,
        slots: usize,
    ) -> Result<Arc<Self>, LifecycleApiError> {
        Self::control_bytes(slots)?;
        let constructor_bytes = prepared_constructor_control_bytes()?;
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(slots)
            .map_err(|_| refusal("cleanup cell allocation refused"))?;
        cells.resize_with(slots, CleanupSlot::empty);
        Ok(Arc::new(Self {
            slots: cells,
            constructor_bytes,
            _pool: pool,
        }))
    }

    pub(crate) fn handle(self: &Arc<Self>) -> LifecycleCleanupHandle {
        LifecycleCleanupHandle {
            queue: Arc::downgrade(self),
        }
    }

    /// Runs bounded retirement passes only during the containing Main teardown.
    ///
    /// The caller must hold the actual saved Original across this pass. A
    /// dormant Reserved owner is barred from further work before its existing
    /// cleanup runs. Zero outside reports may abandon an export but never prove
    /// native, body or receiver return. Actual terminal fields are destroyed
    /// outside all locks before the exact role can become reusable.
    pub(crate) fn retry_pending(self: &Arc<Self>) -> Result<(), LifecycleApiError> {
        let mut refused = false;
        for (index, slot) in self.slots.iter().enumerate() {
            let epoch = slot.epoch.load(Ordering::Acquire);
            if slot.is(CleanupPhase::Reserved) && report_refs::register(slot, epoch) {
                if slot.epoch.load(Ordering::Acquire) == epoch && slot.is(CleanupPhase::Reserved) {
                    slot.request_retirement();
                    if slot.report_references.load(Ordering::Acquire) == 1 {
                        slot.export_abandoned.store(true, Ordering::Release);
                    }
                }
                report_refs::release(slot, epoch, false);
            }
            let _attempt = retry_slot(slot, Some(epoch));
            if slot.is(CleanupPhase::TerminalReady)
                && slot.report_references.load(Ordering::Acquire) == 0
                && report_refs::register(slot, epoch)
            {
                let key = ServiceMainPreclaim {
                    queue: Arc::downgrade(self),
                    index,
                    epoch,
                };
                match terminal::take_terminal_body(&key) {
                    Ok(body) => drop(body),
                    Err(_) => report_refs::release(slot, epoch, false),
                }
            }
            refused |= !slot.is(CleanupPhase::Free);
        }
        if refused {
            Err(refusal("lifecycle cleanup remains owned or pending"))
        } else {
            Ok(())
        }
    }

    /// Refuses retirement without borrowing any publication-owned cell.
    pub(crate) fn verify_empty(&self) -> Result<(), LifecycleApiError> {
        if self.slots.iter().all(|slot| slot.is(CleanupPhase::Free)) {
            Ok(())
        } else {
            Err(refusal("cleanup ownership has not physically returned"))
        }
    }
}

fn refusal(message: &'static str) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: String::from(message),
    }
}

/// Uses the actual configured constructor geometry charged before Main birth.
fn prepared_constructor_control_bytes() -> Result<u64, LifecycleApiError> {
    type SourceFactory = crate::ComposedQemuAttemptResourceGuardFactory<
        crate::SharedQemuAttemptHostResourceFactory<crate::LinuxQemuAttemptHostResourceFactory>,
    >;
    let source =
        crate::qemu_lifecycle_launcher::PendingSourceConstruction::<SourceFactory>::control_bytes(
        )?;
    let target =
        crate::qemu_hot_fork_world_factory::target_construction::PendingTargetConstruction::<
            SourceFactory,
        >::control_bytes()?;
    Ok(source.max(target))
}
