//! Same-original physical-worker capacity and continuously borrowed closure.
//!
//! Only an entered, model-paid State recovery or lifecycle Domain stage lends
//! this financial owner. Each actual flight consumes a noncopy full-vector
//! operation before request construction or native worker acquisition. Positive
//! native posts precede the upper owner's real transient disposal; completion
//! then performs no IO or accounting decision. Resident debt is never refunded.

use super::*;
use crate::controller_resource_reservation::component_receiving::{
    complete_bound_delta_v1, ComponentReceivingOwnedOperationV1,
};
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, RetainedCgroupAnchor,
    CgroupPopulationObservationV1, CgroupPopulationObservationRefusalV1,
    ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1,
    WorkerCgroupOpeningV1, WorkerCgroupOpeningRefusalV1,
    PidsLimitReadbackV1, PidsLimitReadbackRefusalV1,
    MemoryLimitReadbackV1, MemoryLimitReadbackRefusalV1,
};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketSocket, ReceivedRecord, RecordBindingError};
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;

// The existing fixed worker recipe and inherited hard limit bound each
// independent table by128. This is a conservative cost recipe, never a native
// hard-limit proof: actual unit/recipient/child provenance remains mandatory.
// The two tables already present in each callee's complete demand remain paid.
const WORKER_FILES_PER_TABLE_V1: u64 = 128;
const EXISTING_WORKER_TABLES_V1: u64 = 2;

// A new positively separated worker flight may reuse paid resident capacity,
// but every entered flight spends its complete traffic again. Capacity remains
// full22 DATA for the same consumed operation preflight; it is never a refund.
fn worker_complete_demand_growth_v2(previous: ResourceVector, demand: ResourceVector)
    -> Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>
{
    let (capacity, delta) = complete_bound_delta_v1(previous, demand)?;
    let reusable = aos_sandbox_core::component_receiving::without_operation_traffic_v1(delta);
    let traffic = aos_sandbox_core::component_receiving::operation_traffic_demand_v1(demand);
    Ok((capacity, reusable.checked_add(traffic)?))
}

fn additional_descendant_files_v1(tasks: u64) -> Result<u64, StorageReceivingClosedV1> {
    tasks.checked_sub(EXISTING_WORKER_TABLES_V1)
        .and_then(|additional| additional.checked_mul(WORKER_FILES_PER_TABLE_V1))
        .ok_or(StorageReceivingClosedV1)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WorkerKind {
    Candidate,
    Capture,
    Zfs,
    Pin,
    GuestRootPublication31,
    GuestRootStartupHealth,
}

impl WorkerKind {
    fn is_guest_root_v2(self) -> bool {
        matches!(self, Self::GuestRootPublication31 | Self::GuestRootStartupHealth)
    }
}

#[derive(Clone, Copy)]
enum WorkerFailure {
    CaptureStop,
    CaptureCurrent,
    CaptureQuiescence,
    CaptureFinalClock,
    CaptureDrain,
    CaptureRepresentation,
    TaskRecipe,
    DescendantFiles,
    TaskCapture,
    TaskPost,
    MemoryCapture,
    MemoryPost,
    LimitBinding,
    Delivery,
    Growth,
    Reservation,
    Operation,
    Shape,
    SocketBinding,
    Before,
    PostPreparation,
    Alive,
    Membership,
    Population,
    PopulationOwner,
    Aggregate,
    AggregateIdentity,
    BindingPost,
    After,
    Closed,
}

pub(super) struct PhysicalWorkerReceivingV1 {
    capture_stop: capture_stop::CaptureStopNativeOriginalV4,
    capture_final_clock: capture::CaptureFinalClockV3,
    capture_final_pair: Option<Result<aos_sandbox_core::RawPairedClockSample, capture::CaptureFinalClockErrorV3>>,
    capture_final_comparison: Option<Result<(), aos_sandbox_broker::BrokerAdmissionError>>,
    capture_quiescence_entered: bool,
    capture_quiescence_alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    capture_quiescence_population: CgroupPopulationObservationV1,
    capture_quiescence_population_result: Option<Result<(), CgroupPopulationObservationRefusalV1>>,
    capture_quiescence_result: Option<Result<(), StorageReceivingClosedV1>>,
    capture_ready: Option<std::sync::Arc<ReceivedRecord>>,
    capture_resident: bool,
    capture_source: Option<(aos_sandbox_core::ObjectDigest, u64)>,
    capture_representation_bound: ResourceVector,
    capture_representation_highwater: ResourceVector,
    capture_representation_growth: Option<Result<(ResourceVector, ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    capture_representation_payment: Option<Result<(), aos_sandbox_core::AccountingError>>,
    capture_append_demand: Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,

    capture_recheck: Option<NativeResult>,
    capture_drain_remaining: Option<Result<ResourceVector, aos_sandbox_core::AccountingError>>,
    capture_drain_reservation: Option<Result<(), aos_sandbox_core::AccountingError>>,
    capture_drain_ceiling: Option<u64>,
    capacity: ResourceVector,
    task_recipe: Option<Result<u64, StorageReceivingClosedV1>>,
    descendant_files: Option<Result<u64, StorageReceivingClosedV1>>,
    tasks: PidsLimitReadbackV1,
    task_capture: Option<Result<(), PidsLimitReadbackRefusalV1>>,
    task_post: Option<Result<(), PidsLimitReadbackRefusalV1>>,
    memory: MemoryLimitReadbackV1,
    memory_capture: Option<Result<(), MemoryLimitReadbackRefusalV1>>,
    memory_post: Option<Result<(), MemoryLimitReadbackRefusalV1>>,
    limit_binding: Option<Result<(), StorageReceivingClosedV1>>,
    delivery: Option<Result<ResourceVector, aos_sandbox_core::AccountingError>>,
    growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    reservation: Option<Result<(), aos_sandbox_core::AccountingError>>,
    operation: Option<ComponentReceivingOwnedOperationV1>,
    required: ResourceVector,
    kind: Option<WorkerKind>,
    before: Option<NativeResult>,
    owed_post: StorageObserverOperationOriginalV1,
    post_preparation: Option<Result<(), StorageReceivingClosedV1>>,
    post_result: Option<Result<(), StorageReceivingClosedV1>>,
    binding_post: Option<NativeResult>,
    after: Option<NativeResult>,
    shape: Option<Result<ResourceVector, aos_sandbox_core::AccountingError>>,
    socket_binding: Option<Result<(), RecordBindingError>>,
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    membership: Option<ExactCgroupMembershipReadbackV1>,
    membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    population: Option<Result<CgroupPopulationState, aos_sandbox_linux::Error>>,
    population_owner: Option<Result<(), aos_sandbox_linux::Error>>,
    binding_population: CgroupPopulationObservationV1,
    binding_population_result: Option<Result<(), CgroupPopulationObservationRefusalV1>>,
    final_population: CgroupPopulationObservationV1,
    final_population_result: Option<Result<(), CgroupPopulationObservationRefusalV1>>,
    aggregate_worker: WorkerCgroupOpeningV1,
    aggregate_resolution: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    aggregate_identity: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<WorkerFailure>,
    bound: bool,
    disposal_entered: bool,
}

impl PhysicalWorkerReceivingV1 {
    pub(super) fn new() -> Self {
        Self {
            capture_stop: capture_stop::CaptureStopNativeOriginalV4::new(),
            capture_final_clock: capture::CaptureFinalClockV3::default(),
            capture_final_pair: None, capture_final_comparison: None,
            capture_quiescence_entered: false, capture_quiescence_alive: None,
            capture_quiescence_population: CgroupPopulationObservationV1::new(),
            capture_quiescence_population_result: None, capture_quiescence_result: None,
            capture_ready: None,
            capture_resident: false,
            capture_source: None,
            capture_representation_bound: ResourceVector::ZERO,
            capture_representation_highwater: ResourceVector::ZERO,
            capture_representation_growth: None,
            capture_representation_payment: None,
            capture_append_demand: None,
            capture_recheck: None,
            capture_drain_remaining: None,
            capture_drain_reservation: None,
            capture_drain_ceiling: None,
            capacity: ResourceVector::ZERO,
            task_recipe: None,
            descendant_files: None,
            tasks: PidsLimitReadbackV1::new(),
            task_capture: None,
            task_post: None,
            memory: MemoryLimitReadbackV1::new(),
            memory_capture: None,
            memory_post: None,
            limit_binding: None,
            delivery: None,
            growth: None,
            reservation: None,
            operation: None,
            required: ResourceVector::ZERO,
            kind: None,
            before: None,
            owed_post: StorageObserverOperationOriginalV1::new(),
            post_preparation: None,
            post_result: None,
            binding_post: None,
            after: None,
            shape: None,
            socket_binding: None,
            alive: None,
            membership: None,
            membership_result: None,
            population: None,
            population_owner: None,
            binding_population: CgroupPopulationObservationV1::new(),
            binding_population_result: None,
            final_population: CgroupPopulationObservationV1::new(),
            final_population_result: None,
            aggregate_worker: WorkerCgroupOpeningV1::new(),
            aggregate_resolution: None,
            aggregate_identity: None,
            first: None,
            bound: false,
            disposal_entered: false,
        }
    }

    pub(super) fn is_between_flights_v2(&self) -> bool {
        self.first.is_none() && self.operation.is_none() && self.kind.is_none()
            && !self.capture_resident && self.capture_ready.is_none()
    }

    pub(super) fn before_first_flight_v1(&self) -> bool {
        self.first.is_none() && self.operation.is_none() && self.kind.is_none()
            && self.capacity == ResourceVector::ZERO
    }

    // The sole caller first checks before_first_flight_v1 under an exclusive
    // same-original borrow, then reserves this exact scan demand on its ledger.
    // No entry or concurrent mutation occurs between that check and this move.
    pub(super) fn retain_initial_file_peak_v1(&mut self, admitted: ResourceVector) {
        self.capacity = ResourceVector::ZERO.with(D::OpenFiles, admitted.get(D::OpenFiles));
    }

    fn begin(&mut self, ledger: &mut ComponentServiceReceivingLedgerV1,
        kind: WorkerKind, demand: ResourceVector, original_f: ResourceVector) -> Result<(), StorageReceivingClosedV1>
    {
        if self.first.is_some() || self.operation.is_some() || self.kind.is_some() {
            self.first.get_or_insert(WorkerFailure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.kind = Some(kind);
        // The genuine original, not caller DATA, derives the selected unit's
        // tightened task ceiling. Main and its joined observer remain paid.
        self.task_recipe = Some(original_f.get(D::Pids)
            .checked_sub(RESIDENT_PROCESS_SLOTS_V1)
            .map(|remaining| remaining.min(16))
            .filter(|remaining| *remaining >= 2)
            .ok_or(StorageReceivingClosedV1));
        let Some(tasks) = self.task_recipe.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.first.get_or_insert(WorkerFailure::TaskRecipe);
            return Err(StorageReceivingClosedV1);
        };
        if demand.get(D::Pids) != 0 {
            self.first.get_or_insert(WorkerFailure::TaskRecipe);
            return Err(StorageReceivingClosedV1);
        }
        // cgroup.pids counts tasks, not shared descriptor tables. In the
        // absence of a tighter connected per-verb proof, every permitted task
        // can own its own inherited table. The two existing128 terms cover
        // only the worker and one child; keep all remaining tables explicit.
        self.descendant_files = Some(additional_descendant_files_v1(tasks));
        let Some(descendant_files) = self.descendant_files.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.first.get_or_insert(WorkerFailure::DescendantFiles);
            return Err(StorageReceivingClosedV1);
        };
        let demand = demand.with(D::Pids, tasks);
        // This additional actual launch descriptor debt is mandatory, not a
        // caller-supplied amount. The complete worker/model/child supplier is
        // separate and must still include its genuine NOFILE/task/traffic peak.
        let limit_memory = PidsLimitReadbackV1::dominant_requested_bytes_v1()
            .and_then(|pids| MemoryLimitReadbackV1::dominant_requested_bytes_v1()
                .and_then(|memory| pids.checked_add(memory)))
            .and_then(|bytes| CgroupPopulationObservationV1::requested_bytes_v1()
                .and_then(|population| population.checked_mul(2))
                .and_then(|population| bytes.checked_add(population)))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<
                Option<Result<u64, StorageReceivingClosedV1>>,
            >()))
            .and_then(|bytes| aos_sandbox_linux::process::StorageWorkerInheritedLimitOriginalV1::requested_bytes_v1()
                .and_then(|recipe| bytes.checked_add(recipe)))
            .and_then(|bytes| if kind == WorkerKind::Capture {
                bytes.checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?
                    .checked_add(capture::CaptureFinalClockV3::dominant_requested_bytes_v1()?)
            } else { Some(bytes) })
            .and_then(|bytes| bytes.checked_add(256))
            .and_then(|bytes| u64::try_from(bytes).ok());
        let Some(limit_memory) = limit_memory else {
            self.first.get_or_insert(WorkerFailure::TaskRecipe);
            return Err(StorageReceivingClosedV1);
        };
        let delivery = ResourceVector::ZERO
            .with(D::MemoryBytes, limit_memory)
            .with(D::OpenFiles,
                aos_sandbox_linux::cgroup::StorageWorkerAggregateReadbackV1::maximum_fork_descriptor_slots_v1()
                    + PidsLimitReadbackV1::MAXIMUM_RETAINED_FILES_V1 as u64
                    + MemoryLimitReadbackV1::MAXIMUM_RETAINED_FILES_V1 as u64
                    + descendant_files
                    + if kind == WorkerKind::Capture {
                        capture::CaptureFinalClockV3::MAXIMUM_RETAINED_FILES_V1 as u64
                    } else { 0 });
        // A primary failure may retain its native control-name probes and
        // unjoined observer. This independently owed sample needs its own
        // main+aggregate before/after control peak and one observer task.
        let local = ReceivingContainmentCurrentnessV1::fixed_demand();
        self.delivery = Some(demand.checked_add(delivery)
            .and_then(|demand| {
                // The actual fixed publisher owns1GiB and two inherited128-
                // file tables. This intrinsic obligation is not caller DATA.
                if kind.is_guest_root_v2() {
                    demand.checked_add(ResourceVector::ZERO
                        .with(D::MemoryBytes, 1024 * 1024 * 1024)
                        .with(D::OpenFiles, 2 * WORKER_FILES_PER_TABLE_V1))
                } else { Ok(demand) }
            })
            .and_then(|demand| local.checked_add(local)
                .and_then(|peak| peak.checked_add(local))
                .and_then(|peak| peak.checked_add(local))
                .and_then(|peak| demand.checked_add(peak.with(D::Pids, 1)))));
        let Some(Ok(demand)) = self.delivery.as_ref().copied() else {
            self.first.get_or_insert(WorkerFailure::Delivery);
            return Err(StorageReceivingClosedV1);
        };
        self.required = demand;
        self.growth = Some(worker_complete_demand_growth_v2(self.capacity, demand));
        let Some(Ok((capacity, delta))) = self.growth.as_ref().copied() else {
            self.first.get_or_insert(WorkerFailure::Growth);
            return Err(StorageReceivingClosedV1);
        };
        self.reservation = Some(ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(self.reservation, Some(Ok(()))) {
            self.first.get_or_insert(WorkerFailure::Reservation);
            return Err(StorageReceivingClosedV1);
        }
        self.capacity = capacity;
        self.operation = Some(ComponentReceivingOwnedOperationV1::preflight(capacity, demand));
        let Some(operation) = self.operation.as_mut() else { std::process::abort() };
        if operation.consume_once().is_err() {
            self.first.get_or_insert(WorkerFailure::Operation);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    fn current(&self) -> bool {
        self.first.is_none() && self.kind.is_some() && !self.disposal_entered
            && self.operation.as_ref().is_some_and(ComponentReceivingOwnedOperationV1::is_consumed_current)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
        }
        match self.first? {
            WorkerFailure::CaptureStop => self.capture_stop.failure(),
            WorkerFailure::CaptureRepresentation => error(&self.capture_representation_growth)
                .or_else(|| error(&self.capture_representation_payment))
                .or_else(|| error(&self.capture_append_demand)),
            WorkerFailure::CaptureFinalClock => self.capture_final_clock.failure()
                .or_else(|| error(&self.capture_final_pair))
                .or_else(|| error(&self.capture_final_comparison)),
            WorkerFailure::CaptureQuiescence => error(&self.capture_quiescence_alive)
                .or_else(|| self.capture_quiescence_population.failure())
                .or_else(|| error(&self.capture_quiescence_population_result))
                .or_else(|| error(&self.capture_quiescence_result)),
            WorkerFailure::CaptureCurrent => error(&self.capture_recheck),
            WorkerFailure::CaptureDrain => error(&self.capture_drain_remaining)
                .or_else(|| error(&self.capture_drain_reservation))
                .or(Some(&StorageReceivingClosedV1)),
            WorkerFailure::TaskRecipe => error(&self.task_recipe).or(Some(&StorageReceivingClosedV1)),
            WorkerFailure::DescendantFiles => error(&self.descendant_files)
                .or(Some(&StorageReceivingClosedV1)),
            WorkerFailure::TaskCapture | WorkerFailure::TaskPost => self.tasks.failure().map(|cause| cause as _),
            WorkerFailure::MemoryCapture | WorkerFailure::MemoryPost => self.memory.failure().map(|cause| cause as _),
            WorkerFailure::LimitBinding => error(&self.limit_binding),
            WorkerFailure::Delivery => error(&self.delivery),
            WorkerFailure::Growth => error(&self.growth),
            WorkerFailure::Reservation => error(&self.reservation),
            WorkerFailure::Operation => self.operation.as_ref().and_then(ComponentReceivingOwnedOperationV1::failure).map(|cause| cause as _),
            WorkerFailure::Shape => error(&self.shape),
            WorkerFailure::SocketBinding => error(&self.socket_binding),
            WorkerFailure::Before => error(&self.before),
            WorkerFailure::PostPreparation => self.owed_post.failure()
                .or_else(|| error(&self.post_preparation)),
            WorkerFailure::Alive => error(&self.alive),
            WorkerFailure::Membership => self.membership.as_ref()
                .and_then(ExactCgroupMembershipReadbackV1::failure).map(|cause| cause as _)
                .or_else(|| error(&self.membership_result)),
            WorkerFailure::Population => {
                let raw = if self.disposal_entered { self.final_population.failure() }
                    else { self.binding_population.failure() };
                raw.or_else(|| error(&self.population))
            },
            WorkerFailure::PopulationOwner => error(&self.population_owner),
            WorkerFailure::Aggregate => self.aggregate_worker.failure()
                .or_else(|| error(&self.aggregate_resolution)),
            WorkerFailure::AggregateIdentity => error(&self.aggregate_identity),
            WorkerFailure::BindingPost => error(&self.binding_post),
            WorkerFailure::After => self.owed_post.failure().or_else(|| error(&self.after)),
            WorkerFailure::Closed => Some(&StorageReceivingClosedV1 as &(dyn Error + 'static)),
        }.or(Some(&StorageReceivingClosedV1))
    }
}

/// Borrows one genuinely paid physical-worker flight before upper growth.
#[must_use]
pub struct StoragePhysicalWorkerLoanV1<'flight, 'original> {
    receiving: &'flight mut StoragePrepareReceivingLoanV1<'original>,
    completed: bool,
}

// Both references are the actual original transport lent at READY. No copied
// socket cookie, pid number or decoded worker row can construct this enum.
enum WorkerSocketV1<'worker> {
    Zfs(&'worker mut SeqpacketSocket),
    Pin(&'worker mut DescriptorSubjectSocket),
}

/// Keeps the actual socket and worker originals borrowed through exchange/end.
#[must_use]
pub struct StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original> {
    flight: StoragePhysicalWorkerLoanV1<'flight, 'original>,
    socket: WorkerSocketV1<'worker>,
    subject: &'worker KernelAuthorizedRecordSubject,
    cgroup: &'worker RetainedCgroupAnchor,
    population: &'worker CgroupPopulationMonitor,
}

mod capture_stop;
pub use capture_stop::StorageCaptureStopQuiescenceV4;
mod capture;
pub use capture::{StorageResidentCaptureWorkerV2, StorageCaptureWorkerBorrowV2,
    StorageCaptureWorkerDisposalV2};

/// Keeps the payer exclusively borrowed until actual positive upper disposal.
#[must_use]
pub struct StoragePhysicalWorkerDisposalV1<'flight, 'original> {
    flight: StoragePhysicalWorkerLoanV1<'flight, 'original>,
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Borrows one catalog worker flight for the actual paid Inventory turn.
    ///
    /// The same State writer was captured during paid startup replay. This
    /// entry requires the real Inventory retention debit and closes before
    /// either outcome or a Prepare catalog turn begins. The callee derives
    /// `demand` from its actual catalog protocol; DATA creates no new original.
    ///
    /// # Errors
    ///
    /// Refuses another State writer, incomplete startup, absent Inventory
    /// payment, entered outcome/Prepare work, previous failure or a complete
    /// physical footprint that exceeds this same original's installed ceiling.
    pub fn borrow_inventory_catalog_worker_flight_v1<'flight>(
        &'flight mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.prepare_wire
            || !receiving.catalog_observer_peak_paid
            || !receiving.inventory_paid
            || receiving.inventory_outcome.is_entered()
            || receiving.prepare_outcome.is_entered()
            || receiving.catalog_paid
            || !receiving.startup.state_recovery_ready_v1(journal)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }

        // The existing engine owns the full22 consumed flight, actual before
        // observation and independently prepaid owed post. It does not borrow
        // the old resident-only catalog observer peak as traffic currency.
        self.begin_physical_worker_v1(WorkerKind::Pin, demand)
    }

    // Sole callers are inherent methods on the real model-paid State/Domain
    // guards. Keeping this private prevents ordinary startup loans from using
    // a numeric demand as a physical effect-entry capability.
    fn begin_physical_worker_v1<'flight>(&'flight mut self, kind: WorkerKind,
        demand: ResourceVector) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1>
    {
        // Ordinary State/Session/Inventory entry retains its same fresh gate.
        self.receiving()?;
        self.begin_physical_worker_prechecked_v2(kind, demand)
    }

    // Only the ordinary fresh gate above and the closed actual RootExport
    // borrower below reach this shared native/owed-post body. Neither caller
    // permits fresh work after original health or its own purpose has closed.
    fn begin_physical_worker_prechecked_v2<'flight>(&'flight mut self, kind: WorkerKind,
        demand: ResourceVector) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1>
    {
        if !self.original.open { return Err(StorageReceivingClosedV1); }
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else { return Err(StorageReceivingClosedV1); };
        receiving.require_initial()?;
        if receiving.initial_pin_entered
            && (!matches!(receiving.initial_pin_payment, Some(Ok(())))
                || !receiving.initial_pin_quiescence.as_ref()
                    .is_some_and(InitialPinQuiescenceOriginalV1::files_disposed_positive_v1))
        {
            // An unfinished/forgotten/negative scan still owns its native peak.
            // Only its actual same-owner positive disposition permits this
            // sequential reuse; a successful reserve or status is insufficient.
            receiving.first.get_or_insert(Failure::InitialPinQuiescence);
            return Err(StorageReceivingClosedV1);
        }
        if receiving.physical_worker.begin(&mut receiving.ledger, kind, demand, receiving.ceiling).is_err() {
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        // Arm an exclusive paid post before the primary interval can poison
        // ordinary admission. The enclosing State stage may already hold its
        // own pending post, so it cannot lend this independent destination.
        let preparation = receiving.physical_worker.owed_post.prepare_once_v1(
            &mut receiving.ledger, &receiving.lifetime,
        );
        let prepared = preparation.is_ok();
        receiving.physical_worker.post_preparation = Some(preparation);
        if !prepared {
            receiving.physical_worker.first.get_or_insert(WorkerFailure::PostPreparation);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        let before = self.original.recheck();
        let positive = before.is_ok();
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut() else { std::process::abort() };
        receiving.physical_worker.before = Some(before);
        if !positive {
            receiving.physical_worker.first.get_or_insert(WorkerFailure::Before);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            let _ = StoragePhysicalWorkerLoanV1 { receiving: self, completed: false }
                .finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        Ok(StoragePhysicalWorkerLoanV1 { receiving: self, completed: false })
    }
}

impl<'flight, 'original> StoragePhysicalWorkerLoanV1<'flight, 'original> {
    fn state(&mut self) -> &mut PhysicalWorkerReceivingV1 {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.receiving.original.recipient.as_mut() else { std::process::abort() };
        &mut receiving.physical_worker
    }

    /// Checks the actual private executor recipe before encoding or native work.
    ///
    /// # Errors
    /// Refuses an incomplete flight or a real reached footprint exceeding its
    /// already consumed all-dimension permit; actual arithmetic stays owned.
    pub fn require_shape_v1(&mut self, actual: ResourceVector) -> Result<(), StorageReceivingClosedV1> {
        let original = self.state();
        if !original.current() {
            return Err(StorageReceivingClosedV1);
        }
        original.shape = Some(original.required.checked_sub(actual));
        if !matches!(original.shape, Some(Ok(_))) {
            original.first.get_or_insert(WorkerFailure::Shape);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    fn bind<'worker>(mut self, socket: WorkerSocketV1<'worker>,
        subject: &'worker KernelAuthorizedRecordSubject, cgroup: &'worker RetainedCgroupAnchor,
        population: &'worker CgroupPopulationMonitor, kind: WorkerKind, worker_path: &str,
    ) -> Result<StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        let original = self.state();
        if !original.current() || original.bound || original.kind != Some(kind)
            || !matches!(original.shape, Some(Ok(_)))
        {
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        original.bound = true;
        let name = worker_path.strip_prefix(aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::ReceivingAggregate
            .worker_parent_relative_v1()).and_then(|name| name.strip_prefix('/'));
        let name = name.filter(|name| {
            let allowed = match kind {
                WorkerKind::Candidate | WorkerKind::Capture | WorkerKind::Zfs => name.strip_prefix("aos-sandbox-zfs-worker@"),
                WorkerKind::GuestRootPublication31 | WorkerKind::GuestRootStartupHealth => name.strip_prefix("aos-sandbox-guest-root-publisher@"),
                WorkerKind::Pin => name.strip_prefix("aos-sandbox-workspace-pin-worker@")
                    .or_else(|| name.strip_prefix("aos-sandbox-workspace-pin-observer@"))
                    .or_else(|| name.strip_prefix("aos-sandbox-workspace-root-initializer@")),
            };
            allowed.and_then(|suffix| suffix.strip_suffix(".service"))
                .is_some_and(|instance| !instance.is_empty() && instance.len() <= 255 && !instance.contains('/'))
        });
        if let Some(name) = name {
            let aggregate = self.receiving.original.custody.aggregate.anchor();
            if let Ok(aggregate) = aggregate {
                let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                    self.receiving.original.recipient.as_mut() else { std::process::abort() };
                let original = &mut receiving.physical_worker;
                original.aggregate_resolution = Some(original.aggregate_worker.capture_descendant_once(
                    aggregate, std::path::Path::new(name),
                ));
                original.aggregate_identity = Some(match original.aggregate_worker.anchor() {
                    Some(candidate) if candidate.kernel_id() == cgroup.kernel_id() => Ok(()),
                    _ => Err(StorageReceivingClosedV1),
                });
                if !matches!(original.aggregate_resolution, Some(Ok(()))) {
                    original.first.get_or_insert(WorkerFailure::Aggregate);
                } else if !matches!(original.aggregate_identity, Some(Ok(()))) {
                    original.first.get_or_insert(WorkerFailure::AggregateIdentity);
                }
            } else {
                self.state().aggregate_identity = Some(Err(StorageReceivingClosedV1));
                self.state().first.get_or_insert(WorkerFailure::AggregateIdentity);
            }
        } else {
            self.state().aggregate_identity = Some(Err(StorageReceivingClosedV1));
            self.state().first.get_or_insert(WorkerFailure::AggregateIdentity);
        }
        let original = self.state();
        // Both entered native limits owe their independent bookends even if
        // the other limit or an earlier membership join already refused.
        original.task_capture = Some(original.tasks.capture_once(cgroup));
        original.memory_capture = Some(original.memory.capture_once(cgroup));
        original.task_post = Some(original.tasks.recheck_once(cgroup));
        original.memory_post = Some(original.memory.recheck_once(cgroup));
        let Some(tasks) = original.task_recipe.as_ref().and_then(|result| result.as_ref().ok()).copied() else { std::process::abort() };
        original.limit_binding = Some((|| {
            use aos_sandbox_broker::receiving::receiving_limits::require_finite_limit_bytes_v1 as require_limit_bytes;
            require_limit_bytes(original.tasks.initial_bytes(), tasks).map_err(|_| StorageReceivingClosedV1)?;
            require_limit_bytes(original.tasks.final_bytes(), tasks).map_err(|_| StorageReceivingClosedV1)?;
            // Each closed purpose retains its actual installed service limit.
            // Guest-root population keeps the existing1GiB implementation.
            let memory = if kind.is_guest_root_v2() {
                1024 * 1024 * 1024
            } else { 128 * 1024 * 1024 };
            require_limit_bytes(original.memory.initial_bytes(), memory).map_err(|_| StorageReceivingClosedV1)?;
            require_limit_bytes(original.memory.final_bytes(), memory).map_err(|_| StorageReceivingClosedV1)
        })());
        for (positive, failure) in [
            (matches!(original.task_capture, Some(Ok(()))), WorkerFailure::TaskCapture),
            (matches!(original.memory_capture, Some(Ok(()))), WorkerFailure::MemoryCapture),
            (matches!(original.task_post, Some(Ok(()))), WorkerFailure::TaskPost),
            (matches!(original.memory_post, Some(Ok(()))), WorkerFailure::MemoryPost),
            (matches!(original.limit_binding, Some(Ok(()))), WorkerFailure::LimitBinding),
        ] {
            if !positive { original.first.get_or_insert(failure); }
        }
        original.population_owner = Some(population.require_same_cgroup(cgroup));
        original.membership = Some(ExactCgroupMembershipReadbackV1::new());
        let Some(membership) = original.membership.as_mut() else { std::process::abort() };
        original.membership_result = Some(membership.capture_once(cgroup, subject.pidfd()));
        original.binding_population_result = Some(population.observe_state_retaining_v1(
            &mut original.binding_population,
        ));
        original.population = Some(original.binding_population.state().ok_or_else(|| {
            aos_sandbox_linux::Error::InvalidInput {
                field: "physical worker population", message: "native original retained".into(),
            }
        }));
        if !matches!(original.population_owner, Some(Ok(()))) {
            original.first.get_or_insert(WorkerFailure::PopulationOwner);
        } else if !matches!(original.membership_result, Some(Ok(()))) {
            original.first.get_or_insert(WorkerFailure::Membership);
        } else if !matches!(original.population, Some(Ok(CgroupPopulationState::Populated))) {
            original.first.get_or_insert(WorkerFailure::Population);
        }
        if original.first.is_some() {
            // Binding entered native work, so it owes the service post even
            // though no further worker IO may be lent after this refusal.
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        // Worker acquisition can wait for PID1/READY. Recheck the actual
        // original and aggregate controls after the native membership joins,
        // immediately before lending the channel for its first effect request.
        let binding_post = self.receiving.original.recheck();
        let positive = binding_post.is_ok();
        let original = self.state();
        original.binding_post = Some(binding_post);
        if !positive {
            original.first.get_or_insert(WorkerFailure::BindingPost);
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        Ok(StorageBoundPhysicalWorkerLoanV1 { flight: self, socket, subject, cgroup, population })
    }

    /// Binds the same actual generic ZFS socket and authenticated READY owner.
    ///
    /// # Errors
    /// Refuses foreign READY/socket provenance, wrong purpose, repeated or unpaid
    /// entry, dead subjects, or nonmember originals.
    pub fn bind_zfs_once_v1<'worker>(mut self, socket: &'worker mut SeqpacketSocket,
        ready: &'worker ReceivedRecord, cgroup: &'worker RetainedCgroupAnchor,
        population: &'worker CgroupPopulationMonitor,
        worker_path: &str,
    ) -> Result<StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        self.state().socket_binding = Some(socket.compare_worker_received_original_v1(ready));
        if !matches!(self.state().socket_binding, Some(Ok(()))) {
            self.state().first.get_or_insert(WorkerFailure::SocketBinding);
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        let kind = match self.state().kind {
            Some(WorkerKind::Zfs) => WorkerKind::Zfs,
            Some(WorkerKind::Candidate) => WorkerKind::Candidate,
            _ => { let _ = self.finish_failed_interval_v1(); return Err(StorageReceivingClosedV1); }
        };
        self.bind(WorkerSocketV1::Zfs(socket), ready.subject(), cgroup, population, kind, worker_path)
    }

    /// Binds the same actual descriptor-channel pin socket and READY owner.
    ///
    /// # Errors
    /// Refuses foreign READY/socket provenance, wrong purpose, repeated or unpaid
    /// entry, dead subjects, or nonmember originals.
    pub fn bind_pin_once_v1<'worker>(mut self, socket: &'worker mut DescriptorSubjectSocket,
        ready: &'worker ReceivedDescriptorRecord, cgroup: &'worker RetainedCgroupAnchor,
        population: &'worker CgroupPopulationMonitor,
        worker_path: &str,
    ) -> Result<StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        self.state().socket_binding = Some(socket.validate_received_origin_retaining(ready));
        if !matches!(self.state().socket_binding, Some(Ok(()))) {
            self.state().first.get_or_insert(WorkerFailure::SocketBinding);
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        self.bind(WorkerSocketV1::Pin(socket), ready.subject(), cgroup, population, WorkerKind::Pin, worker_path)
    }

    /// Binds only the fixed method31 publisher through the descriptor engine.
    ///
    /// # Errors
    /// Refuses a foreign channel/READY original, unpaid purpose or changed
    /// cgroup, limits, native membership or same-F association.
    pub fn bind_guest_root_publication_once_v2<'worker>(self,
        socket: &'worker mut DescriptorSubjectSocket, ready: &'worker ReceivedDescriptorRecord,
        cgroup: &'worker RetainedCgroupAnchor, population: &'worker CgroupPopulationMonitor,
        worker_path: &str,
    ) -> Result<StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        self.bind_guest_root_descriptor_once_v2(socket, ready, cgroup, population,
            WorkerKind::GuestRootPublication31, worker_path)
    }

    /// Binds only the fixed observation-only startup health channel.
    ///
    /// # Errors
    /// Refuses another native flight, channel, fixed service or actual F.
    pub fn bind_guest_root_health_once_v2<'worker>(self,
        socket: &'worker mut DescriptorSubjectSocket, ready: &'worker ReceivedDescriptorRecord,
        cgroup: &'worker RetainedCgroupAnchor, population: &'worker CgroupPopulationMonitor,
        worker_path: &str,
    ) -> Result<StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        self.bind_guest_root_descriptor_once_v2(socket, ready, cgroup, population,
            WorkerKind::GuestRootStartupHealth, worker_path)
    }

    fn bind_guest_root_descriptor_once_v2<'worker>(mut self,
        socket: &'worker mut DescriptorSubjectSocket, ready: &'worker ReceivedDescriptorRecord,
        cgroup: &'worker RetainedCgroupAnchor, population: &'worker CgroupPopulationMonitor,
        kind: WorkerKind, worker_path: &str,
    ) -> Result<StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        self.state().socket_binding = Some(socket.validate_received_origin_retaining(ready));
        if !matches!(self.state().socket_binding, Some(Ok(()))) {
            self.state().first.get_or_insert(WorkerFailure::SocketBinding);
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        self.bind(WorkerSocketV1::Pin(socket), ready.subject(), cgroup, population, kind, worker_path)
    }

    fn observe_owed_post_v1(&mut self) -> NativeResult {
        let Some(StorageResourceRecipientCustodyV1::Receiving { component, receiving }) =
            self.receiving.original.recipient.as_mut()
        else {
            return Err(StorageWorkerOriginCauseV3::Closed);
        };
        let Some(initial) = receiving.before.as_ref().and_then(|result| result.as_ref().ok()) else {
            return Err(StorageWorkerOriginCauseV3::Binding);
        };
        // This consumes only the already armed operation. Do not consult or
        // restore the ordinary open/first/ledger-health admission latches.
        let result = receiving.physical_worker.owed_post.observe_prepared_once_v1(
            &receiving.lifetime, &self.receiving.original.custody, component,
            initial, &receiving.containment,
        );
        let positive = result.is_ok();
        receiving.physical_worker.post_result = Some(result);
        if positive { Ok(()) } else { Err(StorageWorkerOriginCauseV3::Binding) }
    }

    /// Runs the actual original service post after a failed worker interval.
    ///
    /// # Errors
    /// Retains the actual service failure. This lends no disposal/retry credit.
    pub fn finish_failed_interval_v1(mut self) -> Result<(), StorageReceivingClosedV1> {
        let result = self.observe_owed_post_v1();
        let positive = result.is_ok();
        let original = self.state();
        original.after = Some(result);
        original.first.get_or_insert(if positive { WorkerFailure::Closed } else { WorkerFailure::After });
        Err(StorageReceivingClosedV1)
    }
}

impl<'worker, 'flight, 'original> StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original> {
    /// Lends the same actual ZFS socket without exposing another endpoint.
    ///
    /// # Errors
    /// Refuses the distinct descriptor-channel purpose.
    pub fn zfs_socket_mut_v1(&mut self) -> Result<&mut SeqpacketSocket, StorageReceivingClosedV1> {
        match &mut self.socket { WorkerSocketV1::Zfs(socket) => Ok(socket), _ => Err(StorageReceivingClosedV1) }
    }

    /// Lends the exact method31 descriptor channel after its native binding.
    ///
    /// # Errors
    /// Refuses another closed physical worker purpose or channel kind.
    pub fn guest_root_publication_socket_mut_v2(&mut self)
        -> Result<&mut DescriptorSubjectSocket, StorageReceivingClosedV1> {
        self.guest_root_socket_mut_v2(WorkerKind::GuestRootPublication31)
    }

    /// Lends only the already-bound observation-only startup health channel.
    ///
    /// # Errors
    /// Refuses another closed native purpose or channel kind.
    pub fn guest_root_health_socket_mut_v2(&mut self)
        -> Result<&mut DescriptorSubjectSocket, StorageReceivingClosedV1> {
        self.guest_root_socket_mut_v2(WorkerKind::GuestRootStartupHealth)
    }

    fn guest_root_socket_mut_v2(&mut self, kind: WorkerKind)
        -> Result<&mut DescriptorSubjectSocket, StorageReceivingClosedV1> {
        if self.flight.state().kind != Some(kind) { return Err(StorageReceivingClosedV1); }
        match &mut self.socket { WorkerSocketV1::Pin(socket) => Ok(socket), _ => Err(StorageReceivingClosedV1) }
    }

    /// Lends the same actual descriptor-channel socket without replacing it.
    ///
    /// # Errors
    /// Refuses the distinct generic ZFS purpose.
    pub fn pin_socket_mut_v1(&mut self) -> Result<&mut DescriptorSubjectSocket, StorageReceivingClosedV1> {
        if self.flight.state().kind != Some(WorkerKind::Pin) { return Err(StorageReceivingClosedV1); }
        match &mut self.socket { WorkerSocketV1::Pin(socket) => Ok(socket), _ => Err(StorageReceivingClosedV1) }
    }

    /// Runs the independent service post after failure, preserving all debt.
    ///
    /// # Errors
    /// Always refuses positive disposal; actual post failures remain owned.
    pub fn finish_failed_interval_v1(self) -> Result<(), StorageReceivingClosedV1> {
        self.flight.finish_failed_interval_v1()
    }

    /// Proves exact worker death and held empty/retired population before disposal.
    ///
    /// The private upper caller must also hold a successful parsed response,
    /// actual ACK/cleanup results and every required domain/control post. These
    /// native checks execute while all those original carriers remain alive.
    ///
    /// # Errors
    /// Refuses live/uncertain worker, nonempty/uncertain held cgroup, original
    /// service failure, repeated disposal or earlier flight debt.
    pub fn prepare_positive_disposal_v1(mut self)
        -> Result<StoragePhysicalWorkerDisposalV1<'flight, 'original>, StorageReceivingClosedV1>
    {
        if self.flight.state().kind == Some(WorkerKind::Capture) {
            // A resident Capture interval has its own terminal/EOF disposition.
            return Err(StorageReceivingClosedV1);
        }
        self.flight.prepare_positive_disposal_inner_v2(self.subject, self.cgroup, self.population)
    }
}

impl<'flight, 'original> StoragePhysicalWorkerLoanV1<'flight, 'original> {
    fn prepare_positive_disposal_inner_v2(self,
        subject: &KernelAuthorizedRecordSubject,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
    ) -> Result<StoragePhysicalWorkerDisposalV1<'flight, 'original>, StorageReceivingClosedV1> {
        self.prepare_positive_disposal_native_v3(subject, cgroup, population, None)
    }

    // Capture supplies its actual verified immutable lifetime. Ordinary workers
    // preserve their original None route through these same native bookends.
    fn prepare_positive_disposal_native_v3(mut self,
        subject: &KernelAuthorizedRecordSubject,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
        capture: Option<&aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3>,
    ) -> Result<StoragePhysicalWorkerDisposalV1<'flight, 'original>, StorageReceivingClosedV1> {
        let original = self.state();
        if !original.current() || !original.bound { return Err(StorageReceivingClosedV1); }
        original.disposal_entered = true;
        // These are independent post observations on the SAME borrowed objects.
        // Do not try exact membership after death: the retained pidfd then no
        // longer names a live member, while its lifetime and events OFD persist.
        original.alive = Some(subject.pidfd().is_alive());
        original.final_population_result = Some(population.observe_state_retaining_v1(
            &mut original.final_population,
        ));
        original.population = Some(original.final_population.state().ok_or_else(|| {
            aos_sandbox_linux::Error::InvalidInput {
                field: "physical worker population", message: "native original retained".into(),
            }
        }));
        let alive_ok = matches!(original.alive, Some(Ok(false)));
        let population_ok = matches!(original.population,
            Some(Ok(CgroupPopulationState::Empty | CgroupPopulationState::Retired)));
        if !alive_ok {
            original.first.get_or_insert(WorkerFailure::Alive);
        }
        if !population_ok {
            original.first.get_or_insert(WorkerFailure::Population);
        }
        let post = self.observe_owed_post_v1();
        let post_ok = post.is_ok();
        let original = self.state();
        original.after = Some(post);
        if !post_ok {
            original.first.get_or_insert(WorkerFailure::After);
        }
        if let Some(verified) = capture {
            // This sample is independently owed after the final native post.
            // Keep earlier death/population/post causes selected if it fails.
            original.capture_final_pair = Some(original.capture_final_clock.observe_once(None));
            original.capture_final_comparison = Some(match original.capture_final_pair.as_ref() {
                Some(Ok(pair)) => verified.require_ongoing_clock_v3(pair),
                _ => Err(aos_sandbox_broker::BrokerAdmissionError::FenceRejected),
            });
            if original.capture_source != Some((verified.source_v3().source_digest_v2(), verified.ongoing_deadline_v3()))
                || !matches!(original.capture_final_comparison, Some(Ok(())))
            {
                original.first.get_or_insert(WorkerFailure::CaptureFinalClock);
            }
        }
        if !alive_ok || !population_ok || !post_ok || original.first.is_some() {
            return Err(StorageReceivingClosedV1);
        }
        // The monitor was privately joined to this held anchor before any
        // exchange; both remain continuously borrowed to this final boundary.
        let _same_held_anchor = cgroup;
        Ok(StoragePhysicalWorkerDisposalV1 { flight: self })
    }
}

impl StoragePhysicalWorkerDisposalV1<'_, '_> {
    /// Completes only after actual positive upper transient disposal.
    pub fn complete_after_disposal_v1(mut self) {
        let original = self.flight.state();
        if !original.disposal_entered || original.first.is_some()
            || original.capture_resident || original.capture_ready.is_some()
        {
            std::process::abort();
        }
        let Some(operation) = original.operation.take() else { std::process::abort() };
        operation.complete_after_disposal();
        // These are only successful observation/control results. Failed and
        // ambiguous owners cannot construct this token or reach this branch.
        original.task_recipe = None;
        original.tasks = PidsLimitReadbackV1::new();
        original.task_capture = None;
        original.task_post = None;
        original.memory = MemoryLimitReadbackV1::new();
        original.memory_capture = None;
        original.memory_post = None;
        original.limit_binding = None;
        original.capture_final_clock = capture::CaptureFinalClockV3::default();
        original.capture_final_pair = None;
        original.capture_final_comparison = None;
        original.capture_quiescence_entered = false;
        original.capture_quiescence_alive = None;
        original.capture_quiescence_population = CgroupPopulationObservationV1::new();
        original.capture_quiescence_population_result = None;
        original.capture_quiescence_result = None;
        original.capture_drain_remaining = None;
        original.capture_drain_reservation = None;
        original.capture_drain_ceiling = None;
        original.kind = None;
        original.bound = false;
        original.disposal_entered = false;
        original.before = None;
        original.post_preparation = None;
        original.post_result = None;
        original.binding_post = None;
        original.after = None;
        original.shape = None;
        original.socket_binding = None;
        original.alive = None;
        original.membership = None;
        original.membership_result = None;
        original.population = None;
        original.population_owner = None;
        original.binding_population = CgroupPopulationObservationV1::new();
        original.binding_population_result = None;
        original.final_population = CgroupPopulationObservationV1::new();
        original.final_population_result = None;
        original.aggregate_worker = WorkerCgroupOpeningV1::new();
        original.aggregate_resolution = None;
        original.aggregate_identity = None;
        self.flight.completed = true;
    }
}

impl Drop for StoragePhysicalWorkerLoanV1<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            else { return; };
            receiving.physical_worker.first.get_or_insert(WorkerFailure::Closed);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
        }
    }
}

impl<'cut, 'original> super::state_recovery::StorageStateRecoveryEncodingLoanV1<'cut, 'original> {
    /// Borrows one ZFS flight from the same model-paid State recovery stage.
    ///
    /// # Errors
    /// Refuses a substituted State writer, inactive/unpaid stage, original
    /// debt, full-vector arithmetic refusal or unfinished predecessor flight.
    pub fn borrow_zfs_worker_flight_v1<'flight>(
        &'flight mut self, journal: &crate::Journal, demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        self.receiving_worker_v1(journal)?.begin_physical_worker_v1(WorkerKind::Zfs, demand)
    }

    /// Borrows one pin flight from the same model-paid State recovery stage.
    ///
    /// # Errors
    /// Refuses a substituted State writer, inactive/unpaid stage, original
    /// debt, full-vector arithmetic refusal or unfinished predecessor flight.
    pub fn borrow_pin_worker_flight_v1<'flight>(
        &'flight mut self, journal: &crate::Journal, demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        self.receiving_worker_v1(journal)?.begin_physical_worker_v1(WorkerKind::Pin, demand)
    }
}

impl<'cut, 'original> super::lifecycle::StorageLifecycleSessionLoanV1<'cut, 'original> {
    /// Borrows one ZFS flight from the current paid Session Domain stage.
    ///
    /// # Errors
    /// Refuses changed Session writer/socket, unpaid or wrong phase, original
    /// debt, full-vector arithmetic refusal or unfinished predecessor flight.
    pub fn borrow_zfs_worker_flight_v1<'flight>(
        &'flight mut self, journal: &crate::Journal, socket: &SeqpacketSocket,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        self.receiving_domain_v1(journal, socket)?.begin_physical_worker_v1(WorkerKind::Zfs, demand)
    }

    /// Borrows one pin flight from the current paid Session Domain stage.
    ///
    /// # Errors
    /// Refuses changed Session writer/socket, unpaid or wrong phase, original
    /// debt, full-vector arithmetic refusal or unfinished predecessor flight.
    pub fn borrow_pin_worker_flight_v1<'flight>(
        &'flight mut self, journal: &crate::Journal, socket: &SeqpacketSocket,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        self.receiving_domain_v1(journal, socket)?.begin_physical_worker_v1(WorkerKind::Pin, demand)
    }
}

#[cfg(test)]
mod descendant_file_tests {
    use super::*;
    use aos_sandbox_core::{ResourceDimension, ResourceVector};
    use crate::controller_resource_reservation::component_receiving::ComponentServiceReceivingLedgerV1;

    #[test]
    fn additional_tables_cannot_admit_a_flight_under_the_unchanged_two_table_ceiling() {
        let limit = ResourceVector::ZERO.with(ResourceDimension::OpenFiles, 256);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(limit);
        ledger.reserve(ResourceVector::ZERO.with(ResourceDimension::OpenFiles, 256)).unwrap();
        let before = ledger.charged();
        let additional = additional_descendant_files_v1(3).unwrap();

        assert!(ledger.reserve(ResourceVector::ZERO.with(ResourceDimension::OpenFiles, additional)).is_err());
        assert_eq!(ledger.charged(), before);
        assert!(ledger.failure().is_some());
    }
}

impl<'outer, 'original> super::root_launch_export::StorageRootLaunchExportReceivingLoanV2<'outer, 'original> {
    /// Lends only the existing catalog/pin worker under the same paid export turn.
    ///
    /// The complete concrete worker shape is passive DATA. The actual F,
    /// current State identity, occupied root-export operation and complete
    /// model payment must already exist; no vector can construct them. Actual
    /// closed canary/launch authority remains an independent upper obligation.
    /// Generic ZFS mutation and effect/repair pin entry remain unavailable.
    ///
    /// # Errors
    /// Refuses another State, incomplete/closed financing, another worker,
    /// original failure or a footprint outside this same installed original.
    pub fn borrow_catalog_worker_flight_v2<'flight>(
        &'flight mut self,
        journal: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        if !self.receiving.original.open { return Err(StorageReceivingClosedV1); }
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else { return Err(StorageReceivingClosedV1); };
        receiving.require_initial()?;
        if !receiving.startup.state_recovery_ready_v1(journal)
            || receiving.root_launch_export.require_catalog_v2().is_err()
            || !receiving.physical_worker.is_between_flights_v2()
        {
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        self.receiving.begin_physical_worker_prechecked_v2(WorkerKind::Pin, demand)
    }
}

impl<'cut, 'original> super::lifecycle::StorageLifecycleSessionLoanV1<'cut, 'original> {
    /// Borrows only the readonly candidate worker from this paid actual Domain.
    ///
    /// The actual authenticated method41 and retained Session remain upper
    /// obligations; no Source944 or60 worker lifetime can select this purpose.
    ///
    /// # Errors
    /// Refuses another method/direction, missing signed authorization, wrong
    /// Session Domain, prior native debt or unaffordable full worker geometry.
    pub fn borrow_candidate_worker_flight_v1<'flight>(
        &'flight mut self, journal: &crate::Journal, socket: &SeqpacketSocket,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        if request.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            || request.authorization().is_none()
        { return Err(StorageReceivingClosedV1); }
        self.receiving_domain_v1(journal, socket)?.begin_physical_worker_v1(WorkerKind::Candidate, demand)
    }
}


impl<'cut, 'original> StorageStateRecoveryEncodingLoanV1<'cut, 'original> {
    /// Borrows the shared catalog observer during the actual method31 turn.
    ///
    /// This lends only the existing Pin observation flight. It cannot select
    /// the GuestRoot mutation worker or an initial Inventory once slot.
    ///
    /// # Errors
    /// Refuses another State/request, unpaid models, unfinished previous
    /// physical custody or the same-F complete-demand refusal.
    pub fn borrow_guest_root_catalog_worker_v2<'flight>(
        &'flight mut self,
        state: &crate::Journal,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        self.require_guest_root_publication_method_v2(state, request)?;
        self.receiving_worker_v1(state)?.begin_physical_worker_v1(WorkerKind::Pin, demand)
    }

    /// Borrows the fixed publisher on the same current method31 State interval.
    ///
    /// `demand` is the actual callee's finite footprint, never a payer or a
    /// mutation grant. The separately authenticated Storage admission remains
    /// mandatory before any request can reach the one-shot publisher.
    ///
    /// # Errors
    /// Refuses initial/foreign/unpaid State custody, another signed method,
    /// outstanding worker debt or same-original full-vector capacity refusal.
    pub fn borrow_guest_root_publication_worker_v2<'flight>(&'flight mut self,
        state: &crate::Journal,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        self.require_guest_root_publication_method_v2(state, request)?;
        self.receiving_worker_v1(state)?.begin_physical_worker_v1(WorkerKind::GuestRootPublication31, demand)
    }
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Pays the one actual startup health owner's constructor before growth.
    ///
    /// This named observation requires the installed same-F State and idle
    /// lifecycle/Session/worker owners. It supplies no method31 effect grant.
    ///
    /// # Errors
    /// Refuses reentry, another State, existing debt, nonrepresentation demand
    /// or the original ledger's actual capacity refusal before construction.
    pub fn reserve_guest_root_startup_health_v2(
        &mut self, state: &crate::Journal, demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        let representation = ResourceVector::ZERO
            .with(D::MemoryBytes, demand.get(D::MemoryBytes))
            .with(D::OpenFiles, demand.get(D::OpenFiles))
            .with(D::MetadataEntries, demand.get(D::MetadataEntries));
        if receiving.guest_root_health_entered
            || !receiving.startup.state_recovery_ready_v1(state)
            || !receiving.lifecycle.is_parked_v1()
            || !receiving.session_wire.is_between_flights_v1()
            || !receiving.physical_worker.is_between_flights_v2()
            || demand != representation
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.guest_root_health_entered = true;
        receiving.reserve(demand)?;
        receiving.guest_root_health_models_paid = true;
        Ok(())
    }

    /// Lends only the actual once-owned startup health worker on the same F.
    ///
    /// # Errors
    /// Refuses unpaid construction, reentry, another State or existing debt.
    pub fn borrow_guest_root_startup_health_v2<'flight>(
        &'flight mut self, state: &crate::Journal, demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.guest_root_health_entered || !receiving.guest_root_health_models_paid
            || receiving.guest_root_health_worker_entered
            || !receiving.startup.state_recovery_ready_v1(state)
            || !receiving.lifecycle.is_parked_v1()
            || !receiving.session_wire.is_between_flights_v1()
            || !receiving.physical_worker.is_between_flights_v2()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.guest_root_health_worker_entered = true;
        self.begin_physical_worker_prechecked_v2(WorkerKind::GuestRootStartupHealth, demand)
    }
}

#[cfg(test)]
mod traffic_tests {
    use super::*;

    #[test]
    fn equal_later_worker_flight_spends_again_and_retains_the_actual_refusal() {
        let complete = ResourceVector::ZERO.with(D::MemoryBytes, 64)
            .with(D::NetworkBytes, 6).with(D::OutputBytes, 2);
        let ceiling = ResourceVector::ZERO.with(D::MemoryBytes, 64)
            .with(D::NetworkBytes, 10).with(D::OutputBytes, 4);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(ceiling);
        let (capacity, first) = worker_complete_demand_growth_v2(ResourceVector::ZERO, complete).unwrap();
        ledger.reserve(first).unwrap();
        let charged = ledger.charged();

        let (same_capacity, next) = worker_complete_demand_growth_v2(capacity, complete).unwrap();
        assert_eq!(same_capacity, capacity);
        assert_eq!(next.get(D::MemoryBytes), 0);
        assert_eq!(next.get(D::NetworkBytes), 6);
        assert!(ledger.reserve(next).is_err());
        assert_eq!(ledger.charged(), charged);
        let first_failure = ledger.failure().unwrap() as *const aos_sandbox_core::AccountingError;
        assert!(ledger.reserve(ResourceVector::ZERO).is_err());
        assert!(std::ptr::eq(first_failure, ledger.failure().unwrap()));
    }
}
