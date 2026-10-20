//! Owns the installed startup health pass on the same paid Storage F.
//!
//! The no-effect request shares method31's descriptor/native worker engine.
//! It carries no effect, lease, mutation request or replacement State owner.
//! Every failure stays resident before the daemon renders it and terminates.

use super::*;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

#[derive(Clone, Copy)]
enum First { Gate, Publisher, Clock, Deadline, WorkerDemand, WorkerEntry, Worker }

pub(super) struct GuestRootStartupHealthOriginalV2 {
    dispatch: Option<Result<repair_worker_drain::WorkerDispatchLease, StorageRuntimeError>>,
    publisher_open: crate::pin_worker_runtime::GuestRootPublisherOpenOriginalV2,
    publisher: Option<Result<SystemdGuestRootPublisherClientV1, ZfsWorkerError>>,
    clock: Option<Result<u64, ZfsWorkerError>>,
    deadline: Option<Result<u64, AccountingError>>,
    worker: Option<Result<(), ZfsWorkerError>>,
    worker_demand: Option<Result<ResourceVector, AccountingError>>,
    worker_entry: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    constructor_post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    gate: Option<StorageRuntimeError>,
    first: Option<First>,
    entered: bool,
    positive: bool,
}

impl GuestRootStartupHealthOriginalV2 {
    fn new() -> Self {
        Self { dispatch: None, publisher_open: crate::pin_worker_runtime::GuestRootPublisherOpenOriginalV2::new(),
            publisher: None, clock: None, deadline: None, worker: None, worker_demand: None,
            worker_entry: None, constructor_post: None, gate: None,
            first: None, entered: false, positive: false }
    }

    fn receiving_demand_v2() -> Result<ResourceVector, AccountingError> {
        let invalid = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Box<Self>>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let native = crate::pin_worker_runtime::GuestRootPublisherOpenOriginalV2::receiving_demand_v2()
            .ok_or_else(invalid)?;
        native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    fn refuse(&mut self, first: First) -> Result<(), StorageRuntimeError> {
        self.first.get_or_insert(first);
        Err(StorageRuntimeError::Receiving)
    }

    fn run_once_v2(&mut self, runtime: &StorageBrokerRuntime,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageRuntimeError> {
        if self.entered { self.positive = false; return self.refuse(First::Gate); }
        self.entered = true;
        self.dispatch = Some(runtime.worker_dispatch.enter().map_err(|_| StorageRuntimeError::Recovery));
        if !matches!(self.dispatch, Some(Ok(_))) || !runtime.is_inventory_ready() {
            self.gate = Some(StorageRuntimeError::Recovery);
            return self.refuse(First::Gate);
        }
        self.clock = Some(boottime_now_nanoseconds());
        let Some(Ok(now)) = self.clock.as_ref() else { return self.refuse(First::Clock); };
        // Preserve the installed health check's original 60-second READY bound.
        self.deadline = Some(now.checked_add(60 * 1_000_000_000)
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes }));
        let Some(Ok(deadline)) = self.deadline.as_ref() else { return self.refuse(First::Deadline); };
        let deadline = *deadline;
        self.worker_demand = Some(SystemdGuestRootPublisherClientV1::health_worker_receiving_demand_v2()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes }));
        let Some(Ok(demand)) = self.worker_demand.as_ref() else { return self.refuse(First::WorkerDemand); };
        let demand = *demand;
        let flight = match receiving.borrow_guest_root_startup_health_v2(
            runtime.coordinator.recovery_encoding_journal_v1(), demand,
        ) {
            Ok(flight) => { self.worker_entry = Some(Ok(())); flight }
            Err(cause) => { self.worker_entry = Some(Err(cause)); return self.refuse(First::WorkerEntry); }
        };
        // The native before and independently paid post are armed while the
        // SAME original is resident, before any publisher constructor IO.
        self.publisher = Some(self.publisher_open.open_once_v2());
        let Some(Ok(publisher)) = self.publisher.as_mut() else {
            self.first.get_or_insert(First::Publisher);
            self.constructor_post = Some(flight.finish_failed_interval_v1());
            return Err(StorageRuntimeError::Receiving);
        };
        self.worker = Some(publisher.probe_receiving_entered_v2(deadline, demand, flight));
        if !matches!(self.worker, Some(Ok(()))) { return self.refuse(First::Worker); }
        // The shared worker retired its actual request/READY/native capsules
        // only after exit, independent posts and original deadline-after.
        drop(self.dispatch.take());
        self.positive = true;
        Ok(())
    }

    fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            First::Gate => self.gate.as_ref().map(|cause| cause as _),
            First::Publisher => self.publisher_open.failure_v2().or_else(|| error(&self.publisher)),
            First::Clock => error(&self.clock),
            First::Deadline => error(&self.deadline),
            First::WorkerDemand => error(&self.worker_demand),
            First::WorkerEntry => error(&self.worker_entry),
            First::Worker => error(&self.worker),
        }
    }
}

impl Drop for GuestRootStartupHealthOriginalV2 {
    fn drop(&mut self) {
        if self.entered && !self.positive { std::process::abort(); }
    }
}

impl StorageBrokerRuntime {
    pub(crate) fn probe_guest_root_publisher_receiving_v2(&mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageRuntimeError> {
        if let Some(owner) = self.guest_root_health.as_mut() {
            owner.positive = false;
            owner.first.get_or_insert(First::Gate);
            owner.gate.get_or_insert(StorageRuntimeError::Receiving);
            return Err(StorageRuntimeError::Receiving);
        }
        if self.guest_root_health_demand.is_some() { return Err(StorageRuntimeError::Receiving); }
        self.guest_root_health_demand = Some(GuestRootStartupHealthOriginalV2::receiving_demand_v2());
        let Some(Ok(demand)) = self.guest_root_health_demand.as_ref() else {
            return Err(StorageRuntimeError::Receiving);
        };
        self.guest_root_health_payment = Some(receiving.reserve_guest_root_startup_health_v2(
            self.coordinator.recovery_encoding_journal_v1(), *demand,
        ));
        if !matches!(self.guest_root_health_payment, Some(Ok(()))) {
            return Err(StorageRuntimeError::Receiving);
        }
        let mut original = Box::new(GuestRootStartupHealthOriginalV2::new());
        let result = original.run_once_v2(self, receiving);
        if result.is_ok() {
            // The actual native worker token already completed after its own
            // upper disposal. Health has no later borrower: retire its exact
            // positive constructor/client now, without refunding F debt.
            drop(original);
        } else {
            self.guest_root_health = Some(original);
        }
        result
    }

    pub(crate) fn guest_root_startup_health_failure_v2<'owner>(&'owner self,
        receiving: &'owner aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.guest_root_health_demand { return Some(cause); }
        if matches!(self.guest_root_health_payment, Some(Err(_))) { return receiving.failure(); }
        let owner = self.guest_root_health.as_ref()?;
        let cause = owner.failure_v2()?;
        if matches!(owner.first, Some(First::WorkerEntry)) {
            return receiving.failure().or(Some(cause));
        }
        if matches!(owner.first, Some(First::Worker)) {
            let selected = cause.downcast_ref::<ZfsWorkerError>()
                .and_then(ZfsWorkerError::physical_native_refusal_v1).is_some();
            if selected { return receiving.failure().or(Some(cause)); }
        }
        Some(cause)
    }
}
