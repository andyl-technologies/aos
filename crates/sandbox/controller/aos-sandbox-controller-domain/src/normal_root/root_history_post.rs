//! Owns a separately prearmed Root/Controller/Root history post on the SAME R.
//!
//! Earlier financial or append refusal cannot suppress these observations or
//! replace their native destinations. Only whole positive comparison and actual
//! settlement disposes this sample; it never clears the Root invocation fence.

use std::error::Error as StdError;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::receiving::RootPrearmedHistoryServicePostV1;
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, service_interval::ObserverLifetime};
use super::{ProductionNormalRootStartupV1, NormalRootStartupErrorV1 as Error, RootControllerPeerReceivingV1};
use super::controller_peer::receiving::RootControllerPeerCurrentSampleV1;

enum RootPeerPostSchedulingV1 {
    InitialSharedWorker,
    ContinuationPaidWorker { cutoff: u64 },
}

pub(crate) struct RootHistoryPeerPostV1 {
    traffic: Result<(), ResourceReservationErrorV1>,
    before: RootPrearmedHistoryServicePostV1,
    after: RootPrearmedHistoryServicePostV1,
    peer: Option<RootControllerPeerCurrentSampleV1>,
    worker_entry: Option<Result<(), Error>>,
    worker_exit: Option<Result<(), Error>>,
    before_result: Option<Result<(), Error>>,
    peer_result: Option<Result<(), Error>>,
    after_result: Option<Result<(), Error>>,
    deadline_sample: Option<rustix::time::Timespec>,
    deadline_result: Option<Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>>,
    settlement: Option<Result<(), Error>>,
    complete: bool,
    closed: bool,
}

impl RootHistoryPeerPostV1 {
    pub(crate) fn from_originals_v1(before: RootPrearmedHistoryServicePostV1,
        after: RootPrearmedHistoryServicePostV1, lifetime: ObserverLifetime,
        traffic: Result<(), ResourceReservationErrorV1>) -> Self {
        Self { traffic, before, after, peer: Some(RootControllerPeerCurrentSampleV1::new(lifetime)),
            worker_entry: None, worker_exit: None, before_result: None, peer_result: None, after_result: None, deadline_sample: None, deadline_result: None, settlement: None,
            complete: false, closed: false }
    }

    fn complete_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let service = RootPrearmedHistoryServicePostV1::demand_v1().ok_or_else(invalid)?;
        let peer = RootControllerPeerCurrentSampleV1::demand_v1()?;
        service.checked_add(service).and_then(|value| value.checked_add(peer)).map_err(|_| invalid())
    }

    pub(crate) fn demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let demand = Self::complete_demand_v1()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(std::mem::size_of::<Self>().checked_mul(3)
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?))
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let row = aos_systemd_client::FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(64 * 1024)
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        // Every archive.read joins its worker before returning, including
        // timeout/native/panic failure. These three calls run synchronously in
        // order. SUM memory and FDs remain charged for retained negative
        // runtimes; only the actual simultaneous explicit worker count is one.
        Ok(without_traffic(demand).with(D::Pids, row.worker_threads))
    }

    pub(crate) fn additional_resident_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let demand = Self::demand_v1()?;
        let named = RootControllerPeerReceivingV1::fixed_demand()?.get(D::Pids);
        // The SAME original initial peer stage explicitly paid this worker
        // peak. Actual arming requires its positive archive settlement and
        // each observe exclusively enters/leaves that named slot below.
        if demand.get(D::Pids) > named { return Err(ResourceReservationErrorV1::EnrollmentUnavailable); }
        Ok(demand.with(D::Pids, 0))
    }

    pub(crate) fn traffic_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        Ok(traffic_only(Self::complete_demand_v1()?))
    }

    pub(crate) fn initial_traffic_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        // The central Root before and prearmed after each debit their own
        // canonical one-row traffic. This initial peer recipe covers only its
        // actual three Controller rows; the history recipe above remains R2+C1.
        Ok(traffic_only(RootControllerPeerReceivingV1::fixed_demand()?))
    }

    pub(crate) fn is_positive_v1(&self) -> bool { self.complete && !self.closed && self.failure().is_none() }

    pub(crate) fn require_armed_v1(&self) -> Result<(), Error> {
        if self.traffic.is_ok() { Ok(()) } else { Err(Error::Service) }
    }

    pub(crate) fn observe_once(&mut self, startup: &ProductionNormalRootStartupV1,
        native: Option<&RetainedUnixStream>, peer: Option<&RootControllerPeerReceivingV1<'_>>)
        -> Result<(), Error> {
        self.observe_with_scheduling_once(startup, native, peer,
            RootPeerPostSchedulingV1::InitialSharedWorker)
    }

    // The genuine D flight prepays this post's full worker bound. It never
    // claims the InitialController shared worker or clears that original slot.
    pub(crate) fn observe_delete_once_v1(&mut self, startup: &ProductionNormalRootStartupV1,
        native: Option<&RetainedUnixStream>, peer: Option<&RootControllerPeerReceivingV1<'_>>,
        cutoff: u64)
        -> Result<(), Error> {
        self.observe_continuation_once_v1(startup, native, peer, cutoff)
    }

    // Both closed continuation purposes pay the full worker/native bound.
    // The old InitialController scheduling branch stays unchanged.
    pub(crate) fn observe_continuation_once_v1(&mut self, startup: &ProductionNormalRootStartupV1,
        native: Option<&RetainedUnixStream>, peer: Option<&RootControllerPeerReceivingV1<'_>>,
        cutoff: u64)
        -> Result<(), Error> {
        self.observe_with_scheduling_once(startup, native, peer,
            RootPeerPostSchedulingV1::ContinuationPaidWorker { cutoff })
    }

    fn observe_with_scheduling_once(&mut self, startup: &ProductionNormalRootStartupV1,
        native: Option<&RetainedUnixStream>, peer: Option<&RootControllerPeerReceivingV1<'_>>,
        scheduling: RootPeerPostSchedulingV1) -> Result<(), Error> {
        if self.worker_entry.is_some() || self.before_result.is_some() || self.closed { self.closed = true; return Err(Error::Service); }
        self.require_armed_v1()?;
        if matches!(scheduling, RootPeerPostSchedulingV1::InitialSharedWorker) {
            self.worker_entry = Some(worker_slot(startup, true));
            if !matches!(self.worker_entry, Some(Ok(()))) { return Err(Error::Service); }
        }
        self.before_result = Some(observe_root(startup, &mut self.before));
        // An earlier Root service/financial/append refusal never suppresses the
        // separately owned Controller sample or independently owed Root after.
        self.peer_result = Some(match (native, peer, self.peer.as_mut()) {
            (Some(native), Some(peer), Some(sample)) => peer.observe_prearmed_current_into_v1(native, sample),
            _ => Err(Error::Service),
        });
        self.after_result = Some(observe_root(startup, &mut self.after));
        // Every reached archive.read has returned through its unconditional
        // join. Retained negative runtimes/FDs stay owned; only this explicit
        // worker-task exclusivity ends. Refusal still prevents another arm.
        if matches!(scheduling, RootPeerPostSchedulingV1::InitialSharedWorker) {
            self.worker_exit = Some(worker_slot(startup, false));
        }
        if let RootPeerPostSchedulingV1::ContinuationPaidWorker { cutoff } = scheduling {
            // This local native leaf must also be timely before its positive
            // archive/native originals can be retired below. The enclosing
            // chunk still owes its separate paired-clock and subject/copy posts.
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            self.deadline_sample = Some(now);
            self.deadline_result = Some(crate::policy_compiler::root_deadline_remaining_v1(
                now, cutoff).map(|_| ()));
        }
        if self.failure().is_none() && matches!(self.peer_result, Some(Ok(()))) {
            self.settlement = Some(self.peer.as_mut().ok_or(Error::Service)?.settle_after_root_post_once_v1());
        }
        self.complete = matches!(self.settlement, Some(Ok(()))) && self.failure().is_none();
        if self.complete {
            // The same old successful current sample disposal frontier follows
            // actual independent Root after and archive/socket settlement.
            drop(self.peer.take());
            self.before.retire_positive_once_v1();
            self.after.retire_positive_once_v1();
            Ok(())
        } else {
            if startup.receiving.is_some() {
                if let Ok(mut original) = startup.lock_receiving_v1() {
                    original.original_mut_v1().refuse_history_peer_post_v1();
                }
            }
            Err(Error::Service)
        }
    }

    pub(crate) fn property_failure_view_v1(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let first = self.failure()?;
        let peer = self.peer.as_ref()?;
        if peer.failure().is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _)) {
            peer.property_failure_view_v1()
        } else { None }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.traffic.as_ref().err().map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| cause(&self.worker_entry))
            .or_else(|| self.before.failure()).or_else(|| cause(&self.before_result))
            .or_else(|| self.peer.as_ref().and_then(|sample| sample.failure()))
            .or_else(|| cause(&self.peer_result)).or_else(|| self.after.failure())
            .or_else(|| cause(&self.after_result)).or_else(|| cause(&self.worker_exit))
            .or_else(|| cause(&self.deadline_result))
            .or_else(|| cause(&self.settlement))
    }
}

fn observe_root(startup: &ProductionNormalRootStartupV1, post: &mut RootPrearmedHistoryServicePostV1)
    -> Result<(), Error> {
    let mut receiving = startup.lock_receiving_v1()?;
    let returned = receiving.original_mut_v1().observe_armed_history_service_once_v1(startup, post);
    receiving.finish_returned_v1(returned)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

// Both Root flight and peer-post schedules use the sole pure traffic law.
use aos_sandbox_model::component_receiving::operation_traffic_demand_v1 as traffic_only;
pub(crate) use aos_sandbox_model::component_receiving::without_operation_traffic_v1 as without_traffic;

fn worker_slot(startup: &ProductionNormalRootStartupV1, enter: bool) -> Result<(), Error> {
    let mut receiving = startup.lock_receiving_v1()?;
    let original = receiving.original_mut_v1();
    let returned = if enter { original.enter_history_peer_worker_once_v1() }
        else { original.finish_history_peer_worker_once_v1() };
    receiving.finish_returned_v1(returned)
}
