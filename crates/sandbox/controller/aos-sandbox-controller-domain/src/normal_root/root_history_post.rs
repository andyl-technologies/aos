//! Owns a separately prearmed Root/Controller/Root history post on the SAME R.
//!
//! Earlier financial or append refusal cannot suppress these observations or
//! replace their native destinations. Only whole positive comparison and actual
//! settlement disposes this sample; it never clears the Root invocation fence.

use std::error::Error as StdError;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::receiving::{RootHistoryPeerPostNativeOriginalV1, RootPrearmedHistoryServicePostV1};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, service_interval::ObserverLifetime};
use super::{ProductionNormalRootStartupV1, NormalRootStartupErrorV1 as Error, RootControllerPeerReceivingV1};

enum RootPeerPostSchedulingV1 {
    InitialSharedWorker,
    ContinuationPaidWorker { cutoff: u64 },
}

pub(crate) struct RootHistoryPeerPostV1 {
    traffic: Result<(), ResourceReservationErrorV1>,
    native: RootHistoryPeerPostNativeOriginalV1,
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
        Self { traffic, native: RootHistoryPeerPostNativeOriginalV1::from_originals_v1(before, after, lifetime),
            worker_entry: None, worker_exit: None, before_result: None, peer_result: None, after_result: None, deadline_sample: None, deadline_result: None, settlement: None,
            complete: false, closed: false }
    }

    fn complete_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        RootHistoryPeerPostNativeOriginalV1::demand_v1()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    pub(crate) fn demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let demand = Self::complete_demand_v1()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(std::mem::size_of::<Self>().checked_mul(3)
                .and_then(|bytes| bytes.checked_add(UpperHistoryProgrammeV1::control_bytes_v1()?))
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
        self.observe_with_scheduling_once(startup, native,
            RootHistoryControllerPeerBorrowV1::Upper(peer),
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
        self.observe_with_scheduling_once(startup, native,
            RootHistoryControllerPeerBorrowV1::Upper(peer),
            RootPeerPostSchedulingV1::ContinuationPaidWorker { cutoff })
    }

    // NoApply owns its actual peer in Policy. This fixed native borrow enters
    // the same sampler, with the same paid continuation scheduling branch.
    pub(crate) fn observe_native_continuation_once_v2(&mut self,
        startup: &ProductionNormalRootStartupV1,
        native: Option<&RetainedUnixStream>,
        peer: Option<&aos_sandbox_broker::receiving::RootSelectedControllerPeerOriginalV1<'_>>,
        cutoff: u64,
    ) -> Result<(), Error> {
        self.observe_with_scheduling_once(startup, native, RootHistoryControllerPeerBorrowV1::Native(peer),
            RootPeerPostSchedulingV1::ContinuationPaidWorker { cutoff })
    }

    fn observe_with_scheduling_once(&mut self, startup: &ProductionNormalRootStartupV1,
        native: Option<&RetainedUnixStream>, peer: RootHistoryControllerPeerBorrowV1<'_, '_>,
        scheduling: RootPeerPostSchedulingV1) -> Result<(), Error> {
        let mut driver = UpperHistoryProgrammeV1 { original: self, startup, native, peer, scheduling };
        aos_sandbox_broker::root_history_observation_programme_v1!(driver)
    }

    pub(crate) fn native_original_mut_v1(&mut self) -> &mut RootHistoryPeerPostNativeOriginalV1 {
        &mut self.native
    }

    pub(crate) fn property_failure_view_v1(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let first = self.failure()?;
        if self.native.peer_failure_v1().is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _)) {
            self.native.peer_property_failure_view_v1()
        } else { None }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.traffic.as_ref().err().map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| cause(&self.worker_entry))
            .or_else(|| self.native.before_failure_v1()).or_else(|| cause(&self.before_result))
            .or_else(|| self.native.peer_failure_v1())
            .or_else(|| cause(&self.peer_result)).or_else(|| self.native.after_failure_v1())
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

// The closed reference alternatives preserve a failed upper getter until the
// actual Controller frontier, after Root-before and before independent Root-after.
enum RootHistoryControllerPeerBorrowV1<'a, 'startup> {
    Upper(Option<&'a RootControllerPeerReceivingV1<'startup>>),
    Native(Option<&'a aos_sandbox_broker::receiving::RootSelectedControllerPeerOriginalV1<'startup>>),
}

struct UpperHistoryProgrammeV1<'a, 'startup> {
    original: &'a mut RootHistoryPeerPostV1,
    startup: &'a ProductionNormalRootStartupV1,
    native: Option<&'a RetainedUnixStream>,
    peer: RootHistoryControllerPeerBorrowV1<'a, 'startup>,
    scheduling: RootPeerPostSchedulingV1,
}

impl UpperHistoryProgrammeV1<'_, '_> {
    fn begin_once_v1(&mut self) -> Result<(), Error> {
        if self.original.worker_entry.is_some() || self.original.before_result.is_some() || self.original.closed {
            self.original.closed = true;
            return Err(Error::Service);
        }
        Ok(())
    }

    fn require_armed_v1(&self) -> Result<(), Error> { self.original.require_armed_v1() }

    fn uses_shared_worker_v1(&self) -> bool {
        matches!(self.scheduling, RootPeerPostSchedulingV1::InitialSharedWorker)
    }

    fn enter_worker_once_v1(&mut self) -> Result<(), Error> {
        self.original.worker_entry = Some(worker_slot(self.startup, true));
        if matches!(self.original.worker_entry, Some(Ok(()))) { Ok(()) }
        else { Err(Error::Service) }
    }

    fn observe_root_before_once_v1(&mut self) {
        self.original.before_result = Some(observe_root(self.startup,
            self.original.native.before_original_mut_v1()));
    }

    fn observe_controller_once_v1(&mut self) {
        self.original.peer_result = Some(match &self.peer {
            RootHistoryControllerPeerBorrowV1::Upper(Some(peer)) => match peer.native_original_v1() {
                Ok(peer) => self.original.native.observe_controller_once_v1(self.native, Some(peer)).map_err(Into::into),
                Err(error) => Err(error),
            },
            RootHistoryControllerPeerBorrowV1::Native(Some(peer)) => self.original.native
                .observe_controller_once_v1(self.native, Some(*peer)).map_err(Into::into),
            RootHistoryControllerPeerBorrowV1::Upper(None) | RootHistoryControllerPeerBorrowV1::Native(None) =>
                self.original.native.observe_controller_once_v1(self.native, None).map_err(Into::into),
        });
    }

    fn observe_root_after_once_v1(&mut self) {
        self.original.after_result = Some(observe_root(self.startup,
            self.original.native.after_original_mut_v1()));
    }

    fn finish_worker_once_v1(&mut self) {
        self.original.worker_exit = Some(worker_slot(self.startup, false));
    }

    fn observe_deadline_once_v1(&mut self) {
        if let RootPeerPostSchedulingV1::ContinuationPaidWorker { cutoff } = self.scheduling {
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            self.original.deadline_sample = Some(now);
            self.original.deadline_result = Some(aos_sandbox_broker::bounded_stream_io::remaining(
                now, cutoff).map(|_| ()));
        }
    }

    fn settle_if_complete_once_v1(&mut self) {
        if self.original.failure().is_none() && matches!(self.original.peer_result, Some(Ok(()))) {
            self.original.settlement = Some(self.original.native.settle_after_root_post_once_v1().map_err(Into::into));
        }
    }

    fn finish_once_v1(&mut self) -> Result<(), Error> {
        self.original.complete = matches!(self.original.settlement, Some(Ok(()))) && self.original.failure().is_none();
        if self.original.complete {
            self.original.native.retire_positive_once_v1();
            Ok(())
        } else {
            if self.startup.receiving.is_some() {
                if let Ok(mut original) = self.startup.lock_receiving_v1() {
                    original.original_mut_v1().refuse_history_peer_post_v1();
                }
            }
            Err(Error::Service)
        }
    }
}

impl UpperHistoryProgrammeV1<'_, '_> {
    fn control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<RootHistoryControllerPeerBorrowV1<'_, '_>>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut RootHistoryPeerPostV1, &ProductionNormalRootStartupV1,
                Option<&RetainedUnixStream>, RootHistoryControllerPeerBorrowV1<'_, '_>, RootPeerPostSchedulingV1)>().checked_mul(3)?)?
            .checked_add(size_of::<&mut Self>().checked_mul(27)?)?
            .checked_add(size_of::<&Self>().checked_mul(9)?)?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(12)?)?
            .checked_add(size_of::<bool>().checked_mul(12)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}
