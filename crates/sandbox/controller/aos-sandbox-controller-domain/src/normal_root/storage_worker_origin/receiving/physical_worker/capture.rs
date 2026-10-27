//! Occupied physical Capture continuation on the same Storage original.
//!
//! Parking releases only a Rust borrow. The actual operation, full-vector
//! debt, READY original, limit and membership observations, and armed post stay
//! on the original. No second worker can enter while that operation is resident.
//! The Controller response can therefore complete before Host starts Guest,
//! without falsely completing the physical interval at that response boundary.

use super::*;

#[derive(Debug, thiserror::Error)]
pub(super) enum CaptureFinalClockErrorV3 {
    #[error("original Capture final clock or execution horizon changed")]
    Stale,
    #[error(transparent)]
    Native(aos_linux_descriptors::Error),
}

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for CaptureFinalClockErrorV3 {
    fn stale() -> Self { Self::Stale }
    fn kernel(cause: aos_linux_descriptors::Error) -> Self { Self::Native(cause) }
}

pub(super) type CaptureFinalClockV3 = aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<CaptureFinalClockErrorV3>;
use std::sync::Arc;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;

/// Identifies an occupied Capture interval through its actual READY original.
///
/// Only a bound, purpose-specific worker can produce this owner. It grants no
/// new work or funding. The actual Storage owner keeps it with the worker
/// channel, pipes and terminal originals until positive physical retirement.
#[must_use]
pub struct StorageResidentCaptureWorkerV2 {
    pub(super) ready: Option<Arc<ReceivedRecord>>,
    pub(super) completed: bool,
}

/// Reborrows an occupied Capture interval without constructing another flight.
#[must_use]
pub struct StorageCaptureWorkerBorrowV2<'worker, 'flight, 'original> {
    flight: StoragePhysicalWorkerLoanV1<'flight, 'original>,
    socket: &'worker mut SeqpacketSocket,
    cgroup: &'worker RetainedCgroupAnchor,
    population: &'worker CgroupPopulationMonitor,
    resident: &'worker mut StorageResidentCaptureWorkerV2,
}

/// Holds the same original until actual positive upper Capture disposal.
#[must_use]
pub struct StorageCaptureWorkerDisposalV2<'worker, 'flight, 'original> {
    native: StoragePhysicalWorkerDisposalV1<'flight, 'original>,
    resident: &'worker mut StorageResidentCaptureWorkerV2,
}

fn resident_representation_v2() -> Option<ResourceVector> {
    let bytes = std::mem::size_of::<ReceivedRecord>()
        .checked_add(2 * std::mem::size_of::<usize>())?
        .checked_add(std::mem::align_of::<ReceivedRecord>())?
        .checked_add(3 * std::mem::size_of::<StorageResidentCaptureWorkerV2>())?;
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
}

// The actual native request and opaque signed admission select this sole
// entry. Base acquisition DATA and historical parsed rows cannot enter it.
pub(super) fn matches_actual_capture_request_v3(
    request: &AuthenticatedBrokerMethodRequestV1,
    verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
) -> bool {
    use sha2::Digest as _;
    let effect = &verified.admission_v3().effect;
    request.direction() == AuthenticatedBrokerRequestDirectionV1::ServerReceive
        && request.method() == BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
        && request.storage_execution_capture_source_ongoing_v2()
            .is_some_and(|source| source == verified.source_v3())
        && effect.status() == aos_sandbox_broker::BrokerEffectStatusV1::Pending
        && effect.verb() == aos_sandbox_model::BrokerVerb::StorageReserveExecutionCapture
        && effect.request_id() == &request.request_id()
        && effect.request_digest().as_bytes() == &request.semantic_commitment()
        && effect.transport_request_digest() == aos_sandbox_model::ObjectDigest::from_bytes(
            sha2::Sha256::digest(request.exact_body()).into(),
        )
}

impl<'cut, 'original> super::super::lifecycle::StorageLifecycleSessionLoanV1<'cut, 'original> {
    /// Enters the Capture worker under its genuine verified ongoing admission.
    ///
    /// The whole signed Source944, actual request body and original effect must
    /// match. Actual currentness, durable attempt, physical catalog and policy
    /// checks remain upper obligations before fixed worker dispatch. The same
    /// existing ledger pays the READY and resident continuation before entry.
    ///
    /// # Errors
    /// Refuses another request/source/effect, changed actual Session, an occupied
    /// worker, arithmetic failure or exhausted same-original receiving capacity.
    pub fn borrow_capture_worker_flight_ongoing_v3<'flight>(
        &'flight mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        request: &AuthenticatedBrokerMethodRequestV1,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving_domain_v1(journal, socket)?;
        begin_actual_capture_flight_v3(receiving, request, verified, demand)
    }
}

impl<'flight, 'original> StoragePhysicalWorkerLoanV1<'flight, 'original> {
    /// Binds the actual Capture READY before its continuation may be parked.
    ///
    /// The caller allocates this one READY Arc only after the complete native
    /// flight has been consumed. Its identity is retained on the same original;
    /// a copied response, pid number or replacement Arc cannot resume the loan.
    ///
    /// # Errors
    /// Refuses wrong purpose, repeated binding or any existing worker check.
    pub fn bind_capture_once_v2<'worker>(
        mut self,
        socket: &'worker mut SeqpacketSocket,
        ready: &'worker Arc<ReceivedRecord>,
        cgroup: &'worker RetainedCgroupAnchor,
        population: &'worker CgroupPopulationMonitor,
        worker_path: &str,
    ) -> Result<StorageBoundPhysicalWorkerLoanV1<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        if self.state().kind != Some(WorkerKind::Capture)
            || self.state().capture_ready.is_some()
        {
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        self.state().capture_ready = Some(Arc::clone(ready));
        self.state().socket_binding = Some(socket.compare_worker_received_original_v1(ready));
        if !matches!(self.state().socket_binding, Some(Ok(()))) {
            self.state().first.get_or_insert(WorkerFailure::SocketBinding);
            let _ = self.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        self.bind(WorkerSocketV1::Zfs(socket), ready.subject(), cgroup, population,
            WorkerKind::Capture, worker_path)
    }
}

impl StorageBoundPhysicalWorkerLoanV1<'_, '_, '_> {
    /// Prepays the remaining finite helper-output allowance once on this F.
    ///
    /// The upper fixed Capture recipe must already have paid every co-live
    /// native/bookend/result/terminal obligation before reaching this phase.
    /// This late debit takes only the actual same-ledger unpromised OutputBytes;
    /// it cannot create another operation, renew a source or change a ceiling.
    /// The authenticated child receives only this restrictive scalar. Every
    /// requested read, including discarded output and an EOF probe, consumes
    /// its capacity before IO and never returns short-read credit.
    ///
    /// # Errors
    /// Refuses another worker kind, repeated entry, an unarmed independent post,
    /// an unhealthy original or an empty/unaffordable remaining allowance. The
    /// failed worker, operation and already owed post stay on this original.
    pub fn prepay_capture_drain_total_once_v3(&mut self)
        -> Result<u64, StorageReceivingClosedV1>
    {
        let receiving = self.flight.receiving.receiving()?;
        let state = &mut receiving.physical_worker;
        if !state.current() || state.kind != Some(WorkerKind::Capture)
            || !state.bound || state.capture_ready.is_none() || state.capture_resident
            || !matches!(state.post_preparation, Some(Ok(())))
            || state.capture_drain_remaining.is_some() || state.capture_drain_ceiling.is_some()
        {
            state.first.get_or_insert(WorkerFailure::CaptureDrain);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        state.capture_drain_remaining = Some(receiving.ledger.remaining());
        let Some(Ok(remaining)) = state.capture_drain_remaining.as_ref() else {
            state.first.get_or_insert(WorkerFailure::CaptureDrain);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        };
        let ceiling = remaining.get(D::OutputBytes);
        if ceiling == 0 {
            state.first.get_or_insert(WorkerFailure::CaptureDrain);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        state.capture_drain_reservation = Some(receiving.ledger.reserve(
            ResourceVector::ZERO.with(D::OutputBytes, ceiling),
        ).map_err(|cause| *cause));
        if !matches!(state.capture_drain_reservation, Some(Ok(()))) {
            state.first.get_or_insert(WorkerFailure::CaptureDrain);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        state.capture_drain_ceiling = Some(ceiling);
        Ok(ceiling)
    }

    /// Parks the occupied Capture flight without settling its physical debt.
    ///
    /// The caller retains the same socket, READY, aggregate anchor and
    /// population monitor. It may park during preparation to let its same State
    /// encoder commit the observed catalog. Parking proves no physical Ready,
    /// mounted files, handed-off pipes, EOF or terminal completion.
    /// It performs no IO, operation completion, post, refund or fresh admission.
    ///
    /// # Errors
    /// Refuses other purposes, failed or repeated parking, or absent READY.
    pub fn park_capture_once_v2(mut self) -> Result<StorageResidentCaptureWorkerV2, StorageReceivingClosedV1> {
        let state = self.flight.state();
        if !state.current() || state.kind != Some(WorkerKind::Capture)
            || state.capture_resident || !state.bound
        {
            let _ = self.flight.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        let Some(ready) = state.capture_ready.as_ref() else {
            state.first.get_or_insert(WorkerFailure::Closed);
            let _ = self.flight.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        };
        let resident = StorageResidentCaptureWorkerV2 {
            ready: Some(Arc::clone(ready)), completed: false,
        };
        state.capture_resident = true;
        self.flight.completed = true;
        Ok(resident)
    }
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Rejoins only this original's still-occupied physical Capture interval.
    ///
    /// No capacity is derived, reserved, copied or reset at this boundary.
    /// Independent endpoint and stream checks remain in the retained upper
    /// owner. Actual worker transport and aggregate continuity are rechecked.
    ///
    /// # Errors
    /// Refuses another resident, changed socket/anchor, prior native debt or a
    /// completed interval. A failure does not consume its armed post.
    pub fn resume_capture_worker_v2<'worker, 'flight>(
        &'flight mut self,
        resident: &'worker mut StorageResidentCaptureWorkerV2,
        socket: &'worker mut SeqpacketSocket,
        cgroup: &'worker RetainedCgroupAnchor,
        population: &'worker CgroupPopulationMonitor,
    ) -> Result<StorageCaptureWorkerBorrowV2<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        self.prepare_resume_capture_worker_v2(resident, socket, cgroup, population)?;
        Ok(StorageCaptureWorkerBorrowV2 {
            flight: StoragePhysicalWorkerLoanV1 { receiving: self, completed: false },
            socket, cgroup, population, resident,
        })
    }

    /// Rejoins the occupied Capture interval and attempts its owed post on refusal.
    ///
    /// Preparation performs every fallible check before constructing a loan.
    /// A refused preparation retains the actual native post in this original's
    /// existing post destinations before returning the original refusal.
    ///
    /// # Errors
    /// Refuses the same identity, currentness and native conditions as
    /// `resume_capture_worker_v2`; no failure grants positive disposal.
    pub fn resume_capture_worker_with_failed_post_v3<'worker, 'flight>(
        &'flight mut self,
        resident: &'worker mut StorageResidentCaptureWorkerV2,
        socket: &'worker mut SeqpacketSocket,
        cgroup: &'worker RetainedCgroupAnchor,
        population: &'worker CgroupPopulationMonitor,
    ) -> Result<StorageCaptureWorkerBorrowV2<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        if let Err(cause) = self.prepare_resume_capture_worker_v2(resident, socket, cgroup, population) {
            // The post owns its native Result in physical_worker.after and
            // post_result. Its coarse refusal cannot replace the earlier cause.
            let _ = self.finish_failed_capture_worker_v2(resident);
            return Err(cause);
        }
        Ok(StorageCaptureWorkerBorrowV2 {
            flight: StoragePhysicalWorkerLoanV1 { receiving: self, completed: false },
            socket, cgroup, population, resident,
        })
    }

    fn prepare_resume_capture_worker_v2(
        &mut self,
        resident: &StorageResidentCaptureWorkerV2,
        socket: &SeqpacketSocket,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut()
            else { return Err(StorageReceivingClosedV1) };
        let state = &mut receiving.physical_worker;
        let same = match (state.capture_ready.as_ref(), resident.ready.as_ref()) {
            (Some(original), Some(ready)) => Arc::ptr_eq(original, ready),
            _ => false,
        };
        if !same || resident.completed || !state.capture_resident
            || state.kind != Some(WorkerKind::Capture) || !state.current()
            || !self.original.open || receiving.first.is_some()
        {
            state.first.get_or_insert(WorkerFailure::Closed);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        // The same existing sampler buys its own actual interval on the same
        // monotone ledger; this is never a copied profile or a paid-status flag.
        let current = self.original.recheck();
        let positive = current.is_ok();
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut()
            else { std::process::abort() };
        let state = &mut receiving.physical_worker;
        state.capture_recheck = Some(current);
        if !positive {
            state.first.get_or_insert(WorkerFailure::CaptureCurrent);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        let Some(ready) = resident.ready.as_ref() else { std::process::abort() };
        state.socket_binding = Some(socket.compare_worker_received_original_v1(ready));
        state.aggregate_identity = Some(match state.aggregate_worker.anchor() {
            Some(anchor) if anchor.kernel_id() == cgroup.kernel_id() => Ok(()),
            _ => Err(StorageReceivingClosedV1),
        });
        state.population_owner = Some(population.require_same_cgroup(cgroup));
        state.alive = Some(ready.subject().pidfd().is_alive());
        for (positive, failure) in [
            (matches!(state.socket_binding, Some(Ok(()))), WorkerFailure::SocketBinding),
            (matches!(state.aggregate_identity, Some(Ok(()))), WorkerFailure::AggregateIdentity),
            (matches!(state.population_owner, Some(Ok(()))), WorkerFailure::PopulationOwner),
            (matches!(state.alive, Some(Ok(true))), WorkerFailure::Alive),
        ] {
            if !positive { state.first.get_or_insert(failure); }
        }
        if state.first.is_some() { return Err(StorageReceivingClosedV1); }
        Ok(())
    }

    /// Attempts the original prearmed Capture post even after primary failure.
    ///
    /// # Errors
    /// Always retains a negative interval and its actual post result; refuses
    /// another resident without sampling or reopening an admission gate.
    pub fn finish_failed_capture_worker_v2(
        &mut self, resident: &StorageResidentCaptureWorkerV2,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut()
            else { return Err(StorageReceivingClosedV1) };
        let same = match (receiving.physical_worker.capture_ready.as_ref(), resident.ready.as_ref()) {
            (Some(original), Some(ready)) => Arc::ptr_eq(original, ready),
            _ => false,
        };
        if !same || resident.completed || !receiving.physical_worker.capture_resident {
            return Err(StorageReceivingClosedV1);
        }
        if receiving.physical_worker.post_result.is_some() {
            return Err(StorageReceivingClosedV1);
        }
        StoragePhysicalWorkerLoanV1 { receiving: self, completed: false }
            .finish_failed_interval_v1()
    }
}

impl<'worker, 'flight, 'original> StorageCaptureWorkerBorrowV2<'worker, 'flight, 'original> {
    /// Lends the same actual worker channel under this exclusive original borrow.
    pub fn socket_mut_v2(&mut self) -> &mut SeqpacketSocket {
        self.socket
    }

    /// Reparks a still-live interval after one independently checked channel use.
    ///
    /// This preserves all native and financial destinations. It performs no
    /// completion and makes no assertion that either stream reached EOF.
    pub fn park_v2(mut self) {
        self.flight.completed = true;
    }

    /// Runs the shared death, population and prearmed post before retirement.
    ///
    /// The upper owner must already retain both real pipe EOFs, successful
    /// bounded file sync/readback, physical terminal and actual ACK/cleanup.
    ///
    /// # Errors
    /// Refuses a live/uncertain worker, native post failure, changed actual
    /// source or expired original ongoing/wall horizon after the final F post.
    pub fn prepare_positive_disposal_v2(self,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    ) -> Result<StorageCaptureWorkerDisposalV2<'worker, 'flight, 'original>, StorageReceivingClosedV1>
    {
        let Self { flight, socket: _, cgroup, population, resident } = self;
        let Some(ready) = resident.ready.as_ref() else { std::process::abort() };
        let native = flight.prepare_positive_disposal_native_v3(ready.subject(), cgroup, population, Some(verified))?;
        Ok(StorageCaptureWorkerDisposalV2 { native, resident })
    }
}

impl StorageCaptureWorkerDisposalV2<'_, '_, '_> {
    /// Completes after actual positive upper pipe/channel/result disposal.
    ///
    /// The original READY references retire before the existing infallible
    /// operation completion. No failed interval can reach this continuation.
    pub fn complete_after_disposal_v2(mut self) {
        let state = self.native.flight.state();
        if !state.capture_resident || state.kind != Some(WorkerKind::Capture) {
            std::process::abort();
        }
        drop(state.capture_ready.take());
        drop(self.resident.ready.take());
        state.capture_resident = false;
        self.resident.completed = true;
        self.native.complete_after_disposal_v1();
    }
}

impl Drop for StorageResidentCaptureWorkerV2 {
    fn drop(&mut self) {
        if !self.completed {
            // The actual original and worker must remain resident on refusal.
            // Silently abandoning this token would release a live native prefix.
            std::process::abort();
        }
    }
}

fn begin_actual_capture_flight_v3<'flight, 'original>(
    receiving: &'flight mut StoragePrepareReceivingLoanV1<'original>,
    request: &AuthenticatedBrokerMethodRequestV1,
    verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    demand: ResourceVector,
) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        if !matches_actual_capture_request_v3(request, verified) {
            receiving.receiving()?.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let Some(resident) = resident_representation_v2() else {
            receiving.receiving()?.first.get_or_insert(Failure::Arithmetic);
            return Err(StorageReceivingClosedV1);
        };
        let complete = demand.checked_add(resident);
        if complete.is_err() {
            let original = receiving.receiving()?;
            original.physical_worker.shape = Some(complete);
            original.physical_worker.first.get_or_insert(WorkerFailure::Shape);
            original.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        let Ok(complete) = complete else { std::process::abort() };
        let mut flight = receiving.begin_physical_worker_v1(WorkerKind::Capture, complete)?;
        flight.state().capture_source = Some((verified.source_v3().source_digest_v2(), verified.ongoing_deadline_v3()));
        // The actual signed60 State borrower paid and armed cancellation
        // before the first effect. This boundary cannot reserve/rearm it.
        if flight.receiving.require_capture_stop_liability_v4(verified).is_err() {
            flight.state().first.get_or_insert(WorkerFailure::CaptureStop);
            let _ = flight.finish_failed_interval_v1();
            return Err(StorageReceivingClosedV1);
        }
        Ok(flight)
}

impl<'original> super::super::state_recovery::StorageStateRecoveryEncodingLoanV1<'_, 'original> {
    /// Lends the same paid State interval to its exact ongoing Capture worker.
    ///
    /// The actual signed60 and Native verified lifetime select the same closed
    /// flight used by the Session adapter. Parking releases its nested borrow
    /// so this State interval can commit the observed catalog before mounting.
    /// No second State operation, physical readiness or capacity is created.
    ///
    /// # Errors
    /// Refuses an initial/unpaid State interval, replaced writer or Session,
    /// wrong signed60/lifetime, occupied flight or actual original refusal.
    pub fn borrow_capture_worker_flight_ongoing_v3<'flight>(
        &'flight mut self,
        state: &crate::Journal,
        request: &AuthenticatedBrokerMethodRequestV1,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
        demand: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving_capture_worker_v3(state)?;
        begin_actual_capture_flight_v3(receiving, request, verified, demand)
    }

    /// Reborrows this State interval's still-occupied actual Capture worker.
    ///
    /// # Errors
    /// Refuses a closed State interval or any existing same-original, READY,
    /// socket, cgroup, native currentness or resident identity check.
    pub fn resume_capture_worker_v3<'worker, 'flight>(
        &'flight mut self,
        state: &crate::Journal,
        resident: &'worker mut StorageResidentCaptureWorkerV2,
        socket: &'worker mut SeqpacketSocket,
        cgroup: &'worker RetainedCgroupAnchor,
        population: &'worker CgroupPopulationMonitor,
    ) -> Result<StorageCaptureWorkerBorrowV2<'worker, 'flight, 'original>, StorageReceivingClosedV1> {
        self.receiving_capture_worker_v3(state)?.resume_capture_worker_v2(
            resident, socket, cgroup, population,
        )
    }
}


impl StorageCaptureWorkerBorrowV2<'_, '_, '_> {
    fn require_capture_writers_v3(
        &mut self, state: &crate::Journal, output: &crate::Journal,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    ) -> Result<(), StorageReceivingClosedV1> {
        // `Self` exists only after the actual READY Arc/socket/cgroup/original
        // resume. The initial signed60 association stays immutable beyond its
        // short Session interval; no new operation or effect is admitted here.
        let receiving = self.flight.receiving.receiving()?;
        let physical = &mut receiving.physical_worker;
        if !physical.current() || !physical.capture_resident || physical.kind != Some(WorkerKind::Capture)
            || physical.capture_source != Some((verified.source_v3().source_digest_v2(), verified.ongoing_deadline_v3()))
            || !receiving.startup.state_recovery_ready_v1(state)
            || !receiving.startup.output_currentness_ready_v1(output)
        {
            physical.first.get_or_insert(WorkerFailure::Closed);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Pays reached retained catalog/terminal models on the same occupied F.
    ///
    /// The cost is passive representation DATA from the sole actual held model
    /// supplier. This method grants no append, State operation, worker, EOF or
    /// terminal authority. Existing Source/attempt/native owners remain held.
    /// Reached resident bounds accumulate and every traffic term is debited;
    /// there is no operation reset, refund or copied budget.
    ///
    /// # Errors
    /// Refuses changed actual writers/source, closed native occupancy, invalid
    /// dimensions or the same ledger's sticky checked capacity refusal.
    pub fn reserve_capture_terminal_models_v3(
        &mut self, state: &crate::Journal, output: &crate::Journal,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_capture_writers_v3(state, output, verified)?;
        let shape = ResourceVector::ZERO.with(D::MemoryBytes, demand.get(D::MemoryBytes))
            .with(D::MetadataEntries, demand.get(D::MetadataEntries))
            .with(D::OpenFiles, demand.get(D::OpenFiles))
            .with(D::StorageBytes, demand.get(D::StorageBytes))
            .with(D::OutputBytes, demand.get(D::OutputBytes))
            .with(D::NetworkBytes, demand.get(D::NetworkBytes));
        let receiving = self.flight.receiving.receiving()?;
        let physical = &mut receiving.physical_worker;
        if demand != shape {
            physical.first.get_or_insert(WorkerFailure::Closed);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        physical.capture_representation_growth = Some((|| {
            use aos_sandbox_model::component_receiving::{without_operation_traffic_v1, operation_traffic_demand_v1};
            let bound = physical.capture_representation_bound.checked_add(without_operation_traffic_v1(demand))?;
            let (highwater, resident_delta) = complete_bound_delta_v1(physical.capture_representation_highwater, bound)?;
            let delta = resident_delta.checked_add(operation_traffic_demand_v1(demand))?;
            Ok((bound, highwater, delta))
        })());
        let Some((bound, highwater, delta)) = physical.capture_representation_growth.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            physical.first.get_or_insert(WorkerFailure::CaptureRepresentation);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        };
        physical.capture_representation_payment = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(physical.capture_representation_payment, Some(Ok(()))) {
            physical.first.get_or_insert(WorkerFailure::CaptureRepresentation);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        physical.capture_representation_bound = bound;
        physical.capture_representation_highwater = highwater;
        Ok(())
    }

    /// Pays the canonical full676 terminal append through the held Output engine.
    ///
    /// The one record shape is the actual existing AOSCCD02 envelope, not a
    /// caller-selected record/transaction. Native provenance and all owed posts
    /// remain upper prerequisites to entering its private commit engine.
    ///
    /// # Errors
    /// Refuses a different State/Output/source, unavailable actual append
    /// geometry or exhausted same-original capacity before encoder growth.
    pub fn reserve_capture_complete_append_v3(
        &mut self, state: &crate::Journal, output: &crate::Journal,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_capture_writers_v3(state, output, verified)?;
        let demand = output.append_receiving_demand_v1(std::iter::once(
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: 17,
                value_bytes: Some(8 + aos_sandbox_protocol::storage_capture_result::CAPTURE_COMPLETE_RECORD_BYTES_V2 + 32),
            },
        ));
        let receiving = self.flight.receiving.receiving()?;
        receiving.physical_worker.capture_append_demand = Some(demand);
        let Some(demand) = receiving.physical_worker.capture_append_demand.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            receiving.physical_worker.first.get_or_insert(WorkerFailure::CaptureRepresentation);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        };
        self.reserve_capture_terminal_models_v3(state, output, verified, demand)
    }
}


impl StorageCaptureWorkerBorrowV2<'_, '_, '_> {
    /// Arms the same Output observer from this actual occupied Capture owner.
    ///
    /// The live READY/socket/cgroup resume and exact State/Output/full Source
    /// association replace the expired initial60 Session as this closed lender.
    /// This neither admits another effect nor creates or renews any lifetime.
    ///
    /// # Errors
    /// Refuses replaced writers/source, an unoccupied original or native debt.
    pub fn arm_capture_output_after_v3(&mut self, state: &crate::Journal,
        output: &crate::Journal, verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
        source: &std::path::Path, original: &mut super::super::lifecycle::StorageOutputOwedAfterOriginalV1)
        -> Result<(), StorageReceivingClosedV1> {
        let binding = self.require_capture_writers_v3(state, output, verified);
        self.flight.receiving.arm_output_owed_after_v1_inner_v3(binding, output, source, original)
    }

    /// Observes this resident's already-owed Output names after primary poison.
    ///
    /// # Errors
    /// Retains substituted originals, repeated entry and actual native errors.
    pub fn observe_capture_output_names_v3(&mut self,
        original: &mut super::super::lifecycle::StorageOutputOwedAfterOriginalV1,
        output: &crate::Journal, names: &mut crate::journal::ProtectedJournalCurrentnessOriginalsV1,
        health: &mut Option<Result<(), crate::JournalError>>) -> Result<(), crate::JournalError> {
        self.flight.receiving.observe_output_owed_names_once_v1_inner_v3(original, output, names, health)
    }

    /// Finishes only the observer armed by this same resident original.
    ///
    /// # Errors
    /// Retains missing/mismatched debt and actual observer failure.
    pub fn finish_capture_output_after_v3(&mut self,
        original: &mut super::super::lifecycle::StorageOutputOwedAfterOriginalV1)
        -> Result<(), StorageReceivingClosedV1> {
        self.flight.receiving.finish_output_owed_after_once_v1_inner_v3(original)
    }

    /// Closes the same occupied original without discarding its owed observer.
    pub fn close_capture_output_currentness_v3(&mut self) {
        self.flight.receiving.close_output_owed_currentness_v1_inner_v3();
    }
}


impl StorageCaptureWorkerBorrowV2<'_, '_, '_> {
    /// Runs the original physical post after a refused held Capture interval.
    ///
    /// This closes the same occupied original without consuming or disposing
    /// its resident READY, worker, pipe aliases or retained native failures.
    ///
    /// # Errors
    /// Retains the primary and every actual independently owed post failure.
    pub fn finish_failed_capture_interval_v3(self) -> Result<(), StorageReceivingClosedV1> {
        self.flight.finish_failed_interval_v1()
    }
}

impl StorageCaptureWorkerDisposalV2<'_, '_, '_> {
    /// Compares this actual positive-disposal token to its original full source.
    ///
    /// This performs only retained DATA comparisons. It grants no work or
    /// deadline and cannot construct or substitute a physical disposal token.
    ///
    /// # Errors
    /// Refuses a different source/horizon or an absent occupied Capture owner.
    pub fn require_capture_original_v3(&mut self,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3)
        -> Result<(), StorageReceivingClosedV1> {
        let state = self.native.flight.state();
        if !state.capture_resident || state.kind != Some(WorkerKind::Capture)
            || state.capture_source != Some((verified.source_v3().source_digest_v2(), verified.ongoing_deadline_v3()))
        { return Err(StorageReceivingClosedV1); }
        Ok(())
    }
}


impl StorageCaptureWorkerBorrowV2<'_, '_, '_> {
    /// Observes actual worker death and empty population before publishing676.
    ///
    /// The same READY pidfd and privately associated aggregate monitor are
    /// continuously held. This one-shot native sample grants no disposal;
    /// final death/population and the original independent F post remain owed.
    /// Its bytes and primitive/native results stay on this genuine original.
    ///
    /// # Errors
    /// Refuses repeated/foreign/unoccupied work, live or uncertain pidfd,
    /// nonempty population, and actual native read/parse failures.
    pub fn observe_capture_precommit_quiescence_v3(&mut self) -> Result<(), StorageReceivingClosedV1> {
        let state = self.flight.state();
        if !state.current() || !state.capture_resident || state.kind != Some(WorkerKind::Capture)
            || state.capture_quiescence_entered { return Err(StorageReceivingClosedV1); }
        state.capture_quiescence_entered = true;
        let Some(ready) = self.resident.ready.as_ref() else { return Err(StorageReceivingClosedV1); };
        // Both observations enter independently through the sole native
        // death/population recipe, also used by fresh Stop containment.
        super::capture_stop::observe_quiescence_native_v4(ready, self.population,
            &mut state.capture_quiescence_alive, &mut state.capture_quiescence_population,
            &mut state.capture_quiescence_population_result);
        let positive = matches!(state.capture_quiescence_population_result, Some(Ok(())))
            && capture_quiescence_data_v3(state.capture_quiescence_alive.as_ref()
                .and_then(|result| result.as_ref().ok()).copied(), state.capture_quiescence_population.state());
        state.capture_quiescence_result = Some(if positive { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !positive {
            state.first.get_or_insert(WorkerFailure::CaptureQuiescence);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }
}


// Comparison DATA only: only the actual resident sampler supplies the native
// inputs above. This function cannot create a receiving or completion owner.
pub(super) fn capture_quiescence_data_v3(alive: Option<bool>, population: Option<CgroupPopulationState>) -> bool {
    alive == Some(false) && matches!(population, Some(CgroupPopulationState::Empty | CgroupPopulationState::Retired))
}

#[cfg(test)]
mod capture_quiescence_tests {
    use super::*;

    #[test]
    fn report_or_dead_leader_alone_cannot_publish_complete() {
        assert!(!capture_quiescence_data_v3(Some(true), Some(CgroupPopulationState::Empty)));
        assert!(!capture_quiescence_data_v3(Some(false), Some(CgroupPopulationState::Populated)));
        assert!(!capture_quiescence_data_v3(None, Some(CgroupPopulationState::Empty)));
        assert!(!capture_quiescence_data_v3(Some(false), None));

        assert!(capture_quiescence_data_v3(Some(false), Some(CgroupPopulationState::Empty)));
        assert!(capture_quiescence_data_v3(Some(false), Some(CgroupPopulationState::Retired)));
    }
}
