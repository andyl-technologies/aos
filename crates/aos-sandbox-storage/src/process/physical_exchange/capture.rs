//! Holds the actual Capture READY/create report through the next catalog turn.
//!
//! This closed branch shares the existing worker setup and bounded exchange
//! engines. It parks the SAME F interval after verified create readback; no
//! ACK, worker death, physical Ready or result retirement follows this stage.

use super::*;
mod mounted;
mod terminal;
mod held;
mod stop_cleanup;
use mounted::CaptureMountedParentOriginalV3;
use std::sync::Arc;
use aos_sandbox::{StorageResidentCaptureWorkerV2, StorageStateRecoveryEncodingLoanV1};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3;
use crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3;

// Construction is exclusive to the actual received-report join below. The
// inner DATA parser cannot produce this owning native-context witness.
pub(crate) struct NativeCaptureCreatedReadbackV3 {
    observed: CaptureCreatedDatasetReadbackV3,
    source: aos_sandbox_core::ObjectDigest,
    durable_attempt: aos_sandbox_core::ObjectDigest,
}

impl NativeCaptureCreatedReadbackV3 {
    pub(crate) fn observed_v3(&self) -> &CaptureCreatedDatasetReadbackV3 { &self.observed }

    pub(crate) fn require_native_v3(&self, native: &NativeCaptureCreateOriginalV3)
        -> Result<(), crate::StorageStateError>
    {
        if self.source != native.admission_v3().source_v3().source_digest_v2()
            || self.durable_attempt != native.durable_attempt_digest_v3()
        { return Err(crate::StorageStateError::AuthorityLinkMismatch); }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CaptureFailureV3 { Shape, Native, Encoding, Setup, Drain, Report, Decode, Park, Catalog, Physical, Mounted, Held, Stop }

pub(crate) struct CapturePhysicalPreparationOriginalV3 {
    native: NativeCaptureCreateOriginalV3,
    exchange: PhysicalWorkerFailureV1,
    ready: Option<Arc<ReceivedRecord>>,
    resident: Option<Result<StorageResidentCaptureWorkerV2, StorageReceivingClosedV1>>,
    shape: Option<Result<ResourceVector, ZfsWorkerError>>,
    drain: Option<Result<u64, StorageReceivingClosedV1>>,
    created: Option<Result<NativeCaptureCreatedReadbackV3, ZfsWorkerError>>,
    catalog: crate::state::CaptureStateCatalogOriginalV3,
    catalog_result: Option<Result<(), crate::StorageStateError>>,
    physical: crate::execution_output::CapturePhysicalBindingOriginalV3,
    physical_result: Option<Result<(), crate::execution_output::ExecutionOutputLedgerErrorV1>>,
    mounted: CaptureMountedParentOriginalV3,
    terminal: terminal::CaptureNativeTerminalOriginalV3,
    held: held::CaptureHeldNativeOriginalV3,
    stop: stop_cleanup::CaptureStopCleanupOriginalV4,
    first: Option<CaptureFailureV3>,
    entered: bool,
}

impl CapturePhysicalPreparationOriginalV3 {
    pub(crate) fn mounted_preparation_completed_v3(&self) -> bool {
        self.first.is_none() && !self.stop.entered_v4() && self.mounted.completed_v3()
            && matches!(self.resident, Some(Ok(_)))
            && matches!(self.catalog_result, Some(Ok(()))) && matches!(self.physical_result, Some(Ok(())))
    }

    pub(crate) fn require_response_clock_v3(&self, clock: &aos_sandbox_core::RawPairedClockSample)
        -> Result<(), aos_sandbox_broker::BrokerAdmissionError>
    {
        let lifetime = self.native.admission_v3().lifetime_v3();
        lifetime.require_ongoing_clock_v3(clock)?;
        if clock.boottime_nanoseconds() >= lifetime.acquisition_deadline_v3() {
            return Err(aos_sandbox_broker::BrokerAdmissionError::FenceRejected);
        }
        Ok(())
    }

    pub(crate) fn new(native: NativeCaptureCreateOriginalV3, stop_inspection_bytes: usize) -> Self {
        Self { native, exchange: PhysicalWorkerFailureV1::new(), ready: None,
            resident: None, shape: None, drain: None, created: None,
            catalog: crate::state::CaptureStateCatalogOriginalV3::new(), catalog_result: None,
            physical: crate::execution_output::CapturePhysicalBindingOriginalV3::new(),
            physical_result: None, mounted: CaptureMountedParentOriginalV3::new(), terminal: terminal::CaptureNativeTerminalOriginalV3::new(), held: held::CaptureHeldNativeOriginalV3::new(), stop: stop_cleanup::CaptureStopCleanupOriginalV4::new(stop_inspection_bytes), first: None, entered: false }
    }

    pub(crate) fn created_v3(&self) -> Option<&NativeCaptureCreatedReadbackV3> {
        if self.first.is_some() || !matches!(self.resident, Some(Ok(_))) { return None; }
        self.created.as_ref()?.as_ref().ok()
    }

    pub(crate) fn begin_create_once_v3(
        &mut self,
        executor: &SystemdZfsExecutor,
        request: &AuthenticatedBrokerMethodRequestV1,
        state: &aos_sandbox::Journal,
        receiving: &mut StorageStateRecoveryEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(ZfsWorkerError::Authority); }
        self.entered = true;
        self.first = Some(CaptureFailureV3::Shape);
        self.shape = Some(self.receiving_demand_v3().ok_or(ZfsWorkerError::Authority));
        let Some(demand) = self.shape.as_ref().and_then(|result| result.as_ref().ok()).copied() else { return Err(worker_entry::retained()); };
        self.first = Some(CaptureFailureV3::Native);
        let mut flight = match receiving.borrow_capture_worker_flight_ongoing_v3(
            state, request, self.native.admission_v3().lifetime_v3(), demand,
        ) {
            Ok(flight) => flight,
            Err(refusal) => {
                self.exchange.native = Some(Err(refusal));
                self.exchange.first = Some(Failure::Native);
                return Err(worker_entry::retained());
            }
        };
        if flight.require_shape_v1(demand).is_err() {
            self.exchange.first.get_or_insert(Failure::Native);
            self.exchange.native = Some(flight.finish_failed_interval_v1());
            return Err(worker_entry::retained());
        }
        // The transport's original fixed opening timeout can only tighten the
        // persisted lifetime. It cannot renew the ongoing source horizon.
        let deadline = Deadline::after(CONNECTION_TIMEOUT);
        self.exchange.deadline = Some(u64::try_from(deadline.0.as_nanos()));
        let Some(Ok(deadline)) = self.exchange.deadline.as_ref().copied() else {
            self.exchange.first = Some(Failure::Deadline);
            self.exchange.native = Some(flight.finish_failed_interval_v1());
            return Err(worker_entry::retained());
        };
        let deadline = deadline.min(self.native.admission_v3().lifetime_v3().ongoing_deadline_v3());
        self.first = Some(CaptureFailureV3::Setup);
        self.exchange.setup_capture_v3(executor, deadline);
        if self.exchange.first.is_some() {
            self.exchange.native = Some(flight.finish_failed_interval_v1());
            return Err(worker_entry::retained());
        }
        let Some(Ok(ready)) = self.exchange.ready.take() else { std::process::abort(); };
        self.ready = Some(Arc::new(ready));
        let Some(ready) = self.ready.as_ref() else { std::process::abort(); };
        let Some(Ok(socket)) = self.exchange.connection.as_mut() else { std::process::abort(); };
        let Some(anchor) = self.exchange.cgroup.anchor() else { std::process::abort(); };
        let Some(population) = self.exchange.cgroup.population() else { std::process::abort(); };
        let path = decode_selected_ready_v1(ready.payload())?;
        let mut bound = match flight.bind_capture_once_v2(socket, ready, anchor, population, path) {
            Ok(bound) => bound,
            Err(refusal) => {
                self.exchange.native = Some(Err(refusal));
                self.exchange.first = Some(Failure::Native);
                return Err(worker_entry::retained());
            }
        };
        // All finite later worker/Host replies are included in the consumed
        // complete flight above. State append pays its own native/byte recipe
        // and has no OutputBytes debit. Only now take the exact unpromised F
        // output remainder as a restrictive total drain allowance, never a new
        // ledger, timeout, stored-output limit or refundable balance.
        self.first = Some(CaptureFailureV3::Drain);
        self.drain = Some(bound.prepay_capture_drain_total_once_v3());
        let Some(ceiling) = self.drain.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.exchange.native = Some(bound.finish_failed_interval_v1());
            return Err(worker_entry::retained());
        };
        self.first = Some(CaptureFailureV3::Encoding);
        self.exchange.encoding = Some(capture_worker::wire::encode_from_native_v3(
            &self.native, ceiling, &mut self.exchange.request,
        ));
        if !matches!(self.exchange.encoding, Some(Ok(()))) {
            self.exchange.native = Some(bound.finish_failed_interval_v1());
            return Err(worker_entry::retained());
        }
        self.first = Some(CaptureFailureV3::Report);
        let channel = bound.zfs_socket_mut_v1().map_err(|_| worker_entry::retained())?;
        self.exchange.traffic.run_capture_created_v3(channel, &self.exchange.request,
            ready.subject(), anchor, population, deadline);
        if self.exchange.traffic.first.is_some() {
            self.exchange.native = Some(bound.finish_failed_interval_v1());
            return Err(worker_entry::retained());
        }
        let Some(Ok(response)) = self.exchange.traffic.response.as_ref() else { std::process::abort(); };
        self.first = Some(CaptureFailureV3::Decode);
        self.created = Some(capture_worker::wire::decode_created_data_v3(
            response.payload(), &self.exchange.request, &self.native,
        ).map(|observed| NativeCaptureCreatedReadbackV3 {
            observed, source: self.native.admission_v3().source_v3().source_digest_v2(),
            durable_attempt: self.native.durable_attempt_digest_v3(),
        }));
        if !matches!(self.created, Some(Ok(_))) {
            self.exchange.native = Some(bound.finish_failed_interval_v1());
            return Err(worker_entry::retained());
        }
        self.first = Some(CaptureFailureV3::Park);
        self.resident = Some(bound.park_capture_once_v2());
        if !matches!(self.resident, Some(Ok(_))) { return Err(worker_entry::retained()); }
        self.first = None;
        Ok(())
    }

    pub(crate) fn commit_catalog_once_v3(
        &mut self,
        store: &mut crate::StorageTransactionStore,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut StorageStateRecoveryEncodingLoanV1<'_, '_>,
    ) -> Result<(), crate::StorageStateError> {
        if self.first.is_some() || self.catalog_result.is_some()
            || !matches!(self.resident, Some(Ok(_)))
        { return Err(crate::StorageStateError::Receiving); }
        let Some(Ok(created)) = self.created.as_ref() else {
            return Err(crate::StorageStateError::Receiving);
        };
        self.first = Some(CaptureFailureV3::Catalog);
        self.catalog_result = Some(self.catalog.commit_once_v3(store, &self.native, created, receiving));
        if !matches!(self.catalog_result, Some(Ok(()))) { return Err(crate::StorageStateError::Receiving); }
        self.first = Some(CaptureFailureV3::Physical);
        self.physical_result = Some(store.bind_capture_output_dataset_v3(
            output, &mut self.physical, &self.native, &self.catalog, receiving,
        ));
        if !matches!(self.physical_result, Some(Ok(()))) { return Err(crate::StorageStateError::Receiving); }
        self.first = None;
        Ok(())
    }

    fn receiving_demand_v3(&self) -> Option<ResourceVector> {
        let source = self.native.admission_v3().source_v3().original_source_v1();
        let (_, stdout_maximum, stderr_maximum) = source.output_limits();
        let retained_payload = crate::execution_capture_files::capture_retained_payload_bytes_v3(
            stdout_maximum, stderr_maximum,
        )?;
        let allocation = source.space_policy().0;
        // The reservation contains the claim and both streams. Charge the
        // entire protected allocation once; file payloads are within it, not
        // an additional reservation. A space policy that cannot contain the
        // actual marker plus stream ceilings refuses before worker entry.
        if allocation < retained_payload { return None; }
        let (connection_bytes, connection_files) = SeqpacketSocket::storage_worker_admission_obligations_v3()?;
        let (ready_bytes, ready_files) = zfs_worker_record_obligations_v1(ZfsWorkerRecordKindV1::Ready)?;
        let (report_bytes, report_files) = zfs_worker_record_obligations_v1(ZfsWorkerRecordKindV1::MutationResult)?;
        // Three distinct reached responses are Created, mounted/files Ready,
        // and native Complete. Three parent bodies are request, catalog and
        // terminal; the final existing ACK is separate. All remain paid while
        // the occupied F continuation survives the method60 response.
        let parent_frames = MAXIMUM_REQUEST_BYTES.checked_mul(3)?.checked_add(MAXIMUM_ACK_BYTES)?;
        let worker_frames = MAXIMUM_READY_BYTES.checked_add(capture_worker::wire::CREATED_BYTES_V3)?
            .checked_add(capture_worker::wire::MOUNTED_BYTES_V3)?
            .checked_add(capture_worker::wire::COMPLETED_BYTES_V3)?;
        let host_frames = aos_sandbox_protocol::storage_capture_session::CAPTURE_PROOF_BYTES_V2
            .checked_add(aos_sandbox_protocol::storage_capture_session::CAPTURE_ACK_BYTES_V2)?;
        let output = parent_frames.checked_add(worker_frames)?.checked_add(host_frames)?
            .checked_add(worker_aggregate::WorkerAggregateV1::capture_tool_output_bytes_v3()?)?;
        let network = parent_frames.checked_add(worker_frames)?.checked_add(host_frames)?
            .checked_add(aos_sandbox_protocol::storage_capture_session::ongoing::CAPTURE_BEGIN_BYTES_V3)?
            .checked_add(aos_sandbox_protocol::storage_capture_session::CAPTURE_TERMINAL_BYTES_V2)?
            .checked_add(4 * 80)?;
        let (pipes_bytes, pipes_files) = SeqpacketSocket::capture_worker_pipes_obligations_v3()?;
        let (held_bytes, held_files) = held::CaptureHeldNativeOriginalV3::receiving_geometry_v3()?;
        let memory = 2usize.checked_mul(std::mem::size_of::<Self>())?
            .checked_add(held_bytes)?
            .checked_add(connection_bytes)?.checked_add(ready_bytes)?.checked_add(3 * report_bytes)?
            .checked_add(pipes_bytes)?
            .checked_add(3 * MAXIMUM_REQUEST_BYTES)?
            .checked_add(2 * WorkerCgroupOpeningV1::dominant_requested_bytes_v1()?)?
            .checked_add(4 * ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(worker_aggregate::WorkerAggregateV1::capture_fork_requested_bytes_v3()?)?
            .checked_add(capture_worker::receiving_bytes_v3()?)?
            .checked_add(crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::<4>::receiving_bytes_v3()?)?;
        let files = connection_files.checked_add(held_files)?.checked_add(ready_files)?.checked_add(3 * report_files)?
            .checked_add(pipes_files)?
            .checked_add(2 * WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1)?
            .checked_add(4 * ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?
            // All child and parent paired native reservoirs stay paid. Their
            // positive primitive files retire in the shared clock engine;
            // every actually failed sample still owns its reached prefix.
            .checked_add(crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::<41>::maximum_retained_files_v3()?)?
            .checked_add(128 + 128)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::MetadataEntries, u64::try_from(worker_aggregate::WorkerAggregateV1::capture_fork_metadata_entries_v3()
                // One real ZFS dataset plus exclusive claim/stdout/stderr names.
                // Pipe/stat/result carriers add bytes, not namespace entries.
                .checked_add(4)?
                // The additional fixed Host path has two components and its
                // active cgroup.procs name; carrier fields add no namespaces.
                .checked_add(std::path::Path::new("system.slice/aos-sandbox-hostd.service").components().count())?
                .checked_add(1)?).ok()?)
            .with(D::ConcurrentOperations, 1)
            .with(D::StorageBytes, allocation)
            .with(D::OutputBytes, u64::try_from(output).ok()?)
            .with(D::NetworkBytes, u64::try_from(network).ok()?))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            CaptureFailureV3::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureFailureV3::Native | CaptureFailureV3::Setup => self.exchange.failure(),
            CaptureFailureV3::Encoding => self.exchange.encoding.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureFailureV3::Drain => self.drain.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureFailureV3::Report => self.exchange.traffic.failure(),
            CaptureFailureV3::Decode => self.created.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureFailureV3::Physical => self.physical.failure()
                .or_else(|| self.physical_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            CaptureFailureV3::Catalog => self.catalog.failure()
                .or_else(|| self.catalog_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            CaptureFailureV3::Mounted => self.mounted.failure(),
            CaptureFailureV3::Held => self.held.failure().or_else(|| self.terminal.failure()),
            CaptureFailureV3::Stop => self.stop.failure_without_native_v4(&self.mounted),
            CaptureFailureV3::Park => self.resident.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}


impl CapturePhysicalPreparationOriginalV3 {
    pub(crate) fn native_complete_record_v3(&self)
        -> Option<aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2> {
        if self.first.is_some() { return None; }
        self.terminal.completed_v3()
    }
}
