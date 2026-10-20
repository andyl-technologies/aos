//! Connects the actual catalog observer to the same paid physical worker loan.
//!
//! This owns selected disposition of the existing one-shot worker protocol.
//! Frame codecs, native sends/receives, subject/membership predicates, reply
//! interpretation and exact termination share the ordinary engines. Payment
//! precedes request cloning, owner allocation, connection and all native IO.

use super::*;
use crate::pin_worker::frame_send::WorkerFrameSendOriginalV1;
use crate::process::receiving_stage::StoragePhysicalWorkerStageV1;
use aos_sandbox::{StorageReceivingClosedV1, StoragePhysicalWorkerLoanV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{ExactCgroupMembershipReadbackV1, WorkerCgroupOpeningV1, WorkerCgroupOpeningRefusalV1};
use aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1;
use aos_sandbox_linux::seqpacket::bounded::{
    WorkerObserverReceiveErrorV1, DescriptorWorkerSendAttemptV1, DescriptorWorkerSendKindV1,
    descriptor_worker_record_obligations_v1, receive_worker_observer_record_v1,
    send_descriptor_worker_record_v1,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::WorkerObserverRecordKindV1;

#[derive(Clone, Copy)]
enum DescriptorPlanV1<'a> {
    Catalog(&'a WorkspaceCatalogObservationRequestV1),
    Pin(&'a crate::workspace_pin::WorkspacePinAttemptV1),
    Repair(super::repair_validation::RepairPlanV1<'a>),
    GuestRoot(&'a crate::guest_root_attempt::GuestRootPublicationAttemptV2),
    GuestRootStartupHealth,
}

impl DescriptorPlanV1<'_> {
    fn guest_root(self) -> bool { matches!(self, Self::GuestRoot(_) | Self::GuestRootStartupHealth) }

    fn exports_mount(self) -> bool {
        matches!(self, Self::Catalog(request) if request.exports_mount())
    }

    fn response_kind(self) -> WorkerObserverRecordKindV1 {
        match self {
            Self::Catalog(request) if request.exports_mount() => WorkerObserverRecordKindV1::ExportReply,
            Self::Catalog(_) => WorkerObserverRecordKindV1::ReadyOrResult,
            Self::Pin(_) | Self::Repair(_) => WorkerObserverRecordKindV1::PinResult,
            Self::GuestRoot(_) => WorkerObserverRecordKindV1::GuestRootPublicationResultV2,
            Self::GuestRootStartupHealth => WorkerObserverRecordKindV1::GuestRootStartupHealthV2,
        }
    }

    fn maximum_response_bytes(self) -> usize {
        match self {
            Self::Catalog(_) => MAXIMUM_CATALOG_OBSERVATION_RESULT_BYTES,
            Self::Pin(_) | Self::Repair(_) => MAXIMUM_PIN_WORKER_RESULT_BYTES,
            Self::GuestRoot(_) => 274,
            Self::GuestRootStartupHealth => crate::guest_root_worker::HEALTH_RESULT_MAGIC.len(),
        }
    }
}

enum DescriptorResultV1 {
    Catalog(WorkspaceCatalogObservationResultV1),
    Pin(WorkspacePinWorkerResultV1),
    Repair(super::repair_validation::RepairResultV1),
    GuestRoot(aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1),
    GuestRootStartupHealth,
}

enum DescriptorValidationOriginalV1 {
    Catalog(catalog_validation::CatalogResultOriginalV1),
    Pin(super::pin_validation::PinResultOriginalV1),
    Repair(super::repair_validation::RepairResultOriginalV1),
    GuestRoot(super::guest_root_validation::GuestRootResultOriginalV2),
}

impl DescriptorValidationOriginalV1 {
    fn new(plan: DescriptorPlanV1<'_>) -> Self {
        match plan {
            DescriptorPlanV1::Catalog(_) => Self::Catalog(catalog_validation::CatalogResultOriginalV1::new()),
            DescriptorPlanV1::Pin(_) => Self::Pin(super::pin_validation::PinResultOriginalV1::new()),
            DescriptorPlanV1::Repair(plan) => Self::Repair(super::repair_validation::RepairResultOriginalV1::new(plan)),
            DescriptorPlanV1::GuestRoot(_) | DescriptorPlanV1::GuestRootStartupHealth => Self::GuestRoot(super::guest_root_validation::GuestRootResultOriginalV2::new()),
        }
    }

    fn observe_once(
        &mut self,
        response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject,
        plan: DescriptorPlanV1<'_>,
        anchor: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        match (self, plan) {
            (Self::Catalog(original), DescriptorPlanV1::Catalog(request)) => {
                original.observe_once(response, ready, request, anchor)
            }
            (Self::Pin(original), DescriptorPlanV1::Pin(attempt)) => {
                original.observe_once(response, ready, attempt, anchor)
            }
            (Self::Repair(original), DescriptorPlanV1::Repair(plan)) => {
                original.observe_once(response, ready, plan, anchor)
            }
            (Self::GuestRoot(original), DescriptorPlanV1::GuestRoot(attempt)) => {
                original.observe_once(response, ready, Some(attempt), anchor)
            }
            (Self::GuestRoot(original), DescriptorPlanV1::GuestRootStartupHealth) => {
                original.observe_once(response, ready, None, anchor)
            }
            _ => Err(ZfsWorkerError::Authority),
        }
    }

    fn take_positive(&mut self) -> Option<DescriptorResultV1> {
        match self {
            Self::Catalog(original) => original.take_positive().map(DescriptorResultV1::Catalog),
            Self::Pin(original) => original.take_positive().map(DescriptorResultV1::Pin),
            Self::Repair(original) => original.take_positive().map(DescriptorResultV1::Repair),
            Self::GuestRoot(original) => original.take_positive().map(|reply| match reply {
                super::guest_root_validation::GuestRootReplyDataV2::Publication(proof) => DescriptorResultV1::GuestRoot(proof),
                super::guest_root_validation::GuestRootReplyDataV2::StartupHealth => DescriptorResultV1::GuestRootStartupHealth,
            }),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Catalog(original) => original.failure(),
            Self::Pin(original) => original.failure(),
            Self::Repair(original) => original.failure(),
            Self::GuestRoot(original) => original.failure(),
        }
    }

    fn requested_bytes_v1(plan: DescriptorPlanV1<'_>) -> Option<usize> {
        match plan {
            DescriptorPlanV1::Catalog(request) => catalog_validation::CatalogResultOriginalV1::requested_bytes_v1(request),
            DescriptorPlanV1::Pin(_) => super::pin_validation::PinResultOriginalV1::requested_bytes_v1(),
            DescriptorPlanV1::Repair(plan) => super::repair_validation::RepairResultOriginalV1::requested_bytes_v1(plan),
            DescriptorPlanV1::GuestRoot(_) | DescriptorPlanV1::GuestRootStartupHealth => super::guest_root_validation::GuestRootResultOriginalV2::requested_bytes_v2(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum First { Connection, Peer, Ready, ReadyPath, Cgroup, Worker,
    Parent, Population, Request, Response, Validation, Ack, Exit, Native, Deadline }

/// Retains the actual selected descriptor-worker failure and every reached owner.
///
/// The opaque failure exposes its original cause through `Error::source`.
/// No constructor accepts a budget, purpose flag or replacement native loan.
pub struct PhysicalDescriptorWorkerFailureV1 {
    request: Vec<u8>,
    deadline_before: DeadlineOriginalV1,
    deadline_after: DeadlineOriginalV1,
    connection: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer_membership: worker_subject::MembershipObservationV1,
    peer: Option<Result<(), ZfsWorkerError>>,
    ready: Option<Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1>>,
    ready_path: Option<Result<String, ZfsWorkerError>>,
    cgroup: WorkerCgroupOpeningV1,
    cgroup_result: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    worker_membership: worker_subject::MembershipObservationV1,
    worker: Option<Result<(), ZfsWorkerError>>,
    parent: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    population: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    request_send: WorkerFrameSendOriginalV1,
    single_request_send: Option<DescriptorWorkerSendAttemptV1>,
    request_result: Option<Result<(), ZfsWorkerError>>,
    response: Option<Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1>>,
    validation: DescriptorValidationOriginalV1,
    validation_result: Option<Result<(), ZfsWorkerError>>,
    ack: Option<DescriptorWorkerSendAttemptV1>,
    exit: worker_exit::WorkerExitOriginalV1,
    exit_result: Option<Result<(), ZfsWorkerError>>,
    cancellation: worker_exit::WorkerExitOriginalV1,
    cancellation_result: Option<Result<(), ZfsWorkerError>>,
    native: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<First>,
}

impl std::fmt::Debug for PhysicalDescriptorWorkerFailureV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhysicalDescriptorWorkerFailureV1").field("first", &self.first).finish_non_exhaustive()
    }
}

impl std::fmt::Display for PhysicalDescriptorWorkerFailureV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() { Some(error) => write!(f, "descriptor worker refused: {error}"),
            None => f.write_str("descriptor worker is incomplete") }
    }
}

impl std::error::Error for PhysicalDescriptorWorkerFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
}

impl PhysicalDescriptorWorkerFailureV1 {
    fn new(plan: DescriptorPlanV1<'_>) -> Self {
        Self { request: Vec::new(), deadline_before: DeadlineOriginalV1::new(),
            deadline_after: DeadlineOriginalV1::new(), connection: None,
            peer_membership: worker_subject::MembershipObservationV1::new(), peer: None,
            ready: None, ready_path: None, cgroup: WorkerCgroupOpeningV1::new(), cgroup_result: None,
            worker_membership: worker_subject::MembershipObservationV1::new(), worker: None,
            parent: None, population: None, request_send: WorkerFrameSendOriginalV1::new(), single_request_send: None, request_result: None,
            response: None, validation: DescriptorValidationOriginalV1::new(plan), validation_result: None,
            ack: None, exit: worker_exit::WorkerExitOriginalV1::new(), exit_result: None,
            cancellation: worker_exit::WorkerExitOriginalV1::new(), cancellation_result: None,
            native: None, first: None }
    }

    fn setup(&mut self, executor: &SystemdWorkspacePinExecutor, deadline: u64) {
        self.connection = Some(DescriptorSubjectSocket::connect_retaining(&executor.socket_path));
        let Some(Ok(socket)) = self.connection.as_mut() else { self.first = Some(First::Connection); return; };
        socket.begin_original_retention_v1();
        self.peer = Some(verify_systemd_peer_with_originals_v1(socket.peer(),
            &executor.systemd_manager_cgroup, Some(&mut self.peer_membership)));
        if !matches!(self.peer, Some(Ok(()))) { self.first = Some(First::Peer); return; }
        self.ready = Some(receive_worker_observer_record_v1(socket, WorkerObserverRecordKindV1::ReadyOrResult, deadline));
        let Some(Ok(ready)) = self.ready.as_ref() else { self.first = Some(First::Ready); return; };
        self.ready_path = Some(decode_selected_ready_v1(ready.payload(), executor.role).map(str::to_owned));
        let Some(Ok(path)) = self.ready_path.as_ref() else { self.first = Some(First::ReadyPath); return; };
        let parent = match executor.role {
            WorkspacePinServiceRole::GuestRootPublication31 => aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::ReceivingAggregate.worker_parent_relative_v1(),
            _ => CONTROL_SLICE_CGROUP,
        };
        let Ok(relative) = Path::new(path).strip_prefix(parent) else { std::process::abort() };
        self.cgroup_result = Some(self.cgroup.capture_descendant_once(&executor.worker_parent_cgroup, relative));
        if !matches!(self.cgroup_result, Some(Ok(()))) { self.first = Some(First::Cgroup); }
        if self.first.is_none() {
            let Some(anchor) = self.cgroup.anchor() else { std::process::abort() };
            self.worker = Some(verify_exact_worker_subject_with_originals_v1(ready.subject(), anchor,
                Some(&mut self.worker_membership)));
            if !matches!(self.worker, Some(Ok(()))) { self.first = Some(First::Worker); }
        }
        // This actual parent post remains owed after the entered descendant
        // or membership prefix even when either preceding native step failed.
        self.parent = Some(self.cgroup.observe_owed_parent_once_v1(&executor.worker_parent_cgroup));
        if !matches!(self.parent, Some(Ok(()))) { self.first.get_or_insert(First::Parent); }
        if self.first.is_some() { return; }
        self.population = Some(self.cgroup.capture_population_once());
        if !matches!(self.population, Some(Ok(()))) { self.first = Some(First::Population); }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|error| error as _) }
        match self.first? {
            First::Connection => cause(&self.connection),
            First::Peer => self.peer_membership.failure().or_else(|| cause(&self.peer)),
            First::Ready => cause(&self.ready), First::ReadyPath => cause(&self.ready_path),
            First::Cgroup | First::Parent | First::Population => self.cgroup.failure(),
            First::Worker => self.worker_membership.failure().or_else(|| cause(&self.worker)),
            First::Request => self.single_request_send.as_ref().and_then(DescriptorWorkerSendAttemptV1::failure)
                .or_else(|| self.request_send.failure()).or_else(|| cause(&self.request_result)),
            First::Response => cause(&self.response),
            First::Validation => self.validation.failure().or_else(|| cause(&self.validation_result)),
            First::Ack => self.ack.as_ref()?.failure(),
            First::Exit => self.exit.failure().or_else(|| cause(&self.exit_result)),
            First::Native => cause(&self.native),
            First::Deadline => self.deadline_before.failure().or_else(|| self.deadline_after.failure()),
        }
    }

    fn record_failed_native_v1(&mut self, result: Result<(), StorageReceivingClosedV1>, cutoff: u64) {
        if self.native.is_some() { std::process::abort(); }
        self.native = Some(result);
        let _owed_deadline = self.deadline_after.observe_once(cutoff);
    }

    pub(crate) fn native_primary_v1(&self) -> Option<&StorageReceivingClosedV1> {
        if !matches!(self.first, Some(First::Native)) { return None; }
        self.native.as_ref()?.as_ref().err()
    }

    fn demand(request_bytes: &[u8], plan: DescriptorPlanV1<'_>) -> Option<ResourceVector> {
        let (connection_bytes, connection_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::retained_connect_obligations_v1();
        let (ready_bytes, ready_files, _) = descriptor_worker_record_obligations_v1(WorkerObserverRecordKindV1::ReadyOrResult)?;
        let kind = plan.response_kind();
        let (response_bytes, response_files, _) = descriptor_worker_record_obligations_v1(kind)?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(request_bytes.len().checked_mul(2)?)?
            .checked_add(connection_bytes)?.checked_add(ready_bytes)?.checked_add(response_bytes)?
            .checked_add(WorkerCgroupOpeningV1::dominant_requested_bytes_v1()?)?
            .checked_add(2 * 4097)?
            .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?.checked_mul(3)?)?
            .checked_add(WorkerFrameSendOriginalV1::requested_bytes_v1()?)?
            .checked_add(DescriptorWorkerSendAttemptV1::requested_bytes_v1()?
                .checked_mul(if plan.guest_root() { 2 } else { 1 })?)?
            .checked_add(DescriptorValidationOriginalV1::requested_bytes_v1(plan)?)?
            .checked_add(worker_exit::WorkerExitOriginalV1::requested_bytes_v1()?.checked_mul(2)?)?
            // The method31 Native kind carries its actual installed1GiB worker
            // and inherited tables. Existing pin/catalog callers retain theirs here.
            .checked_add(if plan.guest_root() { 0 } else { 128 * 1024 * 1024 })?;
        let files = connection_files.checked_add(ready_files)?.checked_add(response_files)?
            .checked_add(WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1)?
            .checked_add(3 * ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?
            .checked_add(aos_sandbox_linux::cgroup::CgroupKillAttemptV1::maximum_retained_files_v1())?
            // Existing worker+child NOFILE bounds are kept in full. This is
            // deliberately not a claim about smaller or descendant-free peaks.
            .checked_add(if plan.guest_root() { 0 } else { 128 + 128 })?;
        // Both frame encoders use the actual fixed4096-byte packet profile.
        // The header/content split is exposed by the same protocol producer.
        let (frame_bytes, frames) = if plan.guest_root() {
            (request_bytes.len(), 1)
        } else {
            (crate::observation_protocol::framed_receiving_bytes_v1(request_bytes.len())?,
                crate::observation_protocol::framed_receiving_record_count_v1(request_bytes.len())?)
        };
        // Each request frame and ACK can carry the existing exact80-byte
        // credential/PIDFD/rights control shape in addition to its payload.
        let ack_bytes = if plan.guest_root() {
            crate::guest_root_worker::ACK_MAGIC.len()
        } else { ACK.len() };
        let output = frame_bytes.checked_add(ack_bytes)?
            .checked_add(frames.checked_add(1)?.checked_mul(80)?)?;
        let network = output.checked_add(MAXIMUM_READY_BYTES)?.checked_add(plan.maximum_response_bytes())?.checked_add(2 * 80)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::ConcurrentOperations, 1).with(D::NetworkBytes, u64::try_from(network).ok()?)
            .with(D::OutputBytes, u64::try_from(output).ok()?)
            .with(D::Mounts, u64::from(plan.exports_mount())))
    }
}

impl SystemdWorkspacePinExecutor {
    pub(super) fn exchange_catalog_receiving_v1(&mut self,
        bytes: &[u8], request: &WorkspaceCatalogObservationRequestV1,
        custody: &WorkspacePinHostCustody, deadline: u64,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<(WorkspaceCatalogObservationResultV1, Option<OwnedFd>), ZfsWorkerError> {
        if self.fail_stopped { return Err(ZfsWorkerError::Protocol("workspace pin executor is fail-stopped")); }
        let demand = PhysicalDescriptorWorkerFailureV1::demand(bytes, DescriptorPlanV1::Catalog(request)).ok_or(ZfsWorkerError::Authority)?;
        let flight = stage.borrow_pin_v1(demand).map_err(|cause| ZfsWorkerError::PhysicalAdmission(
            crate::process::PhysicalWorkerAdmissionFailureV1::from_native_refusal_v1(cause)))?;
        let (result, descriptor) = self.exchange_descriptor_entered_v1(
            bytes, DescriptorPlanV1::Catalog(request), Some(custody), deadline, demand, flight,
        )?;
        let DescriptorResultV1::Catalog(result) = result else { std::process::abort() };
        Ok((result, descriptor))
    }

    pub(super) fn exchange_pin_receiving_v1(
        &mut self,
        bytes: &[u8],
        attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
        custody: &WorkspacePinHostCustody,
        deadline: u64,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Protocol("workspace pin executor is fail-stopped"));
        }
        let plan = DescriptorPlanV1::Pin(attempt);
        let demand = PhysicalDescriptorWorkerFailureV1::demand(bytes, plan)
            .ok_or(ZfsWorkerError::Authority)?;
        let flight = stage.borrow_effect_pin_v1(demand).map_err(|cause| {
            ZfsWorkerError::PhysicalAdmission(
                crate::process::PhysicalWorkerAdmissionFailureV1::from_native_refusal_v1(cause),
            )
        })?;
        let (result, descriptor) = self.exchange_descriptor_entered_v1(
            bytes, plan, Some(custody), deadline, demand, flight,
        )?;
        if descriptor.is_some() { std::process::abort(); }
        let DescriptorResultV1::Pin(result) = result else { std::process::abort() };
        Ok(result)
    }

    pub(super) fn exchange_repair_receiving_v1(
        &mut self,
        bytes: &[u8],
        plan: super::repair_validation::RepairPlanV1<'_>,
        custody: &WorkspacePinHostCustody,
        deadline: u64,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<super::repair_validation::RepairResultV1, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Protocol("workspace pin executor is fail-stopped"));
        }
        let plan = DescriptorPlanV1::Repair(plan);
        let demand = PhysicalDescriptorWorkerFailureV1::demand(bytes, plan)
            .ok_or(ZfsWorkerError::Authority)?;
        let flight = stage.borrow_effect_pin_v1(demand).map_err(|cause| {
            ZfsWorkerError::PhysicalAdmission(
                crate::process::PhysicalWorkerAdmissionFailureV1::from_native_refusal_v1(cause),
            )
        })?;
        let (result, descriptor) = self.exchange_descriptor_entered_v1(
            bytes, plan, Some(custody), deadline, demand, flight,
        )?;
        if descriptor.is_some() { std::process::abort(); }
        let DescriptorResultV1::Repair(result) = result else { std::process::abort() };
        Ok(result)
    }

    pub(super) fn exchange_guest_root_receiving_v2(
        &mut self,
        bytes: &[u8],
        attempt: &crate::guest_root_attempt::GuestRootPublicationAttemptV2,
        deadline: u64,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1, ZfsWorkerError> {
        if self.fail_stopped || !matches!(self.role, WorkspacePinServiceRole::GuestRootPublication31) {
            return Err(ZfsWorkerError::Authority);
        }
        let plan = DescriptorPlanV1::GuestRoot(attempt);
        let demand = PhysicalDescriptorWorkerFailureV1::demand(bytes, plan)
            .ok_or(ZfsWorkerError::Authority)?;
        let flight = stage.borrow_guest_root_publication_v2(demand).map_err(|cause| {
            ZfsWorkerError::PhysicalAdmission(
                crate::process::PhysicalWorkerAdmissionFailureV1::from_native_refusal_v1(cause),
            )
        })?;
        let (result, descriptor) = self.exchange_descriptor_entered_v1(
            bytes, plan, None, deadline, demand, flight,
        )?;
        if descriptor.is_some() { std::process::abort(); }
        let DescriptorResultV1::GuestRoot(proof) = result else { std::process::abort() };
        Ok(proof)
    }

    pub(super) fn guest_root_startup_health_demand_v2() -> Option<ResourceVector> {
        PhysicalDescriptorWorkerFailureV1::demand(
            crate::guest_root_worker::HEALTH_REQUEST_MAGIC, DescriptorPlanV1::GuestRootStartupHealth,
        )
    }

    pub(super) fn exchange_guest_root_startup_health_entered_v2(
        &mut self,
        deadline: u64,
        demand: ResourceVector,
        flight: StoragePhysicalWorkerLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        if self.fail_stopped || !matches!(self.role, WorkspacePinServiceRole::GuestRootPublication31) {
            let _post = flight.finish_failed_interval_v1();
            return Err(ZfsWorkerError::Authority);
        }
        let plan = DescriptorPlanV1::GuestRootStartupHealth;
        let bytes = crate::guest_root_worker::HEALTH_REQUEST_MAGIC;
        let (result, descriptor) = self.exchange_descriptor_entered_v1(bytes, plan, None, deadline, demand, flight)?;
        if descriptor.is_some() || !matches!(result, DescriptorResultV1::GuestRootStartupHealth) {
            std::process::abort();
        }
        Ok(())
    }

    fn exchange_descriptor_entered_v1(&mut self, bytes: &[u8], plan: DescriptorPlanV1<'_>,
        custody: Option<&WorkspacePinHostCustody>, deadline: u64, demand: ResourceVector,
        mut flight: StoragePhysicalWorkerLoanV1<'_, '_>,
    ) -> Result<(DescriptorResultV1, Option<OwnedFd>), ZfsWorkerError> {
        if let Err(cause) = flight.require_shape_v1(demand) {
            let _post = flight.finish_failed_interval_v1();
            return Err(ZfsWorkerError::PhysicalAdmission(crate::process::PhysicalWorkerAdmissionFailureV1::from_native_refusal_v1(cause)));
        }
        let mut original = Box::new(PhysicalDescriptorWorkerFailureV1::new(plan));
        if original.deadline_before.observe_once(deadline).is_err() {
            original.first = Some(First::Deadline);
            original.record_failed_native_v1(flight.finish_failed_interval_v1(), deadline);
            self.fail_stopped = true;
            return Err(ZfsWorkerError::DescriptorPhysical(original));
        }
        original.request = bytes.to_vec();
        original.setup(self, deadline);
        if original.first.is_some() {
            original.record_failed_native_v1(flight.finish_failed_interval_v1(), deadline);
            self.fail_stopped = true;
            return Err(ZfsWorkerError::DescriptorPhysical(original));
        }
        let Some(Ok(socket)) = original.connection.as_mut() else { std::process::abort() };
        let Some(Ok(ready)) = original.ready.as_ref() else { std::process::abort() };
        let Some(anchor) = original.cgroup.anchor() else { std::process::abort() };
        let Some(population) = original.cgroup.population() else { std::process::abort() };
        let Some(Ok(path)) = original.ready_path.as_ref() else { std::process::abort() };
        let bound = match plan {
            DescriptorPlanV1::GuestRoot(_) => flight.bind_guest_root_publication_once_v2(socket, ready, anchor, population, path),
            DescriptorPlanV1::GuestRootStartupHealth => flight.bind_guest_root_health_once_v2(socket, ready, anchor, population, path),
            _ => flight.bind_pin_once_v1(socket, ready, anchor, population, path),
        };
        let mut bound = match bound {
            Ok(bound) => bound,
            Err(cause) => { original.record_failed_native_v1(Err(cause), deadline); original.first = Some(First::Native);
                self.fail_stopped = true; return Err(ZfsWorkerError::DescriptorPhysical(original)); }
        };
        let socket = match plan {
            DescriptorPlanV1::GuestRoot(_) => bound.guest_root_publication_socket_mut_v2(),
            DescriptorPlanV1::GuestRootStartupHealth => bound.guest_root_health_socket_mut_v2(),
            _ => bound.pin_socket_mut_v1(),
        };
        let socket = match socket { Ok(socket) => socket, Err(_) => std::process::abort() };
        original.request_result = Some(match plan {
            DescriptorPlanV1::GuestRoot(_) | DescriptorPlanV1::GuestRootStartupHealth => {
                let kind = if matches!(plan, DescriptorPlanV1::GuestRootStartupHealth) {
                    DescriptorWorkerSendKindV1::GuestRootStartupHealthV2
                } else { DescriptorWorkerSendKindV1::GuestRootPublicationRequestV2 };
                original.single_request_send = Some(send_descriptor_worker_record_v1(socket,
                    &original.request, &[], kind, deadline));
                if original.single_request_send.as_ref().is_some_and(DescriptorWorkerSendAttemptV1::is_sent) { Ok(()) }
                else { Err(ZfsWorkerError::Protocol("guest-root request original retained")) }
            }
            DescriptorPlanV1::Catalog(_) => original.request_send.send_catalog_once(
                socket, &original.request,
                [custody.unwrap_or_else(|| std::process::abort()).mount_namespace().as_fd(),
                    custody.unwrap_or_else(|| std::process::abort()).pin_root().as_fd()], deadline,
            ),
            DescriptorPlanV1::Pin(_) | DescriptorPlanV1::Repair(_) => original.request_send.send_pin_once(
                socket, &original.request,
                [custody.unwrap_or_else(|| std::process::abort()).mount_namespace().as_fd(),
                    custody.unwrap_or_else(|| std::process::abort()).pin_root().as_fd()], deadline,
            ),
        });
        if !matches!(original.request_result, Some(Ok(()))) { original.first = Some(First::Request); }
        if original.first.is_none() {
            let kind = plan.response_kind();
            original.response = Some(receive_worker_observer_record_v1(socket, kind, deadline));
            let Some(Ok(response)) = original.response.as_ref() else {
                original.first = Some(First::Response);
                original.cancellation_result = Some(original.cancellation.quiesce_once(ready.subject(), anchor, population));
                let native = bound.finish_failed_interval_v1();
                original.record_failed_native_v1(native, deadline); self.fail_stopped = true;
                return Err(ZfsWorkerError::DescriptorPhysical(original));
            };
            original.validation_result = Some(original.validation.observe_once(response, ready.subject(), plan, anchor));
            if !matches!(original.validation_result, Some(Ok(()))) { original.first = Some(First::Validation); }
            else {
                let acknowledgement: &[u8] = match plan {
                    DescriptorPlanV1::GuestRoot(_) | DescriptorPlanV1::GuestRootStartupHealth => crate::guest_root_worker::ACK_MAGIC,
                    _ => ACK,
                };
                original.ack = Some(send_descriptor_worker_record_v1(socket, acknowledgement, &[], DescriptorWorkerSendKindV1::Acknowledgment, deadline));
                if !original.ack.as_ref().is_some_and(DescriptorWorkerSendAttemptV1::is_sent) { original.first = Some(First::Ack); }
            }
        }
        if original.first.is_none() {
            original.exit_result = Some(original.exit.wait_once(ready.subject(), population, NATURAL_EXIT_TIMEOUT, deadline));
            if !matches!(original.exit_result, Some(Ok(()))) { original.first = Some(First::Exit); }
        }
        if original.first.is_some() {
            original.cancellation_result = Some(original.cancellation.quiesce_once(ready.subject(), anchor, population));
            let native = bound.finish_failed_interval_v1();
            original.record_failed_native_v1(native, deadline); self.fail_stopped = true;
            return Err(ZfsWorkerError::DescriptorPhysical(original));
        }
        let token = match bound.prepare_positive_disposal_v1() {
            Ok(token) => token,
            Err(cause) => { original.native = Some(Err(cause)); original.first = Some(First::Native);
                let _deadline = original.deadline_after.observe_once(deadline);
                self.fail_stopped = true; return Err(ZfsWorkerError::DescriptorPhysical(original)); }
        };
        // Native post work may itself reach the cutoff. Retain the actual
        // trailing clock with every original still resident, before disposal.
        if original.deadline_after.observe_once(deadline).is_err() {
            original.first = Some(First::Deadline);
            drop(token);
            self.fail_stopped = true;
            return Err(ZfsWorkerError::DescriptorPhysical(original));
        }
        // All actual semantic/native posts are complete with originals resident.
        // The selected output model and optional FD require their separate
        // upstream retained-result budget; they are not transient-disposal credit.
        let Some(result) = original.validation.take_positive() else { std::process::abort() };
        let Some(Ok(response)) = original.response.take() else { std::process::abort() };
        let (_, _, descriptors) = response.into_parts();
        let descriptor = descriptors.into_iter().next();
        drop(original);
        token.complete_after_disposal_v1();
        Ok((result, descriptor))
    }
}

struct DeadlineOriginalV1 {
    clock: Option<rustix::time::Timespec>,
    value: Option<Result<u64, ZfsWorkerError>>,
    completion: Option<Result<(), ZfsWorkerError>>,
}

impl DeadlineOriginalV1 {
    fn new() -> Self { Self { clock: None, value: None, completion: None } }

    fn observe_once(&mut self, cutoff: u64) -> Result<(), ZfsWorkerError> {
        if self.clock.is_some() { return Err(ZfsWorkerError::Protocol("physical deadline original is occupied")); }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.clock = Some(now);
        self.value = Some(crate::pin_worker::boottime_from_timespec_v1(now));
        self.completion = Some(match self.value.as_ref() {
            Some(Ok(value)) if *value < cutoff => Ok(()),
            _ => Err(ZfsWorkerError::Protocol("workspace pin transfer deadline elapsed")),
        });
        if matches!(self.completion, Some(Ok(()))) { Ok(()) }
        else { Err(ZfsWorkerError::Protocol("physical deadline original retained")) }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.value.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.completion.as_ref()?.as_ref().err()).map(|error| error as _)
    }
}
