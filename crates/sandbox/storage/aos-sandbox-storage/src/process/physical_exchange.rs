//! Owns selected physical ZFS request, exchange, cleanup and native settlement.
//!
//! The genuine State/Domain stage pays this concrete attempt before encoding or
//! connecting. The existing worker service/protocol, typed codecs, peer checks,
//! exact membership engine and bounded transport adapter remain shared. Failed
//! attempts return their whole reached owner; only complete positive native and
//! semantic checks can precede actual transient disposal and infallible reuse.

use super::*;

mod capture;
pub(crate) use capture::{CapturePhysicalPreparationOriginalV3, NativeCaptureCreatedReadbackV3};
use super::receiving_stage::StoragePhysicalWorkerStageV1;
use aos_sandbox_controller_domain::{StoragePhysicalWorkerLoanV1, StorageReceivingClosedV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{
    ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1,
    WorkerCgroupOpeningRefusalV1, WorkerCgroupOpeningV1,
};
use aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1;
use aos_sandbox_linux::seqpacket::bounded::{
    ZfsWorkerReceiveErrorV1, ZfsWorkerRecordKindV1, ZfsWorkerSendAttemptV1,
    ZfsWorkerSendKindV1, receive_zfs_worker_record_v1, send_zfs_worker_record_v1,
    zfs_worker_record_obligations_v1,
};

/// Reports an actual refused Native physical admission before upper growth.
///
/// Construction is private to the real stage caller. The actual Native first
/// cause stays on that continuously held receiving original; this value owns
/// its returned status without allocating an unfunded exchange reservoir.
#[derive(Debug, thiserror::Error)]
#[error("original physical admission refused")]
pub struct PhysicalWorkerAdmissionFailureV1 {
    refusal: StorageReceivingClosedV1,
}

impl PhysicalWorkerAdmissionFailureV1 {
    pub(crate) fn from_native_refusal_v1(refusal: StorageReceivingClosedV1) -> Self {
        Self { refusal }
    }
}

/// Retains the actual failed physical exchange and its chronological cause.
pub struct PhysicalWorkerFailureV1 {
    request: Vec<u8>,
    encoding: Option<Result<(), ZfsWorkerError>>,
    deadline: Option<Result<u64, std::num::TryFromIntError>>,
    connection: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    activation_membership: ExactCgroupMembershipReadbackV1,
    activation_membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    activation: Option<Result<(), ZfsWorkerError>>,
    ready: Option<Result<ReceivedRecord, ZfsWorkerReceiveErrorV1>>,
    ready_validation: Option<Result<(), ZfsWorkerError>>,
    cgroup: WorkerCgroupOpeningV1,
    cgroup_result: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    worker_membership: ExactCgroupMembershipReadbackV1,
    worker_membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    worker_validation: Option<Result<(), ZfsWorkerError>>,
    parent_post: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    population: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    traffic: WorkerTrafficV1,
    output: WorkerProcessOutput,
    decoding: Option<Result<(), ZfsWorkerError>>,
    observation: Option<Result<WorkerObservationOutcome, ZfsWorkerError>>,
    preflight: Option<Result<CaptureZfsPreflightV1, crate::catalog_transition::execution_capture::readback::CaptureZfsReadbackErrorV1>>,
    native: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<Failure>,
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Encoding, Deadline, Connection, Activation, Ready, ReadyValidation, Cgroup,
    WorkerMembership, WorkerValidation, ParentPost, Population, Traffic,
    Decoding, Observation, Preflight, Native,
}

impl std::fmt::Debug for PhysicalWorkerFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PhysicalWorkerFailureV1")
            .field("first", &self.first).finish_non_exhaustive()
    }
}

impl std::fmt::Display for PhysicalWorkerFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(error) => write!(formatter, "physical worker refused: {error}"),
            None => formatter.write_str("physical worker is incomplete"),
        }
    }
}

impl std::error::Error for PhysicalWorkerFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

impl PhysicalWorkerFailureV1 {
    fn new() -> Self {
        Self {
            request: Vec::new(), encoding: None, deadline: None, connection: None,
            activation_membership: ExactCgroupMembershipReadbackV1::new(),
            activation_membership_result: None, activation: None,
            ready: None, ready_validation: None, cgroup: WorkerCgroupOpeningV1::new(),
            cgroup_result: None, worker_membership: ExactCgroupMembershipReadbackV1::new(),
            worker_membership_result: None, worker_validation: None,
            parent_post: None, population: None, traffic: WorkerTrafficV1::new(),
            output: WorkerProcessOutput { stdout: Vec::new(), stderr: Vec::new(),
                success: false, timed_out: false },
            decoding: None, observation: None, preflight: None, native: None, first: None,
        }
    }

    /// Borrows the first actual failure while every later owed result stays held.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            slot.as_ref()?.as_ref().err().map(|error| error as _)
        }
        match self.first? {
            Failure::Encoding => cause(&self.encoding),
            Failure::Deadline => cause(&self.deadline),
            Failure::Connection => cause(&self.connection),
            Failure::Activation => self.activation_membership.failure().map(|error| error as _)
                .or_else(|| cause(&self.activation)),
            Failure::Ready => cause(&self.ready),
            Failure::ReadyValidation => cause(&self.ready_validation),
            Failure::Cgroup | Failure::ParentPost | Failure::Population => self.cgroup.failure(),
            Failure::WorkerMembership => self.worker_membership.failure().map(|error| error as _),
            Failure::WorkerValidation => cause(&self.worker_validation),
            Failure::Traffic => self.traffic.failure(),
            Failure::Decoding => cause(&self.decoding),
            Failure::Observation => cause(&self.observation),
            Failure::Preflight => cause(&self.preflight),
            Failure::Native => cause(&self.native),
        }
    }

    fn native_primary_v1(&self) -> Option<&StorageReceivingClosedV1> {
        if !matches!(self.first, Some(Failure::Native)) {
            return None;
        }
        self.native.as_ref()?.as_ref().err()
    }

    fn setup(&mut self, executor: &SystemdZfsExecutor, deadline: u64) {
        self.setup_native_v3(executor, deadline, false)
    }

    fn setup_capture_v3(&mut self, executor: &SystemdZfsExecutor, deadline: u64) {
        self.setup_native_v3(executor, deadline, true)
    }

    fn setup_native_v3(&mut self, executor: &SystemdZfsExecutor, deadline: u64, raw_peer: bool) {
        self.connection = Some(if raw_peer {
            SeqpacketSocket::connect_storage_worker_retaining_v3(&executor.socket_path)
        } else { SeqpacketSocket::connect_retaining(&executor.socket_path) });
        let Some(Ok(socket)) = self.connection.as_mut() else {
            self.first = Some(Failure::Connection); return;
        };
        // The ordinary credentials/membership/pid predicate is one engine;
        // selected disposition keeps its actual native receiver and Result.
        self.activation = Some(verify_systemd_activation_peer_with_originals_v1(
            socket.peer(), &executor.systemd_manager_cgroup,
            Some((&mut self.activation_membership, &mut self.activation_membership_result)),
        ));
        if !matches!(self.activation, Some(Ok(()))) {
            self.first = Some(Failure::Activation);
            return;
        }
        self.ready = Some(receive_zfs_worker_record_v1(socket, ZfsWorkerRecordKindV1::Ready, deadline));
        let Some(Ok(ready)) = self.ready.as_ref() else {
            self.first = Some(Failure::Ready); return;
        };
        self.ready_validation = Some(decode_selected_ready_v1(ready.payload()).map(|_| ()));
        if !matches!(self.ready_validation, Some(Ok(()))) {
            self.first = Some(Failure::ReadyValidation); return;
        }
        let Ok(path) = decode_selected_ready_v1(ready.payload()) else { std::process::abort() };
        let credentials = ready.subject().credentials();
        self.worker_validation = Some(require_worker_credentials_v1(ready.subject()));
        if matches!(self.worker_validation, Some(Err(_))) {
            self.first = Some(Failure::WorkerValidation); return;
        }
        let Ok(relative) = Path::new(path).strip_prefix(CONTROL_SLICE_CGROUP) else {
            self.worker_validation = Some(Err(ZfsWorkerError::PeerMismatch));
            self.first = Some(Failure::WorkerValidation); return;
        };
        self.cgroup_result = Some(self.cgroup.capture_descendant_once(&executor.worker_parent_cgroup, relative));
        if !matches!(self.cgroup_result, Some(Ok(()))) {
            self.first = Some(Failure::Cgroup); return;
        }
        let Some(anchor) = self.cgroup.anchor() else { std::process::abort() };
        self.worker_membership_result = Some(self.worker_membership.capture_once(anchor, ready.subject().pidfd()));
        if !matches!(self.worker_membership_result, Some(Ok(()))) {
            self.first = Some(Failure::WorkerMembership); return;
        }
        let Some(Ok(info)) = self.worker_membership.result() else { std::process::abort() };
        self.worker_validation = Some(if info.pid() != credentials.pid().get()
            || info.thread_group_id() != credentials.pid().get()
        { Err(ZfsWorkerError::PeerMismatch) } else { Ok(()) });
        if matches!(self.worker_validation, Some(Err(_))) {
            self.first = Some(Failure::WorkerValidation); return;
        }
        self.parent_post = Some(self.cgroup.observe_parent_once(&executor.worker_parent_cgroup));
        if !matches!(self.parent_post, Some(Ok(()))) {
            self.first = Some(Failure::ParentPost); return;
        }
        self.population = Some(self.cgroup.capture_population_once());
        if !matches!(self.population, Some(Ok(()))) {
            self.first = Some(Failure::Population);
        }
    }
}

struct WorkerTrafficV1 {
    request: Option<ZfsWorkerSendAttemptV1>,
    response: Option<Result<ReceivedRecord, ZfsWorkerReceiveErrorV1>>,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: ExactCgroupMembershipReadbackV1,
    membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    acknowledgment: Option<ZfsWorkerSendAttemptV1>,
    natural_exit: Option<Result<(), ZfsWorkerError>>,
    cancellation: WorkerCleanupReport,
    kill: aos_sandbox_linux::cgroup::CgroupKillAttemptV1,
    kill_result: Option<Result<(), aos_sandbox_linux::cgroup::CgroupKillRefusalV1>>,
    cleanup: Option<Result<(), ZfsWorkerError>>,
    first: Option<TrafficFailure>,
}

#[derive(Clone, Copy)]
enum TrafficFailure { Request, Response, Subject, Membership, Acknowledgment, NaturalExit }

impl WorkerTrafficV1 {
    fn new() -> Self {
        Self { request: None, response: None, subject: None,
            membership: ExactCgroupMembershipReadbackV1::new(), membership_result: None,
            acknowledgment: None, natural_exit: None, cancellation: WorkerCleanupReport::default(),
            kill: aos_sandbox_linux::cgroup::CgroupKillAttemptV1::new(), kill_result: None,
            cleanup: None, first: None }
    }

    fn run(&mut self, socket: &mut SeqpacketSocket, request: &[u8],
        subject: &KernelAuthorizedRecordSubject, anchor: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor, response_kind: ZfsWorkerRecordKindV1, deadline: u64,
    ) {
        self.run_with_disposition_v3(socket, request, subject, anchor, population,
            response_kind, deadline, false);
    }

    fn run_capture_created_v3(&mut self, socket: &mut SeqpacketSocket, request: &[u8],
        subject: &KernelAuthorizedRecordSubject, anchor: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor, deadline: u64,
    ) {
        self.run_with_disposition_v3(socket, request, subject, anchor, population,
            ZfsWorkerRecordKindV1::CaptureCreatedV3, deadline, true);
    }

    fn run_with_disposition_v3(&mut self, socket: &mut SeqpacketSocket, request: &[u8],
        subject: &KernelAuthorizedRecordSubject, anchor: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor, response_kind: ZfsWorkerRecordKindV1,
        deadline: u64, capture_pending: bool,
    ) {
        self.request = Some(send_zfs_worker_record_v1(socket, request, ZfsWorkerSendKindV1::Request, deadline));
        if !self.request.as_ref().is_some_and(ZfsWorkerSendAttemptV1::is_sent) {
            self.first = Some(TrafficFailure::Request);
        } else {
            self.response = Some(receive_zfs_worker_record_v1(socket, response_kind, deadline));
            let Some(Ok(response)) = self.response.as_ref() else {
                self.first = Some(TrafficFailure::Response);
                if !capture_pending { self.cleanup = Some(self.capture_cleanup(subject, anchor, population)); }
                return;
            };
            self.subject = Some(verify_same_live_subject(subject, response.subject()));
            if !matches!(self.subject, Some(Ok(()))) {
                self.first = Some(TrafficFailure::Subject);
            } else {
                self.membership_result = Some(self.membership.capture_once(anchor, response.subject().pidfd()));
                if !matches!(self.membership_result, Some(Ok(()))) {
                    self.first = Some(TrafficFailure::Membership);
                } else if !capture_pending {
                    self.acknowledgment = Some(send_zfs_worker_record_v1(socket, &encode_ack(),
                        ZfsWorkerSendKindV1::Acknowledgment, deadline));
                    if !self.acknowledgment.as_ref().is_some_and(ZfsWorkerSendAttemptV1::is_sent) {
                        self.first = Some(TrafficFailure::Acknowledgment);
                    }
                }
            }
        }
        if self.first.is_some() {
            if !capture_pending { self.cleanup = Some(self.capture_cleanup(subject, anchor, population)); }
            return;
        }
        // Capture keeps the SAME worker occupied for catalog/mount/drain.
        // An ambiguous prefix must not ACK, kill, close or pretend quiescence.
        if capture_pending { return; }
        self.natural_exit = Some(wait_for_worker_quiescence(subject, population, NATURAL_EXIT_TIMEOUT));
        if !matches!(self.natural_exit, Some(Ok(()))) {
            self.first = Some(TrafficFailure::NaturalExit);
            if !capture_pending { self.cleanup = Some(self.capture_cleanup(subject, anchor, population)); }
        }
    }

    fn capture_cleanup(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        anchor: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
    ) -> Result<(), ZfsWorkerError> {
        capture_worker_cleanup_retaining_v1(
            &mut self.cancellation, subject, anchor, population,
            &mut self.kill, &mut self.kill_result,
        )
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            TrafficFailure::Request => self.request.as_ref()?.failure(),
            TrafficFailure::Response => self.response.as_ref()?.as_ref().err().map(|error| error as _),
            TrafficFailure::Subject => self.subject.as_ref()?.as_ref().err().map(|error| error as _),
            TrafficFailure::Membership => self.membership.failure().map(|error| error as _),
            TrafficFailure::Acknowledgment => self.acknowledgment.as_ref()?.failure(),
            TrafficFailure::NaturalExit => self.natural_exit.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }
}

// These borrowed typed inputs are never a payer or an admitted worker. Only
// their concrete compiler/transport geometry is read before the real stage
// lends its exclusive operation. Every physical send still follows encoding.
enum RequestV1<'request> {
    Candidate {
        contract: &'request ZfsHelperContract,
        plan: &'request CaptureZfsPreflightPlanV1,
        cutoff: u64,
    },
    Transaction {
        verb: WorkerRequestVerb,
        contract: &'request ZfsHelperContract,
        operation: StorageOperation,
        catalog: &'request ResolvedCatalogCommitmentV1,
    },
    Atomic {
        verb: AtomicSnapshotRequestVerbV1,
        contract: &'request ZfsHelperContract,
        program: &'request crate::DormantAtomicDatasetSnapshotV1,
    },
}

impl RequestV1<'_> {
    fn response_kind(&self) -> ZfsWorkerRecordKindV1 {
        match self {
            Self::Transaction { verb: WorkerRequestVerb::ObservePreconditions
                | WorkerRequestVerb::ObservePostcondition, .. } => ZfsWorkerRecordKindV1::ObservationResult,
            _ => ZfsWorkerRecordKindV1::MutationResult,
        }
    }

    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), ZfsWorkerError> {
        match self {
            Self::Candidate { contract, plan, cutoff } => candidate_preflight::encode_request_into(contract, plan, *cutoff, output),
            Self::Transaction { verb, contract, operation, catalog } => {
                wire::encode_request_retaining_v1(*verb, contract, *operation, catalog, output)
            }
            Self::Atomic { verb, contract, program } => {
                wire::encode_atomic_snapshot_request_retaining_v1(*verb, contract, program, output)
            }
        }
    }

    // Includes the original initial capacity and late byte-limit rejection.
    // A valid framed request remains <=24KiB; an invalid candidate can grow
    // farther before that old check and must be paid before its actual Vec.
    fn construction_bound(&self) -> Option<usize> {
        match self {
            Self::Candidate { contract, plan, .. } => {
                let encoded = candidate_preflight::construction_bytes_v1(contract, plan)?;
                // Initial encoded reservoir, its retained exact request and
                // worker decoded path/root backing are three named planes.
                encoded.checked_add(encoded)?.checked_add(encoded)
            }
            Self::Transaction { contract, catalog, .. } => {
                96_usize.checked_add(contract.executable().as_os_str().len())?
                    .checked_add(catalog.canonical_bytes().len())?.checked_mul(3)
            }
            Self::Atomic { contract, program, .. } => {
                let path = contract.executable().as_os_str().len();
                let initial = 128_usize.checked_add(path)?
                    .checked_add(program.member_count().checked_mul(192)?)?;
                let mut encoded = 79_usize.checked_add(path)?;
                for member in program.members() {
                    encoded = encoded.checked_add(12)?
                        .checked_add(member.source_name().len())?
                        .checked_add(member.destination_name().len())?;
                }
                initial.max(encoded).checked_mul(3)
            }
        }
    }

    fn demand(&self) -> Option<ResourceVector> {
        let response = self.response_kind();
        let (connection_bytes, connection_files) = SeqpacketSocket::retained_connect_obligations_v1();
        let (ready_bytes, ready_files) = zfs_worker_record_obligations_v1(ZfsWorkerRecordKindV1::Ready)?;
        let (response_bytes, response_files) = zfs_worker_record_obligations_v1(response)?;
        let membership_bytes = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        // Actual Box body plus its explicit construction temporary; the new
        // error does not hide an unpriced second clone of this whole owner.
        let memory = std::mem::size_of::<PhysicalWorkerFailureV1>().checked_mul(2)?
            .checked_add(self.construction_bound()?)?
            .checked_add(match self {
                Self::Candidate { contract, plan, .. } => candidate_preflight::receiving_bytes_v1(contract, plan)?,
                _ => 0,
            })?
            .checked_add(connection_bytes)?.checked_add(ready_bytes)?.checked_add(response_bytes)?
            .checked_add(WorkerCgroupOpeningV1::dominant_requested_bytes_v1()?.checked_mul(2)?)?
            .checked_add(membership_bytes.checked_mul(4)?)?
            .checked_add(2 * std::mem::size_of::<ZfsWorkerSendAttemptV1>())?
            .checked_add(128 * 256)?
            .checked_add(8 * 256)?
            .checked_add(MAXIMUM_STDOUT_BYTES + MAXIMUM_STDERR_BYTES)?
            .checked_add(128 * 1024 * 1024)?
            .checked_add(super::worker_aggregate::WorkerAggregateV1::fork_requested_bytes_v1()?)?;
        let files = connection_files.checked_add(ready_files)?.checked_add(response_files)?
            .checked_add(2 * WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1)?
            .checked_add(4 * ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?
            .checked_add(2)?
            .checked_add(aos_sandbox_linux::cgroup::CgroupKillAttemptV1::maximum_retained_files_v1())?
            // The installed fixed unit and its synchronous child each have
            // NOFILE128. Their actual simultaneous owner census is not yet
            // proved smaller; raw ancillary23 cannot replace either table.
            // A positive256FD fit requires a separate genuine phase proof.
            .checked_add(128 + 128)?;
        let output = MAXIMUM_REQUEST_BYTES.checked_add(MAXIMUM_ACK_BYTES)?;
        let network = output.checked_add(MAXIMUM_READY_BYTES)?
            .checked_add(response.maximum_payload_bytes())?.checked_add(2 * 80)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            // Native derives/adds exact installed worker task ceiling from F.
            .with(D::Pids, 0)
            .with(D::ConcurrentOperations, 1)
            .with(D::NetworkBytes, u64::try_from(network).ok()?)
            .with(D::OutputBytes, u64::try_from(output).ok()?))
    }
}

enum PositiveV1 {
    Preflight(CaptureZfsPreflightV1),
    Mutation(WorkerProcessOutput),
    Observation(WorkerObservationOutcome),
}

impl SystemdZfsExecutor {
    // One selected caller engine for mutation, atomic and observation. The
    // actual model-paid upstream owner stays borrowed through native closure.
    fn exchange_receiving_v1(
        &mut self,
        request: RequestV1<'_>,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<PositiveV1, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Protocol("fixed ZFS executor is fail-stopped"));
        }
        // The readonly Candidate entrance cannot borrow a generic mutation
        // turn, and a State/Domain turn cannot select this request variant.
        if stage.is_candidate_v1() != matches!(&request, RequestV1::Candidate { .. }) {
            return Err(ZfsWorkerError::Authority);
        }
        let demand = request.demand().ok_or(ZfsWorkerError::Authority)?;
        let mut flight = stage.borrow_zfs_v1(demand).map_err(|refusal| {
            ZfsWorkerError::PhysicalAdmission(PhysicalWorkerAdmissionFailureV1 { refusal })
        })?;
        if flight.require_shape_v1(demand).is_err() {
            let refusal = match flight.finish_failed_interval_v1() {
                Err(refusal) => refusal,
                Ok(()) => std::process::abort(),
            };
            return Err(ZfsWorkerError::PhysicalAdmission(PhysicalWorkerAdmissionFailureV1 { refusal }));
        }
        let mut attempt = Box::new(PhysicalWorkerFailureV1::new());
        attempt.encoding = Some(request.encode_into(&mut attempt.request));
        if !matches!(attempt.encoding, Some(Ok(()))) {
            attempt.first = Some(Failure::Encoding);
            attempt.native = Some(flight.finish_failed_interval_v1());
            return Err(ZfsWorkerError::Physical(attempt));
        }
        let deadline = match &request {
            RequestV1::Candidate { cutoff, .. } => Deadline(Deadline::after(CONNECTION_TIMEOUT).0.min(Duration::from_nanos(*cutoff))),
            _ => Deadline::after(CONNECTION_TIMEOUT),
        };
        attempt.deadline = Some(u64::try_from(deadline.0.as_nanos()));
        let Some(Ok(deadline)) = attempt.deadline.as_ref().copied() else {
            attempt.first = Some(Failure::Deadline);
            attempt.native = Some(flight.finish_failed_interval_v1());
            return Err(ZfsWorkerError::Physical(attempt));
        };
        attempt.setup(self, deadline);
        if attempt.first.is_some() {
            attempt.native = Some(flight.finish_failed_interval_v1());
            return Err(ZfsWorkerError::Physical(attempt));
        }

        let Some(Ok(socket)) = attempt.connection.as_mut() else { std::process::abort() };
        let Some(Ok(ready)) = attempt.ready.as_ref() else { std::process::abort() };
        let Some(anchor) = attempt.cgroup.anchor() else { std::process::abort() };
        let Some(population) = attempt.cgroup.population() else { std::process::abort() };
        let worker_path = match decode_selected_ready_v1(ready.payload()) {
            Ok(path) => path,
            Err(_) => std::process::abort(),
        };
        let bound = flight.bind_zfs_once_v1(socket, ready, anchor, population, worker_path);
        let mut bound = match bound {
            Ok(bound) => bound,
            Err(error) => {
                attempt.native = Some(Err(error));
                attempt.first = Some(Failure::Native);
                return Err(ZfsWorkerError::Physical(attempt));
            }
        };
        let socket = match bound.zfs_socket_mut_v1() {
            Ok(socket) => socket,
            Err(_) => std::process::abort(),
        };
        attempt.traffic.run(socket, &attempt.request, ready.subject(), anchor, population,
            request.response_kind(), deadline);
        if attempt.traffic.first.is_some() {
            attempt.first = Some(Failure::Traffic);
            attempt.native = Some(bound.finish_failed_interval_v1());
            // Failed/ambiguous flights cannot lend a next operation, even if
            // cancellation eventually observes an empty worker cgroup.
            self.fail_stopped = true;
            return Err(ZfsWorkerError::Physical(attempt));
        }
        let Some(Ok(response)) = attempt.traffic.response.as_ref() else { std::process::abort() };
        let positive = match request.response_kind() {
            ZfsWorkerRecordKindV1::ObservationResult => {
                attempt.observation = Some(decode_observation_response(response.payload()));
                match attempt.observation.as_ref() {
                    Some(Ok(_)) => {
                        let Some(Ok(observation)) = attempt.observation.take() else { std::process::abort() };
                        PositiveV1::Observation(observation)
                    },
                    _ => {
                        attempt.first = Some(Failure::Observation);
                        attempt.native = Some(bound.finish_failed_interval_v1());
                        return Err(ZfsWorkerError::Physical(attempt));
                    }
                }
            }
            _ => {
                attempt.decoding = Some(wire::decode_mutation_response_retaining_v1(
                    response.payload(), &mut attempt.output,
                ));
                if !matches!(attempt.decoding, Some(Ok(()))) {
                    attempt.first = Some(Failure::Decoding);
                    attempt.native = Some(bound.finish_failed_interval_v1());
                    return Err(ZfsWorkerError::Physical(attempt));
                }
                if let RequestV1::Candidate { plan, .. } = &request {
                    let outputs = match candidate_preflight::decode_rows(&attempt.output) {
                        Ok(outputs) => outputs,
                        Err(cause) => {
                            attempt.decoding = Some(Err(cause)); attempt.first = Some(Failure::Decoding);
                            attempt.native = Some(bound.finish_failed_interval_v1());
                            return Err(ZfsWorkerError::Physical(attempt));
                        }
                    };
                    attempt.preflight = Some(plan.evaluate(outputs));
                    match attempt.preflight.take() {
                        Some(Ok(preflight)) => PositiveV1::Preflight(preflight),
                        result => {
                            attempt.preflight = result; attempt.first = Some(Failure::Preflight);
                            attempt.native = Some(bound.finish_failed_interval_v1());
                            return Err(ZfsWorkerError::Physical(attempt));
                        }
                    }
                } else {
                    PositiveV1::Mutation(std::mem::replace(&mut attempt.output, WorkerProcessOutput {
                        stdout: Vec::new(), stderr: Vec::new(), success: false, timed_out: false,
                    }))
                }
            }
        };
        let token = match bound.prepare_positive_disposal_v1() {
            Ok(token) => token,
            Err(error) => {
                // Restore the already-reached semantic output before returning
                // the whole owner; a failed native post grants no disposal.
                match positive {
                    PositiveV1::Preflight(preflight) => attempt.preflight = Some(Ok(preflight)),
                    PositiveV1::Mutation(output) => attempt.output = output,
                    PositiveV1::Observation(observation) => attempt.observation = Some(Ok(observation))
                }
                attempt.native = Some(Err(error));
                attempt.first = Some(Failure::Native);
                return Err(ZfsWorkerError::Physical(attempt));
            }
        };
        // The returned semantic output was separately prepaid by the upstream
        // model stage. Raw wire, subject, native, control and cleanup owners are
        // disposed now, while the exclusive positive token still blocks reuse.
        drop(attempt);
        token.complete_after_disposal_v1();
        Ok(positive)
    }

    pub(crate) fn execute_once_receiving_v1(
        &mut self, contract: &ZfsHelperContract, operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<WorkerProcessOutput, ZfsWorkerError> {
        match self.exchange_receiving_v1(RequestV1::Transaction {
            verb: WorkerRequestVerb::Mutate, contract, operation, catalog,
        }, stage)? {
            PositiveV1::Mutation(output) => Ok(output),
            PositiveV1::Observation(_) | PositiveV1::Preflight(_) => std::process::abort(),
        }
    }

    pub(crate) fn atomic_snapshot_once_receiving_v1(
        &mut self, contract: &ZfsHelperContract,
        program: &crate::DormantAtomicDatasetSnapshotV1, mutate: bool,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<WorkerProcessOutput, ZfsWorkerError> {
        let verb = if mutate { AtomicSnapshotRequestVerbV1::Mutate }
            else { AtomicSnapshotRequestVerbV1::Observe };
        match self.exchange_receiving_v1(RequestV1::Atomic { verb, contract, program }, stage)? {
            PositiveV1::Mutation(output) => Ok(output),
            PositiveV1::Observation(_) | PositiveV1::Preflight(_) => std::process::abort(),
        }
    }

    pub(crate) fn observe_preconditions_receiving_v1(
        &mut self, contract: &ZfsHelperContract, operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<WorkerObservationOutcome, ZfsWorkerError> {
        self.observe_receiving_v1(WorkerRequestVerb::ObservePreconditions, contract, operation, catalog, stage)
    }

    pub(crate) fn observe_postcondition_receiving_v1(
        &mut self, contract: &ZfsHelperContract, operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<WorkerObservationOutcome, ZfsWorkerError> {
        self.observe_receiving_v1(WorkerRequestVerb::ObservePostcondition, contract, operation, catalog, stage)
    }

    fn observe_receiving_v1(
        &mut self, verb: WorkerRequestVerb, contract: &ZfsHelperContract,
        operation: StorageOperation, catalog: &ResolvedCatalogCommitmentV1,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<WorkerObservationOutcome, ZfsWorkerError> {
        match self.exchange_receiving_v1(RequestV1::Transaction { verb, contract, operation, catalog }, stage)? {
            PositiveV1::Observation(output) => Ok(output),
            PositiveV1::Mutation(_) | PositiveV1::Preflight(_) => std::process::abort(),
        }
    }
}

impl ZfsWorkerError {
    /// Identifies only this returned error's primary Native refusal.
    pub(crate) fn physical_native_refusal_v1(&self) -> Option<&StorageReceivingClosedV1> {
        match self {
            Self::PhysicalAdmission(failure) => Some(&failure.refusal),
            Self::Physical(failure) => failure.native_primary_v1(),
            Self::DescriptorPhysical(failure) => failure.native_primary_v1(),
            _ => None,
        }
    }
}

impl SystemdZfsExecutor {
    pub(crate) fn observe_capture_candidate_preflight_receiving_v1(&mut self,
        contract: &ZfsHelperContract, plan: &CaptureZfsPreflightPlanV1, cutoff: u64,
        stage: &mut StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<CaptureZfsPreflightV1, ZfsWorkerError> {
        match self.exchange_receiving_v1(RequestV1::Candidate { contract, plan, cutoff }, stage)? {
            PositiveV1::Preflight(preflight) => Ok(preflight),
            PositiveV1::Mutation(_) | PositiveV1::Observation(_) => std::process::abort(),
        }
    }
}
