//! Executes only the admitted O request through the same retained read engine.

use super::*;
use crate::kernel_reader::observation_helpers_v2::{
    NetworkObservationReadProgrammeOriginalV2, ObservationProgrammeDataV2, ReadFrontierOriginalV2,
};
use crate::namespace_catalog::NetworkNamespaceObservedStateKindV1;
use crate::namespace_observer::{
    NetworkNamespaceObserverError, observe_stable_destroyed_network_kernel_with_port_v2,
    observe_stable_expected_network_kernel_with_port_v2,
};
use crate::observation_worker_runtime::read_admission_v2::{
    NetworkObserverReadLoanV2, NetworkObserverReadOriginalV2,
};
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_linux::pidfd::{
    NamespaceAdoptionFailureV2, NamespaceFd, NamespaceIdentity, NamespaceKind,
    PidFdNamespaceOriginalV2,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    NetworkWorkerBootstrapWaitOriginalV3, NetworkWorkerBootstrapWaitRefusalV3,
    ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{RecordBindingError, RetainedSeqpacketReceiveErrorV1};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the observer's original read execution is closed")]
pub(super) struct ReadExecutionClosedV2;

#[derive(Clone, Copy)]
enum First {
    Order,
    Funding,
    Before,
    Cutoff,
    Wait,
    Receive,
    Origin,
    Source,
    Payload,
    Descriptors,
    HostEntry,
    HostCurrent,
    OriginAfter,
    After,
    Retirement,
    Programme,
    Observation,
    Panic,
}

/// Keeps actual namespaces, read programme and semantic outcome through ACK.
/// Failed entered helpers remain here until process handback; dropping them
/// instead would invoke the canonical runner's disposal enforcement.
pub(super) struct ObserverReadExecutionOriginalV2 {
    entered: bool,
    first: Option<First>,
    before: ReadFrontierOriginalV2,
    before_result: Option<Result<(), crate::kernel_reader::NetworkKernelReaderError>>,
    cutoff: Option<aos_sandbox_linux::seqpacket::NetworkWorkerNativeCutoffV4>,
    wait: NetworkWorkerBootstrapWaitOriginalV3,
    wait_result: Option<Result<(), NetworkWorkerBootstrapWaitRefusalV3>>,
    record: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    origin: Option<Result<(), RecordBindingError>>,
    source_record: NetworkChildSourceRecordOriginalV2,
    source_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    payload: Option<Result<(), ReadExecutionClosedV2>>,
    raw_namespaces: Vec<OwnedFd>,
    namespace_adoptions: [Option<Result<NamespaceFd, NamespaceAdoptionFailureV2>>; 2],
    peer_namespace_original: PidFdNamespaceOriginalV2,
    peer_namespace_result: Option<Result<(), aos_linux_descriptors::Error>>,
    peer_namespace: Option<NamespaceFd>,
    peer_namespace_identity: Option<NamespaceIdentity>,
    namespace_roles: Option<Result<(), NetworkObservationWorkerError>>,
    namespaces: Option<Result<(NamespaceFd, NamespaceFd), NetworkObservationWorkerError>>,
    host_entry: Option<Result<(), aos_linux_descriptors::Error>>,
    host_current: Option<Result<(), aos_linux_descriptors::Error>>,
    origin_after: Option<Result<(), RecordBindingError>>,
    after: ReadFrontierOriginalV2,
    after_result: Option<Result<(), crate::kernel_reader::NetworkKernelReaderError>>,
    stat_retirement: Option<Result<(), NetworkChildOriginClosedV2>>,
    programme: Option<NetworkObservationReadProgrammeOriginalV2>,
    observation: Option<Result<ObjectDigest, NetworkNamespaceObserverError>>,
    response: Option<super::super::PreparedNetworkObservationV1>,
}

impl ObserverReadExecutionOriginalV2 {
    pub(super) fn namespace_slot_for_owed_custody_v3(
        &self,
    ) -> super::disposition::InputSlotOriginalV3<'_> {
        use super::disposition::InputSlotOriginalV3 as Slot;
        if matches!(self.first, Some(First::Panic)) {
            return Slot::Uncertain;
        }
        match self.record.as_ref() {
            Some(Ok(record)) => Slot::Record(record),
            Some(Err(_)) => Slot::Uncertain,
            None => Slot::Unentered,
        }
    }

    pub(super) fn new() -> Self {
        Self {
            entered: false,
            first: None,
            before: ReadFrontierOriginalV2::new(),
            before_result: None,
            cutoff: None,
            wait: NetworkWorkerBootstrapWaitOriginalV3::new(),
            wait_result: None,
            record: None,
            origin: None,
            source_record: NetworkChildSourceRecordOriginalV2::new(),
            source_result: None,
            payload: None,
            raw_namespaces: Vec::new(),
            namespace_adoptions: [None, None],
            peer_namespace_original: PidFdNamespaceOriginalV2::new(),
            peer_namespace_result: None,
            peer_namespace: None,
            peer_namespace_identity: None,
            namespace_roles: None,
            namespaces: None,
            host_entry: None,
            host_current: None,
            origin_after: None,
            after: ReadFrontierOriginalV2::new(),
            after_result: None,
            stat_retirement: None,
            programme: None,
            observation: None,
            response: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_once_v2<'held, 'native>(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'native>,
        socket: &mut DescriptorSubjectSocket,
        read_original: &'held NetworkObserverReadOriginalV2,
        read: &NetworkObserverReadLoanV2<'held, 'native>,
        startup: &ObserverStartupOriginalV2,
        exact_namespace_bytes: usize,
        programme: ObservationProgrammeDataV2,
    ) -> Result<(), ReadExecutionClosedV2> {
        if self.entered || self.first.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(ReadExecutionClosedV2);
        }
        self.entered = true;
        if !source.prepaid_fee_data_v2().is_some_and(|paid| {
            paid.checked_sub(programme.receiving_obligations_data_v2())
                .is_ok()
        }) {
            self.first = Some(First::Funding);
            return Err(ReadExecutionClosedV2);
        }
        self.before_result = Some(self.before.observe(read, source));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first = Some(First::Before);
        }
        self.cutoff = self.before.native_cutoff_data_v2(read);
        if self.cutoff.is_none() {
            self.first.get_or_insert(First::Cutoff);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.capture_namespaces(
                    source,
                    socket,
                    read_original,
                    startup,
                    exact_namespace_bytes,
                );
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Panic);
        }
        if let Some(Ok(record)) = self.record.as_ref() {
            self.origin_after = Some(socket.validate_received_origin_retaining(record));
            if !matches!(self.origin_after, Some(Ok(()))) {
                self.first.get_or_insert(First::OriginAfter);
            }
        }
        // The same read/Source engine runs after every reached native prefix,
        // even a refused descriptor, namespace enter or original panic.
        self.after_result = Some(self.after.observe(read, source));
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            return Err(ReadExecutionClosedV2);
        }
        // The actual peer namespace has now passed role, host-entry and all
        // transport/Source posts. Its identity/result remain resident; only
        // this completed temporary can close before any helper fork.
        drop(self.peer_namespace.take());
        self.stat_retirement = Some(self.source_record.retire_positive_stat_proof_once_v2());
        if !matches!(self.stat_retirement, Some(Ok(()))) {
            self.first = Some(First::Retirement);
            return Err(ReadExecutionClosedV2);
        }

        // This creates only the finite, already-paid roster. Permission comes
        // from the genuine same Source and sealed signed read borrower below.
        self.programme = NetworkObservationReadProgrammeOriginalV2::new(programme);
        let Some(programme) = self.programme.as_mut() else {
            self.first = Some(First::Programme);
            return Err(ReadExecutionClosedV2);
        };
        let request = read_original.request().map_err(|_| {
            self.first = Some(First::Programme);
            ReadExecutionClosedV2
        })?;
        let Some(Ok((host, target))) = self.namespaces.as_ref() else {
            self.first = Some(First::Descriptors);
            return Err(ReadExecutionClosedV2);
        };
        let worker = startup.worker.as_ref().ok_or_else(|| {
            self.first = Some(First::Programme);
            ReadExecutionClosedV2
        })?;
        let readers = startup
            .readers
            .for_plan_data_v2(&request.plan)
            .ok_or_else(|| {
                self.first = Some(First::Programme);
                ReadExecutionClosedV2
            })?;
        let mut port = programme
            .borrow_port_v2(read, source, &startup.readers)
            .map_err(|_| {
                self.first = Some(First::Programme);
                ReadExecutionClosedV2
            })?;
        self.observation = Some(
            if request.expected_state.kind() == NetworkNamespaceObservedStateKindV1::Absent {
                observe_stable_destroyed_network_kernel_with_port_v2(
                    readers,
                    &request.plan,
                    target,
                    request.kernel_plan_digest,
                    request.kernel_boot_id,
                    host,
                    worker,
                    &mut port,
                )
            } else {
                observe_stable_expected_network_kernel_with_port_v2(
                    readers,
                    &request.plan,
                    target,
                    request.kernel_plan_digest,
                    request.kernel_boot_id,
                    request.expected_state,
                    host,
                    worker,
                    &mut port,
                )
                .map(|observation| observation.digest())
            },
        );
        let Some(Ok(digest)) = self.observation.as_ref() else {
            self.first = Some(First::Observation);
            return Err(ReadExecutionClosedV2);
        };
        self.response = Some(super::super::PreparedNetworkObservationV1 {
            request_id: request.request_id,
            effect_digest: request.effect_digest,
            kernel_plan_digest: request.kernel_plan_digest,
            kernel_boot_id: request.kernel_boot_id,
            namespace: request.namespace,
            observed_state: request.expected_state,
            observation_digest: *digest,
        });
        Ok(())
    }

    fn capture_namespaces(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        read: &NetworkObserverReadOriginalV2,
        startup: &ObserverStartupOriginalV2,
        exact_bytes: usize,
    ) {
        let Some(cutoff) = self.cutoff else {
            self.first = Some(First::Cutoff);
            return;
        };
        let donor = match source.original_netd_pidfd_for_worker_wait_v2() {
            Ok(donor) => donor,
            Err(_) => {
                self.first = Some(First::Source);
                return;
            }
        };
        self.wait_result = Some(self.wait.observe_once_v3(socket, donor, Some(cutoff)));
        if !matches!(self.wait_result, Some(Ok(()))) {
            self.first = Some(First::Wait);
            return;
        }
        self.record = Some(
            socket.receive_network_observer_namespace_request_retaining_v3(exact_bytes, cutoff),
        );
        let Some(Ok(record)) = self.record.as_mut() else {
            self.first = Some(First::Receive);
            return;
        };
        self.origin = Some(socket.validate_received_origin_retaining(record));
        if !matches!(self.origin, Some(Ok(()))) {
            self.first = Some(First::Origin);
        }
        self.source_result =
            Some(source.require_same_netd_record_once_v2(record, &mut self.source_record));
        if !matches!(self.source_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Source);
        }
        self.payload = Some(
            read.require_same_observation_request_data_v2(record.payload())
                .map_err(|_| ReadExecutionClosedV2),
        );
        if !matches!(self.payload, Some(Ok(()))) {
            self.first.get_or_insert(First::Payload);
        }
        if self.first.is_some() {
            return;
        }
        let Some(descriptors) = record.take_network_observer_namespace_descriptors_data_v2() else {
            self.first = Some(First::Descriptors);
            return;
        };
        let request = match read.request() {
            Ok(request) => request,
            Err(_) => {
                self.first = Some(First::Payload);
                return;
            }
        };
        self.raw_namespaces = descriptors;
        if self.raw_namespaces.len() != 2 {
            self.first = Some(First::Descriptors);
            return;
        }
        for index in 0..2 {
            let descriptor = self.raw_namespaces.remove(0);
            self.namespace_adoptions[index] = Some(NamespaceFd::from_owned_retaining_v2(
                descriptor,
                NamespaceKind::Network,
            ));
            if !matches!(self.namespace_adoptions[index], Some(Ok(_))) {
                self.first = Some(First::Descriptors);
                return;
            }
        }
        self.peer_namespace_result = Some(
            self.peer_namespace_original
                .capture_once(socket.peer().pidfd(), NamespaceKind::Network),
        );
        if !matches!(self.peer_namespace_result, Some(Ok(()))) {
            self.first = Some(First::Descriptors);
            return;
        }
        self.peer_namespace = self.peer_namespace_original.take_completed_once();
        let (Some(Ok(host)), Some(Ok(target)), Some(peer_namespace)) = (
            self.namespace_adoptions[0].as_ref(),
            self.namespace_adoptions[1].as_ref(),
            self.peer_namespace.as_ref(),
        ) else {
            self.first = Some(First::Descriptors);
            return;
        };
        self.peer_namespace_identity = Some(peer_namespace.identity());
        self.namespace_roles = Some(super::super::validate_request_namespace_roles(
            socket.peer(),
            host,
            target,
            peer_namespace,
            request.namespace,
        ));
        if !matches!(self.namespace_roles, Some(Ok(()))) {
            self.first = Some(First::Descriptors);
            return;
        }
        let adopted = std::mem::replace(&mut self.namespace_adoptions, [None, None]);
        match adopted {
            [Some(Ok(host)), Some(Ok(target))] => self.namespaces = Some(Ok((host, target))),
            retained => {
                self.namespace_adoptions = retained;
                self.first = Some(First::Descriptors);
                return;
            }
        }
        let Some(Ok((host, _))) = self.namespaces.as_ref() else {
            self.first = Some(First::Descriptors);
            return;
        };
        let Some(worker) = startup.worker.as_ref() else {
            self.first = Some(First::HostEntry);
            return;
        };
        self.host_entry = Some(host.enter(worker));
        if !matches!(self.host_entry, Some(Ok(()))) {
            self.first = Some(First::HostEntry);
            return;
        }
        self.host_current = Some(host.validate_current_network());
        if !matches!(self.host_current, Some(Ok(()))) {
            self.first = Some(First::HostCurrent);
        }
    }

    pub(super) fn response(&self) -> Option<super::super::PreparedNetworkObservationV1> {
        if self.first.is_some() {
            return None;
        }
        self.response
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            First::Before => self.before.failure(),
            First::Wait => self.wait.failure(),
            First::Receive => error(&self.record),
            First::Origin => error(&self.origin),
            First::Source => self.source_record.failure(),
            First::Payload => error(&self.payload),
            First::Descriptors => self
                .namespace_adoptions
                .iter()
                .find_map(|result| {
                    result
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .map(|failure| failure.cause() as &(dyn Error + 'static))
                })
                .or_else(|| {
                    self.peer_namespace_original
                        .failure()
                        .map(|cause| cause as _)
                })
                .or_else(|| error(&self.peer_namespace_result))
                .or_else(|| error(&self.namespace_roles))
                .or_else(|| error(&self.namespaces)),
            First::HostEntry => error(&self.host_entry),
            First::HostCurrent => error(&self.host_current),
            First::OriginAfter => error(&self.origin_after),
            First::After => self.after.failure(),
            First::Retirement => self
                .source_record
                .failure()
                .or_else(|| error(&self.stat_retirement)),
            First::Programme => self
                .programme
                .as_ref()
                .and_then(|programme| programme.failure()),
            First::Observation => error(&self.observation).or_else(|| {
                self.programme
                    .as_ref()
                    .and_then(|programme| programme.failure())
            }),
            First::Order | First::Funding | First::Cutoff | First::Panic => None,
        };
        cause.or(Some(&ReadExecutionClosedV2))
    }
}

/// Quotes the exact namespace transport and its two actual read frontiers.
/// The existing O5/stable-recipe supplier remains a separate whole-invoice term.
pub(crate) fn observer_execution_obligations_data_v2(
    exact_namespace_bytes: usize,
) -> Option<ResourceVector> {
    let native =
        DescriptorSubjectSocket::network_observer_namespace_request_receive_obligations_v3(
            exact_namespace_bytes,
        )?;
    let frontier = ReadFrontierOriginalV2::receiving_obligations_data_v2()?;
    let bytes = std::mem::size_of::<ObserverReadExecutionOriginalV2>()
        .checked_mul(2)?
        .checked_add(native.0)?
        .checked_add(std::mem::size_of::<OwnedFd>().checked_mul(4)?)?
        .checked_add(NetworkWorkerBootstrapWaitOriginalV3::receiving_bytes_v3()?)?;
    // Canonical descriptor validation temporarily opens the peer's netns in
    // addition to the two donated namespaces already owned by the carrier.
    let files = native.1.checked_add(1)?;
    ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::OpenFiles, u64::try_from(files).ok()?)
        .checked_add(frontier)
        .ok()?
        .checked_add(frontier)
        .ok()?
        .checked_add(NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?)
        .ok()
}
