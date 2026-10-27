//! Owns the real Host Begin, two pipe transfers and terminal on the fixed socket.
//!
//! Only the already-created native Capture owner enters. The Source944/attempt
//! selector is compared to that same owner before pipe use. Every failed raw
//! packet, accepted endpoint, peer sampler and independently owed post stays
//! resident. Abort/Ack is transport-only and cannot release physical debt.

use super::*;
use crate::execution_output_credential::{
    StorageExecutionOutputCustodyV1, StorageOutputOwedAfterV1,
};
use crate::peer::{
    HostRootExportPeerVerifier, RootServiceConnectionOriginalV2, RootServicePeerError,
    RootServiceRecordOriginalV2,
};
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_linux::cgroup::{CgroupV2Root, ControllerStartupHostCgroupReadbackV1};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, RecordSubjectListener, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1, SeqpacketError,
};
use aos_sandbox_protocol::storage_capture_session::ongoing::{
    CAPTURE_BEGIN_BYTES_V3, CaptureHeldBeginDataV3,
};
use aos_sandbox_protocol::storage_capture_session::{
    CAPTURE_PROOF_BYTES_V2, CAPTURE_TERMINAL_BYTES_V2, CaptureHeldAckDataV2,
    CaptureHeldProofDataV2, CaptureHeldTerminalDataV2, CapturePipeIdentityDataV2,
    CaptureSessionProtocolErrorV2, CaptureTerminalModeDataV2,
};
use std::os::fd::AsFd as _;

type Clock = crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3<6>;

#[derive(Clone, Copy)]
enum Failure {
    Payment,
    OutputArm(usize),
    Host,
    Listener,
    Accept,
    Peer,
    Before,
    ProofClock,
    AckBefore,
    Wait(usize),
    Receive(usize),
    Binding(usize),
    Subject(usize),
    Begin,
    Row,
    Catalog,
    Proof,
    Send,
    After,
    Terminal,
    TerminalClock,
    Complete,
    Ack,
    AckDigest,
    AckPost,
    OutputAfter(usize),
    Disposal,
    NativeBoundary,
}

pub(super) struct CaptureHeldNativeOriginalV3 {
    entered: bool,
    begin_completed: bool,
    terminal_entered: bool,
    demand:
        [Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>; 2],
    payment: [Option<Result<(), StorageReceivingClosedV1>>; 2],
    current_catalog:
        Option<Result<crate::state::VerifiedStorageResolverJournalV1, crate::StorageStateError>>,
    output_after: [StorageOutputOwedAfterV1; 2],
    output_arm: [Option<Result<(), crate::service::StorageServiceError>>; 2],
    output_post: [Option<Result<(), crate::service::StorageServiceError>>; 2],
    physical_post: Option<Result<(), StorageReceivingClosedV1>>,
    native_boundary: Option<StorageReceivingClosedV1>,
    host: ControllerStartupHostCgroupReadbackV1,
    host_result: Option<aos_linux_descriptors::Result<()>>,
    host_pair: Option<
        Result<(CgroupV2Root, HostRootExportPeerVerifier), crate::service::StorageServiceError>,
    >,
    listener: Option<Result<(), SeqpacketError>>,
    socket: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer: RootServiceConnectionOriginalV2,
    peer_result: Option<Result<aos_linux_descriptors::pidfd::PidFdInfo, RootServicePeerError>>,
    waits: [Option<Result<(), aos_sandbox_linux::seqpacket::bounded::BoundedRecordError>>; 2],
    records: [Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>; 2],
    bindings: [Option<Result<(), RecordBindingError>>; 2],
    subjects: [RootServiceRecordOriginalV2; 2],
    subject_results: [Option<Result<(), RootServicePeerError>>; 2],
    clocks: Option<Clock>,
    clock_status: [Option<Result<(), ()>>; 6],
    begin: Option<Result<CaptureHeldBeginDataV3, CaptureSessionProtocolErrorV2>>,
    row: Option<
        Result<
            crate::execution_output::ProtectedRetainedOutputV1,
            crate::execution_output::ExecutionOutputLedgerErrorV1,
        >,
    >,
    proof: Option<Result<CaptureHeldProofDataV2, CaptureSessionProtocolErrorV2>>,
    proof_bytes: Option<Result<[u8; CAPTURE_PROOF_BYTES_V2], CaptureSessionProtocolErrorV2>>,
    sent: Option<aos_sandbox_linux::seqpacket::bounded::DescriptorWorkerSendAttemptV1>,
    terminal: Option<Result<CaptureHeldTerminalDataV2, CaptureSessionProtocolErrorV2>>,
    terminal_binding: Option<Result<(), CaptureSessionProtocolErrorV2>>,
    terminal_digest: Option<Result<[u8; 32], CaptureSessionProtocolErrorV2>>,
    complete_digest: Option<Result<ObjectDigest, aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordErrorV2>>,
    ack: Option<
        Result<
            [u8; aos_sandbox_protocol::storage_capture_session::CAPTURE_ACK_BYTES_V2],
            CaptureSessionProtocolErrorV2,
        >,
    >,
    ack_sent: Option<aos_sandbox_linux::seqpacket::bounded::DescriptorWorkerSendAttemptV1>,
    listener_post: [Option<Result<(), SeqpacketError>>; 2],
    peer_posts: [RootServiceConnectionOriginalV2; 2],
    peer_post_results:
        [Option<Result<aos_linux_descriptors::pidfd::PidFdInfo, RootServicePeerError>>; 2],
    subject_posts: [crate::peer::RootServiceSubjectPostOriginalV2; 2],
    subject_post_results: [Option<Result<(), RootServicePeerError>>; 2],
    socket_post: [Option<Result<(), SeqpacketError>>; 2],
    first: Option<Failure>,
    completed: bool,
}

impl CaptureHeldNativeOriginalV3 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            begin_completed: false,
            terminal_entered: false,
            demand: std::array::from_fn(|_| None),
            payment: std::array::from_fn(|_| None),
            current_catalog: None,
            output_after: std::array::from_fn(|_| StorageOutputOwedAfterV1::new()),
            output_arm: std::array::from_fn(|_| None),
            output_post: std::array::from_fn(|_| None),
            physical_post: None,
            native_boundary: None,
            host: ControllerStartupHostCgroupReadbackV1::new(),
            host_result: None,
            host_pair: None,
            listener: None,
            socket: None,
            peer: RootServiceConnectionOriginalV2::new(),
            peer_result: None,
            waits: std::array::from_fn(|_| None),
            records: std::array::from_fn(|_| None),
            bindings: std::array::from_fn(|_| None),
            subjects: std::array::from_fn(|_| RootServiceRecordOriginalV2::new()),
            subject_results: std::array::from_fn(|_| None),
            clocks: None,
            clock_status: std::array::from_fn(|_| None),
            begin: None,
            row: None,
            proof: None,
            proof_bytes: None,
            sent: None,
            terminal: None,
            terminal_binding: None,
            terminal_digest: None,
            complete_digest: None,
            ack: None,
            ack_sent: None,
            listener_post: std::array::from_fn(|_| None),
            socket_post: std::array::from_fn(|_| None),
            peer_posts: std::array::from_fn(|_| RootServiceConnectionOriginalV2::new()),
            peer_post_results: std::array::from_fn(|_| None),
            subject_posts: std::array::from_fn(|_| {
                crate::peer::RootServiceSubjectPostOriginalV2::new()
            }),
            subject_post_results: std::array::from_fn(|_| None),
            first: None,
            completed: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(
            value: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            Failure::Payment => self
                .demand
                .iter()
                .find_map(error)
                .or_else(|| self.payment.iter().find_map(error)),
            Failure::Catalog => error(&self.current_catalog),
            Failure::OutputArm(index) | Failure::OutputAfter(index) => self.output_after[index]
                .failure()
                .or_else(|| error(&self.output_arm[index]))
                .or_else(|| error(&self.output_post[index])),
            Failure::Host => self
                .host
                .failure()
                .or_else(|| error(&self.host_result))
                .or_else(|| error(&self.host_pair)),
            Failure::Listener => error(&self.listener),
            Failure::Accept => error(&self.socket),
            Failure::Peer => self.peer.failure().or_else(|| error(&self.peer_result)),
            Failure::Before => self.clocks.as_ref()?.failure_at_v3(0),
            Failure::ProofClock => self.clocks.as_ref()?.failure_at_v3(1),
            Failure::AckBefore => self.clocks.as_ref()?.failure_at_v3(4),
            Failure::After => self
                .clocks
                .as_ref()?
                .failure_at_v3(2)
                .or_else(|| self.transport_failure_v3(0)),
            Failure::TerminalClock => self.clocks.as_ref()?.failure_at_v3(3),
            Failure::AckPost => self
                .clocks
                .as_ref()?
                .failure_at_v3(5)
                .or_else(|| self.listener_post.iter().find_map(error))
                .or_else(|| self.socket_post.iter().find_map(error))
                .or_else(|| {
                    self.peer_posts
                        .iter()
                        .find_map(RootServiceConnectionOriginalV2::failure)
                })
                .or_else(|| {
                    self.subject_posts
                        .iter()
                        .find_map(crate::peer::RootServiceSubjectPostOriginalV2::failure)
                }),
            Failure::Wait(index) => error(&self.waits[index]),
            Failure::Receive(index) => error(&self.records[index]),
            Failure::Binding(index) => error(&self.bindings[index]),
            Failure::Subject(index) => self.subjects[index]
                .failure()
                .or_else(|| error(&self.subject_results[index])),
            Failure::Begin => error(&self.begin),
            Failure::Row => error(&self.row),
            Failure::Proof => error(&self.proof).or_else(|| error(&self.proof_bytes)),
            Failure::Send => self.sent.as_ref()?.failure(),
            Failure::Terminal => error(&self.terminal_binding).or_else(|| error(&self.terminal)),
            Failure::AckDigest => error(&self.complete_digest).or_else(|| error(&self.terminal_digest)),
            Failure::Ack => {
                error(&self.ack).or_else(|| self.ack_sent.as_ref().and_then(|sent| sent.failure()))
            }
            // This marker selects the exact lower receiving original at the
            // failed native boundary. Later owed posts never change that
            // selection or override an earlier held/body failure.
            Failure::NativeBoundary => self.native_boundary.as_ref().map(|cause| cause as _),
            Failure::Complete | Failure::Disposal => None,
        }
    }

    fn clock(
        &mut self,
        index: usize,
        lifetime: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    ) -> bool {
        let Some(clocks) = self.clocks.as_mut() else {
            return false;
        };
        self.clock_status[index] = Some(clocks.observe_verified_once_v3(index, lifetime));
        matches!(self.clock_status[index], Some(Ok(())))
    }

    fn receive(
        &mut self,
        index: usize,
        maximum: usize,
        deadline: u64,
    ) -> Result<(), ZfsWorkerError> {
        let Some(Ok(socket)) = self.socket.as_mut() else {
            return Err(worker_entry::retained());
        };
        self.first = Some(Failure::Wait(index));
        self.waits[index] = Some(
            aos_sandbox_linux::seqpacket::bounded::wait_storage_root_export_request_v2(
                socket, deadline,
            ),
        );
        if !matches!(self.waits[index], Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Receive(index));
        self.records[index] = Some(socket.receive_storage_held_output_reply_retaining_v2(maximum));
        let Some(Ok(record)) = self.records[index].as_ref() else {
            return Err(worker_entry::retained());
        };
        self.first = Some(Failure::Binding(index));
        self.bindings[index] = Some(socket.validate_received_origin_retaining(record));
        if !matches!(self.bindings[index], Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Subject(index));
        let Some(Ok((_, verifier))) = self.host_pair.as_ref() else {
            return Err(worker_entry::retained());
        };
        let Some(execution) = self
            .peer_result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return Err(worker_entry::retained());
        };
        self.subject_results[index] = Some(verifier.verify_record_retaining_v2(
            execution,
            socket.peer(),
            record.subject(),
            &mut self.subjects[index],
        ));
        if !matches!(self.subject_results[index], Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.first = None;
        Ok(())
    }
}

impl CaptureHeldNativeOriginalV3 {
    fn finish_transport_posts(&mut self, index: usize, listener: &RecordSubjectListener) -> bool {
        self.listener_post[index] = Some(listener.validate_current());
        if let (Some(Ok(socket)), Some(Ok((_, verifier)))) =
            (self.socket.as_mut(), self.host_pair.as_ref())
        {
            self.socket_post[index] = Some(socket.observe_owed_local_filesystem_path_v2(
                std::path::Path::new("/run/aos/sandbox-storage/existing-output.sock"),
            ));
            self.peer_post_results[index] = Some(
                verifier.verify_connection_retaining_v2(socket.peer(), &mut self.peer_posts[index]),
            );
            if let (Some(Ok(record)), Some(Ok(execution))) =
                (&self.records[index], self.peer_result.as_ref())
            {
                self.subject_post_results[index] = Some(verifier.observe_record_subject_owed_v2(
                    *execution,
                    record.subject(),
                    &mut self.subject_posts[index],
                ));
            }
        }
        self.transport_posts_complete_v3(index)
    }

    fn transport_failure_v3(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        self.listener_post[index]
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.socket_post[index]
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.peer_posts[index].failure())
            .or_else(|| self.subject_posts[index].failure())
    }

    fn transport_posts_complete_v3(&self, index: usize) -> bool {
        matches!(self.listener_post[index], Some(Ok(())))
            && matches!(self.socket_post[index], Some(Ok(())))
            && self.peer_post_results[index]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                == self
                    .peer_result
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
            && matches!(self.subject_post_results[index], Some(Ok(())))
    }
}

impl CaptureHeldNativeOriginalV3 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe_once_v3(
        &mut self,
        worker: &mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'_, '_, '_>,
        native: &NativeCaptureCreateOriginalV3,
        request: &[u8],
        mounted: &mut CaptureMountedParentOriginalV3,
        catalog: &crate::state::CaptureStateCatalogOriginalV3,
        physical: &crate::execution_output::CapturePhysicalBindingOriginalV3,
        terminal_native: &mut terminal::CaptureNativeTerminalOriginalV3,
        ready: &ReceivedRecord,
        anchor: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        listener: &mut RecordSubjectListener,
        store: &crate::StorageTransactionStore,
        state: &aos_sandbox_controller_domain::Journal,
        output: &mut StorageExecutionOutputCustodyV1,
    ) -> Result<(), ZfsWorkerError> {
        if !mounted.completed_v3() || self.terminal_entered || self.first.is_some() {
            return Err(ZfsWorkerError::Authority);
        }
        let phase = if self.begin_completed {
            self.terminal_entered = true;
            1
        } else {
            if self.entered {
                return Err(ZfsWorkerError::Authority);
            }
            self.entered = true;
            0
        };
        self.first = Some(Failure::Payment);
        self.demand[phase] = Some(
            store
                .receiving_inventory_geometry_v1()
                .and_then(|geometry| geometry.retained_model_demand_v1()),
        );
        let Some(demand) = self.demand[phase]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return Err(worker_entry::retained());
        };
        self.payment[phase] = Some(worker.reserve_capture_terminal_models_v3(
            state,
            output.ledger().held_journal_for_receiving_v1(),
            native.admission_v3().lifetime_v3(),
            demand,
        ));
        if !matches!(self.payment[phase], Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::OutputArm(phase));
        self.output_arm[phase] = Some(output.prepare_capture_owed_after_v3(
            worker,
            state,
            native.admission_v3().lifetime_v3(),
            &mut self.output_after[phase],
        ));
        if !matches!(self.output_arm[phase], Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        let body = if phase == 0 {
            self.begin_body_v3(
                native, request, mounted, catalog, physical, listener, store, output,
            )
        } else {
            self.terminal_body_v3(
                worker,
                native,
                request,
                mounted,
                physical,
                terminal_native,
                ready,
                anchor,
                listener,
                store,
                state,
                output,
            )
        };
        // The two phases each close their own prepaid Output and native posts
        // before returning to the daemon. The physical worker stays occupied.
        let posts = if self.listener_post[phase].is_none() {
            self.finish_transport_posts(phase, listener)
        } else {
            self.transport_posts_complete_v3(phase)
        };
        let clock_index = if phase == 0 { 2 } else { 5 };
        let clock = if self.clock_status[clock_index].is_none() && self.clocks.is_some() {
            self.clock(clock_index, native.admission_v3().lifetime_v3())
        } else {
            matches!(self.clock_status[clock_index], Some(Ok(())))
        };
        self.output_post[phase] =
            Some(output.finish_capture_owed_after_v3(worker, &mut self.output_after[phase]));
        if body.is_err() {
            return body;
        }
        if !posts || !clock {
            self.first = Some(if phase == 0 {
                Failure::After
            } else {
                Failure::AckPost
            });
            return Err(worker_entry::retained());
        }
        if !matches!(self.output_post[phase], Some(Ok(()))) {
            self.first = Some(Failure::OutputAfter(phase));
            return Err(worker_entry::retained());
        }
        if phase == 0 {
            // Only sender duplicates retire after the complete Begin phase.
            // The genuine Host aliases and occupied F continuation survive.
            mounted.retire_transferred_pipe_aliases_v3();
            self.begin_completed = true;
        } else {
            self.completed = true;
        }
        self.first = None;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_body_v3(
        &mut self,
        native: &NativeCaptureCreateOriginalV3,
        request: &[u8],
        mounted: &CaptureMountedParentOriginalV3,
        catalog: &crate::state::CaptureStateCatalogOriginalV3,
        physical: &crate::execution_output::CapturePhysicalBindingOriginalV3,
        listener: &mut RecordSubjectListener,
        store: &crate::StorageTransactionStore,
        output: &mut StorageExecutionOutputCustodyV1,
    ) -> Result<(), ZfsWorkerError> {
        let source = *native.admission_v3().source_v3();
        let cutoff = native.admission_v3().lifetime_v3().ongoing_deadline_v3();
        self.clocks = Some(Clock::from_verified_v3(native.admission_v3().lifetime_v3()));
        self.first = Some(Failure::Host);
        self.host_result = Some(self.host.capture_once());
        if !matches!(self.host_result, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.host_pair = Some(HostRootExportPeerVerifier::take_fixed_capture_v2(
            &mut self.host,
        ));
        if !matches!(self.host_pair, Some(Ok(_))) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Listener);
        self.listener = Some(listener.validate_current());
        if !matches!(self.listener, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Accept);
        self.socket = Some(listener.accept_storage_root_export_retaining_v2());
        let Some(Ok(socket)) = self.socket.as_ref() else {
            return Err(worker_entry::retained());
        };
        self.first = Some(Failure::Peer);
        let Some(Ok((_, verifier))) = self.host_pair.as_ref() else {
            return Err(worker_entry::retained());
        };
        self.peer_result =
            Some(verifier.verify_connection_retaining_v2(socket.peer(), &mut self.peer));
        if !matches!(self.peer_result, Some(Ok(_))) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Before);
        if !self.clock(0, native.admission_v3().lifetime_v3()) {
            return Err(worker_entry::retained());
        }
        let acquisition = native
            .admission_v3()
            .lifetime_v3()
            .acquisition_deadline_v3();
        self.receive(0, CAPTURE_BEGIN_BYTES_V3, acquisition)?;
        self.first = Some(Failure::Begin);
        let Some(Ok(record)) = self.records[0].as_ref() else {
            return Err(worker_entry::retained());
        };
        self.begin = Some(CaptureHeldBeginDataV3::decode(record.payload()));
        let Some(begin) = self
            .begin
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return Err(worker_entry::retained());
        };
        if begin.source != source
            || begin.attempt != native.worker_result_identity_v3().attempt
            || begin.durable_attempt_digest != native.durable_attempt_digest_v3()
            || begin.cutoff_boottime_nanoseconds > cutoff
            || begin.acquisition_cutoff_boottime_nanoseconds > acquisition
        {
            return Err(ZfsWorkerError::Authority);
        }
        // Fresh nonce/readback comparison remains a short acquisition bound;
        // it cannot replace the separately verified original execution horizon.
        if self
            .clocks
            .as_ref()
            .and_then(|clock| clock.boottime_at_v3(0))
            .is_none_or(|clock| clock >= begin.acquisition_deadline_boottime_nanoseconds)
        {
            return Err(ZfsWorkerError::Authority);
        }
        self.first = Some(Failure::Row);
        let original = source.original_source_v1();
        self.row = Some(output.ledger().read_protected_retained_output(
            *original.settlement().execution().as_bytes(),
            *original.settlement().create_operation().as_bytes(),
            original.output_record_digest(),
        ));
        let Some(Ok(row)) = self.row.as_ref() else {
            return Err(worker_entry::retained());
        };
        let Some(mounted_report) = mounted.report_v3() else {
            return Err(worker_entry::retained());
        };
        self.first = Some(Failure::Catalog);
        self.current_catalog = Some(store.verified_resolver_journal());
        let Some(Ok(current_catalog)) = self.current_catalog.as_ref() else {
            return Err(worker_entry::retained());
        };
        let requirement = native
            .catalog_resolution_v3()
            .ok_or(ZfsWorkerError::Authority)?
            .requirement_v3();
        let dataset = requirement
            .verify_present(current_catalog.physical())
            .map_err(|_| ZfsWorkerError::Authority)?;
        let expected = catalog
            .dataset_for_native_v3(native)
            .ok_or(ZfsWorkerError::Authority)?;
        if dataset.binding() != expected.binding()
            || dataset.binding() != mounted_report.dataset_binding
        {
            return Err(ZfsWorkerError::Authority);
        }
        let physical_row = physical
            .row_digest_for_native_v3(native)
            .ok_or(ZfsWorkerError::Authority)?;
        self.first = Some(Failure::Proof);
        self.proof = Some((|| {
            let proof = CaptureHeldProofDataV2 {
                begin_digest: begin.digest()?,
                row: aos_sandbox_protocol::storage_existing_output::ExistingOutputResponseV1 {
                    nonce: begin.nonce,
                    request_digest: begin.digest()?,
                    execution: row.execution(),
                    create: row.create_operation(),
                    assignment_digest: *row.assignment_digest().as_bytes(),
                    claim_digest: *row.claim_digest().as_bytes(),
                    record_digest: *row.record_digest().as_bytes(),
                    admitted_bytes: row.admitted_bytes(),
                    maximum_stdout_bytes: row.maximum_stdout_bytes(),
                    maximum_stderr_bytes: row.maximum_stderr_bytes(),
                    journal_sequence: row.journal_sequence(),
                },
                physical_row_digest: physical_row,
                dataset_binding: mounted_report.dataset_binding,
                catalog_generation: dataset.catalog_v3().generation(),
                catalog_digest: dataset.catalog_v3().digest(),
                mount_id: mounted_report.mount_id,
                stdout: CapturePipeIdentityDataV2 {
                    device: mounted_report.pipe_identities[0].0,
                    inode: mounted_report.pipe_identities[0].1,
                },
                stderr: CapturePipeIdentityDataV2 {
                    device: mounted_report.pipe_identities[1].0,
                    inode: mounted_report.pipe_identities[1].1,
                },
                worker_request_digest: ObjectDigest::from_bytes(
                    request[request.len() - 32..]
                        .try_into()
                        .map_err(|_| CaptureSessionProtocolErrorV2::Binding)?,
                ),
            };
            proof.verify_begin_ongoing_v3(begin)?;
            Ok(proof)
        })());
        let Some(proof) = self
            .proof
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return Err(worker_entry::retained());
        };
        self.proof_bytes = Some(proof.encode());
        self.first = Some(Failure::ProofClock);
        if !self.clock(1, native.admission_v3().lifetime_v3())
            || self
                .clocks
                .as_ref()
                .and_then(|clock| clock.boottime_at_v3(1))
                .is_none_or(|now| now >= begin.acquisition_deadline_boottime_nanoseconds)
        {
            return Err(worker_entry::retained());
        }
        let Some(Ok(bytes)) = self.proof_bytes.as_ref() else {
            return Err(worker_entry::retained());
        };
        let Some(pipes) = mounted.pipe_endpoints_v3() else {
            return Err(worker_entry::retained());
        };
        let Some(Ok(socket)) = self.socket.as_mut() else {
            return Err(worker_entry::retained());
        };
        self.first = Some(Failure::Send);
        self.sent = Some(aos_sandbox_linux::seqpacket::bounded::send_descriptor_worker_record_v1(socket,
            bytes, &[pipes[0].as_fd(), pipes[1].as_fd()],
            aos_sandbox_linux::seqpacket::bounded::DescriptorWorkerSendKindV1::StorageCaptureProof,
            begin.acquisition_deadline_boottime_nanoseconds));
        let sent = self.sent.as_ref().is_some_and(|sent| sent.is_sent());
        let after = self.clock(2, native.admission_v3().lifetime_v3());
        let posts = self.finish_transport_posts(0, listener);
        if !sent {
            return Err(worker_entry::retained());
        }
        if !after || !posts {
            self.first = Some(Failure::After);
            return Err(worker_entry::retained());
        }
        self.first = None;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn terminal_body_v3(
        &mut self,
        worker: &mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'_, '_, '_>,
        native: &NativeCaptureCreateOriginalV3,
        request: &[u8],
        mounted: &CaptureMountedParentOriginalV3,
        physical: &crate::execution_output::CapturePhysicalBindingOriginalV3,
        terminal_native: &mut terminal::CaptureNativeTerminalOriginalV3,
        ready: &ReceivedRecord,
        anchor: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        listener: &mut RecordSubjectListener,
        store: &crate::StorageTransactionStore,
        state: &aos_sandbox_controller_domain::Journal,
        output: &mut StorageExecutionOutputCustodyV1,
    ) -> Result<(), ZfsWorkerError> {
        let begin = self
            .begin
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ZfsWorkerError::Authority)?;
        let proof = self
            .proof
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ZfsWorkerError::Authority)?;
        let negative = begin.cutoff_boottime_nanoseconds.checked_add(aos_sandbox_protocol::storage_capture_session::CAPTURE_NEGATIVE_TERMINAL_NANOSECONDS_V2)
            .ok_or(ZfsWorkerError::Authority)?;
        self.receive(1, CAPTURE_TERMINAL_BYTES_V2, negative)?;
        self.first = Some(Failure::Terminal);
        let Some(Ok(record)) = self.records[1].as_ref() else {
            return Err(worker_entry::retained());
        };
        self.terminal = Some(CaptureHeldTerminalDataV2::decode(record.payload()));
        let Some(terminal) = self
            .terminal
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return Err(worker_entry::retained());
        };
        self.terminal_binding = Some(terminal.verify_proof_ongoing_v3(begin, proof));
        if !matches!(self.terminal_binding, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::TerminalClock);
        let current = self.clock(3, native.admission_v3().lifetime_v3())
            && self
                .clocks
                .as_ref()
                .and_then(|clock| clock.boottime_at_v3(3))
                .is_some_and(|now| now < begin.cutoff_boottime_nanoseconds);
        let complete = terminal.mode == CaptureTerminalModeDataV2::Complete;
        let result = if complete {
            if !current {
                return Err(worker_entry::retained());
            }
            self.first = Some(Failure::Complete);
            terminal_native.observe_once_v3(
                worker,
                native,
                request,
                mounted.report_v3().ok_or(ZfsWorkerError::Authority)?,
                physical
                    .row_digest_for_native_v3(native)
                    .ok_or(ZfsWorkerError::Authority)?,
                ready,
                anchor,
                store,
                state,
                output,
                terminal.settlement_digest,
            )?;
            Some(
                terminal_native
                    .completed_v3()
                    .ok_or(ZfsWorkerError::Authority)?,
            )
        } else {
            None
        };
        self.first = Some(Failure::AckDigest);
        let result_digest = match result {
            Some(record) => {
                self.complete_digest = Some(record.digest());
                let Some(Ok(digest)) = self.complete_digest.as_ref() else {
                    return Err(worker_entry::retained());
                };
                *digest
            }
            // The canonical Abort grammar has no complete result.
            None => ObjectDigest::from_bytes([0; 32]),
        };
        self.terminal_digest = Some(terminal.digest());
        let Some(Ok(terminal_digest)) = self.terminal_digest.as_ref() else {
            return Err(worker_entry::retained());
        };
        self.first = Some(Failure::Ack);
        self.ack = Some(
            CaptureHeldAckDataV2 {
                mode: terminal.mode,
                nonce: terminal.nonce,
                terminal_digest: *terminal_digest,
                proof_digest: terminal.proof_digest,
                held_head: terminal.held_head,
                final_head: output
                    .ledger()
                    .held_journal_for_receiving_v1()
                    .snapshot_sequence(),
                result_digest,
                complete: result,
            }
            .encode(),
        );
        let Some(Ok(ack)) = self.ack.as_ref() else {
            return Err(worker_entry::retained());
        };
        let Some(Ok(socket)) = self.socket.as_mut() else {
            return Err(worker_entry::retained());
        };
        // Abort is an independently prepaid negative transport obligation. An
        // expired positive sample never suppresses this same original reply.
        self.first = Some(Failure::AckBefore);
        let before_ack = self
            .clocks
            .as_mut()
            .map(|clock| clock.observe_verified_once_v3(4, native.admission_v3().lifetime_v3()))
            .is_some_and(|value| value.is_ok());
        let before_ack = before_ack
            && self
                .clocks
                .as_ref()
                .and_then(|clock| clock.boottime_at_v3(4))
                .is_some_and(|now| now < begin.cutoff_boottime_nanoseconds);
        if complete && !before_ack {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Ack);
        self.ack_sent = Some(aos_sandbox_linux::seqpacket::bounded::send_descriptor_worker_record_v1(socket,
            ack, &[], aos_sandbox_linux::seqpacket::bounded::DescriptorWorkerSendKindV1::StorageCaptureAck,
            if complete { begin.cutoff_boottime_nanoseconds } else { negative }));
        let sent = self.ack_sent.as_ref().is_some_and(|sent| sent.is_sent());
        let after = self.clock(5, native.admission_v3().lifetime_v3());
        let posts = self.finish_transport_posts(1, listener);
        if !current {
            self.first = Some(Failure::TerminalClock);
            return Err(worker_entry::retained());
        }
        if !before_ack {
            self.first = Some(Failure::AckBefore);
            return Err(worker_entry::retained());
        }
        if !sent {
            return Err(worker_entry::retained());
        }
        if !complete || !after || !posts {
            self.first = Some(Failure::AckPost);
            return Err(worker_entry::retained());
        }
        self.completed = true;
        self.first = None;
        Ok(())
    }
}

impl CaptureHeldNativeOriginalV3 {
    pub(super) fn receiving_geometry_v3() -> Option<(usize, usize)> {
        let (admission_bytes, admission_files) =
            DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?;
        let (begin_bytes, begin_files) =
            DescriptorSubjectSocket::storage_held_output_reply_obligations_v2(
                CAPTURE_BEGIN_BYTES_V3,
            )?;
        let (terminal_bytes, terminal_files) =
            DescriptorSubjectSocket::storage_held_output_reply_obligations_v2(
                CAPTURE_TERMINAL_BYTES_V2,
            )?;
        let (peer_bytes, peer_files) = RootServiceConnectionOriginalV2::receiving_demand_v2()?;
        let (record_bytes, record_files) = RootServiceRecordOriginalV2::receiving_demand_v2()?;
        // Accepted peer plus two independently owed peer posts; two record
        // sandwiches plus their distinct subject posts use the exact existing
        // membership supplier. Subject posts are bounded by a full connection
        // sampler, which includes the same one exact membership engine.
        let peers = peer_bytes
            .checked_mul(5)?
            .checked_add(record_bytes.checked_mul(2)?)?;
        let peer_fds = peer_files
            .checked_mul(5)?
            .checked_add(record_files.checked_mul(2)?)?;
        let host = std::mem::size_of::<ControllerStartupHostCgroupReadbackV1>().checked_mul(3)?;
        let bytes = std::mem::size_of::<rustix::event::PollFd<'_>>()
            .checked_mul(2)?
            .checked_add(admission_bytes)?
            .checked_add(begin_bytes)?
            .checked_add(terminal_bytes)?
            .checked_add(peers)?
            .checked_add(host)?
            .checked_add(Clock::receiving_bytes_v3()?)?;
        // Fixed Host cgroup capture owns at most six native descriptors. All
        // raw-admission and hostile80 ancillary prefixes are priced separately.
        let files = admission_files
            .checked_add(begin_files)?
            .checked_add(terminal_files)?
            .checked_add(peer_fds)?
            .checked_add(6)?
            .checked_add(Clock::maximum_retained_files_v3()?)?;
        Some((bytes, files))
    }
}

impl CaptureHeldNativeOriginalV3 {
    pub(super) fn awaiting_begin_v3(&self) -> bool {
        !self.entered && self.first.is_none()
    }

    pub(super) fn push_terminal_poll_v3<'fd>(
        &'fd self,
        polls: &mut Vec<rustix::event::PollFd<'fd>>,
    ) -> Option<usize> {
        if !self.begin_completed || self.terminal_entered || self.first.is_some() {
            return None;
        }
        let socket = self.socket.as_ref()?.as_ref().ok()?;
        let descriptor = socket.as_fd().ok()?;
        let index = polls.len();
        polls.push(rustix::event::PollFd::from_borrowed_fd(
            descriptor,
            rustix::event::PollFlags::IN,
        ));
        Some(index)
    }

    pub(super) fn dispose_after_positive_v3(&mut self) {
        if !self.completed
            || self.first.is_some()
            || !self
                .output_post
                .iter()
                .all(|post| matches!(post, Some(Ok(()))))
            || !self.ack_sent.as_ref().is_some_and(|sent| sent.is_sent())
        {
            std::process::abort();
        }
        drop(self.records[0].take());
        drop(self.records[1].take());
        drop(self.socket.take());
        drop(self.host_pair.take());
    }
}

impl CapturePhysicalPreparationOriginalV3 {
    pub(crate) fn serve_host_held_once_v3(
        &mut self,
        listener: &mut RecordSubjectListener,
        store: &crate::StorageTransactionStore,
        state: &aos_sandbox_controller_domain::Journal,
        output: &mut StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), ZfsWorkerError> {
        if !self.mounted_preparation_completed_v3() || self.held.terminal_entered {
            return Err(ZfsWorkerError::Authority);
        }
        self.first = Some(CaptureFailureV3::Held);
        let Some(Ok(resident)) = self.resident.as_mut() else {
            return Err(worker_entry::retained());
        };
        let Some(Ok(socket)) = self.exchange.connection.as_mut() else {
            return Err(worker_entry::retained());
        };
        let Some(anchor) = self.exchange.cgroup.anchor() else {
            return Err(worker_entry::retained());
        };
        let Some(population) = self.exchange.cgroup.population() else {
            return Err(worker_entry::retained());
        };
        let Some(ready) = self.ready.as_ref() else {
            return Err(worker_entry::retained());
        };
        // The producer runs every fallible check and its independently owed
        // failed-worker post before constructing a successful exclusive loan.
        let resumed = receiving.resume_capture_worker_with_failed_post_v3(
            resident, socket, anchor, population,
        );
        let mut worker = match resumed {
            Ok(worker) => worker,
            Err(cause) => {
                self.held.native_boundary = Some(cause);
                self.held.first = Some(Failure::NativeBoundary);
                return Err(worker_entry::retained());
            }
        };
        let body = self.held.observe_once_v3(
            &mut worker,
            &self.native,
            &self.exchange.request,
            &mut self.mounted,
            &self.catalog,
            &self.physical,
            &mut self.terminal,
            ready,
            anchor,
            listener,
            store,
            state,
            output,
        );
        if body.is_err() {
            self.held.physical_post = Some(worker.finish_failed_capture_interval_v3());
            return body;
        }
        if !self.held.terminal_entered {
            // Begin/proof and all of its own posts are complete. Return the
            // actual Rust borrow while preserving the same occupied worker.
            worker.park_v2();
            self.first = None;
            return Ok(());
        }
        // Full native completion and Host/Ack/Output posts precede the actual
        // death/population/independent F post. Only that token can retire the
        // same native issuer; neither a parsed676 nor Abort/Ack can enter here.
        let Some(record) = self.terminal.completed_v3() else {
            self.held.physical_post = Some(worker.finish_failed_capture_interval_v3());
            return Err(worker_entry::retained());
        };
        self.held.first = Some(Failure::Disposal);
        let mut disposal = match worker.prepare_positive_disposal_v2(self.native.admission_v3().lifetime_v3()) {
            Ok(disposal) => disposal,
            Err(cause) => {
                self.held.native_boundary = Some(cause);
                self.held.first = Some(Failure::NativeBoundary);
                return Err(worker_entry::retained());
            }
        };
        self.native
            .retire_after_complete_disposal_v3(&mut disposal, &record)?;
        self.held.first = None;
        self.held.dispose_after_positive_v3();
        // The actual READY Arc retained by the resident token is the final
        // native association. This redundant upper Arc can now retire.
        drop(self.ready.take());
        disposal.complete_after_disposal_v2();
        self.first = None;
        Ok(())
    }
}

impl CapturePhysicalPreparationOriginalV3 {
    pub(crate) fn awaiting_host_begin_v3(&self) -> bool {
        self.mounted_preparation_completed_v3() && self.held.awaiting_begin_v3()
    }

    pub(crate) fn push_host_terminal_poll_v3<'fd>(
        &'fd self,
        polls: &mut Vec<rustix::event::PollFd<'fd>>,
    ) -> Option<usize> {
        if self.first.is_some() {
            return None;
        }
        self.held.push_terminal_poll_v3(polls)
    }
}

impl CaptureHeldNativeOriginalV3 {
    pub(super) fn stop_selector_v4(&self) -> Option<CaptureHeldBeginDataV3> {
        // The actual verified Begin, private native physical proof and entered
        // retained send recipe may precede a later uncertain send/post. Fresh
        // Stop can contain that original without claiming positive Sent. The
        // original sender, all causes and outstanding writer aliases stay held.
        // This selector lends comparison DATA only; actual fresh signed Stop,
        // same READY/source/attempt/runtime/physical binding and peer checks
        // remain mandatory at the separate negative receiver.
        if self.sent.is_none() || !matches!(self.proof_bytes, Some(Ok(_))) {
            return None;
        }
        self.begin.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn stop_peer_verifier_v4(&self) -> Option<&HostRootExportPeerVerifier> {
        self.host_pair.as_ref()?.as_ref().ok().map(|(_, verifier)| verifier)
    }
}
