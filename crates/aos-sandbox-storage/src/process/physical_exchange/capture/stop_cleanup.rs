//! Receives fresh Stop cancellation on one prepaid channel of the same Capture.
//!
//! The old held channel, original errors, native worker and full F operation
//! remain occupied. A new native-authenticated Host connection may cancel this
//! exact Source/attempt/runtime under fresh signed Stop permission. It produces
//! only QuiescentIncomplete DATA, never676, drained output or F disposal.

use super::*;
use crate::peer::{
    HostRootExportPeerVerifier, RootServiceConnectionOriginalV2, RootServicePeerError,
    RootServiceRecordOriginalV2, RootServiceSubjectPostOriginalV2,
};
use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_broker::{
    BrokerAdmissionError, BrokerAuthority, StorageCaptureStopInspectionOriginalV4,
    VerifiedStorageCaptureStopCleanupV4,
};
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_linux::seqpacket::bounded::{
    BoundedRecordError, DescriptorWorkerSendAttemptV1, DescriptorWorkerSendKindV1,
    send_descriptor_worker_record_v1, wait_storage_root_export_request_v2,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, RecordSubjectListener, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1, SeqpacketError,
};
use aos_sandbox_protocol::storage_capture_session::ongoing::CaptureHeldBeginDataV3;
use aos_sandbox_protocol::storage_capture_session::stop_cleanup::{
    CAPTURE_STOP_RECEIPT_BYTES_V4, CaptureQuiescentIncompleteFieldsDataV4,
    CaptureQuiescentIncompleteReceiptDataV4, CaptureStopCleanupProtocolErrorV4,
    CaptureStopCleanupRequestDataV4, MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4,
};

// One ingress sample, one after-ingress/admission sample, two exact close
// gates, and six distinct alias/native/send/post observations remain resident.
const CLOCKS: usize = 8 + aos_sandbox_linux::seqpacket::capture_stop::CAPTURE_WRITER_ALIAS_COUNT_V4;
const AFTER_ALIAS: usize = CLOCKS - 6;
const BEFORE_NATIVE: usize = CLOCKS - 5;
const AFTER_NATIVE: usize = CLOCKS - 4;
const BEFORE_SEND: usize = CLOCKS - 3;
const AFTER_SEND: usize = CLOCKS - 2;
const AFTER_POST: usize = CLOCKS - 1;

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("fresh Capture Stop clock is unavailable or stale")]
    Stale,
    #[error(transparent)]
    Native(aos_sandbox_linux::Error),
}
impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }
    fn kernel(cause: aos_sandbox_linux::Error) -> Self {
        Self::Native(cause)
    }
}
type Clock = RetainedKernelPairedClockAttemptV1<ClockError>;

struct ClockSlot {
    original: Clock,
    pair: Option<Result<RawPairedClockSample, ClockError>>,
    cut: Option<Result<(), BrokerAdmissionError>>,
}
impl ClockSlot {
    fn new() -> Self {
        Self {
            original: Clock::default(),
            pair: None,
            cut: None,
        }
    }
    fn observe(
        &mut self,
        permission: Option<&VerifiedStorageCaptureStopCleanupV4>,
    ) -> Result<(), ZfsWorkerError> {
        if self.pair.is_some() {
            return Err(ZfsWorkerError::Authority);
        }
        self.pair = Some(self.original.observe_once(None));
        let Some(Ok(pair)) = self.pair.as_ref() else {
            return Err(worker_entry::retained());
        };
        if let Some(permission) = permission {
            self.cut = Some(permission.require_current_sample_v4(pair));
            if !matches!(self.cut, Some(Ok(()))) {
                return Err(worker_entry::retained());
            }
        }
        Ok(())
    }
    fn sample(&self) -> Option<RawPairedClockSample> {
        self.pair.as_ref()?.as_ref().ok().copied()
    }
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .failure()
            .or_else(|| self.pair.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.cut.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[derive(Clone, Copy)]
enum First {
    Peer,
    Clock(usize),
    Wait,
    Receive,
    Binding,
    Subject,
    Wire,
    Begin,
    Selector,
    Verify,
    Aliases,
    Native,
    Receipt,
    Post(usize),
    Send,
}

pub(super) struct CaptureStopCleanupOriginalV4 {
    // This is the actual enrolled authority's passive complete decoding bound,
    // captured before the initial physical flight. It creates no permission.
    inspection_bytes: usize,
    entered: bool,
    waiting: Option<Result<(), BoundedRecordError>>,
    listener: Option<Result<(), SeqpacketError>>,
    accepted: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    listener_after: Option<Result<(), SeqpacketError>>,
    returned: Option<Result<(), ZfsWorkerError>>,
    action: Action,
}

struct Action {
    clocks: [ClockSlot; CLOCKS],
    peer: RootServiceConnectionOriginalV2,
    peer_result: Option<Result<aos_sandbox_linux::pidfd::PidFdInfo, RootServicePeerError>>,
    wait: Option<Result<(), BoundedRecordError>>,
    record: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    binding: Option<Result<(), RecordBindingError>>,
    subject: RootServiceRecordOriginalV2,
    subject_result: Option<Result<(), RootServicePeerError>>,
    wire: Option<Result<(), CaptureStopCleanupProtocolErrorV4>>,
    begin_digest: Option<
        Result<
            [u8; 32],
            aos_sandbox_protocol::storage_capture_session::CaptureSessionProtocolErrorV2,
        >,
    >,
    selector: Option<Result<(), ZfsWorkerError>>,
    inspector: StorageCaptureStopInspectionOriginalV4,
    inspection: Option<Result<(), BrokerAdmissionError>>,
    aliases: Option<Result<(), ZfsWorkerError>>,
    alias_gate: Option<ZfsWorkerError>,
    native: Option<Result<(), StorageReceivingClosedV1>>,
    fields: Option<CaptureQuiescentIncompleteFieldsDataV4>,
    receipt:
        Option<Result<CaptureQuiescentIncompleteReceiptDataV4, CaptureStopCleanupProtocolErrorV4>>,
    sent: Option<DescriptorWorkerSendAttemptV1>,
    peer_after: [RootServiceConnectionOriginalV2; 2],
    peer_after_result:
        [Option<Result<aos_sandbox_linux::pidfd::PidFdInfo, RootServicePeerError>>; 2],
    subject_after: [RootServiceSubjectPostOriginalV2; 2],
    subject_after_result: [Option<Result<(), RootServicePeerError>>; 2],
    socket_after: [Option<Result<(), SeqpacketError>>; 2],
    result: Option<Result<(), ZfsWorkerError>>,
    final_result: Option<Result<(), ZfsWorkerError>>,
    first: Option<First>,
    completed: bool,
}

impl CaptureStopCleanupOriginalV4 {
    pub(super) fn new(inspection_bytes: usize) -> Self {
        Self {
            inspection_bytes,
            entered: false,
            waiting: None,
            listener: None,
            accepted: None,
            listener_after: None,
            returned: None,
            action: Action::new(),
        }
    }

    pub(crate) fn receiving_demand_v4(inspection_bytes: usize) -> Option<ResourceVector> {
        let (admission, admission_files) =
            DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?;
        let (record, record_files) =
            DescriptorSubjectSocket::storage_held_output_reply_obligations_v2(
                MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4,
            )?;
        let (peer, peer_files) = RootServiceConnectionOriginalV2::receiving_demand_v2()?;
        let (subject, subject_files) = RootServiceRecordOriginalV2::receiving_demand_v2()?;
        // One before and two after peer samples, plus one exact record sandwich
        // and two owed subject samples. A full peer sampler bounds each owed
        // subject's same exact membership/liveness recipe, as in held.rs.
        let memory = std::mem::size_of::<Self>()
            .checked_add(inspection_bytes)?.checked_add(admission)?.checked_add(record)?
            .checked_add(aos_sandbox_linux::seqpacket::bounded::capture_stop_listener_wait_bytes_v4()?)?
            .checked_add(peer.checked_mul(5)?)?.checked_add(subject)?
            .checked_add(Clock::dominant_requested_bytes_v1()?.checked_mul(CLOCKS)?)?
            .checked_add(aos_sandbox_linux::seqpacket::capture_stop::CaptureWriterAliasCloseOriginalV4::receiving_bytes_v4()?)?;
        let files = admission_files
            .checked_add(record_files)?
            .checked_add(peer_files.checked_mul(5)?)?
            .checked_add(subject_files)?
            .checked_add(Clock::MAXIMUM_RETAINED_FILES_V1.checked_mul(CLOCKS)?)?;
        let traffic =
            MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4.checked_add(CAPTURE_STOP_RECEIPT_BYTES_V4)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                .with(D::NetworkBytes, u64::try_from(traffic).ok()?)
                .with(
                    D::OutputBytes,
                    u64::try_from(CAPTURE_STOP_RECEIPT_BYTES_V4).ok()?,
                ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe_once_v4(
        &mut self,
        listener: &mut RecordSubjectListener,
        verifier: &HostRootExportPeerVerifier,
        begin: &CaptureHeldBeginDataV3,
        authority: &BrokerAuthority,
        native: &NativeCaptureCreateOriginalV3,
        mounted: &mut CaptureMountedParentOriginalV3,
        physical: &crate::execution_output::CapturePhysicalBindingOriginalV3,
        resident: &aos_sandbox::StorageResidentCaptureWorkerV2,
        anchor: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        population: &aos_sandbox_linux::cgroup::CgroupPopulationMonitor,
        state: &aos_sandbox::Journal,
        output: &aos_sandbox::Journal,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered {
            return Err(ZfsWorkerError::Authority);
        }
        // A malformed, replayed or failing connection cannot reset this slot.
        self.entered = true;
        self.listener = Some(listener.validate_current());
        if !matches!(self.listener, Some(Ok(()))) {
            self.listener_after = Some(listener.validate_current());
            return Err(worker_entry::retained());
        }
        if authority.storage_capture_stop_inspection_receiving_bytes_v4(
            MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4,
        ) != Some(self.inspection_bytes)
        {
            self.returned = Some(Err(ZfsWorkerError::Authority));
            self.listener_after = Some(listener.validate_current());
            return Err(worker_entry::retained());
        }
        self.accepted = Some(listener.accept_storage_root_export_retaining_v2());
        self.returned = Some(match self.accepted.as_mut() {
            Some(Ok(socket)) => self.action.run_once_v4(
                socket, verifier, begin, authority, native, mounted, physical, resident, anchor,
                population, state, output, receiving,
            ),
            _ => Err(worker_entry::retained()),
        });
        // Listener debt remains independently owed after accepted-prefix poison.
        self.listener_after = Some(listener.validate_current());
        if !matches!(self.returned, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        if !matches!(self.listener_after, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        Ok(())
    }
}

impl Action {
    fn new() -> Self {
        Self {
            clocks: std::array::from_fn(|_| ClockSlot::new()),
            peer: RootServiceConnectionOriginalV2::new(),
            peer_result: None,
            wait: None,
            record: None,
            binding: None,
            subject: RootServiceRecordOriginalV2::new(),
            subject_result: None,
            wire: None,
            begin_digest: None,
            selector: None,
            inspector: StorageCaptureStopInspectionOriginalV4::new(),
            inspection: None,
            aliases: None,
            alias_gate: None,
            native: None,
            fields: None,
            receipt: None,
            sent: None,
            peer_after: std::array::from_fn(|_| RootServiceConnectionOriginalV2::new()),
            peer_after_result: std::array::from_fn(|_| None),
            subject_after: std::array::from_fn(|_| RootServiceSubjectPostOriginalV2::new()),
            subject_after_result: std::array::from_fn(|_| None),
            socket_after: std::array::from_fn(|_| None),
            result: None,
            final_result: None,
            first: None,
            completed: false,
        }
    }

    fn posts(
        &mut self,
        index: usize,
        socket: &DescriptorSubjectSocket,
        verifier: &HostRootExportPeerVerifier,
    ) -> bool {
        self.socket_after[index] = Some(socket.observe_owed_local_filesystem_path_v2(
            std::path::Path::new("/run/aos/sandbox-storage/existing-output.sock"),
        ));
        self.peer_after_result[index] = Some(
            verifier.verify_connection_retaining_v2(socket.peer(), &mut self.peer_after[index]),
        );
        if let (Some(Ok(record)), Some(Ok(peer))) = (&self.record, self.peer_result.as_ref()) {
            self.subject_after_result[index] = Some(verifier.observe_record_subject_owed_v2(
                *peer,
                record.subject(),
                &mut self.subject_after[index],
            ));
        }
        let positive = matches!(self.socket_after[index], Some(Ok(())))
            && matches!(self.peer_result, Some(Ok(_)))
            && self.peer_after_result[index]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                == self
                    .peer_result
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
            && (!matches!(self.record, Some(Ok(_)))
                || matches!(self.subject_after_result[index], Some(Ok(()))));
        if !positive {
            self.first.get_or_insert(First::Post(index));
        }
        positive
    }

    #[allow(clippy::too_many_arguments)]
    fn run_once_v4(
        &mut self,
        socket: &mut DescriptorSubjectSocket,
        verifier: &HostRootExportPeerVerifier,
        begin: &CaptureHeldBeginDataV3,
        authority: &BrokerAuthority,
        native: &NativeCaptureCreateOriginalV3,
        mounted: &mut CaptureMountedParentOriginalV3,
        physical: &crate::execution_output::CapturePhysicalBindingOriginalV3,
        resident: &aos_sandbox::StorageResidentCaptureWorkerV2,
        anchor: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        population: &aos_sandbox_linux::cgroup::CgroupPopulationMonitor,
        state: &aos_sandbox::Journal,
        output: &aos_sandbox::Journal,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), ZfsWorkerError> {
        self.result = Some((|| {
            self.first = Some(First::Peer);
            self.peer_result =
                Some(verifier.verify_connection_retaining_v2(socket.peer(), &mut self.peer));
            let Some(peer) = self
                .peer_result
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied()
            else {
                return Err(worker_entry::retained());
            };
            self.first = Some(First::Clock(0));
            self.clocks[0].observe(None)?;
            let sample = self.clocks[0].sample().ok_or(ZfsWorkerError::Authority)?;
            // This bound limits unauthenticated ingress only. It is not a Stop
            // grant and can never extend the later independently signed cut.
            let ingress = sample
                .boottime_nanoseconds()
                .checked_add(
                    u64::try_from(CONNECTION_TIMEOUT.as_nanos())
                        .map_err(|_| ZfsWorkerError::Authority)?,
                )
                .ok_or(ZfsWorkerError::Authority)?;
            self.first = Some(First::Wait);
            self.wait = Some(wait_storage_root_export_request_v2(socket, ingress));
            let waited = matches!(self.wait, Some(Ok(())));
            if waited {
                self.first = Some(First::Receive);
                self.record = Some(socket.receive_storage_held_output_reply_retaining_v2(
                    MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4,
                ));
            }
            // This actual after-ingress pair is owed after either native wait
            // or receive refusal, without replacing that earlier native cause.
            let clock = self.clocks[1].observe(None);
            if !waited {
                return Err(worker_entry::retained());
            }
            let Some(Ok(record)) = self.record.as_ref() else {
                return Err(worker_entry::retained());
            };
            if clock.is_err() {
                self.first = Some(First::Clock(1));
                return Err(worker_entry::retained());
            }
            self.first = Some(First::Binding);
            self.binding = Some(socket.validate_received_origin_retaining(record));
            if !matches!(self.binding, Some(Ok(()))) {
                return Err(worker_entry::retained());
            }
            self.first = Some(First::Subject);
            self.subject_result = Some(verifier.verify_record_retaining_v2(
                peer,
                socket.peer(),
                record.subject(),
                &mut self.subject,
            ));
            if !matches!(self.subject_result, Some(Ok(()))) {
                return Err(worker_entry::retained());
            }
            self.first = Some(First::Wire);
            let wire = match CaptureStopCleanupRequestDataV4::decode_v4(record.payload()) {
                Ok(wire) => {
                    self.wire = Some(Ok(()));
                    wire
                }
                Err(cause) => {
                    self.wire = Some(Err(cause));
                    return Err(worker_entry::retained());
                }
            };
            self.first = Some(First::Begin);
            self.begin_digest = Some(begin.digest());
            let Some(Ok(begin_digest)) = self.begin_digest.as_ref() else {
                return Err(worker_entry::retained());
            };
            self.first = Some(First::Selector);
            self.selector = Some(
                if begin.source == *native.admission_v3().source_v3()
                    && begin.attempt == native.worker_result_identity_v3().attempt
                    && begin.durable_attempt_digest == native.durable_attempt_digest_v3()
                    && wire.nonce_v4() == &begin.nonce
                    && wire.begin_digest_v4() == begin_digest
                    && wire.source_digest_v4() == begin.source.source_digest_v2().as_bytes()
                    && wire.attempt_v4() == &begin.attempt
                    && physical.row_digest_for_native_v3(native).is_some()
                {
                    Ok(())
                } else {
                    Err(ZfsWorkerError::Authority)
                },
            );
            if !matches!(self.selector, Some(Ok(()))) {
                return Err(worker_entry::retained());
            }
            self.first = Some(First::Verify);
            let sample = self.clocks[1].sample().ok_or(ZfsWorkerError::Authority)?;
            self.inspection = Some(self.inspector.observe_once_v4(
                authority,
                &wire,
                native.admission_v3().source_v3(),
                &sample,
            ));
            let permission = self
                .inspector
                .verified_v4()
                .ok_or_else(worker_entry::retained)?;
            self.first = Some(First::Aliases);
            let mut close_index = 2;
            let clocks = &mut self.clocks;
            let mut current = || {
                let index = close_index;
                close_index += 1;
                clocks
                    .get_mut(index)
                    .ok_or(ZfsWorkerError::Authority)?
                    .observe(Some(permission))
            };
            let (aliases, gate) =
                mounted.retire_stop_pipe_aliases_v4(permission, native, &mut current);
            self.aliases = Some(aliases);
            self.alias_gate = gate;
            let aliases_positive = matches!(self.aliases, Some(Ok(())));
            // The after and native containment remain owed independently of
            // the close failure; no remaining alias is silently discarded.
            let after_alias = self.clocks[AFTER_ALIAS].observe(Some(permission));
            let before_native = self.clocks[BEFORE_NATIVE].observe(Some(permission));
            if before_native.is_ok() {
                self.native = Some(receiving.observe_capture_stop_quiescence_v4(
                    resident, state, output, anchor, population, permission,
                ));
            }
            let after_native = self.clocks[AFTER_NATIVE].observe(Some(permission));
            if !aliases_positive {
                return Err(worker_entry::retained());
            }
            if after_alias.is_err() {
                self.first = Some(First::Clock(AFTER_ALIAS));
                return Err(worker_entry::retained());
            }
            if before_native.is_err() {
                self.first = Some(First::Clock(BEFORE_NATIVE));
                return Err(worker_entry::retained());
            }
            self.first = Some(First::Native);
            if !matches!(self.native, Some(Ok(()))) {
                return Err(worker_entry::retained());
            }
            if after_native.is_err() {
                self.first = Some(First::Clock(AFTER_NATIVE));
                return Err(worker_entry::retained());
            }
            let proof = receiving
                .capture_stop_quiescence_v4()
                .ok_or_else(worker_entry::retained)?;
            if proof.source_digest_v4() != begin.source.source_digest_v2()
                || proof.stop_request_id_v4() != permission.request_id_v4()
                || proof.frame_digest_v4() != permission.frame_digest_v4()
            {
                return Err(ZfsWorkerError::Authority);
            }
            self.fields = Some(CaptureQuiescentIncompleteFieldsDataV4 {
                nonce: begin.nonce,
                begin: *begin_digest,
                source: begin.source.source_digest_v2(),
                attempt: begin.attempt,
                durable_attempt: begin.durable_attempt_digest,
                stop_request: *permission.request_id_v4(),
                runtime: ObjectDigest::from_bytes(*permission.runtime_handle_v4()),
                stop_frame: ObjectDigest::from_bytes(wire.digest_v4()),
                stop_plan: permission.plan_digest_v4(),
                stop_lease: permission.lease_digest_v4(),
                physical_binding: physical
                    .row_digest_for_native_v3(native)
                    .ok_or(ZfsWorkerError::Authority)?,
                native_cleanup: proof.native_cleanup_digest_v4(),
                observed_wall_seconds: proof.final_sample_v4().wall_seconds(),
                observed_boottime_nanoseconds: proof.final_sample_v4().boottime_nanoseconds(),
                stop_cutoff_boottime_nanoseconds: permission.cutoff_v4(),
            });
            self.first = None;
            Ok(())
        })());
        let posts = self.posts(0, socket, verifier);
        if !matches!(self.result, Some(Ok(()))) || !posts {
            return Err(worker_entry::retained());
        }
        let permission = self
            .inspector
            .verified_v4()
            .ok_or_else(worker_entry::retained)?;
        self.final_result = Some((|| {
            self.first = Some(First::Clock(BEFORE_SEND));
            self.clocks[BEFORE_SEND].observe(Some(permission))?;
            let pair = self.clocks[BEFORE_SEND]
                .sample()
                .ok_or(ZfsWorkerError::Authority)?;
            let mut fields = self.fields.take().ok_or(ZfsWorkerError::Authority)?;
            fields.observed_wall_seconds = pair.wall_seconds();
            fields.observed_boottime_nanoseconds = pair.boottime_nanoseconds();
            self.first = Some(First::Receipt);
            self.receipt = Some(CaptureQuiescentIncompleteReceiptDataV4::from_fields_v4(
                fields,
            ));
            let Some(Ok(receipt)) = self.receipt.as_ref() else {
                return Err(worker_entry::retained());
            };
            self.first = Some(First::Send);
            self.sent = Some(send_descriptor_worker_record_v1(
                socket,
                receipt.canonical_bytes_v4(),
                &[],
                DescriptorWorkerSendKindV1::StorageCaptureAck,
                permission.cutoff_v4(),
            ));
            let sent = self.sent.as_ref().is_some_and(|sent| sent.is_sent());
            // Entered send always owes its own after, even on native refusal.
            let after = self.clocks[AFTER_SEND].observe(Some(permission));
            if !sent {
                return Err(worker_entry::retained());
            }
            if after.is_err() {
                self.first = Some(First::Clock(AFTER_SEND));
                return Err(worker_entry::retained());
            }
            self.first = None;
            Ok(())
        })());
        // Once final preparation enters, neither Clock7 nor receipt/native
        // refusal can skip these prepaid independent posts and final sample.
        // Their later errors cannot replace that phase's earlier selected cause.
        let posts = self.posts(1, socket, verifier);
        let permission = self.inspector.verified_v4();
        let final_clock = self.clocks[AFTER_POST].observe(permission);
        let final_positive = matches!(self.final_result, Some(Ok(())));
        if final_positive && posts && (permission.is_none() || final_clock.is_err()) {
            self.first = Some(First::Clock(AFTER_POST));
        }
        self.completed = final_positive && posts && permission.is_some() && final_clock.is_ok();
        if self.completed {
            self.first = None;
            Ok(())
        } else {
            Err(worker_entry::retained())
        }
    }
}

fn error<T, E: std::error::Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl CaptureStopCleanupOriginalV4 {
    pub(super) fn completed_v4(&self) -> bool {
        self.entered
            && !matches!(self.waiting, Some(Err(_)))
            && self.action.completed
            && matches!(self.listener_after, Some(Ok(())))
    }

    pub(super) fn failure_v4<'cause>(
        &'cause self,
        receiving: &'cause aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        mounted: &'cause CaptureMountedParentOriginalV3,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        error(&self.waiting)
            .or_else(|| error(&self.listener))
            .or_else(|| error(&self.accepted))
            .or_else(|| self.action.failure_v4(Some(receiving), mounted))
            .or_else(|| error(&self.returned))
            .or_else(|| error(&self.listener_after))
    }
}

impl Action {
    fn failure_v4<'cause>(
        &'cause self,
        receiving: Option<&'cause aos_sandbox::StoragePrepareReceivingLoanV1<'_>>,
        mounted: &'cause CaptureMountedParentOriginalV3,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        let selected = match self.first? {
            First::Peer => self.peer.failure().or_else(|| error(&self.peer_result)),
            First::Clock(index) => self.clocks[index].failure(),
            First::Wait => error(&self.wait),
            First::Receive => error(&self.record),
            First::Binding => error(&self.binding),
            First::Subject => self
                .subject
                .failure()
                .or_else(|| error(&self.subject_result)),
            First::Wire => error(&self.wire),
            First::Begin => error(&self.begin_digest),
            First::Selector => error(&self.selector),
            First::Verify => self.inspector.failure().or_else(|| error(&self.inspection)),
            First::Aliases => mounted
                .stop_pipe_alias_failure_v4()
                .or_else(|| {
                    if self.alias_gate.is_some() {
                        self.clocks[2..AFTER_ALIAS]
                            .iter()
                            .find_map(ClockSlot::failure)
                    } else {
                        None
                    }
                })
                .or_else(|| self.alias_gate.as_ref().map(|cause| cause as _))
                .or_else(|| error(&self.aliases)),
            First::Native => receiving
                .and_then(|loan| loan.capture_stop_failure_v4())
                .or_else(|| error(&self.native)),
            First::Receipt => error(&self.receipt),
            First::Post(index) => error(&self.socket_after[index])
                .or_else(|| self.peer_after[index].failure())
                .or_else(|| error(&self.peer_after_result[index]))
                .or_else(|| self.subject_after[index].failure())
                .or_else(|| error(&self.subject_after_result[index])),
            First::Send => self.sent.as_ref()?.failure(),
        };
        selected
            .or_else(|| error(&self.result))
            .or_else(|| error(&self.final_result))
    }
}

impl CaptureStopCleanupOriginalV4 {
    pub(super) fn entered_v4(&self) -> bool {
        self.entered
    }

    pub(super) fn failure_without_native_v4<'cause>(
        &'cause self,
        mounted: &'cause CaptureMountedParentOriginalV3,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        // The live F borrower lends its selected native cause separately.
        // Historical access follows the identical first-cause selector and
        // must never scan later clock or observer failures ahead of it.
        error(&self.waiting)
            .or_else(|| error(&self.listener))
            .or_else(|| error(&self.accepted))
            .or_else(|| self.action.failure_v4(None, mounted))
            .or_else(|| error(&self.returned))
            .or_else(|| error(&self.listener_after))
    }
}

impl CapturePhysicalPreparationOriginalV3 {
    pub(crate) fn stop_receiving_demand_v4(inspection_bytes: usize) -> Option<ResourceVector> {
        CaptureStopCleanupOriginalV4::receiving_demand_v4(inspection_bytes)
    }

    pub(crate) fn can_receive_stop_cleanup_v4(&self) -> bool {
        !self.stop.entered_v4()
            && self.held.stop_selector_v4().is_some()
            && matches!(self.resident, Some(Ok(_)))
            && !self.terminal.complete_publication_entered_v4()
    }

    pub(crate) fn wait_stop_cleanup_once_v4(
        &mut self,
        listener: &RecordSubjectListener,
    ) -> Result<(), ZfsWorkerError> {
        if !self.can_receive_stop_cleanup_v4() || self.stop.waiting.is_some() {
            return Err(ZfsWorkerError::Authority);
        }
        self.stop.waiting =
            Some(aos_sandbox_linux::seqpacket::bounded::wait_capture_stop_listener_v4(listener));
        if matches!(self.stop.waiting, Some(Ok(()))) {
            Ok(())
        } else {
            Err(worker_entry::retained())
        }
    }

    pub(crate) fn serve_stop_cleanup_once_v4(
        &mut self,
        listener: &mut RecordSubjectListener,
        authority: &BrokerAuthority,
        state: &aos_sandbox::Journal,
        output: &aos_sandbox::Journal,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), ZfsWorkerError> {
        if !self.can_receive_stop_cleanup_v4() || matches!(self.stop.waiting, Some(Err(_))) {
            return Err(ZfsWorkerError::Authority);
        }
        let begin = self
            .held
            .stop_selector_v4()
            .ok_or(ZfsWorkerError::Authority)?;
        let verifier = self
            .held
            .stop_peer_verifier_v4()
            .ok_or(ZfsWorkerError::Authority)?;
        let Some(Ok(resident)) = self.resident.as_ref() else {
            return Err(ZfsWorkerError::Authority);
        };
        let anchor = self
            .exchange
            .cgroup
            .anchor()
            .ok_or(ZfsWorkerError::Authority)?;
        let population = self
            .exchange
            .cgroup
            .population()
            .ok_or(ZfsWorkerError::Authority)?;
        // A private once-slot fences every positive handler while this owner
        // remains exclusively borrowed. It never clears any earlier failure.
        self.first.get_or_insert(CaptureFailureV3::Stop);
        self.stop.observe_once_v4(
            listener,
            verifier,
            &begin,
            authority,
            &self.native,
            &mut self.mounted,
            &self.physical,
            resident,
            anchor,
            population,
            state,
            output,
            receiving,
        )
    }

    pub(crate) fn stop_cleanup_failure_v4<'cause>(
        &'cause self,
        receiving: &'cause aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.stop.failure_v4(receiving, &self.mounted)
    }

    pub(crate) fn stopped_with_residual_v4(&self) -> bool {
        self.stop.completed_v4()
    }
}
