//! Retains the actual issued P/O parent's native transport programme.
//!
//! The private service caller supplies its genuine reservation after paying
//! this exact transport quote. Every operation delegates to the existing
//! retained socket, framed-send or strict record engine; no Source, admission,
//! positive result or replacement deadline is constructed here.

use super::super::*;
use crate::worker_process::NetworkWorkerSubjectOriginalV4;
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, NetworkWorkerBirthPurposeV2,
    NetworkWorkerBirthReservationV2,
};
use aos_sandbox_broker::{
    BrokerAuthorityConfigError, ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    ProtectedBrokerPublicCredentialRole, ProtectedBrokerPublicCredentials,
};
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::bounded::{
    NetworkWorkerSendAttemptV4, NetworkWorkerSendKindV4, WorkerRecordError,
    send_network_worker_record_v4, wait_network_worker_record_ready_data_v2,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorWorkerNativeSendAttemptV1, NetworkWorkerConnectionKindV4,
};
use aos_sandbox_linux::seqpacket::{
    NetworkWorkerNativeCutoffV4, NetworkWorkerRecordKindV4, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1,
};

#[derive(Clone, Copy)]
enum First {
    Order,
    Connect,
    Manager,
    Cutoff,
    ReadyGate,
    ReadyWait,
    Ready,
    ReadyPost,
    Frame,
    TerminalGate,
    TerminalWait,
    Terminal,
    TerminalPost,
    Ack,
    Public,
    HandoffHeader,
    Handoff,
    Observation,
}

struct FrameOriginalV2 {
    bytes: Vec<u8>,
    send: NetworkWorkerSendAttemptV4<Closed>,
}

pub(crate) struct NetworkParentTransportOriginalV2 {
    purpose: NetworkWorkerBirthPurposeV2,
    connect: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    connect_gate: Option<Closed>,
    manager: NetworkWorkerSubjectOriginalV4,
    manager_result: Option<Result<(), NetworkWorkerProcessError>>,
    ready_gate: Option<Result<RawPairedClockSample, Closed>>,
    ready_wait: Option<Result<(), WorkerRecordError>>,
    ready: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    ready_post: Option<Result<(), aos_linux_descriptors::Error>>,
    frames_entered: bool,
    frames: Vec<FrameOriginalV2>,
    terminal_gate: Option<Result<RawPairedClockSample, Closed>>,
    terminal_wait: Option<Result<(), WorkerRecordError>>,
    terminal: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    terminal_post: Option<Result<(), aos_linux_descriptors::Error>>,
    ack: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    public: ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    public_result: Option<Result<(), BrokerAuthorityConfigError>>,
    handoff: Option<Vec<u8>>,
    handoff_header_gate: Option<Result<RawPairedClockSample, Closed>>,
    handoff_header_send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    handoff_header_cutoff_error: Option<aos_linux_descriptors::Error>,
    handoff_gate: Option<Result<RawPairedClockSample, Closed>>,
    handoff_send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    handoff_cutoff_error: Option<aos_linux_descriptors::Error>,
    observation: Option<NetworkWorkerSendAttemptV4<Closed>>,
    cutoff: Option<NetworkWorkerNativeCutoffV4>,
    first: Option<First>,
}

impl NetworkParentTransportOriginalV2 {
    pub(super) const fn marker_text_v2() -> &'static str {
        "issued parent transport original retained"
    }

    pub(crate) fn new(purpose: NetworkWorkerBirthPurposeV2) -> Self {
        Self {
            purpose,
            connect: None,
            connect_gate: None,
            manager: NetworkWorkerSubjectOriginalV4::new(),
            manager_result: None,
            ready_gate: None,
            ready_wait: None,
            ready: None,
            ready_post: None,
            frames_entered: false,
            frames: Vec::new(),
            terminal_gate: None,
            terminal_wait: None,
            terminal: None,
            terminal_post: None,
            ack: None,
            public: ProtectedBrokerPublicCredentialRevalidationOriginalV1::new(),
            public_result: None,
            handoff: None,
            handoff_header_gate: None,
            handoff_header_send: None,
            handoff_header_cutoff_error: None,
            handoff_gate: None,
            handoff_send: None,
            handoff_cutoff_error: None,
            observation: None,
            cutoff: None,
            first: None,
        }
    }

    /// Quotes the exact retained native programme before its private caller grows it.
    pub(crate) fn receiving_demand_v2(
        purpose: NetworkWorkerBirthPurposeV2,
        request_bytes: usize,
        handoff_bytes: Option<usize>,
    ) -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let (connect_bytes, connect_files) =
            DescriptorSubjectSocket::network_worker_admission_obligations_v4::<Closed>()
                .ok_or(overflow)?;
        let (manager_bytes, manager_files, manager_names) =
            NetworkWorkerSubjectOriginalV4::receiving_obligations_v4().ok_or(overflow)?;
        let (ready_kind, terminal_kind) = match purpose {
            NetworkWorkerBirthPurposeV2::Preparation => (
                NetworkWorkerRecordKindV4::PreparationReadyOrNegativeV2,
                NetworkWorkerRecordKindV4::PreparationTerminalV2,
            ),
            NetworkWorkerBirthPurposeV2::Observation => (
                NetworkWorkerRecordKindV4::ObservationReadyOrNegativeV2,
                NetworkWorkerRecordKindV4::ObservationTerminalV2,
            ),
        };
        let ready = DescriptorSubjectSocket::network_worker_receive_obligations_v4(ready_kind)
            .ok_or(overflow)?;
        let terminal =
            DescriptorSubjectSocket::network_worker_receive_obligations_v4(terminal_kind)
                .ok_or(overflow)?;
        let mut bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|value| value.checked_add(connect_bytes))
            .and_then(|value| value.checked_add(manager_bytes))
            .and_then(|value| value.checked_add(ready.0))
            .and_then(|value| value.checked_add(terminal.0))
            .and_then(|value| {
                value.checked_add(DescriptorWorkerNativeSendAttemptV1::requested_bytes_v1()?)
            })
            .and_then(|value| {
                value.checked_add(4 * std::mem::size_of::<rustix::event::PollFd<'_>>())
            })
            .and_then(|value| value.checked_add(8 * std::mem::size_of::<rustix::event::Timespec>()))
            .and_then(|value| {
                value
                    .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?.checked_mul(4)?)
            })
            .ok_or(overflow)?;
        let mut files = connect_files
            .checked_add(manager_files)
            .and_then(|value| value.checked_add(ready.1))
            .and_then(|value| value.checked_add(terminal.1))
            .ok_or(overflow)?;
        let mut names = manager_names;
        match purpose {
            NetworkWorkerBirthPurposeV2::Preparation => {
                if request_bytes == 0
                    || request_bytes > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES
                    || handoff_bytes.is_some()
                {
                    return Err(overflow);
                }
                let count = request_bytes.div_ceil(MAXIMUM_FRAME_PAYLOAD_BYTES);
                let send =
                    NetworkWorkerSendAttemptV4::<Closed>::receiving_bytes_v4().ok_or(overflow)?;
                let frames = request_bytes
                    .checked_add(count.checked_mul(FRAME_HEADER_BYTES).ok_or(overflow)?)
                    .and_then(|value| value.checked_mul(2))
                    .and_then(|value| {
                        value
                            .checked_add(count.checked_mul(std::mem::size_of::<FrameOriginalV2>())?)
                    })
                    .and_then(|value| value.checked_add(count.checked_mul(send)?))
                    .ok_or(overflow)?;
                bytes = bytes.checked_add(frames).ok_or(overflow)?;
            }
            NetworkWorkerBirthPurposeV2::Observation => {
                let length = handoff_bytes
                    .filter(|length| {
                        (crate::observer_handoff_v2::HEADER_BYTES
                            ..=crate::observer_handoff_v2::MAXIMUM_HANDOFF_BYTES)
                            .contains(length)
                    })
                    .ok_or(overflow)?;
                if !(184..=184 + 512 * 1024).contains(&request_bytes) {
                    return Err(overflow);
                }
                let public = ProtectedBrokerPublicCredentialRevalidationOriginalV1::receiving_obligations_v1().ok_or(overflow)?;
                bytes = bytes.checked_add(public.0)
                    .and_then(|value| value.checked_add(length.checked_mul(2)?))
                    .and_then(|value| value.checked_add(DescriptorSubjectSocket::network_observer_handoff_header_send_obligations_v3()?))
                    .and_then(|value| value.checked_add(DescriptorSubjectSocket::network_observer_handoff_send_obligations_v2()?))
                    .and_then(|value| value.checked_add(NetworkWorkerSendAttemptV4::<Closed>::receiving_bytes_v4()?))
                    .ok_or(overflow)?;
                files = files.checked_add(public.1).ok_or(overflow)?;
                names = names.checked_add(public.2).ok_or(overflow)?;
            }
        }
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow)?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow)?)
            .with(
                D::MetadataEntries,
                u64::try_from(names).map_err(|_| overflow)?,
            ))
    }

    pub(crate) fn connect_once_v2(
        &mut self,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, '_>,
        manager: &RetainedCgroupAnchor,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.connect.is_some() || reservation.purpose_data_v2() != Some(self.purpose) {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        let kind = match self.purpose {
            NetworkWorkerBirthPurposeV2::Preparation => NetworkWorkerConnectionKindV4::Preparation,
            NetworkWorkerBirthPurposeV2::Observation => NetworkWorkerConnectionKindV4::Observation,
        };
        self.first.get_or_insert(First::Connect);
        let (result, gate) =
            DescriptorSubjectSocket::connect_network_worker_retaining_v4(kind, &mut || {
                reservation.observe_parent_worker_clock_v2().map(|_| ())
            });
        self.connect = Some(result);
        self.connect_gate = gate;
        let Some(Ok(socket)) = self.connect.as_ref() else {
            return Err(marker());
        };
        if self.connect_gate.is_some() {
            return Err(marker());
        }
        self.first = Some(First::Manager);
        self.manager_result = Some(self.manager.capture_manager_once(socket.peer(), manager));
        if !matches!(self.manager_result, Some(Ok(()))) {
            return Err(marker());
        }
        self.cutoff = reservation.parent_worker_cutoff_data_v2().ok();
        if self.cutoff.is_none() {
            self.first = Some(First::Cutoff);
            return Err(marker());
        }
        self.first = None;
        Ok(())
    }

    pub(crate) fn receive_ready_once_v2(
        &mut self,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, '_>,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.ready.is_some() || self.ready_gate.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.ready_gate = Some(reservation.observe_parent_worker_clock_v2());
        if matches!(self.ready_gate, Some(Ok(_))) {
            self.cutoff = reservation.parent_worker_cutoff_data_v2().ok();
        }
        let Some(Ok(socket)) = self.connect.as_mut() else {
            return Err(marker());
        };
        if matches!(self.ready_gate, Some(Ok(_))) {
            if let Some(cutoff) = self.cutoff {
                self.ready_wait = Some(wait_network_worker_record_ready_data_v2(socket, cutoff));
            }
        }
        // One already-prepaid native receive still retains a genuine negative
        // when the old positive Source/D wait has refused. No late READY is
        // thereby adopted: the enclosing recipe checks the retained gate.
        let kind = match self.purpose {
            NetworkWorkerBirthPurposeV2::Preparation => {
                NetworkWorkerRecordKindV4::PreparationReadyOrNegativeV2
            }
            NetworkWorkerBirthPurposeV2::Observation => {
                NetworkWorkerRecordKindV4::ObservationReadyOrNegativeV2
            }
        };
        self.ready = Some(socket.receive_owed_network_worker_ready_or_negative_retaining_v2(kind));
        if let Some(cutoff) = self.cutoff {
            self.ready_post = Some(cutoff.observe_native_v4().map(|_| ()));
        }
        if !matches!(self.ready_gate, Some(Ok(_))) {
            self.first.get_or_insert(First::ReadyGate);
        }
        if !matches!(self.ready_wait, Some(Ok(()))) {
            self.first.get_or_insert(First::ReadyWait);
        }
        if !matches!(self.ready, Some(Ok(_))) {
            self.first.get_or_insert(First::Ready);
        }
        if !matches!(self.ready_post, Some(Ok(()))) {
            self.first.get_or_insert(First::ReadyPost);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(marker())
        }
    }

    pub(crate) fn send_preparation_frames_once_v2(
        &mut self,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, '_>,
        request: &[u8],
        host: &NamespaceFd,
        target: Option<&NamespaceFd>,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.frames_entered
            || !matches!(self.purpose, NetworkWorkerBirthPurposeV2::Preparation)
            || request.is_empty()
            || request.len() > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES
        {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.frames_entered = true;
        let cutoff = self.cutoff.ok_or_else(marker)?;
        let count = request.len().div_ceil(MAXIMUM_FRAME_PAYLOAD_BYTES);
        self.frames.reserve_exact(count);
        let digest: [u8; 32] = Sha256::digest(request).into();
        let Some(Ok(socket)) = self.connect.as_mut() else {
            return Err(marker());
        };
        for index in 0..count {
            let offset = index
                .checked_mul(MAXIMUM_FRAME_PAYLOAD_BYTES)
                .ok_or_else(marker)?;
            let end = offset
                .checked_add(MAXIMUM_FRAME_PAYLOAD_BYTES)
                .ok_or_else(marker)?
                .min(request.len());
            let bytes = encode_frame(request, digest, offset, end)?;
            let mut rights = [host.as_fd(), host.as_fd()];
            let table: &[BorrowedFd<'_>] = if index != 0 {
                &[]
            } else if let Some(target) = target {
                rights[0] = target.as_fd();
                &rights
            } else {
                &rights[..1]
            };
            let kind = if index == 0 {
                NetworkWorkerSendKindV4::PreparationFirstV2
            } else {
                NetworkWorkerSendKindV4::PreparationContinuation
            };
            let send =
                send_network_worker_record_v4(socket, &bytes, table, kind, cutoff, &mut || {
                    reservation.observe_parent_worker_clock_v2().map(|_| ())
                });
            let sent = send.is_sent();
            self.frames.push(FrameOriginalV2 { bytes, send });
            if !sent {
                self.first.get_or_insert(First::Frame);
                return Err(marker());
            }
        }
        Ok(())
    }

    // Only the private service-original caller supplies these exact borrowed
    // originals from its completed admission and actual six credential owner.
    // The canonical encoder emits DATA; the child still owes its independent
    // same-Source, signed9/63 and original lease/fence read admission.
    pub(crate) fn send_observer_handoff_once_v2(
        &mut self,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, '_>,
        credentials: &ProtectedBrokerPublicCredentials,
        sections: [&[u8]; 9],
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if !matches!(self.purpose, NetworkWorkerBirthPurposeV2::Observation)
            || self.public_result.is_some()
            || self.handoff.is_some()
        {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        let binding = reservation
            .child_operation_binding_data_v2()
            .ok_or_else(marker)?;
        let evidence =
            match credentials.revalidated_descriptor_evidence_retaining_v1(&mut self.public) {
                Ok(evidence) => {
                    self.public_result = Some(Ok(()));
                    evidence
                }
                Err(error) => {
                    self.public_result = Some(Err(error));
                    self.first.get_or_insert(First::Public);
                    return Err(marker());
                }
            };
        if evidence
            .iter()
            .zip(ProtectedBrokerPublicCredentialRole::ALL)
            .any(|(entry, expected)| entry.0 != expected)
        {
            self.first.get_or_insert(First::Public);
            return Err(marker());
        }
        let snapshots = std::array::from_fn(|index| evidence[index].2);
        self.handoff = crate::observer_handoff_v2::encode_observer_handoff_data_v2(
            binding, snapshots, sections,
        );
        let Some(packet) = self.handoff.as_ref() else {
            self.first.get_or_insert(First::Handoff);
            return Err(marker());
        };
        self.handoff_header_gate = Some(reservation.observe_parent_worker_clock_v2());
        if !matches!(self.handoff_header_gate, Some(Ok(_))) {
            self.first.get_or_insert(First::HandoffHeader);
            return Err(marker());
        }
        let cutoff = self.cutoff.ok_or_else(marker)?;
        let Some(Ok(socket)) = self.connect.as_mut() else {
            return Err(marker());
        };
        let (header_send, header_cutoff_error) = socket
            .send_network_observer_handoff_header_retaining_v3(
                &packet[..crate::observer_handoff_v2::HEADER_BYTES],
                cutoff,
            );
        self.handoff_header_send = Some(header_send);
        self.handoff_header_cutoff_error = header_cutoff_error;
        if self.handoff_header_cutoff_error.is_some()
            || !self
                .handoff_header_send
                .as_ref()
                .is_some_and(|result| result.as_ref().is_ok_and(|receipt| receipt.is_sent()))
        {
            self.first.get_or_insert(First::HandoffHeader);
            return Err(marker());
        }
        self.handoff_gate = Some(reservation.observe_parent_worker_clock_v2());
        if !matches!(self.handoff_gate, Some(Ok(_))) {
            self.first.get_or_insert(First::Handoff);
            return Err(marker());
        }
        let rights = std::array::from_fn(|index| evidence[index].1);
        let (sent, cutoff_error) =
            socket.send_network_observer_handoff_retaining_v2(packet, rights, cutoff);
        self.handoff_send = Some(sent);
        self.handoff_cutoff_error = cutoff_error;
        if self.handoff_cutoff_error.is_some()
            || !self
                .handoff_send
                .as_ref()
                .is_some_and(|result| result.as_ref().is_ok_and(|receipt| receipt.is_sent()))
        {
            self.first.get_or_insert(First::Handoff);
            return Err(marker());
        }
        Ok(())
    }

    pub(crate) fn send_observation_request_once_v2(
        &mut self,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, '_>,
        packet: &[u8],
        target: &NamespaceFd,
        host: &NamespaceFd,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.observation.is_some()
            || !matches!(self.purpose, NetworkWorkerBirthPurposeV2::Observation)
            || !self
                .handoff_send
                .as_ref()
                .is_some_and(|result| result.as_ref().is_ok_and(|receipt| receipt.is_sent()))
        {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        let cutoff = self.cutoff.ok_or_else(marker)?;
        let Some(Ok(socket)) = self.connect.as_mut() else {
            return Err(marker());
        };
        self.observation = Some(send_network_worker_record_v4(
            socket,
            packet,
            &[host.as_fd(), target.as_fd()],
            NetworkWorkerSendKindV4::ObservationRequest,
            cutoff,
            &mut || reservation.observe_parent_worker_clock_v2().map(|_| ()),
        ));
        if self.observation.as_ref().is_some_and(|send| send.is_sent()) {
            Ok(())
        } else {
            self.first.get_or_insert(First::Observation);
            Err(marker())
        }
    }

    pub(crate) fn receive_terminal_once_v2(
        &mut self,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, '_>,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.terminal.is_some() || self.terminal_gate.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.terminal_gate = Some(reservation.observe_parent_worker_clock_v2());
        let Some(Ok(socket)) = self.connect.as_mut() else {
            return Err(marker());
        };
        if matches!(self.terminal_gate, Some(Ok(_))) {
            if let Some(cutoff) = self.cutoff {
                self.terminal_wait = Some(wait_network_worker_record_ready_data_v2(socket, cutoff));
            }
        }
        let kind = match self.purpose {
            NetworkWorkerBirthPurposeV2::Preparation => {
                NetworkWorkerRecordKindV4::PreparationTerminalV2
            }
            NetworkWorkerBirthPurposeV2::Observation => {
                NetworkWorkerRecordKindV4::ObservationTerminalV2
            }
        };
        self.terminal = Some(socket.receive_owed_network_worker_terminal_retaining_v2(kind));
        if let Some(cutoff) = self.cutoff {
            self.terminal_post = Some(cutoff.observe_native_v4().map(|_| ()));
        }
        if !matches!(self.terminal_gate, Some(Ok(_))) {
            self.first.get_or_insert(First::TerminalGate);
        }
        if !matches!(self.terminal_wait, Some(Ok(()))) {
            self.first.get_or_insert(First::TerminalWait);
        }
        if !matches!(self.terminal, Some(Ok(_))) {
            self.first.get_or_insert(First::Terminal);
        }
        if !matches!(self.terminal_post, Some(Ok(()))) {
            self.first.get_or_insert(First::TerminalPost);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(marker())
        }
    }

    // The caller first authenticates the actual terminal/negative record to
    // the continuously held issued child. This receipt grants no effect and
    // intentionally uses no fresh Source or deadline gate after old D.
    pub(crate) fn acknowledge_once_v2(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        if self.ack.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        let Some(Ok(socket)) = self.connect.as_mut() else {
            return Err(marker());
        };
        self.ack = Some(socket.send_worker_record_retaining_v1(&acknowledgement(), &[]));
        if self
            .ack
            .as_ref()
            .is_some_and(|result| result.as_ref().is_ok_and(|receipt| receipt.is_sent()))
        {
            Ok(())
        } else {
            self.first.get_or_insert(First::Ack);
            Err(marker())
        }
    }

    pub(crate) fn ready_record_v2(&self) -> Option<&ReceivedDescriptorRecord> {
        self.ready.as_ref()?.as_ref().ok()
    }

    pub(crate) fn cutoff_data_v2(&self) -> Option<NetworkWorkerNativeCutoffV4> {
        self.cutoff
    }

    pub(crate) fn terminal_entered_v2(&self) -> bool {
        self.terminal_gate.is_some()
    }

    pub(crate) fn ack_entered_v2(&self) -> bool {
        self.ack.is_some()
    }

    pub(crate) fn parent_failure_selected_v2(&self) -> bool {
        match self.first {
            Some(First::Connect) => self.connect_gate.is_some(),
            Some(First::Cutoff) => true,
            Some(First::ReadyGate | First::TerminalGate) => true,
            Some(First::HandoffHeader) => matches!(self.handoff_header_gate, Some(Err(_))),
            Some(First::Handoff) => matches!(self.handoff_gate, Some(Err(_))),
            Some(First::Frame) => self
                .frames
                .iter()
                .any(|frame| frame.send.original_gate_failure_v4().is_some()),
            Some(First::Observation) => self
                .observation
                .as_ref()
                .is_some_and(|send| send.original_gate_failure_v4().is_some()),
            _ => false,
        }
    }

    pub(crate) fn ready_record_mut_v2(&mut self) -> Option<&mut ReceivedDescriptorRecord> {
        self.ready.as_mut()?.as_mut().ok()
    }

    pub(crate) fn terminal_record_v2(&self) -> Option<&ReceivedDescriptorRecord> {
        self.terminal.as_ref()?.as_ref().ok()
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Connect => self
                .connect
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _)
                .or_else(|| self.connect_gate.as_ref().map(|cause| cause as _)),
            First::Manager => self.manager.failure(),
            First::ReadyWait => self
                .ready_wait
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Ready => self.ready.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ReadyPost => self
                .ready_post
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Frame => self.frames.iter().find_map(|frame| frame.send.failure()),
            First::TerminalWait => self
                .terminal_wait
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Terminal => self
                .terminal
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::TerminalPost => self
                .terminal_post
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Ack => self.ack.as_ref().and_then(|result| match result {
                Ok(receipt) => receipt.failure(),
                Err(cause) => Some(cause as _),
            }),
            First::Public => self.public.failure(),
            First::HandoffHeader => self
                .handoff_header_cutoff_error
                .as_ref()
                .map(|cause| cause as _)
                .or_else(|| {
                    self.handoff_header_send
                        .as_ref()
                        .and_then(|result| match result {
                            Ok(receipt) => receipt.failure(),
                            Err(cause) => Some(cause as _),
                        })
                }),
            First::Handoff => self
                .handoff_cutoff_error
                .as_ref()
                .map(|cause| cause as _)
                .or_else(|| {
                    self.handoff_send.as_ref().and_then(|result| match result {
                        Ok(receipt) => receipt.failure(),
                        Err(cause) => Some(cause as _),
                    })
                }),
            First::Observation => self.observation.as_ref()?.failure(),
            First::Order | First::Cutoff | First::ReadyGate | First::TerminalGate => None,
        }
        .or(Some(&Closed))
    }
}

fn marker() -> NetworkWorkerRuntimeError {
    NetworkWorkerRuntimeError::Protocol(NetworkParentTransportOriginalV2::marker_text_v2())
}
