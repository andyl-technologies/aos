//! Disposes only the finite unentered O input slots and an authentic owed ACK.
//!
//! This port permanently closes positive child Source permission. It grants no
//! read, D, admission, credit or disposal of ambiguous native custody. Every
//! native receive is once-only; an entered failed receive is never retried.

use super::execution::ObserverReadExecutionOriginalV2;
use super::handoff::ObserverHandoffOriginalV3;
use super::*;
use crate::observation_worker_runtime::read_admission_v2::NetworkObserverReadOriginalV2;
use crate::observer_handoff_v2::{
    HEADER_BYTES, ObserverHandoffDataV2, ObserverHandoffHeaderDataV3,
};
use aos_sandbox_broker::receiving::NetworkChildOperationBindingDataV2;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    NetworkWorkerBootstrapWaitOriginalV3, NetworkWorkerBootstrapWaitRefusalV3,
    NetworkWorkerRetiredRecordDataV2, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{
    NetworkWorkerRecordKindV4, RecordBindingError, RetainedSeqpacketReceiveErrorV1,
};

/// Borrows actual input custody; it cannot be inferred from a receive error.
pub(super) enum InputSlotOriginalV3<'held> {
    Unentered,
    Record(&'held ReceivedDescriptorRecord),
    RetiredHeader(&'held NetworkWorkerRetiredRecordDataV2),
    Uncertain,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the observer's owed input custody remains unresolved")]
pub(super) struct DispositionClosedV3;

#[derive(Clone, Copy)]
enum ExpectedInputV3<'held> {
    Header,
    Full(&'held [u8; HEADER_BYTES]),
    Namespace(&'held [u8]),
    Acknowledgment,
}

enum CapturedInputDataV3 {
    Header([u8; HEADER_BYTES], [usize; 9]),
    NamespaceRequest(Vec<u8>),
    Namespace,
    Acknowledgment,
}

#[derive(Clone, Copy)]
enum SlotFirst {
    Order,
    Uncertain,
    Wait,
    Receive,
    Origin,
    Source,
    OriginAfter,
    Shape,
}

struct InputDispositionSlotOriginalV3 {
    entered: bool,
    first: Option<SlotFirst>,
    wait: NetworkWorkerBootstrapWaitOriginalV3,
    wait_result: Option<Result<(), NetworkWorkerBootstrapWaitRefusalV3>>,
    record: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    origin: Option<Result<(), RecordBindingError>>,
    source: NetworkChildSourceRecordOriginalV2,
    source_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    origin_after: Option<Result<(), RecordBindingError>>,
    shape: Option<Result<CapturedInputDataV3, DispositionClosedV3>>,
}

impl InputDispositionSlotOriginalV3 {
    fn new() -> Self {
        Self {
            entered: false,
            first: None,
            wait: NetworkWorkerBootstrapWaitOriginalV3::new(),
            wait_result: None,
            record: None,
            origin: None,
            source: NetworkChildSourceRecordOriginalV2::new(),
            source_result: None,
            origin_after: None,
            shape: None,
        }
    }

    fn capture_once_v3(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
        original: InputSlotOriginalV3<'_>,
        expected: ExpectedInputV3<'_>,
        binding: NetworkChildOperationBindingDataV2,
    ) -> Result<(), DispositionClosedV3> {
        if self.entered {
            self.first.get_or_insert(SlotFirst::Order);
            return Err(DispositionClosedV3);
        }
        self.entered = true;
        let record = match original {
            InputSlotOriginalV3::Uncertain => {
                self.first = Some(SlotFirst::Uncertain);
                return Err(DispositionClosedV3);
            }
            InputSlotOriginalV3::RetiredHeader(data) => {
                // Only the header's actual successful native owner can yield
                // this variant. Its inert bytes do not supply a new Source.
                if !matches!(expected, ExpectedInputV3::Header) {
                    self.first = Some(SlotFirst::Uncertain);
                    return Err(DispositionClosedV3);
                }
                self.shape = Some(decode_header(data.payload(), binding));
                if !matches!(self.shape, Some(Ok(_))) {
                    self.first = Some(SlotFirst::Shape);
                    return Err(DispositionClosedV3);
                }
                return Ok(());
            }
            InputSlotOriginalV3::Record(record) => record,
            InputSlotOriginalV3::Unentered => {
                self.wait_result = Some(self.wait.observe_once_v3(socket, donor, None));
                if !matches!(self.wait_result, Some(Ok(()))) {
                    self.first = Some(SlotFirst::Wait);
                    return Err(DispositionClosedV3);
                }
                self.record = Some(match &expected {
                    ExpectedInputV3::Header => {
                        socket.receive_network_observer_handoff_header_retaining_v3()
                    }
                    ExpectedInputV3::Full(header) => {
                        let facts = ObserverHandoffHeaderDataV3::decode(*header)
                            .ok_or(DispositionClosedV3)?;
                        socket.receive_owed_network_observer_handoff_or_ack_retaining_v3(
                            facts.total_bytes,
                        )
                    }
                    ExpectedInputV3::Namespace(bytes) => socket
                        .receive_owed_network_observer_namespace_or_ack_retaining_v3(bytes.len()),
                    ExpectedInputV3::Acknowledgment => {
                        socket.receive_owed_network_worker_acknowledgment_retaining_v3()
                    }
                });
                match self.record.as_ref() {
                    Some(Ok(record)) => record,
                    _ => {
                        self.first = Some(SlotFirst::Receive);
                        return Err(DispositionClosedV3);
                    }
                }
            }
        };

        self.origin = Some(socket.validate_received_origin_retaining(record));
        if !matches!(self.origin, Some(Ok(()))) {
            self.first = Some(SlotFirst::Origin);
        }
        // These are native owed identity/controls posts, never a live grant.
        self.source_result =
            Some(source.require_owed_netd_record_once_v2(record, &mut self.source));
        if !matches!(self.source_result, Some(Ok(()))) {
            self.first.get_or_insert(SlotFirst::Source);
        }
        if self.first.is_none() {
            self.shape = Some(decode_input(
                record,
                expected,
                binding,
                self.record.is_some(),
            ));
            if !matches!(self.shape, Some(Ok(_))) {
                self.first = Some(SlotFirst::Shape);
            }
        }
        self.origin_after = Some(socket.validate_received_origin_retaining(record));
        if !matches!(self.origin_after, Some(Ok(()))) {
            self.first.get_or_insert(SlotFirst::OriginAfter);
        }
        if self.first.is_some() {
            Err(DispositionClosedV3)
        } else {
            Ok(())
        }
    }

    fn output(&self) -> Result<&CapturedInputDataV3, DispositionClosedV3> {
        if self.first.is_some() {
            return Err(DispositionClosedV3);
        }
        self.shape
            .as_ref()
            .and_then(|shape| shape.as_ref().ok())
            .ok_or(DispositionClosedV3)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            SlotFirst::Wait => self.wait.failure(),
            SlotFirst::Receive => error(&self.record),
            SlotFirst::Origin => error(&self.origin),
            SlotFirst::Source => self.source.failure(),
            SlotFirst::OriginAfter => error(&self.origin_after),
            SlotFirst::Shape => error(&self.shape),
            SlotFirst::Order | SlotFirst::Uncertain => None,
        };
        cause.or(Some(&DispositionClosedV3))
    }
}

#[derive(Clone, Copy)]
enum First {
    Order,
    PeerBefore,
    Header,
    Fee,
    Full,
    Namespace,
    Acknowledgment,
    PeerAfter,
    Panic,
}

#[derive(Clone, Copy)]
enum AcknowledgmentSlotV3 {
    Header,
    Full,
    Namespace,
    Terminal,
}

/// Holds all reached negative native prefixes until actual process handback.
pub(super) struct ObserverInputDispositionOriginalV3 {
    entered: bool,
    first: Option<First>,
    peer_before: NetworkChildSourceRecordOriginalV2,
    peer_before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    header: InputDispositionSlotOriginalV3,
    fee: Option<Result<ResourceVector, DispositionClosedV3>>,
    full: InputDispositionSlotOriginalV3,
    namespace: InputDispositionSlotOriginalV3,
    acknowledgment: InputDispositionSlotOriginalV3,
    completed: Option<AcknowledgmentSlotV3>,
    peer_after: NetworkChildSourceRecordOriginalV2,
    peer_after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
}

impl ObserverInputDispositionOriginalV3 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            first: None,
            peer_before: NetworkChildSourceRecordOriginalV2::new(),
            peer_before_result: None,
            header: InputDispositionSlotOriginalV3::new(),
            fee: None,
            full: InputDispositionSlotOriginalV3::new(),
            namespace: InputDispositionSlotOriginalV3::new(),
            acknowledgment: InputDispositionSlotOriginalV3::new(),
            completed: None,
            peer_after: NetworkChildSourceRecordOriginalV2::new(),
            peer_after_result: None,
        }
    }

    /// Uses only slots whose actual native owner proves they were unentered.
    /// Cached binding/fee are deny-only copies from this same inherited840;
    /// actual failed Source/native/channel identity remains independently owed.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture_once_v3(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
        binding: NetworkChildOperationBindingDataV2,
        originally_paid: ResourceVector,
        handoff: &ObserverHandoffOriginalV3,
        read: &NetworkObserverReadOriginalV2,
        execution: &ObserverReadExecutionOriginalV2,
    ) -> Result<(), DispositionClosedV3> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(DispositionClosedV3);
        }
        self.entered = true;
        self.peer_before_result =
            Some(source.require_owed_netd_peer_once_v2(socket, &mut self.peer_before));
        if !matches!(self.peer_before_result, Some(Ok(()))) {
            self.first = Some(First::PeerBefore);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.capture_inputs(
                    source,
                    socket,
                    donor,
                    binding,
                    originally_paid,
                    handoff,
                    read,
                    execution,
                )
            } else {
                Err(DispositionClosedV3)
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Panic);
        }
        self.peer_after_result =
            Some(source.require_owed_netd_peer_once_v2(socket, &mut self.peer_after));
        if !matches!(self.peer_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::PeerAfter);
        }
        match body {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => {
                result?;
                if self.first.is_some() || self.completed.is_none() {
                    Err(DispositionClosedV3)
                } else {
                    Ok(())
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn capture_inputs(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
        binding: NetworkChildOperationBindingDataV2,
        originally_paid: ResourceVector,
        handoff: &ObserverHandoffOriginalV3,
        read: &NetworkObserverReadOriginalV2,
        execution: &ObserverReadExecutionOriginalV2,
    ) -> Result<(), DispositionClosedV3> {
        self.header
            .capture_once_v3(
                source,
                socket,
                donor,
                handoff.header_slot_for_owed_custody_v3(),
                ExpectedInputV3::Header,
                binding,
            )
            .inspect_err(|_| {
                self.first = Some(First::Header);
            })?;
        let (header, lengths) = match self.header.output()? {
            CapturedInputDataV3::Acknowledgment => {
                self.completed = Some(AcknowledgmentSlotV3::Header);
                return Ok(());
            }
            CapturedInputDataV3::Header(header, lengths) => (*header, *lengths),
            _ => {
                self.first = Some(First::Header);
                return Err(DispositionClosedV3);
            }
        };
        // The original parent had to pay ALL these possible prefixes before
        // birth. This comparison cannot debit, renew or repair an old deficit.
        self.fee = Some(
            observer_input_disposition_obligations_data_v3(lengths)
                .filter(|demand| originally_paid.checked_sub(*demand).is_ok())
                .ok_or(DispositionClosedV3),
        );
        if !matches!(self.fee, Some(Ok(_))) {
            self.first = Some(First::Fee);
            return Err(DispositionClosedV3);
        }
        self.full
            .capture_once_v3(
                source,
                socket,
                donor,
                handoff.full_slot_for_owed_custody_v3(read),
                ExpectedInputV3::Full(&header),
                binding,
            )
            .inspect_err(|_| {
                self.first = Some(First::Full);
            })?;
        let request = match self.full.output()? {
            CapturedInputDataV3::Acknowledgment => {
                self.completed = Some(AcknowledgmentSlotV3::Full);
                return Ok(());
            }
            CapturedInputDataV3::NamespaceRequest(request) => request,
            _ => {
                self.first = Some(First::Full);
                return Err(DispositionClosedV3);
            }
        };
        self.namespace
            .capture_once_v3(
                source,
                socket,
                donor,
                execution.namespace_slot_for_owed_custody_v3(),
                ExpectedInputV3::Namespace(request),
                binding,
            )
            .inspect_err(|_| {
                self.first = Some(First::Namespace);
            })?;
        if matches!(
            self.namespace.output()?,
            CapturedInputDataV3::Acknowledgment
        ) {
            self.completed = Some(AcknowledgmentSlotV3::Namespace);
            return Ok(());
        }
        self.acknowledgment
            .capture_once_v3(
                source,
                socket,
                donor,
                InputSlotOriginalV3::Unentered,
                ExpectedInputV3::Acknowledgment,
                binding,
            )
            .inspect_err(|_| {
                self.first = Some(First::Acknowledgment);
            })?;
        if !matches!(
            self.acknowledgment.output()?,
            CapturedInputDataV3::Acknowledgment
        ) {
            self.first = Some(First::Acknowledgment);
            return Err(DispositionClosedV3);
        }
        self.completed = Some(AcknowledgmentSlotV3::Terminal);
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            First::PeerBefore => self.peer_before.failure(),
            First::Header => self.header.failure(),
            First::Fee => error(&self.fee),
            First::Full => self.full.failure(),
            First::Namespace => self.namespace.failure(),
            First::Acknowledgment => self.acknowledgment.failure(),
            First::PeerAfter => self.peer_after.failure(),
            First::Order | First::Panic => None,
        };
        cause.or(Some(&DispositionClosedV3))
    }
}

fn decode_header(
    bytes: &[u8],
    binding: NetworkChildOperationBindingDataV2,
) -> Result<CapturedInputDataV3, DispositionClosedV3> {
    let facts = ObserverHandoffHeaderDataV3::decode(bytes)
        .filter(|facts| facts.matches_native(binding))
        .ok_or(DispositionClosedV3)?;
    Ok(CapturedInputDataV3::Header(
        bytes.try_into().map_err(|_| DispositionClosedV3)?,
        facts.section_lengths_data_v3(),
    ))
}

fn decode_input(
    record: &ReceivedDescriptorRecord,
    expected: ExpectedInputV3<'_>,
    binding: NetworkChildOperationBindingDataV2,
    received_here: bool,
) -> Result<CapturedInputDataV3, DispositionClosedV3> {
    if record.payload().len() == 10
        && record.descriptors().is_empty()
        && crate::worker_process::decode_acknowledgement(record.payload()).is_ok()
    {
        return Ok(CapturedInputDataV3::Acknowledgment);
    }
    match expected {
        ExpectedInputV3::Header if record.descriptors().is_empty() => {
            decode_header(record.payload(), binding)
        }
        ExpectedInputV3::Full(header) => {
            let data = ObserverHandoffDataV2::decode(record.payload())
                .filter(|data| data.matches_native(binding))
                .ok_or(DispositionClosedV3)?;
            let rights = record.descriptors().len();
            if record.payload().get(..HEADER_BYTES) != Some(header.as_slice())
                || (received_here && rights != 6)
                || (!received_here && !matches!(rights, 0 | 6))
            {
                return Err(DispositionClosedV3);
            }
            Ok(CapturedInputDataV3::NamespaceRequest(
                data.sections[8].to_vec(),
            ))
        }
        ExpectedInputV3::Namespace(request) => {
            let rights = record.descriptors().len();
            if record.payload() != request
                || (received_here && rights != 2)
                || (!received_here && !matches!(rights, 0 | 2))
            {
                return Err(DispositionClosedV3);
            }
            Ok(CapturedInputDataV3::Namespace)
        }
        _ => Err(DispositionClosedV3),
    }
}

/// Quotes all possible retained negative inputs before native birth.
pub(crate) fn observer_input_disposition_obligations_data_v3(
    lengths: [usize; 9],
) -> Option<ResourceVector> {
    let total = crate::observer_handoff_v2::observer_handoff_length_data_v2(lengths)?;
    let header = DescriptorSubjectSocket::network_worker_receive_obligations_v4(
        NetworkWorkerRecordKindV4::ObservationHandoffHeaderV3,
    )?;
    let full = DescriptorSubjectSocket::network_observer_handoff_receive_obligations_v2(total)?;
    let namespace =
        DescriptorSubjectSocket::network_observer_namespace_request_receive_obligations_v3(
            lengths[8],
        )?;
    let acknowledgment = DescriptorSubjectSocket::network_worker_receive_obligations_v4(
        NetworkWorkerRecordKindV4::AcknowledgmentV2,
    )?;
    let bytes = std::mem::size_of::<ObserverInputDispositionOriginalV3>()
        .checked_mul(2)?
        .checked_add(NetworkWorkerBootstrapWaitOriginalV3::receiving_bytes_v3()?.checked_mul(4)?)?
        .checked_add(header.0)?
        .checked_add(full.0)?
        .checked_add(namespace.0)?
        .checked_add(acknowledgment.0)?
        .checked_add(lengths[8].checked_mul(3)?)?;
    let files = header
        .1
        .checked_add(full.1)?
        .checked_add(namespace.1)?
        .checked_add(acknowledgment.1)?;
    let mut demand = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::OpenFiles, u64::try_from(files).ok()?);
    let identity = NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?;
    for _ in 0..6 {
        demand = demand.checked_add(identity).ok()?;
    }
    Some(demand)
}
