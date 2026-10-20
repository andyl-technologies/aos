//! Retains the finite already-issued P input/ACK custody after body failure.
//!
//! Only genuinely unentered native receives may run. Existing returned frames
//! remain on their original intake owner; an unreturned or failed native read
//! is never retried. A canonical ACK may arrive early. No input is admitted as
//! an effect, namespace, Source, public credential or replacement deadline.

use super::*;
use crate::worker_process::{NetworkWorkerNegativeV2, decode_acknowledgement};
use crate::worker_runtime::child_intake_v2::{
    NetworkPreparationFrameDispositionV3 as Slot, NetworkPreparationIntakeOriginalV2,
};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorWorkerNativeSendAttemptV1, NetworkWorkerBootstrapWaitOriginalV3,
    NetworkWorkerBootstrapWaitRefusalV3, NetworkWorkerRetiredRecordDataV2,
    ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{
    NetworkWorkerRecordKindV4, RecordBindingError, RetainedSeqpacketReceiveErrorV1, SeqpacketError,
};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the P input/ACK custody remains unresolved")]
pub(super) struct PreparationDispositionClosedV2;

struct DispositionSlot {
    wait: NetworkWorkerBootstrapWaitOriginalV3,
    wait_result: Option<Result<(), NetworkWorkerBootstrapWaitRefusalV3>>,
    receive: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    origin: [Option<Result<(), RecordBindingError>>; 2],
    source: NetworkChildSourceRecordOriginalV2,
    source_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    shape: Option<Result<bool, PreparationDispositionClosedV2>>,
    rights: Vec<OwnedFd>,
    retirement: Option<Result<(), NetworkChildOriginClosedV2>>,
    retired: Option<NetworkWorkerRetiredRecordDataV2>,
}

impl DispositionSlot {
    fn new() -> Self {
        Self {
            wait: NetworkWorkerBootstrapWaitOriginalV3::new(),
            wait_result: None,
            receive: None,
            origin: std::array::from_fn(|_| None),
            source: NetworkChildSourceRecordOriginalV2::new(),
            source_result: None,
            shape: None,
            rights: Vec::new(),
            retirement: None,
            retired: None,
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.wait
            .failure()
            .or_else(|| failed(&self.receive))
            .or_else(|| failed(&self.origin[0]))
            .or_else(|| self.source.failure())
            .or_else(|| failed(&self.origin[1]))
            .or_else(|| failed(&self.shape))
            .or_else(|| failed(&self.retirement))
    }

    fn receive_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
        first: bool,
    ) -> Result<(Vec<u8>, usize), PreparationDispositionClosedV2> {
        self.wait_result = Some(self.wait.observe_once_v3(socket, donor, None));
        if !matches!(self.wait_result, Some(Ok(()))) {
            return Err(PreparationDispositionClosedV2);
        }
        self.receive =
            Some(socket.receive_owed_network_preparation_frame_or_ack_retaining_v3(first));
        let record = self
            .receive
            .as_ref()
            .and_then(|record| record.as_ref().ok())
            .ok_or(PreparationDispositionClosedV2)?;
        validate_record_v2(
            record,
            source,
            socket,
            &mut self.origin,
            &mut self.source,
            &mut self.source_result,
        )
    }
}

fn validate_record_v2(
    record: &ReceivedDescriptorRecord,
    source: &mut NetworkChildSourceLoanV2<'_>,
    socket: &mut DescriptorSubjectSocket,
    origin: &mut [Option<Result<(), RecordBindingError>>; 2],
    identity: &mut NetworkChildSourceRecordOriginalV2,
    result: &mut Option<Result<(), NetworkChildOriginClosedV2>>,
) -> Result<(Vec<u8>, usize), PreparationDispositionClosedV2> {
    origin[0] = Some(socket.validate_received_origin_retaining(record));
    *result = Some(source.require_owed_netd_record_once_v2(record, identity));
    origin[1] = Some(socket.validate_received_origin_retaining(record));
    if origin.iter().all(|result| matches!(result, Some(Ok(())))) && matches!(*result, Some(Ok(())))
    {
        Ok((record.payload().to_vec(), record.descriptors().len()))
    } else {
        Err(PreparationDispositionClosedV2)
    }
}

/// Owns one negative send and the exact finite unentered frame/ACK suffix.
pub(super) struct PreparationDispositionOriginalV2 {
    entered: bool,
    failure_slot: Option<usize>,
    closed: Option<PreparationDispositionClosedV2>,
    negative: Option<[u8; 160]>,
    peer_before: NetworkChildSourceRecordOriginalV2,
    peer_before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    native_post: Option<aos_sandbox_linux::Error>,
    binding: Option<Result<(), RecordBindingError>>,
    peer_after: NetworkChildSourceRecordOriginalV2,
    peer_after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    slots: Vec<DispositionSlot>,
    total: Option<usize>,
    digest: Option<[u8; 32]>,
    hasher: Sha256,
    gate: Option<Result<(), PreparationDispositionClosedV2>>,
    acknowledged: bool,
}

impl PreparationDispositionOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            failure_slot: None,
            closed: None,
            negative: None,
            peer_before: NetworkChildSourceRecordOriginalV2::new(),
            peer_before_result: None,
            send: None,
            native_post: None,
            binding: None,
            peer_after: NetworkChildSourceRecordOriginalV2::new(),
            peer_after_result: None,
            slots: Vec::new(),
            total: None,
            digest: None,
            hasher: Sha256::new(),
            gate: None,
            acknowledged: false,
        }
    }

    pub(super) fn capture_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
        intake: &NetworkPreparationIntakeOriginalV2,
        paid: ResourceVector,
        negative: Option<NetworkWorkerNegativeV2>,
    ) -> Result<(), PreparationDispositionClosedV2> {
        if self.entered {
            return self.refuse();
        }
        self.entered = true;
        self.negative = negative.map(|negative| negative.encode());
        self.peer_before_result =
            Some(source.require_owed_netd_peer_once_v2(socket, &mut self.peer_before));
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if !matches!(self.peer_before_result, Some(Ok(()))) {
                return self.refuse();
            }
            if let Some(negative) = self.negative.as_ref() {
                let (send, post) = socket.send_network_worker_child_record_retaining_v3(
                    NetworkWorkerRecordKindV4::PreparationTerminalV2,
                    negative,
                    &[],
                    None,
                );
                self.send = Some(send);
                self.native_post = post;
                if let Some(Ok(receipt)) = self.send.as_ref() {
                    self.binding = Some(receipt.require_same_socket(socket));
                }
                if !matches!(self.send, Some(Ok(ref receipt)) if receipt.is_sent()) {
                    return self.refuse();
                }
                if self.native_post.is_some() || !matches!(self.binding, Some(Ok(()))) {
                    // Actual delivery still owes its ACK disposition. Keep the
                    // failed post resident while draining only issued input.
                    self.closed.get_or_insert(PreparationDispositionClosedV2);
                }
            }
            self.receive_suffix_v2(source, socket, donor, intake, paid)
        }));
        // The final exact-parent native post runs after every body refusal and
        // unwind. It closes only already-issued custody, never effect time.
        self.peer_after_result =
            Some(source.require_owed_netd_peer_once_v2(socket, &mut self.peer_after));
        if !matches!(self.peer_after_result, Some(Ok(()))) {
            self.closed.get_or_insert(PreparationDispositionClosedV2);
        }
        match body {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(_)) => self.refuse(),
            Ok(Ok(())) if self.closed.is_none() && self.acknowledged => Ok(()),
            Ok(Ok(())) => self.refuse(),
        }
    }

    fn receive_suffix_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
        intake: &NetworkPreparationIntakeOriginalV2,
        paid: ResourceVector,
    ) -> Result<(), PreparationDispositionClosedV2> {
        let mut index = 0usize;
        loop {
            // The first native slot is prepaid fixed geometry. The actual
            // Source-bound header gates all later Vec growth before reserve.
            self.slots.push(DispositionSlot::new());
            let original = if self.total.is_some_and(|total| {
                index == total.div_ceil(super::super::MAXIMUM_FRAME_PAYLOAD_BYTES)
            }) {
                Slot::Unentered
            } else {
                intake.frame_disposition_original_v3(index)
            };
            let already_held = !matches!(&original, Slot::Unentered);
            let captured = match original {
                Slot::Uncertain => {
                    self.failure_slot = Some(index);
                    return self.refuse();
                }
                Slot::Retired(data) => {
                    let result = self.classify_v2(data.payload(), 0, index, true);
                    self.slots[index].shape = Some(result);
                    match self.slots[index].shape {
                        Some(Ok(true)) => {
                            self.acknowledged = true;
                            return Ok(());
                        }
                        Some(Ok(false)) => {
                            self.admit_suffix_v2(paid, index)?;
                            index += 1;
                            continue;
                        }
                        _ => {
                            self.failure_slot = Some(index);
                            return self.refuse();
                        }
                    }
                }
                Slot::Record(record) => {
                    let slot = &mut self.slots[index];
                    validate_record_v2(
                        record,
                        source,
                        socket,
                        &mut slot.origin,
                        &mut slot.source,
                        &mut slot.source_result,
                    )
                }
                Slot::Unentered => {
                    let slot = &mut self.slots[index];
                    slot.receive_once_v2(source, socket, donor, index == 0)
                }
            };
            let (bytes, rights) = match captured {
                Ok(captured) => captured,
                Err(_) => {
                    self.failure_slot = Some(index);
                    return self.refuse();
                }
            };
            let result = self.classify_v2(&bytes, rights, index, already_held);
            self.slots[index].shape = Some(result);
            if !matches!(self.slots[index].shape, Some(Ok(_))) {
                self.failure_slot = Some(index);
                return self.refuse();
            }
            let acknowledged = matches!(self.slots[index].shape, Some(Ok(true)));
            // Only new, wholly positive native proof temporaries retire.
            // Existing failed intake records stay untouched on their owner.
            if self.slots[index].receive.is_some() {
                self.retire_completed_slot_v2(index)?;
            }
            if acknowledged {
                self.acknowledged = true;
                return Ok(());
            }
            self.admit_suffix_v2(paid, index)?;
            index = index.checked_add(1).ok_or(PreparationDispositionClosedV2)?;
        }
    }

    fn classify_v2(
        &mut self,
        bytes: &[u8],
        rights: usize,
        index: usize,
        already_held: bool,
    ) -> Result<bool, PreparationDispositionClosedV2> {
        if rights == 0 && decode_acknowledgement(bytes).is_ok() {
            return Ok(true);
        }
        let frame =
            super::super::decode_frame(bytes).map_err(|_| PreparationDispositionClosedV2)?;
        let expected_offset = index
            .checked_mul(super::super::MAXIMUM_FRAME_PAYLOAD_BYTES)
            .ok_or(PreparationDispositionClosedV2)?;
        let length = frame
            .total
            .checked_sub(expected_offset)
            .ok_or(PreparationDispositionClosedV2)?
            .min(super::super::MAXIMUM_FRAME_PAYLOAD_BYTES);
        if frame.offset != expected_offset || frame.payload.len() != length || length == 0 {
            return Err(PreparationDispositionClosedV2);
        }
        if index == 0 {
            let (method, _, _, total) = super::super::preparation_input_v2::header_data_v2(
                frame
                    .payload
                    .get(..super::super::preparation_input_v2::INPUT_HEADER_BYTES)
                    .ok_or(PreparationDispositionClosedV2)?,
            )
            .ok_or(PreparationDispositionClosedV2)?;
            if total != frame.total
                || !((already_held && rights == 0) || rights == if method == 63 { 1 } else { 2 })
            {
                return Err(PreparationDispositionClosedV2);
            }
            self.total = Some(total);
            self.digest = Some(frame.digest);
        } else if self.total != Some(frame.total)
            || self.digest != Some(frame.digest)
            || rights != 0
        {
            return Err(PreparationDispositionClosedV2);
        }
        self.hasher.update(frame.payload);
        if frame.offset + frame.payload.len() == frame.total
            && self.digest != Some(<[u8; 32]>::from(self.hasher.clone().finalize()))
        {
            return Err(PreparationDispositionClosedV2);
        }
        Ok(false)
    }

    fn admit_suffix_v2(
        &mut self,
        paid: ResourceVector,
        index: usize,
    ) -> Result<(), PreparationDispositionClosedV2> {
        if index != 0 {
            return Ok(());
        }
        self.gate = Some(
            match self.total.and_then(Self::receiving_obligations_data_v2) {
                Some(demand) if paid.checked_sub(demand).is_ok() => Ok(()),
                _ => Err(PreparationDispositionClosedV2),
            },
        );
        if !matches!(self.gate, Some(Ok(()))) {
            return self.refuse();
        }
        let count = self
            .total
            .ok_or(PreparationDispositionClosedV2)?
            .div_ceil(super::super::MAXIMUM_FRAME_PAYLOAD_BYTES)
            .checked_add(1)
            .ok_or(PreparationDispositionClosedV2)?;
        self.slots.reserve_exact(
            count
                .checked_sub(self.slots.len())
                .ok_or(PreparationDispositionClosedV2)?,
        );
        Ok(())
    }

    fn retire_completed_slot_v2(
        &mut self,
        index: usize,
    ) -> Result<(), PreparationDispositionClosedV2> {
        let slot = &mut self.slots[index];
        slot.retirement = Some(slot.source.retire_positive_stat_proof_once_v2());
        if !matches!(slot.retirement, Some(Ok(()))) {
            self.failure_slot = Some(index);
            return self.refuse();
        }
        let original = slot.receive.take();
        if let Some(Ok(mut record)) = original {
            if !record.descriptors().is_empty() {
                slot.rights = record
                    .take_network_preparation_frame_descriptors_data_v3()
                    .ok_or(PreparationDispositionClosedV2)?;
            }
            match record.retire_network_worker_positive_subject_data_v2() {
                Ok(data) => {
                    slot.retired = Some(data);
                    return Ok(());
                }
                Err(record) => slot.receive = Some(Ok(record)),
            }
        } else {
            slot.receive = original;
        }
        self.failure_slot = Some(index);
        self.refuse()
    }

    fn refuse<T>(&mut self) -> Result<T, PreparationDispositionClosedV2> {
        self.closed.get_or_insert(PreparationDispositionClosedV2);
        Err(PreparationDispositionClosedV2)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.peer_before
            .failure()
            .or_else(|| match self.send.as_ref() {
                Some(Ok(receipt)) => receipt.failure(),
                Some(Err(cause)) => Some(cause as _),
                None => None,
            })
            .or_else(|| self.native_post.as_ref().map(|cause| cause as _))
            .or_else(|| failed(&self.binding))
            .or_else(|| {
                self.failure_slot
                    .and_then(|index| self.slots.get(index))
                    .and_then(DispositionSlot::failure)
            })
            .or_else(|| self.peer_after.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(super) fn receiving_obligations_data_v2(width: usize) -> Option<ResourceVector> {
        if width == 0 || width > super::super::MAXIMUM_NETWORK_WORKER_REQUEST_BYTES {
            return None;
        }
        let count = width
            .div_ceil(super::super::MAXIMUM_FRAME_PAYLOAD_BYTES)
            .checked_add(1)?;
        let native = DescriptorSubjectSocket::network_worker_receive_obligations_v4(
            NetworkWorkerRecordKindV4::PreparationRequestFirstV2,
        )?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                std::mem::size_of::<DispositionSlot>()
                    .checked_mul(2)?
                    .checked_mul(count)?,
            )?
            .checked_add(
                native
                    .0
                    .checked_add(NetworkWorkerBootstrapWaitOriginalV3::receiving_bytes_v3()?)?
                    .checked_mul(count)?,
            )?
            .checked_add(width.checked_mul(2)?)?
            .checked_add(DescriptorSubjectSocket::network_worker_child_send_obligations_v3()?)?;
        let identity = NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(native.1.checked_add(3)?).ok()?);
        for _ in 0..count.checked_add(2)? {
            demand = demand.checked_add(identity).ok()?;
        }
        Some(demand)
    }
}
