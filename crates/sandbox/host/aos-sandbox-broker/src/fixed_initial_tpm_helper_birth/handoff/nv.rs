//! Retains finite NV and close exchanges on the original authenticated child.
//!
//! The finite recipe is Read, optional one Extend, final Read, then close ACK.
//! These mechanics confer no approval, NV-public or checkpoint authority. Security
//! makes those decisions while the genuine Source keeps this same loan alive.

use super::*;
use crate::fixed_tpm_helper_wire::{
    HelperObservationV1, HelperOperationV1, REQUEST_BYTES, RESPONSE_BYTES, decode_response_v2,
    encode_initial_close_request_v2, encode_request_v2, require_initial_closed_ack_v2,
};

pub(super) struct InitialHelperNvOriginalV1 {
    active: Option<usize>,
    pub(super) slots: [ExchangeOriginalV1; 4],
}

pub(super) struct ExchangeOriginalV1 {
    operation: Option<HelperOperationV1>,
    pub(super) sequence: Option<u64>,
    closed_ack: Option<Result<(), TpmHelperFrameErrorV2>>,
    frame: Option<Result<[u8; REQUEST_BYTES], TpmHelperFrameErrorV2>>,
    readiness: [SeqpacketReadinessOriginalV1; 2],
    pub(super) child_posts: [PidFdProcOriginalsV1; 6],
    child_after: [Option<Result<(), InitialTpmHelperBirthClosedV1>>; 2],
    clocks: [Option<Timespec>; 5],
    sent: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: SeqpacketSendAfterOriginalV1,
    send_post: Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
    received: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    subject: HelperRecordSubjectOriginalV1,
    decoded: Option<Result<HelperObservationV1, TpmHelperFrameErrorV2>>,
}

impl InitialHelperNvOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            active: None,
            slots: std::array::from_fn(|_| ExchangeOriginalV1::new()),
        }
    }

    pub(super) fn receiving_bytes_v1() -> Option<usize> {
        // Construction covers all four fixed owners. Native receive/proc
        // suppliers and bounded DATA-return overlap are paid separately.
        let (receive, _) =
            SeqpacketSocket::closed_zero_rights_receive_obligations_v1(RESPONSE_BYTES)?;
        receive
            .checked_add(PidFdProcOriginalsV1::receiving_bytes_v1()?.checked_mul(6)?)?
            .checked_add(8192)?
            .checked_add(std::mem::size_of::<HelperObservationV1>().checked_mul(2)?)?
            .checked_mul(4)
    }

    pub(super) fn receiving_files_v1() -> Option<usize> {
        SeqpacketSocket::closed_zero_rights_receive_obligations_v1(RESPONSE_BYTES)?
            .1
            .checked_mul(4)
    }

    pub(super) fn traffic_bytes_v1() -> Option<usize> {
        PidFdProcOriginalsV1::stat_maximum_requested_read_bytes_v1()?
            .checked_add(PidFdProcOriginalsV1::context_maximum_requested_read_bytes_v1()?)?
            .checked_mul(3)?
            .checked_add(REQUEST_BYTES)?
            .checked_add(RESPONSE_BYTES.checked_mul(2)?)?
            .checked_mul(4)
    }
}

impl ExchangeOriginalV1 {
    fn new() -> Self {
        Self {
            operation: None,
            sequence: None,
            closed_ack: None,
            frame: None,
            readiness: std::array::from_fn(|_| SeqpacketReadinessOriginalV1::new()),
            child_posts: std::array::from_fn(|_| PidFdProcOriginalsV1::new()),
            child_after: [None; 2],
            clocks: [None; 5],
            sent: None,
            send_after: SeqpacketSendAfterOriginalV1::new(),
            send_post: None,
            received: None,
            subject: HelperRecordSubjectOriginalV1::new(),
            decoded: None,
        }
    }

    fn sample(&mut self, index: usize, cut: FixedProcessBoottimeCutV1) -> bool {
        self.clocks[index] = Some(clock_gettime(ClockId::Boottime));
        self.clocks[index]
            .and_then(nanoseconds)
            .is_some_and(|now| now < cut.exclusive_nanoseconds())
    }
}

impl InitialTpmHelperDrivingLoanV1<'_> {
    /// Prepares the first Read on this original authenticated child once.
    ///
    /// # Errors
    /// Refuses missing original AUTH, reentry or failed canonical encoding.
    pub fn prepare_initial_read_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        self.prepare_nv(HelperOperationV1::Read, [0; 32], false)
    }

    /// Prepares at most one initial Extend after this child's original Read.
    ///
    /// The input is comparison DATA, not approval. Security must derive it from
    /// its resident verified intent and the same current original journal cut.
    ///
    /// # Errors
    /// Refuses missing first Read, a second Extend, sentinel input or prior failure.
    pub fn prepare_initial_extend_once_v1(
        &mut self,
        input: [u8; 32],
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        self.prepare_nv(HelperOperationV1::Extend, input, false)
    }

    /// Prepares the final Read after the original first Read or sole Extend.
    ///
    /// # Errors
    /// Refuses missing predecessor, repeated final Read or a failed carrier.
    pub fn prepare_final_read_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        self.prepare_nv(HelperOperationV1::Read, [0; 32], true)
    }

    fn prepare_nv(
        &mut self,
        operation: HelperOperationV1,
        input: [u8; 32],
        final_read: bool,
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            let index = match (
                self.handoff.phase,
                self.handoff.nv.active,
                operation,
                final_read,
            ) {
                (Phase::Authenticated, None, HelperOperationV1::Read, false) => 0,
                (Phase::NvObserved, Some(0), HelperOperationV1::Extend, false)
                | (Phase::NvObserved, Some(0), HelperOperationV1::Read, true) => 1,
                (Phase::NvObserved, Some(1), HelperOperationV1::Read, true)
                    if self.handoff.nv.slots[1].operation == Some(HelperOperationV1::Extend) =>
                {
                    2
                }
                _ => return Err(InitialTpmHelperBirthClosedV1),
            };
            self.require_phase(self.handoff.phase)?;
            self.handoff.phase = Phase::NvPreparing;
            self.handoff.nv.active = Some(index);
            let slot = &mut self.handoff.nv.slots[index];
            slot.operation = Some(operation);
            slot.sequence = Some(index as u64 + 1);
            slot.frame = Some(encode_request_v2(
                operation,
                self.handoff.nonce.ok_or(InitialTpmHelperBirthClosedV1)?,
                slot.sequence.ok_or(InitialTpmHelperBirthClosedV1)?,
                input,
            ));
            if !matches!(slot.frame, Some(Ok(_))) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::NvPrepared;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Prepares initial-only context closure after the admitted final Read.
    ///
    /// The same exchange carrier retains the close ACK before subject, original
    /// child and framing admission. This grants no process-cleanup or checkpoint
    /// authority; the helper remains alive holding both locks until finish.
    ///
    /// # Errors
    /// Refuses a missing final Read, reuse, prior failure or invalid correlation.
    pub fn prepare_initial_close_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::NvObserved)?;
            let previous = self
                .handoff
                .nv
                .active
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            if !matches!(previous, 1 | 2)
                || self.handoff.nv.slots[previous].operation != Some(HelperOperationV1::Read)
                || !matches!(self.handoff.nv.slots[previous].decoded, Some(Ok(_)))
            {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::NvPreparing;
            let sequence = previous as u64 + 2;
            self.handoff.nv.active = Some(3);
            let slot = &mut self.handoff.nv.slots[3];
            slot.sequence = Some(sequence);
            slot.frame = Some(encode_initial_close_request_v2(
                self.handoff.nonce.ok_or(InitialTpmHelperBirthClosedV1)?,
                sequence,
            ));
            if !matches!(slot.frame, Some(Ok(_))) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::NvPrepared;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Waits once for request readiness and reobserves the held child.
    ///
    /// Source currentness must be checked again after this wait before sending.
    ///
    /// # Errors
    /// Retains timeout, unexpected events or changed child; refuses wrong phase.
    pub fn wait_nv_send_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::NvPrepared)?;
            let index = self
                .handoff
                .nv
                .active
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            let fd = self
                .channel
                .as_fd()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?;
            if !self.handoff.nv.slots[index].readiness[0].observe(
                fd,
                PollFlags::OUT,
                self.cut.exclusive_nanoseconds(),
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.observe_child(ChildPostV1::NvBeforeSend(index))?;
            self.handoff.phase = Phase::NvSendReady;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Sends the retained request once and independently observes socket and child.
    ///
    /// # Errors
    /// Refuses missing readiness, elapsed cut, send or either custody post failure.
    /// Actual native results remain even when transmission may have reached TPM.
    pub fn send_nv_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::NvSendReady)?;
            self.handoff.phase = Phase::NvSending;
            let index = self
                .handoff
                .nv
                .active
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            let slot = &mut self.handoff.nv.slots[index];
            if !slot.sample(0, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            let bytes = slot
                .frame
                .as_ref()
                .and_then(|frame| frame.as_ref().ok())
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            slot.sent = Some(self.channel.send_retaining(bytes));
            slot.send_post = Some(slot.send_after.observe_once_v1(
                self.channel,
                slot.sent.as_ref().and_then(|sent| sent.as_ref().err()),
            ));
            let child = self.observe_child(ChildPostV1::NvAfterSend(index));
            let slot = &mut self.handoff.nv.slots[index];
            slot.child_after[0] = Some(child);
            let after = slot.sample(1, self.cut);
            if !matches!(slot.sent, Some(Ok(())))
                || !matches!(slot.send_post, Some(Ok(())))
                || !matches!(slot.child_after[0], Some(Ok(())))
                || !after
            {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::NvSent;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Waits for one reply under the same original child's finite cut.
    ///
    /// # Errors
    /// Refuses wrong phase, timeout, failed poll or unexpected event flags.
    pub fn wait_nv_receive_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::NvSent)?;
            let index = self
                .handoff
                .nv
                .active
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            let fd = self
                .channel
                .as_fd()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?;
            if !self.handoff.nv.slots[index].readiness[1].observe(
                fd,
                PollFlags::IN,
                self.cut.exclusive_nanoseconds(),
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::NvReceiveReady;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Retains the native reply before checking subject, child and correlation.
    ///
    /// The held-child post is attempted even after a failed native receive.
    /// Decoding supplies DATA only; Security independently checks public area,
    /// expected Name and exact initial target while retaining its original loan.
    ///
    /// # Errors
    /// Retains receive failures, malformed records and foreign/dead subjects;
    /// refuses changed child, framing, late observation or wrong phase.
    pub fn receive_nv_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::NvReceiveReady)?;
            self.handoff.phase = Phase::NvReceiving;
            let index = self
                .handoff
                .nv
                .active
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            self.channel
                .zero_rights_receive_obligations_v1(RESPONSE_BYTES)
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            let slot = &mut self.handoff.nv.slots[index];
            if !slot.sample(2, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            slot.received = Some(
                self.channel
                    .receive_storage_preparation_retaining_v1(RESPONSE_BYTES),
            );
            let after = slot.sample(3, self.cut);
            let child_after = self.observe_child(ChildPostV1::NvAfterReceive(index));
            let slot = &mut self.handoff.nv.slots[index];
            slot.child_after[1] = Some(child_after);
            if !after || !matches!(slot.child_after[1], Some(Ok(()))) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            let record = slot
                .received
                .as_ref()
                .and_then(|received| received.as_ref().ok())
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            let (child, _) = self
                .driving
                .original_child()
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            slot.subject.observe_once(
                record,
                child,
                self.identity.ok_or(InitialTpmHelperBirthClosedV1)?.pid(),
            )?;
            let nonce = self.handoff.nonce.ok_or(InitialTpmHelperBirthClosedV1)?;
            let sequence = slot.sequence.ok_or(InitialTpmHelperBirthClosedV1)?;
            if index == 3 {
                slot.closed_ack = Some(require_initial_closed_ack_v2(
                    record.payload(),
                    nonce,
                    sequence,
                ));
                if !matches!(slot.closed_ack, Some(Ok(()))) || !slot.sample(4, self.cut) {
                    return Err(InitialTpmHelperBirthClosedV1);
                }
                self.handoff.phase = Phase::ContextClosed;
            } else {
                slot.decoded = Some(decode_response_v2(
                    record.payload(),
                    slot.operation.ok_or(InitialTpmHelperBirthClosedV1)?,
                    nonce,
                    sequence,
                ));
                if !matches!(slot.decoded, Some(Ok(_))) || !slot.sample(4, self.cut) {
                    return Err(InitialTpmHelperBirthClosedV1);
                }
                self.handoff.phase = Phase::NvObserved;
            }
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Borrows only decoded comparison DATA from the last admitted native reply.
    ///
    /// This exports neither a record nor child/channel authority. A successful
    /// borrow cannot replace Security's own current approval/public-area checks.
    ///
    /// # Errors
    /// Refuses incomplete, failed or replaced exchange state.
    pub fn nv_observation_data_v1(
        &self,
    ) -> Result<&HelperObservationV1, InitialTpmHelperBirthClosedV1> {
        self.require_phase(Phase::NvObserved)?;
        self.handoff.nv.slots[self
            .handoff
            .nv
            .active
            .ok_or(InitialTpmHelperBirthClosedV1)?]
        .decoded
        .as_ref()
        .and_then(|decoded| decoded.as_ref().ok())
        .ok_or(InitialTpmHelperBirthClosedV1)
    }
}
