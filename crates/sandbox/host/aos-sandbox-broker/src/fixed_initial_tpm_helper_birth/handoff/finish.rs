//! Retains the finish send after the same measured child's closed-context ACK.
//!
//! The final send permits normal child exit. It does not manufacture a live
//! child post after that exit, or claim reaping, unit drain or checkpoint safety.

use super::*;
use crate::fixed_tpm_helper_wire::{INITIAL_TERMINAL_BYTES, encode_initial_finish_v2};

pub(super) struct InitialHelperFinishOriginalV1 {
    frame: Option<Result<[u8; INITIAL_TERMINAL_BYTES], TpmHelperFrameErrorV2>>,
    readiness: SeqpacketReadinessOriginalV1,
    pub(super) child_posts: [PidFdProcOriginalsV1; 2],
    clocks: [Option<Timespec>; 2],
    sent: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: SeqpacketSendAfterOriginalV1,
    send_post: Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
}

impl InitialHelperFinishOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            frame: None,
            readiness: SeqpacketReadinessOriginalV1::new(),
            child_posts: std::array::from_fn(|_| PidFdProcOriginalsV1::new()),
            clocks: [None; 2],
            sent: None,
            send_after: SeqpacketSendAfterOriginalV1::new(),
            send_post: None,
        }
    }

    pub(super) fn receiving_bytes_v1() -> Option<usize> {
        PidFdProcOriginalsV1::receiving_bytes_v1()?
            .checked_mul(2)?
            .checked_add(4096)
    }

    pub(super) fn traffic_bytes_v1() -> Option<usize> {
        PidFdProcOriginalsV1::stat_maximum_requested_read_bytes_v1()?
            .checked_add(PidFdProcOriginalsV1::context_maximum_requested_read_bytes_v1()?)?
            .checked_add(INITIAL_TERMINAL_BYTES)
    }

    fn sample(&mut self, index: usize, cut: FixedProcessBoottimeCutV1) -> bool {
        self.clocks[index] = Some(clock_gettime(ClockId::Boottime));
        self.clocks[index]
            .and_then(nanoseconds)
            .is_some_and(|now| now < cut.exclusive_nanoseconds())
    }
}

impl InitialTpmHelperDrivingLoanV1<'_> {
    /// Waits for finish readiness after this child's original closed-context ACK.
    ///
    /// Source currentness must be observed after the wait before the final send.
    /// The helper is still required to be the same live measured child here.
    ///
    /// # Errors
    /// Refuses missing close admission, reentry, timeout or changed held child.
    pub fn wait_initial_finish_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::ContextClosed)?;
            self.handoff.phase = Phase::FinishPreparing;
            let sequence = self.handoff.nv.slots[3]
                .sequence
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            self.handoff.finish.frame = Some(encode_initial_finish_v2(
                self.handoff.nonce.ok_or(InitialTpmHelperBirthClosedV1)?,
                sequence,
            ));
            if !matches!(self.handoff.finish.frame, Some(Ok(_))) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            let fd = self
                .channel
                .as_fd()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?;
            if !self.handoff.finish.readiness.observe(
                fd,
                PollFlags::OUT,
                self.cut.exclusive_nanoseconds(),
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.observe_child(ChildPostV1::BeforeFinish)?;
            self.handoff.phase = Phase::FinishReady;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Sends the exact finish frame once without replacing original cleanup.
    ///
    /// Successful transmission allows immediate child exit. The retained
    /// same-socket post is independent of peer liveness; actual original process
    /// completion remains owed before the caller can claim cleanup.
    ///
    /// # Errors
    /// Retains native send/socket failure and refuses reentry or elapsed cut.
    pub fn send_initial_finish_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::FinishReady)?;
            self.handoff.phase = Phase::Finishing;
            let slot = &mut self.handoff.finish;
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
            let after = slot.sample(1, self.cut);
            if !matches!(slot.sent, Some(Ok(())))
                || !matches!(slot.send_post, Some(Ok(())))
                || !after
            {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::FinishSent;
            Ok(())
        })();
        self.retain_refusal(result)
    }
}
