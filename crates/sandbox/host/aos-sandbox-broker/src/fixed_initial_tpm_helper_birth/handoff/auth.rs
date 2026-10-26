//! Sends original held authentication only through the acknowledged helper.
//!
//! The caller's Source keeps its private credential. This owner has no public
//! secret, frame, socket or destination getter. Its single zeroizing frame and
//! all reached native observations stay inside the same child reservoir.

use super::*;
use crate::fixed_tpm_helper_wire::{AUTH_BYTES, encode_auth_v2};

pub(super) struct InitialHelperAuthOriginalV1 {
    frame: Option<Result<Zeroizing<[u8; AUTH_BYTES]>, TpmHelperFrameErrorV2>>,
    readiness: SeqpacketReadinessOriginalV1,
    pub(super) child_posts: [PidFdProcOriginalsV1; 4],
    clocks: [Option<Timespec>; 2],
    sent: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: SeqpacketSendAfterOriginalV1,
    send_post: Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
    child_after: Option<Result<(), InitialTpmHelperBirthClosedV1>>,
}

impl InitialHelperAuthOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            frame: None,
            readiness: SeqpacketReadinessOriginalV1::new(),
            child_posts: std::array::from_fn(|_| PidFdProcOriginalsV1::new()),
            clocks: [None; 2],
            sent: None,
            send_after: SeqpacketSendAfterOriginalV1::new(),
            send_post: None,
            child_after: None,
        }
    }

    pub(super) fn receiving_bytes_v1() -> Option<usize> {
        // The enclosing construction quote already covers this fixed owner.
        // Retained native proc readers separately supply their bounded work.
        PidFdProcOriginalsV1::receiving_bytes_v1()?
            .checked_mul(4)?
            .checked_add(4096)
    }

    pub(super) fn traffic_bytes_v1() -> Option<usize> {
        PidFdProcOriginalsV1::stat_maximum_requested_read_bytes_v1()?
            .checked_add(PidFdProcOriginalsV1::context_maximum_requested_read_bytes_v1()?)?
            .checked_mul(2)?
            .checked_add(AUTH_BYTES)
    }

    fn sample(&mut self, index: usize, cut: FixedProcessBoottimeCutV1) -> bool {
        self.clocks[index] = Some(clock_gettime(ClockId::Boottime));
        self.clocks[index]
            .and_then(nanoseconds)
            .is_some_and(|now| now < cut.exclusive_nanoseconds())
    }
}

impl InitialTpmHelperDrivingLoanV1<'_> {
    /// Waits once for AUTH and reobserves the same acknowledged child.
    ///
    /// The Source rechecks its own currentness after this bounded wait and
    /// before borrowing its original private credential for the actual send.
    /// No secret is accepted, encoded or transmitted by readiness preparation.
    ///
    /// # Errors
    /// Refuses a missing original ACK, reentry, timeout, unexpected readiness
    /// flags or changed native child. Actual poll and held-proc results remain.
    pub fn wait_auth_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::Acknowledged)?;
            self.handoff.phase = Phase::AuthPreparing;
            let fd = self
                .channel
                .as_fd()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?;
            if !self.handoff.auth.readiness.observe(
                fd,
                PollFlags::OUT,
                self.cut.exclusive_nanoseconds(),
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.observe_child(ChildPostV1::BeforeAuth)?;
            self.handoff.phase = Phase::AuthReady;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Sends one zeroizing AUTH frame to this original acknowledged child.
    ///
    /// The genuine Source supplies a borrow of its already-held credential
    /// after its own currentness observation. No caller selects the destination,
    /// nonce or endpoint. The same native retained sender and same-socket post
    /// preserve failures. Successful transmission grants no TPM observation,
    /// Extend or checkpoint authority; semantic decisions remain with Security.
    ///
    /// # Errors
    /// Refuses missing original child/ACK/readiness, reentry, noninitial purpose,
    /// sentinel auth, elapsed cut, native send or independent custody-post failure.
    /// The actual zeroizing frame and native error remain resident on refusal.
    pub fn send_held_auth_once_v1(
        &mut self,
        auth: &[u8; 32],
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::AuthReady)?;
            self.handoff.phase = Phase::Authenticating;
            let endpoint = match self.image.purpose_data_v1() {
                FixedTpmHelperPurposeV1::InitialController => {
                    FixedTpmEndpointV2::ControllerStorageClient
                }
                FixedTpmHelperPurposeV1::InitialStorage => FixedTpmEndpointV2::StorageBroker,
                _ => return Err(InitialTpmHelperBirthClosedV1),
            };
            self.handoff.auth.frame = Some(encode_auth_v2(
                endpoint,
                self.handoff.nonce.ok_or(InitialTpmHelperBirthClosedV1)?,
                auth,
            ));
            if !self.handoff.auth.sample(0, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            let bytes = self
                .handoff
                .auth
                .frame
                .as_ref()
                .and_then(|frame| frame.as_ref().ok())
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            self.handoff.auth.sent = Some(self.channel.send_retaining(bytes.as_ref()));
            self.handoff.auth.send_post = Some(
                self.handoff.auth.send_after.observe_once_v1(
                    self.channel,
                    self.handoff
                        .auth
                        .sent
                        .as_ref()
                        .and_then(|sent| sent.as_ref().err()),
                ),
            );
            // A failed send still owes both original socket and child posts.
            // Source currentness is independently observed by its enclosing loan.
            self.handoff.auth.child_after = Some(self.observe_child(ChildPostV1::AfterAuth));
            let after = self.handoff.auth.sample(1, self.cut);
            if !matches!(self.handoff.auth.sent, Some(Ok(())))
                || !matches!(self.handoff.auth.send_post, Some(Ok(())))
                || !matches!(self.handoff.auth.child_after, Some(Ok(())))
                || !after
            {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::Authenticated;
            Ok(())
        })();
        self.retain_refusal(result)
    }
}
