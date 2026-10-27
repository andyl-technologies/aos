//! Retains one nonce-bound HELLO and the actual measured child's lock ACK.
//!
//! Readiness and descriptor sends reuse the native sequenced-packet engine.
//! No private key, channel or ACK-derived application authority is exported.

use std::os::fd::BorrowedFd;

use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RetainedSeqpacketReceiveErrorV1, RetainedSeqpacketSendErrorV1,
    SeqpacketReadinessOriginalV1, SeqpacketSendAfterOriginalV1,
};
use rustix::event::PollFlags;
use zeroize::Zeroizing;

mod auth;
mod cleanup;
mod finish;
mod nv;
use auth::InitialHelperAuthOriginalV1;
use cleanup::InitialHelperCleanupOriginalV1;
use finish::InitialHelperFinishOriginalV1;
use nv::InitialHelperNvOriginalV1;

use super::*;
use crate::bounded_entropy::RetainedKernelNonceOriginalV1;
use crate::fixed_tpm_helper_wire::{
    FixedTpmEndpointV2, HELLO_BYTES, LOCK_ACK_BYTES, TpmHelperFrameErrorV2, encode_hello_v2,
    require_lock_ack_v2,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Fresh,
    Preparing,
    Prepared,
    SendReady,
    Sending,
    HelloSent,
    AckReady,
    Receiving,
    Acknowledged,
    AuthPreparing,
    AuthReady,
    Authenticating,
    Authenticated,
    NvPreparing,
    NvPrepared,
    NvSendReady,
    NvSending,
    NvSent,
    NvReceiveReady,
    NvReceiving,
    NvObserved,
    ContextClosed,
    FinishPreparing,
    FinishReady,
    Finishing,
    FinishSent,
    CleanupAdvancing,
    CleanupNeedsWait,
    CleanupAdvanceReady,
    Cleaned,
}

enum ChildPostV1 {
    BeforeHello,
    BeforeFinish,
    AfterAck,
    BeforeAuth,
    AfterAuth,
    NvBeforeSend(usize),
    NvAfterSend(usize),
    NvAfterReceive(usize),
}

pub(super) struct InitialHelperHandoffOriginalV1 {
    phase: Phase,
    auth: InitialHelperAuthOriginalV1,
    nv: InitialHelperNvOriginalV1,
    finish: InitialHelperFinishOriginalV1,
    cleanup: InitialHelperCleanupOriginalV1,
    entropy: [RetainedKernelNonceOriginalV1; 2],
    nonce: Option<[u8; 32]>,
    hello: Option<Result<Zeroizing<[u8; HELLO_BYTES]>, TpmHelperFrameErrorV2>>,
    readiness: [SeqpacketReadinessOriginalV1; 2],
    sent: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: SeqpacketSendAfterOriginalV1,
    send_post: Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
    received: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    clocks: [Option<Timespec>; 5],
    proc_posts: [PidFdProcOriginalsV1; 4],
    subject: HelperRecordSubjectOriginalV1,
    ack: Option<Result<(), TpmHelperFrameErrorV2>>,
}

impl InitialHelperHandoffOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            phase: Phase::Fresh,
            auth: InitialHelperAuthOriginalV1::new(),
            nv: InitialHelperNvOriginalV1::new(),
            finish: InitialHelperFinishOriginalV1::new(),
            cleanup: InitialHelperCleanupOriginalV1::new(),
            entropy: std::array::from_fn(|_| RetainedKernelNonceOriginalV1::new()),
            nonce: None,
            hello: None,
            readiness: std::array::from_fn(|_| SeqpacketReadinessOriginalV1::new()),
            sent: None,
            send_after: SeqpacketSendAfterOriginalV1::new(),
            send_post: None,
            received: None,
            clocks: [None; 5],
            proc_posts: std::array::from_fn(|_| PidFdProcOriginalsV1::new()),
            subject: HelperRecordSubjectOriginalV1::new(),
            ack: None,
        }
    }

    pub(super) fn receiving_bytes_v1() -> Option<usize> {
        let (receive, _) =
            SeqpacketSocket::closed_zero_rights_receive_obligations_v1(LOCK_ACK_BYTES)?;
        receive
            .checked_add(PidFdProcOriginalsV1::receiving_bytes_v1()?.checked_mul(4)?)?
            .checked_add(8192)?
            .checked_add(InitialHelperAuthOriginalV1::receiving_bytes_v1()?)?
            .checked_add(InitialHelperNvOriginalV1::receiving_bytes_v1()?)?
            .checked_add(InitialHelperFinishOriginalV1::receiving_bytes_v1()?)?
            .checked_add(InitialHelperCleanupOriginalV1::receiving_bytes_v1()?)
    }

    pub(super) fn receiving_files_v1() -> Option<usize> {
        // The ACK installs three parent-side native descriptions; HELLO also
        // installs the two borrowed lock descriptions in the actual child.
        SeqpacketSocket::closed_zero_rights_receive_obligations_v1(LOCK_ACK_BYTES)?
            .1
            .checked_add(2)?
            .checked_add(InitialHelperNvOriginalV1::receiving_files_v1()?)
    }

    pub(super) fn traffic_bytes_v1() -> Option<usize> {
        // Two actual stat/context posts bracket HELLO and ACK. The existing
        // receive engine previews and consumes the same bounded ACK record.
        // Both retained nonce halves allow at most nine complete fills.
        PidFdProcOriginalsV1::stat_maximum_requested_read_bytes_v1()?
            .checked_add(PidFdProcOriginalsV1::context_maximum_requested_read_bytes_v1()?)?
            .checked_mul(2)?
            .checked_add(9 * 32)?
            .checked_add(HELLO_BYTES)?
            .checked_add(LOCK_ACK_BYTES.checked_mul(2)?)?
            .checked_add(InitialHelperAuthOriginalV1::traffic_bytes_v1()?)?
            .checked_add(InitialHelperNvOriginalV1::traffic_bytes_v1()?)?
            .checked_add(InitialHelperFinishOriginalV1::traffic_bytes_v1()?)
    }

    fn sample(&mut self, index: usize, cut: FixedProcessBoottimeCutV1) -> bool {
        self.clocks[index] = Some(clock_gettime(ClockId::Boottime));
        self.clocks[index]
            .and_then(nanoseconds)
            .is_some_and(|now| now < cut.exclusive_nanoseconds())
    }
}

struct HelperRecordSubjectOriginalV1 {
    entered: bool,
    info: [Option<Result<PidFdInfo, LinuxError>>; 2],
    alive: Option<Result<bool, LinuxError>>,
}

impl HelperRecordSubjectOriginalV1 {
    fn new() -> Self {
        Self {
            entered: false,
            info: std::array::from_fn(|_| None),
            alive: None,
        }
    }

    fn observe_once(
        &mut self,
        record: &ReceivedRecord,
        child: &aos_linux_descriptors::pidfd::PidFd,
        expected_pid: u32,
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        if std::mem::replace(&mut self.entered, true) {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        let subject = record.subject();
        let credentials = subject.credentials();
        self.info[0] = Some(subject.pidfd().info());
        self.info[1] = Some(child.info());
        self.alive = Some(subject.is_alive());
        if credentials.pid().get() != expected_pid
            || credentials.uid() != 0
            || credentials.gid() != 0
            || !matches!((&self.info[0], &self.info[1]), (Some(Ok(a)), Some(Ok(b))) if a == b)
            || !matches!(self.alive, Some(Ok(true)))
        {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        Ok(())
    }
}

impl InitialTpmHelperDrivingLoanV1<'_> {
    /// Prepares public HELLO from actual lock and provisioning comparison DATA.
    ///
    /// The image's closed initial purpose must match the endpoint. The same
    /// retained child is reobserved before nonce generation. This sends nothing;
    /// the Source separately checks currentness before each subsequent native IO.
    ///
    /// # Errors
    /// Refuses missing original birth, reentry, crossed purpose, changed child,
    /// native entropy failure or invalid public provisioning/lock DATA.
    pub fn prepare_hello_once_v1(
        &mut self,
        endpoint: FixedTpmEndpointV2,
        salt_name: [u8; 34],
        locks: [(u64, u64, u32); 2],
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::Fresh)?;
            self.handoff.phase = Phase::Preparing;
            if !matches!(
                (self.image.purpose_data_v1(), endpoint),
                (
                    FixedTpmHelperPurposeV1::InitialController,
                    FixedTpmEndpointV2::ControllerStorageClient
                ) | (
                    FixedTpmHelperPurposeV1::InitialStorage,
                    FixedTpmEndpointV2::StorageBroker
                )
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.observe_child(ChildPostV1::BeforeHello)?;
            let mut nonce = [0; 32];
            nonce[..16].copy_from_slice(
                &self.handoff.entropy[0]
                    .observe_once()
                    .map_err(|_| InitialTpmHelperBirthClosedV1)?,
            );
            nonce[16..].copy_from_slice(
                &self.handoff.entropy[1]
                    .observe_once()
                    .map_err(|_| InitialTpmHelperBirthClosedV1)?,
            );
            self.handoff.nonce = Some(nonce);
            self.handoff.hello = Some(encode_hello_v2(endpoint, nonce, salt_name, locks));
            if !matches!(self.handoff.hello, Some(Ok(_))) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::Prepared;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Waits once for HELLO send readiness under the original child's deadline.
    ///
    /// # Errors
    /// Retains timeout, poll or unexpected-event refusal; rejects wrong phase.
    pub fn wait_hello_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::Prepared)?;
            let fd = self
                .channel
                .as_fd()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?;
            if !self.handoff.readiness[0].observe(
                fd,
                PollFlags::OUT,
                self.cut.exclusive_nanoseconds(),
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::SendReady;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Sends the original HELLO with exactly two borrowed lock descriptions once.
    ///
    /// The enclosing Source supplies its held descriptions after readiness and
    /// its own currentness check. Errors preserve the actual sending socket.
    ///
    /// # Errors
    /// Refuses wrong phase, elapsed deadline or native descriptor send failure.
    pub fn send_hello_once_v1(
        &mut self,
        locks: [BorrowedFd<'_>; 2],
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::SendReady)?;
            self.handoff.phase = Phase::Sending;
            if !self.handoff.sample(0, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            let bytes = self
                .handoff
                .hello
                .as_ref()
                .and_then(|hello| hello.as_ref().ok())
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            self.handoff.sent = Some(
                self.channel
                    .send_with_descriptors_retaining_v1(bytes.as_ref(), &locks),
            );
            self.handoff.send_post = Some(
                self.handoff.send_after.observe_once_v1(
                    self.channel,
                    self.handoff
                        .sent
                        .as_ref()
                        .and_then(|sent| sent.as_ref().err()),
                ),
            );
            let after = self.handoff.sample(1, self.cut);
            if !matches!(self.handoff.sent, Some(Ok(())))
                || !matches!(self.handoff.send_post, Some(Ok(())))
                || !after
            {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::HelloSent;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Waits once for the original helper's ACK before the same absolute cut.
    ///
    /// # Errors
    /// Retains timeout, poll or unexpected-event refusal; rejects wrong phase.
    pub fn wait_ack_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::HelloSent)?;
            let fd = self
                .channel
                .as_fd()
                .map_err(|_| InitialTpmHelperBirthClosedV1)?;
            if !self.handoff.readiness[1].observe(
                fd,
                PollFlags::IN,
                self.cut.exclusive_nanoseconds(),
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::AckReady;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    /// Receives and retains the zero-rights ACK before admitting its actual subject.
    ///
    /// Kernel credentials, both pidfd observations, liveness and the original
    /// child's held stat/context must agree. No maps are reread after the fixed
    /// helper becomes nondumpable. Canonical framing binds its nonce and locks.
    ///
    /// # Errors
    /// Retains malformed native/record prefixes, crossed or dead subject,
    /// changed child, bad ACK, elapsed deadline or wrong phase. No auth is sent.
    pub fn receive_ack_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::AckReady)?;
            self.handoff.phase = Phase::Receiving;
            self.channel
                .zero_rights_receive_obligations_v1(LOCK_ACK_BYTES)
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            if !self.handoff.sample(2, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.received = Some(
                self.channel
                    .receive_storage_preparation_retaining_v1(LOCK_ACK_BYTES),
            );
            let after = self.handoff.sample(3, self.cut);
            let record = self
                .handoff
                .received
                .as_ref()
                .and_then(|received| received.as_ref().ok())
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            if !after {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            let (child, _) = self
                .driving
                .original_child()
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            self.handoff.subject.observe_once(
                record,
                child,
                self.identity.ok_or(InitialTpmHelperBirthClosedV1)?.pid(),
            )?;
            self.handoff.ack = Some(require_lock_ack_v2(
                record.payload(),
                self.handoff.nonce.ok_or(InitialTpmHelperBirthClosedV1)?,
            ));
            if !matches!(self.handoff.ack, Some(Ok(()))) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.observe_child(ChildPostV1::AfterAck)?;
            if !self.handoff.sample(4, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.handoff.phase = Phase::Acknowledged;
            Ok(())
        })();
        self.retain_refusal(result)
    }

    fn require_phase(&self, expected: Phase) -> Result<(), InitialTpmHelperBirthClosedV1> {
        if self.first.is_none() && *self.measured && self.handoff.phase == expected {
            Ok(())
        } else {
            Err(InitialTpmHelperBirthClosedV1)
        }
    }

    fn observe_child(&mut self, phase: ChildPostV1) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let (originals, offset): (&mut [PidFdProcOriginalsV1], usize) = match phase {
            ChildPostV1::BeforeFinish => (&mut self.handoff.finish.child_posts, 0),
            ChildPostV1::BeforeHello => (&mut self.handoff.proc_posts, 0),
            ChildPostV1::AfterAck => (&mut self.handoff.proc_posts, 2),
            ChildPostV1::BeforeAuth => (&mut self.handoff.auth.child_posts, 0),
            ChildPostV1::AfterAuth => (&mut self.handoff.auth.child_posts, 2),
            ChildPostV1::NvBeforeSend(index) => (&mut self.handoff.nv.slots[index].child_posts, 0),
            ChildPostV1::NvAfterSend(index) => (&mut self.handoff.nv.slots[index].child_posts, 2),
            ChildPostV1::NvAfterReceive(index) => {
                (&mut self.handoff.nv.slots[index].child_posts, 4)
            }
        };
        let (child, _) = self
            .driving
            .original_child()
            .ok_or(InitialTpmHelperBirthClosedV1)?;
        let observations = self
            .observations
            .as_mut()
            .ok_or(InitialTpmHelperBirthClosedV1)?;
        let identity = observations
            .observe_identity_retaining_v1(child, &mut originals[offset])
            .map_err(|_| InitialTpmHelperBirthClosedV1)?;
        let context = observations
            .observe_context_retaining_v1(child, &mut originals[offset + 1])
            .map_err(|_| InitialTpmHelperBirthClosedV1)?;
        if Some(identity) != *self.identity
            || !context_matches(
                context,
                initial_context(self.image.purpose_data_v1())
                    .ok_or(InitialTpmHelperBirthClosedV1)?,
            )
        {
            return Err(InitialTpmHelperBirthClosedV1);
        }
        Ok(())
    }

    fn retain_refusal(
        &mut self,
        result: Result<(), InitialTpmHelperBirthClosedV1>,
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        if result.is_err() {
            self.first.get_or_insert(InitialTpmHelperBirthClosedV1);
        }
        result
    }
}

fn nanoseconds(sample: Timespec) -> Option<u64> {
    u64::try_from(sample.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(
            u64::try_from(sample.tv_nsec)
                .ok()
                .filter(|nanos| *nanos < 1_000_000_000)?,
        )
}

#[cfg(test)]
mod subject_tests {
    use super::*;
    use aos_linux_descriptors::pidfd::PidFd;
    use std::num::NonZeroU32;

    #[test]
    fn foreign_pid_refusal_retains_actual_record_and_pidfd_observations() {
        // This tests only the shared native subject comparison. Neither a
        // measured helper nor Source/approval authority is constructed.
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let pid = std::process::id();
        let held = PidFd::open(NonZeroU32::new(pid).unwrap()).unwrap();
        sender.send(b"subject comparison").unwrap();
        let record = receiver.receive(32).unwrap();
        let mut original = HelperRecordSubjectOriginalV1::new();

        assert!(
            original
                .observe_once(&record, &held, pid.checked_add(1).unwrap())
                .is_err()
        );

        let observed = *original.info[0].as_ref().unwrap().as_ref().unwrap();
        let held_info = *original.info[1].as_ref().unwrap().as_ref().unwrap();
        assert_eq!(observed, held_info);
        assert_eq!(observed.pid(), pid);
        assert!(matches!(original.alive, Some(Ok(true))));
        assert_eq!(record.payload(), b"subject comparison");

        assert!(original.observe_once(&record, &held, pid).is_err());

        assert_eq!(
            original.info[0].as_ref().unwrap().as_ref().unwrap(),
            &observed
        );
        assert_eq!(
            original.info[1].as_ref().unwrap().as_ref().unwrap(),
            &held_info
        );
        assert!(matches!(original.alive, Some(Ok(true))));
    }

    #[test]
    fn native_subject_comparison_requires_actual_root_credentials() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let pid = std::process::id();
        let held = PidFd::open(NonZeroU32::new(pid).unwrap()).unwrap();
        sender.send(b"root subject comparison").unwrap();
        let record = receiver.receive(32).unwrap();
        let credentials = record.subject().credentials();
        let expected = credentials.uid() == 0 && credentials.gid() == 0;
        let mut original = HelperRecordSubjectOriginalV1::new();

        assert_eq!(original.observe_once(&record, &held, pid).is_ok(), expected);

        assert!(original.entered);
        assert!(matches!(original.alive, Some(Ok(true))));
        assert_eq!(
            original.info[0].as_ref().unwrap().as_ref().unwrap(),
            original.info[1].as_ref().unwrap().as_ref().unwrap()
        );
    }
}
