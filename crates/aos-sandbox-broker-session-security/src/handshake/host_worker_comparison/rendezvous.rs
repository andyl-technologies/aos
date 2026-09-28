//! Fresh preparation exchange while the original Host and Mount owners remain held.
//!
//! ```text
//! AOSFWX02 | version2/method49/purpose56/Host1.0/RootMount5/zero-rights/phase |
//! original comparison binding | exact WorkerRendezvousChallengeV2
//! phase = READY(1), JOINED(2), CONFIRMED(3); SCM_RIGHTS is forbidden
//! AOSFWX03 | identical binding/zero-rights contract with version3 |
//! phase = START_INIT(4), IDMAP_APPLIED(5), PREPARATION_CONFIRMED(6)
//! ```
//!
//! Host's READY is sent only inside its actual post-copy-barrier live launch
//! callback. Mount independently receives and retains the original worker's
//! record subject, then Host repeats its physical/SID/invocation observations
//! around all rendezvous and kernel-only phases. The worker retains one C
//! session while Mount applies its original namespace's actual kernel idmap.
//! Nothing here mints a current read/Root guard or
//! reconstructs ownership from a frame, comparison FD, pidfd or historical row.

use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use aos_sandbox_protocol::fuse_worker_preparation::{
    WORKER_KERNEL_PREPARATION_BYTES_V3, WORKER_RENDEZVOUS_BYTES_V2,
    WorkerKernelPreparationPhaseV3 as KernelPhase, WorkerRendezvousChallengeV2,
};

use super::*;
use crate::dormant_handshake::DormantBrokerSessionHandshakeErrorV1 as RendezvousError;
use aos_sandbox_host::OriginalHostFuseWorkerTransportProgressV1 as Progress;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RendezvousStage {
    Pending,
    Ready,
    Joined,
    Confirmed,
    InitRequested,
    IdmapApplied,
    KernelConfirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    Ready = 1,
    Joined = 2,
    Confirmed = 3,
    StartInit = 4,
    IdmapApplied = 5,
    PreparationConfirmed = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlReceive {
    Received,
    Backpressure,
}

fn frame(
    binding: Binding,
    control: Control,
    challenge: &WorkerRendezvousChallengeV2,
    maximum: u32,
) -> Result<Vec<u8>, RendezvousError> {
    let (magic, version) = match control {
        Control::Ready | Control::Joined | Control::Confirmed => (b"AOSFWX02", 2),
        Control::StartInit | Control::IdmapApplied | Control::PreparationConfirmed => {
            (b"AOSFWX03", 3)
        }
    };
    let mut contract = [0, version, 0, 49, 0, 0, 0, 56, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0];
    contract[17] = control as u8;
    encode_profile(magic, &contract, binding, &challenge.encode(), maximum)
}

impl HeldOriginalHostWorkerComparisonV1<'_> {
    fn check_fresh(
        &mut self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<(), RendezvousError> {
        self.recheck()?;
        if self.stage != ReplyStage::Compared {
            return Err(RendezvousError::RemoteInvalid);
        }
        challenge
            .check_deadline(super::super::protected_boottime_nanoseconds()?)
            .map_err(|_| RendezvousError::RemoteInvalid)?;
        if let Some(original) = &self.fresh_challenge {
            if original != challenge {
                return Err(RendezvousError::RemoteInvalid);
            }
        } else {
            self.fresh_challenge = Some(challenge.clone());
        }
        Ok(())
    }

    fn send_control(
        &mut self,
        control: Control,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        self.check_fresh(challenge)?;
        let frame = frame(
            self.binding,
            control,
            challenge,
            self.request.maximum_response_bytes(),
        )?;
        let sent = self.session.send_response_packet(&frame);
        self.check_fresh(challenge)?;
        match sent {
            Ok(()) => Ok(Progress::Sent),
            Err(TransportError::Transport) => {
                self.wait(true)?;
                self.check_fresh(challenge)?;
                Ok(Progress::Backpressure)
            }
            Err(error) => {
                self.stage = ReplyStage::ReconciliationRequired;
                Err(error.into())
            }
        }
    }

    fn receive_control(
        &mut self,
        control: Control,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<ControlReceive, RendezvousError> {
        self.check_fresh(challenge)?;
        let expected = frame(
            self.binding,
            control,
            challenge,
            self.request.maximum_response_bytes(),
        )?;
        // This receiver verifies the actual per-record fixed service subject
        // on the original socket and rejects all rights before returning bytes.
        let received = self.session.receive_response_packet(expected.len());
        self.check_fresh(challenge)?;
        match received {
            Ok(received) if received == expected => Ok(ControlReceive::Received),
            Ok(_) => {
                self.stage = ReplyStage::ReconciliationRequired;
                Err(RendezvousError::RemoteInvalid)
            }
            Err(TransportError::Transport) => {
                self.wait(false)?;
                self.check_fresh(challenge)?;
                Ok(ControlReceive::Backpressure)
            }
            Err(error) => {
                self.stage = ReplyStage::ReconciliationRequired;
                Err(error.into())
            }
        }
    }

    pub(crate) fn send_rendezvous_ready(
        &mut self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        self.host_control(Control::Ready, challenge)
    }

    pub(crate) fn receive_rendezvous_joined(
        &mut self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        self.host_control(Control::Joined, challenge)
    }

    pub(crate) fn send_rendezvous_confirmed(
        &mut self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        self.host_control(Control::Confirmed, challenge)
    }

    pub(crate) fn send_kernel_init_start(
        &mut self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        self.host_control(Control::StartInit, challenge)
    }

    pub(crate) fn receive_kernel_idmap_applied(
        &mut self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        self.host_control(Control::IdmapApplied, challenge)
    }

    pub(crate) fn send_kernel_preparation_confirmed(
        &mut self,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        self.host_control(Control::PreparationConfirmed, challenge)
    }

    fn host_control(
        &mut self,
        control: Control,
        challenge: &WorkerRendezvousChallengeV2,
    ) -> Result<Progress, RendezvousError> {
        let (before, after) = match control {
            Control::Ready => (RendezvousStage::Pending, RendezvousStage::Ready),
            Control::Joined => (RendezvousStage::Ready, RendezvousStage::Joined),
            Control::Confirmed => (RendezvousStage::Joined, RendezvousStage::Confirmed),
            Control::StartInit => (RendezvousStage::Confirmed, RendezvousStage::InitRequested),
            Control::IdmapApplied => (
                RendezvousStage::InitRequested,
                RendezvousStage::IdmapApplied,
            ),
            Control::PreparationConfirmed => (
                RendezvousStage::IdmapApplied,
                RendezvousStage::KernelConfirmed,
            ),
        };
        let result = (|| {
            if self.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
                || self.rendezvous_stage != before
            {
                return Err(RendezvousError::RemoteInvalid);
            }
            let progress = if matches!(control, Control::Joined | Control::IdmapApplied) {
                match self.receive_control(control, challenge)? {
                    ControlReceive::Received => match control {
                        Control::Joined => Progress::RendezvousJoined,
                        _ => Progress::KernelIdmapApplied,
                    },
                    ControlReceive::Backpressure => Progress::Backpressure,
                }
            } else {
                self.send_control(control, challenge)?
            };
            if progress != Progress::Backpressure {
                self.rendezvous_stage = after;
            }
            Ok(progress)
        })();
        if result.is_err() {
            self.stage = ReplyStage::ReconciliationRequired;
        }
        result
    }

    /// Consumes the real original-channel reply before acknowledging the join.
    pub(crate) fn complete_mount_rendezvous<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
    ) -> Result<(), RendezvousError> {
        let result = self.mount_rendezvous(handoff, original, comparison);
        if result.is_err() {
            // The actual durable owners remain occupied; even an error before
            // receipt cannot establish that another channel copy did not send.
            self.stage = ReplyStage::ReconciliationRequired;
        }
        result
    }

    fn mount_rendezvous<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
    ) -> Result<(), RendezvousError> {
        if self.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || self.rendezvous_stage != RendezvousStage::Pending
            || self.stage != ReplyStage::Compared
        {
            return Err(RendezvousError::RemoteInvalid);
        }
        let ready = self.receive_ready(handoff, original)?;
        let subject = self.exchange_original_worker(handoff, original, comparison, &ready)?;
        self.confirm_worker_join(handoff, original, comparison, &ready, &subject)?;
        self.complete_mount_kernel_preparation(handoff, original, comparison, &ready, &subject)
    }

    fn receive_ready<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
    ) -> Result<WorkerRendezvousChallengeV2, RendezvousError> {
        loop {
            self.check_mount(handoff, original)?;
            let received = self
                .session
                .receive_response_packet(HEADER_BYTES + WORKER_RENDEZVOUS_BYTES_V2);
            self.check_mount(handoff, original)?;
            match received {
                Ok(received) => {
                    let body = received
                        .get(HEADER_BYTES..)
                        .ok_or(RendezvousError::RemoteInvalid)?;
                    let challenge = WorkerRendezvousChallengeV2::decode(
                        body,
                        handoff.plan(),
                        super::super::protected_boottime_nanoseconds()?,
                    )
                    .map_err(|_| RendezvousError::RemoteInvalid)?;
                    if received
                        != frame(
                            self.binding,
                            Control::Ready,
                            &challenge,
                            self.request.maximum_response_bytes(),
                        )?
                    {
                        return Err(RendezvousError::RemoteInvalid);
                    }
                    self.check_fresh(&challenge)?;
                    self.rendezvous_stage = RendezvousStage::Ready;
                    return Ok(challenge);
                }
                Err(TransportError::Transport) => self.wait(false)?,
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn exchange_original_worker<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
        ready: &WorkerRendezvousChallengeV2,
    ) -> Result<KernelAuthorizedRecordSubject, RendezvousError> {
        // The called sender moved and dropped its outgoing table; the Host
        // received/consumed that packet and emitted READY only after its actual
        // local/PID1 cleanup and uncached observations. This method neither
        // receives arbitrary endpoints nor infers absence from Option alone.
        loop {
            self.check_mount(handoff, original)?;
            self.check_fresh(ready)?;
            let sent = handoff
                .original_worker_channel()
                .map_err(|_| RendezvousError::RemoteInvalid)?
                .send(&ready.encode());
            self.check_mount(handoff, original)?;
            match sent {
                Ok(()) => break,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    self.wait_worker(handoff, original, true)?;
                }
                Err(_) => return Err(RendezvousError::RemoteInvalid),
            }
        }

        loop {
            self.check_mount(handoff, original)?;
            self.check_fresh(ready)?;
            let channel = handoff
                .original_worker_channel()
                .map_err(|_| RendezvousError::RemoteInvalid)?;
            let record = channel.receive(WORKER_RENDEZVOUS_BYTES_V2);
            match record {
                Ok(record) => {
                    // Connection peer and creation SID remain Mount. Bind the
                    // actual receiving socket, then use this record's subject.
                    let bound = channel
                        .bind_received(record)
                        .map_err(|_| RendezvousError::KernelEvidence)?;
                    ready
                        .compare_reply(
                            bound.payload(),
                            super::super::protected_boottime_nanoseconds()?,
                        )
                        .map_err(|_| RendezvousError::RemoteInvalid)?;
                    let (_, subject, _) = bound.into_parts();
                    comparison.recheck_record_subject(&subject)?;
                    self.check_mount(handoff, original)?;
                    return Ok(subject);
                }
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    self.wait_worker(handoff, original, false)?;
                }
                Err(_) => return Err(RendezvousError::RemoteInvalid),
            }
        }
    }

    fn confirm_worker_join<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
        ready: &WorkerRendezvousChallengeV2,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), RendezvousError> {
        loop {
            self.check_mount(handoff, original)?;
            comparison.recheck_record_subject(subject)?;
            if self.send_control(Control::Joined, ready)? == Progress::Sent {
                comparison.recheck_record_subject(subject)?;
                self.check_mount(handoff, original)?;
                self.rendezvous_stage = RendezvousStage::Joined;
                break;
            }
            comparison.recheck_record_subject(subject)?;
            self.check_mount(handoff, original)?;
        }
        loop {
            self.check_mount(handoff, original)?;
            comparison.recheck_record_subject(subject)?;
            if self.receive_control(Control::Confirmed, ready)? == ControlReceive::Received {
                self.rendezvous_stage = RendezvousStage::Confirmed;
                break;
            }
            comparison.recheck_record_subject(subject)?;
            self.check_mount(handoff, original)?;
        }
        comparison.recheck_record_subject(subject)?;
        self.check_mount(handoff, original)?;
        // Keep this actual subject for kernel-only preparation, never a grant.
        Ok(())
    }

    fn complete_mount_kernel_preparation<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
        challenge: &WorkerRendezvousChallengeV2,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), RendezvousError> {
        loop {
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            let received = self.receive_control(Control::StartInit, challenge)?;
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            if received == ControlReceive::Received {
                self.rendezvous_stage = RendezvousStage::InitRequested;
                break;
            }
        }
        self.send_worker_kernel_phase(
            handoff,
            original,
            comparison,
            challenge,
            subject,
            KernelPhase::StartInit,
        )?;
        self.receive_worker_kernel_phase(
            handoff,
            original,
            comparison,
            challenge,
            subject,
            KernelPhase::InitComplete,
        )?;

        // INIT_COMPLETE is not an initialized-connection proof. Only this
        // actual syscall on the original coowned mount/ns can complete idmap:
        // the kernel refuses SB_I_NOIDMAP unless real INIT negotiated support.
        self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
        handoff
            .apply_original_prepared_idmap()
            .map_err(|_| RendezvousError::RemoteInvalid)?;
        self.rendezvous_stage = RendezvousStage::IdmapApplied;
        self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
        self.send_worker_kernel_phase(
            handoff,
            original,
            comparison,
            challenge,
            subject,
            KernelPhase::IdmapComplete,
        )?;
        self.receive_worker_kernel_phase(
            handoff,
            original,
            comparison,
            challenge,
            subject,
            KernelPhase::SessionRetained,
        )?;

        // Host is still inside its original live/physical callback, waiting
        // for this distinct ACK. No backing, names, metadata or Root claim.
        loop {
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            let sent = self.send_control(Control::IdmapApplied, challenge)?;
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            if sent == Progress::Sent {
                break;
            }
        }
        loop {
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            let received = self.receive_control(Control::PreparationConfirmed, challenge)?;
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            if received == ControlReceive::Received {
                self.rendezvous_stage = RendezvousStage::KernelConfirmed;
                break;
            }
        }
        self.check_kernel_preparation(handoff, original, comparison, challenge, subject)
    }

    fn check_kernel_preparation<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
        challenge: &WorkerRendezvousChallengeV2,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), RendezvousError> {
        self.check_mount(handoff, original)?;
        self.check_fresh(challenge)?;
        comparison.recheck_record_subject(subject)?;
        if matches!(
            self.rendezvous_stage,
            RendezvousStage::IdmapApplied | RendezvousStage::KernelConfirmed
        ) {
            handoff
                .recheck_original_prepared_idmap()
                .map_err(|_| RendezvousError::RemoteInvalid)?;
        }
        self.check_mount(handoff, original)
    }

    fn send_worker_kernel_phase<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
        challenge: &WorkerRendezvousChallengeV2,
        subject: &KernelAuthorizedRecordSubject,
        phase: KernelPhase,
    ) -> Result<(), RendezvousError> {
        loop {
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            let sent = handoff
                .original_worker_channel()
                .map_err(|_| RendezvousError::RemoteInvalid)?
                .send(&phase.encode(challenge));
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            match sent {
                Ok(()) => return Ok(()),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    self.wait_worker(handoff, original, true)?;
                    self.check_kernel_preparation(
                        handoff, original, comparison, challenge, subject,
                    )?;
                }
                Err(_) => return Err(RendezvousError::RemoteInvalid),
            }
        }
    }

    fn receive_worker_kernel_phase<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        comparison: &OriginalHostWorkerComparisonV1,
        challenge: &WorkerRendezvousChallengeV2,
        subject: &KernelAuthorizedRecordSubject,
        phase: KernelPhase,
    ) -> Result<(), RendezvousError> {
        loop {
            self.check_kernel_preparation(handoff, original, comparison, challenge, subject)?;
            let channel = handoff
                .original_worker_channel()
                .map_err(|_| RendezvousError::RemoteInvalid)?;
            let received = channel.receive(WORKER_KERNEL_PREPARATION_BYTES_V3);
            match received {
                Ok(record) => {
                    let bound = channel
                        .bind_received(record)
                        .map_err(|_| RendezvousError::KernelEvidence)?;
                    phase
                        .compare(
                            bound.payload(),
                            challenge,
                            super::super::protected_boottime_nanoseconds()?,
                        )
                        .map_err(|_| RendezvousError::RemoteInvalid)?;
                    comparison.recheck_record_subject(bound.subject())?;
                    drop(bound);
                    return self.check_kernel_preparation(
                        handoff, original, comparison, challenge, subject,
                    );
                }
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    self.wait_worker(handoff, original, false)?;
                    self.check_kernel_preparation(
                        handoff, original, comparison, challenge, subject,
                    )?;
                }
                Err(_) => return Err(RendezvousError::RemoteInvalid),
            }
        }
    }

    fn check_mount<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
    ) -> Result<(), RendezvousError> {
        original.recheck()?;
        handoff
            .recheck()
            .map_err(|_| RendezvousError::RemoteInvalid)?;
        self.recheck()?;
        Ok(())
    }

    fn wait_worker<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
        write: bool,
    ) -> Result<(), RendezvousError> {
        self.check_mount(handoff, original)?;
        let fd = handoff
            .original_worker_channel()
            .map_err(|_| RendezvousError::RemoteInvalid)?
            .as_fd()
            .map_err(|_| RendezvousError::KernelEvidence)?;
        let waited = crate::dormant_handshake::wait_for_handshake_readiness(
            fd,
            write,
            self.binding.deadline,
        );
        self.check_mount(handoff, original)?;
        waited
    }
}

impl OriginalHostWorkerComparisonV1 {
    fn recheck_record_subject(
        &self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), RendezvousError> {
        let expected = self
            .process
            .info()
            .map_err(|_| RendezvousError::KernelEvidence)?;
        let observed = subject
            .pidfd()
            .info()
            .map_err(|_| RendezvousError::KernelEvidence)?;
        let credentials = expected
            .credentials()
            .ok_or(RendezvousError::KernelEvidence)?;
        let nominated = subject.credentials();
        if expected != observed
            || observed != subject.initial_info()
            || expected.pid() != nominated.pid().get()
            || expected.thread_group_id() != nominated.pid().get()
            || credentials.real_user_id() != nominated.uid()
            || credentials.effective_user_id() != nominated.uid()
            || credentials.real_group_id() != nominated.gid()
            || credentials.effective_group_id() != nominated.gid()
            || !self
                .process
                .is_alive()
                .map_err(|_| RendezvousError::KernelEvidence)?
            || !subject
                .is_alive()
                .map_err(|_| RendezvousError::KernelEvidence)?
            || self
                .process
                .info()
                .map_err(|_| RendezvousError::KernelEvidence)?
                != expected
            || subject
                .pidfd()
                .info()
                .map_err(|_| RendezvousError::KernelEvidence)?
                != expected
        {
            return Err(RendezvousError::KernelEvidence);
        }
        let anchor = self
            .cgroup
            .resolve(Path::new("."))
            .map_err(|_| RendezvousError::KernelEvidence)?;
        anchor
            .verify_exact_membership(&self.process)
            .map_err(|_| RendezvousError::KernelEvidence)?;
        anchor
            .verify_exact_membership(subject.pidfd())
            .map_err(|_| RendezvousError::KernelEvidence)?;
        if self
            .process
            .info()
            .map_err(|_| RendezvousError::KernelEvidence)?
            != expected
            || subject
                .pidfd()
                .info()
                .map_err(|_| RendezvousError::KernelEvidence)?
                != expected
            || !subject
                .is_alive()
                .map_err(|_| RendezvousError::KernelEvidence)?
        {
            return Err(RendezvousError::KernelEvidence);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_protocol::fuse_worker_preparation::WorkerPreparationPlanV1;

    use super::*;

    fn challenge() -> WorkerRendezvousChallengeV2 {
        // Structural fixture only, not a held Mount plan or worker issuer.
        let plan = WorkerPreparationPlanV1 {
            worker_instance: [1; 16],
            kernel_boot: [2; 16],
            challenge: [3; 32],
            controller_request: [4; 32],
            mount_reservation: [5; 32],
            assignment: [6; 32],
            attachment: [7; 32],
            original_view_descriptor: [8; 32],
            resolved_policy_descriptor: [9; 32],
            mount_slot: [10; 32],
            ownership_lease: [11; 16],
            ownership_lease_expires_boottime_ns: 300,
            preparation_deadline_boottime_ns: 100,
        };
        WorkerRendezvousChallengeV2::new(&plan, [12; 32]).unwrap()
    }

    #[test]
    fn zero_rights_controls_are_distinct_from_original_comparison_and_each_phase() {
        let challenge = challenge();
        let binding = super::super::tests::binding();
        let ready = frame(binding, Control::Ready, &challenge, 4096).unwrap();

        assert_eq!(ready.len(), HEADER_BYTES + WORKER_RENDEZVOUS_BYTES_V2);
        assert_eq!(&ready[..8], b"AOSFWX02");
        assert_eq!(&ready[22..25], &[0, 0, 0]);
        assert_eq!(ready[25], Control::Ready as u8);
        assert!(decode(&ready, binding, 4096).is_err());
        for phase in [Control::Joined, Control::Confirmed] {
            assert_ne!(ready, frame(binding, phase, &challenge, 4096).unwrap());
        }
        let old = encode(binding, &challenge.encode(), 4096).unwrap();
        assert_ne!(ready, old);
    }

    #[test]
    fn every_binding_role_and_length_substitution_changes_the_exact_control() {
        let challenge = challenge();
        let binding = super::super::tests::binding();
        let ready = frame(binding, Control::Ready, &challenge, 4096).unwrap();

        for index in [0, 8, 11, 15, 17, 21, 23, 25, 33, 34, 50, 82, 114, 149, 190] {
            let mut substituted = ready.clone();
            substituted[index] ^= 1;
            assert_ne!(
                substituted,
                frame(binding, Control::Ready, &challenge, 4096).unwrap()
            );
        }
        assert!(
            frame(
                binding,
                Control::Ready,
                &challenge,
                (ready.len() - 1) as u32
            )
            .is_err()
        );
        let mut appended = ready.clone();
        appended.push(0);
        assert_ne!(appended, ready);
        assert_ne!(&ready[..ready.len() - 1], ready.as_slice());
    }

    #[test]
    fn kernel_controls_have_a_distinct_version_and_preserve_original_binding() {
        let challenge = challenge();
        let binding = super::super::tests::binding();
        let old = frame(binding, Control::Ready, &challenge, 4096).unwrap();
        for control in [
            Control::StartInit,
            Control::IdmapApplied,
            Control::PreparationConfirmed,
        ] {
            let exact = frame(binding, control, &challenge, 4096).unwrap();
            assert_eq!(&exact[..8], b"AOSFWX03");
            assert_eq!(&exact[8..10], &[0, 3]);
            assert_eq!(&exact[22..25], &[0, 0, 0]);
            assert_eq!(&exact[26..150], &old[26..150]);
            assert_ne!(exact, old);
            assert!(decode(&exact, binding, 4096).is_err());
            for offset in [0, 9, 11, 15, 17, 21, 23, 25, 33, 50, 82, 114, 149, 190] {
                let mut changed = exact.clone();
                changed[offset] ^= 1;
                assert_ne!(changed, exact, "offset {offset}");
            }
            for other in [
                Control::StartInit,
                Control::IdmapApplied,
                Control::PreparationConfirmed,
            ] {
                if other != control {
                    assert_ne!(exact, frame(binding, other, &challenge, 4096).unwrap());
                }
            }
        }
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_tests {
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::num::NonZeroU32;
    use std::os::fd::AsFd as _;
    use std::process::{Child, Command, Stdio};

    use aos_sandbox_linux::seqpacket::SeqpacketSocket;

    use super::*;

    const FIXTURE_ENV: &str = "AOS_FUSE_RENDEZVOUS_FOREIGN_RECORD_FIXTURE_V2";

    struct Fixture(Child);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn foreign_worker_fixture() {
        if std::env::var_os(FIXTURE_ENV).is_none() {
            return;
        }
        // No raw FD adoption or fork-from-test-harness boundary is added.
        // The child writes the inherited endpoint and stays alive until the
        // parent consumes its actual kernel record subject.
        std::io::stdout().write_all(b"foreign-worker").unwrap();
        std::io::stdout().flush().unwrap();
        let mut release = [0];
        let _ = std::io::stdin().read(&mut release);
    }

    #[test]
    fn actual_record_subject_cannot_be_replaced_by_the_socket_creation_peer() {
        let (mut channel, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let process = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let expected = OriginalHostWorkerComparisonV1 {
            body: Vec::new(),
            process,
            cgroup: CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").unwrap().into()).unwrap(),
        };
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "handshake::host_worker_comparison::rendezvous::kernel_tests::foreign_worker_fixture",
                "--nocapture",
            ])
            .env(FIXTURE_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::from(endpoint))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let child = Fixture(child);
        let deadline =
            super::super::super::protected_boottime_nanoseconds().unwrap() + 10_000_000_000;
        let record = loop {
            match channel.receive(512) {
                Ok(record) => break record,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        channel.as_fd().unwrap(),
                        false,
                        deadline,
                    )
                    .unwrap();
                }
                Err(error) => panic!("foreign worker receive: {error}"),
            }
        };
        let bound = channel.bind_received(record).unwrap();

        assert_eq!(bound.peer().credentials().pid().get(), std::process::id());
        assert_eq!(bound.subject().credentials().pid().get(), child.0.id());
        assert!(bound.subject().is_alive().unwrap());
        assert!(expected.recheck_record_subject(bound.subject()).is_err());
        assert!(bound.subject().is_alive().unwrap());
        // This proves only actual foreign-subject rejection. A full valid
        // worker/current-cgroup/Host-SID joint owner fixture is still required.
    }

    #[test]
    fn preparation_channel_refuses_rights_and_revokes_the_same_endpoint() {
        let (mut channel, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let unwanted = File::open("/dev/null").unwrap();
        sender
            .send_with_descriptors(b"not-zero-rights", &[unwanted.as_fd()])
            .unwrap();

        assert!(matches!(
            channel.receive(512),
            Err(SeqpacketError::Ancillary(_))
        ));
        assert!(matches!(channel.as_fd(), Err(SeqpacketError::Closed)));
    }
}
