//! Holds the actual PID1 launch through same-writer Bank publication and ACK/Confirm.
//!
//! The private constructor consumes only the paired startup's real channel.
//! Preparing an Offer never lends a role: actual typed mutation, native append,
//! per-record index, publication/readback and all independent posts must complete
//! on this SAME fixed writer before PID1 confirms its retained ACK.
//!
//! ```text
//! common = AOSRCO02 || phase:u8 || kind:u8 || reserved[6] || ordinal:u64be
//! offer = common || producer[16] || confirmed-predecessor[16] || recipient[16]
//!         || cgroup-device:u64be || cgroup-inode:u64be || nonces[32] || cutoff:u64be
//! ack-or-confirm = common || offer-digest[32] || mutation-digest[32]
//!                  || transaction[16] || recipient[16] || reserved[8]
//! suffix = range-commitment[32] || physical-donor[16] || confirmed-ordinal:u64be
//! packet = (offer | ack-or-confirm) || suffix  // exactly 184 bytes
//! ```
//!
//! Phase is Offer1, ACK2 or Confirm3; kind is Initial1 or Successor2. Initial
//! no-recovery launches use a zero suffix and cannot launch a successor. V11
//! range entry requires the sealed 192-byte AOSRSE03 delivery and exact policy
//! commitment. PID1 enables the range only after the initial durable bank seal
//! and actual ACK/Confirm posts, then consumes each ordinal before child growth.
//!
//! A successor's donated PIDFD names the actual latest physical donor, which
//! may have died before ACK. The confirmed floor remains separate. Only the
//! same retained PID1 owner can establish the intervening death, manager reap,
//! Empty and closure cuts. The exact bank CAS may advance from a committed row
//! above that floor without fabricating confirmation for an unconfirmed attempt.
//! Each consumed allowance and cumulative parent M debt remain charged; neither
//! EOF, a historical row nor this decoder refunds credit or renews an old D.

use std::cell::OnceCell;
use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Arc;

use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{
    RetainedSeqpacketAdmissionErrorV1, RetainedSeqpacketReceiveErrorV1,
    RetainedSeqpacketSendErrorV1, SeqpacketSocket,
    descriptor_subject::ReceivedDescriptorRecord,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, RecipientSuccessorMutation};
use rustix::event::{PollFd, PollFlags, Timespec};
use sha2::{Digest as _, Sha256};

use crate::controller_receiving::{ControllerReceivingOriginalV1, ControllerLaunchReceivingShapeV1};
use crate::controller_receiving::profile::{ControllerSelfProfileOriginalV1, ControllerProfileErrorV1};
use crate::receiving::OriginalEnrollment;
use super::append::ControllerDurableAppendReceiptV1;
use super::coordinator::ControllerCoordinatorWriterV1;
use super::mutation::EnrollmentTransitionV1;
use super::writer::{ControllerFixedWriterOriginalV1, ControllerWriterNameSampleV1};
use super::ControllerBankLaunchErrorV1;

mod completed_native;
use completed_native::CompletedLaunchNativeV1;

type State = std::collections::BTreeMap<(aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>>;
const PACKET_BYTES: usize = 184;
const MAGIC: &[u8; 8] = b"AOSRCO02";
const OFFER: u8 = 1;
const ACK: u8 = 2;
const CONFIRM: u8 = 3;
const COLD_INTERVAL_NANOSECONDS: u64 = 30_000_000_000;

#[derive(Clone, Copy, Eq, PartialEq)]
enum LaunchKind {
    Initial,
    Successor,
}

#[derive(Clone, Copy)]
struct Offer {
    kind: LaunchKind,
    cutoff: u64,
    generation: u64,
    predecessor: [u8; 16],
    recipient: [u8; 16],
    digest: [u8; 32],
    range: [u8; 32],
    donor: [u8; 16],
    confirmed_ordinal: u64,
}

#[derive(Clone, Copy)]
enum Failure {
    Closed,
    Funding,
    Deadline,
    CurrentPidfd,
    Channel,
    OfferPoll,
    OfferReceive,
    OfferShape,
    NamesBefore,
    Preparation,
    SemanticGate,
    Crossing,
    Kernel(usize),
    Native,
    Readback,
    NamesAfter,
    ProfileAfter,
    Ack,
    AckSend,
    ConfirmPoll,
    ConfirmReceive,
    ConfirmShape,
    NamesFinal,
    ProfileFinal,
    NativeDisposal,
}

struct PollObservation {
    result: Result<usize, rustix::io::Errno>,
    events: PollFlags,
}

struct KernelPost {
    peer_info: Result<PidFdInfo, aos_sandbox_linux::Error>,
    peer_alive: Result<bool, aos_sandbox_linux::Error>,
    subject_alive: Result<bool, aos_sandbox_linux::Error>,
    old_death: PollObservation,
    offered_stat: Result<rustix::fs::Stat, rustix::io::Errno>,
    clock: Option<Result<u64, ControllerBankLaunchErrorV1>>,
    shape: Result<(), ControllerBankLaunchErrorV1>,
}

struct ConfirmDescriptors {
    offered: Result<rustix::fs::Stat, rustix::io::Errno>,
    confirmed: Result<rustix::fs::Stat, rustix::io::Errno>,
    death: PollObservation,
    binding: Result<(), ControllerBankLaunchErrorV1>,
}

impl ConfirmDescriptors {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.offered.as_ref().err().map(|cause| cause as _)
            .or_else(|| self.confirmed.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.death.result.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.binding.as_ref().err().map(|cause| cause as _))
    }
}

impl KernelPost {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.peer_info.as_ref().err().map(|cause| cause as _)
            .or_else(|| self.peer_alive.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.subject_alive.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.old_death.result.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.offered_stat.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.clock.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.shape.as_ref().err().map(|cause| cause as _))
    }
}

enum LaunchMutation {
    Initial(EnrollmentTransitionV1),
    Successor(RecipientSuccessorMutation),
}

impl LaunchMutation {
    fn require_exact(&self, state: &State, transaction: &JournalTransaction)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        match self {
            Self::Initial(initial) => initial.require_exact(state, transaction),
            Self::Successor(successor) => Ok(successor.require_exact(state, transaction)?),
        }
    }

    fn require_returned<P>(&self, writer: &ControllerFixedWriterOriginalV1<P>)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        match self {
            Self::Initial(initial) => initial.require_returned(writer),
            Self::Successor(successor) => Ok(successor.require_returned_rows(writer.bank_state_v1()?)?),
        }
    }

    fn commitment(&self, transaction: &JournalTransaction)
        -> Result<[u8; 32], ControllerBankLaunchErrorV1>
    {
        match self {
            Self::Initial(_) => Ok(bank::transaction_digest(transaction)?),
            Self::Successor(successor) => Ok(successor.row().commitment()?),
        }
    }
}

struct PreparedBankMutation {
    mutation: LaunchMutation,
    transaction: JournalTransaction,
    head: u64,
}

/// Lends the SAME private launch preparation to its trusted semantic coordinator.
///
/// No public constructor or success flag exists. Transaction bytes remain DATA;
/// actual lower publication/readback and ACK/Confirm are separately mandatory.
pub struct ControllerPreparedBankMutationV1 {
    prepared: Arc<PreparedBankMutation>,
}

impl ControllerPreparedBankMutationV1 {
    /// Borrows the actual closed Bank transaction without reconstructing it.
    pub fn transaction(&self) -> &JournalTransaction {
        &self.prepared.transaction
    }
}

/// Retains one actual startup channel and every reached native launch result.
///
/// The genuine paired Startup owns this object. It cannot be constructed from
/// a caller FD, decoded Offer, durable map, receipt DATA or success Boolean.
pub struct ControllerBankLaunchOriginalV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    raw: Option<OwnedFd>,
    funding: Option<Result<(), ControllerBankLaunchErrorV1>>,
    deadline_result: Option<Result<u64, ControllerBankLaunchErrorV1>>,
    current_pidfd: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    channel: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    offer_poll: Option<Result<PollObservation, ControllerBankLaunchErrorV1>>,
    offer_receive: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    offer: Option<Result<Offer, ControllerBankLaunchErrorV1>>,
    names_before: ControllerWriterNameSampleV1,
    prepared: Option<Result<Arc<PreparedBankMutation>, ControllerBankLaunchErrorV1>>,
    kernels: [OnceCell<KernelPost>; 4],
    semantic_gate_failure: OnceCell<ControllerBankLaunchErrorV1>,
    crossing: OnceCell<Result<(), ControllerBankLaunchErrorV1>>,
    native: Option<Result<Arc<ControllerDurableAppendReceiptV1>, ControllerBankLaunchErrorV1>>,
    readback: Option<Result<(), ControllerBankLaunchErrorV1>>,
    names_after: ControllerWriterNameSampleV1,
    names_after_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    profile_after: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    profile_after_binding: Option<Result<(), ControllerBankLaunchErrorV1>>,
    ack: Option<Result<[u8; PACKET_BYTES], ControllerBankLaunchErrorV1>>,
    ack_send: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    confirm_poll: Option<Result<PollObservation, ControllerBankLaunchErrorV1>>,
    confirm_receive: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    confirm_descriptors: OnceCell<ConfirmDescriptors>,
    confirm_shape: Option<Result<(), ControllerBankLaunchErrorV1>>,
    confirmation: Option<Result<(), ControllerBankLaunchErrorV1>>,
    native_disposal: Option<Result<CompletedLaunchNativeV1, ControllerBankLaunchErrorV1>>,
    names_final: ControllerWriterNameSampleV1,
    names_final_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    profile_final: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    profile_final_binding: Option<Result<(), ControllerBankLaunchErrorV1>>,
    process: u32,
    deadline: Option<u64>,
    first: Option<Failure>,
    entered: bool,
    confirmed: bool,
}

impl ControllerBankLaunchOriginalV1 {
    pub(in crate::controller_receiving) fn from_paired_startup(
        original: Arc<ControllerReceivingOriginalV1>, raw: OwnedFd,
    ) -> Self {
        Self {
            original, raw: Some(raw), funding: None, deadline_result: None,
            current_pidfd: None, channel: None, offer_poll: None,
            offer_receive: None, offer: None, names_before: ControllerWriterNameSampleV1::new(),
            prepared: None, kernels: std::array::from_fn(|_| OnceCell::new()),
            semantic_gate_failure: OnceCell::new(), crossing: OnceCell::new(), native: None,
            readback: None, names_after: ControllerWriterNameSampleV1::new(),
            names_after_result: None, profile_after: None, profile_after_binding: None,
            ack: None, ack_send: None, confirm_poll: None, confirm_receive: None,
            confirm_descriptors: OnceCell::new(), confirm_shape: None, confirmation: None, native_disposal: None,
            names_final: ControllerWriterNameSampleV1::new(), names_final_result: None,
            profile_final: None, profile_final_binding: None, process: std::process::id(),
            deadline: None, first: None, entered: false, confirmed: false,
        }
    }

    fn socket(&self) -> Result<&SeqpacketSocket, ControllerBankLaunchErrorV1> {
        self.channel.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)
    }

    fn socket_mut(&mut self) -> Result<&mut SeqpacketSocket, ControllerBankLaunchErrorV1> {
        self.channel.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)
    }

    fn stop(&mut self, site: Failure) -> ControllerBankLaunchErrorV1 {
        self.first.get_or_insert(site);
        ControllerBankLaunchErrorV1::Conflict
    }

    fn now() -> Result<u64, ControllerBankLaunchErrorV1> {
        let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        u64::try_from(time.tv_sec).ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|nanos| u64::try_from(time.tv_nsec).ok().and_then(|part| nanos.checked_add(part)))
            .ok_or(ControllerBankLaunchErrorV1::Conflict)
    }

    fn wait_once(&self) -> Result<PollObservation, ControllerBankLaunchErrorV1> {
        let remaining = self.deadline.ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .checked_sub(Self::now()?).filter(|remaining| *remaining > 0)
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let descriptor = self.socket()?.as_fd()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let mut poll = [PollFd::new(&descriptor, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: (remaining / 1_000_000_000) as _,
            tv_nsec: (remaining % 1_000_000_000) as _,
        };
        let result = rustix::event::poll(&mut poll, Some(&timeout));
        Ok(PollObservation { result, events: poll[0].revents() })
    }

    fn decode_offer(&self, enrollment: OriginalEnrollment) -> Result<Offer, ControllerBankLaunchErrorV1> {
        let record = self.offer_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let bytes = record.payload();
        let socket = self.socket()?;
        let peer = socket.peer();
        let subject = record.subject();
        let credentials = subject.credentials();
        if bytes.len() != PACKET_BYTES || &bytes[..8] != MAGIC || bytes[8] != OFFER
            || !matches!(bytes[9], 1 | 2) || bytes[10..16] != [0; 6]
            || record.descriptors().len() != 1
            || peer.credentials().pid().get() != 1 || peer.credentials().uid() != 0
            || peer.credentials().gid() != 0 || peer.initial_info().pid() != 1
            || credentials.pid().get() != 1 || credentials.uid() != 0 || credentials.gid() != 0
            || subject.initial_info() != peer.initial_info()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let generation = read_u64(&bytes[16..24])?;
        let predecessor = fixed::<16>(&bytes[40..56])?;
        let recipient = fixed::<16>(&bytes[56..72])?;
        let kind = match bytes[9] {
            1 if generation == 0 && predecessor == [0; 16] => LaunchKind::Initial,
            2 if generation > 0 && predecessor != [0; 16] && predecessor != recipient => LaunchKind::Successor,
            _ => return Err(ControllerBankLaunchErrorV1::Conflict),
        };
        let range = fixed::<32>(&bytes[128..160])?;
        let donor = fixed::<16>(&bytes[160..176])?;
        let confirmed_ordinal = read_u64(&bytes[176..184])?;
        if enrollment.policy.bootstrap_provisions().controller_recovery.is_some() {
            let (recipients, _) = enrollment.policy.controller_recovery_range_v1()
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            let expected = bank::controller_recipient_range_commitment_v1(enrollment.identity, enrollment.policy)?;
            if range != expected || enrollment.controller_range_commitment_v2 != Some(expected)
                || generation > recipients || confirmed_ordinal >= generation && kind == LaunchKind::Successor
                || (kind == LaunchKind::Initial && (donor != [0; 16] || confirmed_ordinal != 0))
                || (kind == LaunchKind::Successor && (donor == [0; 16] || donor == recipient))
            { return Err(ControllerBankLaunchErrorV1::Conflict); }
            require_same_controller_generation_v1(enrollment.controller_generation_v1, generation)?;
        } else if kind != LaunchKind::Initial || bytes[128..184] != [0; 56] {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let cutoff = read_u64(&bytes[120..128])?;
        if cutoff <= Self::now()? || bytes[24..40] != enrollment.identity.native_fields().invocation
            || recipient != enrollment.recipient_invocation || bytes[88..120] == [0; 32]
            || read_u64(&bytes[80..88])? == 0
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(Offer { kind, cutoff, generation, predecessor, recipient, digest: Sha256::digest(bytes).into(),
            range, donor, confirmed_ordinal })
    }

    fn observe_kernel(&self) -> Result<KernelPost, ControllerBankLaunchErrorV1> {
        let socket = self.socket()?;
        let record = self.offer_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let old = record.descriptors().first()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let peer_info = socket.peer().pidfd().info();
        let peer_alive = socket.peer().pidfd().is_alive();
        let subject_alive = record.subject().is_alive();
        let mut poll = [PollFd::new(old, PollFlags::IN)];
        let result = rustix::event::poll(&mut poll, Some(&Timespec { tv_sec: 0, tv_nsec: 0 }));
        let old_death = PollObservation { result, events: poll[0].revents() };
        let offered_stat = rustix::fs::fstat(old);
        let kind = self.offer.as_ref().and_then(|result| result.as_ref().ok())
            .map(|offer| offer.kind);
        let original_matches = match kind {
            Some(LaunchKind::Initial) => matches!(old_death.result, Ok(0))
                && old_death.events.is_empty()
                && match (&offered_stat, &self.current_pidfd) {
                    (Ok(offered), Some(Ok(current))) => offered.st_dev == current.st_dev
                        && offered.st_ino == current.st_ino,
                    _ => false,
                },
            Some(LaunchKind::Successor) => matches!(old_death.result, Ok(1))
                && old_death.events.contains(PollFlags::HUP),
            None => false,
        };
        // Keep the original short-circuit clock frontier, and retain its real
        // result if the preceding native identity checks reach it.
        let mut clock = None;
        let shape = if self.process == std::process::id()
            && peer_info.as_ref().is_ok_and(|value| *value == socket.peer().initial_info())
            && matches!(peer_alive, Ok(true)) && matches!(subject_alive, Ok(true))
            && original_matches
            && self.deadline.is_some_and(|deadline| {
                clock = Some(Self::now());
                clock.as_ref().is_some_and(|result| result.as_ref().is_ok_and(|now| *now < deadline))
            })
        {
            Ok(())
        } else {
            Err(ControllerBankLaunchErrorV1::Conflict)
        };
        Ok(KernelPost { peer_info, peer_alive, subject_alive, old_death, offered_stat, clock, shape })
    }

    fn kernel_once(&self, index: usize) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.kernels[index].get().is_none() {
            let post = self.observe_kernel()?;
            // This private synchronous initializer cannot reenter itself.
            let _ = self.kernels[index].set(post);
        }
        if self.kernels[index].get().is_some_and(|post| post.failure().is_none()) {
            Ok(())
        } else {
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }


    pub(in crate::controller_receiving) fn fixed_demand_v1()
        -> Result<aos_sandbox_core::ResourceVector, ControllerBankLaunchErrorV1>
    {
        let invalid = || ControllerBankLaunchErrorV1::Conflict;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<PreparedBankMutation>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .ok_or_else(invalid)?;
        let mut demand = ControllerLaunchReceivingShapeV1 { original_bytes: bytes }.fixed_demand_v1()?;
        // The three actual before/after/final samples retain distinct negative
        // native files and metadata. Existing launch FD slack is not credit.
        for _ in 0..3 {
            demand = demand.checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?;
        }
        // The delegated launch shape already pays the whole initial enrollment
        // recipe. The successor's archive/current builders are alternatives;
        // add only a positive excess over that same paid record plane.
        let record_bytes = (17 + bank::RECIPIENT_RANGE_INCARNATION_BYTES)
            .checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>())
            .and_then(|bytes| bytes.checked_mul(2 * 4))
            .ok_or_else(invalid)?;
        let record_bytes = record_bytes.saturating_sub(super::mutation::enrollment_record_bytes_v1()
            .ok_or_else(invalid)?)
            // These are the actual coexisting commitment helper destinations:
            // canonical enrollment, reusable vector buffer and hash state.
            .checked_add(std::mem::size_of::<([u8; 96], [u8; 176], Sha256)>())
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        demand = demand.checked_add(aos_sandbox_core::ResourceVector::ZERO
            .with(aos_sandbox_core::ResourceDimension::MemoryBytes, record_bytes))?;
        Ok(demand)
    }

    /// Prepares this actual launch's sole typed Bank transaction once.
    ///
    /// This stopping entry authenticates the real channel and old/current
    /// descriptor before preparing the same Protocol mutation. It grants no
    /// role operation: the native publication/readback and ACK/Confirm remain.
    ///
    /// # Errors
    /// Retains original accounting, poll, receive, subject, names and mutation
    /// causes. Reentry cannot recapture the channel or rearm a cold deadline.
    pub fn prepare_once<P>(
        &mut self,
        writer: &ControllerCoordinatorWriterV1<P>,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerPreparedBankMutationV1, ControllerBankLaunchErrorV1> {
        let writer = &writer.fixed;
        if self.entered {
            return Err(self.stop(Failure::Closed));
        }
        self.entered = true;
        if !writer.has_original(&self.original) || !profile.has_same_baseline_original(&self.original) {
            return Err(self.stop(Failure::Closed));
        }
        self.funding = Some(self.original.reserve_bank_launch_once());
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(self.stop(Failure::Funding));
        }
        // Arm the SAME held-name owed post before channel/native work. This
        // private entry observes nothing and creates no fresh health re-entry.
        if writer.begin_name_sample(&mut self.names_after).is_err() {
            return Err(self.stop(Failure::NamesAfter));
        }
        self.deadline_result = Some(Self::now().and_then(|now| now.checked_add(COLD_INTERVAL_NANOSECONDS)
            .ok_or(ControllerBankLaunchErrorV1::Conflict)));
        self.current_pidfd = Some(rustix::fs::fstat(profile.original_process().as_fd()));
        if let Some(Ok(deadline)) = self.deadline_result.as_ref() {
            self.deadline = Some(*deadline);
        }
        if self.deadline.is_none() {
            return Err(self.stop(Failure::Deadline));
        }
        if self.current_pidfd.as_ref().is_some_and(Result::is_err) {
            return Err(self.stop(Failure::CurrentPidfd));
        }
        let enrollment = self.original.writer_enrollment()?;
        let raw = self.raw.take().ok_or_else(|| self.stop(Failure::Closed))?;
        self.channel = Some(SeqpacketSocket::from_owned_retaining(raw));
        if self.channel.as_ref().is_none_or(Result::is_err) {
            return Err(self.stop(Failure::Channel));
        }
        self.offer_poll = Some(self.wait_once());
        if !self.offer_poll.as_ref().is_some_and(|result| result.as_ref().is_ok_and(ready)) {
            return Err(self.stop(Failure::OfferPoll));
        }
        let received = self.socket_mut()?.receive_pid1_controller_range_descriptor_retaining_v2();
        self.offer_receive = Some(received);
        if self.offer_receive.as_ref().is_none_or(Result::is_err) {
            return Err(self.stop(Failure::OfferReceive));
        }
        self.offer = Some(self.decode_offer(enrollment));
        let Some(Ok(offer)) = self.offer.as_ref() else {
            return Err(self.stop(Failure::OfferShape));
        };
        let offer = *offer;
        // The original PID1 cut can only shorten this local backstop.
        self.deadline = self.deadline.map(|local| local.min(offer.cutoff));
        if self.kernel_once(0).is_err() {
            return Err(self.stop(Failure::Kernel(0)));
        }
        if writer.begin_name_sample(&mut self.names_before).is_err()
            || writer.finish_owed_name_sample(&mut self.names_before).is_err()
        {
            return Err(self.stop(Failure::NamesBefore));
        }
        self.prepared = Some((|| {
            let (mutation, transaction) = match offer.kind {
                LaunchKind::Initial => {
                    let initial = EnrollmentTransitionV1::prepare(&enrollment, self.original.writer_native_layout())?;
                    let transaction = initial.transaction()?;
                    (LaunchMutation::Initial(initial), transaction)
                }
                LaunchKind::Successor => {
                    let successor = RecipientSuccessorMutation::new_range_v2(
                        writer.bank_state_v1()?, enrollment.identity, offer.recipient,
                        offer.generation, offer.range, offer.confirmed_ordinal,
                        offer.predecessor, offer.digest,
                    )?;
                    successor.row().require_policy_v1(enrollment.policy)?;
                    if enrollment.controller_generation_v1 != Some(offer.generation)
                        || successor.row().generation() != offer.generation {
                        return Err(ControllerBankLaunchErrorV1::Conflict);
                    }
                    let mut digest = Sha256::new();
                    digest.update(b"AOS-controller-recipient-native-cas-v1\0");
                    digest.update(offer.digest);
                    digest.update(successor.row().commitment()?);
                    let digest: [u8; 32] = digest.finalize().into();
                    let id = fixed::<16>(&digest[..16])?;
                    let transaction = successor.transaction(id)?;
                    (LaunchMutation::Successor(successor), transaction)
                }
            };
            mutation.require_exact(writer.bank_state_v1()?, &transaction)?;
            Ok(Arc::new(PreparedBankMutation { mutation, transaction, head: writer.next_sequence() }))
        })());
        let Some(Ok(prepared)) = self.prepared.as_ref() else {
            return Err(self.stop(Failure::Preparation));
        };
        Ok(ControllerPreparedBankMutationV1 { prepared: Arc::clone(prepared) })
    }

    /// Rejoins the actual prepared mutation at the sole upper semantic gate.
    ///
    /// # Errors
    /// Rejects a different transaction/predecessor using the SAME Protocol rule.
    pub fn require_exact(&self, state: &State, transaction: &JournalTransaction)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        if self.semantic_gate_failure.get().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let result = (|| {
            let prepared = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            prepared.mutation.require_exact(state, transaction)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                let _ = self.semantic_gate_failure.set(cause);
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    /// Observes the same original kernel subjects at the actual final crossing.
    ///
    /// # Errors
    /// Retains actual kernel results and refuses a repeated final crossing.
    pub fn final_crossing(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.crossing.get().is_some() || self.semantic_gate_failure.get().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let _ = self.crossing.set(self.kernel_once(1));
        if matches!(self.crossing.get(), Some(Ok(()))) {
            Ok(())
        } else {
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }

    fn pin_actual_native<P>(
        &self,
        writer: &ControllerFixedWriterOriginalV1<P>,
    ) -> Result<Arc<ControllerDurableAppendReceiptV1>, ControllerBankLaunchErrorV1> {
        writer.require_healthy()?;
        let prepared = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let receipt = writer.last_receipt.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if !writer.has_original(&self.original) || !Arc::ptr_eq(&receipt.identity, writer.identity())
            || receipt.transaction != *prepared.transaction.id() || receipt.head != prepared.head
            || self.kernels[1].get().is_none_or(|post| post.failure().is_some())
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(Arc::clone(receipt))
    }

    fn require_profile_pair(&self, pair: &Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        let pair = pair.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let expected = self.original.writer_enrollment()?;
        if expected.recipient_invocation != pair.0 || expected.identity.native_fields().invocation != pair.1 {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Finishes actual same-native readback and owed posts, then ACK/Confirm.
    ///
    /// Callers pass no CommitResult, receipt, permit or success Boolean. The
    /// private receipt is fetched from this actual writer's native publication.
    /// A matching map cannot erase failed/unfinished native stage custody.
    ///
    /// # Errors
    /// Retains native-readback, name/profile/kernel, ACK/Confirm and descriptor
    /// failures. Earlier primary causes remain first through independent posts.
    pub fn finish_native_once<P>(
        &mut self,
        writer: &ControllerCoordinatorWriterV1<P>,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let writer = &writer.fixed;
        if !self.entered || self.names_after_result.is_some() || self.confirmed {
            return Err(self.stop(Failure::Closed));
        }
        // Semantic/final-crossing refusal precedes the native readback marker.
        // Independent posts below still execute after either refusal.
        if self.semantic_gate_failure.get().is_some() {
            self.first.get_or_insert(Failure::SemanticGate);
        }
        if self.crossing.get().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::Crossing);
        }
        self.native = Some(self.pin_actual_native(writer));
        self.readback = Some((|| {
            let prepared = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            prepared.mutation.require_returned(writer)?;
            if !writer.contains_bank_transaction_v1(prepared.transaction.id())? {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            Ok(())
        })());
        if self.native.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::Native);
        }
        if self.readback.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::Readback);
        }
        // The SAME prearmed sample bypasses only fresh health re-entry. It
        // still opens/checks the actual held names and retains failed partials.
        self.names_after_result = Some(writer.finish_owed_name_sample(&mut self.names_after));
        self.profile_after = Some(profile.require_resource_producer());
        self.profile_after_binding = Some(self.require_profile_pair(&self.profile_after));
        let kernel = self.kernel_once(2);
        if self.names_after_result.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::NamesAfter);
        }
        if self.profile_after_binding.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::ProfileAfter);
        }
        if kernel.is_err() {
            self.first.get_or_insert(Failure::Kernel(2));
        }
        if self.first.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        writer.begin_name_sample(&mut self.names_final)?;
        self.confirmation = Some(self.acknowledge_once());
        if self.confirmation.as_ref().is_none_or(Result::is_err) {
            self.first.get_or_insert(Failure::Closed);
        }
        let kernel = self.kernel_once(3);
        self.names_final_result = Some(writer.finish_owed_name_sample(&mut self.names_final));
        self.profile_final = Some(profile.require_resource_producer());
        self.profile_final_binding = Some(self.require_profile_pair(&self.profile_final));
        if kernel.is_err() {
            self.first.get_or_insert(Failure::Kernel(3));
        }
        if self.names_final_result.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::NamesFinal);
        }
        if self.profile_final_binding.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::ProfileFinal);
        }
        if self.first.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.names_before.dispose_after_complete_interval();
        self.names_after.dispose_after_complete_interval();
        self.names_final.dispose_after_complete_interval();
        // All channel/record native uses end here, after final Confirm, the
        // final independent profile and every whole held-name interval.
        // Keep the complete packets and kernel observation DATA; only these
        // completed transport/received-description originals may now close.
        if !self.names_before.has_disposed_complete_interval_v1()
            || !self.names_after.has_disposed_complete_interval_v1()
            || !self.names_final.has_disposed_complete_interval_v1()
            || !profile.has_same_baseline_original(&self.original)
            || !writer.has_original(&self.original) || self.raw.is_some()
        {
            return Err(self.stop(Failure::NativeDisposal));
        }
        self.native_disposal = Some(CompletedLaunchNativeV1::take_completed_v1(
            &mut self.channel, &mut self.offer_receive, &mut self.confirm_receive,
        ));
        if !self.has_disposed_native_v1() {
            return Err(self.stop(Failure::NativeDisposal));
        }
        self.confirmed = true;
        Ok(())
    }

    fn native_ack(&self) -> Result<[u8; PACKET_BYTES], ControllerBankLaunchErrorV1> {
        if self.first.is_some() || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(())))
            || !matches!(self.names_after_result, Some(Ok(())))
            || !matches!(self.profile_after_binding, Some(Ok(())))
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let offer = self.offer.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let prepared = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let mut packet = [0; PACKET_BYTES];
        packet[..8].copy_from_slice(MAGIC);
        packet[8] = ACK;
        packet[9] = if offer.kind == LaunchKind::Initial { 1 } else { 2 };
        packet[16..24].copy_from_slice(&offer.generation.to_be_bytes());
        packet[24..56].copy_from_slice(&offer.digest);
        packet[56..88].copy_from_slice(&prepared.mutation.commitment(&prepared.transaction)?);
        packet[88..104].copy_from_slice(prepared.transaction.id());
        packet[104..120].copy_from_slice(&offer.recipient);
        packet[128..160].copy_from_slice(&offer.range);
        packet[160..176].copy_from_slice(&offer.donor);
        packet[176..184].copy_from_slice(&offer.confirmed_ordinal.to_be_bytes());
        Ok(packet)
    }

    pub(super) fn require_current_recipient<P>(
        &self, writer: &ControllerFixedWriterOriginalV1<P>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.confirmed || self.first.is_some() || self.process != std::process::id()
            || !self.has_disposed_native_v1() || !writer.has_original(&self.original)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let expected = self.original.writer_enrollment()?;
        let prepared = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let row = bank::recipient_incarnation(writer.bank_state_v1()?, expected.identity)?;
        match &prepared.mutation {
            LaunchMutation::Initial(_) if row == bank::initial_recipient_precharge_v1(
                expected.identity, expected.policy, expected.recipient_invocation)? => {},
            LaunchMutation::Successor(successor) if row == Some(successor.row())
                && successor.row().recipient() == expected.recipient_invocation => {},
            _ => return Err(ControllerBankLaunchErrorV1::Conflict),
        }
        if let Some(row) = row {
            row.require_policy_v1(expected.policy)?;
            require_same_controller_generation_v1(expected.controller_generation_v1, row.generation())?;
        }
        if !writer.contains_bank_transaction_v1(prepared.transaction.id())?
            || self.native.as_ref().and_then(|result| result.as_ref().ok())
                .is_none_or(|receipt| !Arc::ptr_eq(&receipt.identity, writer.identity()))
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    fn has_disposed_native_v1(&self) -> bool {
        self.raw.is_none() && self.channel.is_none() && self.offer_receive.is_none()
            && self.confirm_receive.is_none()
            && self.native_disposal.as_ref().is_some_and(|result| match result {
                Ok(completed) => completed.is_complete_v1(),
                Err(_) => false,
            })
    }

    /// Reports only actual completed initial enrollment (deny-only DATA).
    #[must_use]
    pub fn is_initial_enrollment(&self) -> bool {
        self.confirmed && self.first.is_none()
            && self.offer.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|offer| offer.kind == LaunchKind::Initial)
    }

    /// Reports held actual successor completion as deny-only startup DATA.
    ///
    /// This samples nothing and grants no bank, operation or recovery. The
    /// entered native purpose must independently rejoin its actual current
    /// writer/profile and preserve the complete predecessor bank liabilities.
    #[doc(hidden)]
    #[must_use]
    pub fn is_confirmed_operator_recover_successor_v1(&self) -> bool {
        self.confirmed && self.first.is_none() && self.process == std::process::id()
            && self.has_disposed_native_v1()
            && self.offer.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|offer| offer.kind == LaunchKind::Successor)
    }

    /// Reports actual armed native debt after a partially failed prepare.
    ///
    /// This deny-only schedule DATA cannot arm a sample or fund new IO. The
    /// trusted coordinator uses it to drive independently owed completion even
    /// when no typed mutation was returned from an earlier channel failure.
    #[must_use]
    pub fn has_owed_native_post_v1(&self) -> bool {
        self.names_after.has_owed_native_post() && self.names_after_result.is_none()
    }

    /// Reports completion of the actual retained PID1 ACK/Confirm exchange.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.confirmed && self.first.is_none()
    }

    /// Rechecks only this launch's same fixed writer/current recipient join.
    ///
    /// # Errors
    /// Refuses missing real confirmation, receipt, original or current row.
    pub fn require_current_controller_v1<P>(
        &self,
        writer: &ControllerCoordinatorWriterV1<P>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_recipient(&writer.fixed)
    }

    /// Rejoins the current native recipient and its image-bound whole precharge.
    ///
    /// This comparison supplies no recovery authorization or receiving capacity.
    ///
    /// # Errors
    /// Rejects an old image, absent seal, changed partition, or differing native
    /// recipient/Offer/writer/returned commit and independent final posts.
    pub fn require_controller_baseline_precharge_v1<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>) -> Result<(), ControllerBankLaunchErrorV1>
    {
        self.require_current_recipient(&writer.fixed)?;
        let original = self.original.writer_enrollment()?;
        original.policy.controller_baseline_partition_v1()?;
        let row = bank::recipient_incarnation(writer.fixed.bank_state_v1()?, original.identity)?
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        row.require_policy_v1(original.policy)?;
        require_same_controller_generation_v1(original.controller_generation_v1, row.generation())?;
        Ok(())
    }

    // This closed branch requires the actual authenticated successor Offer;
    // historical recipient DATA or an initial first-use interval cannot enter.
    pub(super) fn require_operator_recover_current_v1<P>(
        &self, writer: &ControllerCoordinatorWriterV1<P>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.offer.as_ref().and_then(|result| result.as_ref().ok())
            .is_none_or(|offer| offer.kind != LaunchKind::Successor) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_controller_baseline_precharge_v1(writer)
    }

    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let site = match self.first {
            Some(site) => site,
            None if self.semantic_gate_failure.get().is_some() => Failure::SemanticGate,
            None if self.crossing.get().is_some_and(Result::is_err) => Failure::Crossing,
            None => return None,
        };
        match site {
            Failure::Funding => error(&self.funding),
            Failure::Deadline => error(&self.deadline_result),
            Failure::CurrentPidfd => error(&self.current_pidfd),
            Failure::Channel => error(&self.channel),
            Failure::OfferPoll => error(&self.offer_poll)
                .or_else(|| self.offer_poll.as_ref()?.as_ref().ok().and_then(poll_error)),
            Failure::OfferReceive => error(&self.offer_receive),
            Failure::OfferShape => error(&self.offer),
            Failure::NamesBefore => self.names_before.failure(),
            Failure::Preparation => error(&self.prepared),
            Failure::SemanticGate => self.semantic_gate_failure.get().map(|cause| cause as _),
            Failure::Crossing => self.kernels[1].get().and_then(KernelPost::failure)
                .or_else(|| self.crossing.get().and_then(|result| result.as_ref().err()).map(|cause| cause as _)),
            Failure::Kernel(index) => self.kernels[index].get().and_then(KernelPost::failure),
            Failure::Native => error(&self.native),
            Failure::Readback => error(&self.readback),
            Failure::NamesAfter => self.names_after.failure().or_else(|| error(&self.names_after_result)),
            Failure::ProfileAfter => error(&self.profile_after).or_else(|| error(&self.profile_after_binding)),
            Failure::Ack => error(&self.ack),
            Failure::AckSend => error(&self.ack_send),
            Failure::ConfirmPoll => error(&self.confirm_poll)
                .or_else(|| self.confirm_poll.as_ref()?.as_ref().ok().and_then(poll_error)),
            Failure::ConfirmReceive => error(&self.confirm_receive),
            Failure::ConfirmShape => self.confirm_descriptors.get().and_then(ConfirmDescriptors::failure)
                .or_else(|| error(&self.confirm_shape)),
            Failure::NamesFinal => self.names_final.failure().or_else(|| error(&self.names_final_result)),
            Failure::ProfileFinal => error(&self.profile_final).or_else(|| error(&self.profile_final_binding)),
            Failure::NativeDisposal => error(&self.native_disposal),
            Failure::Closed => error(&self.confirmation),
        }.or(Some(&CLOSED))
    }

    fn acknowledge_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.ack = Some(self.native_ack());
        let Some(Ok(ack)) = self.ack.as_ref() else {
            return Err(self.stop(Failure::Ack));
        };
        let packet = *ack;
        let sent = self.socket_mut()?.send_retaining(&packet);
        self.ack_send = Some(sent);
        if self.ack_send.as_ref().is_none_or(Result::is_err) {
            return Err(self.stop(Failure::AckSend));
        }

        self.confirm_poll = Some(self.wait_once());
        if !self.confirm_poll.as_ref().is_some_and(|result| result.as_ref().is_ok_and(ready)) {
            return Err(self.stop(Failure::ConfirmPoll));
        }
        let received = self.socket_mut()?.receive_pid1_controller_range_descriptor_retaining_v2();
        self.confirm_receive = Some(received);
        if self.confirm_receive.as_ref().is_none_or(Result::is_err) {
            return Err(self.stop(Failure::ConfirmReceive));
        }
        self.confirm_shape = Some(self.require_confirm(&packet));
        if self.confirm_shape.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(Failure::ConfirmShape);
        }
        if self.first.is_some() {
            Err(ControllerBankLaunchErrorV1::Conflict)
        } else {
            Ok(())
        }
    }

    fn require_confirm(&self, ack: &[u8; PACKET_BYTES]) -> Result<(), ControllerBankLaunchErrorV1> {
        let record = self.confirm_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let mut expected = *ack;
        expected[8] = CONFIRM;
        let socket = self.socket()?;
        let credentials = record.subject().credentials();
        if record.payload() != expected || record.descriptors().len() != 1
            || credentials.pid().get() != 1 || credentials.uid() != 0 || credentials.gid() != 0
            || record.subject().initial_info() != socket.peer().initial_info()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let offer = self.offer_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let old = offer.descriptors().first()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let confirm = record.descriptors().first()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let offered = rustix::fs::fstat(old);
        let confirmed = rustix::fs::fstat(confirm);
        let mut poll = [PollFd::new(confirm, PollFlags::IN)];
        let result = rustix::event::poll(&mut poll, Some(&Timespec { tv_sec: 0, tv_nsec: 0 }));
        let death = PollObservation { result, events: poll[0].revents() };
        let kind = self.offer.as_ref().and_then(|result| result.as_ref().ok())
            .map(|offer| offer.kind);
        let subject_settled = match kind {
            Some(LaunchKind::Initial) => matches!(death.result, Ok(0)) && death.events.is_empty(),
            Some(LaunchKind::Successor) => matches!(death.result, Ok(1)) && death.events.contains(PollFlags::HUP),
            None => false,
        };
        let binding = match (&offered, &confirmed) {
            (Ok(old), Ok(new)) if old.st_dev == new.st_dev && old.st_ino == new.st_ino
                && subject_settled => Ok(()),
            _ => Err(ControllerBankLaunchErrorV1::Conflict),
        };
        let _ = self.confirm_descriptors.set(ConfirmDescriptors { offered, confirmed, death, binding });
        // Both transferred duplicates remain in their actual received records
        // through final profile/name posts. The whole positive native handoff
        // is later and is the only place that disposes those originals.
        if self.confirm_descriptors.get().is_some_and(|post| post.failure().is_none()) {
            Ok(())
        } else {
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }

}

impl Drop for ControllerBankLaunchOriginalV1 {
    fn drop(&mut self) {
        if self.entered && !self.confirmed {
            std::process::abort();
        }
    }
}

fn ready(observation: &PollObservation) -> bool {
    matches!(observation.result, Ok(1)) && observation.events.contains(PollFlags::IN)
        && !observation.events.intersects(PollFlags::ERR | PollFlags::NVAL)
}

fn poll_error(observation: &PollObservation) -> Option<&(dyn std::error::Error + 'static)> {
    observation.result.as_ref().err().map(|cause| cause as _)
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

static CLOSED: ControllerBankLaunchErrorV1 = ControllerBankLaunchErrorV1::Conflict;

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ControllerBankLaunchErrorV1> {
    bytes.try_into().map_err(|_| ControllerBankLaunchErrorV1::Conflict)
}

fn read_u64(bytes: &[u8]) -> Result<u64, ControllerBankLaunchErrorV1> {
    Ok(u64::from_be_bytes(fixed::<8>(bytes)?))
}

// Both reached native joins use this comparison: the authenticated Offer may
// not choose another envelope than the earlier sealed first-table delivery.
fn require_same_controller_generation_v1(delivered: Option<u64>, actual: u64)
    -> Result<(), ControllerBankLaunchErrorV1>
{
    if delivered == Some(actual) { Ok(()) }
    else { Err(ControllerBankLaunchErrorV1::Conflict) }
}

#[cfg(test)]
mod baseline_precharge_tests {
    use super::*;

    #[test]
    fn same_native_generation_gate_rejects_wrong_offer_current_row_and_old_delivery() {
        assert!(require_same_controller_generation_v1(Some(0), 0).is_ok());
        assert!(require_same_controller_generation_v1(Some(1), 1).is_ok());
        // This helper compares the already authenticated delivery ordinal;
        // the preceding native Offer/policy gate enforces the prepaid K bound.
        assert!(require_same_controller_generation_v1(Some(2), 2).is_ok());
        for (delivery, reached) in [(Some(0), 1), (Some(1), 0), (None, 0),
            (None, 1), (Some(1), 2)]
        {
            assert!(require_same_controller_generation_v1(delivery, reached).is_err());
        }
    }
}
