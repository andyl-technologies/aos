//! Receives Network's genuine inherited PID1 child-origin carrier exactly once.
//!
//! This module retains native carrier custody before any protected startup
//! capture or READY. Carrier completion alone grants no Source, F account,
//! signed operation or effect. The sealed child factory separately joins the
//! actual donated roles and consumes only the original prepaid child fee.

use std::error::Error;
use std::os::fd::OwnedFd;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::inherited_fd::NetworkWorkerChildInitialTableV2;
use aos_sandbox_linux::seqpacket::{NetworkPid1ReplyProfileOriginalV2,
    NetworkPid1ReplyChannelV2, NetworkPid1RequestOriginalV2, NetworkPid1ReplyOriginalV2,
    RecordBindingError, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1, SeqpacketSocket};
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use rustix::event::{PollFd, PollFlags, poll};

use super::{ActivationNamesErrorV1, NetworkWorkerBirthPurposeV2, original_activation_names_v1};

const _: () = assert!(D::COUNT == 22);
const ACTIVATION_NAME: &str = "aos-network-child-origin-v2";

mod native;
mod source;
pub use source::{NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2,
    NetworkChildSourceRecordOriginalV2, NetworkChildOperationBindingDataV2,
    NetworkChildSourceAffinityOriginalV2};

/// Reports a closed original while its native owner retains the first cause.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, thiserror::Error)]
#[error("the original Network child carrier is closed")]
pub struct NetworkChildOriginClosedV2;

#[derive(Clone, Copy)]
enum First { Order, Table, Names, Channel, Peer, PeerBefore, Poll, Receive,
    Origin, Packet, Profile, Native, Source, SubjectAfter, PeerAfter }

/// Retains the inherited endpoint, real PID1 record and every native prefix.
///
/// It cannot be constructed from a descriptor or decoded packet. Its actual
/// once-only entry captures the fixed inherited table and native PID1 subject.
/// Successful carrier validation alone grants no role or effect permission.
#[must_use]
pub struct NetworkChildOriginOriginalV2 {
    entered: bool,
    table: NetworkWorkerChildInitialTableV2,
    entries: Option<[Option<OwnedFd>; 1]>,
    names: Option<Result<Vec<String>, ActivationNamesErrorV1>>,
    channel: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer_before: Option<Result<bool, aos_linux_descriptors::Error>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    record: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    cookie: Option<Result<u64, aos_linux_descriptors::Error>>,
    origin: Option<Result<(), RecordBindingError>>,
    packet: Option<Result<(), NetworkChildOriginClosedV2>>,
    reply_profile: NetworkPid1ReplyProfileOriginalV2,
    profile: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    subject_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    peer_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    first: Option<First>,
    native: native::NativeOriginalV2,
}

impl NetworkChildOriginOriginalV2 {
    /// Creates inert resident destinations before any native capture.
    #[must_use]
    pub fn new() -> Self {
        Self { entered: false, table: NetworkWorkerChildInitialTableV2::new(),
            entries: None, names: None, channel: None, peer_before: None, poll: None,
            record: None, cookie: None, origin: None, packet: None,
            reply_profile: NetworkPid1ReplyProfileOriginalV2::new(), profile: None,
            subject_after: None, peer_after: None, first: None,
            native: native::NativeOriginalV2::new() }
    }

    /// Captures actual inherited child-origin custody before protected startup.
    ///
    /// PID1's native producer prices this exact carrier on the original Source
    /// before creating the child. Its one poll has no invented timeout: the
    /// operation D is not delivered until after READY. PID1 releases840 only
    /// after real parent ARM, or the parent disposes the actual issued child.
    /// This result authenticates a carrier, never a Source or effect grant.
    ///
    /// # Errors
    /// Retains every reached inherited FD, socket/peer/record, native result
    /// and receive prefix. Refuses wrong geometry, PID1, packet or reentry.
    pub fn capture_inherited_once_v2(&mut self, purpose: NetworkWorkerBirthPurposeV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        let _ = self.capture_inner(purpose);

        // Native carrier afters remain independently owed after any reached
        // record, framing, profile or option failure. No post replaces first.
        if let Some(Ok(record)) = self.record.as_ref() {
            self.subject_after = Some(record.subject().is_alive());
            if !matches!(self.subject_after, Some(Ok(true))) { self.first.get_or_insert(First::SubjectAfter); }
        }
        if let Some(Ok(channel)) = self.channel.as_ref() {
            self.peer_after = Some(channel.peer().is_alive());
            if !matches!(self.peer_after, Some(Ok(true))) { self.first.get_or_insert(First::PeerAfter); }
        }
        if self.first.is_some() { Err(NetworkChildOriginClosedV2) } else { Ok(()) }
    }

    fn capture_inner(&mut self, purpose: NetworkWorkerBirthPurposeV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        if self.table.observe_once().is_err() { return self.refuse(First::Table); }
        self.entries = self.table.take_completed_entries();
        self.names = Some(original_activation_names_v1(1));
        if self.names.as_ref().and_then(|value| value.as_ref().ok())
            .is_none_or(|names| names.len() != 1 || names[0] != ACTIVATION_NAME)
        { return self.refuse(First::Names); }
        let original = self.entries.as_mut().and_then(|entries| entries[0].take());
        let Some(original) = original else { return self.refuse(First::Table); };
        self.channel = Some(SeqpacketSocket::from_owned_network_child_retaining_v2(original));
        let Some(Ok(channel)) = self.channel.as_mut() else { return self.refuse(First::Channel); };
        let peer = channel.peer().credentials();
        if peer.pid().get() != 1 || peer.uid() != 0 || peer.gid() != 0
            || channel.peer().initial_info().pid() != 1 { return self.refuse(First::Peer); }
        self.peer_before = Some(channel.peer().is_alive());
        if !matches!(self.peer_before, Some(Ok(true))) { return self.refuse(First::PeerBefore); }
        let descriptor = match channel.as_fd() {
            Ok(descriptor) => descriptor, Err(_) => return self.refuse(First::Channel),
        };
        let mut descriptors = [PollFd::new(&descriptor, PollFlags::IN)];
        self.poll = Some(poll(&mut descriptors, None));
        if !matches!(self.poll, Some(Ok(1))) || !descriptors[0].revents().contains(PollFlags::IN) {
            return self.refuse(First::Poll);
        }
        self.record = Some(channel.receive_network_child_origin_retaining_v2());
        let Some(Ok(record)) = self.record.as_ref() else { return self.refuse(First::Receive); };
        self.origin = Some(channel.require_network_child_origin_retaining_v2(record, &mut self.cookie));
        if !matches!(self.origin, Some(Ok(()))) { return self.refuse(First::Origin); }
        let credentials = record.subject().credentials();
        self.packet = Some(if credentials.pid().get() == 1 && credentials.uid() == 0
            && credentials.gid() == 0 && record.subject().initial_info() == channel.peer().initial_info()
            && record.descriptors().len() == 9 && packet_is_closed(record.payload(), purpose)
        { Ok(()) } else { Err(NetworkChildOriginClosedV2) });
        if !matches!(self.packet, Some(Ok(()))) { return self.refuse(First::Packet); }
        self.profile = Some(self.reply_profile.configure_once_v2(channel, record));
        if !matches!(self.profile, Some(Ok(()))) { return self.refuse(First::Profile); }
        let Some(Ok(record)) = self.record.as_mut() else { return self.refuse(First::Receive); };
        if self.native.capture_once(record).is_err() { return self.refuse(First::Native); }
        Ok(())
    }

    fn refuse(&mut self, cause: First) -> Result<(), NetworkChildOriginClosedV2> {
        self.first.get_or_insert(cause);
        Err(NetworkChildOriginClosedV2)
    }

    /// Borrows the first actual native refusal while retaining all originals.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Table => self.table.failure().map(|cause| cause as _),
            First::Names => self.names.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Channel => self.channel.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PeerBefore => self.peer_before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Poll => self.poll.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Receive => self.record.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Origin => self.cookie.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.origin.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Profile => self.reply_profile.failure(),
            First::Native => self.native.failure(),
            First::SubjectAfter => self.subject_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PeerAfter => self.peer_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Order | First::Peer | First::Packet | First::Source => None,
        };
        cause.or(Some(&NetworkChildOriginClosedV2))
    }

    /// Quotes this real native carrier before the parent creates its child.
    ///
    /// This source-derived DATA supplies no budget or authority. The actual
    /// whole child recipe must add all native roles, Source probes and startup.
    #[must_use]
    pub fn carrier_obligations_data_v2() -> Option<ResourceVector> {
        let admission = SeqpacketSocket::network_child_admission_obligations_data_v2()?;
        let receive = SeqpacketSocket::network_child_origin_receive_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(admission.0)?.checked_add(receive.0)?
            .checked_add(2 * std::mem::size_of::<PollFd<'_>>())?
            .checked_add(2 * (ACTIVATION_NAME.len() + std::mem::size_of::<String>()))?;
        // Native stdio and fd3 stay installed. Admission counts its owned
        // table duplicate plus the real peer PIDFD; do not bill that duplicate
        // twice. Receive separately prices its actual and hostile prefixes.
        let files = 4_usize.checked_add(admission.1)?.checked_add(receive.1)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?))
    }

    /// Prices the carrier and every actual initial native donated-role join.
    ///
    /// The private parent programme adds its protected startup, helper recipe,
    /// all exact Source probes and native birth before issuing any PREBIRTH.
    /// This value supplies no bank, native admission or effect permission.
    #[must_use]
    pub fn initial_native_obligations_data_v2() -> Option<ResourceVector> {
        Self::carrier_obligations_data_v2()?.checked_add(native::NativeOriginalV2::obligations_data_v2()?).ok()
    }

    /// Counts the fixed native FD row after the complete positive retirement.
    ///
    /// The actual once-only Source factory settles its first query and every
    /// native post before retiring proof temporaries. Stdio/original fd3, the
    /// owned origin socket/peer/initial subject, all nine donated roles, own
    /// PIDFD/executable and three additional admitted anchors remain installed.
    /// The enclosing programme adds all of its real startup, record, helper
    /// and scanner overlap; this DATA grants no table size or process fit.
    #[must_use]
    pub fn positive_retained_frontier_files_data_v2() -> Option<usize> {
        let stdio_and_original = [0_u8, 1, 2, 3].len();
        let carrier = ["owned origin socket", "PID1 peer", "PID1 initial subject"].len();
        let donations = ["Source PIDFD", "Source cgroup", "worker cgroup", "worker memory",
            "worker pids", "aggregate cgroup", "aggregate memory", "aggregate pids", "aggregate CPU"].len();
        let recipient = ["own PIDFD", "own executable"].len();
        let additional_anchors = ["Source anchor", "worker anchor", "aggregate anchor"].len();
        stdio_and_original.checked_add(carrier)?.checked_add(donations)?
            .checked_add(recipient)?.checked_add(additional_anchors)
    }

    /// Borrows only negative request/effect/BOOT comparison DATA from PID1.
    ///
    /// The actual PID1 carrier and closed840 packet must have authenticated.
    /// A later native-role or initial Source-query refusal may still owe its
    /// prepaid negative result/ACK. This tuple supplies no Source, namespace,
    /// plan, financial capacity or permission to perform protected startup.
    #[must_use]
    pub fn bootstrap_negative_correlation_data_v2(&self)
        -> Option<([u8; 16], [u8; 32], [u8; 16])>
    {
        if !matches!(self.origin, Some(Ok(()))) || !matches!(self.packet, Some(Ok(()))) {
            return None;
        }
        let packet = self.record.as_ref()?.as_ref().ok()?.payload();
        Some((packet.get(176..192)?.try_into().ok()?,
            packet.get(192..224)?.try_into().ok()?, packet.get(16..32)?.try_into().ok()?))
    }

    /// Identifies the separately retained first actual Source-probe refusal.
    ///
    /// The caller keeps its original probe beside this carrier and selects
    /// that same probe's native failure; this marker creates no substitute.
    #[must_use]
    pub fn initial_source_failure_is_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::Source))
    }
}

impl Default for NetworkChildOriginOriginalV2 {
    fn default() -> Self { Self::new() }
}

fn packet_is_closed(bytes: &[u8], purpose: NetworkWorkerBirthPurposeV2) -> bool {
    if bytes.len() != 840 || bytes[..8] != *b"AOSNFB02"
        || bytes[8..10] != 2_u16.to_be_bytes() || bytes[10] != purpose as u8
        || bytes[11] != 0 || bytes[12..16] != 840_u32.to_be_bytes()
        || [16..32, 32..48, 48..64, 64..96, 96..128, 128..160, 160..176,
            176..192, 192..224].into_iter().any(|range| bytes[range].iter().all(|byte| *byte == 0))
        || bytes[32..48] == bytes[48..64]
        || (224..304).step_by(8).chain([832]).any(|offset| bytes[offset..offset + 8] == [0; 8])
        || bytes[224..232] == bytes[248..256]
    { return false; }
    let vectors = (|| -> Result<(), AccountingError> {
        let mut fee = ResourceVector::ZERO;
        let mut baseline = ResourceVector::ZERO;
        let mut source = ResourceVector::ZERO;
        for (index, dimension) in D::ALL.into_iter().enumerate() {
            let value = |start| -> Result<u64, AccountingError> {
                let offset = start + index * 8;
                let bytes = bytes[offset..offset + 8].try_into().map_err(|_| {
                    AccountingError::ArithmeticOverflow { dimension }
                })?;
                Ok(u64::from_be_bytes(bytes))
            };
            fee = fee.with(dimension, value(304)?);
            baseline = baseline.with(dimension, value(480)?);
            source = source.with(dimension, value(656)?);
        }
        // Restrictive DATA conservation only. A vector decoded from even an
        // authenticated packet cannot create a Source or independent account.
        source.checked_sub(baseline.checked_add(fee)?)?;
        Ok(())
    })();
    vectors.is_ok()
}
