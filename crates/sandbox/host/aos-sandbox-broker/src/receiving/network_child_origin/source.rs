//! Borrows ongoing permission from the actual enrolled live Netd Source.
//!
//! Only the completed inherited native carrier can lend this once. Each finite
//! query uses its original PID1 endpoint, manager subject, Source/worker pins,
//! challenge and sequence. Neither initial acquisition cutoff nor operation D
//! is renewed here. Financial startup and signed-method admission remain owed.

use super::*;
use aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1;

/// Copies comparison DATA from the already-authenticated original840.
///
/// These fields cannot construct a Source, signed operation or financial loan.
/// The receiving domain must independently admit the actual signed operation,
/// original lease/fence and unchanged D before any effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkChildOperationBindingDataV2 {
    /// Original native purpose, P=1 or O=2.
    pub purpose: u8,
    /// Actual kernel Boot identity authenticated at native bootstrap.
    pub boot: [u8; 16],
    /// Current enrolled Netd Source invocation.
    pub source_invocation: [u8; 16],
    /// This issued worker's exact invocation.
    pub worker_invocation: [u8; 16],
    /// Digest of the parent's original paid PREBIRTH.
    pub prebirth_digest: [u8; 32],
    /// The same original operation's request identity.
    pub request_id: [u8; 16],
    /// The same original operation's effect commitment.
    pub effect_digest: [u8; 32],
    /// The genuine parent operation ordinal shared by P and O.
    pub operation_ordinal: u64,
    /// Actual selected worker MemoryMax, installed NOFILE and TasksMax.
    pub native_limits: [u64; 3],
    /// Finite original Source-query programme paid before native birth.
    pub source_probe_count: u64,
}

#[derive(Clone, Copy)]
enum RecordFirst { Order, Before(usize), SourceInfoBefore, SubjectBefore, Identity, Coordinates,
    SubjectAfter, SourceInfoAfter, After(usize), Retirement }

/// Retains one actual operation record's binding to the held Netd Source.
///
/// This owner authenticates native identity only. Public credentials, signed
/// request semantics, completed lease/fence and D remain domain obligations.
#[must_use]
pub struct NetworkChildSourceRecordOriginalV2 {
    entered: bool,
    before: [Option<Result<bool, aos_sandbox_linux::Error>>; 2],
    subject_before: Option<Result<bool, aos_sandbox_linux::Error>>,
    source_info_before: Option<Result<aos_sandbox_linux::pidfd::PidFdInfo, aos_sandbox_linux::Error>>,
    identity: PidFdProcessIdentityOriginalV1,
    identity_result: Option<Result<(), aos_sandbox_linux::Error>>,
    subject_after: Option<Result<bool, aos_sandbox_linux::Error>>,
    source_info_after: Option<Result<aos_sandbox_linux::pidfd::PidFdInfo, aos_sandbox_linux::Error>>,
    after: [Option<Result<bool, aos_sandbox_linux::Error>>; 2],
    first: Option<RecordFirst>,
    stat_retirement: Option<Result<(), aos_sandbox_linux::Error>>,
}

impl NetworkChildSourceRecordOriginalV2 {
    /// Creates inert resident destinations before the parent's complete quote.
    #[must_use]
    pub fn new() -> Self {
        Self { entered: false, before: std::array::from_fn(|_| None),
            subject_before: None, source_info_before: None,
            identity: PidFdProcessIdentityOriginalV1::new(),
            identity_result: None, subject_after: None, source_info_after: None,
            after: std::array::from_fn(|_| None), first: None, stat_retirement: None }
    }

    /// Prices this actual identity recipe beyond the retained input record.
    ///
    /// The transport record and its subject PIDFD are separately prepaid by
    /// its exact receiver; this supplier adds the real retained stat OFD.
    #[must_use]
    pub fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(identity.0)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(identity.1).ok()?))
    }

    /// Retires only this completed positive stat-file proof temporary.
    ///
    /// The actual input subject and transport record remain owned separately.
    /// The domain calls this only after their independent posts and semantic
    /// result have completed. All stat bytes, coordinates, identities, native
    /// results and original failures remain on this same once-only owner.
    /// Future source probes use the still-held original Source and recipient
    /// PIDFDs; they never reopen or adopt this retired proof. No financial
    /// liability or previously admitted peak is reduced.
    ///
    /// # Errors
    /// Retains incomplete, failed or repeated retirement and its actual cause.
    pub fn retire_positive_stat_proof_once_v2(&mut self)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        if !self.entered || self.first.is_some() || self.stat_retirement.is_some()
            || !matches!(self.identity_result, Some(Ok(())))
            || !matches!(self.subject_before, Some(Ok(true)))
            || !matches!(self.subject_after, Some(Ok(true)))
            || !self.before.iter().all(|value| matches!(value, Some(Ok(true))))
            || !self.after.iter().all(|value| matches!(value, Some(Ok(true))))
            || !matches!(self.source_info_before, Some(Ok(_)))
            || !matches!(self.source_info_after, Some(Ok(_)))
        {
            self.first.get_or_insert(RecordFirst::Order);
            return Err(NetworkChildOriginClosedV2);
        }
        self.stat_retirement = Some(self.identity.retire_positive_stat_file_once_v2());
        if matches!(self.stat_retirement, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(RecordFirst::Retirement);
            Err(NetworkChildOriginClosedV2)
        }
    }

    /// Borrows the first actual cause while all independently owed posts stay held.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            RecordFirst::Before(index) => self.before[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            RecordFirst::SubjectBefore => self.subject_before.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            RecordFirst::Identity => self.identity.failure(),
            RecordFirst::SourceInfoBefore => self.source_info_before.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            RecordFirst::SourceInfoAfter => self.source_info_after.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            RecordFirst::SubjectAfter => self.subject_after.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            RecordFirst::After(index) => self.after[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            RecordFirst::Retirement => self.stat_retirement.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            RecordFirst::Order | RecordFirst::Coordinates => None,
        };
        cause.or(Some(&NetworkChildOriginClosedV2))
    }
}

impl Default for NetworkChildSourceRecordOriginalV2 {
    fn default() -> Self { Self::new() }
}

#[derive(Clone, Copy)]
enum First { Order, Before(usize), Send, Reply, After(usize) }

/// Retains one real native Source query and its independent held-process posts.
#[must_use]
pub struct NetworkChildSourceProbeOriginalV2 {
    entered: bool,
    before: [Option<Result<bool, aos_sandbox_linux::Error>>; 2],
    request: [u8; 64],
    send: NetworkPid1RequestOriginalV2,
    send_result: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    reply: NetworkPid1ReplyOriginalV2,
    reply_result: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    after: [Option<Result<bool, aos_sandbox_linux::Error>>; 2],
    first: Option<First>,
}

impl NetworkChildSourceProbeOriginalV2 {
    /// Creates inert destinations before the parent's prepaid child programme.
    #[must_use]
    pub fn new() -> Self {
        Self { entered: false, before: std::array::from_fn(|_| None), request: [0; 64],
            send: NetworkPid1RequestOriginalV2::new(), send_result: None,
            reply: NetworkPid1ReplyOriginalV2::new(), reply_result: None,
            after: std::array::from_fn(|_| None), first: None }
    }

    /// Borrows the first actual native cause while every owed post stays held.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Before(index) => self.before[index].as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            First::Send => self.send.failure(),
            First::Reply => self.reply.failure(),
            First::After(index) => self.after[index].as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            First::Order => None,
        };
        cause.or(Some(&NetworkChildOriginClosedV2))
    }

    /// Prices every retained query destination before the actual finite array.
    ///
    /// The exact count comes from the closed operation recipe and must match
    /// its PREBIRTH/840 commitment. Zero and overflow refuse without defaults.
    #[must_use]
    pub fn programme_obligations_data_v2(count: u64) -> Option<ResourceVector> {
        let count_usize = usize::try_from(count).ok().filter(|count| *count != 0)?;
        let native = NetworkPid1ReplyProfileOriginalV2::programme_obligations_data_v2(count)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?.checked_mul(count_usize)?
            .checked_add(native.0)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(native.1).ok()?))
    }
}

impl Default for NetworkChildSourceProbeOriginalV2 {
    fn default() -> Self { Self::new() }
}

/// Borrows the actual native child and its once-lent ongoing Source transport.
///
/// Its constructor performs a real initial Source query before returning.
/// It carries no financial account or signed operation permission. The owner
/// keeps the original prepaid F and admits actual original D before effects.
pub struct NetworkChildSourceLoanV2<'native> {
    channel: NetworkPid1ReplyChannelV2<'native>,
    native: &'native native::NativeOriginalV2,
    packet: [u8; 840],
    closed: bool,
}

/// Borrows the same native child owner and actual once-lent PID1 channel epoch.
///
/// This opaque comparison original contains references to genuine retained
/// owners. It has no DATA constructor, account, effect permission or new Source.
/// Its lifetime borrows the underlying native owners, independently of the
/// mutable Source loan used by subsequent O reads and helper frontiers.
pub struct NetworkChildSourceAffinityOriginalV2<'native> {
    native: &'native native::NativeOriginalV2,
    channel: aos_sandbox_linux::seqpacket::NetworkPid1ReplyAffinityOriginalV2<'native>,
}

impl<'native> NetworkChildSourceLoanV2<'native> {
    /// Borrows the same held Netd PIDFD for the worker's prepaid native wait.
    ///
    /// The reference belongs to the continuously retained native owner rather
    /// than to the mutable Source loan, so the independently owed Source post
    /// can still run after the wait. This lends no currentness, deadline,
    /// request, account or effect permission; the actual actor must retain its
    /// own native wait and run the original Source/D gates at their frontiers.
    ///
    /// # Errors
    /// Refuses an already-failed Source or unavailable actual native subject.
    pub fn original_netd_pidfd_for_worker_wait_v2(&self)
        -> Result<&'native aos_sandbox_linux::pidfd::PidFd, NetworkChildOriginClosedV2>
    {
        if self.closed || !self.native.completed() {
            return Err(NetworkChildOriginClosedV2);
        }
        self.native.held_source_pidfd().ok_or(NetworkChildOriginClosedV2)
    }

    /// Borrows opaque affinity from this actual completed Source and channel.
    ///
    /// # Errors
    /// Refuses a failed Source or unavailable original native channel epoch.
    pub fn lend_affinity_original_v2(&self)
        -> Result<NetworkChildSourceAffinityOriginalV2<'native>, NetworkChildOriginClosedV2>
    {
        if self.closed || !self.native.completed() { return Err(NetworkChildOriginClosedV2); }
        let channel = self.channel.lend_affinity_original_v2()
            .map_err(|_| NetworkChildOriginClosedV2)?;
        Ok(NetworkChildSourceAffinityOriginalV2 { native: self.native, channel })
    }

    /// Requires the same retained native Source, channel and once-lending epoch.
    ///
    /// # Errors
    /// Refuses a closed lane or any different actual owner, original record,
    /// profile or native socket. Equal decoded coordinates cannot satisfy it.
    pub fn require_same_affinity_original_v2(&self,
        original: &NetworkChildSourceAffinityOriginalV2<'_>) -> Result<(), NetworkChildOriginClosedV2>
    {
        if self.closed || !self.native.completed() || !std::ptr::eq(self.native, original.native) {
            return Err(NetworkChildOriginClosedV2);
        }
        self.channel.require_same_affinity_original_v2(&original.channel)
            .map_err(|_| NetworkChildOriginClosedV2)
    }

    /// Observes independently owed held-process posts on a negative-only lane.
    ///
    /// This never sends a Source query or returns positive permission. It may
    /// run after an earlier Source or D failure; its actual native results stay
    /// on a distinct prepaid original while the old cause remains selected.
    ///
    /// # Errors
    /// Always refuses positive use, including after successful native posts.
    /// Reentry performs no IO and preserves the original native results.
    pub fn observe_owed_native_after_once_v2(&mut self,
        original: &mut NetworkChildSourceProbeOriginalV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        if original.entered {
            original.first.get_or_insert(First::Order);
            self.closed = true;
            return Err(NetworkChildOriginClosedV2);
        }
        original.entered = true;
        for index in 0..2 {
            original.before[index] = self.native.held_liveness(index);
            if !matches!(original.before[index], Some(Ok(true))) {
                original.first.get_or_insert(First::Before(index));
            }
        }
        for index in 0..2 {
            original.after[index] = self.native.held_liveness(index);
            if !matches!(original.after[index], Some(Ok(true))) {
                original.first.get_or_insert(First::After(index));
            }
        }
        original.first.get_or_insert(First::Order);
        self.closed = true;
        Err(NetworkChildOriginClosedV2)
    }

    /// Borrows exact original native comparison fields while this lane is healthy.
    #[must_use]
    pub fn operation_binding_data_v2(&self) -> Option<NetworkChildOperationBindingDataV2> {
        if self.closed { return None; }
        Some(NetworkChildOperationBindingDataV2 {
            purpose: self.packet[10],
            boot: self.packet[16..32].try_into().ok()?,
            source_invocation: self.packet[32..48].try_into().ok()?,
            worker_invocation: self.packet[48..64].try_into().ok()?,
            prebirth_digest: self.packet[64..96].try_into().ok()?,
            request_id: self.packet[176..192].try_into().ok()?,
            effect_digest: self.packet[192..224].try_into().ok()?,
            operation_ordinal: u64::from_be_bytes(self.packet[296..304].try_into().ok()?),
            native_limits: [packet_u64(&self.packet, 272)?, packet_u64(&self.packet, 280)?,
                packet_u64(&self.packet, 288)?],
            source_probe_count: packet_u64(&self.packet, 832)?,
        })
    }

    /// Checks a real record against the same native Source retained at bootstrap.
    ///
    /// Actual Source and worker liveness, record identity/stat and all reached
    /// subject/process posts are retained independently. The domain still owes
    /// original-channel origin, ongoing Source queries and signed D admission.
    ///
    /// # Errors
    /// Refuses substitution, unavailable identity, dead process or reentry and
    /// permanently fences this Source borrow while preserving the first cause.
    pub fn require_same_netd_record_once_v2(
        &mut self, record: &ReceivedDescriptorRecord,
        original: &mut NetworkChildSourceRecordOriginalV2,
    ) -> Result<(), NetworkChildOriginClosedV2> {
        self.require_same_netd_subject_once_v2(record.subject(), original)
    }

    /// Binds an actual connected parent peer to this same held Netd Source.
    ///
    /// The peer is the native identity of the supplied owned socket; no
    /// record or header is synthesized before READY. Original-channel custody
    /// and the signed operation/D remain separate domain obligations.
    ///
    /// # Errors
    /// Retains changed credentials/coordinates, native failures or reentry,
    /// runs every independent held-process post and fences this Source.
    pub fn require_same_netd_peer_once_v2(&mut self,
        socket: &aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        original: &mut NetworkChildSourceRecordOriginalV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        let peer = socket.peer();
        require_same_netd_identity_once_v2(self.native, &self.packet, IdentityUse::Positive(&mut self.closed),
            peer.pidfd(), peer.initial_info(), peer.credentials().uid(), peer.credentials().gid(),
            original)
    }

    /// Binds a retained native record subject before complete packet allocation.
    ///
    /// The canonical native preview owns this subject and its actual socket
    /// origin. This comparison alone grants no record origin, Source,
    /// financial permission or signed-method admission.
    ///
    /// # Errors
    /// Preserves the same held-identity/stat/credentials first cause and
    /// independent posts as complete-record admission, fencing this Source.
    pub fn require_same_netd_subject_once_v2(&mut self,
        subject: &aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject,
        original: &mut NetworkChildSourceRecordOriginalV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        require_same_netd_identity_once_v2(self.native, &self.packet, IdentityUse::Positive(&mut self.closed),
            subject.pidfd(), subject.initial_info(), subject.credentials().uid(),
            subject.credentials().gid(), original)
    }

    /// Binds only a prepaid negative exchange's actual connected parent peer.
    ///
    /// Positive use is permanently closed before native observation. This
    /// uses only the same retained source/recipient pins, preserves their
    /// native posts and performs no Source query or deadline renewal.
    ///
    /// # Errors
    /// Retains missing/dead/different native pins or reentry on the supplied
    /// already-prepaid destination. It never reopens positive permission.
    pub fn require_owed_netd_peer_once_v2(&mut self,
        socket: &aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        original: &mut NetworkChildSourceRecordOriginalV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        self.closed = true;
        let peer = socket.peer();
        require_same_netd_identity_once_v2(self.native, &self.packet, IdentityUse::Owed,
            peer.pidfd(), peer.initial_info(), peer.credentials().uid(), peer.credentials().gid(), original)
    }

    /// Binds only an owed negative acknowledgement's actual native subject.
    ///
    /// The transport owner independently keeps the same original socket and
    /// record custody. Positive Source use is closed before this observation;
    /// the method grants neither a Source renewal nor a completed effect.
    ///
    /// # Errors
    /// Keeps the same first native identity failure and every reached post.
    pub fn require_owed_netd_record_once_v2(&mut self, record: &ReceivedDescriptorRecord,
        original: &mut NetworkChildSourceRecordOriginalV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        self.closed = true;
        let subject = record.subject();
        require_same_netd_identity_once_v2(self.native, &self.packet, IdentityUse::Owed,
            subject.pidfd(), subject.initial_info(), subject.credentials().uid(),
            subject.credentials().gid(), original)
    }

    /// Queries the same live enrolled Netd Source before a reached frontier.
    ///
    /// The supplied wait is DATA narrowed from the original signed D by its
    /// owner. It creates no new deadline; the bootstrap query alone uses no D.
    /// Every reached held-process after runs despite send/reply failure.
    ///
    /// # Errors
    /// Retains exact native liveness, transport/reply, sequence and reentry
    /// causes; any refusal permanently fences this same borrowed Source lane.
    pub fn require_live_before_once_v2(&mut self, original: &mut NetworkChildSourceProbeOriginalV2,
        timeout: Option<&rustix::event::Timespec>) -> Result<(), NetworkChildOriginClosedV2>
    {
        require_live_source_query_once_v2(self.native, &mut self.channel, &self.packet,
            &mut self.closed, original, timeout)
    }

    /// Borrows the issued additional child fee as comparison DATA only.
    #[must_use]
    pub fn prepaid_fee_data_v2(&self) -> Option<ResourceVector> {
        if self.closed { return None; }
        let mut fee = ResourceVector::ZERO;
        for (index, dimension) in D::ALL.into_iter().enumerate() {
            let offset = 304 + index * 8;
            fee = fee.with(dimension, u64::from_be_bytes(self.packet[offset..offset + 8].try_into().ok()?));
        }
        Some(fee)
    }
}

impl NetworkChildOriginOriginalV2 {
    /// Borrows the actual failed original's Netd subject for owed disposition.
    ///
    /// This is available only after authenticated PID1/840 custody failed at a
    /// later frontier and both original process coordinates were actually
    /// captured. It preserves the first failure, lends no live Source and
    /// cannot authorize READY, admission, effects or another operation.
    ///
    /// # Errors
    /// Refuses an unfailed original, missing authenticated carrier or absent
    /// exact held Source/recipient identity; PID1 is never substituted.
    pub fn owed_netd_pidfd_for_worker_wait_v2(&self)
        -> Result<&aos_sandbox_linux::pidfd::PidFd, NetworkChildOriginClosedV2>
    {
        if self.first.is_none() || !matches!(self.origin, Some(Ok(())))
            || !matches!(self.packet, Some(Ok(())))
        { return Err(NetworkChildOriginClosedV2); }
        let packet = self.record.as_ref().and_then(|result| result.as_ref().ok())
            .map(ReceivedDescriptorRecord::payload).ok_or(NetworkChildOriginClosedV2)?;
        self.native.held_source_for_owed_wait(packet).ok_or(NetworkChildOriginClosedV2)
    }

    /// Binds only an owed negative exchange's actual parent peer.
    ///
    /// An actual prior refusal remains selected. The inherited PID1
    /// carrier/packet must have authenticated, and the
    /// same source/recipient native PIDFDs must actually be retained. A later
    /// failure remains selected on this original. This method constructs no
    /// Source borrow and can authorize neither startup nor a positive effect.
    ///
    /// # Errors
    /// Retains missing native pins, different parent identity or reentry and
    /// performs all reached independent native posts without renewing D.
    pub fn require_owed_netd_peer_once_v2(&self,
        socket: &aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        original: &mut NetworkChildSourceRecordOriginalV2)
        -> Result<(), NetworkChildOriginClosedV2>
    {
        if self.first.is_none() || !matches!(self.origin, Some(Ok(())))
            || !matches!(self.packet, Some(Ok(()))) {
            original.first.get_or_insert(RecordFirst::Order);
            return Err(NetworkChildOriginClosedV2);
        }
        let packet: [u8; 840] = self.record.as_ref().and_then(|record| record.as_ref().ok())
            .and_then(|record| record.payload().try_into().ok())
            .ok_or(NetworkChildOriginClosedV2)?;
        let peer = socket.peer();
        require_same_netd_identity_once_v2(&self.native, &packet, IdentityUse::Owed,
            peer.pidfd(), peer.initial_info(), peer.credentials().uid(), peer.credentials().gid(), original)
    }

    /// Borrows the genuine live Netd Source only after actual native bootstrap.
    ///
    /// The parent's complete child invoice already owns this prefix. Native
    /// carrier, roles, BOOT and currentness precede the actual first query;
    /// protected startup and READY can begin only after this call succeeds.
    /// No packet, scalar, fee DATA or public callback can construct this borrow.
    ///
    /// # Errors
    /// Retains carrier/native/profile failure, wrong original, repeated borrow
    /// or the first actual Source query. It grants no F bank or effect right.
    pub fn borrow_live_source_once_v2<'native>(&'native mut self,
        initial: &mut NetworkChildSourceProbeOriginalV2,
    ) -> Result<NetworkChildSourceLoanV2<'native>, NetworkChildOriginClosedV2> {
        if self.first.is_some() || !self.native.completed() {
            return Err(NetworkChildOriginClosedV2);
        }
        let Some(Ok(socket)) = self.channel.as_mut() else { return Err(NetworkChildOriginClosedV2); };
        let Some(Ok(record)) = self.record.as_ref() else { return Err(NetworkChildOriginClosedV2); };
        let packet: [u8; 840] = record.payload().try_into().map_err(|_| NetworkChildOriginClosedV2)?;
        let mut channel = match self.reply_profile.borrow_completed_channel_once_v2(socket, record) {
            Ok(channel) => channel,
            Err(_) => {
                self.first.get_or_insert(super::First::Profile);
                return Err(NetworkChildOriginClosedV2);
            }
        };
        let mut closed = false;
        if require_live_source_query_once_v2(&self.native, &mut channel, &packet,
            &mut closed, initial, None).is_err() {
            self.first.get_or_insert(super::First::Source);
            return Err(NetworkChildOriginClosedV2);
        }
        // The same actual query, its reply and every native post have now
        // completed. Retire only positive proof temporaries before lending the
        // immutable native owner. The channel sequence/epoch is never reset or
        // borrowed again, and no Source value is reconstructed from DATA.
        if self.native.retire_positive_proofs_once().is_err() {
            self.first.get_or_insert(super::First::Native);
            return Err(NetworkChildOriginClosedV2);
        }
        Ok(NetworkChildSourceLoanV2 { channel, native: &self.native, packet, closed })
    }
}

enum IdentityUse<'held> {
    Positive(&'held mut bool),
    Owed,
}

impl IdentityUse<'_> {
    fn is_closed(&self) -> bool {
        matches!(self, Self::Positive(closed) if **closed)
    }

    fn close_positive(&mut self) {
        if let Self::Positive(closed) = self { **closed = true; }
    }
}

fn require_same_netd_identity_once_v2(native: &native::NativeOriginalV2,
    packet: &[u8; 840], mut use_kind: IdentityUse<'_>, pidfd: &aos_sandbox_linux::pidfd::PidFd,
    initial_info: aos_sandbox_linux::pidfd::PidFdInfo, uid: u32, gid: u32,
    original: &mut NetworkChildSourceRecordOriginalV2)
    -> Result<(), NetworkChildOriginClosedV2>
{
        if use_kind.is_closed() || original.entered {
            original.first.get_or_insert(RecordFirst::Order);
            use_kind.close_positive();
            return Err(NetworkChildOriginClosedV2);
        }
        original.entered = true;
        for index in 0..2 {
            original.before[index] = native.held_liveness(index);
            if !matches!(original.before[index], Some(Ok(true))) {
                original.first.get_or_insert(RecordFirst::Before(index));
            }
        }
        original.subject_before = Some(pidfd.is_alive());
        if !matches!(original.subject_before, Some(Ok(true))) {
            original.first.get_or_insert(RecordFirst::SubjectBefore);
        }
        original.source_info_before = native.held_source_info();
        if !matches!(original.source_info_before, Some(Ok(_))) {
            original.first.get_or_insert(RecordFirst::SourceInfoBefore);
        }
        if original.first.is_none() {
            original.identity_result = Some(original.identity.capture_once(pidfd));
            if !matches!(original.identity_result, Some(Ok(()))) {
                original.first = Some(RecordFirst::Identity);
            } else {
                let identity_matches = original.identity.identity().is_some_and(|identity| {
                    Some(u64::from(identity.pid())) == packet_u64(&packet, 224)
                        && Some(identity.start_time_ticks()) == packet_u64(&packet, 232)
                        && identity.cgroup_id() == packet_u64(&packet, 240)
                        && identity.thread_group_id() == identity.pid()
                        && identity.parent_pid() == 1
                });
                let credentials_match = original.source_info_before.as_ref()
                    .and_then(|result| result.as_ref().ok()).is_some_and(|info| {
                        *info == initial_info
                            && info.credentials().is_some_and(|credentials| {
                                credentials.real_user_id() == uid
                                    && credentials.real_group_id() == gid
                            })
                    });
                if !identity_matches || !credentials_match {
                    original.first = Some(RecordFirst::Coordinates);
                }
            }
        }
        original.subject_after = Some(pidfd.is_alive());
        original.source_info_after = native.held_source_info();
        if !matches!(original.subject_after, Some(Ok(true))) {
            original.first.get_or_insert(RecordFirst::SubjectAfter);
        }
        if !matches!((&original.source_info_before, &original.source_info_after),
            (Some(Ok(before)), Some(Ok(after))) if before == after)
        {
            original.first.get_or_insert(RecordFirst::SourceInfoAfter);
        }
        for index in 0..2 {
            original.after[index] = native.held_liveness(index);
            if !matches!(original.after[index], Some(Ok(true))) {
                original.first.get_or_insert(RecordFirst::After(index));
            }
        }
        if original.first.is_some() {
            use_kind.close_positive();
            Err(NetworkChildOriginClosedV2)
        } else { Ok(()) }

}

fn require_live_source_query_once_v2(native: &native::NativeOriginalV2,
    channel: &mut NetworkPid1ReplyChannelV2<'_>, packet: &[u8; 840], closed: &mut bool,
    original: &mut NetworkChildSourceProbeOriginalV2,
    timeout: Option<&rustix::event::Timespec>) -> Result<(), NetworkChildOriginClosedV2>
{
        if original.entered || *closed {
            original.first.get_or_insert(First::Order);
            *closed = true;
            return Err(NetworkChildOriginClosedV2);
        }
        original.entered = true;
        for index in 0..2 {
            original.before[index] = native.held_liveness(index);
            if !matches!(original.before[index], Some(Ok(true))) { original.first.get_or_insert(First::Before(index)); }
        }
        if original.first.is_none() {
            if let Some(sequence) = channel.next_sequence_data_v2() {
                original.request[..8].copy_from_slice(b"AOSNFP02");
                original.request[8..10].copy_from_slice(&2_u16.to_be_bytes());
                original.request[10] = packet[10];
                original.request[12..16].copy_from_slice(&64_u32.to_be_bytes());
                original.request[16..32].copy_from_slice(&packet[160..176]);
                original.request[32..48].copy_from_slice(&packet[48..64]);
                original.request[48..56].copy_from_slice(&sequence.to_be_bytes());
                original.send_result = Some(channel.send_once_v2(&mut original.send, &original.request));
                if !matches!(original.send_result, Some(Ok(()))) { original.first = Some(First::Send); }
            } else { original.first = Some(First::Order); }
        }
        if original.first.is_none() {
            original.reply_result = Some(channel.receive_before_once_v2(&mut original.reply, timeout));
            if !matches!(original.reply_result, Some(Ok(()))) { original.first = Some(First::Reply); }
        }
        for index in 0..2 {
            original.after[index] = native.held_liveness(index);
            if !matches!(original.after[index], Some(Ok(true))) { original.first.get_or_insert(First::After(index)); }
        }
        if original.first.is_some() {
            *closed = true;
            Err(NetworkChildOriginClosedV2)
        } else { Ok(()) }

}

fn packet_u64(packet: &[u8; 840], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(packet.get(offset..offset.checked_add(8)?)?.try_into().ok()?))
}
