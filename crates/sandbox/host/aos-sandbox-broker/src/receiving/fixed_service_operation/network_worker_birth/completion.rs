//! Retains PID1's actual same-worker reap and final Unit result after K.
//!
//! The fixed FL03 carrier is DATA until the original Source, PID1 subject,
//! channel and complete Birth body agree. Negative status still permits
//! disposal. Positive completion additionally checks the unchanged effect D.

use super::*;
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketReceiveErrorV1, SeqpacketSocket};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

#[derive(Clone, Copy)]
enum First {
    Order,
    Affinity,
    PrearmBefore,
    PrearmAfter,
    SourceBefore,
    PeerBefore,
    Poll,
    Receive,
    BindingBefore,
    Packet,
    Status,
    BindingAfter,
    SubjectAfter,
    PeerAfter,
    SourceAfter,
    Clock,
}

#[derive(Debug, thiserror::Error)]
#[error("worker exited with native code {code}, status {status}, Unit result {unit_result}")]
struct ExitStatus {
    code: u32,
    status: u32,
    unit_result: u32,
}

pub(super) struct CompletionOriginalV3 {
    prearmed: bool,
    entered: bool,
    posts_entered: bool,
    positive: bool,
    invocation: Option<[u8; 16]>,
    ordinal: Option<u64>,
    purpose: Option<NetworkWorkerBirthPurposeV2>,
    source_before: terminal::SourceSample,
    source_after: terminal::SourceSample,
    peer_before: Option<Result<bool, aos_linux_descriptors::Error>>,
    before: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    timeout: Option<Timespec>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    events: [PollFlags; 2],
    receive: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    cookies: [Option<Result<u64, aos_linux_descriptors::Error>>; 2],
    bindings: [Option<Result<(), RecordBindingError>>; 2],
    packet: Option<Result<(), FixedServiceOperationClosedV4>>,
    status: Option<ExitStatus>,
    subject_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    peer_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    clock: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    confirmation: Option<Result<(), FixedServiceOperationClosedV4>>,
    first: Option<First>,
}

impl CompletionOriginalV3 {
    pub(super) fn new() -> Self {
        Self {
            prearmed: false,
            entered: false,
            posts_entered: false,
            positive: false,
            invocation: None,
            ordinal: None,
            purpose: None,
            source_before: terminal::SourceSample::new(),
            source_after: terminal::SourceSample::new(),
            peer_before: None,
            before: None,
            timeout: None,
            poll: None,
            events: [PollFlags::empty(); 2],
            receive: None,
            cookies: [None, None],
            bindings: [None, None],
            packet: None,
            status: None,
            subject_after: None,
            peer_after: None,
            clock: None,
            confirmation: None,
            first: None,
        }
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let receive =
            SeqpacketSocket::network_worker_completion_receive_obligations_v3().ok_or(overflow)?;
        let bytes = receive
            .0
            .checked_add(2 * std::mem::size_of::<PollFd<'_>>())
            .ok_or(overflow)?;
        terminal::TerminalOriginalV2::dynamic_demand()?.checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow)?)
                .with(
                    D::OpenFiles,
                    u64::try_from(receive.1).map_err(|_| overflow)?,
                ),
        )
    }

    pub(super) fn prearm_once(
        &mut self,
        loan: &FixedServiceOperationLoanV4<'_>,
        purpose: NetworkWorkerBirthPurposeV2,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if self.invocation.is_some() {
            return self.refuse(First::Order);
        }
        self.invocation = loan.operation.invocation;
        self.ordinal = loan.operation.operation_ordinal;
        self.purpose = Some(purpose);
        if !terminal::issued_affinity(loan, self.invocation, self.ordinal) {
            return self.refuse(First::Affinity);
        }
        if !self.source_before.prepare(loan) {
            self.first = Some(First::PrearmBefore);
        }
        if !self.source_after.prepare(loan) {
            self.first.get_or_insert(First::PrearmAfter);
        }
        self.prearmed = self.first.is_none();
        self.result()
    }

    pub(super) fn receive_once(
        &mut self,
        loan: &mut FixedServiceOperationLoanV4<'_>,
        birth: &[u8],
        sent: bool,
        positive: bool,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        // Cleanup may borrow an already entered original; it never repeats a
        // native receive or converts its previous negative result to success.
        if self.entered {
            if !self.posts_entered || !matches!(self.packet, Some(Ok(()))) || self.status.is_none()
            {
                return self.refuse(First::Order);
            }
            return self.result();
        }
        self.entered = true;
        if !self.prearmed || !sent {
            return self.refuse(First::Order);
        }
        if !terminal::issued_affinity(loan, self.invocation, self.ordinal)
            || birth.len() != 160
            || birth[..8] != *b"AOSNFH02"
            || birth.get(10).copied() != self.purpose.map(|value| value as u8)
            || birth.get(32..48) != self.invocation.as_ref().map(|value| value.as_slice())
        {
            return self.refuse(First::Affinity);
        }
        self.positive = positive;

        let scope = CompletionAfter {
            original: self,
            loan,
        };
        if !scope.original.source_before.observe(scope.loan) {
            scope.original.first.get_or_insert(First::SourceBefore);
        }
        let _ = scope.original.receive_inner(scope.loan, birth, positive);
        scope.original.observe_posts(scope.loan);
        scope.original.result()
    }

    fn receive_inner(
        &mut self,
        loan: &mut FixedServiceOperationLoanV4<'_>,
        birth: &[u8],
        positive: bool,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if positive {
            self.before = Some(loan.observe_network_worker_effect_clock_v4());
            self.timeout = self
                .before
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .and_then(|before| {
                    let (_, deadline) = loan.retained_network_horizon_data_v4().ok()?;
                    let remaining = deadline.checked_sub(before.boottime_nanoseconds())?;
                    Timespec::try_from(std::time::Duration::from_nanos(remaining)).ok()
                });
            if self.timeout.is_none() {
                self.first.get_or_insert(First::Clock);
            }
        }
        let Some(Ok(channel)) = loan.common.channel.as_mut() else {
            return self.refuse(First::Order);
        };
        self.peer_before = Some(channel.peer().is_alive());
        if !matches!(self.peer_before, Some(Ok(true))) {
            return self.refuse(First::PeerBefore);
        }
        if let Some(timeout) = self.timeout.as_ref() {
            let fd = match channel.as_fd() {
                Ok(fd) => fd,
                Err(_) => return self.refuse(First::Order),
            };
            let peer_fd = channel.peer().pidfd().as_fd();
            let mut descriptors = [
                PollFd::new(&fd, PollFlags::IN),
                PollFd::new(&peer_fd, PollFlags::IN),
            ];
            // One positive wait uses only the original D. Negative disposal
            // instead makes one nonblocking receive, retaining an absent or
            // uncertain reply without waiting for a quarantined C programme.
            self.poll = Some(poll(&mut descriptors, Some(timeout)));
            self.events = [descriptors[0].revents(), descriptors[1].revents()];
            if !matches!(self.poll, Some(Ok(_)))
                || !self.events[0].contains(PollFlags::IN)
                || self.events[0].intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                || !self.events[1].is_empty()
            {
                return self.refuse(First::Poll);
            }
        }
        self.receive = Some(channel.receive_network_worker_completion_retaining_v3());
        let Some(Ok(record)) = self.receive.as_ref() else {
            return self.refuse(First::Receive);
        };
        self.bindings[0] = Some(
            channel.require_network_worker_completion_origin_retaining_v3(
                record,
                &mut self.cookies[0],
            ),
        );
        let credentials = record.subject().credentials();
        let peer = channel.peer();
        self.packet = Some(
            if decode_status(record.payload(), birth).is_some()
                && record.descriptors().is_empty()
                && credentials.pid().get() == 1
                && credentials.uid() == 0
                && credentials.gid() == 0
                && peer.credentials().pid().get() == 1
                && peer.credentials().uid() == 0
                && peer.credentials().gid() == 0
                && peer.initial_info() == record.subject().initial_info()
            {
                Ok(())
            } else {
                Err(FixedServiceOperationClosedV4)
            },
        );
        if !matches!(self.bindings[0], Some(Ok(()))) {
            self.first.get_or_insert(First::BindingBefore);
        }
        if !matches!(self.packet, Some(Ok(()))) {
            return self.refuse(First::Packet);
        }
        self.status = decode_status(record.payload(), birth);
        if !self.success_status() {
            self.first.get_or_insert(First::Status);
        }
        self.result()
    }

    fn observe_posts(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>) {
        if self.posts_entered {
            return;
        }
        self.posts_entered = true;
        if let Some(Ok(record)) = self.receive.as_ref() {
            if let Some(Ok(channel)) = loan.common.channel.as_ref() {
                self.bindings[1] = Some(
                    channel.require_network_worker_completion_origin_retaining_v3(
                        record,
                        &mut self.cookies[1],
                    ),
                );
                if !matches!(self.bindings[1], Some(Ok(()))) {
                    self.first.get_or_insert(First::BindingAfter);
                }
            } else {
                self.first.get_or_insert(First::BindingAfter);
            }
            self.subject_after = Some(record.subject().is_alive());
            if !matches!(self.subject_after, Some(Ok(true))) {
                self.first.get_or_insert(First::SubjectAfter);
            }
        }
        if let Some(Ok(channel)) = loan.common.channel.as_ref() {
            self.peer_after = Some(channel.peer().is_alive());
            if !matches!(self.peer_after, Some(Ok(true))) {
                self.first.get_or_insert(First::PeerAfter);
            }
        } else {
            self.first.get_or_insert(First::PeerAfter);
        }
        if !self.source_after.observe(loan) {
            self.first.get_or_insert(First::SourceAfter);
        }
        if self.positive {
            // The independent parent-D post is retained even after a bad
            // packet, exit status or native prefix. It never replaces that
            // earlier cause or turns negative child facts into success.
            self.clock = Some(loan.observe_network_worker_effect_clock_v4());
            if !matches!(self.clock, Some(Ok(_))) {
                self.first.get_or_insert(First::Clock);
            }
        }
    }

    pub(super) fn confirm_positive(
        &mut self,
        loan: &mut FixedServiceOperationLoanV4<'_>,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if !self.entered || !self.posts_entered || !self.positive || self.confirmation.is_some() {
            return self.refuse(First::Order);
        }
        if self.first.is_some()
            || !self.success_status()
            || !matches!(self.before, Some(Ok(_)))
            || !matches!(self.clock, Some(Ok(_)))
        {
            return Err(FixedServiceOperationClosedV4);
        }
        self.confirmation = Some(loan.require_network_worker_current_v4());
        if !matches!(self.confirmation, Some(Ok(()))) {
            return self.refuse(First::Clock);
        }
        self.result()
    }

    fn success_status(&self) -> bool {
        matches!(
            self.status,
            Some(ExitStatus {
                code: 1,
                status: 0,
                unit_result: 0
            })
        )
    }

    fn result(&self) -> Result<(), FixedServiceOperationClosedV4> {
        if self.first.is_some() {
            Err(FixedServiceOperationClosedV4)
        } else {
            Ok(())
        }
    }

    fn refuse(&mut self, first: First) -> Result<(), FixedServiceOperationClosedV4> {
        self.first.get_or_insert(first);
        Err(FixedServiceOperationClosedV4)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::PrearmBefore | First::SourceBefore => self.source_before.failure(),
            First::PrearmAfter | First::SourceAfter => self.source_after.failure(),
            First::PeerBefore => self
                .peer_before
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Poll => self.poll.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Receive => self
                .receive
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::BindingBefore => self.cookies[0]
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.bindings[0]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::BindingAfter => self.cookies[1]
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.bindings[1]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::SubjectAfter => self
                .subject_after
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::PeerAfter => self
                .peer_after
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Status => self.status.as_ref().map(|cause| cause as _),
            First::Order | First::Affinity | First::Packet | First::Clock => None,
        }
        .or(Some(&FixedServiceOperationClosedV4))
    }

    pub(super) fn parent_failure_selected(&self) -> bool {
        matches!(self.first, Some(First::Clock))
    }
}

struct CompletionAfter<'a, 'financial> {
    original: &'a mut CompletionOriginalV3,
    loan: &'a mut FixedServiceOperationLoanV4<'financial>,
}

impl Drop for CompletionAfter<'_, '_> {
    fn drop(&mut self) {
        self.original.observe_posts(self.loan);
    }
}

fn decode_status(packet: &[u8], birth: &[u8]) -> Option<ExitStatus> {
    if packet.len() != 176
        || birth.len() != 160
        || packet[..8] != *b"AOSNFL03"
        || packet[8..10] != 3_u16.to_be_bytes()
        || packet[10..12] != birth[10..12]
        || packet[16..160] != birth[16..160]
        || packet[12..16] != 176_u32.to_be_bytes()
        || packet[172..176] != [0; 4]
    {
        return None;
    }
    let code = u32::from_be_bytes(packet[160..164].try_into().ok()?);
    let status = u32::from_be_bytes(packet[164..168].try_into().ok()?);
    let unit_result = u32::from_be_bytes(packet[168..172].try_into().ok()?);
    if code > 3
        || unit_result > 1
        || code == 0 && (status != 0 || unit_result != 1)
        || unit_result == 0 && (code != 1 || status != 0)
    {
        return None;
    }
    Some(ExitStatus {
        code,
        status,
        unit_result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(code: u32, status: u32, unit_result: u32) -> ([u8; 176], [u8; 160]) {
        let mut birth = [0; 160];
        birth[..8].copy_from_slice(b"AOSNFH02");
        birth[8..10].copy_from_slice(&2_u16.to_be_bytes());
        birth[10] = 1;
        birth[12..16].copy_from_slice(&160_u32.to_be_bytes());
        for (index, byte) in birth[16..152].iter_mut().enumerate() {
            *byte = u8::try_from(index + 1).unwrap();
        }
        let mut packet = [0; 176];
        packet[..160].copy_from_slice(&birth);
        packet[..8].copy_from_slice(b"AOSNFL03");
        packet[8..10].copy_from_slice(&3_u16.to_be_bytes());
        packet[12..16].copy_from_slice(&176_u32.to_be_bytes());
        packet[160..164].copy_from_slice(&code.to_be_bytes());
        packet[164..168].copy_from_slice(&status.to_be_bytes());
        packet[168..172].copy_from_slice(&unit_result.to_be_bytes());
        (packet, birth)
    }

    #[test]
    fn only_real_normal_exit_and_final_unit_success_are_positive() {
        for (code, status, unit, positive) in [
            (1, 0, 0, true),
            (1, 1, 1, false),
            (2, 9, 1, false),
            (3, 11, 1, false),
            (0, 0, 1, false),
            (1, 0, 1, false),
        ] {
            let (packet, birth) = fixture(code, status, unit);
            let parsed = decode_status(&packet, &birth).unwrap();
            assert_eq!(
                (parsed.code, parsed.status, parsed.unit_result),
                (code, status, unit)
            );
            let mut original = CompletionOriginalV3::new();
            original.status = Some(parsed);
            assert_eq!(original.success_status(), positive);
            // Even authenticated positive DATA alone cannot complete the
            // Source/parent programme or enter its original-D confirmation.
            assert!(!original.entered && !original.posts_entered && original.clock.is_none());
        }
    }

    #[test]
    fn binds_every_birth_coordinate_and_rejects_old_or_noncanonical_status() {
        let (packet, birth) = fixture(1, 0, 0);
        for index in 10..12 {
            let mut changed = packet;
            changed[index] ^= 1;
            assert!(decode_status(&changed, &birth).is_none());
        }
        for index in 16..160 {
            let mut changed = packet;
            changed[index] ^= 1;
            assert!(decode_status(&changed, &birth).is_none());
        }
        for index in [7, 9, 15, 172, 175] {
            let mut changed = packet;
            changed[index] ^= 1;
            assert!(decode_status(&changed, &birth).is_none());
        }
        for (code, status, unit) in [(0, 1, 1), (0, 0, 0), (2, 9, 0), (4, 0, 1), (1, 0, 2)] {
            let (packet, birth) = fixture(code, status, unit);
            assert!(decode_status(&packet, &birth).is_none());
        }
        assert!(decode_status(&packet[..175], &birth).is_none());
    }
}
