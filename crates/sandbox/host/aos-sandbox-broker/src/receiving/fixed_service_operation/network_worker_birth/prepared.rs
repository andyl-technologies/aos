//! Retains actual PID1 PREPARED reception on the same paid Netd Source channel.
//!
//! The packet is not an authority constructor. Its native subject, carrier and
//! exact Source/request commitment are checked beside the real parent loan.
//! Child birth custody, ARMED, child840 and all effect gates remain separate.

use super::*;
use aos_sandbox_linux::seqpacket::{ReceivedRecord, RetainedSeqpacketReceiveErrorV1,
    SeqpacketSocket};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

#[derive(Clone, Copy)]
enum First { Order, Clock, PeerBefore, Poll, Receive, Binding, Packet, SubjectAfter, PeerAfter, ParentAfter }

pub(super) struct PreparedOriginalV2 {
    entered: bool,
    before: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    peer_before: Option<Result<bool, aos_linux_descriptors::Error>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    receive: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    cookie: Option<Result<u64, aos_linux_descriptors::Error>>,
    binding: Option<Result<(), RecordBindingError>>,
    packet: Option<Result<(), FixedServiceOperationClosedV4>>,
    subject_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    peer_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    parent_after: Option<Result<(), FixedServiceOperationClosedV4>>,
    first: Option<First>,
}

impl PreparedOriginalV2 {
    pub(super) const fn new() -> Self {
        Self { entered: false, before: None, peer_before: None, poll: None,
            receive: None, cookie: None, binding: None, packet: None,
            subject_after: None, peer_after: None, parent_after: None, first: None }
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let (bytes, files) = SeqpacketSocket::network_prebirth_prepared_receive_obligations_v2()
            .ok_or(overflow)?;
        let bytes = bytes.checked_add(2 * std::mem::size_of::<PollFd<'_>>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Timespec>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(overflow)?;
        let files = u64::try_from(files).map_err(|_| overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files))
    }

    pub(super) fn receive_once(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>,
        request: &[u8; 496]) -> Result<(), FixedServiceOperationClosedV4>
    {
        if self.entered { self.first.get_or_insert(First::Order); return Err(FixedServiceOperationClosedV4); }
        self.entered = true;
        let _ = self.receive_inner(loan, request);

        // A failed receive, malformed packet or wrong subject cannot suppress
        // the independently owed observations of the actual retained pins.
        if let Some(Ok(record)) = self.receive.as_ref() {
            self.subject_after = Some(record.subject().is_alive());
            if !matches!(self.subject_after, Some(Ok(true))) { self.first.get_or_insert(First::SubjectAfter); }
        }
        if let Some(Ok(channel)) = loan.common.channel.as_ref() {
            self.peer_after = Some(channel.peer().is_alive());
            if !matches!(self.peer_after, Some(Ok(true))) { self.first.get_or_insert(First::PeerAfter); }
        } else { self.first.get_or_insert(First::ParentAfter); }
        self.parent_after = Some(loan.require_network_worker_current_v4());
        if !matches!(self.parent_after, Some(Ok(()))) { self.first.get_or_insert(First::ParentAfter); }
        if self.first.is_some() { Err(FixedServiceOperationClosedV4) } else { Ok(()) }
    }

    fn receive_inner(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>,
        request: &[u8; 496]) -> Result<(), FixedServiceOperationClosedV4>
    {
        let closed = FixedServiceOperationClosedV4;
        self.before = Some(loan.observe_network_worker_effect_clock_v4());
        let Some(Ok(before)) = self.before else { self.first = Some(First::Clock); return Err(closed); };
        let (_, deadline) = match loan.retained_network_horizon_data_v4() {
            Ok(interval) => interval,
            Err(_) => { self.first = Some(First::Clock); return Err(closed); }
        };
        let timeout = deadline.checked_sub(before.boottime_nanoseconds())
            .and_then(|remaining| Timespec::try_from(std::time::Duration::from_nanos(remaining)).ok());
        let Some(timeout) = timeout else { self.first = Some(First::Clock); return Err(closed); };
        let Some(Ok(channel)) = loan.common.channel.as_mut() else {
            self.first = Some(First::Order); return Err(closed);
        };
        self.peer_before = Some(channel.peer().is_alive());
        if !matches!(self.peer_before, Some(Ok(true))) { self.first = Some(First::PeerBefore); return Err(closed); }
        let descriptor = match channel.as_fd() {
            Ok(descriptor) => descriptor,
            Err(_) => { self.first = Some(First::Order); return Err(closed); }
        };
        let mut descriptors = [PollFd::new(&descriptor, PollFlags::IN)];
        self.poll = Some(poll(&mut descriptors, Some(&timeout)));
        if !matches!(self.poll, Some(Ok(1))) || !descriptors[0].revents().contains(PollFlags::IN) {
            self.first = Some(First::Poll); return Err(closed);
        }
        self.receive = Some(channel.receive_network_prebirth_prepared_retaining_v2());
        let Some(Ok(record)) = self.receive.as_ref() else {
            self.first = Some(First::Receive); return Err(closed);
        };
        self.binding = Some(channel.require_network_prebirth_prepared_origin_retaining_v2(record, &mut self.cookie));
        if !matches!(self.binding, Some(Ok(()))) { self.first = Some(First::Binding); return Err(closed); }
        self.packet = Some((|| {
            let bytes = record.payload();
            let subject = record.subject();
            let credentials = subject.credentials();
            let expected: [u8; 32] = Sha256::digest(request).into();
            let source = loan.common.process_before.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(closed)?;
            let cgroup = loan.common.cgroup.as_ref().ok_or(closed)?;
            let peer = channel.peer();
            if bytes.len() != 144 || bytes[..8] != *b"AOSNFA02"
                || bytes[8..10] != 2_u16.to_be_bytes() || bytes[10] != request[10]
                || bytes[11] != 0 || bytes[12..16] != 144_u32.to_be_bytes()
                || bytes[16..48] != request[16..48] || bytes[48..64] != request[80..96]
                || bytes[64..96] != expected || bytes[96..112] == [0; 16]
                || bytes[112..120] != cgroup.kernel_id().to_be_bytes()
                || bytes[120..128] != u64::from(source.pid()).to_be_bytes()
                || bytes[128..136] != source.start_time_ticks().to_be_bytes()
                || bytes[136..144] != [0; 8]
                || credentials.pid().get() != 1 || credentials.uid() != 0 || credentials.gid() != 0
                || peer.credentials().pid().get() != 1 || peer.credentials().uid() != 0
                || peer.credentials().gid() != 0 || peer.initial_info() != subject.initial_info()
            { return Err(closed); }
            Ok(())
        })());
        if !matches!(self.packet, Some(Ok(()))) { self.first = Some(First::Packet); return Err(closed); }
        Ok(())
    }

    pub(super) fn parent_failure_is_selected(&self) -> bool {
        matches!(self.first, Some(First::Clock | First::ParentAfter))
    }

    pub(super) fn completed_payload_data(&self) -> Option<&[u8]> {
        if self.first.is_some() || !matches!(self.parent_after, Some(Ok(()))) { return None; }
        Some(self.receive.as_ref()?.as_ref().ok()?.payload())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::PeerBefore => self.peer_before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Poll => self.poll.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Receive => self.receive.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Binding => self.cookie.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.binding.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::SubjectAfter => self.subject_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PeerAfter => self.peer_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Order | First::Clock | First::Packet | First::ParentAfter => None,
        }.or(Some(&FixedServiceOperationClosedV4))
    }
}
