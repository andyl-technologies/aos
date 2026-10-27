//! Retains authenticated pre-READY native child custody on the real Source.
//!
//! PID1's record supplies no adopted Source or effect permission. The genuine
//! borrower matches its actual PREPARED, then validates and retains all three
//! donations through the canonical native PIDFD, cgroup and events engines.
//! ARMED, child bootstrap and actual signed-method admission remain separate.

use super::*;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor,
    RuntimeScopeCgroupOriginalV1, RuntimeScopeMembershipOriginalV1,
    NetworkBirthPopulationDonationOriginalV2, CgroupPopulationMonitor};
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::pidfd::RuntimeScopeReceivedPidFdOriginalV1;
use aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1;
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketReceiveErrorV1, SeqpacketSocket};
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::os::fd::OwnedFd;

#[derive(Clone, Copy)]
enum First { Order, Clock, PeerBefore, Poll, Receive, Binding, Packet, Donations,
    PidFd, Cgroup, Identity, Coordinates, Membership, Events, MembershipAfter,
    SubjectAfter, PeerAfter, ParentAfter }

pub(super) struct BirthOriginalV2 {
    entered: bool,
    before: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    peer_before: Option<Result<bool, aos_linux_descriptors::Error>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    receive: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    cookie: Option<Result<u64, aos_linux_descriptors::Error>>,
    binding: Option<Result<(), RecordBindingError>>,
    packet: Option<Result<(), FixedServiceOperationClosedV4>>,
    donations: Option<Vec<OwnedFd>>,
    raw_pidfd: Option<OwnedFd>,
    raw_cgroup: Option<OwnedFd>,
    raw_events: Option<OwnedFd>,
    pidfd_original: RuntimeScopeReceivedPidFdOriginalV1,
    pidfd_result: Option<Result<(), aos_linux_descriptors::Error>>,
    pidfd: Option<PidFd>,
    cgroup_original: RuntimeScopeCgroupOriginalV1,
    cgroup_result: Option<Result<(), aos_linux_descriptors::Error>>,
    cgroup: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    identity: PidFdProcessIdentityOriginalV1,
    identity_result: Option<Result<(), aos_linux_descriptors::Error>>,
    membership: RuntimeScopeMembershipOriginalV1,
    membership_result: Option<Result<(), aos_linux_descriptors::Error>>,
    events: NetworkBirthPopulationDonationOriginalV2,
    events_result: Option<Result<(), aos_linux_descriptors::Error>>,
    membership_after: RuntimeScopeMembershipOriginalV1,
    membership_after_result: Option<Result<(), aos_linux_descriptors::Error>>,
    subject_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    peer_after: Option<Result<bool, aos_linux_descriptors::Error>>,
    parent_after: Option<Result<(), FixedServiceOperationClosedV4>>,
    owed_source: [FixedServiceCurrentnessSampleV1<FixedServiceOperationClosedV4>; 2],
    owed_source_results: [Option<Result<(), FixedServiceOperationClosedV4>>; 2],
    posts_entered: bool,
    first: Option<First>,
}

impl BirthOriginalV2 {
    pub(super) fn issued_original<'a>(primary: &'a Option<Self>, owed: &'a Option<Self>) -> Option<&'a Self> {
        primary.as_ref().filter(|value| value.issued_packet_data().is_some())
            .or_else(|| owed.as_ref().filter(|value| value.issued_packet_data().is_some()))
    }

    pub(super) fn new() -> Self {
        Self { entered: false, before: None, peer_before: None, poll: None,
            receive: None, cookie: None, binding: None, packet: None,
            donations: None, raw_pidfd: None, raw_cgroup: None, raw_events: None,
            pidfd_original: RuntimeScopeReceivedPidFdOriginalV1::new(),
            pidfd_result: None, pidfd: None,
            cgroup_original: RuntimeScopeCgroupOriginalV1::new(),
            cgroup_result: None, cgroup: None,
            identity: PidFdProcessIdentityOriginalV1::new(), identity_result: None,
            membership: RuntimeScopeMembershipOriginalV1::new(), membership_result: None,
            events: NetworkBirthPopulationDonationOriginalV2::new(), events_result: None,
            membership_after: RuntimeScopeMembershipOriginalV1::new(), membership_after_result: None,
            subject_after: None, peer_after: None, parent_after: None,
            owed_source: std::array::from_fn(|_| Default::default()),
            owed_source_results: [None, None], posts_entered: false, first: None }
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let receive = SeqpacketSocket::network_birth_handoff_receive_obligations_v2().ok_or(overflow)?;
        let pidfd = RuntimeScopeReceivedPidFdOriginalV1::receiving_demand_v1().ok_or(overflow)?;
        let cgroup = RuntimeScopeCgroupOriginalV1::receiving_demand_v1().ok_or(overflow)?;
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1().ok_or(overflow)?;
        let membership = RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1().ok_or(overflow)?;
        let events = NetworkBirthPopulationDonationOriginalV2::receiving_obligations_data_v2().ok_or(overflow)?;
        let bytes = receive.0.checked_add(pidfd.0).and_then(|n| n.checked_add(cgroup.0))
            .and_then(|n| n.checked_add(identity.0)).and_then(|n| n.checked_add(membership.0.checked_mul(2)?))
            .and_then(|n| n.checked_add(events.0))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<PollFd<'_>>()))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<Timespec>())).ok_or(overflow)?;
        // The exact input PIDFD and cgroup right were already included in
        // receive. Their validators may not bill these same donations twice.
        let files = receive.1.checked_add(pidfd.1.checked_sub(1).ok_or(overflow)?)
            .and_then(|n| n.checked_add(cgroup.1.checked_sub(1)?))
            .and_then(|n| n.checked_add(identity.1))
            .and_then(|n| n.checked_add(membership.1.checked_mul(2)?))
            .and_then(|n| n.checked_add(events.1)).ok_or(overflow)?;
        let names = cgroup.2.checked_add(membership.2.checked_mul(2).ok_or(overflow)?)
            .and_then(|n| n.checked_add(events.2)).ok_or(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow)?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow)?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow)?))
    }

    pub(super) fn owed_dynamic_demand() -> Result<ResourceVector, AccountingError> {
        Self::dynamic_demand()?
            .checked_add(FixedServiceCurrentnessSampleV1::<FixedServiceOperationClosedV4>::dynamic_demand()?)?
            .checked_add(FixedServiceCurrentnessSampleV1::<FixedServiceOperationClosedV4>::dynamic_demand()?)
    }

    pub(super) fn receive_once(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>,
        request: &[u8; 496], prepared: &[u8]) -> Result<(), FixedServiceOperationClosedV4>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        let _ = self.receive_inner(loan, request, prepared, false);
        self.observe_posts(loan, false);
        if self.first.is_some() { Err(FixedServiceOperationClosedV4) } else { Ok(()) }
    }

    // This distinct original never repeats an entered positive receive or
    // retires its failed prefix. It drains only the same issued donation.
    pub(super) fn receive_owed_once(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>,
        request: &[u8; 496], prepared: &[u8]) -> Result<(), FixedServiceOperationClosedV4>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        let mut scope = OwedBirthAfterV2 { original: self, loan };
        scope.original.owed_source_results[0] = Some(observe(scope.loan.common, &mut scope.original.owed_source[0]));
        if !matches!(scope.original.owed_source_results[0], Some(Ok(()))) {
            scope.original.first.get_or_insert(First::ParentAfter);
        }
        let _ = scope.original.receive_inner(scope.loan, request, prepared, true);
        scope.original.observe_posts(scope.loan, true);
        let failed = scope.original.first.is_some();
        drop(scope);
        if failed { Err(FixedServiceOperationClosedV4) } else { Ok(()) }
    }

    fn observe_posts(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>, owed: bool) {
        if self.posts_entered { return; }
        self.posts_entered = true;

        // Each obligation is independent. In particular, a malformed donation
        // cannot suppress the actual manager pin or same Source after.
        if let (Some(process), Some((_, anchor))) = (self.pidfd.as_ref(), self.cgroup.as_ref()) {
            self.membership_after_result = Some(self.membership_after.capture_once(anchor, process, None));
            if !matches!(self.membership_after_result, Some(Ok(()))) {
                self.first.get_or_insert(First::MembershipAfter);
            }
        }
        if let Some(Ok(record)) = self.receive.as_ref() {
            self.subject_after = Some(record.subject().is_alive());
            if !matches!(self.subject_after, Some(Ok(true))) { self.first.get_or_insert(First::SubjectAfter); }
        }
        if let Some(Ok(channel)) = loan.common.channel.as_ref() {
            self.peer_after = Some(channel.peer().is_alive());
            if !matches!(self.peer_after, Some(Ok(true))) { self.first.get_or_insert(First::PeerAfter); }
        } else { self.first.get_or_insert(First::ParentAfter); }
        if owed {
            self.owed_source_results[1] = Some(observe(loan.common, &mut self.owed_source[1]));
            if !matches!(self.owed_source_results[1], Some(Ok(()))) { self.first.get_or_insert(First::ParentAfter); }
        } else {
            self.parent_after = Some(loan.require_network_worker_current_v4());
            if !matches!(self.parent_after, Some(Ok(()))) { self.first.get_or_insert(First::ParentAfter); }
        }
    }

    fn receive_inner(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>, request: &[u8; 496],
        prepared: &[u8], owed: bool) -> Result<(), FixedServiceOperationClosedV4>
    {
        if !owed {
            self.before = Some(loan.observe_network_worker_effect_clock_v4());
            let Some(Ok(before)) = self.before else { return self.refuse(First::Clock); };
            let (_, deadline) = match loan.retained_network_horizon_data_v4() {
                Ok(interval) => interval, Err(_) => return self.refuse(First::Clock),
            };
            let timeout = deadline.checked_sub(before.boottime_nanoseconds())
                .and_then(|remaining| Timespec::try_from(std::time::Duration::from_nanos(remaining)).ok());
            let Some(timeout) = timeout else { return self.refuse(First::Clock); };
            let Some(Ok(channel)) = loan.common.channel.as_mut() else { return self.refuse(First::Order); };
            self.peer_before = Some(channel.peer().is_alive());
            if !matches!(self.peer_before, Some(Ok(true))) { return self.refuse(First::PeerBefore); }
            let descriptor = match channel.as_fd() { Ok(fd) => fd, Err(_) => return self.refuse(First::Order) };
            let mut descriptors = [PollFd::new(&descriptor, PollFlags::IN)];
            self.poll = Some(poll(&mut descriptors, Some(&timeout)));
            if !matches!(self.poll, Some(Ok(1))) || !descriptors[0].revents().contains(PollFlags::IN) {
                return self.refuse(First::Poll);
            }
        }
        let Some(Ok(channel)) = loan.common.channel.as_mut() else { return self.refuse(First::Order); };
        if owed {
            self.peer_before = Some(channel.peer().is_alive());
            if !matches!(self.peer_before, Some(Ok(true))) { self.first.get_or_insert(First::PeerBefore); }
        }
        self.receive = Some(channel.receive_network_birth_handoff_retaining_v2());
        let Some(Ok(record)) = self.receive.as_ref() else { return self.refuse(First::Receive); };
        self.binding = Some(channel.require_network_birth_handoff_origin_retaining_v2(record, &mut self.cookie));
        if !matches!(self.binding, Some(Ok(()))) { return self.refuse(First::Binding); }
        let credentials = record.subject().credentials();
        let peer = channel.peer();
        self.packet = Some(if receipt_is_bound(request, prepared, record.payload())
            && credentials.pid().get() == 1 && credentials.uid() == 0 && credentials.gid() == 0
            && peer.credentials().pid().get() == 1 && peer.credentials().uid() == 0
            && peer.credentials().gid() == 0 && peer.initial_info() == record.subject().initial_info()
            && record.descriptors().len() == 3 { Ok(()) } else { Err(FixedServiceOperationClosedV4) });
        if !matches!(self.packet, Some(Ok(()))) { return self.refuse(First::Packet); }
        let Some(Ok(record)) = self.receive.as_mut() else { return self.refuse(First::Receive); };
        self.donations = record.take_network_birth_handoff_descriptors_data_v2();
        let Some(donations) = self.donations.as_mut() else { return self.refuse(First::Donations); };
        // Move the complete table into resident role slots before validating
        // any role; every remaining right survives an earlier native refusal.
        self.raw_events = donations.pop();
        self.raw_cgroup = donations.pop();
        self.raw_pidfd = donations.pop();
        let Some(pidfd) = self.raw_pidfd.take() else { return self.refuse(First::Donations); };
        self.pidfd_result = Some(self.pidfd_original.capture_once(pidfd));
        if !matches!(self.pidfd_result, Some(Ok(()))) { return self.refuse(First::PidFd); }
        self.pidfd = self.pidfd_original.take_completed_once();
        let Some(cgroup) = self.raw_cgroup.take() else { return self.refuse(First::Donations); };
        self.cgroup_result = Some(self.cgroup_original.capture_once(cgroup));
        if !matches!(self.cgroup_result, Some(Ok(()))) { return self.refuse(First::Cgroup); }
        self.cgroup = self.cgroup_original.take_completed_once();
        let (Some(process), Some((_, anchor))) = (self.pidfd.as_ref(), self.cgroup.as_ref())
            else { return self.refuse(First::Donations); };
        self.identity_result = Some(self.identity.capture_once(process));
        if !matches!(self.identity_result, Some(Ok(()))) { return self.refuse(First::Identity); }
        let Some(identity) = self.identity.identity() else { return self.refuse(First::Identity); };
        let Some(Ok(record)) = self.receive.as_ref() else { return self.refuse(First::Receive); };
        let packet = record.payload();
        if packet[128..136] != u64::from(identity.pid()).to_be_bytes()
            || packet[136..144] != identity.start_time_ticks().to_be_bytes()
            || packet[144..152] != anchor.kernel_id().to_be_bytes()
            || identity.thread_group_id() != identity.pid() || identity.parent_pid() != 1
            || identity.cgroup_id() != Some(anchor.kernel_id()) {
            return self.refuse(First::Coordinates);
        }
        self.membership_result = Some(self.membership.capture_once(anchor, process, None));
        if !matches!(self.membership_result, Some(Ok(()))) { return self.refuse(First::Membership); }
        self.events_result = Some(self.events.capture_once_v2(&mut self.raw_events, anchor));
        if !matches!(self.events_result, Some(Ok(()))) { return self.refuse(First::Events); }
        Ok(())
    }

    fn refuse(&mut self, cause: First) -> Result<(), FixedServiceOperationClosedV4> {
        self.first.get_or_insert(cause);
        Err(FixedServiceOperationClosedV4)
    }

    pub(super) fn parent_failure_is_selected(&self) -> bool {
        matches!(self.first, Some(First::Clock | First::ParentAfter))
    }

    pub(super) fn retained_native_data(&self)
        -> Option<(&PidFd, &RetainedCgroupAnchor, &CgroupPopulationMonitor)>
    {
        Some((self.pidfd.as_ref()?, &self.cgroup.as_ref()?.1, self.events.monitor_data_v2()?))
    }

    pub(super) fn retained_pidfd_data(&self) -> Option<&PidFd> { self.pidfd.as_ref() }

    pub(super) fn retained_cgroup_data(&self) -> Option<&RetainedCgroupAnchor> {
        Some(&self.cgroup.as_ref()?.1)
    }

    pub(super) fn retained_monitor_data(&self) -> Option<&CgroupPopulationMonitor> {
        self.events.monitor_data_v2()
    }

    pub(super) fn completed_packet_data(&self) -> Option<&[u8]> {
        if self.first.is_some() || !matches!(self.parent_after, Some(Ok(()))) { return None; }
        Some(self.receive.as_ref()?.as_ref().ok()?.payload())
    }

    pub(super) fn issued_packet_data(&self) -> Option<&[u8]> {
        // An independently owed Source or child after may have refused after
        // the actual packet and all donated native roles were joined. Keep
        // those issued-child cleanup inputs available without restoring the
        // ordinary completed/admission gate or replacing its earlier cause.
        if !matches!(self.binding, Some(Ok(()))) || !matches!(self.packet, Some(Ok(()))) {
            return None;
        }
        self.retained_native_data()?;
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
            First::PidFd => self.pidfd_original.failure().map(|cause| cause as _),
            First::Cgroup => self.cgroup_original.failure().map(|cause| cause as _),
            First::Identity => self.identity.failure(),
            First::Membership => self.membership.failure().map(|cause| cause as _),
            First::Events => self.events.failure(),
            First::MembershipAfter => self.membership_after.failure().map(|cause| cause as _),
            First::SubjectAfter => self.subject_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PeerAfter => self.peer_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ParentAfter => self.owed_source.iter().find_map(|sample| sample.failure()),
            First::Order | First::Clock | First::Packet | First::Donations | First::Coordinates => None,
        }.or(Some(&FixedServiceOperationClosedV4))
    }
}

// This is only the already-paid after of the exact negative donation drain.
// A caught native unwind never permits replay of the entered receive or post.
struct OwedBirthAfterV2<'a, 'financial> {
    original: &'a mut BirthOriginalV2,
    loan: &'a mut FixedServiceOperationLoanV4<'financial>,
}

impl Drop for OwedBirthAfterV2<'_, '_> {
    fn drop(&mut self) { self.original.observe_posts(self.loan, true); }
}

fn receipt_is_bound(request: &[u8; 496], prepared: &[u8], packet: &[u8]) -> bool {
    prepared.len() == 144 && packet.len() == 160
        && packet[..8] == *b"AOSNFH02" && packet[8..10] == 2_u16.to_be_bytes()
        && packet[10] == request[10] && packet[11] == 0
        && packet[12..16] == 160_u32.to_be_bytes()
        && packet[16..48] == request[16..48] && packet[48..64] != [0; 16]
        && packet[64..96] == prepared[64..96]
        && packet[96..112] == prepared[96..112]
        && packet[112..128] == request[80..96]
        && packet[128..136] != [0; 8] && packet[136..144] != [0; 8]
        && packet[144..152] != [0; 8] && packet[152..160] == [0; 8]
}

#[cfg(test)]
mod tests {
    use super::receipt_is_bound;

    #[test]
    fn receipt_requires_the_actual_prepared_and_original_request_without_any_cleanup_inference() {
        let mut request = [0; 496];
        request[10] = 1;
        request[16..48].fill(3);
        request[80..96].fill(4);
        let mut prepared = [0; 144];
        prepared[64..96].fill(5);
        prepared[96..112].fill(6);
        let mut packet = [0; 160];
        packet[..8].copy_from_slice(b"AOSNFH02");
        packet[8..10].copy_from_slice(&2_u16.to_be_bytes());
        packet[10] = 1;
        packet[12..16].copy_from_slice(&160_u32.to_be_bytes());
        packet[16..48].copy_from_slice(&request[16..48]);
        packet[48..64].fill(7);
        packet[64..96].copy_from_slice(&prepared[64..96]);
        packet[96..112].copy_from_slice(&prepared[96..112]);
        packet[112..128].copy_from_slice(&request[80..96]);
        packet[128..136].copy_from_slice(&10_u64.to_be_bytes());
        packet[136..144].copy_from_slice(&11_u64.to_be_bytes());
        packet[144..152].copy_from_slice(&12_u64.to_be_bytes());

        assert!(receipt_is_bound(&request, &prepared, &packet));
        for offset in (0..48).chain(64..128).chain(152..160) {
            let mut foreign = packet;
            foreign[offset] ^= 1;
            assert!(!receipt_is_bound(&request, &prepared, &foreign), "byte {offset}");
        }
        for range in [48..64, 128..136, 136..144, 144..152] {
            let mut absent = packet;
            absent[range].fill(0);
            assert!(!receipt_is_bound(&request, &prepared, &absent));
        }
        assert!(!receipt_is_bound(&request, &prepared[..143], &packet));
        for length in 0..160 { assert!(!receipt_is_bound(&request, &prepared, &packet[..length])); }
        let mut extended = packet.to_vec();
        extended.push(0);
        assert!(!receipt_is_bound(&request, &prepared, &extended));
    }
}
