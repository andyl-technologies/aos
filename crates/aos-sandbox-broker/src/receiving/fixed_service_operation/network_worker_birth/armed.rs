//! Sends actual custody acknowledgement before PID1 releases child bootstrap.
//!
//! The same parent retains its native child pins, receipt and Source debt. The
//! acknowledgement is a one-way custody fact, not an effect or cleanup grant.

use super::*;
use aos_sandbox_linux::cgroup::{RetainedCgroupAnchor, RuntimeScopeMembershipOriginalV1};
use aos_sandbox_linux::pidfd::PidFd;

#[derive(Clone, Copy)]
enum First { Order, Clock, MembershipBefore, Send, SendAfter, MembershipAfter, ParentAfter }

pub(super) struct ArmedOriginalV2 {
    packet: [u8; 160],
    entered: bool,
    before: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    membership_before: RuntimeScopeMembershipOriginalV1,
    membership_before_result: Option<Result<(), aos_sandbox_linux::Error>>,
    send: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: SeqpacketSendAfterOriginalV1,
    send_after_result: Option<Result<(), RecordBindingError>>,
    membership_after: RuntimeScopeMembershipOriginalV1,
    membership_after_result: Option<Result<(), aos_sandbox_linux::Error>>,
    parent_after: Option<Result<(), FixedServiceOperationClosedV4>>,
    first: Option<First>,
}

impl ArmedOriginalV2 {
    pub(super) fn new() -> Self {
        Self { packet: [0; 160], entered: false, before: None,
            membership_before: RuntimeScopeMembershipOriginalV1::new(), membership_before_result: None,
            send: None, send_after: SeqpacketSendAfterOriginalV1::new(), send_after_result: None,
            membership_after: RuntimeScopeMembershipOriginalV1::new(), membership_after_result: None,
            parent_after: None, first: None }
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let native = RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1().ok_or(overflow)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(native.0.checked_mul(2).ok_or(overflow)?).map_err(|_| overflow)?)
            .with(D::OpenFiles, u64::try_from(native.1.checked_mul(2).ok_or(overflow)?).map_err(|_| overflow)?)
            .with(D::MetadataEntries, u64::try_from(native.2.checked_mul(2).ok_or(overflow)?).map_err(|_| overflow)?))
    }

    pub(super) fn send_once(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>,
        birth: &[u8], process: &PidFd, anchor: &RetainedCgroupAnchor)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        if birth.len() != 160 || birth[..8] != *b"AOSNFH02" {
            return self.refuse(First::Order);
        }
        self.packet.copy_from_slice(birth);
        self.packet[..8].copy_from_slice(b"AOSNFJ02");
        let _ = self.send_inner(loan, process, anchor);

        // Both obligations run after every reached before or send failure.
        // Neither native child movement nor a later Source refusal can replace
        // the earlier transport/cookie result or release custody of its pins.
        self.membership_after_result = Some(self.membership_after.capture_once(anchor, process, None));
        if !matches!(self.membership_after_result, Some(Ok(()))) { self.first.get_or_insert(First::MembershipAfter); }
        self.parent_after = Some(loan.require_network_worker_current_v4());
        if !matches!(self.parent_after, Some(Ok(()))) { self.first.get_or_insert(First::ParentAfter); }
        if self.first.is_some() { Err(FixedServiceOperationClosedV4) } else { Ok(()) }
    }

    fn send_inner(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>, process: &PidFd,
        anchor: &RetainedCgroupAnchor) -> Result<(), FixedServiceOperationClosedV4>
    {
        self.before = Some(loan.observe_network_worker_effect_clock_v4());
        if !matches!(self.before, Some(Ok(_))) { return self.refuse(First::Clock); }
        self.membership_before_result = Some(self.membership_before.capture_once(anchor, process, None));
        if !matches!(self.membership_before_result, Some(Ok(()))) { return self.refuse(First::MembershipBefore); }
        let Some(Ok(channel)) = loan.common.channel.as_mut() else { return self.refuse(First::Order); };
        self.send = Some(channel.send_retaining(&self.packet));
        if !matches!(self.send, Some(Ok(()))) { self.first = Some(First::Send); }
        let failed = self.send.as_ref().and_then(|value| value.as_ref().err());
        self.send_after_result = Some(self.send_after.observe_once_v1(channel, failed));
        if !matches!(self.send_after_result, Some(Ok(()))) { self.first.get_or_insert(First::SendAfter); }
        if self.first.is_some() { Err(FixedServiceOperationClosedV4) } else { Ok(()) }
    }

    fn refuse(&mut self, cause: First) -> Result<(), FixedServiceOperationClosedV4> {
        self.first.get_or_insert(cause);
        Err(FixedServiceOperationClosedV4)
    }

    pub(super) fn parent_failure_is_selected(&self) -> bool {
        matches!(self.first, Some(First::Clock | First::ParentAfter))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::MembershipBefore => self.membership_before.failure().map(|cause| cause as _),
            First::Send => self.send.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SendAfter => self.send_after.failure(),
            First::MembershipAfter => self.membership_after.failure().map(|cause| cause as _),
            First::Order | First::Clock | First::ParentAfter => None,
        }.or(Some(&FixedServiceOperationClosedV4))
    }
}
