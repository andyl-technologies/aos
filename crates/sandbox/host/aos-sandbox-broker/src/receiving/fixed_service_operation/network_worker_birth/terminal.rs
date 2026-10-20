//! Settles actual issued-child custody without renewing its effect deadline.
//!
//! Native disposal is independently owed after a failed or expired effect.
//! The positive reservation prepays and prearms every destination. This lane
//! keeps the earlier D/cause and cannot issue another operation or effect.

use super::*;
use aos_sandbox_linux::cgroup::{CgroupPopulationMonitor, CgroupPopulationState};
use aos_sandbox_linux::pidfd::{PidFd, PidFdNegativeIdentityOriginalV1};
use crate::receiving::receiving_limits::ReceivingContainmentCurrentnessV1;

#[derive(Clone, Copy)]
enum First {
    Order, PrearmBefore, PrearmAfter, Affinity, SourceBefore, LeaderBefore,
    PopulationBefore, Send, SendAfter, LeaderAfter, PopulationAfter, SourceAfter,
}

pub(super) struct SourceSample {
    identity: PidFdNegativeIdentityOriginalV1,
    preparation: Option<Result<(), aos_sandbox_linux::Error>>,
    observation: Option<Result<(), aos_sandbox_linux::Error>>,
    limits: ReceivingContainmentCurrentnessV1,
    aggregate: ReceivingContainmentCurrentnessV1,
    aggregate_result: Option<Result<(), FixedServiceOperationClosedV4>>,
    limits_positive: bool,
    binding_positive: bool,
}

impl SourceSample {
    pub(super) fn new() -> Self {
        Self { identity: PidFdNegativeIdentityOriginalV1::new(), preparation: None,
            observation: None, limits: Default::default(), aggregate: Default::default(),
            aggregate_result: None, limits_positive: false,
            binding_positive: false }
    }

    pub(super) fn prepare(&mut self, loan: &FixedServiceOperationLoanV4<'_>) -> bool {
        self.preparation = Some(loan.common.process.prepare_negative_identity_once_into_v1(&mut self.identity));
        matches!(self.preparation, Some(Ok(())))
    }

    pub(super) fn observe(&mut self, loan: &FixedServiceOperationLoanV4<'_>) -> bool {
        self.observation = Some(loan.common.process.observe_negative_identity_once_v1(&mut self.identity));
        // Same-original controls are independent of the stat comparison. This
        // readonly native sample must run even when that comparison refused.
        if let Some(anchor) = loan.common.cgroup.as_ref() {
            loan.common.limits.observe_current_into(anchor, &mut self.limits);
            self.limits_positive = self.limits.require_current().is_ok();
        }
        if let Some(aggregate) = loan.common.network_aggregate.as_ref() {
            self.aggregate_result = Some(aggregate.observe_current_into_v4(&mut self.aggregate)
                .map_err(|_| FixedServiceOperationClosedV4));
        }
        self.binding_positive = self.identity.completed_info_v1().is_some_and(|observed| {
            loan.common.membership.as_ref().and_then(|value| value.as_ref().ok()) == Some(&observed)
        });
        matches!(self.observation, Some(Ok(()))) && self.binding_positive && self.limits_positive
            && matches!(self.aggregate_result, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.identity.failure()
            .or_else(|| self.preparation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.observation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.limits.failure())
            .or_else(|| self.aggregate.failure())
    }
}

pub(super) struct TerminalOriginalV2 {
    prearmed: bool,
    entered: bool,
    invocation: Option<[u8; 16]>,
    ordinal: Option<u64>,
    purpose: Option<NetworkWorkerBirthPurposeV2>,
    source_before: SourceSample,
    source_after: SourceSample,
    packet: [u8; 160],
    leader_before: Option<Result<bool, aos_sandbox_linux::Error>>,
    population_before: Option<Result<CgroupPopulationState, aos_sandbox_linux::Error>>,
    send: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: SeqpacketSendAfterOriginalV1,
    send_after_result: Option<Result<(), RecordBindingError>>,
    leader_after: Option<Result<bool, aos_sandbox_linux::Error>>,
    population_after: Option<Result<CgroupPopulationState, aos_sandbox_linux::Error>>,
    first: Option<First>,
}

impl TerminalOriginalV2 {
    pub(super) fn request_was_sent(&self) -> bool {
        matches!(self.send, Some(Ok(())))
    }

    pub(super) fn new() -> Self {
        Self { prearmed: false, entered: false, invocation: None, ordinal: None,
            purpose: None, source_before: SourceSample::new(), source_after: SourceSample::new(),
            packet: [0; 160], leader_before: None, population_before: None, send: None,
            send_after: SeqpacketSendAfterOriginalV1::new(), send_after_result: None,
            leader_after: None, population_after: None, first: None }
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let identity = PidFdNegativeIdentityOriginalV1::receiving_demand_v1().ok_or(overflow)?;
        // The identity supplier's control/parser census is byte backing, not
        // resident namespace metadata. Its exact one stat duplicate is an OFD.
        let identity = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(identity.0).map_err(|_| overflow)?)
            .with(D::OpenFiles, u64::try_from(identity.1).map_err(|_| overflow)?);
        let controls = ReceivingContainmentCurrentnessV1::fixed_demand();
        let sample = controls.checked_add(controls)?.checked_add(identity)?;
        sample.checked_add(sample)
    }

    pub(super) fn prearm_once(&mut self, loan: &FixedServiceOperationLoanV4<'_>,
        purpose: NetworkWorkerBirthPurposeV2) -> Result<(), FixedServiceOperationClosedV4>
    {
        if self.prearmed || self.invocation.is_some() { return self.refuse(First::Order); }
        self.invocation = loan.operation.invocation;
        self.ordinal = loan.operation.operation_ordinal;
        self.purpose = Some(purpose);
        if !issued_affinity(loan, self.invocation, self.ordinal) { return self.refuse(First::Affinity); }

        // A failed first duplicate cannot suppress the independent second
        // prepaid destination. Both failed originals remain held here.
        if !self.source_before.prepare(loan) { self.first = Some(First::PrearmBefore); }
        if !self.source_after.prepare(loan) { self.first.get_or_insert(First::PrearmAfter); }
        self.prearmed = self.first.is_none();
        if self.prearmed { Ok(()) } else { Err(FixedServiceOperationClosedV4) }
    }

    pub(super) fn send_once(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>,
        birth: &[u8], process: &PidFd, monitor: &CgroupPopulationMonitor)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        if self.entered || !self.prearmed { return self.refuse(First::Order); }
        self.entered = true;
        if !issued_affinity(loan, self.invocation, self.ordinal)
            || birth.len() != 160 || birth[..8] != *b"AOSNFH02"
            || self.purpose.map(|purpose| purpose as u8) != birth.get(10).copied()
            || self.invocation.as_ref().map(|value| value.as_slice()) != birth.get(32..48)
        { return self.refuse(First::Affinity); }
        self.packet.copy_from_slice(birth);
        self.packet[..8].copy_from_slice(b"AOSNFK02");

        if !self.source_before.observe(loan) { self.first.get_or_insert(First::SourceBefore); }
        self.leader_before = Some(process.is_alive());
        if !matches!(self.leader_before, Some(Ok(false))) { self.first.get_or_insert(First::LeaderBefore); }
        self.population_before = Some(monitor.state());
        if !population_is_terminal(&self.population_before) { self.first.get_or_insert(First::PopulationBefore); }
        if self.first.is_none() {
            if let Some(Ok(channel)) = loan.common.channel.as_mut() {
                self.send = Some(channel.send_retaining(&self.packet));
                if !matches!(self.send, Some(Ok(()))) { self.first = Some(First::Send); }
                let failed = self.send.as_ref().and_then(|value| value.as_ref().err());
                self.send_after_result = Some(self.send_after.observe_once_v1(channel, failed));
                if !matches!(self.send_after_result, Some(Ok(()))) { self.first.get_or_insert(First::SendAfter); }
            } else { self.first.get_or_insert(First::Send); }
        }

        // These are owed even after old effect expiry, body/accounting poison,
        // an unexpectedly live child, a bad population read or failed send.
        self.leader_after = Some(process.is_alive());
        if !matches!(self.leader_after, Some(Ok(false))) { self.first.get_or_insert(First::LeaderAfter); }
        self.population_after = Some(monitor.state());
        if !population_is_terminal(&self.population_after) { self.first.get_or_insert(First::PopulationAfter); }
        if !self.source_after.observe(loan) { self.first.get_or_insert(First::SourceAfter); }

        if self.first.is_some() { Err(FixedServiceOperationClosedV4) } else { Ok(()) }
    }

    fn refuse(&mut self, cause: First) -> Result<(), FixedServiceOperationClosedV4> {
        self.first.get_or_insert(cause);
        Err(FixedServiceOperationClosedV4)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::PrearmBefore | First::SourceBefore => self.source_before.failure(),
            First::PrearmAfter | First::SourceAfter => self.source_after.failure(),
            First::LeaderBefore => self.leader_before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PopulationBefore => self.population_before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Send => self.send.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _),
            First::SendAfter => self.send_after.failure(),
            First::LeaderAfter => self.leader_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PopulationAfter => self.population_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Order | First::Affinity => None,
        }.or(Some(&FixedServiceOperationClosedV4))
    }
}

pub(super) fn issued_affinity(loan: &FixedServiceOperationLoanV4<'_>, invocation: Option<[u8; 16]>, ordinal: Option<u64>) -> bool {
    // Deliberately does not inspect effect D, old body/accounting failure or
    // the ordinary healthy gate. This selects already-paid disposal only.
    invocation.is_some() && ordinal.is_some_and(|value| value != 0)
        && invocation == loan.operation.invocation
        && invocation == loan.common.enrollment.map(|value| value.recipient_invocation)
        && ordinal == loan.operation.operation_ordinal && ordinal == Some(loan.common.operation_ordinal)
        && matches!(loan.common.role, FixedServiceRoleV1::Network)
        && matches!(loan.operation.purpose, Some(Purpose::NetworkPrepare | Purpose::NetworkDestroy))
        && loan.operation.armed && !loan.operation.finished && loan.common.operation_active
        && matches!(loan.operation.before_result, Some(Ok(())))
        && matches!(loan.operation.method, Some(Ok(())))
}

fn population_is_terminal(result: &Option<Result<CgroupPopulationState, aos_sandbox_linux::Error>>) -> bool {
    matches!(result, Some(Ok(CgroupPopulationState::Empty | CgroupPopulationState::Retired)))
}
