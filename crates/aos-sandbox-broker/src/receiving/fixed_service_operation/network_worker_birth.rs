//! Reserves child liabilities on the actual held Prepare63 or Destroy9 payer.
//!
//! This module issues no Source or effect authority. Its borrowed reservation
//! cannot outlive the original loan, move an account or refund earlier work.
//! The PID1 prebirth handshake and native child escrow must separately retain
//! and verify that same reservation before a worker can become available.

use super::*;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use sha2::{Digest as _, Sha256};
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketSendErrorV1,
    SeqpacketSendAfterOriginalV1, RecordBindingError};

// This wire geometry is the source's full vector width, never an FD ceiling.
const _: () = assert!(D::COUNT == 22);

mod prepared;
mod birth;
mod armed;
mod terminal;
mod completion;
mod parent_io;
mod domain_custody;
mod issued_cleanup;
mod profile;
mod pair;

/// Names the two physical child purposes shared by Prepare63 and Destroy9.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkWorkerBirthPurposeV2 {
    /// Runs the operation's closed mutation programme.
    Preparation = 1,
    /// Independently observes the same operation's resulting physical state.
    Observation = 2,
}

#[derive(Clone, Copy)]
enum First {
    Source,
    Geometry,
    Funding,
    Reentry,
    Request,
    Send,
    SendAfter,
    Prepared,
    ChildFunding,
    Birth,
    OwedBirth,
    Armed,
    Terminal,
    Completion,
    Profile,
    DomainCustody,
    Cleanup,
    Pair,
}

/// Retains a child invoice and the actual once-only parent reservation result.
///
/// A numeric child demand is only source-derived DATA. The same genuine parent
/// loan, native producer and child recipient must establish all later facts.
#[must_use]
pub struct NetworkWorkerBirthOriginalV2 {
    purpose: Option<NetworkWorkerBirthPurposeV2>,
    source: Option<Result<(), FixedServiceOperationClosedV4>>,
    baseline: Option<Result<ResourceVector, AccountingError>>,
    demand: Option<Result<ResourceVector, AccountingError>>,
    parent_demand: Option<Result<ResourceVector, AccountingError>>,
    fit: Option<Result<ResourceVector, AccountingError>>,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    child_funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    child: Option<ResourceVector>,
    first: Option<First>,
    closed: FixedServiceOperationClosedV4,
    entered: bool,
    prebirth: [u8; 496],
    prebirth_entered: bool,
    prebirth_ready: bool,
    send_before: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    send: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    send_after: Option<SeqpacketSendAfterOriginalV1>,
    send_post: Option<Result<(), RecordBindingError>>,
    send_parent_after: Option<Result<(), FixedServiceOperationClosedV4>>,
    prepared: prepared::PreparedOriginalV2,
    birth: Option<birth::BirthOriginalV2>,
    owed_birth: Option<birth::BirthOriginalV2>,
    armed: Option<armed::ArmedOriginalV2>,
    terminal: Option<terminal::TerminalOriginalV2>,
    completion: Option<completion::CompletionOriginalV3>,
    profile: profile::ProfileOriginalV2,
    domain_custody: domain_custody::DomainCustodyOriginalV2,
    cleanup_entered: bool,
    cleanup_result: Option<Result<(), FixedServiceOperationClosedV4>>,
    issued_cleanup: Option<issued_cleanup::IssuedCleanupOriginalV2>,
    pair: pair::PairOriginalV2,
}

impl NetworkWorkerBirthOriginalV2 {
    /// Quotes the actual parent reservation and native custody programme.
    ///
    /// This passive supplier is identical to the debit used by reservation.
    /// A closed caller may check the full P/O programme before P effects;
    /// each actual child still pays its own demand before creation.
    ///
    /// # Errors
    /// Returns the existing accounting overflow for any native supplier.
    pub fn parent_receiving_demand_v2(
        purpose: NetworkWorkerBirthPurposeV2,
    ) -> Result<ResourceVector, AccountingError> {
        let custody = match purpose {
            NetworkWorkerBirthPurposeV2::Preparation => domain_custody::DomainCustodyOriginalV2::dynamic_demand()?,
            NetworkWorkerBirthPurposeV2::Observation => ResourceVector::ZERO,
        };
        let bytes = std::mem::size_of::<NetworkWorkerBirthOriginalV2>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<NetworkWorkerBirthReservationV2<'_, '_>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .checked_add(prepared::PreparedOriginalV2::dynamic_demand()?)?
            .checked_add(birth::BirthOriginalV2::dynamic_demand()?)?
            .checked_add(birth::BirthOriginalV2::owed_dynamic_demand()?)?
            .checked_add(armed::ArmedOriginalV2::dynamic_demand()?)?
            .checked_add(terminal::TerminalOriginalV2::dynamic_demand()?)?
            .checked_add(completion::CompletionOriginalV3::dynamic_demand()?)?
            .checked_add(issued_cleanup::IssuedCleanupOriginalV2::dynamic_demand()?)?
            .checked_add(custody)
    }

    /// Creates empty fixed destinations without allocation, observation or IO.
    #[must_use]
    pub const fn new() -> Self {
        Self { purpose: None, source: None, baseline: None, demand: None,
            parent_demand: None, fit: None, funding: None, child_funding: None,
            child: None, first: None,
            closed: FixedServiceOperationClosedV4, entered: false,
            prebirth: [0; 496], prebirth_entered: false, prebirth_ready: false,
            send_before: None, send: None, send_after: None, send_post: None,
            send_parent_after: None, prepared: prepared::PreparedOriginalV2::new(), birth: None, owed_birth: None, armed: None, terminal: None, completion: None,
            profile: profile::ProfileOriginalV2::new(),
            domain_custody: domain_custody::DomainCustodyOriginalV2::new(),
            cleanup_entered: false, cleanup_result: None, issued_cleanup: None,
            pair: pair::PairOriginalV2::new() }
    }

    /// Borrows the actual source/arithmetic refusal retained by this original.
    ///
    /// Financial/native parent failures stay on the same borrowed loan; their
    /// selection is reported by [`Self::parent_failure_is_selected_v2`].
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Source => self.source.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Geometry => self.baseline.as_ref().and_then(|value| value.as_ref().err())
                .or_else(|| self.parent_demand.as_ref()?.as_ref().err())
                .or_else(|| self.demand.as_ref()?.as_ref().err())
                .or_else(|| self.fit.as_ref()?.as_ref().err()).map(|cause| cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reentry | First::Request => Some(&self.closed),
            First::Send => self.send.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SendAfter => self.send_after.as_ref()?.failure(),
            First::Prepared => self.prepared.failure(),
            First::ChildFunding => self.child_funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Birth => self.birth.as_ref()?.failure(),
            First::OwedBirth => self.owed_birth.as_ref()?.failure(),
            First::Armed => self.armed.as_ref()?.failure(),
            First::Terminal => self.terminal.as_ref()?.failure(),
            First::Completion => self.completion.as_ref()?.failure(),
            First::DomainCustody => self.domain_custody.failure(),
            First::Cleanup => self.issued_cleanup.as_ref().and_then(|value| value.failure()).or(Some(&self.closed)),
            First::Profile => self.profile.failure(),
            First::Pair => self.pair.failure(),
        };
        cause.or(Some(&self.closed))
    }

    /// Identifies an actual parent-native or same-bank financial refusal.
    #[must_use]
    pub fn parent_failure_is_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::Source | First::Funding | First::ChildFunding))
            || matches!(self.first, Some(First::Pair)) && self.pair.parent_failure_selected()
            || matches!(self.first, Some(First::Prepared)) && self.prepared.parent_failure_is_selected()
            || matches!(self.first, Some(First::Birth)) && self.birth.as_ref().is_some_and(|birth| birth.parent_failure_is_selected())
            || matches!(self.first, Some(First::Armed)) && self.armed.as_ref().is_some_and(|armed| armed.parent_failure_is_selected())
            || matches!(self.first, Some(First::DomainCustody)) && self.domain_custody.parent_failure_is_selected()
            || matches!(self.first, Some(First::Profile)) && self.profile.parent_failure_selected()
            || matches!(self.first, Some(First::Completion)) && self.completion.as_ref()
                .is_some_and(|completion| completion.parent_failure_selected())
    }

    /// Borrows selected memory, NOFILE and task limits after the paid readback.
    ///
    /// These are protected configuration DATA, never a child fee or grant.
    #[must_use]
    pub fn selected_native_limits_data_v2(&self, purpose: NetworkWorkerBirthPurposeV2)
        -> Option<[u64; 3]>
    {
        self.profile.limits(purpose)
    }

    /// Borrows the actual fixed-path argv count from the selected ExecStart.
    #[must_use]
    pub fn selected_argument_count_data_v2(&self, purpose: NetworkWorkerBirthPurposeV2)
        -> Option<usize>
    {
        self.profile.argument_count(purpose)
    }
}

impl Default for NetworkWorkerBirthOriginalV2 {
    fn default() -> Self { Self::new() }
}

/// Borrows the genuine payer beside its positive, nonrefundable child invoice.
///
/// This is financial custody only. No method exports an account, constructs
/// a native Source, admits a child from a packet, or confirms any effect.
#[must_use]
pub struct NetworkWorkerBirthReservationV2<'held, 'financial> {
    loan: &'held mut FixedServiceOperationLoanV4<'financial>,
    original: &'held mut NetworkWorkerBirthOriginalV2,
}

impl NetworkWorkerBirthReservationV2<'_, '_> {
    /// Retains PID1's actual same-worker exit and final Unit status after K.
    ///
    /// This once-only nonblocking bookkeeping remains owed after the old D or an
    /// earlier failure. It cannot renew Source or make negative cleanup positive.
    /// A known original K send and complete issued Birth affinity are required.
    ///
    /// # Errors
    /// Retains missing custody, original native/status refusal and every post.
    pub fn receive_owed_birth_completion_once_v3(&mut self)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        self.receive_birth_completion_v3(false)
    }

    fn receive_birth_completion_v3(&mut self, positive: bool)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        let sent = self.original.terminal.as_ref()
            .is_some_and(terminal::TerminalOriginalV2::request_was_sent);
        let packet = birth::BirthOriginalV2::issued_original(
            &self.original.birth, &self.original.owed_birth)
            .and_then(|birth| birth.issued_packet_data());
        let result = match (self.original.completion.as_mut(), packet) {
            (Some(completion), Some(packet)) => completion.receive_once(self.loan, packet, sent, positive),
            _ => Err(FixedServiceOperationClosedV4),
        };
        if result.is_err() {
            self.original.first.get_or_insert(First::Completion);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Body));
        }
        Ok(())
    }

    /// Joins actual child exit success with this parent's unchanged live D.
    ///
    /// The received child facts never replace the real parent Source, bank,
    /// effect clock, result or independent native posts. Only this successful
    /// join records the P/O success bit; K retirement is independent.
    ///
    /// # Errors
    /// Refuses negative/malformed status, old parent poison, expired original D,
    /// incomplete posts or repeated confirmation, preserving the first cause.
    pub fn require_positive_birth_completion_v3(&mut self)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        self.receive_birth_completion_v3(true)?;
        let result = match self.original.completion.as_mut() {
            Some(completion) => completion.confirm_positive(self.loan),
            None => Err(FixedServiceOperationClosedV4),
        };
        if result.is_err() {
            self.original.first.get_or_insert(First::Completion);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Body));
        }
        let Some(purpose) = self.original.purpose else {
            self.original.first.get_or_insert(First::Completion);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        self.loan.operation.worker_success_mask |= 1 << (purpose as u8 - 1);
        Ok(())
    }

    /// Borrows the retained native/status cause without replacing earlier errors.
    #[must_use]
    pub fn completion_failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.original.completion.as_ref()?.failure()
    }

    /// Sends the independently owed issued-child terminal custody record once.
    ///
    /// This separately prepaid lane may run after the effect deadline or an
    /// earlier body/financial refusal. It retains that earlier cause and D.
    /// Only actual held PIDFD death and the same native events Empty/Retired
    /// permit this exact AOSNFK02 record. Source/control, cookie and child posts
    /// remain independent. It grants no effect, Source renewal or bank refund.
    ///
    /// # Errors
    /// Refuses absent issued native custody, missing positive prearm, reentry,
    /// changed original affinity, actual liveness/population, send or any post.
    pub fn send_owed_birth_terminal_once_v2(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        let inputs = birth::BirthOriginalV2::issued_original(&self.original.birth, &self.original.owed_birth).and_then(|birth| {
            Some((birth.issued_packet_data()?, birth.retained_native_data()?))
        });
        let Some((packet, (process, _, monitor))) = inputs else {
            self.original.first.get_or_insert(First::Terminal);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        let Some(terminal) = self.original.terminal.as_mut() else {
            self.original.first.get_or_insert(First::Terminal);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        if terminal.send_once(self.loan, packet, process, monitor).is_err() {
            self.original.first.get_or_insert(First::Terminal);
            Err(self.loan.refuse_network_worker_birth_v2(Failure::Body))
        } else {
            let Some(purpose) = self.original.purpose else {
                self.original.first.get_or_insert(First::Terminal);
                return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
            };
            self.loan.operation.worker_terminal_mask |= 1 << (purpose as u8 - 1);
            Ok(())
        }
    }

    /// Borrows this independently owed disposition's selected original cause.
    ///
    /// The ordinary failure getter continues to select any earlier cause.
    #[must_use]
    pub fn terminal_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.original.terminal.as_ref()?.failure()
    }

    /// Sends actual parent custody acknowledgement on the same Source channel.
    ///
    /// Only the completed native birth join may enter this once-only send.
    /// PID1 separately authenticates it before releasing the child's bootstrap.
    /// The real child, parent Source, native cookie and every reached failure
    /// remain retained. Success supplies no signed-method admission or effect.
    ///
    /// # Errors
    /// Refuses missing native custody, repeated entry, stale unchanged D,
    /// actual child membership, transport, cookie or independent native posts.
    pub fn send_birth_armed_once_v2(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if self.original.first.is_some() || self.original.armed.is_some() {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        let Some(birth) = self.original.birth.as_ref() else {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        let (Some(packet), Some((process, anchor, _))) =
            (birth.completed_packet_data(), birth.retained_native_data()) else {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        self.original.armed = Some(armed::ArmedOriginalV2::new());
        let Some(armed) = self.original.armed.as_mut() else {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        if armed.send_once(self.loan, packet, process, anchor).is_err() {
            self.original.first.get_or_insert(First::Armed);
            Err(self.loan.refuse_network_worker_birth_v2(Failure::Body))
        } else { Ok(()) }
    }

    /// Borrows a reached actual PIDFD even when another donation refused.
    #[must_use]
    pub fn retained_birth_pidfd_data_v2(&self) -> Option<&aos_sandbox_linux::pidfd::PidFd> {
        self.original.birth.as_ref().and_then(|birth| birth.retained_pidfd_data())
            .or_else(|| self.original.owed_birth.as_ref()?.retained_pidfd_data())
    }

    /// Borrows a reached actual cgroup anchor without granting admission.
    #[must_use]
    pub fn retained_birth_cgroup_data_v2(&self) -> Option<&aos_sandbox_linux::cgroup::RetainedCgroupAnchor> {
        self.original.birth.as_ref().and_then(|birth| birth.retained_cgroup_data())
            .or_else(|| self.original.owed_birth.as_ref()?.retained_cgroup_data())
    }

    /// Borrows a completed native events join without inferring population.
    #[must_use]
    pub fn retained_birth_monitor_data_v2(&self) -> Option<&aos_sandbox_linux::cgroup::CgroupPopulationMonitor> {
        self.original.birth.as_ref().and_then(|birth| birth.retained_monitor_data())
            .or_else(|| self.original.owed_birth.as_ref()?.retained_monitor_data())
    }

    /// Receives and validates actual native child custody before any READY.
    ///
    /// The same reservation already paid the complete native receiver before
    /// prebirth. The PID1 packet, subject and all three rights stay retained on
    /// this original even when a role check or independently owed post fails.
    /// This does not send ARMED, admit a child, grant an effect or prove cleanup.
    ///
    /// # Errors
    /// Refuses absent actual PREPARED, repeated entry, the original unchanged
    /// deadline, native transport, donated roles, identity or any owed post.
    pub fn receive_birth_custody_once_v2(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if self.original.first.is_some() || self.original.birth.is_some() {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        let Some(prepared) = self.original.prepared.completed_payload_data() else {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        self.original.birth = Some(birth::BirthOriginalV2::new());
        let Some(birth) = self.original.birth.as_mut() else {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        if birth.receive_once(self.loan, &self.original.prebirth, prepared).is_err() {
            self.original.first.get_or_insert(First::Birth);
            Err(self.loan.refuse_network_worker_birth_v2(Failure::Body))
        } else { Ok(()) }
    }

    /// Drains the already-issued birth donation once without renewing Source.
    ///
    /// This prepaid negative lane uses the same actual Source channel and
    /// exact PREPARED request/challenge/ordinal. It performs one nonblocking
    /// strict receive and the existing native donation validators and posts.
    /// Neither expired D nor primary poison can suppress this disposition;
    /// absent or uncertain donation retains unresolved custody, never absence.
    /// The ordinary ARMED and positive admission gate cannot use this result.
    ///
    /// # Errors
    /// Refuses missing original preparation, repeated drain, unavailable or
    /// malformed donation, foreign native roles, or independently owed posts.
    pub fn receive_owed_birth_custody_once_v2(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if self.original.owed_birth.is_some() || !self.original.prebirth_ready {
            self.original.first.get_or_insert(First::OwedBirth);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        let Some(prepared) = self.original.prepared.completed_payload_data() else {
            self.original.first.get_or_insert(First::OwedBirth);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };
        self.loan.common.operation_closed = true;
        self.loan.operation.fail(Failure::Body);
        self.original.owed_birth = Some(birth::BirthOriginalV2::new());
        let Some(birth) = self.original.owed_birth.as_mut() else {
            return Err(FixedServiceOperationClosedV4);
        };
        let earlier = self.original.first;
        self.original.first.get_or_insert(First::OwedBirth);
        let result = birth.receive_owed_once(self.loan, &self.original.prebirth, prepared);
        if result.is_ok() { self.original.first = earlier; }
        result
    }

    /// Borrows reached actual native cleanup pins without a disposition claim.
    ///
    /// A fully correlated owed donation can supply only negative disposition.
    ///
    /// A failed later post never discards a completed native donation join.
    /// These retained originals alone prove no leader death or Empty/Retired.
    #[must_use]
    pub fn retained_birth_native_data_v2(&self) -> Option<(
        &aos_sandbox_linux::pidfd::PidFd,
        &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        &aos_sandbox_linux::cgroup::CgroupPopulationMonitor,
    )> {
        birth::BirthOriginalV2::issued_original(&self.original.birth, &self.original.owed_birth)?
            .retained_native_data()
    }

    /// Borrows the same ledger's original selected financial refusal.
    ///
    /// No account or mutable ledger escapes this short diagnostic borrow.
    #[must_use]
    pub fn failure_with_parent_v2(&self) -> Option<&(dyn Error + 'static)> {
        if matches!(self.original.first, Some(First::DomainCustody))
            && self.original.domain_custody.parent_failure_is_selected() {
            return self.loan.failure().or_else(|| self.original.failure());
        }
        if matches!(self.original.first, Some(First::Funding | First::ChildFunding)) {
            return self.loan.common.representation.as_ref()
                .and_then(|ledger| ledger.failure()).map(|cause| cause as _)
                .or_else(|| self.original.failure());
        }
        self.original.failure()
    }

    /// Receives actual PID1 PREPARED on this reservation's same Source channel.
    ///
    /// The complete receiver was charged by the original reservation before
    /// native entry. Its original deadline is sampled and reused without a
    /// retry, timeout renewal or substitute Source/effect constructor.
    ///
    /// # Errors
    /// Retains every reached poll/receive/subject/cookie/native-post failure;
    /// refuses a missing actual send, wrong prepared binding or repeated entry.
    pub fn receive_prepared_once_v2(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.original.send, Some(Ok(()))) || self.original.first.is_some() {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        let result = self.original.prepared.receive_once(self.loan, &self.original.prebirth);
        if result.is_err() {
            self.original.first.get_or_insert(First::Prepared);
            Err(self.loan.refuse_network_worker_birth_v2(Failure::Body))
        } else { Ok(()) }
    }

    /// Sends prebirth on this same enrolled Netd Source's retained PID1 channel.
    ///
    /// The exact fixed request is resident before the fresh paid clock gate.
    /// Every reached send, native cookie post and independent financial post
    /// remains owned here; a later post never replaces an earlier send refusal.
    /// Success means only that the prebirth request was atomically sent. The
    /// actual PREPARED, birth custody, child bootstrap and effects remain owed.
    ///
    /// # Errors
    /// Permanently fences positive entry for missing preparation, repeated
    /// send, original clock failure, native transport or either post refusal.
    pub fn send_prebirth_once_v2(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !self.original.prebirth_ready || self.original.send_before.is_some()
            || self.original.first.is_some() {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        self.original.send_before = Some(self.loan.observe_network_worker_effect_clock_v4());
        if !matches!(self.original.send_before, Some(Ok(_))) {
            self.original.first = Some(First::Source);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Clock));
        }
        let channel = self.loan.common.channel.as_mut().and_then(|value| value.as_mut().ok());
        if let Some(channel) = channel {
            self.original.send = Some(channel.send_retaining(&self.original.prebirth));
            if !matches!(self.original.send, Some(Ok(()))) { self.original.first = Some(First::Send); }
            self.original.send_after = Some(SeqpacketSendAfterOriginalV1::new());
            if let Some(post) = self.original.send_after.as_mut() {
                let failed = self.original.send.as_ref().and_then(|value| value.as_ref().err());
                self.original.send_post = Some(post.observe_once_v1(channel, failed));
                if !matches!(self.original.send_post, Some(Ok(()))) {
                    self.original.first.get_or_insert(First::SendAfter);
                }
            }
        } else {
            self.original.first = Some(First::Source);
        }
        self.original.send_parent_after = Some(self.loan.require_network_worker_current_v4());
        if !matches!(self.original.send_parent_after, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Source);
        }
        if self.original.first.is_some() {
            Err(self.loan.refuse_network_worker_birth_v2(Failure::Body))
        } else { Ok(()) }
    }

    /// Encodes the actual same-payer prebirth request into its prepaid fixed slot.
    ///
    /// Boot, Source invocation, parent commitment, ordinal, fee and retained
    /// baseline come from the continuously held original. The authenticated
    /// request supplies correlation DATA; the effect digest and probe count
    /// must come from the caller's same compiled signed63 or signed9 programme.
    /// This packet grants no effect permission, child Source or new bank.
    ///
    /// # Errors
    /// Permanently fences the parent for reentry, wrong authenticated method,
    /// missing same-source native identity, zero count or stale original D.
    pub fn prepare_prebirth_data_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        effect: ObjectDigest,
        probe_count: u64,
    ) -> Result<&[u8; 496], FixedServiceOperationClosedV4> {
        if self.original.prebirth_entered {
            self.original.first.get_or_insert(First::Reentry);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        self.original.prebirth_entered = true;
        if self.loan.require_network_worker_current_v4().is_err() {
            self.original.first.get_or_insert(First::Source);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        let fields = (|| {
            let enrollment = self.loan.common.enrollment.ok_or(self.original.closed)?;
            let purpose = self.original.purpose.ok_or(self.original.closed)?;
            let child = self.child_fee_data_v2().ok_or(self.original.closed)?;
            let baseline = self.parent_baseline_data_v2().ok_or(self.original.closed)?;
            let ordinal = self.loan.operation.operation_ordinal.ok_or(self.original.closed)?;
            let (_, deadline) = self.loan.retained_network_horizon_data_v4()?;
            if !self.loan.network_worker_request_matches_v4(request)
                || request.request_id() == [0; 16] || effect.as_bytes() == &[0; 32]
                || probe_count == 0 || ordinal == 0
                || deadline > request.deadline_boottime_nanoseconds()
                || self.loan.common.parent_len == 0
                || self.loan.common.parent_len > self.loan.common.parent_bytes.len()
            { return Err(self.original.closed); }
            let parent: [u8; 32] = Sha256::digest(&self.loan.common.parent_bytes[
                ..self.loan.common.parent_len]).into();
            Ok((enrollment, purpose, child, baseline, ordinal, parent))
        })();
        let (enrollment, purpose, child, baseline, ordinal, parent) = match fields {
            Ok(fields) => fields,
            Err(_) => {
                self.original.first.get_or_insert(First::Request);
                return Err(self.loan.refuse_network_worker_birth_v2(Failure::Body));
            }
        };

        let bytes = &mut self.original.prebirth;
        bytes[..8].copy_from_slice(b"AOSNFR02");
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes[10] = purpose as u8;
        bytes[12..16].copy_from_slice(&496_u32.to_be_bytes());
        bytes[16..32].copy_from_slice(&enrollment.identity.native_fields().boot);
        bytes[32..48].copy_from_slice(&enrollment.recipient_invocation);
        bytes[48..80].copy_from_slice(&parent);
        bytes[80..96].copy_from_slice(&request.request_id());
        bytes[96..128].copy_from_slice(effect.as_bytes());
        bytes[128..136].copy_from_slice(&ordinal.to_be_bytes());
        bytes[136..144].copy_from_slice(&probe_count.to_be_bytes());
        for (index, dimension) in D::ALL.into_iter().enumerate() {
            let offset = 144 + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&child.get(dimension).to_be_bytes());
            let offset = 320 + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&baseline.get(dimension).to_be_bytes());
        }
        self.original.prebirth_ready = true;
        Ok(&self.original.prebirth)
    }

    /// Borrows the actual purpose of the original child reservation.
    #[must_use]
    pub fn purpose_data_v2(&self) -> Option<NetworkWorkerBirthPurposeV2> {
        self.original.purpose
    }

    /// Borrows charged parent liabilities from before this child debit.
    #[must_use]
    pub fn parent_baseline_data_v2(&self) -> Option<ResourceVector> {
        let baseline = *self.original.baseline.as_ref()?.as_ref().ok()?;
        let demand = *self.original.demand.as_ref()?.as_ref().ok()?;
        let child = self.original.child?;
        // The parent escrow original itself stays resident beside the child.
        // Its backing was included in the actual debit, not the child's fee.
        baseline.checked_add(demand.checked_sub(child).ok()?).ok()
    }

    /// Borrows the exact additional child liabilities, without physical credit.
    #[must_use]
    pub fn child_fee_data_v2(&self) -> Option<ResourceVector> { self.original.child }

    /// Checks the same original worker interval without a new deadline.
    ///
    /// # Errors
    /// Retains the parent's existing refusal for stale, foreign or poisoned entry.
    pub fn require_parent_current_v2(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        self.loan.require_network_worker_current_v4()
    }
}

impl<'financial> FixedServiceOperationLoanV4<'financial> {
    /// Prepays and retains the final selected P/O unit profile before PREBIRTH.
    ///
    /// The same actual signed operation pays the complete bounded file owner
    /// before opening its protected image-produced input. Physical readbacks
    /// and the independent parent after remain owed after any reached failure.
    /// The result supplies comparison and cost DATA only, never a child grant.
    ///
    /// # Errors
    /// Retains reentry, genuine parent/financial refusal, native open/readback,
    /// bounded literal syntax, selected-command digest or independent after.
    pub fn read_network_worker_profile_once_v2(&mut self,
        original: &mut NetworkWorkerBirthOriginalV2,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if original.entered || original.first.is_some() {
            original.first.get_or_insert(First::Reentry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        }
        if original.profile.capture_once(self).is_err() {
            original.first.get_or_insert(First::Profile);
            return Err(self.refuse_network_worker_birth_v2(Failure::Body));
        }
        Ok(())
    }

    /// Reserves actual additional child liabilities before native prebirth IO.
    ///
    /// The complete earlier ledger debt stays charged. OpenFiles are joined to
    /// the same F3 liability for parent receipts only. The already-debited
    /// permanent parent FD envelope remains in the ledger. Child FD debt is
    /// genuinely additional and enters that SAME ledger directly; it cannot
    /// be zeroed into the parent's recurring counter or create another bank.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete native entry, reentry, source quote
    /// failure, overflow, insufficient capacity or the actual same-ledger debit.
    /// Every reached result remains on its original owner before any growth.
    pub fn reserve_network_worker_birth_once_v2<'held>(
        &'held mut self,
        original: &'held mut NetworkWorkerBirthOriginalV2,
        purpose: NetworkWorkerBirthPurposeV2,
        child_fee: Result<ResourceVector, AccountingError>,
    ) -> Result<NetworkWorkerBirthReservationV2<'held, 'financial>, FixedServiceOperationClosedV4> {
        let birth_bit = 1 << (purpose as u8 - 1);
        let wrong_order = matches!(purpose, NetworkWorkerBirthPurposeV2::Observation)
            && (self.operation.worker_birth_mask != 1 || self.operation.worker_terminal_mask & 1 == 0
                || self.operation.worker_success_mask & 1 == 0);
        if original.entered || self.operation.worker_birth_mask & birth_bit != 0 || wrong_order {
            original.first.get_or_insert(First::Reentry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        }
        self.operation.worker_birth_mask |= birth_bit;
        original.entered = true;
        original.purpose = Some(purpose);
        original.source = Some(self.require_network_worker_current_v4());
        if !matches!(original.source, Some(Ok(()))) {
            original.first = Some(First::Source);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        }
        original.baseline = Some((|| {
            let overflow = AccountingError::ArithmeticOverflow { dimension: D::OpenFiles };
            let ledger = self.common.representation.as_ref().ok_or(overflow)?;
            let files = self.common.fixed_startup_demand()?.get(D::OpenFiles)
                .checked_add(self.common.service_startup.as_ref()
                    .map_or(0, |startup| startup.committed_files()))
                .and_then(|files| files.checked_add(self.common.operation_files))
                .ok_or(overflow)?;
            let permanent = self.common.permanent_open_files().map_err(|_| overflow)?;
            if files > permanent {
                return Err(AccountingError::LimitExceeded {
                    dimension: D::OpenFiles, limit: permanent, attempted: files,
                });
            }
            // Recurring parent slots consume coverage within this charged
            // envelope. Replacing it with a smaller observed counter would
            // manufacture child headroom from already-paid parent capacity.
            Ok(ledger.charged())
        })());
        original.parent_demand = Some(NetworkWorkerBirthOriginalV2::parent_receiving_demand_v2(purpose));
        original.demand = Some(child_fee.and_then(|child| {
            original.child = Some(child);
            let parent = original.parent_demand.as_ref()
                .and_then(|value| value.as_ref().ok()).copied()
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            // New parent bytes/names consume bank capacity. Parent receipt
            // FDs use existing F3 coverage; the child FD fee stays additional.
            child.checked_add(parent.with(D::OpenFiles, 0))
        }));
        if !matches!(original.baseline, Some(Ok(_))) || !matches!(original.demand, Some(Ok(_))) {
            original.first = Some(First::Geometry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Geometry));
        }
        let Some(baseline) = original.baseline.as_ref().and_then(|value| value.as_ref().ok()).copied()
        else {
            original.first = Some(First::Geometry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Geometry));
        };
        let Some(demand) = original.demand.as_ref().and_then(|value| value.as_ref().ok()).copied()
        else {
            original.first = Some(First::Geometry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Geometry));
        };
        let Some(ceiling) = self.common.parent.as_ref().and_then(|value| value.as_ref().ok())
            .map(|(ceiling, _, _)| *ceiling)
        else {
            original.first = Some(First::Source);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        };
        original.fit = Some(remaining_parent_after_child_v2(ceiling, baseline, demand));
        if !matches!(original.fit, Some(Ok(_))) {
            original.first = Some(First::Geometry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Geometry));
        }
        let Some(parent) = original.parent_demand.as_ref()
            .and_then(|value| value.as_ref().ok()).copied()
        else {
            original.first = Some(First::Geometry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Geometry));
        };
        original.funding = Some(self.require_additional_representation_v4(parent));
        if !matches!(original.funding, Some(Ok(()))) {
            original.first = Some(First::Funding);
            return Err(self.refuse_network_worker_birth_v2(Failure::Accounting));
        }
        let Some(child) = original.child else {
            original.first = Some(First::Geometry);
            return Err(self.refuse_network_worker_birth_v2(Failure::Geometry));
        };
        let Some(ledger) = self.common.representation.as_mut() else {
            original.first = Some(First::Source);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        };
        original.child_funding = Some(debit_child_on_same_ledger_v2(ledger, child)
            .map_err(|_| original.closed));
        if !matches!(original.child_funding, Some(Ok(()))) {
            original.first = Some(First::ChildFunding);
            return Err(self.refuse_network_worker_birth_v2(Failure::Accounting));
        }
        original.terminal = Some(terminal::TerminalOriginalV2::new());
        original.completion = Some(completion::CompletionOriginalV3::new());
        let Some(terminal) = original.terminal.as_mut() else {
            original.first = Some(First::Terminal);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        };
        let terminal_prearm = terminal.prearm_once(self, purpose);
        let completion_prearm = original.completion.as_mut()
            .map(|completion| completion.prearm_once(self, purpose));
        if terminal_prearm.is_err() {
            original.first = Some(First::Terminal);
            return Err(self.refuse_network_worker_birth_v2(Failure::Before));
        }
        if !matches!(completion_prearm, Some(Ok(()))) {
            original.first = Some(First::Completion);
            return Err(self.refuse_network_worker_birth_v2(Failure::Before));
        }
        Ok(NetworkWorkerBirthReservationV2 { loan: self, original })
    }

    fn refuse_network_worker_birth_v2(&mut self, cause: Failure) -> FixedServiceOperationClosedV4 {
        self.common.operation_closed = true;
        self.operation.fail(cause)
    }
}

// All three inputs are DATA derived by the actual owner above. This arithmetic
// neither supplies an account nor identifies a native Source or child.
fn remaining_parent_after_child_v2(
    ceiling: ResourceVector,
    baseline: ResourceVector,
    additional_child: ResourceVector,
) -> Result<ResourceVector, AccountingError> {
    baseline.checked_add(additional_child)
        .and_then(|required| ceiling.checked_sub(required))
}

fn debit_child_on_same_ledger_v2<'ledger>(
    ledger: &'ledger mut impl RepresentationDemandDebitV1,
    additional_child: ResourceVector,
) -> Result<(), &'ledger AccountingError> {
    ledger.reserve(additional_child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_liabilities_cannot_hide_the_retained_parent_or_duplicate_its_rate() {
        let baseline = ResourceVector::ZERO.with(D::CpuMicrosPerPeriod, 1000)
            .with(D::MemoryBytes, 11).with(D::OpenFiles, 7).with(D::Pids, 1);
        let child = ResourceVector::ZERO.with(D::MemoryBytes, 13)
            .with(D::OpenFiles, 9).with(D::Pids, 2);
        let complete = baseline.checked_add(child).unwrap();

        assert_eq!(remaining_parent_after_child_v2(complete, baseline, child).unwrap(),
            ResourceVector::ZERO);
        for dimension in [D::MemoryBytes, D::OpenFiles, D::Pids] {
            let short = complete.with(dimension, complete.get(dimension) - 1);
            assert!(matches!(remaining_parent_after_child_v2(short, baseline, child),
                Err(AccountingError::InsufficientAmount { dimension: failed, .. }) if failed == dimension));
        }
        assert!(remaining_parent_after_child_v2(complete, baseline,
            child.with(D::CpuMicrosPerPeriod, 1)).is_err());
        assert!(remaining_parent_after_child_v2(complete.with(D::Pids, 2), baseline, child).is_err());
    }

    #[test]
    fn child_fds_enter_the_same_ledger_beside_the_full_parent_envelope() {
        use aos_sandbox_core::component_receiving::ComponentServiceReceivingLedgerV1;

        // These arithmetic fixtures create no Source, bank, operation loan or
        // native receiver. A parent's recurring slots already fit INSIDE7;
        // they do not shrink that charged envelope to manufacture child room.
        let parent = ResourceVector::ZERO.with(D::OpenFiles, 7);
        let child = ResourceVector::ZERO.with(D::OpenFiles, 5);
        let mut enough = ComponentServiceReceivingLedgerV1::new(
            ResourceVector::ZERO.with(D::OpenFiles, 12));
        enough.reserve(parent).unwrap();
        debit_child_on_same_ledger_v2(&mut enough, child).unwrap();

        assert_eq!(enough.charged().get(D::OpenFiles), 12);
        assert_eq!(enough.remaining().unwrap().get(D::OpenFiles), 0);
        let mut short = ComponentServiceReceivingLedgerV1::new(
            ResourceVector::ZERO.with(D::OpenFiles, 11));
        short.reserve(parent).unwrap();
        let first = debit_child_on_same_ledger_v2(&mut short, child).unwrap_err() as *const AccountingError;
        assert_eq!(short.charged().get(D::OpenFiles), 7);
        assert!(debit_child_on_same_ledger_v2(&mut short, ResourceVector::ZERO).is_err());
        assert!(std::ptr::eq(short.failure().unwrap(), first));
    }
}
