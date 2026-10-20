//! Resident Inventory-to-Prepare receipt, execution and terminal custody.
//!
//! The same genuine receiving loan admits both bounded wire turns. Shared
//! protected receipt and response engines retain the real Session and native
//! results; uncertain admission or effects never become a replacement request.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::StoragePrepareReceivingLoanV1;

use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerExecutionFailureV1, DormantBrokerResponseSendProgressV1,
    DormantBrokerSessionHandshakeErrorV1, ProductionBrokerRequestEventV1,
    ProductionStorageBrokerDispatchErrorV1, ProtectedBrokerOutcomeCommitResultV1,
};

use super::wait_output_original;
use crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1;

type Dispatch = Result<
    ProtectedBrokerOutcomeCommitResultV1,
    DormantBrokerExecutionFailureV1<ProductionStorageBrokerDispatchErrorV1>,
>;
type Send = Result<DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1>;

pub(super) struct StorageSessionChecks {
    clock: [Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>; 3],
    receiving: [Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>; 3],
    current: [Option<Result<(), BrokerSessionSecurityError>>; 3],
}

impl StorageSessionChecks {
    pub(super) fn empty() -> Self {
        Self {
            clock: [None, None, None],
            receiving: [None, None, None],
            current: [None, None, None],
        }
    }

    pub(super) fn observe(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: Result<(), aos_sandbox::StorageReceivingClosedV1>,
        source: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
        index: usize,
        deadline: u64,
    ) -> Option<Cause> {
        // Positive samples may be replaced. The caller exits on a negative
        // before another observation could overwrite that retained cause.
        let mut first = None;
        self.receiving[index] = Some(receiving);
        if self.receiving[index].as_ref().is_some_and(Result::is_err) {
            first = Some(Cause::Receiving(index));
        }
        self.current[index] = Some(session.recheck_storage_receiving_v3(Some(source)));
        if self.current[index].as_ref().is_some_and(Result::is_err) {
            first.get_or_insert(Cause::Current(index));
        }
        self.clock[index] = Some(crate::dormant_handshake::check_production_deadline(deadline));
        if self.clock[index].as_ref().is_some_and(Result::is_err) {
            first.get_or_insert(Cause::Clock(index));
        }
        first
    }

    pub(super) fn failure(&self, cause: Cause) -> Option<&(dyn std::error::Error + 'static)> {
        match cause {
            Cause::Clock(index) => self.clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            Cause::Receiving(index) => self.receiving[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            Cause::Current(index) => self.current[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            _ => None,
        }
    }

    pub(super) fn debt(&self, first: Option<Cause>) -> Option<&(dyn std::error::Error + 'static)> {
        for index in 0..3 {
            for cause in [Cause::Receiving(index), Cause::Current(index), Cause::Clock(index)] {
                if first != Some(cause) {
                    if let Some(error) = self.failure(cause) {
                        return Some(error);
                    }
                }
            }
        }
        None
    }
}

struct PrepareReplayLane {
    receipt: OriginalOutputServerReceiptV1,
    event: Option<ProductionBrokerRequestEventV1>,
    send: Option<Result<
        crate::DormantBrokerTerminalReplaySendProgressV1,
        DormantBrokerSessionHandshakeErrorV1,
    >>,
    send_attempt: Option<crate::handshake::StorageResponseSendAttemptV1>,
    readiness: Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>,
    checks: StorageSessionChecks,
}

impl PrepareReplayLane {
    fn empty() -> Self {
        Self {
            receipt: OriginalOutputServerReceiptV1::empty(),
            event: None,
            send: None,
            send_attempt: None,
            readiness: None,
            checks: StorageSessionChecks::empty(),
        }
    }
}

struct PrepareTurn {
    receipt: OriginalOutputServerReceiptV1,
    event: Option<ProductionBrokerRequestEventV1>,
    dispatch: Option<Dispatch>,
    send: Option<Send>,
    send_attempt: Option<crate::handshake::StorageResponseSendAttemptV1>,
    readiness: Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>,
    checks: StorageSessionChecks,
}

impl PrepareTurn {
    fn empty() -> Self {
        Self {
            receipt: OriginalOutputServerReceiptV1::empty(),
            event: None,
            dispatch: None,
            send: None,
            send_attempt: None,
            readiness: None,
            checks: StorageSessionChecks::empty(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Cause {
    Wire,
    Receive,
    Dispatch,
    Send,
    Readiness,
    Clock(usize),
    Receiving(usize),
    Current(usize),
    Poll,
    Closed,
}

/// Reports a closed selected cycle while its actual causes remain resident.
#[derive(Debug, thiserror::Error)]
#[error("the original Storage Prepare cycle is closed with its custody resident")]
pub struct StoragePrepareCycleClosedV1;

/// Retains the original Session, Inventory/Prepare and a fixed replay lane.
///
/// The constructor consumes a genuine authenticated Session. The actual daemon
/// supplies its same Native receiving loan for every advance. Wire admission is
/// one monotone debit covering both simultaneously retained request turns.
/// Post-Prepared replay has one separately paid reusable carrier lane; request
/// CAS, initialization, domain execution and terminal transport remain shared.
#[must_use = "retain original request and terminal uncertainty until genuine disposition"]
pub struct ProductionOriginalStoragePrepareCycleV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    retirement: Option<StorageSessionRetirementV1>,
    turns: [PrepareTurn; 2],
    demand: Option<Result<aos_sandbox_core::resources::ResourceVector, BrokerSessionSecurityError>>,
    wire: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    replay_demand: Option<Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError>>,
    replay_reservation: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    replay_lane: Option<PrepareReplayLane>,
    poll: Option<rustix::io::Errno>,
    first: Option<(usize, Cause)>,
    next: usize,
    closed: bool,
    prepared: bool,
}

// The Session is absent only after a complete positive transport disposition.
// The cycle stays closed and clears Prepared in the same infallible handoff.
fn active_session(owner: &mut Option<DormantAuthenticatedBrokerSessionV1>) -> &mut DormantAuthenticatedBrokerSessionV1 {
    match owner {
        Some(session) => session,
        None => std::process::abort(),
    }
}

fn active_session_ref(owner: &Option<DormantAuthenticatedBrokerSessionV1>) -> &DormantAuthenticatedBrokerSessionV1 {
    match owner {
        Some(session) => session,
        None => std::process::abort(),
    }
}

pub(super) struct StorageSessionRetirementV1 {
    terminal: [Option<Result<(), BrokerSessionSecurityError>>; 2],
    current: [Option<Result<(), BrokerSessionSecurityError>>; 2],
    clock: [Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>; 2],
    raw_current: [Option<bool>; 2],
    pub(super) end: Option<aos_sandbox_linux::seqpacket::StorageSeqpacketEndAttemptV1>,
    pub(super) native_error: Option<aos_sandbox::StorageLifecycleDisposalErrorV1>,
    pub(super) entry_error: Option<aos_sandbox::StorageReceivingClosedV1>,
    pub(super) first: Option<RetirementCause>,
}

#[derive(Clone, Copy)]
pub(super) enum RetirementCause {
    Terminal(usize),
    Current(usize),
    Clock(usize),
    Raw(usize),
    Native,
    Entry,
}

impl StorageSessionRetirementV1 {
    pub(super) fn new() -> Self {
        Self {
            terminal: [None, None],
            current: [None, None],
            clock: [None, None],
            raw_current: [None, None],
            end: None,
            native_error: None,
            entry_error: None,
            first: None,
        }
    }

    pub(super) fn observe(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        terminal: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        mut receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
        index: usize,
        deadline: u64,
    ) {
        // Each required upper post executes independently, even after an
        // earlier terminal, endpoint/floor or cutoff observation refused.
        let compared = match receiving.as_mut() {
            Some(source) => session.compare_storage_terminal_receiving_v3(terminal, &mut **source),
            None => session.compare_retained_storage_terminal_v1(terminal),
        };
        self.observe_inner_v1(session, compared, receiving, index, deadline);
    }

    fn observe_inner_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        compared: Result<(), BrokerSessionSecurityError>,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
        index: usize,
        deadline: u64,
    ) {
        self.terminal[index] = Some(compared);
        if matches!(self.terminal[index], Some(Err(_))) {
            self.first.get_or_insert(RetirementCause::Terminal(index));
        }
        self.current[index] = Some(session.recheck_storage_receiving_v3(receiving));
        if matches!(self.current[index], Some(Err(_))) {
            self.first.get_or_insert(RetirementCause::Current(index));
        }
        self.clock[index] = Some(crate::dormant_handshake::check_production_deadline(deadline));
        if matches!(self.clock[index], Some(Err(_))) {
            self.first.get_or_insert(RetirementCause::Clock(index));
        }
    }

    pub(super) fn observe_terminal_owner_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        terminal: &crate::recovery::RetainedStorageTerminalV1,
        mut receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
        index: usize,
        deadline: u64,
    ) {
        let compared = match receiving.as_mut() {
            Some(source) => session.compare_storage_terminal_owner_receiving_v3(terminal, &mut **source),
            None => session.compare_retained_storage_terminal_owner_v1(terminal),
        };
        self.observe_inner_v1(session, compared, receiving, index, deadline);
    }

    fn observe_raw(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        turns: &mut [PrepareTurn; 2],
        completed: usize,
    ) {
        for (index, turn) in turns.iter_mut().enumerate().take(completed) {
            let current = session.recheck_storage_prepare_replay_transport_v1(&mut turn.receipt);
            self.raw_current[index] = Some(current);
            if !current {
                self.first.get_or_insert(RetirementCause::Raw(index));
            }
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            RetirementCause::Terminal(index) => self.terminal[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Current(index) => self.current[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Clock(index) => self.clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Raw(_) => Some(&StoragePrepareCycleClosedV1),
            RetirementCause::Native => self.native_error.as_ref()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Entry => self.entry_error.as_ref()
                .map(|error| error as &dyn std::error::Error),
        }
    }
}

/// Retains the same protected Session Journal, floor and Broker endpoint.
///
/// Only an actual positive resident transport retirement constructs this owner.
/// It cannot reload a role, reopen a Journal, reset startup payment or prove
/// physical effects drained. A following HELLO must use the same genuine payer.
#[must_use = "retain the original Journal, floor and endpoint until their actual continuation"]
pub struct ProductionStorageSessionContinuationV1 {
    pub(crate) owner: Option<crate::recovery::ProtectedBrokerSessionOwnerV1>,
    pub(crate) acceptance: Option<crate::production_activation::StorageRetainedSocketAcceptanceV1>,
    pub(crate) handshake: Option<crate::handshake::retained_storage_session::StorageRetainedSessionHandshakeV1>,
}

impl Drop for ProductionStorageSessionContinuationV1 {
    fn drop(&mut self) {
        if self.owner.is_some() || self.acceptance.is_some() || self.handshake.is_some() {
            // No implicit release of the sole protected writer between clients.
            std::process::abort();
        }
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Parks the original Session before selected Storage request receipt.
    #[must_use]
    pub fn begin_original_storage_prepare_cycle(self) -> ProductionOriginalStoragePrepareCycleV1 {
        ProductionOriginalStoragePrepareCycleV1 {
            session: Some(self),
            retirement: None,
            turns: std::array::from_fn(|_| PrepareTurn::empty()),
            demand: None,
            wire: None,
            replay_demand: None,
            replay_reservation: None,
            replay_lane: None,
            poll: None,
            first: None,
            next: 0,
            closed: false,
            prepared: false,
        }
    }
}

impl Drop for ProductionOriginalStoragePrepareCycleV1 {
    fn drop(&mut self) {
        if self.session.is_some() && (self.closed || self.first.is_some() || self.prepared) {
            // A local Prepared send is not settlement or release of its genuine
            // Native reservation; an uncertain original also cannot disappear.
            std::process::abort();
        }
    }
}

impl ProductionOriginalStoragePrepareCycleV1 {
    pub(crate) fn retained_carrier_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Retires this actual completed Preparation transport into the same writer.
    ///
    /// The original Prepared/domain owners remain in Storage's composition.
    /// This only disposes successful control copies after real shutdown and all
    /// same-owner Native, terminal, endpoint/floor, subject and cutoff posts.
    ///
    /// # Errors
    /// Retains the whole Session/cycle, actual end, native disposal error and
    /// upper observations on any refusal. An unfinished retirement cannot retry.
    pub fn retire_prepared_session_v1(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
    ) -> Result<ProductionStorageSessionContinuationV1, StoragePrepareCycleClosedV1> {
        if self.closed || self.first.is_some() || !self.prepared
            || self.replay_lane.is_some() || self.retirement.is_some() || self.next == 0
        {
            return Err(StoragePrepareCycleClosedV1);
        }
        self.closed = true;
        self.retirement = Some(StorageSessionRetirementV1::new());
        let session = active_session(&mut self.session);
        let Some(Ok(DormantBrokerResponseSendProgressV1::Sent(terminal))) =
            self.turns[self.next - 1].send.as_ref()
        else {
            self.first.get_or_insert((self.next - 1, Cause::Closed));
            return Err(StoragePrepareCycleClosedV1);
        };
        let mut native = match session.borrow_prepared_session_retirement_v1(receiving) {
            Ok(native) => native,
            Err(error) => {
                let Some(retirement) = self.retirement.as_mut() else { std::process::abort(); };
                retirement.entry_error = Some(error);
                retirement.first = Some(RetirementCause::Entry);
                retirement.observe(session, terminal, None, 1, deadline);
                retirement.observe_raw(session, &mut self.turns, self.next);
                return Err(StoragePrepareCycleClosedV1);
            }
        };
        let Some(retirement) = self.retirement.as_mut() else { std::process::abort(); };
        retirement.observe(session, terminal, Some(&mut native), 0, deadline);
        if retirement.first.is_some() {
            retirement.observe_raw(session, &mut self.turns, self.next);
            return Err(StoragePrepareCycleClosedV1);
        }

        retirement.end = Some(session.end_storage_session_transport_v1());
        let Some(ended) = retirement.end.take() else { std::process::abort(); };
        let prepared = session.prepare_storage_transport_disposal_v1(&mut native, ended);
        let mut positive = match prepared {
            Ok(positive) => positive,
            Err(error) => {
                retirement.native_error = Some(error);
                retirement.first.get_or_insert(RetirementCause::Native);
                // Actual terminal/floor/cutoff posts remain owed on native Err.
                retirement.observe(session, terminal, None, 1, deadline);
                retirement.observe_raw(session, &mut self.turns, self.next);
                return Err(StoragePrepareCycleClosedV1);
            }
        };

        match positive.borrow_transport_post_receiving_v3() {
            Ok(source) => retirement.observe(session, terminal, Some(source), 1, deadline),
            Err(cause) => {
                retirement.entry_error = Some(cause);
                retirement.first.get_or_insert(RetirementCause::Entry);
            }
        }
        retirement.observe_raw(session, &mut self.turns, self.next);
        if retirement.first.is_some() {
            // Dropping the unfinished positive token closes the original payer;
            // all upper originals and the actual error remain resident here.
            return Err(StoragePrepareCycleClosedV1);
        }

        // All fallible checks are finished while the actual socket, raw turns,
        // responses and protected owner are resident. Only moves/drop and the
        // Native token's infallible completion follow this cut.
        let session = match self.session.take() {
            Some(session) => session,
            None => std::process::abort(),
        };
        let terminal = match self.turns[self.next - 1].send.take() {
            Some(Ok(DormantBrokerResponseSendProgressV1::Sent(terminal))) => terminal,
            _ => std::process::abort(),
        };
        let owner = session.into_retained_storage_owner_v1(terminal);
        self.turns = std::array::from_fn(|_| PrepareTurn::empty());
        self.retirement = None;
        self.closed = true;
        self.prepared = false;
        positive.complete_after_disposal_v1();
        Ok(ProductionStorageSessionContinuationV1 {
            owner: Some(owner), acceptance: None, handshake: None,
        })
    }

    /// Borrows the same carrier before the next fixed selected turn.
    ///
    /// # Errors
    /// Refuses uncertainty or exhaustion before Prepared. After Prepared the
    /// same carrier accepts only its separately paid exact-terminal replays.
    pub fn as_fd(
        &self,
    ) -> Result<std::os::fd::BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        if self.closed || (!self.prepared && self.next >= self.turns.len()) {
            return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        active_session_ref(&self.session).as_fd()
    }

    /// Retains an actual daemon poll error without replacing an earlier cause.
    pub fn close_on_poll_failure(&mut self, error: rustix::io::Errno) {
        self.poll.get_or_insert(error);
        self.first.get_or_insert((self.next.min(1), Cause::Poll));
        self.closed = true;
    }

    /// Borrows the first original action or currentness rejection.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(retirement) = &self.retirement {
            if let Some(RetirementCause::Raw(index)) = retirement.first {
                return self.turns[index].receipt.replay_transport_failure_v1()
                    .or_else(|| self.turns[index].receipt.failure())
                    .or(Some(&StoragePrepareCycleClosedV1));
            }
            if let Some(error) = retirement.failure() {
                return Some(error);
            }
        }
        let (index, cause) = self.first?;
        if self.prepared {
            return self.replay_failure(cause);
        }
        let turn = &self.turns[index];
        match cause {
            Cause::Wire => self.demand.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error)
                .or_else(|| self.wire.as_ref()?.as_ref().err()
                    .map(|error| error as &dyn std::error::Error)),
            Cause::Receive => turn.receipt.failure()
                .or_else(|| turn.receipt.postcheck_debt().map(|e| e as &dyn std::error::Error)),
            Cause::Dispatch => match turn.dispatch.as_ref()? {
                Err(DormantBrokerExecutionFailureV1::BeforeEffect { error, .. }) => Some(error),
                Err(DormantBrokerExecutionFailureV1::OutcomeUnknown { error, .. }) => Some(error),
                Ok(ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&StoragePrepareCycleClosedV1),
            },
            Cause::Send => turn.send_attempt.as_ref().and_then(|attempt| attempt.failure()).or_else(|| match turn.send.as_ref()? {
                Err(error) => Some(error),
                Ok(DormantBrokerResponseSendProgressV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&StoragePrepareCycleClosedV1),
            }),
            Cause::Readiness => turn.readiness.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            Cause::Clock(_) | Cause::Receiving(_) | Cause::Current(_) => turn.checks.failure(cause),
            Cause::Poll => self.poll.as_ref()
                .map(|error| error as &dyn std::error::Error),
            Cause::Closed => Some(&StoragePrepareCycleClosedV1),
        }
    }

    /// Borrows a later independent currentness or cutoff failure as debt.
    ///
    /// An earlier receipt/effect/send cause remains the primary diagnostic.
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for (index, turn) in self.turns.iter().enumerate() {
            if let Some(error) = turn.receipt.postcheck_debt() {
                return Some(error);
            }
            let first = self.first.filter(|(turn_index, _)| !self.prepared && *turn_index == index)
                .map(|(_, cause)| cause);
            if let Some(error) = turn.checks.debt(first) {
                return Some(error);
            }
        }
        if let Some(lane) = &self.replay_lane {
            if let Some(error) = lane.receipt.postcheck_debt() {
                return Some(error);
            }
            return lane.checks.debt(self.first.map(|(_, cause)| cause));
        }
        None
    }

    pub(super) fn failure_with_storage_v1<'owner>(
        &'owner self,
        storage: &'owner aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &'owner StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        let cause = self.failure()?;
        let Some((index, Cause::Dispatch)) = self.first else {
            return Some(if cause.is::<aos_sandbox::StorageReceivingClosedV1>() {
                receiving.failure().unwrap_or(cause)
            } else { cause });
        };
        let native_projection = matches!(self.turns.get(index).and_then(|turn| turn.dispatch.as_ref()),
            Some(Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: crate::DormantBrokerExecutionErrorV1::Domain(
                    ProductionStorageBrokerDispatchErrorV1::Operation(
                        aos_sandbox_storage::DormantStorageBrokerCallErrorV1::Runtime(
                            aos_sandbox_storage::StorageRuntimeError::Receiving,
                        ),
                    ) | ProductionStorageBrokerDispatchErrorV1::Inventory(
                        aos_sandbox_storage::StorageRuntimeError::Receiving,
                    ),
                ), ..
            })));
        if !native_projection {
            return Some(cause);
        }
        // The signed closed two-turn schedule is Inventory then Prepare.
        // Resolve only its actual returned Receiving projection; concrete
        // earlier errors retain precedence over an independently owed post.
        let detail = match index {
            0 => storage.storage_receiving_inventory_failure_v1(),
            1 => storage.storage_prepare_receiving_failure_v1(),
            _ => None,
        }.unwrap_or(cause);
        Some(if detail.is::<aos_sandbox::StorageReceivingClosedV1>() {
            receiving.failure().unwrap_or(detail)
        } else { detail })
    }

    /// Reports locally sent Prepared with its genuine owners still pending.
    ///
    /// This is neither settlement, release permission nor physical Drain.
    #[must_use]
    pub fn has_prepared_pending(&self) -> bool {
        self.prepared && !self.closed && self.first.is_none()
    }

    fn bookend(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        index: usize,
        deadline: u64,
    ) -> bool {
        let current = receiving.require_prepare_retention_v1();
        if let Some(cause) = self.turns[self.next].checks.observe(
            active_session(&mut self.session), current, receiving, index, deadline,
        ) {
            self.first.get_or_insert((self.next, cause));
        }
        self.first.is_none()
    }

    fn replay_failure(&self, cause: Cause) -> Option<&(dyn std::error::Error + 'static)> {
        if cause == Cause::Wire {
            return self.replay_demand.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error)
                .or_else(|| self.replay_reservation.as_ref()?.as_ref().err()
                    .map(|error| error as &dyn std::error::Error));
        }
        if cause == Cause::Poll {
            return self.poll.as_ref().map(|error| error as &dyn std::error::Error);
        }
        let Some(lane) = self.replay_lane.as_ref() else {
            return Some(&StoragePrepareCycleClosedV1);
        };
        match cause {
            Cause::Receive => lane.receipt.replay_transport_failure_v1()
                .or_else(|| lane.receipt.failure()),
            Cause::Send => lane.send_attempt.as_ref().and_then(|attempt| attempt.failure()).or_else(|| match lane.send.as_ref()? {
                Err(error) => Some(error),
                Ok(crate::DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&StoragePrepareCycleClosedV1),
            }),
            Cause::Readiness => lane.readiness.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            Cause::Clock(_) | Cause::Receiving(_) | Cause::Current(_) => lane.checks.failure(cause),
            _ => Some(&StoragePrepareCycleClosedV1),
        }
    }

    fn replay_bookend(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        index: usize,
        deadline: u64,
    ) -> bool {
        let Some(lane) = self.replay_lane.as_mut() else {
            self.first.get_or_insert((self.next.saturating_sub(1), Cause::Closed));
            return false;
        };
        let current = receiving.require_prepare_replay_lane_current_v1();
        if let Some(cause) = lane.checks.observe(active_session(&mut self.session), current, receiving, index, deadline) {
            self.first.get_or_insert((self.next.saturating_sub(1), cause));
        }
        self.first.is_none()
    }

    fn serve_storage_prepare_terminal_replay_v1(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
    ) -> Result<(), StoragePrepareCycleClosedV1> {
        // The original Prepared and its Sent committed response stay in turns.
        // A failed or interrupted lane cannot be replaced by another receive.
        self.closed = true;
        if self.replay_lane.is_some() {
            return Err(StoragePrepareCycleClosedV1);
        }
        if self.replay_demand.is_none() {
            let Some(Ok(DormantBrokerResponseSendProgressV1::Sent(committed))) =
                self.turns[self.next - 1].send.as_ref()
            else {
                self.first = Some((self.next.saturating_sub(1), Cause::Closed));
                return Err(StoragePrepareCycleClosedV1);
            };
            self.replay_demand = Some(active_session(&mut self.session).storage_prepare_replay_demand_v1(committed));
            let Some(Ok(demand)) = &self.replay_demand else {
                self.first = Some((self.next.saturating_sub(1), Cause::Wire));
                return Err(StoragePrepareCycleClosedV1);
            };
            self.replay_reservation = Some(receiving.reserve_prepare_replay_lane_once_v1(*demand));
            if !matches!(self.replay_reservation, Some(Ok(()))) {
                self.first = Some((self.next.saturating_sub(1), Cause::Wire));
                return Err(StoragePrepareCycleClosedV1);
            }
        }
        self.replay_lane = Some(PrepareReplayLane::empty());
        if !self.replay_bookend(receiving, 0, deadline) {
            return Err(StoragePrepareCycleClosedV1);
        }

        let Some(Ok(DormantBrokerResponseSendProgressV1::Sent(committed))) =
            self.turns[self.next - 1].send.as_ref()
        else {
            self.first = Some((self.next.saturating_sub(1), Cause::Closed));
            return Err(StoragePrepareCycleClosedV1);
        };
        let Some(lane) = self.replay_lane.as_mut() else {
            std::process::abort();
        };
        lane.event = active_session(&mut self.session).receive_original_storage_prepare_replay_v1(
            &mut lane.receipt, deadline, receiving, committed,
        );
        if lane.event.is_none() {
            self.first = Some((self.next - 1, Cause::Receive));
        }
        if !self.replay_bookend(receiving, 1, deadline) {
            return Err(StoragePrepareCycleClosedV1);
        }
        let Some(lane) = self.replay_lane.as_mut() else {
            std::process::abort();
        };
        // The parent already proved exact bytes against the held current
        // Prepared terminal before any semantic or request-append path.
        let Some(ProductionBrokerRequestEventV1::TerminalReplay(_)) = lane.event.as_ref() else {
            self.first = Some((self.next - 1, Cause::Closed));
            return Err(StoragePrepareCycleClosedV1);
        };
        let Some(ProductionBrokerRequestEventV1::TerminalReplay(replay)) = lane.event.take() else {
            std::process::abort();
        };
        lane.send = Some(active_session(&mut self.session).send_storage_terminal_replay_receiving_v3(replay, &mut lane.send_attempt, receiving));
        loop {
            let Some(lane) = self.replay_lane.as_mut() else {
                std::process::abort();
            };
            if matches!(lane.send,
                Some(Err(_))
                    | Some(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired { .. }))
                    | Some(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::DescriptorRecoveryRequired(_))))
            {
                self.first.get_or_insert((self.next - 1, Cause::Send));
            }
            if !self.replay_bookend(receiving, 1, deadline) {
                return Err(StoragePrepareCycleClosedV1);
            }
            let Some(lane) = self.replay_lane.as_mut() else {
                std::process::abort();
            };
            if matches!(lane.send, Some(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Sent(_)))) {
                let transport_current = active_session(&mut self.session).recheck_storage_prepare_replay_transport_v1(
                    &mut lane.receipt,
                );
                if !transport_current {
                    self.first.get_or_insert((self.next - 1, Cause::Receive));
                }
                if !self.replay_bookend(receiving, 2, deadline) {
                    return Err(StoragePrepareCycleClosedV1);
                }
                // Only the new successful transport receipt and no-write replay
                // authority are disposed. The real Session, original raw turns,
                // Prepared and committed response remain resident. ReceivedRecord
                // owns bytes/subject/origin, not an ongoing physical operation;
                // this disposal is not shutdown, Drain or an effect refund.
                self.replay_lane = None;
                self.closed = false;
                return Ok(());
            }
            lane.readiness = Some(wait_output_original(active_session_ref(&self.session), true, deadline));
            if lane.readiness.as_ref().is_some_and(Result::is_err) {
                self.first.get_or_insert((self.next - 1, Cause::Readiness));
            }
            if !self.replay_bookend(receiving, 1, deadline) {
                return Err(StoragePrepareCycleClosedV1);
            }
            let Some(lane) = self.replay_lane.as_mut() else {
                std::process::abort();
            };
            let Some(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Pending(replay))) = lane.send.take() else {
                std::process::abort();
            };
            lane.send = Some(active_session(&mut self.session).send_storage_terminal_replay_receiving_v3(replay, &mut lane.send_attempt, receiving));
        }
    }

    /// Drives the next bounded Inventory or Prepare through the same actual loan.
    ///
    /// # Errors
    /// Returns only closed status after retaining the actual reservation,
    /// receipt, dispatch, recovery or send result. A retry cannot replace it.
    /// After Prepared, only byte-exact current terminal replay can be sent;
    /// new effects and ambiguous replay remain resident without redispatch.
    pub fn serve_production_storage_prepare_request_v1(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
    ) -> Result<(), StoragePrepareCycleClosedV1> {
        if self.closed || (!self.prepared && self.next >= self.turns.len()) {
            return Err(StoragePrepareCycleClosedV1);
        }
        if self.prepared {
            return self.serve_storage_prepare_terminal_replay_v1(receiving, deadline);
        }
        self.closed = true;
        if self.demand.is_none() {
            self.demand = Some(
                active_session(&mut self.session).storage_prepare_request_demand_v1(),
            );
            let Some(Ok(demand)) = &self.demand else {
                self.first = Some((self.next, Cause::Wire));
                return Err(StoragePrepareCycleClosedV1);
            };
            self.wire = Some(receiving.reserve_prepare_wire_once_v1(*demand));
            if !matches!(self.wire, Some(Ok(()))) {
                self.first = Some((self.next, Cause::Wire));
                return Err(StoragePrepareCycleClosedV1);
            }
        }
        if !self.bookend(receiving, 0, deadline) {
            return Err(StoragePrepareCycleClosedV1);
        }

        let turn = &mut self.turns[self.next];
        turn.event = active_session(&mut self.session).receive_original_storage_prepare_request_v1(
            &mut turn.receipt, deadline, receiving,
        );
        if turn.event.is_none() {
            self.first = Some((self.next, Cause::Receive));
            self.bookend(receiving, 1, deadline);
            return Err(StoragePrepareCycleClosedV1);
        }
        if !self.bookend(receiving, 1, deadline) {
            return Err(StoragePrepareCycleClosedV1);
        }
        // New-only admission is deliberate: replay/uncertain work stays in
        // event beside its raw original and never authorizes another effect.
        let turn = &mut self.turns[self.next];
        let Some(ProductionBrokerRequestEventV1::Request(request)) = turn.event.as_ref() else {
            self.first = Some((self.next, Cause::Closed));
            return Err(StoragePrepareCycleClosedV1);
        };
        let method = request.method();
        let deadline = deadline.min(request.original_storage_prepare_deadline());
        if !matches!(method, BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG)
            && !(self.next == 0 && method == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
        {
            self.first = Some((self.next, Cause::Closed));
            return Err(StoragePrepareCycleClosedV1);
        }
        if !self.bookend(receiving, 1, deadline) {
            return Err(StoragePrepareCycleClosedV1);
        }
        let turn = &mut self.turns[self.next];
        let Some(ProductionBrokerRequestEventV1::Request(request)) = turn.event.take() else {
            std::process::abort();
        };
        turn.dispatch = Some(active_session(&mut self.session).dispatch_storage_prepare_request_and_commit_v1(
            request, storage, receiving,
        ));
        if !matches!(turn.dispatch, Some(Ok(ProtectedBrokerOutcomeCommitResultV1::Committed(_)))) {
            self.first = Some((self.next, Cause::Dispatch));
        }
        if !self.bookend(receiving, 2, deadline) {
            return Err(StoragePrepareCycleClosedV1);
        }

        let turn = &mut self.turns[self.next];
        let Some(Ok(ProtectedBrokerOutcomeCommitResultV1::Committed(committed))) = turn.dispatch.take() else {
            std::process::abort();
        };
        turn.send = Some(active_session(&mut self.session).send_storage_response_receiving_v3(committed, &mut turn.send_attempt, receiving));
        loop {
            let turn = &mut self.turns[self.next];
            if matches!(
                turn.send,
                Some(Err(_))
                    | Some(Ok(DormantBrokerResponseSendProgressV1::RecoveryRequired { .. }))
            ) {
                self.first.get_or_insert((self.next, Cause::Send));
            }
            if !self.bookend(receiving, 2, deadline) {
                return Err(StoragePrepareCycleClosedV1);
            }
            let turn = &mut self.turns[self.next];
            if matches!(turn.send, Some(Ok(DormantBrokerResponseSendProgressV1::Sent(_)))) {
                self.prepared = method == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG;
                self.next += 1;
                // The original Prepared remains pending. Further traffic is
                // restricted to its paid exact-terminal replay lane.
                self.closed = false;
                return Ok(());
            }
            turn.readiness = Some(wait_output_original(active_session_ref(&self.session), true, deadline));
            if turn.readiness.as_ref().is_some_and(Result::is_err) {
                self.first.get_or_insert((self.next, Cause::Readiness));
                self.bookend(receiving, 2, deadline);
                return Err(StoragePrepareCycleClosedV1);
            }
            if !self.bookend(receiving, 2, deadline) {
                return Err(StoragePrepareCycleClosedV1);
            }
            let turn = &mut self.turns[self.next];
            let Some(Ok(DormantBrokerResponseSendProgressV1::Pending(pending))) = turn.send.take() else {
                std::process::abort();
            };
            turn.send = Some(active_session(&mut self.session).send_storage_response_receiving_v3(pending, &mut turn.send_attempt, receiving));
        }
    }
}
