//! Binds Initial Controller COMMIT and EOF hooks to their actual receiving owner.
//!
//! The purpose checks the same Initial and completed stage under the original
//! short upper exclusion, at the named-opening and captured-file frontiers.
//! These private slots retain those actual calls; no supplied successful result,
//! generic payer or optional Common replay route can construct this context.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootUpperMutationGuardV1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    controller_intent::ControllerIntentBodyDataV1,
    native_suffix::controller::ControllerHistoryNativeSuffixV1, ready::ControllerAdmissionDataV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::controller_acceptance_data::{
    ControllerAcceptedHistoryObserverDataV1, ControllerAcceptedHistoryProgressDataV1,
};
use crate::native::readonly::{RootControllerReadonlyGeometryAuditV1, RootReadonlyErrorV1};

use super::initial_open::RootInitialOpenPreparedOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;

type E = RootReadonlyErrorV1;
type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Slot = Option<Result<(), E>>;

/// Retains the two actual live checks and each reached semantic frontier.
///
/// This private owner lives on the same Controller purpose as its actual three
/// stage reservoirs. Its inert constructor cannot issue a completed admission.
pub(super) struct RootCurrentReadonlyReceivingOriginalV1 {
    named: Slot,
    named_predecessor: Option<RootObservationErrorV1>,
    named_consumed: bool,
    captured: Slot,
    captured_predecessor: Option<RootObservationErrorV1>,
    captured_consumed: bool,
    frontier: Slot,
    lock_name: Option<String>,
}

impl RootCurrentReadonlyReceivingOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            named: None,
            named_predecessor: None,
            named_consumed: false,
            captured: None,
            captured_predecessor: None,
            captured_consumed: false,
            frontier: None,
            lock_name: None,
        }
    }

    // This method runs after the actual mount-before observation and before
    // bound file preparation, under the same short Initial/L/U interval.
    pub(super) fn admit_named_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        fixed: &RootInitialStageOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.named.is_some() || self.named_consumed {
            self.named_consumed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.named = Some(require_same_live_stage(
            initial, open, fixed, financial, exclusion,
        ));
        if matches!(self.named, Some(Ok(()))) {
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(RootObservationErrorV1::Service)
        }
    }

    // The physical accepted-history observer is constructed before this live
    // check, just as before. The same captured cursor starts only afterwards.
    pub(super) fn admit_captured_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        semantic: &RootInitialStageOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.captured.is_some() || self.captured_consumed {
            self.captured_consumed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.captured = Some(require_same_live_stage(
            initial, open, semantic, financial, exclusion,
        ));
        if matches!(self.captured, Some(Ok(()))) {
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(super) fn park_named_predecessor_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.named_predecessor.get_or_insert(error);
        self.refuse_named_entry_once_v1();
    }

    pub(super) fn park_captured_predecessor_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.captured_predecessor.get_or_insert(error);
        self.refuse_captured_entry_once_v1();
    }

    // An upper lock/borrow failure remains owned above this nonissuing marker.
    pub(super) fn refuse_named_entry_once_v1(&mut self) {
        if self.named.is_none() {
            self.named = Some(Err(E::ProtectedBoundary));
        } else {
            self.named_consumed = true;
        }
    }

    pub(super) fn refuse_captured_entry_once_v1(&mut self) {
        if self.captured.is_none() {
            self.captured = Some(Err(E::ProtectedBoundary));
        } else {
            self.captured_consumed = true;
        }
    }

    pub(super) fn preparation_v1(&mut self) -> RootCurrentReadonlyReceivingContextV1<'_, '_, '_> {
        RootCurrentReadonlyReceivingContextV1 {
            original: self,
            audit: None,
            suffix: None,
            accepted: None,
        }
    }

    pub(super) fn replay_v1<'borrow, 'original, 'data>(
        &'borrow mut self,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow>,
        original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        progress: &'borrow mut ControllerAcceptedHistoryProgressDataV1,
    ) -> RootCurrentReadonlyReceivingContextV1<'borrow, 'original, 'data> {
        let accepted = audit
            .native_data_v1()
            .and_then(|native| native.state())
            .and_then(|state| {
                ControllerAcceptedHistoryObserverDataV1::new(state, original, admission, progress)
            });
        RootCurrentReadonlyReceivingContextV1 {
            original: self,
            audit: Some(audit),
            suffix: Some(RootControllerHistorySuffixV1::Initial(suffix)),
            accepted,
        }
    }

    pub(super) fn replay_reserved_v1<'borrow, 'original, 'data>(
        &'borrow mut self,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 6>,
        original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        reserved: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut ControllerAcceptedHistoryProgressDataV1,
    ) -> RootCurrentReadonlyReceivingContextV1<'borrow, 'original, 'data> {
        let accepted = audit
            .native_data_v1()
            .and_then(|native| native.state())
            .and_then(|state| {
                ControllerAcceptedHistoryObserverDataV1::new_reserved(
                    state, original, admission, reserved, progress,
                )
            });
        RootCurrentReadonlyReceivingContextV1 {
            original: self,
            audit: Some(audit),
            suffix: Some(RootControllerHistorySuffixV1::Reserved(suffix)),
            accepted,
        }
    }

    pub(super) fn replay_signed_v1<'borrow, 'original, 'data>(
        &'borrow mut self,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 7>,
        original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        reserved: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut ControllerAcceptedHistoryProgressDataV1,
    ) -> RootCurrentReadonlyReceivingContextV1<'borrow, 'original, 'data> {
        let accepted = audit.native_data_v1().and_then(|native| native.state()).and_then(|state| {
            ControllerAcceptedHistoryObserverDataV1::new_reserved(state, original, admission, reserved, progress)
        });
        RootCurrentReadonlyReceivingContextV1 { original: self, audit: Some(audit),
            suffix: Some(RootControllerHistorySuffixV1::Signed(suffix)), accepted }
    }

    pub(super) fn replay_outcome_v1<'borrow, 'original, 'data>(
        &'borrow mut self,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 10>,
        original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        reserved: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut ControllerAcceptedHistoryProgressDataV1,
    ) -> RootCurrentReadonlyReceivingContextV1<'borrow, 'original, 'data> {
        let accepted = audit.native_data_v1().and_then(|native| native.state()).and_then(|state| {
            ControllerAcceptedHistoryObserverDataV1::new_reserved(state, original, admission, reserved, progress)
        });
        RootCurrentReadonlyReceivingContextV1 { original: self, audit: Some(audit),
            suffix: Some(RootControllerHistorySuffixV1::Outcome(suffix)), accepted }
    }

    pub(super) fn replay_closed_v1<'borrow, 'original, 'data>(
        &'borrow mut self,
        audit: &'original RootControllerReadonlyGeometryAuditV1,
        suffix: ControllerHistoryNativeSuffixV1<'data, 'borrow, 12>,
        original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        reserved: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'borrow mut ControllerAcceptedHistoryProgressDataV1,
    ) -> RootCurrentReadonlyReceivingContextV1<'borrow, 'original, 'data> {
        let accepted = audit.native_data_v1().and_then(|native| native.state()).and_then(|state| {
            ControllerAcceptedHistoryObserverDataV1::new_committed(state, original, admission, reserved, progress)
        });
        RootCurrentReadonlyReceivingContextV1 { original: self, audit: Some(audit),
            suffix: Some(RootControllerHistorySuffixV1::Closed(suffix)), accepted }
    }

    pub(super) fn named_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.named_predecessor
            .as_ref()
            .map(|error| error as _)
            .or_else(|| cause(&self.named))
    }

    pub(super) fn captured_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.captured_predecessor
            .as_ref()
            .map(|error| error as _)
            .or_else(|| cause(&self.captured))
            .or_else(|| cause(&self.frontier))
    }
}

// All arguments come from the same genuine predecessor and private purpose.
// This repeats the old receiver/refusal/completed-stage conjunction only; it
// neither debits demand nor repeats service, clock or native observations.
fn require_same_live_stage(
    initial: &RootInitialReceivingOriginalV1,
    open: &RootInitialOpenPreparedOriginalV1,
    stage: &RootInitialStageOriginalV1,
    financial: &RootJournalFinancialOriginalV1,
    exclusion: &RootUpperMutationGuardV1<'_>,
) -> Result<(), E> {
    if !exclusion.same_financial_original_data_v1(financial) || initial.failure().is_some() {
        return Err(E::ProtectedBoundary);
    }
    let body = open.body_v1().map_err(|_| E::ProtectedBoundary)?;
    let enrollment = initial.enrollment_v1().ok_or(E::ProtectedBoundary)?;
    if (body.root_recipient, body.root_producer)
        != (
            enrollment.recipient_invocation,
            enrollment.identity.native_fields().invocation,
        )
        || stage
            .financial
            .as_ref()
            .is_none_or(|same| !same.same_original_data_v1(financial))
    {
        return Err(E::ProtectedBoundary);
    }
    stage
        .require_complete_v1()
        .map_err(|_| E::ProtectedBoundary)?;
    Ok(())
}

// Both variants route the same actual cursor events to the sole Protocol
// suffix observer. Neither a variant nor its DATA creates a role admission.
enum RootControllerHistorySuffixV1<'data, 'progress> {
    Initial(ControllerHistoryNativeSuffixV1<'data, 'progress, 3>),
    Reserved(ControllerHistoryNativeSuffixV1<'data, 'progress, 6>),
    Signed(ControllerHistoryNativeSuffixV1<'data, 'progress, 7>),
    Outcome(ControllerHistoryNativeSuffixV1<'data, 'progress, 10>),
    Closed(ControllerHistoryNativeSuffixV1<'data, 'progress, 12>),
}

impl RootControllerHistorySuffixV1<'_, '_> {
    fn observe(&mut self, transaction: &JournalTransaction, begin: u64, commit: u64,
        before_end: u64, after_end: u64)
        -> Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairSuffixErrorV1>
    {
        match self {
            Self::Initial(suffix) => {
                suffix.observe(transaction, begin, commit, before_end, after_end)
            }
            Self::Reserved(suffix) => {
                suffix.observe(transaction, begin, commit, before_end, after_end)
            }
            Self::Signed(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
            Self::Outcome(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
            Self::Closed(suffix) => suffix.observe(transaction, begin, commit, before_end, after_end),
        }
    }

    fn finish(&mut self, next: u64, end: u64, captured: u64)
        -> Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairSuffixErrorV1>
    {
        match self {
            Self::Initial(suffix) => suffix.finish(next, end, captured),
            Self::Reserved(suffix) => suffix.finish(next, end, captured),
            Self::Signed(suffix) => suffix.finish(next, end, captured),
            Self::Outcome(suffix) => suffix.finish(next, end, captured),
            Self::Closed(suffix) => suffix.finish(next, end, captured),
        }
    }

    fn failure(&self) -> Option<&aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairSuffixErrorV1>{
        match self {
            Self::Initial(suffix) => suffix.failure_v1(),
            Self::Reserved(suffix) => suffix.failure_v1(),
            Self::Signed(suffix) => suffix.failure_v1(),
            Self::Outcome(suffix) => suffix.failure_v1(),
            Self::Closed(suffix) => suffix.failure_v1(),
        }
    }
}

/// Borrows the real admission slots, Audit, suffix and physical accepted observer.
///
/// Construction is confined to this private same-purpose owner. The sole Cold
/// binding invokes these hooks before each semantic allocation and at EOF.
pub(in crate::native) struct RootCurrentReadonlyReceivingContextV1<'borrow, 'original, 'data> {
    original: &'borrow mut RootCurrentReadonlyReceivingOriginalV1,
    audit: Option<&'original RootControllerReadonlyGeometryAuditV1>,
    suffix: Option<RootControllerHistorySuffixV1<'data, 'borrow>>,
    accepted: Option<ControllerAcceptedHistoryObserverDataV1<'original, 'data, 'borrow>>,
}

impl RootCurrentReadonlyReceivingContextV1<'_, '_, '_> {
    // This concrete short bridge is invoked on the same replay context after
    // its physical accepted observer exists and before its retained cursor.
    pub(super) fn admit_captured_live_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        semantic: &RootInitialStageOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.original
            .admit_captured_once_v1(initial, open, semantic, financial, exclusion)
    }

    pub(super) fn park_captured_live_predecessor_refusal_v1(
        &mut self,
        error: RootObservationErrorV1,
    ) {
        self.original.park_captured_predecessor_refusal_v1(error);
    }

    pub(super) fn refuse_captured_live_entry_once_v1(&mut self) {
        self.original.refuse_captured_entry_once_v1();
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.accepted
            .as_ref()
            .and_then(|accepted| accepted.failure())
            .or_else(|| {
                self.suffix
                    .as_ref()
                    .and_then(|suffix| suffix.failure())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| self.original.captured_failure_v1())
    }

    pub(in crate::native) fn retained_lock_name_destination_v1(&mut self) -> &mut Option<String> {
        &mut self.original.lock_name
    }

    pub(in crate::native) fn require_fixed_named_preparation(&mut self) -> Result<(), E> {
        if self.original.named_consumed || self.audit.is_some() || self.suffix.is_some() {
            return Err(E::ProtectedBoundary);
        }
        self.original.named_consumed = true;
        require_positive(&self.original.named)
    }

    pub(in crate::native) fn require_captured_file_end(&mut self, end: u64) -> Result<(), E> {
        if self.original.captured_consumed {
            return Err(E::ProtectedBoundary);
        }
        self.original.captured_consumed = true;
        require_positive(&self.original.captured)?;
        self.original.frontier = Some((|| {
            let actual = self
                .audit
                .and_then(|audit| audit.captured_extent_v1())
                .ok_or(E::ProtectedBoundary)?;
            if actual.native_bytes != end || self.suffix.is_none() {
                return Err(E::ProtectedBoundary);
            }
            Ok(())
        })());
        require_positive(&self.original.frontier)
    }

    pub(in crate::native) fn before_semantic_replay(
        &mut self,
        state: &State,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(), E> {
        require_positive(&self.original.captured)?;
        if self.original.frontier.as_ref().is_some_and(Result::is_err) {
            return Err(E::ProtectedBoundary);
        }
        self.original.frontier = Some(
            self.audit
                .ok_or(E::ProtectedBoundary)?
                .require_actual_semantic_frontier_v1(state, transaction),
        );
        require_positive(&self.original.frontier)
    }

    pub(in crate::native) fn observe_native_commit(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), E> {
        require_positive(&self.original.captured)?;
        self.accepted
            .as_mut()
            .ok_or(E::ProtectedBoundary)?
            .observe(
                transaction,
                begin_sequence,
                commit_sequence,
                begin_offset,
                end_offset,
            )
            .map_err(E::from)?;
        self.suffix
            .as_mut()
            .ok_or(E::ProtectedBoundary)?
            .observe(
                transaction,
                begin_sequence,
                commit_sequence,
                begin_offset,
                end_offset,
            )
            .map_err(|_| E::ProtectedBoundary)
    }

    pub(in crate::native) fn finish_native_replay(&mut self, next: u64, end: u64) -> Result<(), E> {
        require_positive(&self.original.captured)?;
        let captured_end = self
            .audit
            .and_then(|audit| audit.captured_extent_v1())
            .ok_or(E::ProtectedBoundary)?
            .native_bytes;
        self.suffix
            .as_mut()
            .ok_or(E::ProtectedBoundary)?
            .finish(next, end, captured_end)
            .map_err(|_| E::ProtectedBoundary)?;
        let audit = self.audit.ok_or(E::ProtectedBoundary)?;
        let ids = audit
            .native_data_v1()
            .and_then(|native| native.transaction_ids_data_v1())
            .ok_or(E::ProtectedBoundary)?;
        self.accepted
            .as_mut()
            .ok_or(E::ProtectedBoundary)?
            .finish_original_names(ids)
            .map_err(E::from)
    }
}

pub(super) fn receiving_control_bytes_v1() -> Option<usize> {
    let owners = size_of::<RootCurrentReadonlyReceivingOriginalV1>().checked_mul(2)?;
    let contexts = size_of::<RootCurrentReadonlyReceivingContextV1<'_, '_, '_>>().checked_mul(2)?;
    let admissions = size_of::<Result<(), E>>().checked_mul(12)?;
    let returned = size_of::<Result<(), RootObservationErrorV1>>().checked_mul(6)?;
    let named_arguments = size_of::<(
        &mut RootCurrentReadonlyReceivingOriginalV1,
        &mut RootInitialReceivingOriginalV1,
        &RootInitialOpenPreparedOriginalV1,
        &RootInitialStageOriginalV1,
        &RootJournalFinancialOriginalV1,
        &RootUpperMutationGuardV1<'_>,
    )>()
    .checked_mul(6)?;
    let semantic_arguments = size_of::<(
        &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
        &State,
        Option<&JournalTransaction>,
    )>()
    .checked_mul(6)?;
    let replay_arguments = size_of::<(
        &mut RootCurrentReadonlyReceivingOriginalV1,
        &RootControllerReadonlyGeometryAuditV1,
        RootControllerHistorySuffixV1<'_, '_>,
        ControllerIntentBodyDataV1<'_>,
        ControllerAdmissionDataV1<'_>,
        &mut ControllerAcceptedHistoryProgressDataV1,
    )>()
    .checked_mul(3)?;
    let affinity = size_of::<(
        &RootUpperMutationGuardV1<'_>,
        &RootJournalFinancialOriginalV1,
    )>()
    .checked_mul(6)?
    .checked_add(size_of::<bool>().checked_mul(6)?)?;
    let variants = size_of::<RootControllerHistorySuffixV1<'_, '_>>()
        .checked_mul(6)?
        .checked_add(size_of::<ControllerHistoryNativeSuffixV1<'_, '_, 6>>().checked_mul(3)?)?;
    let observer = crate::controller_acceptance_data::fixed_interface_control_bytes_v1::<E>()?;
    let suffix = aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::controller::receiving_interface_control_bytes_v1::<E>()?;

    owners
        .checked_add(contexts)?
        .checked_add(admissions)?
        .checked_add(returned)?
        .checked_add(named_arguments)?
        .checked_add(semantic_arguments)?
        .checked_add(replay_arguments)?
        .checked_add(affinity)?
        .checked_add(observer)?
        .checked_add(suffix)?
        .checked_add(variants)
}

fn require_positive(slot: &Slot) -> Result<(), E> {
    if matches!(slot, Some(Ok(()))) {
        Ok(())
    } else {
        Err(E::ProtectedBoundary)
    }
}

fn cause(slot: &Slot) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| error as _)
}
