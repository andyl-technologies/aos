//! Constructs the initial Source query from the same admitted Root and Ready.
//!
//! The private owner retains its real cumulative financial Stage, framing and
//! encoded request. Query bytes are diagnostic protocol DATA; they grant no
//! Source reply, Cache admission, signing, Use, append or serving authority.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::receiving::{
    RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, ready::ReadyBundleDataV1,
    source_current::{SOURCE_CURRENT_QUERY_BYTES_V1, SourceCurrentQueryDataV1},
};

use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::initial_open::{RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_trust::RootInitialTrustOriginalV1;
use super::proof_turn::RootCurrentProofTurnV1;

/// Retains failure to produce the admitted initial Source query.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialSourceQueryErrorV1 {
    /// Retains the same Open, Ready, native or financial diagnostic category.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains the existing protocol framing or correlation cause.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The genuine admission or request construction has not completed.
    #[error("initial Source query is incomplete")]
    Incomplete,
}

type E = RootInitialSourceQueryErrorV1;

pub(super) struct RootInitialSourceQueryOriginalV1 {
    stage: RootInitialStageOriginalV1,
    predecessor: Option<RootObservationErrorV1>,
    framing: Option<Result<(), HistoryErrorV1>>,
    encoded: Option<Result<[u8; SOURCE_CURRENT_QUERY_BYTES_V1], HistoryErrorV1>>,
    production: Option<Result<(), E>>,
    entered: bool,
    closed: bool,
}

impl RootInitialSourceQueryOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: RootInitialStageOriginalV1::new(),
            predecessor: None,
            framing: None,
            encoded: None,
            production: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn claim_entry_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn refuse_unprepared_v1(&mut self) {
        self.closed = true;
    }

    pub(super) fn park_predecessor_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.predecessor.get_or_insert(error);
        self.closed = true;
    }

    pub(super) fn begin_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        trust: &RootInitialTrustOriginalV1,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.begin_for_turn_once_v1(open, ready, trust, RootCurrentProofTurnV1::Initial,
            predecessor, startup, exclusion)
    }

    pub(super) fn begin_reserved_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        trust: &RootInitialTrustOriginalV1,
        authorization: &super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        reserved: &super::use_tail::reserved::RootUseReservedOriginalV1,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.begin_for_turn_once_v1(open, ready, trust,
            RootCurrentProofTurnV1::Reserved { authorization, reserved },
            predecessor, startup, exclusion)
    }

    fn begin_for_turn_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        trust: &RootInitialTrustOriginalV1,
        turn: RootCurrentProofTurnV1<'_>,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.entered || self.closed || self.stage.entered {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.stage.entered = true;
        self.stage.financial = Some(financial.clone());

        self.stage.permit = Some((|| {
            ready.raw_ready_bytes_v1().map_err(|_| NativeError::boundary())?;
            trust.require_complete_v1().map_err(|_| NativeError::boundary())?;
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if initial.failure().is_some()
                || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || !turn.same_query_financial_v1(trust, financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = turn.query_prefix_v1(trust).map_err(|_| NativeError::boundary())?;
            let demand = base.checked_add(Self::fixed_demand_v1()?)
                .map_err(|_| NativeError::boundary())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        self.stage.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn encode_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
    ) -> Result<(), E> {
        if self.production.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.production = Some(self.encode_inner_v1(open, ready));
        if matches!(self.production, Some(Ok(()))) && self.failure_v1().is_none() {
            Ok(())
        } else {
            self.closed = true;
            Err(E::Incomplete)
        }
    }

    fn encode_inner_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
    ) -> Result<(), E> {
        self.stage.require_complete_v1()?;
        let raw = ready.raw_ready_bytes_v1()?;
        let root = open.body_v1()?;
        let bundle = match ReadyBundleDataV1::decode(raw) {
            Ok(bundle) => {
                self.framing = Some(if bundle.lane == root.open.lane {
                    Ok(())
                } else {
                    Err(HistoryErrorV1::Correlation)
                });
                bundle
            }
            Err(error) => {
                self.framing = Some(Err(error));
                return Err(E::Incomplete);
            }
        };
        if !matches!(self.framing, Some(Ok(()))) {
            return Err(E::Incomplete);
        }
        self.encoded = Some(SourceCurrentQueryDataV1::from_records(
            open.committed_record_v1()?, bundle.source_held,
        ).and_then(|query| query.encode()));
        if matches!(self.encoded, Some(Ok(_))) {
            Ok(())
        } else {
            Err(E::Incomplete)
        }
    }

    pub(super) fn prepared_bytes_v1(&self) -> Result<&[u8; SOURCE_CURRENT_QUERY_BYTES_V1], E> {
        if self.closed || !matches!(self.production, Some(Ok(()))) || self.failure_v1().is_some() {
            return Err(E::Incomplete);
        }
        self.encoded.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(E::Incomplete)
    }

    pub(super) fn require_complete_for_v1(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
    ) -> Result<(), E> {
        let query = SourceCurrentQueryDataV1::decode(self.prepared_bytes_v1()?)?;
        let bundle = ReadyBundleDataV1::decode(ready.raw_ready_bytes_v1()?)?;
        if query.root_open_record().as_slice() != open.committed_record_v1()?.as_slice()
            || query.source_held_receipt().as_slice() != bundle.source_held
        {
            return Err(E::Incomplete);
        }
        Ok(())
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.prepared_bytes_v1()?;
        Ok(self.stage.require_complete_v1()?)
    }

    pub(super) fn same_financial_v1(
        &self,
        financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> bool {
        match &self.stage.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, NativeError> {
        let invalid = || NativeError::Mechanical(Mechanical::JournalTooLarge);
        let memory = size_of::<Self>().checked_mul(2).ok_or_else(invalid)?;
        let own = ResourceVector::ZERO.with(
            D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?,
        );
        let framing = ReadyBundleDataV1::fixed_framing_receiving_demand_v1()
            .ok_or_else(invalid)?;
        own.checked_add(framing).map_err(|_| invalid())
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor.as_ref().map(|error| error as _)
            .or_else(|| self.stage.failure_v1())
            .or_else(|| cause(&self.framing))
            .or_else(|| cause(&self.encoded))
            .or_else(|| cause(&self.production))
    }
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
