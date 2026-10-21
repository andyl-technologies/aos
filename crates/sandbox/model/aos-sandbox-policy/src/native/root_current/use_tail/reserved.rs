//! Retains the genuine R-funded reserved frame and its distinct Controller owner.
//!
//! The completed Use authorization supplies the original cumulative prefix.
//! Frame construction occurs outside L/U after actual fixed admission; its
//! history posts remain separately armed. A received frame is comparison DATA
//! until a distinct paid same-file Controller replay has completed.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;

use super::super::initial_controller::{
    RootInitialControllerReadonlyErrorV1, RootInitialControllerReadonlyOriginalV1,
};
use super::super::initial_open::{RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1};
use super::super::initial_receiving::RootInitialStageOriginalV1;
use super::super::initial_use_authorized::{
    RootInitialUseAuthorizedErrorV1, RootInitialUseAuthorizedOriginalV1,
};
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

mod received;
pub(in crate::native::root_current) use received::RootUseReservedReceivedOriginalV1;

/// Retains the exact reserved frame, receiving or independent replay refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootUseReservedErrorV1 {
    /// Retains the original Open, endpoint, history-post or clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains refusal of the actual completed authorization predecessor.
    #[error(transparent)]
    Authorization(#[from] RootInitialUseAuthorizedErrorV1),
    /// Retains the actual independent Controller reader/model refusal.
    #[error(transparent)]
    Controller(#[from] RootInitialControllerReadonlyErrorV1),
    /// Retains canonical frame and receipt correlation refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The actual receiving, comparison or independent replay is incomplete.
    #[error("reserved-use purpose is incomplete")]
    Incomplete,
}

type E = RootUseReservedErrorV1;

pub(in crate::native::root_current) struct RootUseReservedOriginalV1 {
    frame_stage: RootInitialStageOriginalV1,
    predecessor: Option<RootObservationErrorV1>,
    received: Option<Box<RootUseReservedReceivedOriginalV1>>,
    controller_stage: Option<RootInitialStageOriginalV1>,
    controller_quote: Option<Result<ResourceVector, super::super::initial_controller::DemandError>>,
    controller: Option<Box<RootInitialControllerReadonlyOriginalV1>>,
    closed: bool,
}

impl RootUseReservedOriginalV1 {
    pub(in crate::native::root_current) fn new() -> Self {
        Self {
            frame_stage: RootInitialStageOriginalV1::new(),
            predecessor: None,
            received: None,
            controller_stage: Some(RootInitialStageOriginalV1::new()),
            controller_quote: None,
            controller: None,
            closed: false,
        }
    }

    pub(in crate::native::root_current) fn entered_v1(&self) -> bool {
        self.frame_stage.entered
    }

    pub(in crate::native::root_current) fn frame_fixed_demand_v1()
    -> Result<ResourceVector, NativeError> {
        let owner = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(NativeError::Mechanical(Mechanical::JournalTooLarge))?;
        RootUseReservedReceivedOriginalV1::fixed_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, owner))
            .map_err(|_| NativeError::Mechanical(Mechanical::JournalTooLarge))
    }

    pub(in crate::native::root_current) fn begin_frame_fixed_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.frame_stage.entered || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.frame_stage.entered = true;
        self.frame_stage.financial = Some(financial.clone());
        self.frame_stage.permit = Some(Self::frame_permit_v1(
            initial,
            open,
            authorization,
            financial,
            startup,
            exclusion,
        ));
        self.frame_stage.finish_v1(initial, startup, exclusion)
    }

    fn frame_permit_v1(
        initial: &RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, NativeError> {
        let body = open.body_v1().map_err(|_| NativeError::boundary())?;
        let authorized = authorization
            .completed_body_v1()
            .map_err(|_| NativeError::boundary())?;
        if authorized.root_nonce != body.root_nonce
            || authorized.ready != body.open.ready
            || authorized.association.controller_nonce != body.open.controller_nonce
        {
            return Err(NativeError::boundary());
        }
        let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
        if initial.failure().is_some()
            || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
            || (body.root_recipient, body.root_producer)
                != (
                    enrollment.recipient_invocation,
                    enrollment.identity.native_fields().invocation,
                )
            || !startup.same_financial_original_data_v1(financial)
            || !authorization.same_financial_v1(financial)
        {
            return Err(NativeError::boundary());
        }
        let base = authorization
            .completed_prefix_v1()
            .map_err(|_| NativeError::boundary())?;
        let demand = base
            .checked_add(Self::frame_fixed_demand_v1()?)
            .map_err(|_| NativeError::boundary())?;
        if financial
            .require_receiving_demand_under_upper_exclusion_v1(exclusion, demand)
            .is_err()
        {
            return Err(NativeError::Financial(financial.clone()));
        }
        Ok(demand)
    }

    pub(in crate::native::root_current) fn construct_frame_once_v1(&mut self) -> Result<(), E> {
        if self.closed || self.received.is_some() {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.frame_stage
            .require_complete_v1()
            .map_err(|_| E::Incomplete)?;
        self.received = Some(Box::new(RootUseReservedReceivedOriginalV1::new()));
        Ok(())
    }

    pub(in crate::native::root_current) fn frame_v1(
        &self,
    ) -> Result<&RootUseReservedReceivedOriginalV1, E> {
        self.received.as_deref().ok_or(E::Incomplete)
    }

    pub(in crate::native::root_current) fn frame_mut_v1(
        &mut self,
    ) -> Result<&mut RootUseReservedReceivedOriginalV1, E> {
        self.received.as_deref_mut().ok_or(E::Incomplete)
    }

    pub(in crate::native::root_current) fn park_predecessor_refusal_v1(
        &mut self,
        cause: RootObservationErrorV1,
    ) {
        self.predecessor.get_or_insert(cause);
    }

    pub(in crate::native::root_current) fn begin_controller_fixed_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        let Some(stage) = &mut self.controller_stage else {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        };
        if stage.entered || self.closed || self.controller.is_some() {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        stage.entered = true;
        stage.financial = Some(financial.clone());
        stage.permit = Some((|| {
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            let authorized = authorization
                .completed_body_v1()
                .map_err(|_| NativeError::boundary())?;
            if authorized.root_nonce != body.root_nonce
                || authorized.ready != body.open.ready
                || authorized.association.controller_nonce != body.open.controller_nonce
            {
                return Err(NativeError::boundary());
            }
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if initial.failure().is_some()
                || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (
                        enrollment.recipient_invocation,
                        enrollment.identity.native_fields().invocation,
                    )
                || !startup.same_financial_original_data_v1(financial)
                || !authorization.same_financial_v1(financial)
                || self
                    .frame_stage
                    .financial
                    .as_ref()
                    .is_none_or(|same| !same.same_original_data_v1(financial))
            {
                return Err(NativeError::boundary());
            }
            self.received
                .as_deref()
                .ok_or_else(NativeError::boundary)?
                .require_received_v1()
                .map_err(|_| NativeError::boundary())?;
            let base = self
                .frame_stage
                .require_complete_v1()
                .map_err(|_| NativeError::boundary())?;
            self.controller_quote =
                Some(RootInitialControllerReadonlyOriginalV1::reserved_fixed_demand_v1());
            let additional = self
                .controller_quote
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or_else(NativeError::boundary)?;
            let demand = base
                .checked_add(additional)
                .map_err(|_| NativeError::boundary())?;
            if financial
                .require_receiving_demand_under_upper_exclusion_v1(exclusion, demand)
                .is_err()
            {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        stage.finish_v1(initial, startup, exclusion)
    }

    pub(in crate::native::root_current) fn construct_controller_once_v1(
        &mut self,
    ) -> Result<(), E> {
        if self.closed || self.controller.is_some() {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.controller_stage
            .as_ref()
            .ok_or(E::Incomplete)?
            .require_complete_v1()?;
        let fixed = self.controller_stage.take().ok_or(E::Incomplete)?;
        self.controller = Some(Box::new(
            RootInitialControllerReadonlyOriginalV1::new_reserved_after_fixed_v1(fixed),
        ));
        Ok(())
    }

    pub(in crate::native::root_current) fn controller_v1(
        &self,
    ) -> Result<&RootInitialControllerReadonlyOriginalV1, E> {
        self.controller.as_deref().ok_or(E::Incomplete)
    }

    pub(in crate::native::root_current) fn controller_mut_v1(
        &mut self,
    ) -> Result<&mut RootInitialControllerReadonlyOriginalV1, E> {
        self.controller.as_deref_mut().ok_or(E::Incomplete)
    }

    pub(in crate::native::root_current) fn borrow_controller_once_v1<'cut, 'startup, 'inputs>(
        &'cut mut self,
        writers: &'cut super::super::writers::RootCurrentWritersOriginalV1,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        authorization: &'cut RootInitialUseAuthorizedOriginalV1,
        ready: &'cut super::super::initial_ready::RootInitialReadyOriginalV1,
        cache: &'cut super::super::initial_cache::RootInitialCacheProofOriginalV1,
        source: &'cut super::super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
        ownership: &'cut super::super::initial_bundle::RootInitialBundleOwnershipOriginalV1,
        policy: &'cut crate::root_policy_inputs_data::RootCurrentPolicyInputDataV1<'inputs>,
        originals: &'cut super::super::owned::RootCurrentAcceptedOriginalsV1<'startup>,
    ) -> Result<
        super::super::initial_controller::RootInitialControllerReadonlyPreparedBorrowV1<
            'cut,
            'startup,
            'inputs,
        >,
        E,
    > {
        let received = self.received.as_deref().ok_or(E::Incomplete)?;
        self.controller
            .as_deref_mut()
            .ok_or(E::Incomplete)?
            .borrow_reserved_prepared_once_v1(
                writers,
                open,
                ready,
                cache,
                source,
                ownership,
                policy,
                originals,
                authorization,
                received,
            )
            .map_err(E::from)
    }

    pub(in crate::native::root_current) fn observe_controller_native_posts_once_v1(
        &mut self,
        writers: &super::super::writers::RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
    ) {
        if let (Some(received), Some(controller)) = (&self.received, &mut self.controller) {
            controller.observe_reserved_native_posts_once_v1(
                writers,
                open,
                authorization,
                received,
            );
        }
    }

    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        if self.closed {
            return Err(E::Incomplete);
        }
        self.frame_stage.require_complete_v1()?;
        self.frame_v1()?.require_received_v1()?;
        self.controller_v1()?.require_complete_v1()?;
        if self.failure_v1().is_some() {
            Err(E::Incomplete)
        } else {
            Ok(())
        }
    }

    pub(in crate::native::root_current) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        self.controller_v1()?.completed_prefix_v1().map_err(E::from)
    }

    pub(in crate::native::root_current) fn completed_controller_v1(
        &self,
    ) -> Result<&RootInitialControllerReadonlyOriginalV1, E> {
        self.require_complete_v1()?;
        self.controller_v1()
    }

    pub(in crate::native::root_current) fn received_original_v1(
        &self,
    ) -> Result<&RootUseReservedReceivedOriginalV1, E> {
        self.require_complete_v1()?;
        self.frame_v1()
    }

    pub(in crate::native::root_current) fn completed_receipt_v1(&self, lane: [u8; 16])
        -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedNativeReceiptDataV1<'_>, E>
    {
        self.received_original_v1()?.receipt_v1(lane)
    }

    pub(in crate::native::root_current) fn same_financial_v1(
        &self,
        financial: &RootJournalFinancialOriginalV1,
    ) -> bool {
        self.frame_stage
            .financial
            .as_ref()
            .is_some_and(|same| same.same_original_data_v1(financial))
            && self
                .controller_v1()
                .is_ok_and(|controller| controller.same_financial_v1(financial))
    }

    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor
            .as_ref()
            .map(|cause| cause as _)
            .or_else(|| self.frame_stage.failure_v1())
            .or_else(|| {
                self.received
                    .as_deref()
                    .and_then(RootUseReservedReceivedOriginalV1::failure_v1)
            })
            .or_else(|| {
                self.controller_quote
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.controller_stage
                    .as_ref()
                    .and_then(RootInitialStageOriginalV1::failure_v1)
            })
            .or_else(|| {
                self.controller
                    .as_deref()
                    .and_then(RootInitialControllerReadonlyOriginalV1::failure_v1)
            })
    }
}
