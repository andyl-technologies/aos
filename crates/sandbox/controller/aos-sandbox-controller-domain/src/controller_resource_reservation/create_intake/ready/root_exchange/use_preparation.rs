//! Bookends actual same-Session request reservation under the returned U.
//!
//! The closed native C7/C8 owners select the current Controller position. The
//! same original Root/Source/Cache peer and prepaid owed post remain callable
//! after a later actual request, funding or native append refusal.

use super::*;
use super::super::use_reserved::{OriginalCreateStorageSignedV1, UseReceivingOriginalsV1};
use super::super::super::history::{dispatch::DispatchOriginalsV1, session::SessionOriginalsV1};

#[derive(Default)]
pub(super) struct PreparationRootOriginalsV1 {
    entered: bool,
    refusal: Option<CreateStorageRootExchangeClosedV1>,
    before_entered: bool,
    before: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    after_entered: bool,
    after: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
}

impl PreparationRootOriginalsV1 {
    pub(super) fn started(&self) -> bool { self.entered }
    pub(super) fn before_is_owed(&self) -> bool { self.before_entered && self.before.is_none() }
    pub(super) fn after_is_owed(&self) -> bool { self.after_entered && self.after.is_none() }

    pub(super) fn failure<'a>(&'a self, peer: &'a CreateStorageRootPeerReceivingOriginalsV1)
        -> Option<&'a (dyn Error + 'static)> {
        if matches!(self.before, Some(Err(_))) { peer.failure().or_else(|| cause(&self.before)) }
        else if matches!(self.after, Some(Err(_))) { peer.failure().or_else(|| cause(&self.after)) }
        else { self.refusal.as_ref().map(|cause| cause as _) }
    }
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn observe_preparation_root_once(&mut self,
        parent: &ProjectPreparationReservationAttemptV1, intake: &mut Q04OriginalIntakeAttemptV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut OriginalCreateStorageCacheLoanV1<'_>, signed: &OriginalCreateStorageSignedV1<'_>,
        dispatch: &DispatchOriginalsV1, session: &SessionOriginalsV1,
        receiving: &mut UseReceivingOriginalsV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        self.observe_preparation_engine_once(parent, intake, controller, source, profile,
            cache, signed, dispatch, session, receiving, PreparationRootPurposeV1::Request)
    }

    fn observe_preparation_engine_once(&mut self,
        parent: &ProjectPreparationReservationAttemptV1, intake: &mut Q04OriginalIntakeAttemptV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut OriginalCreateStorageCacheLoanV1<'_>, signed: &OriginalCreateStorageSignedV1<'_>,
        dispatch: &DispatchOriginalsV1, session: &SessionOriginalsV1,
        receiving: &mut UseReceivingOriginalsV1, purpose: PreparationRootPurposeV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if purpose.select(&self.turn).entered && !purpose.select(&self.turn).before_entered {
            return self.observe_preparation_refusal_engine_once(parent, intake, controller, source,
                profile, cache, signed, dispatch, session, receiving, purpose);
        }
        let after = purpose.select(&self.turn).entered;
        if !after {
            self.require_preparation_purpose_v1(purpose, signed)?;
            self.turn.expected_controller = Some(purpose.expected_before(dispatch, session)?);
        } else {
            if !purpose.select(&self.turn).before_entered || purpose.select(&self.turn).after_entered {
                return Err(CreateStorageRootExchangeClosedV1);
            }
            // An attempted C8 never falls back to the older positive C7.
            self.turn.expected_controller = if session.started() { session.position().ok() }
                else { dispatch.position().ok() };
        }
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent, intake, controller, source, profile, cache, state: &mut self.turn,
            use_receiving: Some(RootUseReceivingV1::Original(receiving)),
        };
        if !after {
            purpose.select_mut(loan.state).entered = true;
            // Both purposes retain one next-purpose refusal post after their two bookends.
            loan.prepay_use_root_observations_once(3)?;
            purpose.select_mut(loan.state).before_entered = true;
            loan.state.owed_post = Some(purpose.before_frontier());
            let observed = self.peer.recheck_once(&mut loan);
            purpose.select_mut(loan.state).before = Some(observed);
            if matches!(purpose.select(loan.state).before, Some(Ok(()))) { Ok(()) }
            else { Err(CreateStorageRootExchangeClosedV1) }
        } else {
            purpose.select_mut(loan.state).after_entered = true;
            loan.state.owed_post = Some(purpose.after_frontier());
            let observed = self.peer.recheck_once(&mut loan);
            purpose.select_mut(loan.state).after = Some(observed);
            if matches!(purpose.select(loan.state).after, Some(Ok(()))) { Ok(()) }
            else { Err(CreateStorageRootExchangeClosedV1) }
        }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn preparation_before_entered_v1(&self) -> bool {
        self.turn.preparation.before_entered
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn preparation_cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        if !matches!(self.turn.preparation.before, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.turn.use_tail.admitted_cutoff_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn require_preparation_after_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if matches!(self.turn.preparation.after, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn preparation_clock_v1(&self) -> Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1> {
        self.preparation_cutoff_v1()?;
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.turn.last_native_clock.ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn observe_preparation_refusal_once(&mut self,
        parent: &ProjectPreparationReservationAttemptV1, intake: &mut Q04OriginalIntakeAttemptV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut OriginalCreateStorageCacheLoanV1<'_>, signed: &OriginalCreateStorageSignedV1<'_>,
        dispatch: &DispatchOriginalsV1, session: &SessionOriginalsV1, receiving: &mut UseReceivingOriginalsV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        self.observe_preparation_refusal_engine_once(parent, intake, controller, source,
            profile, cache, signed, dispatch, session, receiving, PreparationRootPurposeV1::Request)
    }

    fn observe_preparation_refusal_engine_once(&mut self,
        parent: &ProjectPreparationReservationAttemptV1, intake: &mut Q04OriginalIntakeAttemptV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut OriginalCreateStorageCacheLoanV1<'_>, signed: &OriginalCreateStorageSignedV1<'_>,
        dispatch: &DispatchOriginalsV1, session: &SessionOriginalsV1, receiving: &mut UseReceivingOriginalsV1,
        purpose: PreparationRootPurposeV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if purpose.select(&self.turn).after_entered || purpose.select(&self.turn).before_entered {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        if !purpose.select(&self.turn).entered {
            self.require_preparation_purpose_v1(purpose, signed)?;
        }
        self.turn.expected_controller = Some(purpose.expected_before(dispatch, session)?);
        purpose.select_mut(&mut self.turn).entered = true;
        purpose.select_mut(&mut self.turn).after_entered = true;
        purpose.select_mut(&mut self.turn).refusal = Some(CreateStorageRootExchangeClosedV1);
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent, intake, controller, source, profile, cache, state: &mut self.turn,
            use_receiving: Some(RootUseReceivingV1::Original(receiving)),
        };
        // Root11 prepaid this exact following refusal before accepting its
        // comparison. No new debit or health restoration occurs after poison.
        loan.state.owed_post = Some(purpose.after_frontier());
        let post = self.peer.recheck_once(&mut loan);
        purpose.select_mut(loan.state).after = Some(post);
        Err(CreateStorageRootExchangeClosedV1)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PreparationRootPurposeV1 { Request, Terminal }

impl PreparationRootPurposeV1 {
    fn select(self, turn: &RootTurnStateV1) -> &PreparationRootOriginalsV1 {
        match self { Self::Request => &turn.preparation, Self::Terminal => &turn.preparation_terminal }
    }

    fn select_mut(self, turn: &mut RootTurnStateV1) -> &mut PreparationRootOriginalsV1 {
        match self { Self::Request => &mut turn.preparation, Self::Terminal => &mut turn.preparation_terminal }
    }

    fn before_frontier(self) -> RootPostFrontierV1 {
        match self { Self::Request => RootPostFrontierV1::PreparationBefore,
            Self::Terminal => RootPostFrontierV1::PreparationTerminalBefore }
    }

    fn after_frontier(self) -> RootPostFrontierV1 {
        match self { Self::Request => RootPostFrontierV1::PreparationAfter,
            Self::Terminal => RootPostFrontierV1::PreparationTerminalAfter }
    }

    fn expected_before(self, dispatch: &DispatchOriginalsV1, session: &SessionOriginalsV1)
        -> Result<super::super::super::history::CreateStorageWriterPositionV1, CreateStorageRootExchangeClosedV1> {
        match self { Self::Request => dispatch.position(), Self::Terminal => session.position() }
            .map_err(|_| CreateStorageRootExchangeClosedV1)
    }
}

impl RootExchangeOriginalsV1 {
    fn require_preparation_purpose_v1(&self, purpose: PreparationRootPurposeV1,
        signed: &OriginalCreateStorageSignedV1<'_>,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        match purpose {
            PreparationRootPurposeV1::Request => self.borrow_signed_bound_v1(signed).map(|_| ())
                .map_err(|_| CreateStorageRootExchangeClosedV1),
            PreparationRootPurposeV1::Terminal => self.require_preparation_after_v1()
                .map_err(|_| CreateStorageRootExchangeClosedV1),
        }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn observe_preparation_terminal_root_once(&mut self,
        parent: &ProjectPreparationReservationAttemptV1, intake: &mut Q04OriginalIntakeAttemptV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut OriginalCreateStorageCacheLoanV1<'_>, signed: &OriginalCreateStorageSignedV1<'_>,
        dispatch: &DispatchOriginalsV1, session: &SessionOriginalsV1,
        receiving: &mut UseReceivingOriginalsV1, finish: bool,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if finish && !self.turn.preparation_terminal.before_entered {
            self.observe_preparation_refusal_engine_once(parent, intake, controller, source,
                profile, cache, signed, dispatch, session, receiving, PreparationRootPurposeV1::Terminal)
        } else {
            self.observe_preparation_engine_once(parent, intake, controller, source,
                profile, cache, signed, dispatch, session, receiving, PreparationRootPurposeV1::Terminal)
        }
    }
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn require_preparation_terminal_after_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if matches!(self.turn.preparation_terminal.after, Some(Ok(()))) && self.failure().is_none() { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}
