//! Bookends the genuine original held-owner releases after positive U commit.
//!
//! The Source and Cache writer operations remain separate native originals.
//! This owner retains their same-stream Root observations without lending a
//! position from an earlier Controller phase or renewing the original cutoff.

use super::*;
use crate::controller_resource_reservation::create_intake::{
    history::source_released::SourceReleasedOriginalsV1,
    ready::use_reserved::{OriginalCreateStorageUseCommittedV1, UseReceivingOriginalsV1},
};
use crate::controller_resource_reservation::create_intake::ready::root_exchange::{
    CreateStorageRootExchangeClosedV1 as Closed, OriginalCreateStorageRootExchangeV1,
    RootExchangeOriginalsV1, RootPostFrontierV1, RootUseReceivingV1,
};

#[derive(Clone, Copy)]
enum FirstV1 { Funding, Admission, Before, Association, After, CacheFunding, CacheAdmission, CacheBefore, CacheAfter }

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
struct RootHeldReleaseTurnOriginalsV1 {
    entered: bool,
    position: Option<Result<super::super::CreateStorageWriterPositionV1, ResourceReservationErrorV1>>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    admission: Option<Result<(), Closed>>,
    before: Option<Result<(), Closed>>,
    association: Option<Result<crate::controller_resource_reservation::create_intake::ready::cache_receiving::OriginalCacheAssociationV1, ResourceReservationErrorV1>>,
    after: Option<Result<(), Closed>>,
    first: Option<FirstV1>,
    source_complete: bool,
    cache_entered: bool,
    cache_shape: Option<Result<aos_sandbox_cache::CacheReleasedShapeV1, crate::cache_programmes::initialization::create_storage::released::CacheReleaseShapeErrorV1>>,
    cache_fixed: Option<Result<(), ResourceReservationErrorV1>>,
    cache_source: Option<crate::JournalError>,
    cache_funding: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheAuditFundingErrorV1>,
    cache_admission: Option<Result<(), Closed>>,
    cache_before: Option<Result<(), Closed>>,
    cache_after: Option<Result<(), Closed>>,
    completed_clock: Option<aos_sandbox_model::RawPairedClockSample>,
}

impl RootHeldReleaseTurnOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(FirstV1::Funding))
            || matches!(self.first, Some(FirstV1::CacheFunding))
                && matches!(self.cache_shape, Some(Ok(_)))
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn admission_is_owed_v1(&self) -> bool {
        self.entered && self.before.is_none() && self.admission.is_none()
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn before_is_owed_v1(&self) -> bool {
        self.entered && self.admission.is_none() && self.before.is_none()
            && matches!(self.fixed, Some(Ok(())))
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn after_is_owed_v1(&self) -> bool { self.before.is_some() && self.after.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failed_position_post_is_active_v1(&self) -> bool {
        self.admission_is_owed_v1() && matches!(self.position, Some(Err(_)))
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn cache_admission_is_owed_v1(&self) -> bool {
        self.cache_entered && self.cache_before.is_none() && self.cache_admission.is_none()
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn cache_before_is_owed_v1(&self) -> bool {
        self.cache_admission_is_owed_v1() && matches!(self.cache_fixed, Some(Ok(())))
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn cache_after_is_owed_v1(&self) -> bool { self.cache_before.is_some() && self.cache_after.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failure<'cause>(&'cause self, peer: &'cause CreateStorageRootPeerReceivingOriginalsV1)
        -> Option<&'cause (dyn Error + 'static)> {
        match self.first? {
            FirstV1::Funding => cause(&self.fixed),
            FirstV1::Admission => peer.failure().or_else(|| cause(&self.admission)),
            FirstV1::Before => peer.failure().or_else(|| cause(&self.before)),
            FirstV1::Association => cause(&self.association),
            FirstV1::After => peer.failure().or_else(|| cause(&self.after)),
            FirstV1::CacheFunding => cause(&self.cache_shape)
                .or_else(|| self.cache_source.as_ref().map(|cause| cause as _))
                .or_else(|| self.cache_funding.as_ref().map(|cause| cause as _))
                .or_else(|| cause(&self.cache_fixed)),
            FirstV1::CacheAdmission => peer.failure().or_else(|| cause(&self.cache_admission)),
            FirstV1::CacheBefore => peer.failure().or_else(|| cause(&self.cache_before)),
            FirstV1::CacheAfter => peer.failure().or_else(|| cause(&self.cache_after)),
        }
    }
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn begin_original_source_release_once(&mut self,
        parent: &super::super::ProjectPreparationReservationAttemptV1,
        intake: &mut super::super::Q04OriginalIntakeAttemptV1,
        controller: &mut super::super::Journal,
        source: &mut super::super::ProtectedSourceDomainJournalOwnerV1,
        profile: &super::super::ProductionControllerNormalRootProfileV1,
        cache: &mut super::super::OriginalCreateStorageCacheLoanV1<'_>,
        committed: &OriginalCreateStorageUseCommittedV1<'_>,
        receiving: &mut UseReceivingOriginalsV1,
    ) -> Result<(), Closed> {
        if self.turn.use_tail.releases.entered {
            self.closed.get_or_insert(Closed);
            return Err(Closed);
        }
        self.turn.use_tail.releases.entered = true;
        self.turn.use_tail.releases.position = Some(committed.position_v1());
        self.turn.expected_controller = self.turn.use_tail.releases.position.as_ref()
            .and_then(|position| position.as_ref().ok()).copied();
        self.turn.use_tail.releases.fixed = Some(SourceReleasedOriginalsV1::inline_receiving_demand_v1()
            .and_then(|demand| receiving.reserve_once(demand)));
        if !matches!(self.turn.use_tail.releases.fixed, Some(Ok(()))) {
            self.turn.use_tail.releases.first = Some(FirstV1::Funding);
        }
        let mut loan = OriginalCreateStorageRootExchangeV1 { parent, intake, controller,
            source, profile, cache, state: &mut self.turn, use_receiving: Some(RootUseReceivingV1::Original(receiving)) };
        if loan.state.use_tail.releases.first.is_some()
            || loan.state.expected_controller.is_none()
            || loan.prepay_use_root_observations_once(3).is_err() {
            // Root5 paid this exact refusal before its own final comparison.
            // No new debit can be attempted after the actual U becomes sticky.
            loan.state.owed_post = Some(RootPostFrontierV1::SourceReleaseAdmission);
            let post = self.peer.recheck_once(&mut loan);
            loan.state.use_tail.releases.admission = Some(post);
            loan.state.use_tail.releases.first.get_or_insert(FirstV1::Admission);
            return Err(Closed);
        }
        loan.state.owed_post = Some(RootPostFrontierV1::SourceReleaseBefore);
        let before = self.peer.recheck_once(&mut loan);
        loan.state.use_tail.releases.before = Some(before);
        if matches!(loan.state.use_tail.releases.before, Some(Ok(()))) { Ok(()) }
        else {
            loan.state.use_tail.releases.first = Some(FirstV1::Before);
            Err(Closed)
        }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn finish_original_source_release_once(&mut self,
        parent: &super::super::ProjectPreparationReservationAttemptV1,
        intake: &mut super::super::Q04OriginalIntakeAttemptV1,
        controller: &mut super::super::Journal,
        source: &mut super::super::ProtectedSourceDomainJournalOwnerV1,
        profile: &super::super::ProductionControllerNormalRootProfileV1,
        cache: &mut super::super::OriginalCreateStorageCacheLoanV1<'_>,
        released: Option<&SourceReleasedOriginalsV1>,
        receiving: &mut UseReceivingOriginalsV1,
    ) -> Result<(), Closed> {
        if !self.turn.use_tail.releases.after_is_owed_v1() { return Err(Closed); }
        if let Some(released) = released.filter(|released| released.position_v1().is_ok()) {
            self.turn.use_tail.releases.association = Some(self.turn.expected_cache
                .ok_or(ResourceReservationErrorV1::Conflict)
                .and_then(|expected| expected.after_original_source_release_v1(released)));
            if let Some(Ok(expected)) = self.turn.use_tail.releases.association {
                self.turn.expected_cache = Some(expected);
            } else {
                self.turn.use_tail.releases.first.get_or_insert(FirstV1::Association);
            }
        }
        let mut loan = OriginalCreateStorageRootExchangeV1 { parent, intake, controller,
            source, profile, cache, state: &mut self.turn, use_receiving: Some(RootUseReceivingV1::Original(receiving)) };
        loan.state.owed_post = Some(RootPostFrontierV1::SourceReleaseAfter);
        let after = self.peer.recheck_once(&mut loan);
        loan.state.use_tail.releases.after = Some(after);
        if !matches!(loan.state.use_tail.releases.after, Some(Ok(()))) {
            loan.state.use_tail.releases.first.get_or_insert(FirstV1::After);
        }
        loan.state.use_tail.releases.source_complete = released.is_some_and(|released| released.position_v1().is_ok())
            && matches!(loan.state.use_tail.releases.before, Some(Ok(())))
            && matches!(loan.state.use_tail.releases.association, Some(Ok(_)))
            && matches!(loan.state.use_tail.releases.after, Some(Ok(())))
            && loan.state.use_tail.releases.first.is_none();
        if loan.state.use_tail.releases.source_complete { Ok(()) } else { Err(Closed) }
    }
}

pub(in crate::controller_resource_reservation::create_intake::ready)
struct OriginalCreateStorageCacheReleaseAdmissionV1<'held> {
    turn: &'held RootHeldReleaseTurnOriginalsV1,
    clock: aos_sandbox_model::RawPairedClockSample,
    cutoff: u64,
}

impl OriginalCreateStorageCacheReleaseAdmissionV1<'_> {
    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn shape_v1(&self) -> Result<aos_sandbox_cache::CacheReleasedShapeV1, ResourceReservationErrorV1> {
        if !matches!(self.turn.cache_fixed, Some(Ok(())))
            || !matches!(self.turn.cache_before, Some(Ok(()))) || !self.turn.source_complete {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.turn.cache_shape.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn clock_v1(&self) -> aos_sandbox_model::RawPairedClockSample { self.clock }

    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn cutoff_v1(&self) -> u64 { self.cutoff }
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn begin_original_cache_release_once<'funding, 'profile, 'cache>(
        &mut self,
        parent: &super::super::ProjectPreparationReservationAttemptV1,
        intake: &mut super::super::Q04OriginalIntakeAttemptV1,
        controller: &mut super::super::Journal,
        source: &'funding super::super::ProtectedSourceDomainJournalOwnerV1,
        profile: &'profile super::super::ProductionControllerNormalRootProfileV1,
        cache: &mut super::super::OriginalCreateStorageCacheLoanV1<'cache>,
        committed: &OriginalCreateStorageUseCommittedV1<'_>,
        receiving: &'funding mut UseReceivingOriginalsV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheAuditFundingLoanV1<'funding, 'profile>, Closed>
    where 'cache: 'funding {
        if !self.turn.use_tail.releases.source_complete || self.turn.use_tail.releases.cache_entered {
            self.closed.get_or_insert(Closed);
            return Err(Closed);
        }
        self.turn.use_tail.releases.cache_entered = true;
        self.turn.use_tail.releases.cache_shape = Some(cache.release_receiving_shape_v1());
        let prepared = (|| {
            if self.turn.expected_controller != Some(committed.position_v1()?) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.turn.use_tail.releases.cache_shape.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            super::super::super::use_reserved::release::cache_release_admission_receiving_demand_v1()
        })();
        let funding = match prepared {
            Ok(non_cache) => match source.journal_ref_v1().cache_audit_source_original_v1() {
                Ok(source_original) => match receiving.borrow_cache_funding_v1(profile) {
                    Ok(original) => match cache.bind_release_audit_funding_v1(original, source_original, non_cache) {
                        Ok(funding) => Ok(funding),
                        Err(cause) => {
                            self.turn.use_tail.releases.cache_funding = Some(cause);
                            Err(ResourceReservationErrorV1::Conflict)
                        }
                    },
                    Err(cause) => Err(cause),
                },
                Err(cause) => {
                    self.turn.use_tail.releases.cache_source = Some(cause);
                    Err(ResourceReservationErrorV1::Conflict)
                }
            },
            Err(cause) => Err(cause),
        };
        let mut funding = match funding {
            Ok(funding) => {
                self.turn.use_tail.releases.cache_fixed = Some(Ok(()));
                funding
            }
            Err(cause) => {
                self.turn.use_tail.releases.cache_fixed = Some(Err(cause));
                self.turn.use_tail.releases.first = Some(FirstV1::CacheFunding);
                // The caller returns this failed borrower before finish performs
                // the already-paid refusal post against the same actual U.
                return Err(Closed);
            }
        };
        {
            // Reborrow the same genuine U for the exact old Root prepayment.
            // This creates neither another initial debit nor a paid mirror.
            let root_funding = funding.borrow_root_observation_funding_v1().map_err(|_| Closed)?;
            let mut loan = OriginalCreateStorageRootExchangeV1 { parent, intake,
                controller, source, profile, cache, state: &mut self.turn,
                use_receiving: Some(RootUseReceivingV1::CacheAudit(root_funding)) };
            if loan.prepay_use_root_observations_once(3).is_err() {
                loan.state.owed_post = Some(RootPostFrontierV1::CacheReleaseAdmission);
                let post = self.peer.recheck_once(&mut loan);
                loan.state.use_tail.releases.cache_admission = Some(post);
                loan.state.use_tail.releases.first.get_or_insert(FirstV1::CacheAdmission);
                return Err(Closed);
            }
            loan.state.owed_post = Some(RootPostFrontierV1::CacheReleaseBefore);
            let before = self.peer.recheck_once(&mut loan);
            loan.state.use_tail.releases.cache_before = Some(before);
            if !matches!(loan.state.use_tail.releases.cache_before, Some(Ok(()))) {
                loan.state.use_tail.releases.first = Some(FirstV1::CacheBefore);
                return Err(Closed);
            }
        }
        Ok(funding)
    }

    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn borrow_original_cache_release_admission_v1(&self)
        -> Result<OriginalCreateStorageCacheReleaseAdmissionV1<'_>, ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let proof = OriginalCreateStorageCacheReleaseAdmissionV1 { turn: &self.turn.use_tail.releases,
            clock: self.turn.last_native_clock.ok_or(ResourceReservationErrorV1::Conflict)?,
            cutoff: self.turn.use_tail.outcome_turn.cutoff_v1().ok_or(ResourceReservationErrorV1::Conflict)? };
        proof.shape_v1()?;
        Ok(proof)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn finish_original_cache_release_once(&mut self,
        parent: &super::super::ProjectPreparationReservationAttemptV1,
        intake: &mut super::super::Q04OriginalIntakeAttemptV1,
        controller: &mut super::super::Journal,
        source: &super::super::ProtectedSourceDomainJournalOwnerV1,
        profile: &super::super::ProductionControllerNormalRootProfileV1,
        cache: &mut super::super::OriginalCreateStorageCacheLoanV1<'_>,
        receiving: &mut UseReceivingOriginalsV1,
    ) -> Result<(), Closed> {
        if matches!(self.turn.use_tail.releases.cache_fixed, Some(Err(_))) {
            if self.turn.use_tail.releases.cache_admission.is_some() { return Err(Closed); }
            // No Cache effect was entered. With its failed funding borrower
            // disposed, discharge the original refusal observation on the same
            // actual U before returning the retained funding failure.
            let mut loan = OriginalCreateStorageRootExchangeV1 { parent, intake,
                controller, source, profile, cache, state: &mut self.turn,
                use_receiving: Some(RootUseReceivingV1::Original(receiving)) };
            loan.state.owed_post = Some(RootPostFrontierV1::CacheReleaseAdmission);
            let post = self.peer.recheck_once(&mut loan);
            loan.state.use_tail.releases.cache_admission = Some(post);
            return Err(Closed);
        }
        if !self.turn.use_tail.releases.cache_after_is_owed_v1() { return Err(Closed); }
        let mut loan = OriginalCreateStorageRootExchangeV1 { parent, intake, controller,
            source, profile, cache, state: &mut self.turn, use_receiving: Some(RootUseReceivingV1::Original(receiving)) };
        loan.state.owed_post = Some(RootPostFrontierV1::CacheReleaseAfter);
        let after = self.peer.recheck_once(&mut loan);
        loan.state.use_tail.releases.cache_after = Some(after);
        if matches!(loan.state.use_tail.releases.cache_after, Some(Ok(()))) {
            loan.state.use_tail.releases.completed_clock = loan.state.last_native_clock;
            Ok(())
        } else {
            loan.state.use_tail.releases.first.get_or_insert(FirstV1::CacheAfter);
            Err(Closed)
        }
    }

    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn completed_original_release_clock_v1(&self)
        -> Result<(aos_sandbox_model::RawPairedClockSample, u64), ResourceReservationErrorV1> {
        if self.failure().is_some() || !matches!(self.turn.use_tail.releases.cache_before, Some(Ok(())))
            || !matches!(self.turn.use_tail.releases.cache_after, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((self.turn.use_tail.releases.completed_clock.ok_or(ResourceReservationErrorV1::Conflict)?,
            self.turn.use_tail.outcome_turn.cutoff_v1().ok_or(ResourceReservationErrorV1::Conflict)?))
    }
}
