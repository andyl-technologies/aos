//! Retains the original Source and Cache releases after native positive U.
//!
//! A release receipt can be lent only by these actual returned/readback owners.
//! The committed bank claim remains immutable if a later writer or post fails.

use super::*;
use super::super::super::history::source_released::SourceReleasedOriginalsV1;

/// Keeps only late-owner handles until actual U admission creates the backing.
#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake)
struct ReleaseOriginalsV1 {
    source: Option<Box<SourceReleasedOriginalsV1>>,
    source_invoked: bool,
    source_returned: Option<Result<(), CreateStorageReadyClosedV1>>,
    cache_invoked: bool,
    cache_returned: Option<Result<(), CreateStorageReadyClosedV1>>,
    cache: Option<Box<crate::cache_programmes::CacheReleasedOriginalsV1>>,
    admission: Option<Box<CacheReleaseAdmissionOriginalsV1>>,
    complete: bool,
    cutoff: Option<u64>,
    clock: Option<aos_sandbox_model::RawPairedClockSample>,
}

/// Borrows both actual released writers beside the same committed bank owner.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageReleasedV1<'held> {
    originals: &'held ReleaseOriginalsV1,
    committed: OriginalCreateStorageUseCommittedV1<'held>,
}

impl ReleaseOriginalsV1 {
    pub(super) fn borrow_released_v1<'held>(&'held self,
        committed: OriginalCreateStorageUseCommittedV1<'held>,
    ) -> Result<OriginalCreateStorageReleasedV1<'held>, ResourceReservationErrorV1> {
        committed.position_v1()?;
        committed.transition_v1()?;
        if !self.complete || self.failure().is_some() || self.clock.is_none() || self.cutoff.is_none() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.source.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?.receipt_v1()?;
        self.cache.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?.receipt_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(OriginalCreateStorageReleasedV1 { originals: self, committed })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn selected_primary_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.source_invoked {
            if let Some(cause) = self.source.as_deref().and_then(SourceReleasedOriginalsV1::failure)
                .or_else(|| self.source_returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)) {
                return Some(cause);
            }
        }
        self.cache_invoked.then(|| self.cache_primary_failure_v1()
            .or_else(|| self.cache_returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))).flatten()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn funding_failure_is_selected_v1(&self) -> bool {
        self.source_invoked && self.source.as_deref()
            .is_some_and(SourceReleasedOriginalsV1::funding_failure_is_selected_v1)
            || self.cache_invoked && self.cache.as_deref().is_some_and(
                crate::cache_programmes::CacheReleasedOriginalsV1::append_funding_failure_is_selected_v1,
            )
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.selected_primary_failure_v1()
    }

    fn cache_primary_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().and_then(SourceReleasedOriginalsV1::failure)
            .or_else(|| self.admission.as_deref().and_then(CacheReleaseAdmissionOriginalsV1::failure))
            .or_else(|| self.cache.as_deref().and_then(|cache| cache.selected_control_v1())
                .and_then(|site| self.admission.as_deref().and_then(|admission| admission.control_failure(site))))
            .or_else(|| self.cache.as_deref().and_then(crate::cache_programmes::CacheReleasedOriginalsV1::failure))
    }
}

impl<'held> OriginalCreateStorageReleasedV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn source_receipt_v1(&self) -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::
        continuation::ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        self.originals.source.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?.receipt_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cache_receipt_v1(&self) -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::
        continuation::ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        self.originals.cache.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?.receipt_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn committed_v1(&self) -> &OriginalCreateStorageUseCommittedV1<'held> { &self.committed }

    pub(super) fn cache_original_v1(&self) -> Result<&'held crate::cache_programmes::CacheReleasedOriginalsV1, ResourceReservationErrorV1> {
        if !self.originals.complete || self.originals.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.originals.cache.as_deref().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.originals.cutoff.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn clock_v1(&self) -> Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1> {
        self.originals.clock.ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Releases the same original Source Held owner after actual U commit.
    ///
    /// The late Source owner is allocated only after its concrete U admission.
    /// The actual Root before/after destinations surround every entered native
    /// outcome; a failed entry consumes the preceding prepaid refusal slot.
    ///
    /// # Errors
    /// Retains incomplete U/Root5, reentry, changed original association,
    /// financial, append/readback or independently owed post failures.
    #[doc(hidden)]
    pub fn release_original_storage_source_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() { return Err(CreateStorageReadyClosedV1); }
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        let (_, append, width, receiving) = actual.reservation.split_commit_inputs_v1()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let reserved = OriginalCreateStorageUseReservedV1 { append,
            request_shape_bytes: width, record: &actual.reserved };
        let committed = commit::completed_committed_view_v1(reserved, &actual.outcome, &actual.commit)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let before = owner.root_exchange.begin_original_source_release_once(&owner.parent, &mut owner.intake,
            self.original.controller, self.original.source, self.original.profile, &mut self.cache,
            &committed, receiving);
        let primary = if before.is_ok() {
            // Root entry reserved the actual construction and retained backing.
            actual.release.source_invoked = true;
            actual.release.source = Some(Box::new(SourceReleasedOriginalsV1::default()));
            (|| {
                let root = owner.root_exchange.borrow_committed_outcome_v1(&committed)
                    .map_err(|_| CreateStorageReadyClosedV1)?;
                let released = actual.release.source.as_deref_mut().ok_or(CreateStorageReadyClosedV1)?;
                released.produce_once(&owner.parent, &mut owner.intake, &owner.histories,
                    self.original.controller, self.original.source, self.original.profile,
                    &committed, &root, receiving).map_err(|_| CreateStorageReadyClosedV1)?;
                owner.cache_capture.install_original_source_release_once(released)
                    .map_err(|_| CreateStorageReadyClosedV1)
            })()
        } else { Err(CreateStorageReadyClosedV1) };
        // A failed before still owes this actual after; a pure admission
        // refusal already consumed its one separately prepaid destination.
        let primary_ok = primary.is_ok();
        actual.release.source_returned = Some(primary);
        let after = owner.root_exchange.finish_original_source_release_once(&owner.parent, &mut owner.intake,
            self.original.controller, self.original.source, self.original.profile, &mut self.cache,
            actual.release.source.as_deref(), receiving);
        if primary_ok && after.is_ok() { Ok(()) } else { Err(CreateStorageReadyClosedV1) }
    }
}

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use crate::cache_programmes::{CacheReleasedOriginalsV1, CacheReleasedCurrentnessSiteV1};
use aos_sandbox_cache::{CacheReleasedShapeV1, CacheHeldIdentityDataV1};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheAuditFundingLoanV1;
use super::super::cache_receiving::{CacheControlOriginalsV1, CacheCurrentnessOriginalV1,
    OriginalCacheAssociationV1};

#[derive(Default)]
struct CacheReleaseAdmissionOriginalsV1 {
    named: Option<Result<(), ResourceReservationErrorV1>>,
    controls: [CacheCurrentnessOriginalV1; 4],
    returned: [Option<Result<(), ResourceReservationErrorV1>>; 4],
}

/// Keeps the actual committed U borrowed beside the same mutable Cache owner.
///
/// This closed borrower has no constructor outside the genuine Ready release
/// entry. Shape and original inputs remain borrowed through all parser hooks.
pub(crate) struct CacheReleaseReceivingLoanV1<'borrow> {
    parent: &'borrow ProjectPreparationReservationAttemptV1,
    intake: &'borrow mut Q04OriginalIntakeAttemptV1,
    controller: &'borrow Journal,
    source: &'borrow ProtectedSourceDomainJournalOwnerV1,
    profile: &'borrow ProductionControllerNormalRootProfileV1,
    committed: &'borrow OriginalCreateStorageUseCommittedV1<'borrow>,
    source_released: &'borrow SourceReleasedOriginalsV1,
    root: super::super::root_exchange::OriginalCreateStorageRootOutcomeV1<'borrow>,
    expected: OriginalCacheAssociationV1,
    funding: ControllerCacheAuditFundingLoanV1<'borrow, 'borrow>,
    state: &'borrow mut CacheReleaseAdmissionOriginalsV1,
    admission: super::super::root_exchange::OriginalCreateStorageCacheReleaseAdmissionV1<'borrow>,
}

impl<'borrow> CacheReleaseReceivingLoanV1<'borrow> {
    pub(crate) fn native_funding_v1(&mut self) -> &mut ControllerCacheAuditFundingLoanV1<'borrow, 'borrow> {
        &mut self.funding
    }

    pub(crate) fn lane_v1(&self) -> Result<[u8; 16], ResourceReservationErrorV1> {
        self.intake.create_lane()
    }

    pub(crate) fn cache_native_base_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.admission.shape_v1().map(|shape| shape.complete_receiving_demand_v1())
    }

    pub(crate) fn cache_current_semantic_peak_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.admission.shape_v1().map(|shape| shape.semantic_peak_v1())
    }

    pub(crate) fn require_cache_named_preparation(&mut self, identity: CacheHeldIdentityDataV1)
        -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.funding.require_storage_use_reserved_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.committed.require_current_state_v1(self.controller.controller_resource_state_v1()?)?;
            self.intake.require_retained_capture()?;
            self.parent.require_create_storage_association(self.controller, self.source, self.profile)?;
            self.expected.require_identity_v1(identity)?;
            self.expected.require_original_source_release_v1(self.source_released)?;
            let shape = self.admission.shape_v1()?;
            if shape.identity_v1() != identity {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })();
        // A later successful name check does not replace an earlier refusal.
        if self.state.named.as_ref().is_none_or(|result| result.is_ok()) {
            self.state.named = Some(result);
        }
        if matches!(self.state.named, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(crate) fn require_cache_release_shape_v1(&mut self, actual: &CacheReleasedShapeV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_cache_named_preparation(actual.identity_v1())?;
        if *actual == self.admission.shape_v1()? { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(crate) fn released_body_v1(&self, held: [u8; 32])
        -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::ReleasedBodyDataV1,
            ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationKindV1;
        let lane = self.lane_v1()?;
        let root = self.root.receipt_v1()?.record_data(lane, ContinuationKindV1::OutcomeRecorded)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let recorded = self.committed.recorded_v1().receipt_v1()?
            .record_data(lane, ContinuationKindV1::ControllerOutcomeRecorded)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::ReleasedBodyDataV1 {
            root_outcome: root.checksum(), held, controller_outcome: recorded.checksum(),
        })
    }

    pub(crate) fn observe_cache_release_currentness_once(&mut self,
        cache: &aos_sandbox_cache::CacheHeldCurrentnessOriginalV1<'_>,
        site: CacheReleasedCurrentnessSiteV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let index = match site {
            CacheReleasedCurrentnessSiteV1::Before => 0,
            CacheReleasedCurrentnessSiteV1::Transition => 1,
            CacheReleasedCurrentnessSiteV1::FinalCrossing => 2,
            CacheReleasedCurrentnessSiteV1::After => 3,
        };
        if self.state.returned[index].is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        // These were paid before entering Cache. Debt cannot suppress an
        // independently owed actual C/Source/profile/clock observation.
        self.state.returned[index] = Some(self.state.controls[index].observe_operation_once(
            CacheControlOriginalsV1 { parent: self.parent, intake: self.intake,
                controller: self.controller, source: self.source, profile: self.profile },
            cache, self.expected, self.committed.position_v1(),
        ));
        if matches!(self.state.returned[index], Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(crate) fn require_current_clock_v1(&self, sample: RawPairedClockSample)
        -> Result<(), ResourceReservationErrorV1> {
        let original = self.admission.clock_v1();
        original.validate_later_sample(sample).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if sample.host_boot_id() != original.host_boot_id()
            || sample.boottime_nanoseconds() >= self.admission.cutoff_v1() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl CacheReleaseAdmissionOriginalsV1 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.named.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
    }

    fn control_failure(&self, site: CacheReleasedCurrentnessSiteV1)
        -> Option<&(dyn std::error::Error + 'static)> {
        let index = match site {
            CacheReleasedCurrentnessSiteV1::Before => 0,
            CacheReleasedCurrentnessSiteV1::Transition => 1,
            CacheReleasedCurrentnessSiteV1::FinalCrossing => 2,
            CacheReleasedCurrentnessSiteV1::After => 3,
        };
        self.controls[index].failure().or_else(|| self.returned[index].as_ref()
            .and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

pub(in crate::controller_resource_reservation::create_intake::ready)
fn cache_release_admission_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let bytes = std::mem::size_of::<CacheReleaseAdmissionOriginalsV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::align_of::<CacheReleaseAdmissionOriginalsV1>()))
        .and_then(|bytes| bytes.checked_add(ControllerCacheAuditFundingLoanV1::root_observation_funding_receiving_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(super::super::root_exchange::RootUseReceivingV1::cache_audit_receiving_bytes_v1()?))
        // The actual Release caller maps the native Root borrower Result to
        // Closed before constructing its Root loan. Both forwarding planes
        // coexist with the native funding Result already in its own supplier.
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheRootObservationFundingLoanV1<'_>,
            super::super::root_exchange::CreateStorageRootExchangeClosedV1,
        >>().checked_mul(2)?))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let (wire, logs) = ProductionControllerNormalRootProfileV1::create_storage_producer_traffic_bound_v1(4)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::NetworkBytes, wire).with(D::LogBytes, logs)
        .checked_add(CacheCurrentnessOriginalV1::receiving_backing_demand_v1(4)?)?
        .checked_add(cache_terminal::receiving_demand_v1()?)
        .map_err(ResourceReservationErrorV1::from)
}

/// Prices both actual held-release producers from their original captured ends.
///
/// Source uses its own compiled limits and native Held position. HOLD alone
/// grows among the five Cache writers. The actual producers use these same
/// suppliers before allocation, append and sequential terminal reader growth.
/// This is cost DATA and cannot construct a release owner or receiving lender.
///
/// # Errors
/// Rejects another Source recipe, an out-of-limit release forecast or checked
/// native/model/row/byte arithmetic overflow.
#[doc(hidden)]
pub fn create_storage_held_release_receiving_demand_v1(
    source_extent: &crate::journal::ProtectedJournalPreopenReplayExtentV1,
    cache_extents: &[aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1; 5],
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    if source_extent.limits != crate::source_domain::source_domain_journal_limits() {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    let append = aos_sandbox_cache::release_append_bytes_v1()
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let source = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        source_extent.limits, source_extent.native_bytes.checked_add(append)
            .ok_or(ResourceReservationErrorV1::Conflict)?,
    )?;
    let semantic = source.dominant_semantic_receiving_demand_v1()?;
    SourceReleasedOriginalsV1::fixed_receiving_demand_v1(&semantic)?
        .checked_add(crate::cache_programmes::initialization::create_storage::released::release_receiving_demand_v1(cache_extents)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?)?
        .checked_add(cache_release_admission_receiving_demand_v1()?)
        .map_err(ResourceReservationErrorV1::from)
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Releases the original Cache Held owner after native Source Released.
    ///
    /// The same U funds the distinct late owner before allocation. All five
    /// terminal audits retain their old ordinals and use the sole native reader;
    /// both Held and Released must occupy the exact observed suffix. Native
    /// clock custody remains armed until the later genuine Root6 terminal.
    ///
    /// # Errors
    /// Retains reentry, missing positive committed U/Source release, changed
    /// originals, funding, native append/readback/audit or owed Root post failure.
    #[doc(hidden)]
    pub fn release_original_storage_cache_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() { return Err(CreateStorageReadyClosedV1); }
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        let (_, append, width, receiving) = actual.reservation.split_commit_inputs_v1()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let reserved = OriginalCreateStorageUseReservedV1 { append,
            request_shape_bytes: width, record: &actual.reserved };
        let committed = commit::completed_committed_view_v1(reserved, &actual.outcome, &actual.commit)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let before = owner.root_exchange.begin_original_cache_release_once(&owner.parent, &mut owner.intake,
            self.original.controller, self.original.source, self.original.profile, &mut self.cache,
            &committed, receiving);
        let primary = if let Ok(funding) = before {
            // The preceding exact Cache shape includes both late allocations
            // and every independently owed native/control destination.
            actual.release.cache_invoked = true;
            actual.terminal = Some(Box::new(cache_terminal::CacheTerminalControlOriginalsV1::default()));
            actual.release.admission = Some(Box::new(CacheReleaseAdmissionOriginalsV1::default()));
            actual.release.cache = Some(Box::new(CacheReleasedOriginalsV1::default()));
            (|| {
                let root = owner.root_exchange.borrow_committed_outcome_v1(&committed)
                    .map_err(|_| CreateStorageReadyClosedV1)?;
                let admission = owner.root_exchange.borrow_original_cache_release_admission_v1()
                    .map_err(|_| CreateStorageReadyClosedV1)?;
                let expected = owner.cache_capture.currentness_association_v1()
                    .map_err(|_| CreateStorageReadyClosedV1)?;
                let source_released = actual.release.source.as_deref().ok_or(CreateStorageReadyClosedV1)?;
                let mut loan = CacheReleaseReceivingLoanV1 { parent: &owner.parent, intake: &mut owner.intake,
                    controller: self.original.controller, source: self.original.source, profile: self.original.profile,
                    committed: &committed, source_released, root, expected, funding,
                    state: actual.release.admission.as_deref_mut().ok_or(CreateStorageReadyClosedV1)?, admission };
                self.cache.release_original_held_once(actual.release.cache.as_deref_mut()
                    .ok_or(CreateStorageReadyClosedV1)?, &mut loan).map_err(|_| CreateStorageReadyClosedV1)
            })()
        } else { Err(CreateStorageReadyClosedV1) };
        let primary_ok = primary.is_ok();
        actual.release.cache_returned = Some(primary);
        let after = owner.root_exchange.finish_original_cache_release_once(&owner.parent, &mut owner.intake,
            self.original.controller, self.original.source, self.original.profile, &mut self.cache, receiving);
        if primary_ok && after.is_ok() && actual.release.failure().is_none() {
            let (clock, cutoff) = owner.root_exchange.completed_original_release_clock_v1()
                .map_err(|_| CreateStorageReadyClosedV1)?;
            actual.release.clock = Some(clock);
            actual.release.cutoff = Some(cutoff);
            actual.release.complete = true;
            Ok(())
        } else { Err(CreateStorageReadyClosedV1) }
    }
}

#[cfg(test)]
mod release_cause_tests {
    use super::*;

    #[test]
    fn an_uninvoked_release_cannot_replace_the_actual_root_before_cause() {
        let mut owner = ReleaseOriginalsV1::default();
        owner.source_returned = Some(Err(CreateStorageReadyClosedV1));

        assert!(owner.selected_primary_failure_v1().is_none());

        owner.source_invoked = true;
        let original = owner.source_returned.as_ref().unwrap().as_ref().unwrap_err() as *const CreateStorageReadyClosedV1;
        let selected = owner.selected_primary_failure_v1().unwrap().downcast_ref::<CreateStorageReadyClosedV1>().unwrap();
        assert!(std::ptr::eq(original, selected));
        assert!(!owner.complete);
    }
}
