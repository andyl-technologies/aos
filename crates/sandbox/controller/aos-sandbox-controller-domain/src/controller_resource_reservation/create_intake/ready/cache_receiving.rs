//! Joins actual initialized Cache capture to the same retained Create original.
//!
//! Fixed, captured and reached semantic demand use the sole J ledger. Named
//! currentness destinations retain independent posts after later account refusal;
//! no copied shape or Source receipt can construct a payer or a fresh original.

use std::error::Error;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use crate::cache_residency::{
    CacheHeldClosedV1, CacheHeldCurrentnessSiteV1, CacheHeldErrorV1,
    CacheHeldIdentityDataV1, CacheHeldNativeSemanticShapeV1, OriginalCreateStorageCacheLoanV1,
};
use crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1;
use crate::journal::{CreateStorageWriterPositionOriginalV1, JournalError};
use super::super::history::{CreateStorageWriterPositionV1, HistoryRoleV1};
use super::*;

#[derive(Clone, Copy)]
pub(super) struct OriginalCacheAssociationV1 {
    identity: CacheHeldIdentityDataV1,
    lane: [u8; 16],
    source: [u8; 508],
    source_position: CreateStorageWriterPositionV1,
    clock: RawPairedClockSample,
    cutoff: u64,
}

impl OriginalCacheAssociationV1 {
    pub(super) fn after_original_source_release_v1(&self,
        released: &super::super::history::source_released::SourceReleasedOriginalsV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        released.require_held_source_v1(&self.source, self.lane)?;
        let mut current = *self;
        current.source_position = released.position_v1()?;
        Ok(current)
    }

    pub(super) fn require_original_source_release_v1(&self,
        released: &super::super::history::source_released::SourceReleasedOriginalsV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let current = self.after_original_source_release_v1(released)?;
        if current.source_position == self.source_position { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    // This is the original accepted cutoff already bound to this association.
    // It is comparison DATA, never a renewed deadline or receiving grant.
    pub(super) fn original_cutoff_v1(&self) -> u64 {
        self.cutoff
    }

    // Pure comparison of the actual retained original. No raw identity accessor
    // or new receiving authority is exposed to a later purpose.
    pub(super) fn require_identity_v1(&self, actual: CacheHeldIdentityDataV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        if actual == self.identity { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(super) fn require_clock_v1(&self, current: RawPairedClockSample)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.clock.validate_later_sample(current).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if current.host_boot_id() != self.clock.host_boot_id()
            || current.boottime_nanoseconds() >= self.cutoff {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct CacheCaptureOriginalV1 {
    started: bool,
    association: Option<OriginalCacheAssociationV1>,
    released_association: Option<Box<OriginalCacheAssociationV1>>,
    released_association_result: Option<Result<(), ResourceReservationErrorV1>>,
    fixed_geometry: Option<Result<ResourceVector, CacheHeldErrorV1>>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    rows_ready: bool,
    capture: Option<Result<(), CacheHeldClosedV1>>,
    variable_geometry: Option<Result<ResourceVector, CacheHeldErrorV1>>,
    variable: Option<Result<(), ResourceReservationErrorV1>>,
    captured_paid: bool,
    semantic_failure: Option<CacheHeldErrorV1>,
    preparation: CacheCurrentnessOriginalV1,
    capture_post: CacheCurrentnessOriginalV1,
    before_capture: CacheCurrentnessOriginalV1,
    transition: CacheCurrentnessOriginalV1,
    final_crossing: CacheCurrentnessOriginalV1,
    after_append: CacheCurrentnessOriginalV1,
    after_root: CacheCurrentnessOriginalV1,
}

impl CacheCaptureOriginalV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn Error + 'static)>
    {
        error(&self.fixed_geometry).or_else(|| error(&self.fixed))
            .or_else(|| self.preparation.failure())
            .or_else(|| error(&self.capture)).or_else(|| error(&self.variable_geometry))
            .or_else(|| error(&self.variable)).or_else(|| self.capture_post.failure())
            .or_else(|| self.before_capture.failure()).or_else(|| self.transition.failure())
            .or_else(|| self.final_crossing.failure()).or_else(|| self.semantic_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.after_append.failure()).or_else(|| self.after_root.failure())
            .or_else(|| error(&self.released_association_result))
    }

    // These actual admission failures precede entered Cache native work. Coarse
    // capture statuses and later independent posts project after Cache's own
    // resident rich cause in the enclosing joined scope.
    pub(super) fn funding_failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.fixed_geometry).or_else(|| error(&self.fixed))
            .or_else(|| self.preparation.failure())
            .or_else(|| error(&self.variable_geometry)).or_else(|| error(&self.variable))
            .or_else(|| self.semantic_failure.as_ref().map(|cause| cause as _))
    }

    pub(super) fn currentness_association_v1(&self)
        -> Result<OriginalCacheAssociationV1, ResourceReservationErrorV1>
    {
        self.require_held_join_v1()?;
        self.released_association.as_deref().copied().or(self.association)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn source_release_association_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<OriginalCacheAssociationV1>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<OriginalCacheAssociationV1>()))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?))
    }

    pub(super) fn install_original_source_release_once(&mut self,
        released: &super::super::history::source_released::SourceReleasedOriginalsV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.released_association_result.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let association = self.association.ok_or(ResourceReservationErrorV1::Conflict)
            .and_then(|expected| expected.after_original_source_release_v1(released));
        self.released_association_result = Some(match association {
            Ok(association) => { self.released_association = Some(Box::new(association)); Ok(()) }
            Err(cause) => Err(cause),
        });
        if matches!(self.released_association_result, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(super) fn require_held_join_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if !self.captured_paid || !self.after_append.entered || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    fn slot(&mut self, site: CacheHeldCurrentnessSiteV1) -> &mut CacheCurrentnessOriginalV1 {
        match site {
            CacheHeldCurrentnessSiteV1::BeforeCapture => &mut self.before_capture,
            CacheHeldCurrentnessSiteV1::Transition => &mut self.transition,
            CacheHeldCurrentnessSiteV1::FinalCrossing => &mut self.final_crossing,
            CacheHeldCurrentnessSiteV1::AfterAppend => &mut self.after_append,
            CacheHeldCurrentnessSiteV1::AfterRoot => &mut self.after_root,
        }
    }
}

// Each concrete purpose has a resident once-only destination. Missing Native
// stages cannot shift a later independent post into an earlier numeric slot.
#[derive(Default)]
pub(super) struct CacheCurrentnessOriginalV1 {
    entered: bool,
    original: Option<Result<(), ResourceReservationErrorV1>>,
    profile: Option<Result<(), ResourceReservationErrorV1>>,
    expected_controller: Option<Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>>,
    controller: CreateStorageWriterPositionOriginalV1,
    source: CreateStorageWriterPositionOriginalV1,
    clock_original: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    binding: Option<Result<(), ResourceReservationErrorV1>>,
}

pub(super) struct CacheControlOriginalsV1<'borrow> {
    pub(super) parent: &'borrow ProjectPreparationReservationAttemptV1,
    pub(super) intake: &'borrow crate::controller_resource_reservation::q04_intake::Q04OriginalIntakeAttemptV1,
    pub(super) controller: &'borrow Journal,
    pub(super) source: &'borrow ProtectedSourceDomainJournalOwnerV1,
    pub(super) profile: &'borrow ProductionControllerNormalRootProfileV1,
}

#[derive(Clone, Copy)]
pub(super) enum CurrentnessProfileRouteV1 {
    CacheArchive,
    PreparationReceiving,
}

impl CacheCurrentnessOriginalV1 {
    // Borrows the actual completed observation, without another clock read or
    // detached currentness claim. Only the same paid operation can use it.
    pub(super) fn completed_clock_data_v1(&self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        if !self.entered || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.clock.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }


    fn clock_backing_demand_v1(sites: usize) -> Result<ResourceVector, JournalError> {
        let clock = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(sites)).ok_or(JournalError::JournalTooLarge)?;
        let cells = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|cells| cells.checked_mul(sites)).ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(clock).map_err(|_| JournalError::JournalTooLarge)?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| JournalError::JournalTooLarge)?))
    }

    // Preserves the two native writer/clock providers' namespace bounds.
    // Inline originals, profile/identity tuples and result controls cost bytes.
    pub(super) fn receiving_metadata_cells_v1() -> Result<usize, JournalError> {
        let controller = CreateStorageWriterPositionOriginalV1::receiving_metadata_cells_v1(
            HistoryRoleV1::Controller)?;
        let source = CreateStorageWriterPositionOriginalV1::receiving_metadata_cells_v1(
            HistoryRoleV1::Source)?;
        let clock = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        controller.checked_add(source)
            .and_then(|cells| cells.checked_add(clock))
            .ok_or(JournalError::JournalTooLarge)
    }

    // Pure additional backing for a concrete actual operation roster. The
    // existing HistoryNames owner supplies the mutually exclusive FD peak;
    // actual positive turn disposal is required before that peak is reused.
    // New retained Vec backing and metadata destinations stay cumulatively paid.
    pub(super) fn receiving_backing_demand_v1(sites: usize)
        -> Result<ResourceVector, JournalError>
    {
        if sites == 0 { return Err(JournalError::JournalTooLarge); }
        let lanes = sites.checked_add(7).ok_or(JournalError::JournalTooLarge)? / 8;
        let names = crate::journal::create_storage_name_peak_demand_v1()?;
        let clock = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(sites)).ok_or(JournalError::JournalTooLarge)?;
        let memory = names.get(D::MemoryBytes).checked_mul(
            u64::try_from(lanes).map_err(|_| JournalError::JournalTooLarge)?)
            .and_then(|bytes| bytes.checked_add(u64::try_from(clock).ok()?))
            .ok_or(JournalError::JournalTooLarge)?;
        let cells = Self::receiving_metadata_cells_v1()?.checked_mul(sites)
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| JournalError::JournalTooLarge)?))
    }

    pub(super) fn observe_once(&mut self, original: CacheControlOriginalsV1<'_>,
        cache: &OriginalCreateStorageCacheLoanV1<'_>, expected: OriginalCacheAssociationV1,
        controller_position: Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>,
        require_copied_source: bool) -> Result<(), ResourceReservationErrorV1>
    {
        self.observe_with_route_once(original, cache, expected, controller_position,
            require_copied_source, CurrentnessProfileRouteV1::CacheArchive)
    }

    pub(super) fn observe_operation_once(
        &mut self,
        original: CacheControlOriginalsV1<'_>,
        cache: &OriginalCreateStorageCacheLoanV1<'_>,
        expected: OriginalCacheAssociationV1,
        controller_position: Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.observe_with_route_once(original, cache, expected, controller_position,
            true, CurrentnessProfileRouteV1::PreparationReceiving)
    }

    fn observe_with_route_once(
        &mut self,
        original: CacheControlOriginalsV1<'_>,
        cache: &OriginalCreateStorageCacheLoanV1<'_>,
        expected: OriginalCacheAssociationV1,
        controller_position: Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>,
        require_copied_source: bool,
        route: CurrentnessProfileRouteV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.expected_controller = Some(controller_position);
        self.original = Some((|| {
            if cache.original_identity_v1() != expected.identity {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            cache.require_same_controller_original_v1(original.profile)?;
            original.parent.require_create_storage_association(original.controller, original.source, original.profile)
        })());
        // These are already prepaid independent destinations. In particular,
        // later sticky J/Cache debt cannot short-circuit their actual IO.
        self.profile = Some(match route {
            CurrentnessProfileRouteV1::CacheArchive =>
                original.intake.require_create_history_post_profile_v1(original.profile),
            CurrentnessProfileRouteV1::PreparationReceiving =>
                original.profile.read_create_storage_receiving_producer_v1()
                    .map_err(ResourceReservationErrorV1::from)
                    .and_then(|(recipient, producer)|
                        original.intake.require_create_storage_original_pair_v1(recipient, producer)),
        });
        self.controller.capture_once(original.controller, HistoryRoleV1::Controller);
        self.source.capture_once(original.source.journal_ref_v1(), HistoryRoleV1::Source);
        self.clock = Some(self.clock_original.observe_once(None));
        self.binding = Some((|| {
            let controller = self.controller.position()?;
            let source = self.source.position()?;
            if controller != self.expected_controller.as_ref().and_then(|result| result.as_ref().ok()).copied()
                    .ok_or(ResourceReservationErrorV1::Conflict)?
                || source != expected.source_position {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if require_copied_source && cache.source_held_bytes_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != &expected.source {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let current = self.clock.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            expected.require_clock_v1(current)
        })());
        if self.failure().is_none() { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.expected_controller).or_else(|| error(&self.original)).or_else(|| error(&self.profile))
            .or_else(|| self.controller.failure()).or_else(|| self.source.failure())
            .or_else(|| self.clock_original.failure()).or_else(|| error(&self.clock)).or_else(|| error(&self.binding))
    }
}

impl CreateStorageOriginalLoanV1<'_> {
    pub(crate) fn admit_cache_fixed_once(&mut self, cache: &OriginalCreateStorageCacheLoanV1<'_>)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.owner.cache_capture.started { return Err(ResourceReservationErrorV1::Conflict); }
        self.owner.cache_capture.started = true;
        let fixed = self.admit_cache_fixed_inner(cache);
        self.owner.cache_capture.fixed = Some(fixed);
        if !matches!(self.owner.cache_capture.fixed, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let expected = self.owner.cache_capture.association.ok_or(ResourceReservationErrorV1::Conflict)?;
        let position = self.current_controller_history_position_v1();
        self.owner.cache_capture.preparation.observe_once(CacheControlOriginalsV1 {
            parent: &self.owner.parent, intake: &self.owner.intake,
            controller: self.controller, source: self.source, profile: self.profile,
        }, cache, expected, position, false)
    }

    fn admit_cache_fixed_inner(&mut self, cache: &OriginalCreateStorageCacheLoanV1<'_>)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.owner.intake.require_retained_capture()?;
        self.owner.parent.require_create_storage_association(self.controller, self.source, self.profile)?;
        cache.require_same_controller_original_v1(self.profile)?;
        let identity = cache.original_q04_identity_data_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if !self.owner.parent.matches_create_continuation_identity(&identity) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let lane = self.owner.intake.create_lane()?;
        let receipt = self.owner.histories.source_held_data_v1(lane)?;
        let source_position = CreateStorageWriterPositionV1 { names: receipt.source_names,
            next: receipt.source_after_next, end: receipt.source_after_end };
        let source = receipt.encode(lane).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let accepted = self.accepted()?;
        let clock = self.owner.intake.create_storage_j_data_v1()?.clock;
        self.owner.cache_capture.association = Some(OriginalCacheAssociationV1 {
            identity: cache.original_identity_v1(), lane, source, source_position,
            clock, cutoff: accepted.original_cutoff,
        });
        self.owner.cache_capture.fixed_geometry = Some(cache.fixed_receiving_demand_v1());
        let fixed = self.owner.cache_capture.fixed_geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        self.owner.intake.reserve_create_capture_complete(CreateContinuationCaptureOwnerV1::CacheHeld, fixed)?;

        // Earlier C/S probes are wholly positive and physically disposed. The
        // same fixed peak is reused; retained ancestor Vec backing for both
        // the old seven slots and these seven slots remains cumulatively paid.
        let names = crate::journal::create_storage_name_peak_demand_v1()?;
        let clocks = CacheCurrentnessOriginalV1::clock_backing_demand_v1(7)?;
        // All seven named controls remain resident, including each actual C/S
        // name result and raw clock. An FD peak alone does not price those
        // retained metadata destinations. The helper includes clock cells.
        let control_cells = CacheCurrentnessOriginalV1::receiving_metadata_cells_v1()?
            .checked_mul(7).ok_or(ResourceReservationErrorV1::Conflict)?;
        let control_cells = u64::try_from(control_cells)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let complete_names = names.with(D::MemoryBytes,
            names.get(D::MemoryBytes).checked_mul(2)
                .and_then(|bytes| bytes.checked_add(clocks.get(D::MemoryBytes)))
                .ok_or(ResourceReservationErrorV1::Conflict)?)
            .with(D::MetadataEntries, names.get(D::MetadataEntries).checked_add(control_cells)
                .ok_or(ResourceReservationErrorV1::Conflict)?);
        self.owner.intake.reserve_create_capture_complete(CreateContinuationCaptureOwnerV1::HistoryNames, complete_names)?;
        self.owner.intake.extend_create_capture_observers_once(self.profile, 7 * 2)?;
        self.owner.cache_capture.rows_ready = true;
        Ok(())
    }

    pub(crate) fn admit_cache_capture(&mut self, cache: &mut OriginalCreateStorageCacheLoanV1<'_>)
        -> Result<(), ResourceReservationErrorV1>
    {
        if !self.owner.cache_capture.rows_ready || self.owner.cache_capture.capture.is_some()
            || self.owner.cache_capture.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let expected = self.owner.cache_capture.association.ok_or(ResourceReservationErrorV1::Conflict)?;
        let capture = cache.capture_receiving_shape_once();
        let primary = match capture {
            Ok(shape) => {
                self.owner.cache_capture.capture = Some(Ok(()));
                self.owner.cache_capture.variable_geometry = Some(shape.dominant_receiving_demand_v1());
                let additional = self.owner.cache_capture.variable_geometry.as_ref().and_then(|result| result.as_ref().ok()).copied();
                let fixed = self.owner.cache_capture.fixed_geometry.as_ref().and_then(|result| result.as_ref().ok()).copied();
                let result = (|| {
                    if shape.original_identity_v1() != expected.identity { return Err(ResourceReservationErrorV1::Conflict); }
                    let complete = fixed.ok_or(ResourceReservationErrorV1::Conflict)?
                        .checked_add(additional.ok_or(ResourceReservationErrorV1::Conflict)?)?;
                    self.owner.intake.reserve_create_capture_complete(CreateContinuationCaptureOwnerV1::CacheHeld, complete)
                })();
                self.owner.cache_capture.variable = Some(result);
                if matches!(self.owner.cache_capture.variable, Some(Ok(()))) {
                    self.owner.cache_capture.captured_paid = true;
                    Ok(())
                } else { Err(ResourceReservationErrorV1::Conflict) }
            }
            Err(cause) => {
                self.owner.cache_capture.capture = Some(Err(cause));
                Err(ResourceReservationErrorV1::Conflict)
            }
        };
        // Actual capture/geometry/admission failure still owes its separate
        // prepaid C/S/profile/clock post, even when the J ledger is now closed.
        let position = self.current_controller_history_position_v1();
        let post = self.owner.cache_capture.capture_post.observe_once(CacheControlOriginalsV1 {
            parent: &self.owner.parent, intake: &self.owner.intake,
            controller: self.controller, source: self.source, profile: self.profile,
        }, cache, expected, position, false);
        primary.and(post)
    }

    pub(crate) fn admit_cache_semantic_shape(&mut self, shape: &CacheHeldNativeSemanticShapeV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_cache_named_preparation(shape.original_identity_v1())?;
        let complete = match shape.dominant_receiving_demand_v1() {
            Ok(complete) => complete,
            Err(cause) => {
                self.owner.cache_capture.semantic_failure = Some(cause);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        self.owner.intake.reserve_create_capture_complete(CreateContinuationCaptureOwnerV1::CacheHeld, complete)
    }

    pub(crate) fn require_cache_named_preparation(&self, identity: CacheHeldIdentityDataV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.owner.intake.require_retained_capture()?;
        let expected = self.owner.cache_capture.association.ok_or(ResourceReservationErrorV1::Conflict)?;
        if !self.owner.cache_capture.rows_ready || !self.owner.cache_capture.captured_paid
            || self.owner.cache_capture.failure().is_some() || identity != expected.identity {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_cache_capture_current(&mut self, cache: &OriginalCreateStorageCacheLoanV1<'_>)
        -> Result<(), ResourceReservationErrorV1>
    {
        if !self.owner.cache_capture.rows_ready { return Err(ResourceReservationErrorV1::Conflict); }
        let expected = self.owner.cache_capture.association.ok_or(ResourceReservationErrorV1::Conflict)?;
        let site = cache.currentness_site_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let position = self.current_controller_history_position_v1();
        self.owner.cache_capture.slot(site).observe_once(CacheControlOriginalsV1 {
            parent: &self.owner.parent, intake: &self.owner.intake,
            controller: self.controller, source: self.source, profile: self.profile,
        }, cache, expected, position, true)
    }


}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}
