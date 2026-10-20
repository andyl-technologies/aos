//! Retains the genuine C17 Cache query over the same initialized five owners.
//!
//! A genuinely initialized or completed Root6 owner enters a new paid Delete purpose;
//! neither Initial Create's once-loan nor its financial peak is reset/reused.
//! Every five-reader failure and independently owed name/physical/clock/C post
//! remains on this query. The pure row fold is the ordinary sole implementation.

use super::*;
use aos_sandbox_core::ResourceDimension as D;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1;
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use crate::cache_residency::recovery::{
    CacheReplayRepresentationPhaseV1, general_replay_representation_bound_v1,
};

pub(super) mod native_admission;
mod source;
mod metadata_graph;
use native_admission::CacheDeleteReadAdmissionV1;
use source::CacheQuerySourceV1;

/// Retains the same five initialized Cache owners and completed Delete inventory.
#[doc(hidden)]
pub struct CacheDeleteInventoryOriginalV1<'cache> {
    originals: CacheHeldOriginalsV1<'cache>,
    identity: CacheHeldIdentityDataV1,
    progress: CacheHeldProgressV1,
    inventory: Option<Result<CacheLifecycleBootInventoryV1, CacheResidencyProtectedJournalErrorV1>>,
    authority_post: Option<CacheResidencyProtectedJournalErrorV1>,
    complete: bool,
    coordinates: Option<([u8; 16], u64)>,
    association: Option<CacheDeleteQueryAssociationV1>,
    metadata_graph: metadata_graph::CacheDeleteMetadataGraphOriginalsV2<'cache>,
    predecessor: Option<Box<CacheDeleteCompletedPayloadsV2<'cache>>>,
    successor_admission: Option<Result<(), JournalError>>,
}

// The immutable completed first read stays owned while the exact mutable
// Cache references move once into the pending query. No journal is reopened,
// model is adopted, failed prefix retired or native destination rearmed.
struct CacheDeleteCompletedPayloadsV2<'cache> {
    _progress: CacheHeldProgressV1,
    _inventory: Option<Result<CacheLifecycleBootInventoryV1, CacheResidencyProtectedJournalErrorV1>>,
    _authority_post: Option<CacheResidencyProtectedJournalErrorV1>,
    _coordinates: Option<([u8; 16], u64)>,
    _association: Option<CacheDeleteQueryAssociationV1>,
    _metadata_graph: metadata_graph::CacheDeleteMetadataGraphOriginalsV2<'cache>,
}

// These private comparison fields are captured only from the genuine Source
// pair/live Root borrower. Keeping them on the positive owner prevents a cut
// from another C17 operation or purpose from being silently adopted later.
enum CacheDeleteQueryAssociationV1 {
    Planning {
        project: [u8; 16], caller: [u8; 16], input_digest: [u8; 32],
        authorization_clock: aos_sandbox_core::RawPairedClockSample, authorization_expires: i64,
        funding: aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1,
        controller_next: u64, controller_end: u64, source_next: u64, source_end: u64,
    },
    Preaccept {
        open: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootOpenDataV2,
        challenge: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootChallengeDataV2,
        funding: aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1,
        controller_next: u64, controller_end: u64,
    },
}

/// Retains one genuinely C17-funded Cache query and its independent native posts.
#[doc(hidden)]
pub struct CacheDeleteInventoryQueryV1<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile> {
    // Abandonment aborts before any borrowed clock/native original can drop.
    receiving: CacheDeleteReadAdmissionV1<'profile>,
    source: CacheQuerySourceV1<'query, 'fence, 'journal, 'original, 'authorization>,
    controller: &'query mut Journal,
    launch: &'query ControllerBankLaunchOriginalV1,
    profile: &'profile ControllerSelfProfileOriginalV1,
    cache: CacheDeleteInventoryOriginalV1<'cache>,
    entry: Option<Result<(), CacheHeldErrorV1>>,
    shape_admission: Option<Result<(), JournalError>>,
    source_started: Option<Result<(), JournalError>>,
    source_finished: Option<Result<(), JournalError>>,
    controller_before: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    controller_after: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    controller_before_access: Option<JournalError>,
    controller_after_access: Option<JournalError>,
    deadline_samples: [Option<rustix::time::Timespec>; 8],
    deadline_results: [Option<Result<(), JournalError>>; 8],
    deadline_next: usize,
    reader_returned: Option<Result<(), CacheHeldClosedV1>>,
    completed_readers: usize,
    disposal: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    attempted: bool,
    outer_source_after: Option<Result<(), JournalError>>,
    first: Option<DeleteFailureV1>,
}

#[derive(Clone, Copy)]
enum DeleteFailureV1 {
    Entry,
    SourceBefore,
    ControllerBefore,
    ControllerBeforeAccess,
    Shape,
    Admission,
    Reader,
    Projection,
    NativeAfter,
    SourceAfter,
    ControllerAfter,
    ControllerAfterAccess,
    Deadline(usize),
    Disposal,
    Snapshots,
    Reentry,
}

pub(super) fn fixed_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
    let bytes = std::mem::size_of::<CacheDeleteInventoryOriginalV1<'_>>().checked_mul(3)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheDeleteInventoryQueryV1<'_, '_, '_, '_, '_, '_, '_>>()
            .checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheDeleteReadAdmissionV1<'_>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(super::super::super::super::DormantCacheOwnerV1::original_q04_recheck_scratch_bytes()))
        .ok_or(CacheHeldErrorV1::Order)?;
    // Shared native paths/namespace suppliers are preserved. No Option,
    // Result, header, FD-carrier or scalar-control metadata fee is added here.
    let native = receiving::fixed_readonly_demand(bytes, 2 * 5 + 5 * 5)?;
    native.checked_add(crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1::planning_root_fixed_demand_v1()?)
        .map_err(Into::into)
}

pub(super) fn additional_demand_v1(
    writers: &[crate::journal::CacheHeldWriterShapeV1; 5],
    authority: &Journal,
    state: &Journal,
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let mut native = ResourceVector::ZERO;
    let mut semantic = ResourceVector::ZERO;
    for writer in writers {
        native = native.componentwise_max(writer.extent.dominant_native_receiving_demand_v1()?);
        semantic = semantic.componentwise_max(writer.extent.dominant_semantic_receiving_demand_v1()?);
    }
    let geometry = CacheReplayManifestGeometryV1::from_initial_journals(
        authority, state, CacheRecoveryLimitsV1::default(),
    )?;
    let models = general_replay_representation_bound_v1(
        geometry.encoded_bytes(), geometry.partition_bound(), CacheReplayRepresentationPhaseV1::InitialInventory,
    )?;
    // Each reconstructed payload consumes at least one encoded byte and adds
    // at most reservation+catalog rows, while every pin consumes another byte.
    // Thus 3*encoded bounds exactly this actionable entry class, including its
    // pre-deduplication Vec growth; it is not bytes times a largest DTO.
    let entries = geometry.encoded_bytes().checked_mul(3)
        .and_then(|count| count.checked_mul(std::mem::size_of::<crate::lifecycle::LifecycleBootDomainEntryV1>()))
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheLifecycleBootInventoryV1>().checked_mul(3)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(CacheHeldErrorV1::Order)?;
    native.checked_add(semantic)?.checked_add(models)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, entries)).map_err(Into::into)
}

impl CacheResidentInitializationV1 {
    // Both entrances retain the same real five-owner initialization: either
    // its actual native completion or its later actual Root6 continuation.
    // Neither parses cold terminal DATA into a positive owner or resets once state.
    fn borrow_delete_inventory_originals_v1<'cache>(
        &'cache mut self,
        owner: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache super::super::super::super::DormantCacheOwnerV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<CacheDeleteInventoryOriginalV1<'cache>, CacheHeldClosedV1> {
        let same_clock = self.clock.as_ref().zip(owner.clock.as_ref())
            .is_some_and(|(initial, current)| Arc::ptr_eq(initial, current));
        let same_authority = self.targets.initialized_authority.as_ref()
            .is_some_and(|initial| Arc::ptr_eq(initial, &owner.authority));
        let selected = self.selected_baseline.as_ref().ok_or(CacheHeldClosedV1)?;
        let initialized = self.complete;
        let root_continuation = self.create_storage_held.finished
            && matches!(self.create_storage_held.root, Some(Ok(())));
        if self.first_failure.is_some() || self.postcheck.is_some() || selected.originals.failure().is_some()
            || self.create_storage_held.failure().is_some() || !(initialized || root_continuation)
            || !same_clock || !same_authority || !selected.originals.matches_original(profile)
        {
            return Err(CacheHeldClosedV1);
        }
        let initialization = self as *const Self as usize;
        let owner_identity = owner as *const CacheResidencyProtectedOwnerV1 as usize;
        let (Some(clock_owner), Some(source), Some((hold, _)), Some(state)) =
            (self.clock.as_ref(), self.source.as_mut(), self.hold.as_mut(), owner.state_journal.as_mut())
        else { return Err(CacheHeldClosedV1); };
        let identity = CacheHeldIdentityDataV1 {
            initialization, owner: owner_identity, source: source as *const _ as usize,
            state: state as *const Journal as usize, authority: Arc::as_ptr(&owner.authority) as usize,
            clock: Arc::as_ptr(clock_owner) as usize, physical: physical as *const _ as usize,
            uid: owner.owner_uid,
        };
        Ok(CacheDeleteInventoryOriginalV1 {
            originals: CacheHeldOriginalsV1 {
                construction: &selected.originals, q04: &self.q04, original_hold: self.original_hold,
                source, state, hold: Some(hold), authority: &owner.authority,
                clock_owner, clock: None, physical, physical_identity: None, uid: owner.owner_uid,
            },
            identity, progress: CacheHeldProgressV1::default(), inventory: None, authority_post: None,
            complete: false, coordinates: None, association: None,
            metadata_graph: metadata_graph::CacheDeleteMetadataGraphOriginalsV2::default(),
            predecessor: None, successor_admission: None,
        })
    }
}

impl<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
    CacheDeleteInventoryQueryV1<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
{
    // Each owning sample is retained before its cutoff verdict. Positive audit
    // scratch cannot be disposed after a late native completion.
    fn observe_deadline_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        let index = self.deadline_next;
        if index >= self.deadline_samples.len() {
            self.first.get_or_insert(DeleteFailureV1::Reentry);
            self.receiving.turn.refuse_primary_v1();
            return Err(CacheHeldClosedV1);
        }
        self.deadline_next += 1;
        self.deadline_samples[index] = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.deadline_results[index] = Some((|| {
            let (_, cutoff) = self.source.coordinates_v1()?;
            require_before_sample_v1(self.deadline_samples[index], cutoff)
        })());
        if matches!(self.deadline_results[index], Some(Ok(()))) { Ok(()) }
        else {
            self.first.get_or_insert(DeleteFailureV1::Deadline(index));
            Err(CacheHeldClosedV1)
        }
    }

    /// Runs the five retained readers and complete protected inventory reducer.
    ///
    /// # Errors
    /// Retains the first native, cutoff, authority or C17 failure and all owed posts.
    #[doc(hidden)]
    pub fn run_once_v1(&mut self) -> Result<(), JournalError> {
        self.run_inner_once_v1().map_err(|_| JournalError::ProtectedBoundary)
    }

    fn run_inner_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        if self.attempted {
            self.first.get_or_insert(DeleteFailureV1::Reentry);
            self.receiving.turn.refuse_primary_v1();
            return Err(CacheHeldClosedV1);
        }
        self.attempted = true;
        match self.controller.controller_coordinator_for_bank_read_v1() {
            Ok(writer) => {
                self.controller_before = Some(self.receiving.turn.observe_before_once_v1(writer));
                if matches!(self.controller_before, Some(Err(_))) {
                    self.first.get_or_insert(DeleteFailureV1::ControllerBefore);
                }
            }
            Err(cause) => {
                self.controller_before_access = Some(cause);
                self.first.get_or_insert(DeleteFailureV1::ControllerBeforeAccess);
            }
        }
        if self.first.is_none() {
            self.source_started = Some(self.source.begin_nonce_once_v1());
            if matches!(self.source_started, Some(Err(_))) {
                self.first.get_or_insert(DeleteFailureV1::SourceBefore);
            }
        }
        if self.first.is_none() { let _ = self.observe_deadline_once_v1(); }
        if self.first.is_none() {
            self.entry = Some(self.capture_and_admit_v1());
            if matches!(self.entry, Some(Err(_))) {
                self.first.get_or_insert(DeleteFailureV1::Entry);
            }
        }
        while self.first.is_none() && self.completed_readers < 5 {
            self.audit_next_once_v1();
        }
        if self.first.is_none() { self.project_inventory_once_v1(); }
        if self.first.is_none() { self.observe_metadata_graph_once_v2(); }

        // This outer set is independent of the primary and each reader's own
        // post set. It remains owed even after shape/payment/parser refusal.
        self.cache.progress.posts[2] = Some(audit::observe_bookends(
            &mut self.cache.originals, &self.cache.progress, None,
        ));
        if self.cache.progress.posts[2].as_ref().is_some_and(|posts| posts.failure().is_some()) {
            self.first.get_or_insert(DeleteFailureV1::NativeAfter);
        }
        // The paired authorization after is prepaid before the first C/native
        // primary. A failed C before cannot suppress this independent sample.
        self.source_finished = Some(self.source.finish_nonce_once_v1());
        if matches!(self.source_finished, Some(Err(_))) {
            self.first.get_or_insert(DeleteFailureV1::SourceAfter);
        }
        match self.controller.controller_coordinator_for_bank_read_v1() {
            Ok(writer) => {
                self.controller_after = Some(self.receiving.turn.observe_after_once_v1(writer));
                if matches!(self.controller_after, Some(Err(_))) {
                    self.first.get_or_insert(DeleteFailureV1::ControllerAfter);
                }
            }
            Err(cause) => {
                self.controller_after_access = Some(cause);
                self.first.get_or_insert(DeleteFailureV1::ControllerAfterAccess);
            }
        }
        let _ = self.observe_deadline_once_v1();
        if self.first.is_some() {
            self.receiving.turn.refuse_primary_v1();
            Err(CacheHeldClosedV1)
        } else { Ok(()) }
    }

    fn capture_and_admit_v1(&mut self) -> Result<(), CacheHeldErrorV1> {
        let clock: &'cache ProtectedCacheClockV1 = self.cache.originals.clock_owner.as_ref();
        match clock.hold_writer_for_create_storage_readback(&mut self.cache.progress.clock_position) {
            Ok(guard) => {
                self.cache.originals.clock = Some(guard);
                self.cache.progress.clock = Some(Ok(()));
            }
            Err(cause) => {
                self.cache.progress.clock = Some(Err(cause.into()));
                self.cache.progress.first = Some(Failure::Clock);
                return Err(CacheHeldErrorV1::Order);
            }
        }
        self.cache.progress.shape = Some(capture::capture_shape_for_originals_v1(
            &mut self.cache.originals, &mut self.cache.progress, self.cache.identity,
            capture::CacheCapturePurposeV1::Delete,
        ));
        if matches!(self.cache.progress.shape, Some(Err(_))) {
            self.cache.progress.first = Some(Failure::Shape);
            return Err(CacheHeldErrorV1::Order);
        }
        let shape = self.cache.progress.shape.as_ref().and_then(|shape| shape.as_ref().ok())
            .ok_or(CacheHeldErrorV1::Order)?;
        // Captured prefix/current semantic geometry is paid on the genuine
        // Source/C17 before the first opening, raw replay or model allocation.
        self.shape_admission = Some(self.source.reserve_additional_v1(
            self.controller, self.launch, self.profile, shape.additional,
        ));
        if matches!(self.shape_admission, Some(Err(_))) {
            self.first.get_or_insert(DeleteFailureV1::Admission);
            return Err(CacheHeldErrorV1::Order);
        }
        let mut semantic = ResourceVector::ZERO;
        for writer in &shape.writers {
            semantic = semantic.componentwise_max(writer.extent.dominant_semantic_receiving_demand_v1()?);
        }
        self.receiving.install_paid_shape(shape.complete_base(), semantic)?;
        Ok(())
    }

    fn audit_next_once_v1(&mut self) {
        let writer = self.completed_readers;
        let Some(Ok(shape)) = &self.cache.progress.shape else {
            self.first.get_or_insert(DeleteFailureV1::Shape);
            return;
        };
        let expected = &shape.writers[writer];
        let coordinates = expected.coordinates;
        self.cache.progress.active_audit = Some(audit::CacheHeldAuditV1::new());
        if let Some(active) = self.cache.progress.active_audit.as_mut() {
            self.reader_returned = Some(active.replay_once(
                &self.cache.originals, native::CacheHeldReadonlyPayerV1::Delete(&mut self.receiving),
                self.cache.identity, shape.complete_base(), expected, writer, None,
            ));
        }
        let posts = audit::observe_bookends(&mut self.cache.originals, &self.cache.progress, None);
        if let Some(active) = self.cache.progress.active_audit.as_mut() { active.posts = Some(posts); }
        let _ = self.observe_deadline_once_v1();
        let Some(active) = self.cache.progress.active_audit.as_ref() else {
            self.first.get_or_insert(DeleteFailureV1::Reader);
            return;
        };
        if !matches!(self.reader_returned, Some(Ok(()))) || active.failure().is_some()
            || !matches!(active.equality, Some(Ok(()))) {
            self.first.get_or_insert(DeleteFailureV1::Reader);
        }
        if self.first.is_some() { return; }
        let Some(Ok(report)) = active.report.as_ref() else {
            self.first.get_or_insert(DeleteFailureV1::Reader);
            return;
        };
        self.cache.progress.audits[writer] = Some(audit::CacheHeldAuditDataV1 { coordinates, report: *report });
        // Actual successful reader/opening/posts dispose before another reader
        // can use the same native peak. Failed originals never reach this take.
        drop(self.cache.progress.active_audit.take());
        self.reader_returned = None;
        self.completed_readers += 1;
    }

    fn project_inventory_once_v1(&mut self) {
        let authority = self.cache.originals.authority;
        let state = &mut *self.cache.originals.state;
        authority.while_authority_current_resident(
            &mut self.cache.inventory, &mut self.cache.authority_post,
            |_owner, _now, validator| {
                let projection = CacheResidencyProtectedJournalV1::claim(state, validator.clone())?.replay()?;
                let inventories = reconstruct_cache_history(projection.records(), &validator)?;
                let entries = super::super::super::lifecycle_inventory::actionable_rows_v1(inventories)?;
                Ok(CacheLifecycleBootInventoryV1 { root: projection.root(), entries })
            },
        );
        if !matches!(self.cache.inventory, Some(Ok(_))) || self.cache.authority_post.is_some() {
            self.first.get_or_insert(DeleteFailureV1::Projection);
        }
    }

    /// Borrows only the actual C17 cause selected by this query's first marker.
    ///
    /// Concrete earlier reader, IO, clock and semantic errors remain primary.
    #[doc(hidden)]
    pub fn native_failure_view_v1(&self)
        -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'_>>
    {
        match self.first? {
            DeleteFailureV1::Admission => self.source.intake_failure_view_v1(self.profile),
            DeleteFailureV1::Snapshots if self.cache.metadata_graph.admission_failed_v2() =>
                self.source.intake_failure_view_v1(self.profile),
            DeleteFailureV1::Entry | DeleteFailureV1::Reader if self.receiving.has_native_marker_v1() =>
                self.receiving.turn.failure_view_v1(),
            DeleteFailureV1::ControllerBefore | DeleteFailureV1::ControllerAfter | DeleteFailureV1::Disposal =>
                self.receiving.turn.failure_view_v1(),
            _ => None,
        }
    }

    /// Borrows the retained first local error without replacing its original.
    #[doc(hidden)]
    pub fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            DeleteFailureV1::Snapshots => self.cache.metadata_graph.failure_v2(),
            DeleteFailureV1::Entry | DeleteFailureV1::Shape => self.cache.progress.failure()
                .or_else(|| self.receiving.local_failure_v1()).or_else(|| error(&self.entry)),
            DeleteFailureV1::SourceBefore => self.source.failure().or_else(|| error(&self.source_started)),
            DeleteFailureV1::ControllerBeforeAccess => self.controller_before_access.as_ref().map(|cause| cause as _),
            DeleteFailureV1::ControllerAfterAccess => self.controller_after_access.as_ref().map(|cause| cause as _),
            DeleteFailureV1::Admission => error(&self.shape_admission),
            DeleteFailureV1::Reader => self.cache.progress.active_audit.as_ref().and_then(audit::CacheHeldAuditV1::failure)
                .or_else(|| error(&self.reader_returned)),
            DeleteFailureV1::Projection => error(&self.cache.inventory)
                .or_else(|| self.cache.authority_post.as_ref().map(|cause| cause as _)),
            DeleteFailureV1::NativeAfter => self.cache.progress.posts[2].as_ref().and_then(audit::CacheHeldBookendsV1::failure),
            DeleteFailureV1::SourceAfter => self.source.failure().or_else(|| error(&self.source_finished)),
            DeleteFailureV1::Deadline(index) => error(&self.deadline_results[index]),
            DeleteFailureV1::Disposal => error(&self.disposal),
            DeleteFailureV1::ControllerBefore => error(&self.controller_before),
            DeleteFailureV1::ControllerAfter => error(&self.controller_after),
            DeleteFailureV1::Reentry => None,
        }
    }
}

impl CacheResidentInitializationV1 {
    pub(crate) fn begin_delete_planning_query_v1<'query, 'cache, 'scope, 'original, 'profile>(
        &'cache mut self,
        owner: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache super::super::super::super::DormantCacheOwnerV1,
        authorized: &'query mut crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>,
        controller: &'query mut Journal,
        launch: &'query ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Result<CacheDeleteInventoryQueryV1<'query, 'cache, 'query, 'scope, 'original, 'scope, 'profile>, JournalError> {
        // Admission precedes new query/nonce/original construction. The Cache
        // reference split itself performs no native IO or variable allocation.
        authorized.reserve_planning_root_additional_v1(
            controller, launch, profile, fixed_demand_v1().map_err(|_| JournalError::ProtectedBoundary)?,
        )?;
        let cut = authorized.planning_root_cut_data_v1(controller, launch, profile)?;
        let mut cache = self.borrow_delete_inventory_originals_v1(owner, physical, profile)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        cache.association = Some(CacheDeleteQueryAssociationV1::Planning {
            project: cut.project, caller: cut.caller, input_digest: cut.input_digest, funding: cut.funding,
            authorization_clock: cut.clock, authorization_expires: cut.expires,
            controller_next: cut.controller_next, controller_end: cut.controller_end,
            source_next: cut.source_next, source_end: cut.source_end,
        });
        let mut source = CacheQuerySourceV1::planning(authorized);
        let turn = source.prepare_turn_v1(controller, launch, profile)?;
        Ok(CacheDeleteInventoryQueryV1::new_prepaid_v1(cache, source, turn, controller, launch, profile))
    }


}

impl<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
    CacheDeleteInventoryQueryV1<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
{
    fn new_prepaid_v1(
        cache: CacheDeleteInventoryOriginalV1<'cache>,
        source: CacheQuerySourceV1<'query, 'fence, 'journal, 'original, 'authorization>,
        turn: aos_sandbox_broker::controller_receiving::bank_launch::ControllerDeletePreacceptTurnOriginalV1<'profile>,
        controller: &'query mut Journal,
        launch: &'query ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Self {
        let receiving = CacheDeleteReadAdmissionV1::new(turn, cache.identity);
        Self {
            receiving, source, controller, launch, profile, cache,
            entry: None, shape_admission: None, source_started: None, source_finished: None,
            controller_before: None, controller_after: None,
            controller_before_access: None, controller_after_access: None,
            deadline_samples: [None; 8], deadline_results: std::array::from_fn(|_| None),
            deadline_next: 0, reader_returned: None, completed_readers: 0,
            disposal: None, attempted: false, outer_source_after: None, first: None,
        }
    }

    /// Attempts the existing enclosing Source/C17 post with the failed Cache held.
    ///
    /// # Errors
    /// Rejects healthy/repeated entry or retains the independently owed refusal.
    /// Earlier Cache/native/clock causes remain first; no success is released.
    #[doc(hidden)]
    pub fn finish_outer_source_failure_once_v1(&mut self) -> Result<(), JournalError> {
        if !self.attempted || self.first.is_none() || self.outer_source_after.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
            self.controller, self.launch, self.profile));
        match &self.outer_source_after {
            Some(Ok(())) => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    // The result retains the five genuine Cache/native originals and complete
    // reducer inventory. It grants neither acceptance nor a new Cache effect.
    /// Disposes completed query scratch and returns the same retained Cache cut.
    ///
    /// Incomplete or refused completion terminates while the whole query,
    /// same Cache originals and actual Source/C17 borrow remain resident.
    #[doc(hidden)]
    pub fn finish_positive_once_v1(mut self) -> CacheDeleteInventoryOriginalV1<'cache> {
        if !self.attempted || self.first.is_some() || self.completed_readers != 5
            || self.cache.progress.active_audit.is_some()
            || self.cache.association.is_none()
            || !matches!(self.cache.inventory, Some(Ok(_))) || self.cache.authority_post.is_some()
            || !matches!(self.controller_before, Some(Ok(())))
            || !matches!(self.controller_after, Some(Ok(())))
            || !self.cache.metadata_graph.complete_v2()
        {
            self.first.get_or_insert(DeleteFailureV1::Reentry);
            self.receiving.turn.refuse_primary_v1();
            if self.outer_source_after.is_none() {
                self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                    self.controller, self.launch, self.profile));
            }
            std::process::abort();
        }
        if self.observe_deadline_once_v1().is_err() {
            self.receiving.turn.refuse_primary_v1();
            if self.outer_source_after.is_none() {
                self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                    self.controller, self.launch, self.profile));
            }
            std::process::abort();
        }
        self.cache.coordinates = match self.source.coordinates_v1() {
            Ok(coordinates) => Some(coordinates),
            Err(_) => {
                self.first.get_or_insert(DeleteFailureV1::Reentry);
                self.receiving.turn.refuse_primary_v1();
                if self.outer_source_after.is_none() {
                    self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                        self.controller, self.launch, self.profile));
                }
                std::process::abort();
            }
        };
        let writer = match self.controller.controller_coordinator_for_bank_read_v1() {
            Ok(writer) => writer,
            Err(cause) => {
                self.controller_after_access = Some(cause);
                self.first.get_or_insert(DeleteFailureV1::ControllerAfterAccess);
                self.receiving.turn.refuse_primary_v1();
                if self.outer_source_after.is_none() {
                    self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                        self.controller, self.launch, self.profile));
                }
                std::process::abort();
            }
        };
        let token = match self.receiving.turn.prepare_positive_disposal_v1(writer) {
            Ok(token) => token,
            Err(cause) => {
                self.disposal = Some(Err(cause));
                self.first.get_or_insert(DeleteFailureV1::Disposal);
                if self.outer_source_after.is_none() {
                    self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                        self.controller, self.launch, self.profile));
                }
                std::process::abort();
            }
        };
        // Source-side nonce/query scratch is physically disposed while the
        // same C17 token still holds the finite slot closed. The native reader
        // scratch was already disposed after its complete local posts.
        self.cache.metadata_graph.retire_positive_native_once_v2();
        drop(self.source);
        token.complete_after_upper_disposal_v1();
        self.cache.complete = true;
        self.cache
    }
}

impl CacheDeleteInventoryOriginalV1<'_> {
    /// Returns the complete protected replay root as comparison DATA.
    ///
    /// # Errors
    /// Refuses an incomplete or failed original query.
    #[doc(hidden)]
    pub fn root_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        self.inventory.as_ref().and_then(|value| value.as_ref().ok()).map(|value| value.root())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Borrows all canonical actionable rows from the same complete reducer.
    ///
    /// # Errors
    /// Refuses an incomplete or failed original query.
    #[doc(hidden)]
    pub fn entries_v1(&self) -> Result<&[crate::lifecycle::LifecycleBootDomainEntryV1], JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        self.inventory.as_ref().and_then(|value| value.as_ref().ok()).map(|value| value.entries())
            .ok_or(JournalError::ProtectedBoundary)
    }

    // Only actual Bank/authorized planning consumers can reach this private
    // graph. Its complete Cache answer and every native post remain resident.
    pub(crate) fn dependency_graph_data_v2(&self)
        -> Result<&crate::journal::DeleteDependencyGraphDataV2, JournalError>
    {
        if !self.complete || !self.metadata_graph.positive {
            return Err(JournalError::ProtectedBoundary);
        }
        self.metadata_graph.graph.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Returns the actual query's nonce and original cutoff as comparison DATA.
    ///
    /// # Errors
    /// Refuses an incomplete or failed original query.
    #[doc(hidden)]
    pub fn coordinates_v1(&self) -> Result<([u8; 16], u64), JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        self.coordinates.ok_or(JournalError::ProtectedBoundary)
    }
}

impl CacheDeleteInventoryOriginalV1<'_> {
    // The actual collector must match the retained intrinsic association again;
    // neither the inventory root nor its nonce alone can adopt a foreign cut.
    pub(crate) fn require_planning_binding_v1(
        &self,
        authorized: &crate::ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        let cut = authorized.planning_root_cut_data_v1(controller, launch, profile)?;
        match &self.association {
            Some(CacheDeleteQueryAssociationV1::Planning { project, caller, input_digest, funding,
                authorization_clock, authorization_expires, controller_next, controller_end, source_next, source_end })
                if project == &cut.project && caller == &cut.caller && input_digest == &cut.input_digest
                    && authorization_clock == &cut.clock && authorization_expires == &cut.expires
                    && funding == &cut.funding && controller_next == &cut.controller_next
                    && controller_end == &cut.controller_end && source_next == &cut.source_next
                    && source_end == &cut.source_end => Ok(()),
            _ => Err(JournalError::StaleAuthoritySnapshot),
        }
    }

    pub(crate) fn require_preaccept_binding_v1(
        &self,
        fence: &crate::journal::SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        live: &crate::normal_root::RootDeleteChallengeLoanV1<'_>,
    ) -> Result<(), JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        fence.require_live_inventory_challenge_v1(controller, launch, profile, live)?;
        let (actual_funding, actual_next, actual_end) = fence.controller_funding_cut_data_v3(controller, launch, profile)?;
        match &self.association {
            Some(CacheDeleteQueryAssociationV1::Preaccept { open, challenge, funding, controller_next, controller_end })
                if open == live.open_v2() && challenge == live.challenge_v2() && *funding == actual_funding
                    && controller_next == &actual_next && controller_end == &actual_end
                    && self.coordinates == Some((*live.nonce_v1(), live.cutoff_v1())) => Ok(()),
            _ => Err(JournalError::StaleAuthoritySnapshot),
        }
    }

    /// Projects the same completed physical original without new native IO.
    ///
    /// # Errors
    /// Refuses an incomplete query/missing original or the actual limits recipe.
    #[doc(hidden)]
    pub fn physical_comparison_data_v2(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1,
        super::super::super::super::CacheOwnerErrorV1,
    > {
        if !self.complete { return Err(super::super::super::super::CacheOwnerErrorV1::Stale); }
        self.originals.physical_identity.ok_or(super::super::super::super::CacheOwnerErrorV1::Stale)?
            .physical_comparison_data_v2(self.originals.physical.limits())
    }

    /// Returns all five actual native journal cuts in their fixed owner order.
    ///
    /// # Errors
    /// Refuses an incomplete query or absent captured original shape.
    #[doc(hidden)]
    pub fn native_coordinates_v1(&self) -> Result<[CacheJournalDataV1; 5], JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(std::array::from_fn(|index| shape.writers[index].coordinates))
    }
}

// The native sample is parked on the query before this pure conversion runs.
fn require_before_sample_v1(sample: Option<rustix::time::Timespec>, cutoff: u64) -> Result<(), JournalError> {
    crate::cache_residency::effect_owner::delete_metadata::require_deadline_sample_v2(sample, cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_native_completion_at_the_original_cutoff_cannot_dispose_positive_scratch() {
        // This is an actual native clock sample, not a fabricated financial or
        // role original. Only its strict cutoff comparison is under test.
        let sample = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let now = u64::try_from(sample.tv_sec).unwrap().checked_mul(1_000_000_000).unwrap()
            .checked_add(u64::try_from(sample.tv_nsec).unwrap()).unwrap();

        assert!(require_before_sample_v1(Some(sample), now.checked_add(1).unwrap()).is_ok());
        assert!(require_before_sample_v1(Some(sample), now).is_err());
        assert!(require_before_sample_v1(Some(sample), 0).is_err());
        assert!(require_before_sample_v1(None, now.checked_add(1).unwrap()).is_err());
    }
}


impl<'cache> CacheDeleteInventoryOriginalV1<'cache> {
    pub(crate) fn into_pending_query_once_v2<'query, 'journal, 'original, 'profile>(
        mut self,
        mut fence: crate::journal::SourceDeletePendingFenceV1<'query, 'journal, 'original, 'journal>,
        controller: &'query mut Journal,
        launch: &'query ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        challenge: &'query crate::normal_root::RootDeleteChallengeLoanV1<'query>,
    ) -> Result<CacheDeleteInventoryQueryV1<'query, 'cache, 'query, 'journal, 'original, 'journal, 'profile>, Self> {
        if !self.complete || self.authority_post.is_some() || self.progress.active_audit.is_some()
            || !matches!(self.inventory, Some(Ok(_))) || !self.metadata_graph.positive
            || !matches!(self.association, Some(CacheDeleteQueryAssociationV1::Planning { .. }))
            || self.predecessor.is_some() || self.successor_admission.is_some()
        {
            if self.successor_admission.is_none() {
                self.successor_admission = Some(Err(JournalError::ProtectedBoundary));
            }
            return Err(self);
        }
        self.successor_admission = Some((|| {
            fence.require_live_inventory_challenge_v1(controller, launch, profile, challenge)?;
            let payload = std::mem::size_of::<CacheDeleteCompletedPayloadsV2<'_>>()
                .checked_mul(3).and_then(|n| u64::try_from(n).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            let complete = fixed_demand_v1().map_err(|_| JournalError::ProtectedBoundary)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, payload))
                .map_err(|_| JournalError::JournalTooLarge)?;
            fence.reserve_preaccept_additional_v1(controller, launch, profile, complete)
        })());
        if !matches!(self.successor_admission, Some(Ok(()))) { return Err(self); }
        let association = (|| {
            let (funding, controller_next, controller_end) = fence.controller_funding_cut_data_v3(controller, launch, profile)?;
            Ok::<_, JournalError>(CacheDeleteQueryAssociationV1::Preaccept {
                open: *challenge.open_v2(), challenge: *challenge.challenge_v2(), funding,
                controller_next, controller_end,
            })
        })();
        let association = match association {
            Ok(value) => value,
            Err(cause) => { self.successor_admission = Some(Err(cause)); return Err(self); }
        };
        let turn = match fence.prepare_preaccept_turn_v1(controller, launch, profile, ResourceVector::ZERO) {
            Ok(turn) => turn,
            Err(cause) => { self.successor_admission = Some(Err(cause)); return Err(self); }
        };
        let Self { originals, identity, progress, inventory, authority_post, coordinates,
            association: previous_association, metadata_graph, .. } = self;
        let predecessor = Box::new(CacheDeleteCompletedPayloadsV2 {
            _progress: progress, _inventory: inventory, _authority_post: authority_post,
            _coordinates: coordinates, _association: previous_association, _metadata_graph: metadata_graph,
        });
        let cache = Self {
            originals, identity, progress: Default::default(), inventory: None,
            authority_post: None, complete: false, coordinates: None,
            association: Some(association), metadata_graph: Default::default(),
            predecessor: Some(predecessor), successor_admission: Some(Ok(())),
        };
        let source = CacheQuerySourceV1::Preaccept { fence, challenge };
        Ok(CacheDeleteInventoryQueryV1::new_prepaid_v1(cache, source, turn, controller, launch, profile))
    }

    /// Borrows the retained whole successor-admission error, if one refused.
    #[doc(hidden)]
    #[must_use]
    pub fn pending_successor_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.successor_admission.as_ref()?.as_ref().err().map(|cause| cause as _)
    }
}
