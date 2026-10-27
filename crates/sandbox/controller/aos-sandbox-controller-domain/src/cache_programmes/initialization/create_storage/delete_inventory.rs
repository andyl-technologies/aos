//! Keeps genuine Delete Source/Controller semantics around actual Cache custody.
//!
//! The native Cache original owns five writers, Clock, full replay and physical
//! metadata. This programme keeps only actual Source/C17/Root associations,
//! owning upper errors, paired nonce and independently owed Controller posts.

use std::error::Error;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_cache::{
    CacheDeleteNativeOriginalV1, CacheDeleteNativePayloadsV1,
    CacheHeldClosedV1, CacheHeldErrorV1, CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1,
};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerDeletePreacceptTurnOriginalV1,
    ControllerCacheDeleteAuditFundingLoanV1, ControllerCacheAuditFundingLoanV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use crate::journal::{Journal, JournalError};
use super::super::CacheResidentInitializationV1;

mod source;
mod metadata_graph;
use source::CacheQuerySourceV1;

/// Retains the same complete actual Cache cut and its genuine upper association.
pub struct CacheDeleteInventoryOriginalV1<'cache> {
    native: CacheDeleteNativeOriginalV1<'cache>,
    complete: bool,
    coordinates: Option<([u8; 16], u64)>,
    association: Option<CacheDeleteQueryAssociationV1>,
    metadata_graph: metadata_graph::CacheDeleteMetadataGraphOriginalsV2,
    predecessor: Option<Box<CacheDeleteCompletedPayloadsV2<'cache>>>,
    successor_admission: Option<Result<(), JournalError>>,
}

struct CacheDeleteCompletedPayloadsV2<'cache> {
    _native: CacheDeleteNativePayloadsV1<'cache>,
    _coordinates: Option<([u8; 16], u64)>,
    _association: Option<CacheDeleteQueryAssociationV1>,
    _metadata_graph: metadata_graph::CacheDeleteMetadataGraphOriginalsV2,
}

enum CacheDeleteQueryAssociationV1 {
    Planning {
        project: [u8; 16], caller: [u8; 16], input_digest: [u8; 32],
        authorization_clock: aos_sandbox_model::RawPairedClockSample, authorization_expires: i64,
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

/// Retains one genuine C17 query and all upper and lower independently owed posts.
pub struct CacheDeleteInventoryQueryV1<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile> {
    // The entered turn aborts before native Clock/failed-reader fields drop.
    turn: ControllerDeletePreacceptTurnOriginalV1<'profile>,
    source: CacheQuerySourceV1<'query, 'fence, 'journal, 'original, 'authorization>,
    controller: &'query mut Journal,
    launch: &'query ControllerBankLaunchOriginalV1,
    profile: &'profile ControllerSelfProfileOriginalV1,
    cache: CacheDeleteInventoryOriginalV1<'cache>,
    entry: Option<Result<(), CacheHeldClosedV1>>,
    shape_admission: Option<Result<(), JournalError>>,
    semantic: Option<Result<ResourceVector, JournalError>>,
    capture_supplement: Option<Result<ResourceVector, JournalError>>,
    deadline_coordinates: Option<([u8; 16], u64)>,
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

pub(super) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
    let native = CacheDeleteNativeOriginalV1::fixed_receiving_demand_v1()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let lower = ControllerCacheDeleteAuditFundingLoanV1::receiving_construction_bytes_v1()
        .and_then(|bytes| bytes.checked_add(crate::journal::SourceDeleteSemanticScopeV1::cache_audit_forwarding_bytes_v1()?))
        .ok_or(JournalError::JournalTooLarge)?;
    let upper = std::mem::size_of::<CacheDeleteInventoryOriginalV1<'_>>().checked_mul(3)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheDeleteInventoryQueryV1<'_, '_, '_, '_, '_, '_, '_>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(lower))
        .and_then(|bytes| bytes.checked_add(Journal::cache_audit_source_original_receiving_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(upper_control_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(metadata_graph::control_bytes_v2()?))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
    native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, upper))
        .map_err(JournalError::ReceivingAccounting)?
        .checked_add(crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1::planning_root_fixed_demand_v1()?)
        .map_err(JournalError::ReceivingAccounting)
}

fn upper_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    size_of::<Result<ResourceVector, JournalError>>().checked_mul(9)?
        .checked_add(size_of::<Result<(), JournalError>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ControllerCacheDeleteAuditFundingLoanV1<'_, '_>, JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<([u8; 16], u64), JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), CacheHeldErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), CacheHeldClosedV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<CacheDeleteNativePayloadsV1<'_>, CacheHeldClosedV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<ResourceVector>>().checked_mul(3)?)?
        .checked_add(size_of::<(usize, usize, Result<ResourceVector, JournalError>)>().checked_mul(3)?)?
        .checked_add(size_of::<aos_sandbox_cache::CreateStorageCacheCurrentExtentsDataV1>().checked_mul(3)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), aos_sandbox_cache::CacheJournalErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<(Option<rustix::time::Timespec>, u64)>().checked_mul(3)?)
}

impl CacheResidentInitializationV1 {
    pub(crate) fn begin_delete_planning_query_v1<'query, 'cache, 'scope, 'original, 'profile>(
        &'cache mut self,
        owner: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache DormantCacheOwnerV1,
        authorized: &'query mut crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>,
        controller: &'query mut Journal,
        launch: &'query ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Result<CacheDeleteInventoryQueryV1<'query, 'cache, 'query, 'scope, 'original, 'scope, 'profile>, JournalError> {
        authorized.reserve_planning_root_additional_v1(controller, launch, profile, fixed_demand_v1().map_err(|_| JournalError::ProtectedBoundary)?)?;
        let cut = authorized.planning_root_cut_data_v1(controller, launch, profile)?;
        if self.create_storage_held.started {
            self.require_create_storage_terminal_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        }
        let native = self.native.borrow_delete_inventory_originals_v1(owner, physical, profile)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let cache = CacheDeleteInventoryOriginalV1 {
            native, complete: false, coordinates: None,
            association: Some(CacheDeleteQueryAssociationV1::Planning {
                project: cut.project, caller: cut.caller, input_digest: cut.input_digest, funding: cut.funding,
                authorization_clock: cut.clock, authorization_expires: cut.expires,
                controller_next: cut.controller_next, controller_end: cut.controller_end,
                source_next: cut.source_next, source_end: cut.source_end,
            }),
            metadata_graph: Default::default(), predecessor: None, successor_admission: None,
        };
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
        turn: ControllerDeletePreacceptTurnOriginalV1<'profile>,
        controller: &'query mut Journal,
        launch: &'query ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Self {
        Self {
            turn, source, controller, launch, profile, cache,
            entry: None, shape_admission: None, source_started: None, source_finished: None,
            semantic: None, capture_supplement: None, deadline_coordinates: None,
            controller_before: None, controller_after: None,
            controller_before_access: None, controller_after_access: None,
            deadline_samples: [None; 8], deadline_results: std::array::from_fn(|_| None),
            deadline_next: 0, reader_returned: None, completed_readers: 0,
            disposal: None, attempted: false, outer_source_after: None, first: None,
        }
    }

    fn observe_deadline_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        let index = self.deadline_next;
        if index >= self.deadline_samples.len() {
            self.first.get_or_insert(DeleteFailureV1::Reentry);
            self.turn.refuse_primary_v1();
            return Err(CacheHeldClosedV1);
        }
        self.deadline_next += 1;
        self.deadline_samples[index] = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.deadline_results[index] = Some(match self.source.coordinates_v1() {
            Ok(coordinates) => {
                self.deadline_coordinates = Some(coordinates);
                require_before_sample_v1(self.deadline_samples[index], coordinates.1)
            }
            Err(cause) => Err(cause),
        });
        if matches!(self.deadline_results[index], Some(Ok(()))) { Ok(()) }
        else { self.first.get_or_insert(DeleteFailureV1::Deadline(index)); Err(CacheHeldClosedV1) }
    }

    /// Runs the actual five-reader inventory and physical metadata query once.
    ///
    /// # Errors
    /// Retains first body/debit/native cause and attempts all independent posts.
    pub fn run_once_v1(&mut self) -> Result<(), JournalError> {
        self.run_inner_once_v1().map_err(|_| JournalError::ProtectedBoundary)
    }

    fn run_inner_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        if self.attempted {
            self.first.get_or_insert(DeleteFailureV1::Reentry);
            self.turn.refuse_primary_v1();
            return Err(CacheHeldClosedV1);
        }
        self.attempted = true;
        match self.controller.controller_coordinator_for_bank_read_v1() {
            Ok(writer) => {
                self.controller_before = Some(self.turn.observe_before_once_v1(writer));
                if matches!(self.controller_before, Some(Err(_))) { self.first.get_or_insert(DeleteFailureV1::ControllerBefore); }
            }
            Err(cause) => {
                self.controller_before_access = Some(cause);
                self.first.get_or_insert(DeleteFailureV1::ControllerBeforeAccess);
            }
        }
        if self.first.is_none() {
            self.source_started = Some(self.source.begin_nonce_once_v1());
            if matches!(self.source_started, Some(Err(_))) { self.first.get_or_insert(DeleteFailureV1::SourceBefore); }
        }
        if self.first.is_none() { let _ = self.observe_deadline_once_v1(); }
        if self.first.is_none() { self.capture_and_audit_once_v1(); }
        if self.first.is_none() && self.cache.native.project_inventory_once_v1().is_err() {
            self.first.get_or_insert(DeleteFailureV1::Projection);
        }
        if self.first.is_none() { self.observe_metadata_graph_once_v2(); }

        // These observations are independent of every primary/shape/debit result.
        if self.cache.native.observe_original_posts_once_v1().is_err() {
            self.first.get_or_insert(DeleteFailureV1::NativeAfter);
        }
        self.source_finished = Some(self.source.finish_nonce_once_v1());
        if matches!(self.source_finished, Some(Err(_))) { self.first.get_or_insert(DeleteFailureV1::SourceAfter); }
        match self.controller.controller_coordinator_for_bank_read_v1() {
            Ok(writer) => {
                self.controller_after = Some(self.turn.observe_after_once_v1(writer));
                if matches!(self.controller_after, Some(Err(_))) { self.first.get_or_insert(DeleteFailureV1::ControllerAfter); }
            }
            Err(cause) => {
                self.controller_after_access = Some(cause);
                self.first.get_or_insert(DeleteFailureV1::ControllerAfterAccess);
            }
        }
        let _ = self.observe_deadline_once_v1();
        if self.first.is_some() { self.turn.refuse_primary_v1(); Err(CacheHeldClosedV1) } else { Ok(()) }
    }

    fn capture_and_audit_once_v1(&mut self) {
        // Park this pure result without selecting it ahead of Clock/physical
        // capture or the first full Ledger prefix. Native uses None solely as
        // the deferred upper-quote marker, never as a zero/S success waiver.
        self.capture_supplement = Some(crate::journal::cache_native_semantic_supplement_v1());
        let supplement = self.capture_supplement.as_ref().and_then(|value| value.as_ref().ok()).copied();
        self.entry = Some(self.cache.native.capture_receiving_shape_once_v1(supplement));
        if matches!(self.entry, Some(Err(_))) {
            self.first.get_or_insert(DeleteFailureV1::Entry);
            return;
        }
        // Keep the original upper semantic error owner. A later pure failure
        // must never suppress the old Source reservation and its earlier cause.
        self.semantic = Some(self.old_semantic_peak_v1());
        let shape = match self.cache.native.captured_shape_v1() {
            Ok(shape) => shape,
            Err(_) => { self.first.get_or_insert(DeleteFailureV1::Shape); return; }
        };
        let additional = match shape.dominant_receiving_demand_v1() {
            Ok(value) => value,
            Err(_) => { self.first.get_or_insert(DeleteFailureV1::Shape); return; }
        };
        if !matches!(self.semantic, Some(Ok(_))) {
            self.shape_admission = Some(self.source.reserve_additional_v1(
                self.controller, self.launch, self.profile, additional,
            ));
            if matches!(self.shape_admission, Some(Err(_))) { self.first.get_or_insert(DeleteFailureV1::Admission); }
            else { self.first.get_or_insert(DeleteFailureV1::Entry); }
            return;
        }
        let complete = match self.cache.native.complete_receiving_demand_v1() {
            Ok(value) => value,
            Err(_) => { self.first.get_or_insert(DeleteFailureV1::Shape); return; }
        };
        let semantic = match self.semantic.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(value) => value,
            None => { self.first.get_or_insert(DeleteFailureV1::Entry); return; }
        };
        let funding = self.source.borrow_audit_funding_v1(self.controller, self.launch,
            self.profile, &mut self.turn, self.cache.native.original_identity_v1(), additional,
            complete, semantic);
        let mut funding = match funding {
            Ok(original) => {
                self.shape_admission = Some(Ok(()));
                ControllerCacheAuditFundingLoanV1::from_delete_v1(original)
            }
            Err(cause) => {
                self.shape_admission = Some(Err(cause));
                self.first.get_or_insert(DeleteFailureV1::Admission);
                return;
            }
        };
        let cutoff = self.deadline_coordinates.map(|(_, cutoff)| cutoff);
        while self.first.is_none() && self.completed_readers < 5 {
            self.reader_returned = Some(self.cache.native.audit_next_once_v1(&mut funding));
            let _ = observe_deadline_v1(&mut self.deadline_samples, &mut self.deadline_results,
                &mut self.deadline_next, &mut self.first, cutoff);
            if matches!(self.reader_returned, Some(Err(_))) { self.first.get_or_insert(DeleteFailureV1::Reader); }
            if self.first.is_some() { break; }
            if self.cache.native.finish_positive_reader_once_v1().is_err() {
                self.first.get_or_insert(DeleteFailureV1::Reader);
                break;
            }
            self.reader_returned = None;
            self.completed_readers += 1;
        }
        drop(funding);
    }

    fn old_semantic_peak_v1(&self) -> Result<ResourceVector, JournalError> {
        let extents = self.cache.native.captured_extents_data_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let mut semantic = ResourceVector::ZERO;
        for extent in extents.captured_extents_v1() {
            let invalid = || JournalError::LimitExceeded("native semantic receiving demand");
            if extent.native_bytes() > extent.limits().maximum_journal_bytes { return Err(invalid()); }
            let physical = usize::try_from(extent.native_bytes()).map_err(|_| invalid())?;
            let rows = physical.checked_div(aos_sandbox_journal::framing::HEADER_BYTES).ok_or_else(invalid)?;
            semantic = semantic.componentwise_max(
                crate::journal::cache_delete_semantic_representation_demand_v1(physical, rows)?,
            );
        }
        Ok(semantic)
    }
}

fn observe_deadline_v1(
    samples: &mut [Option<rustix::time::Timespec>; 8],
    results: &mut [Option<Result<(), JournalError>>; 8],
    next: &mut usize,
    first: &mut Option<DeleteFailureV1>,
    cutoff: Option<u64>,
) -> Result<(), CacheHeldClosedV1> {
    let index = *next;
    if index >= samples.len() { first.get_or_insert(DeleteFailureV1::Reentry); return Err(CacheHeldClosedV1); }
    *next += 1;
    samples[index] = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
    results[index] = Some(cutoff.ok_or(JournalError::ProtectedBoundary)
        .and_then(|cutoff| require_before_sample_v1(samples[index], cutoff)));
    if matches!(results[index], Some(Ok(()))) { Ok(()) }
    else { first.get_or_insert(DeleteFailureV1::Deadline(index)); Err(CacheHeldClosedV1) }
}

fn require_before_sample_v1(sample: Option<rustix::time::Timespec>, cutoff: u64) -> Result<(), JournalError> {
    aos_sandbox_cache::cache_delete_deadline_sample_data_v2(sample, cutoff)
        .map_err(|_| JournalError::ProtectedBoundary)
}


fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}

impl<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
    CacheDeleteInventoryQueryV1<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
{
    /// Borrows only the genuine C17 cause at its selected failure frontier.
    pub fn native_failure_view_v1(&self)
        -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'_>>
    {
        match self.first? {
            DeleteFailureV1::Admission => self.source.intake_failure_view_v1(self.profile),
            DeleteFailureV1::Snapshots if self.cache.metadata_graph.admission_failed_v2() =>
                self.source.intake_failure_view_v1(self.profile),
            DeleteFailureV1::Snapshots if self.cache.native.metadata_funding_failed_data_v2() => self.turn.failure_view_v1(),
            DeleteFailureV1::Reader if self.cache.native.reader_funding_failed_data_v1() =>
                self.turn.failure_view_v1(),
            DeleteFailureV1::ControllerBefore | DeleteFailureV1::ControllerAfter | DeleteFailureV1::Disposal =>
                self.turn.failure_view_v1(),
            _ => None,
        }
    }

    /// Borrows the exact first local cause with all original custody retained.
    pub fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            DeleteFailureV1::Snapshots => self.cache.metadata_graph.failure_v2(&self.cache.native),
            DeleteFailureV1::Entry | DeleteFailureV1::Shape => {
                if self.cache.native.entry_deferred_semantic_quote_data_v1() {
                    error(&self.capture_supplement).or_else(|| self.cache.native.entry_failure_v1())
                } else {
                    self.cache.native.entry_failure_v1().or_else(|| error(&self.semantic)).or_else(|| error(&self.entry))
                }
            },
            DeleteFailureV1::SourceBefore => self.source.failure().or_else(|| error(&self.source_started)),
            DeleteFailureV1::ControllerBeforeAccess => self.controller_before_access.as_ref().map(|cause| cause as _),
            DeleteFailureV1::ControllerAfterAccess => self.controller_after_access.as_ref().map(|cause| cause as _),
            DeleteFailureV1::Admission => error(&self.shape_admission),
            DeleteFailureV1::Reader => self.cache.native.reader_failure_v1()
                .or_else(|| error(&self.reader_returned)),
            DeleteFailureV1::Projection => self.cache.native.projection_failure_v1(),
            DeleteFailureV1::NativeAfter => self.cache.native.outer_post_failure_v1(),
            DeleteFailureV1::SourceAfter => self.source.failure().or_else(|| error(&self.source_finished)),
            DeleteFailureV1::Deadline(index) => error(&self.deadline_results[index]),
            DeleteFailureV1::Disposal => error(&self.disposal),
            DeleteFailureV1::ControllerBefore => error(&self.controller_before),
            DeleteFailureV1::ControllerAfter => error(&self.controller_after),
            DeleteFailureV1::Reentry => None,
        }
    }

    /// Attempts the independently owed outer Source post after query refusal.
    ///
    /// # Errors
    /// Rejects healthy or repeated entry and retains the actual post failure.
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

    /// Disposes only a complete query under the same actual C17 slot token.
    ///
    /// Incomplete or failed completion aborts with the actual Clock, readers
    /// and Source/Controller originals still held, after owed outer posts.
    pub fn finish_positive_once_v1(mut self) -> CacheDeleteInventoryOriginalV1<'cache> {
        if !self.attempted || self.first.is_some() || self.completed_readers != 5
            || self.cache.association.is_none()
            || self.cache.native.inventory_root_data_v1().is_err()
            || !matches!(self.controller_before, Some(Ok(())))
            || !matches!(self.controller_after, Some(Ok(())))
            || !self.cache.metadata_graph.complete_v2()
        {
            self.first.get_or_insert(DeleteFailureV1::Reentry);
            self.turn.refuse_primary_v1();
            if self.outer_source_after.is_none() {
                self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                    self.controller, self.launch, self.profile));
            }
            std::process::abort();
        }
        if self.observe_deadline_once_v1().is_err() {
            self.turn.refuse_primary_v1();
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
                self.turn.refuse_primary_v1();
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
                self.turn.refuse_primary_v1();
                if self.outer_source_after.is_none() {
                    self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                        self.controller, self.launch, self.profile));
                }
                std::process::abort();
            }
        };
        let token = match self.turn.prepare_positive_disposal_v1(writer) {
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
        if self.cache.native.finish_positive_after_posts_once_v2(&token).is_err() {
            self.first.get_or_insert(DeleteFailureV1::Snapshots);
            if self.outer_source_after.is_none() {
                self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                    self.controller, self.launch, self.profile));
            }
            std::process::abort();
        }
        self.cache.metadata_graph.positive = true;
        drop(self.source);
        token.complete_after_upper_disposal_v1();
        self.cache.complete = true;
        self.cache
    }
}

impl CacheDeleteInventoryOriginalV1<'_> {
    /// Returns comparison DATA from the same completed native query.
    ///
    /// # Errors
    /// Refuses incomplete custody or the actual named comparison failure.
    pub fn root_v1(&self) -> Result<aos_sandbox_model::ObjectDigest, JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        self.native.inventory_root_data_v1().map_err(|_| JournalError::ProtectedBoundary)
    }

    /// Returns comparison DATA from the same completed native query.
    ///
    /// # Errors
    /// Refuses incomplete custody or the actual named comparison failure.
    pub fn entries_v1(&self) -> Result<&[aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleBootDomainEntryDataV1], JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        self.native.inventory_entries_data_v1().map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn dependency_graph_data_v2(&self)
        -> Result<&crate::journal::DeleteDependencyGraphDataV2, JournalError>
    {
        if !self.complete || !self.metadata_graph.positive {
            return Err(JournalError::ProtectedBoundary);
        }
        self.metadata_graph.graph.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Returns comparison DATA from the same completed native query.
    ///
    /// # Errors
    /// Refuses incomplete custody or the actual named comparison failure.
    pub fn coordinates_v1(&self) -> Result<([u8; 16], u64), JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        self.coordinates.ok_or(JournalError::ProtectedBoundary)
    }

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

    /// Returns comparison DATA from the same completed native query.
    ///
    /// # Errors
    /// Refuses incomplete custody or the actual named comparison failure.
    pub fn physical_comparison_data_v2(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1,
        aos_sandbox_cache::CacheOwnerErrorV1,
    > {
        if !self.complete { return Err(aos_sandbox_cache::CacheOwnerErrorV1::Stale); }
        self.native.physical_comparison_data_v2()
    }

    /// Returns comparison DATA from the same completed native query.
    ///
    /// # Errors
    /// Refuses incomplete custody or the actual named comparison failure.
    pub fn native_coordinates_v1(&self) -> Result<[aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1; 5], JournalError> {
        if !self.complete { return Err(JournalError::ProtectedBoundary); }
        self.native.native_coordinates_data_v1().map_err(|_| JournalError::ProtectedBoundary)
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
        if !self.complete || self.native.inventory_root_data_v1().is_err() || !self.metadata_graph.positive
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
        let native_payload = match self.native.begin_pending_once_v2() {
            Ok(payload) => payload,
            Err(_) => std::process::abort(),
        };
        let Self { native, coordinates, association: previous_association, metadata_graph, .. } = self;
        let predecessor = Box::new(CacheDeleteCompletedPayloadsV2 {
            _native: native_payload, _coordinates: coordinates,
            _association: previous_association, _metadata_graph: metadata_graph,
        });
        let cache = Self {
            native, complete: false, coordinates: None,
            association: Some(association), metadata_graph: Default::default(),
            predecessor: Some(predecessor), successor_admission: Some(Ok(())),
        };
        let source = CacheQuerySourceV1::Preaccept { fence, challenge };
        Ok(CacheDeleteInventoryQueryV1::new_prepaid_v1(cache, source, turn, controller, launch, profile))
    }

    /// Borrows the retained successor-admission error without moving custody.
    pub fn pending_successor_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.successor_admission.as_ref()?.as_ref().err().map(|cause| cause as _)
    }
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
