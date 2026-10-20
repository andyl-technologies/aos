//! Owns the new Create Storage Cache Held crossing on initialized originals.
//!
//! This is a distinct once-only continuation after ordinary initialization and
//! Q04. It never reopens a writer or turns Q04 comparison DATA into a new loan.
//! State remains borrowed before the existing Hold writer, the clock is held,
//! and the same physical/authority originals survive the entire Root exchange.

use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;

use super::*;
use crate::cache_residency::effect_owner::CachePhysicalReadbackOriginalsV1;
use std::error::Error;
use aos_sandbox_core::{AccountingError, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1,
    RecordEnvelopeV1, HEAD_BYTES,
    cache_held::{CacheHeldBodyDataV1, CacheHeldReceiptDataV1, CacheJournalDataV1,
        CACHE_HELD_BODY_BYTES_V1, CACHE_HELD_RECORD_BYTES_V1},
    source_held::{SourceHeldReceiptDataV1, SOURCE_HELD_RECEIPT_BYTES_V1},
};
use crate::controller_resource_reservation::{CreateStorageOriginalLoanV1, ResourceReservationErrorV1};
use crate::journal::{ReadOnlyJournalOpenOriginalsV1, CacheHeldWriterShapeV1, CommitResult,
    create_storage_history::{HistoryPairReadbackV1, prepare_history_pair_v1, readback_history_pair_v1}};
use crate::cache_residency::protected_journal::CacheHeldSelectionV1;

mod receiving;
mod capture;
mod clock;
mod producer;
mod native;
mod audit;
mod current_audit;
mod delete_inventory;
#[doc(hidden)]
pub use delete_inventory::{CacheDeleteInventoryOriginalV1, CacheDeleteInventoryQueryV1};
mod current_receiving;
mod released;
mod terminal;
pub(crate) use terminal::cache_terminal_receiving_demand_v1;
pub(crate) use released::{CacheReleasedOriginalsV1, CacheReleasedShapeV1,
    CacheReleasedAppendLoanV1, CacheReleasedCurrentnessSiteV1, release_receiving_demand_v1, release_append_bytes_v1};
pub use current_receiving::{CreateStorageCacheCurrentExtentsDataV1, create_storage_cache_current_dynamic_receiving_demand_v1};
pub(crate) use current_receiving::current_cache_fixed_receiving_demand_v1;

pub(crate) use current_audit::{CacheCurrentAuditOriginalsV1, CacheCurrentAuditShapeV1};
pub(crate) use native::{CacheHeldNativeSemanticShapeV1, CacheHeldReadonlyContextV1};
pub(crate) use receiving::{CacheCreateStorageReceivingShapeV1, CacheHeldIdentityDataV1};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("new Cache Held continuation is closed")]
pub(crate) struct CacheHeldClosedV1;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheHeldErrorV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Protected(#[from] CacheResidencyProtectedJournalErrorV1),
    #[error(transparent)]
    Physical(#[from] super::super::super::CacheOwnerErrorV1),
    #[error(transparent)]
    History(#[from] HistoryErrorV1),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Recovery(#[from] crate::cache_residency::RecoveryError),
    #[error(transparent)]
    Bootstrap(#[from] CacheReplayControllerBootstrapErrorV1),
    #[error(transparent)]
    Original(#[from] ResourceReservationErrorV1),
    #[error("new Cache Held stage or original association differs")]
    Order,
}

/// Names the five actual independently funded original-currentness crossings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheHeldCurrentnessSiteV1 {
    BeforeCapture,
    Transition,
    FinalCrossing,
    AfterAppend,
    AfterRoot,
}

#[derive(Clone, Copy)]
enum Failure {
    Order,
    Shape,
    Clock,
    Source,
    Selection,
    Encoding,
    Transaction,
    Crossing,
    Append,
    AppendGeometry,
    Readback,
    Audit,
    Post(usize),
    Root,
    Join(usize),
    Payment(usize),
}

pub(super) struct CacheHeldProgressV1 {
    started: bool,
    producing: bool,
    finished: bool,
    first: Option<Failure>,
    order: Option<CacheHeldErrorV1>,
    payment: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    shape: Option<Result<CacheCreateStorageReceivingShapeV1, CacheHeldErrorV1>>,
    initial_positions: [crate::journal::CreateStorageWriterPositionOriginalV1; 5],
    initial_physical: CachePhysicalReadbackOriginalsV1,
    body_physical: CachePhysicalReadbackOriginalsV1,
    after_hold_position: crate::journal::CreateStorageWriterPositionOriginalV1,
    clock: Option<Result<(), CacheHeldErrorV1>>,
    clock_position: crate::journal::CreateStorageWriterPositionOriginalV1,
    source: Option<Result<[u8; SOURCE_HELD_RECEIPT_BYTES_V1], CacheHeldErrorV1>>,
    selection_original: Option<Result<(), CacheHeldErrorV1>>,
    selection: Option<Result<CacheHeldSelectionV1, CacheHeldErrorV1>>,
    body: Option<Result<CacheHeldBodyDataV1, CacheHeldErrorV1>>,
    encoded_body: Option<Result<[u8; CACHE_HELD_BODY_BYTES_V1], CacheHeldErrorV1>>,
    record: [u8; CACHE_HELD_RECORD_BYTES_V1],
    head: [u8; HEAD_BYTES],
    checksum: Option<Result<[u8; 32], CacheHeldErrorV1>>,
    transaction: Option<Result<Arc<JournalTransaction>, CacheHeldErrorV1>>,
    crossing: [Option<Result<(), CacheHeldErrorV1>>; 2],
    crossing_posts: [Option<audit::CacheHeldBookendsV1>; 2],
    append_geometry: Option<Result<ResourceVector, JournalError>>,
    append_admission: Option<Result<(), ResourceReservationErrorV1>>,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<HistoryPairReadbackV1<CACHE_HELD_RECORD_BYTES_V1>, CacheHeldErrorV1>>,
    after_hold: Option<Result<CacheHeldWriterShapeV1, CacheHeldErrorV1>>,
    active_audit: Option<audit::CacheHeldAuditV1>,
    audits: [Option<audit::CacheHeldAuditDataV1>; 15],
    audit_next: usize,
    posts: [Option<audit::CacheHeldBookendsV1>; 3],
    root: Option<Result<(), ResourceReservationErrorV1>>,
    terminal: Option<Box<terminal::CacheTerminalOriginalsV1>>,
    joins: [Option<Result<(), ResourceReservationErrorV1>>; 5],
    currentness_site: Option<CacheHeldCurrentnessSiteV1>,
}

impl Default for CacheHeldProgressV1 {
    fn default() -> Self {
        Self {
            started: false,
            producing: false,
            finished: false,
            first: None,
            order: None,
            payment: [None, None],
            shape: None,
            initial_positions: std::array::from_fn(|_| Default::default()),
            initial_physical: Default::default(),
            body_physical: Default::default(),
            after_hold_position: Default::default(),
            clock: None,
            clock_position: Default::default(),
            source: None,
            selection_original: None,
            selection: None,
            body: None,
            encoded_body: None,
            record: [0; CACHE_HELD_RECORD_BYTES_V1],
            head: [0; HEAD_BYTES],
            checksum: None,
            transaction: None,
            crossing: [None, None],
            crossing_posts: [None, None],
            append_geometry: None,
            append_admission: None,
            append: None,
            readback: None,
            after_hold: None,
            active_audit: None,
            audits: std::array::from_fn(|_| None),
            audit_next: 0,
            posts: [None, None, None],
            root: None,
            terminal: None,
            joins: std::array::from_fn(|_| None),
            currentness_site: None,
        }
    }
}

impl CacheHeldProgressV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Order => self.order.as_ref().map(|cause| cause as _),
            Failure::Shape => self.initial_physical.failure()
                .or_else(|| self.initial_positions.iter().find_map(|position| position.failure()))
                .or_else(|| error(&self.shape)),
            Failure::Clock => self.clock_position.failure().or_else(|| error(&self.clock)),
            Failure::Source => error(&self.source),
            Failure::Selection => error(&self.selection_original).or_else(|| error(&self.selection)),
            Failure::Encoding => self.body_physical.failure()
                .or_else(|| error(&self.body)).or_else(|| error(&self.encoded_body))
                .or_else(|| error(&self.checksum)),
            Failure::Transaction => error(&self.transaction),
            Failure::Crossing => self.crossing.iter().find_map(error).or_else(|| self.crossing_posts.iter().flatten().find_map(audit::CacheHeldBookendsV1::failure)),
            Failure::Append => error(&self.append),
            Failure::AppendGeometry => error(&self.append_geometry).or_else(|| error(&self.append_admission)),
            Failure::Readback => self.after_hold_position.failure()
                .or_else(|| error(&self.readback)).or_else(|| error(&self.after_hold)),
            Failure::Audit => self.active_audit.as_ref().and_then(audit::CacheHeldAuditV1::failure),
            Failure::Post(index) => self.posts[index].as_ref().and_then(audit::CacheHeldBookendsV1::failure),
            Failure::Root => self.terminal.as_deref().and_then(terminal::CacheTerminalOriginalsV1::failure)
                .or_else(|| error(&self.root)),
            Failure::Join(index) => error(&self.joins[index]),
            Failure::Payment(index) => error(&self.payment[index]),
        }
    }

    fn refuse(&mut self) {
        self.order.get_or_insert(CacheHeldErrorV1::Order);
        self.first.get_or_insert(Failure::Order);
    }

    fn mark(&mut self, failed: bool, site: Failure) {
        if failed { self.first.get_or_insert(site); }
    }
}

struct CacheHeldOriginalsV1<'cache> {
    construction: &'cache super::baseline::CacheConstructionOriginalsV1,
    q04: &'cache Q04ResidentCacheProgressV1,
    original_hold: Option<Option<CachePolicyHoldV1>>,
    source: &'cache mut CacheReplayControllerBootstrapOwnerV1,
    state: &'cache mut Journal,
    hold: Option<&'cache mut Journal>,
    authority: &'cache Arc<ProtectedCacheResidencyReplayAuthorityV1>,
    clock_owner: &'cache Arc<ProtectedCacheClockV1>,
    clock: Option<CacheClockWriterReadbackGuard<'cache>>,
    physical: &'cache super::super::super::DormantCacheOwnerV1,
    physical_identity: Option<super::super::super::effect_owner::CacheOwnerHeldIdentityV1>,
    uid: u32,
}

/// Keeps the genuine initialized Cache originals through the new Held lane.
pub(crate) struct OriginalCreateStorageCacheLoanV1<'cache> {
    originals: CacheHeldOriginalsV1<'cache>,
    identity: CacheHeldIdentityDataV1,
    progress: &'cache mut CacheHeldProgressV1,
    initialization_failure: &'cache mut Option<InitializationCauseV1>,
}

/// Borrows the completed pre-Root Held stage under its genuine live original.
///
/// The private constructor checks retained admissions, append/readback, native
/// audits and independent posts. Historical bytes cannot construct this borrow;
/// dropping it does not finish or dispose the underlying armed Cache loan.
pub(crate) struct CacheHeldPreRootCutV1<'held, 'cache> {
    original: &'held mut OriginalCreateStorageCacheLoanV1<'cache>,
}

impl CacheHeldPreRootCutV1<'_, '_> {
    /// Returns comparison DATA while the same actual held Cache remains borrowed.
    ///
    /// # Errors
    /// Refuses any subsequent retained debt on that actual original.
    pub(crate) fn held_receipt_data_v1(&self) -> Result<CacheHeldReceiptDataV1<'_>, CacheHeldClosedV1> {
        self.original.held_receipt_data_v1()
    }

    /// Borrows the complete node quotas from this actual retained selection.
    ///
    /// The slice stays tied to the same live pre-Root cut. This performs no
    /// replay, allocation or encoding; the B producer separately pays any
    /// representation it builds from these original comparison rows.
    ///
    /// # Errors
    /// Refuses later Held debt or an absent/failed original selection.
    pub(crate) fn node_quotas_v1(
        &self,
    ) -> Result<&[aos_sandbox_protocol::cache_state::NodeCacheQuotaV1], CacheHeldClosedV1> {
        self.original.node_quotas_for_bundle_v1()
    }

    /// Returns same-original comparison DATA without lending a writer or payer.
    pub(crate) fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 {
        self.original.identity
    }
}

/// Borrows the actual completed audits and prior Q04 owner for selection.
///
/// Only the actual Cache producer constructs this temporary loan, after all
/// five initial whole Native readbacks and their independent posts. It has no
/// mutation method and cannot be reconstructed from a historical receipt.
pub(crate) struct CacheHeldSelectionOriginalV1<'selection> {
    q04: &'selection Q04ResidentCacheProgressV1,
    original_hold: Option<Option<CachePolicyHoldV1>>,
    hold: &'selection mut Journal,
    writers: &'selection [CacheHeldWriterShapeV1; 5],
    audits: &'selection [Option<audit::CacheHeldAuditDataV1>; 15],
    comparison: &'selection mut Option<Result<(), CacheHeldErrorV1>>,
}

impl CacheHeldSelectionOriginalV1<'_> {
    /// Rejoins this same actual prior owner and completed Native readbacks.
    ///
    /// # Errors
    /// Retains a prior-owner, audit, target or unchanged cleared-policy mismatch
    /// in the containing Cache progress before returning a coarse projection.
    pub(in crate::cache_residency) fn require_targets(
        &mut self,
        state: &Journal,
        authority: &Journal,
    ) -> Result<(), CacheHeldErrorV1> {
        if self.comparison.is_some() {
            return Err(CacheHeldErrorV1::Order);
        }
        *self.comparison = Some(self.compare_targets(state, authority));
        if matches!(self.comparison, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CacheHeldErrorV1::Order)
        }
    }

    fn compare_targets(&mut self, state: &Journal, authority: &Journal) -> Result<(), CacheHeldErrorV1> {
        self.q04.identity_after_original_clearance(self.original_hold)
            .map_err(|_| CacheHeldErrorV1::Order)?;
        for (audit, writer) in self.audits[..5].iter().zip(self.writers) {
            let audit = audit.as_ref().ok_or(CacheHeldErrorV1::Order)?;
            if audit.coordinates != writer.coordinates || audit.report.truncated_bytes != 0 {
                return Err(CacheHeldErrorV1::Order);
            }
        }
        self.writers[1].require(self.hold)?;
        self.writers[2].require(state)?;
        self.writers[3].require(authority)?;
        let expected = self.original_hold.flatten().ok_or(CacheHeldErrorV1::Order)?;
        self.hold.require_cache_cleared_comparison_data_v1(expected)?;
        Ok(())
    }
}

/// Borrows the same actual Cache and J originals for the sole Native appender.
pub(crate) struct CacheHeldAppendLoanV1<'crossing, 'original, 'cache> {
    cache: &'crossing mut OriginalCreateStorageCacheLoanV1<'cache>,
    original: &'crossing mut CreateStorageOriginalLoanV1<'original>,
}

impl CacheResidentInitializationV1 {
    fn refuse_create_storage_entry(&mut self) -> CacheHeldClosedV1 {
        self.create_storage_held.started = true;
        self.create_storage_held.refuse();
        self.first_failure.get_or_insert(InitializationCauseV1::CreateStorageHeld);
        self.complete = false;
        CacheHeldClosedV1
    }

    /// Borrows already-initialized Cache without observing or allocating.
    ///
    /// # Errors
    /// Refuses missing/foreign selected originals, reentry or prior failure.
    /// The actual J must pay the fixed frontier before capture is invoked.
    pub(crate) fn borrow_create_storage_cache_once<'cache>(
        &'cache mut self,
        owner: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache super::super::super::DormantCacheOwnerV1,
    ) -> Result<OriginalCreateStorageCacheLoanV1<'cache>, CacheHeldClosedV1> {
        let same_clock = self.clock.as_ref().zip(owner.clock.as_ref())
            .is_some_and(|(initialized, current)| Arc::ptr_eq(initialized, current));
        let same_authority = self.targets.initialized_authority.as_ref()
            .is_some_and(|initialized| Arc::ptr_eq(initialized, &owner.authority));
        if !self.complete || self.first_failure.is_some() || self.postcheck.is_some()
            || self.selected_baseline.is_none() || self.create_storage_held.started
            || !same_clock || !same_authority || self.source.is_none() || self.hold.is_none()
            || self.q04.identity_after_original_clearance(self.original_hold).is_err()
            || owner.state_journal.is_none()
        {
            return Err(self.refuse_create_storage_entry());
        }
        let initialization = self as *const Self as usize;
        let owner_identity = owner as *const CacheResidencyProtectedOwnerV1 as usize;
        let (Some(selected), Some(clock_owner), Some(source), Some((hold, _)), Some(state)) =
            (self.selected_baseline.as_ref(), self.clock.as_ref(), self.source.as_mut(),
                self.hold.as_mut(), owner.state_journal.as_mut())
        else {
            self.create_storage_held.refuse();
            self.first_failure.get_or_insert(InitializationCauseV1::CreateStorageHeld);
            self.complete = false;
            return Err(CacheHeldClosedV1);
        };
        let construction = &selected.originals;
        let identity = CacheHeldIdentityDataV1 {
            initialization, owner: owner_identity, source: source as *const _ as usize,
            state: state as *const Journal as usize, authority: Arc::as_ptr(&owner.authority) as usize,
            clock: Arc::as_ptr(clock_owner) as usize, physical: physical as *const _ as usize,
            uid: owner.owner_uid,
        };
        self.create_storage_held.started = true;
        self.complete = false;
        Ok(OriginalCreateStorageCacheLoanV1 {
            originals: CacheHeldOriginalsV1 { construction, q04: &self.q04, original_hold: self.original_hold,
                source, state, hold: Some(hold), authority: &owner.authority,
                clock_owner, clock: None, physical, physical_identity: None, uid: owner.owner_uid },
            identity, progress: &mut self.create_storage_held,
            initialization_failure: &mut self.first_failure,
        })
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}
