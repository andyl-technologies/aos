//! Owns a genuine fixed Root writer beside its actual shared permanent originals.

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use crate::canonical_journal::{CanonicalOpenedWriterDataV1, CanonicalWriterCustodyDataV1};
use crate::canonical_journal::append_stages::{CanonicalAppendPublishedDataV1, CanonicalAppendStagesV1};
use crate::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
    CanonicalCoordinatorReadV1, CanonicalWriterReadViewV1, sealed,
};
use crate::canonical_journal::coordinator::selected_append::{
    SelectedAppendCustodyV1, SelectedAppendGuardV1,
};
use crate::receiving::root_permanent::RootPermanentNativeOriginalV1;
use super::RootWriterErrorV1;

struct Body {
    stages: CanonicalAppendStagesV1<JournalTransaction>,
    boundary: Option<RootWriterErrorV1>,
}

impl Body {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stages.failure().or_else(|| self.boundary.as_ref().map(|cause| cause as _))
    }
}

/// Keeps one fixed native writer with the SAME original Root enrollment/fence.
///
/// Its constructor is private to the original fixed opening. The trusted upper
/// coordinator retains all complete cumulative R debits and semantic gates;
/// this native-only port neither pays those models nor issues their grants.
pub struct RootCoordinatorWriterV1<P> {
    pub(super) original: Arc<RootPermanentNativeOriginalV1>,
    pub(super) physical: CanonicalWriterCustodyDataV1<P>,
    sink: Arc<SelectedAppendCustodyV1<Body>>,
    fenced: bool,
    pub(super) durable_end: u64,
}

impl<P> RootCoordinatorWriterV1<P> {
    /// Copies the actual native sequence as passive comparison DATA.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.physical.native.native().next_sequence()
    }

    /// Copies the actual opened limits without issuing currentness or authority.
    #[must_use]
    pub const fn limits(&self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        self.physical.native.native().limits()
    }

    pub(super) fn from_fixed_opening(
        opened: CanonicalOpenedWriterDataV1,
        index: BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
        compaction: P,
        original: Arc<RootPermanentNativeOriginalV1>,
        durable_end: u64,
    ) -> Self {
        let (physical, _report) = CanonicalWriterCustodyDataV1::from_opened_data_v1(opened, index, compaction);
        Self { original, physical, sink: Arc::new(SelectedAppendCustodyV1::new()), fenced: false, durable_end }
    }

    /// Bounds its actual construction and new sink before their allocation.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(std::mem::size_of::<SelectedAppendCustodyV1<Body>>())?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<SelectedAppendCustodyV1<Body>>())?
            .checked_add(CanonicalWriterCustodyDataV1::<P>::receiving_construction_bytes_v1()?)
    }

    /// Computes actual native append representation bytes before any clone.
    ///
    /// The upper real R stage adds this to its complete current prefix. This
    /// number is DATA, not permission or a substitute for that mandatory gate.
    pub fn append_construction_bytes_v1(transaction: &JournalTransaction) -> Option<usize> {
        let records = transaction.records().len().checked_mul(std::mem::size_of::<JournalRecord>())?;
        let payload = transaction.records().iter().try_fold(0usize, |sum, row| {
            sum.checked_add(row.key().len())?.checked_add(row.value().map_or(0, <[u8]>::len))
        })?;
        let wire = usize::try_from(aos_sandbox_protocol::domain_ledger::transaction::
            encoded_transaction_append_bytes(transaction).ok()?).ok()?;
        records.checked_add(payload)?.checked_mul(3)?
            .checked_add(wire.checked_mul(3)?)?
            .checked_add(std::mem::size_of::<RootPreparedAppendV1>().checked_mul(4)?)?
            .checked_add(std::mem::size_of::<Body>().checked_mul(3)?)?
            .checked_add(RootAppendFailureOriginalV1::receiving_construction_bytes_v1()?)
    }

    /// Bounds one independent native names post before its original is armed.
    ///
    /// # Errors
    /// Refuses checked geometry overflow; the actual upper R pays this demand.
    pub fn native_post_demand_v1(&self) -> Result<aos_sandbox_core::ResourceVector, RootWriterErrorV1> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<RootWriterPostOriginalV1>().checked_mul(3)
            .ok_or(RootWriterErrorV1::Closed)?;
        let parent = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| RootWriterErrorV1::Closed)?);
        let names = crate::writer_currentness::WriterCurrentnessOriginalsV1::<
            crate::canonical_journal::NativeJournalDataErrorV1,
        >::fixed_demand_v1(super::recipe::DIRECTORY.as_ref(), self.physical.location.name())?;
        parent.checked_add(names).map_err(|_| RootWriterErrorV1::Closed)
    }

    /// Arms the already-paid independent post before the actual native interval.
    ///
    /// This closed original is associated with this SAME writer and permanent
    /// Root allocation. It grants no mutation, parser entry or semantic result.
    ///
    /// # Errors
    /// Refuses unhealthy native state or a refused/ended original invocation.
    pub fn arm_native_post_once_v1(&self) -> Result<RootWriterPostOriginalV1, RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        if self.fenced || self.physical.native.native().is_poisoned() || !self.sink.is_idle()
            || !self.physical.replacement_custody.is_idle()
        {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        Ok(RootWriterPostOriginalV1 {
            original: Arc::clone(&self.original), writer: Arc::clone(&self.sink),
            names: crate::writer_currentness::WriterCurrentnessOriginalsV1::new(),
            attempted: false,
        })
    }

    /// Consumes the armed names observation after primary refusal or poison.
    ///
    /// The ordinary healthy entry is intentionally absent from this owed stage.
    /// It still requires the SAME original/writer and cannot start after Initial
    /// ends. Upper Root keeps Initial and its debt resident through this post.
    ///
    /// # Errors
    /// Retains native partials or refuses a foreign/repeated/ended original.
    pub fn finish_native_post_once_v1(
        &self,
        post: &mut RootWriterPostOriginalV1,
    ) -> Result<(), RootWriterErrorV1> {
        let mut guard = self.original.enter_observation()?;
        if post.attempted || !Arc::ptr_eq(&self.original, &post.original)
            || !Arc::ptr_eq(&self.sink, &post.writer)
        {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        post.attempted = true;
        if post.names.begin(true).is_err() {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        let result = (|| {
            self.physical.observe_names_into(&mut post.names)?;
            post.names.observe_directory(super::recipe::DIRECTORY.as_ref(), 0)?;
            post.names.bind_location(&self.physical.location)
        })();
        if post.names.finish(result).is_err() {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        Ok(())
    }

    fn body<'stage>(&self, stage: &'stage mut RootPreparedAppendV1) -> Result<&'stage mut Body, RootWriterErrorV1> {
        if self.fenced || self.physical.native.native().is_poisoned()
            || self.sink.is_closed() || !self.sink.is_active()
            || !Arc::ptr_eq(&self.original, &stage.original)
            || !Arc::ptr_eq(&self.sink, stage.storage.custody())
        {
            return Err(RootWriterErrorV1::Closed);
        }
        let body = stage.storage.body_mut().ok_or(RootWriterErrorV1::Closed)?;
        if body.failure().is_some() { return Err(RootWriterErrorV1::Closed); }
        Ok(body)
    }

    /// Reports only permanent negative native/invocation/storage state.
    #[must_use]
    pub fn is_closed_or_poisoned_v1(&self) -> bool {
        self.fenced || self.physical.native.native().is_poisoned()
            || !self.sink.is_idle() || !self.physical.replacement_custody.is_idle()
            || !self.original.invocation().is_serving()
    }

    /// Reports permanent native uncertainty while allowing the SAME healthy stage.
    ///
    /// Fresh loans still require idle append and replacement sinks. The upper
    /// semantic engine uses this negative-only view during its active stage.
    #[must_use]
    pub fn has_native_uncertainty_v1(&self) -> bool {
        self.fenced || self.physical.native.native().is_poisoned()
            || self.sink.is_closed() || self.physical.replacement_custody.is_closed()
            || !self.original.invocation().is_serving()
    }

    pub(super) fn native_stage_is_idle(&self) -> bool {
        !self.fenced && !self.physical.native.native().is_poisoned()
            && self.sink.is_idle() && self.physical.replacement_custody.is_idle()
    }

    /// Borrows the parked native cause without a shared invocation marker.
    #[must_use]
    pub fn concrete_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.sink.parked_body().and_then(Body::failure)
            .or_else(|| self.physical.replacement_custody.parked_body().and_then(|body| body.failure()))
    }

    /// Borrows the first actual parked native cause before later refusal markers.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.concrete_failure_v1()
            .or_else(|| self.original.invocation().failure().map(|cause| cause as _))
    }
}

/// Retains an independently prepaid names post from one genuine Root writer.
///
/// Its private constructor runs only during healthy original entry. A later
/// refusal cannot erase the obligation or replace its actual native partials.
/// It contains no mutation grant or public success constructor.
pub struct RootWriterPostOriginalV1 {
    original: Arc<RootPermanentNativeOriginalV1>,
    writer: Arc<SelectedAppendCustodyV1<Body>>,
    names: crate::writer_currentness::WriterCurrentnessOriginalsV1<crate::canonical_journal::NativeJournalDataErrorV1>,
    attempted: bool,
}

impl RootWriterPostOriginalV1 {
    /// Borrows only the actual names failure from this independent post.
    #[must_use]
    pub fn concrete_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.names.failure()
    }

    /// Borrows the original names failure before any later invocation marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.concrete_failure_v1().or_else(|| self.original.invocation().failure().map(|cause| cause as _))
    }

    /// Reports completed observation DATA without a serving or semantic grant.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.attempted && self.names.is_complete()
    }
}

impl Drop for RootWriterPostOriginalV1 {
    fn drop(&mut self) {
        if !self.is_complete() {
            self.original.invocation().latch_refusal();
            // Owed native originals must remain in the upper negative owner.
            std::process::abort();
        }
    }
}

/// Keeps one actual Root append with its same original and prepaid sticky sink.
pub struct RootPreparedAppendV1 {
    original: Arc<RootPermanentNativeOriginalV1>,
    storage: SelectedAppendGuardV1<Body>,
}

impl RootPreparedAppendV1 {
    /// Parks the actual negative body and lends its stable original error source.
    #[must_use]
    pub fn into_failure_original_v1(mut self) -> RootAppendFailureOriginalV1 {
        if let Some(body) = self.storage.body_mut() {
            if body.failure().is_none() { body.boundary = Some(RootWriterErrorV1::Closed); }
        }
        self.original.invocation().latch_refusal();
        let failure = RootAppendFailureOriginalV1 {
            original: Arc::clone(&self.original), sink: Arc::clone(self.storage.custody()),
        };
        self.storage.park_unfinished();
        failure
    }
}

impl Drop for RootPreparedAppendV1 {
    fn drop(&mut self) {
        if self.storage.body().is_some() {
            self.original.invocation().latch_refusal();
            self.storage.park_unfinished();
        }
    }
}

/// Retains the exact parked Root native failure and the original invocation.
pub struct RootAppendFailureOriginalV1 {
    original: Arc<RootPermanentNativeOriginalV1>,
    sink: Arc<SelectedAppendCustodyV1<Body>>,
}

impl RootAppendFailureOriginalV1 {
    /// Borrows the actual native first cause without cloning or locking it.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.sink.parked_body().and_then(Body::failure)
            .or_else(|| self.original.invocation().failure().map(|cause| cause as _))
    }

    /// Bounds inline construction/return/destination bytes before preparation.
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)
    }
}

impl std::fmt::Debug for RootAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("RootAppendFailureOriginalV1").field("failure", &self.failure()).finish_non_exhaustive()
    }
}
impl std::fmt::Display for RootAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Root append original was refused"),
        }
    }
}
impl std::error::Error for RootAppendFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
}

impl<P> sealed::ReadOwner for RootCoordinatorWriterV1<P> {}
impl<P> sealed::AppendOwner for RootCoordinatorWriterV1<P> {}
impl sealed::AppendData for RootPreparedAppendV1 {}

impl<P> CanonicalCoordinatorReadV1<P> for RootCoordinatorWriterV1<P> {
    fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P> {
        CanonicalWriterReadViewV1::from_root_parts(
            self.physical.native.native(), &self.physical.index, &self.physical.location,
            self.original.invocation(),
        )
    }
}

impl CanonicalCoordinatorAppendDataV1 for RootPreparedAppendV1 {
    fn transaction(&self) -> Option<&JournalTransaction> { self.storage.body().map(|body| body.stages.transaction()) }
    fn encoded_frames(&self) -> Option<&[Vec<u8>]> { self.storage.body().and_then(|body| body.stages.encoded_frames()) }
    fn projected_materialized_bytes(&self) -> Option<usize> { self.storage.body().and_then(|body| body.stages.projected_materialized_bytes()) }
    fn last_applied_record(&self) -> Option<&JournalRecord> { self.storage.body().and_then(|body| body.stages.last_applied_record()) }
    fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1> { self.storage.body().and_then(|body| body.stages.published_coordinates()) }
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> { self.storage.body().and_then(Body::failure) }
}

impl<P> CanonicalCoordinatorAppendV1<P> for RootCoordinatorWriterV1<P> {
    type Error = RootWriterErrorV1;
    type Prepared<'transaction> = RootPreparedAppendV1;

    fn poison(&mut self) {
        self.fenced = true;
        self.physical.native.native_mut().poison();
        self.original.invocation().latch_refusal();
    }

    fn prepare_append_once<'transaction>(&mut self, transaction: &'transaction JournalTransaction)
        -> Result<RootPreparedAppendV1, RootWriterErrorV1>
    {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        if self.fenced || self.physical.native.native().is_poisoned()
            || !self.physical.replacement_custody.is_idle() || !self.sink.enter()
        {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        // The real upper R supplier admits complete native+semantic demand
        // before this exact trusted coordinator entry and before this clone.
        let mut stages = CanonicalAppendStagesV1::new_retaining_v1(transaction.clone());
        if stages.project_once(self.physical.native.native()).is_ok() {
            let _encoded = stages.encode_once(self.physical.native.native());
        }
        if stages.failure().is_some() { guard.refuse(); }
        Ok(RootPreparedAppendV1 {
            original: Arc::clone(&self.original),
            storage: SelectedAppendGuardV1::new(Arc::clone(&self.sink), Body { stages, boundary: None }),
        })
    }

    fn append_coordinates_once(&self, stage: &mut RootPreparedAppendV1) -> Result<(u64, u64), RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| Ok(self.body(stage)?.stages.coordinates_once().map_err(|_| RootWriterErrorV1::Closed)?))();
        if result.is_err() { guard.refuse(); }
        result
    }

    fn expected_append_length_once(&self, stage: &mut RootPreparedAppendV1) -> Result<u64, RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| Ok(self.body(stage)?.stages.expected_length_once(self.physical.native.native())
            .map_err(|_| RootWriterErrorV1::Closed)?))();
        if result.is_err() { guard.refuse(); }
        result
    }

    fn append_prepared_once(&mut self, stage: &mut RootPreparedAppendV1) -> Result<u64, RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| {
            let body = self.body(stage)?;
            body.stages.append_once(self.physical.native.native_mut()).map_err(|_| RootWriterErrorV1::Closed)
        })();
        if result.is_err() { guard.refuse(); }
        result
    }

    fn apply_next_record_once(&mut self, stage: &mut RootPreparedAppendV1) -> Result<bool, RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| {
            let body = self.body(stage)?;
            body.stages.apply_next_record_once(self.physical.native.native_mut(), &mut self.physical.index)
                .map_err(|_| RootWriterErrorV1::Closed)
        })();
        if result.is_err() { guard.refuse(); }
        result
    }

    fn publish_append_once(&mut self, stage: &mut RootPreparedAppendV1) -> Result<CanonicalAppendPublishedDataV1, RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| {
            let body = self.body(stage)?;
            let published = body.stages.publish_once(self.physical.native.native_mut()).map_err(|_| RootWriterErrorV1::Closed)?;
            self.durable_end = published.durable_bytes;
            Ok(published)
        })();
        if result.is_err() { guard.refuse(); }
        result
    }

    fn finish_append_after_posts_once(&mut self, stage: &mut RootPreparedAppendV1) -> Result<(), RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| {
            if !self.body(stage)?.stages.is_published() {
                return Err(RootWriterErrorV1::Closed);
            }
            let completed = stage.storage.take_body().ok_or(RootWriterErrorV1::Closed)?;
            drop(completed);
            self.sink.release_active();
            Ok(())
        })();
        if result.is_err() { guard.refuse(); }
        result
    }
}

impl<P> Drop for RootCoordinatorWriterV1<P> {
    fn drop(&mut self) {
        self.original.invocation().abort_if_armed();
        if self.fenced || self.physical.native.native().is_poisoned() || !self.sink.is_idle()
            || !self.physical.replacement_custody.is_idle()
        {
            self.original.invocation().latch_refusal();
            // Preserve actual negative native ownership before any field drops.
            std::process::abort();
        }
    }
}

impl<P> crate::canonical_journal::coordinator::sealed::NativeOwner for RootCoordinatorWriterV1<P> {}

impl<P> crate::canonical_journal::coordinator::CanonicalCoordinatorNativeV1<P> for RootCoordinatorWriterV1<P> {
    fn native_operations(&self)
        -> crate::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1<'_, P>
    {
        crate::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1::from_parts(
            self.physical.native.native(), Some(&self.physical.location), Some(self.original.invocation()),
        )
    }
}

impl<P> RootCoordinatorWriterV1<P> {
    pub(in crate::receiving) fn same_permanent_original_v1(
        &self,
        original: &Arc<RootPermanentNativeOriginalV1>,
    ) -> bool {
        Arc::ptr_eq(&self.original, original)
    }
}

impl<P> RootCoordinatorWriterV1<P> {
    /// Prices the actual held-prefix plus proposed append before model growth.
    ///
    /// This is representation DATA only; the continuously retained actual R
    /// owner performs its closed cumulative debit before any native stage.
    ///
    /// # Errors
    /// Refuses actual coordinate, row/node, key or byte geometry overflow.
    pub fn append_receiving_demand_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<aos_sandbox_core::ResourceVector, RootWriterErrorV1> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use crate::canonical_journal::coordinator::indexed_replay::CanonicalReplayIndexOriginalsV1;
        let append = aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(transaction)
            .map_err(|cause| RootWriterErrorV1::Native(cause.into()))?;
        let end = self.durable_end.checked_add(append).ok_or(RootWriterErrorV1::Closed)?;
        let extent = crate::canonical_journal::CanonicalReplayExtentDataV1::new(self.limits(), end)?;
        let bytes = Self::append_construction_bytes_v1(transaction)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(RootWriterErrorV1::Closed)?;
        let native = extent.dominant_native_receiving_demand_v1()?;
        let semantic = extent.dominant_semantic_receiving_demand_v1()?;
        let index = CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)?;
        native.checked_add(semantic)
            .and_then(|demand| demand.checked_add(index))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| RootWriterErrorV1::Closed)
    }
}
