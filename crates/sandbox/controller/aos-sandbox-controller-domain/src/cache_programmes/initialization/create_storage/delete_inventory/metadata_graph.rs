//! Keeps actual Source graph construction around native Cache metadata custody.
//!
//! Source-family replay and graph semantic errors remain upper. The native
//! original retains whole physical readers and canonical models until the
//! same query's independent posts and actual C17 disposal permit retirement.

use super::*;
use crate::journal::SourceDeleteMetadataRequestErrorV2;

#[derive(Debug, thiserror::Error)]
enum MetadataGraphQueryErrorV2 {
    #[error(transparent)]
    Source(#[from] SourceDeleteMetadataRequestErrorV2),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("the bounded Snapshot query allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error(transparent)]
    Native(#[from] CacheHeldClosedV1),
}

#[derive(Default)]
pub(super) struct CacheDeleteMetadataGraphOriginalsV2 {
    source_geometry: Option<Result<ResourceVector, JournalError>>,
    source_admission: Option<Result<(), JournalError>>,
    requests: Option<Result<(), SourceDeleteMetadataRequestErrorV2>>,
    base: Option<aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    semantic: Option<Result<ResourceVector, CacheHeldErrorV1>>,
    admission: Option<Result<(), JournalError>>,
    cutoff: Option<Result<([u8; 16], u64), JournalError>>,
    reader_returned: Option<Result<(), CacheHeldClosedV1>>,
    graph_geometry: Option<Result<ResourceVector, JournalError>>,
    graph_admission: Option<Result<(), JournalError>>,
    pub(super) graph: Option<Result<crate::journal::DeleteDependencyGraphDataV2, crate::journal::SourceDeleteGraphErrorV2>>,
    returned: Option<Result<(), MetadataGraphQueryErrorV2>>,
    pub(super) positive: bool,
}

impl CacheDeleteMetadataGraphOriginalsV2 {
    pub(super) fn admission_failed_v2(&self) -> bool {
        self.source_admission.as_ref().is_some_and(Result::is_err)
            || self.admission.as_ref().is_some_and(Result::is_err)
            || self.graph_admission.as_ref().is_some_and(Result::is_err)
    }

    pub(super) fn failure_v2<'cause>(&'cause self, native: &'cause CacheDeleteNativeOriginalV1<'_>) -> Option<&'cause (dyn Error + 'static)> {
        error(&self.source_geometry).or_else(|| error(&self.source_admission))
            .or_else(|| error(&self.requests)).or_else(|| error(&self.geometry))
            .or_else(|| error(&self.admission)).or_else(|| error(&self.semantic))
            .or_else(|| native.metadata_preparation_failure_v2())
            .or_else(|| error(&self.cutoff)).or_else(|| native.metadata_failure_v2())
            .or_else(|| error(&self.reader_returned))
            .or_else(|| error(&self.graph_geometry)).or_else(|| error(&self.graph_admission))
            .or_else(|| error(&self.graph)).or_else(|| error(&self.returned))
    }

    pub(super) fn complete_v2(&self) -> bool {
        matches!(self.returned, Some(Ok(()))) && self.base.is_none()
            && matches!(self.graph, Some(Ok(_)))
    }
}

impl<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
    CacheDeleteInventoryQueryV1<'query, 'cache, 'fence, 'journal, 'original, 'authorization, 'profile>
{
    pub(super) fn observe_metadata_graph_once_v2(&mut self) {
        if self.cache.metadata_graph.returned.is_some() {
            self.first.get_or_insert(DeleteFailureV1::Reentry);
            return;
        }
        let result = self.read_metadata_graph_inner_v2();
        self.cache.metadata_graph.returned = Some(result);
        if !matches!(self.cache.metadata_graph.returned, Some(Ok(()))) {
            self.first.get_or_insert(DeleteFailureV1::Snapshots);
        }
    }

    fn read_metadata_graph_inner_v2(&mut self) -> Result<(), MetadataGraphQueryErrorV2> {
        self.cache.metadata_graph.source_geometry = Some(self.source.metadata_graph_receiving_demand_v2(self.controller));
        let source = self.cache.metadata_graph.source_geometry.as_ref()
            .and_then(|value| value.as_ref().ok()).copied().ok_or(JournalError::ProtectedBoundary)?;
        self.cache.metadata_graph.source_admission = Some(self.source.reserve_additional_v1(
            self.controller, self.launch, self.profile, source));
        if !matches!(self.cache.metadata_graph.source_admission, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        match self.source.metadata_graph_requests_v2(self.controller) {
            Ok((base, requests)) => {
                self.cache.metadata_graph.base = Some(base);
                self.cache.metadata_graph.requests = Some(Ok(()));
                let geometry = self.cache.native.capture_metadata_shape_once_v2(requests);
                self.cache.metadata_graph.geometry = Some(geometry.map_err(|_| {
                    match self.cache.native.metadata_geometry_failure_v2() {
                        Some(CacheHeldErrorV1::Accounting(cause)) => JournalError::ReceivingAccounting(*cause),
                        _ => JournalError::JournalTooLarge,
                    }
                }));
            }
            Err(cause) => { self.cache.metadata_graph.requests = Some(Err(cause)); }
        }
        self.cache.metadata_graph.requests.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let demand = self.cache.metadata_graph.geometry.as_ref()
            .and_then(|value| value.as_ref().ok()).copied().ok_or(JournalError::ProtectedBoundary)?;
        self.cache.metadata_graph.semantic = Some(self.cache.native.metadata_semantic_demand_v2());
        let semantic = self.cache.metadata_graph.semantic.as_ref()
            .and_then(|value| value.as_ref().ok()).copied();
        // Pure geometry errors remain deferred until the original physical
        // Source debit; an earlier admission refusal remains primary.
        let Some(semantic) = semantic else {
            self.cache.metadata_graph.admission = Some(self.source.reserve_additional_v1(
                self.controller, self.launch, self.profile, demand));
            return Err(JournalError::ProtectedBoundary.into());
        };
        if self.cache.native.metadata_expected_data_v2() != 0 {
            self.cache.metadata_graph.cutoff = Some(self.source.coordinates_v1());
        }
        let funding = self.source.borrow_audit_funding_v1(self.controller, self.launch,
            self.profile, &mut self.turn, self.cache.native.original_identity_v1(),
            demand, demand, semantic);
        let mut funding = match funding {
            Ok(original) => {
                self.cache.metadata_graph.admission = Some(Ok(()));
                ControllerCacheAuditFundingLoanV1::from_delete_v1(original)
            }
            Err(cause) => {
                self.cache.metadata_graph.admission = Some(Err(cause));
                return Err(JournalError::ProtectedBoundary.into());
            }
        };
        // Reserve both exact retained capacities before selecting the first
        // old per-reader coordinate result. No physical read has started yet.
        self.cache.metadata_graph.reader_returned = Some(self.cache.native.prepare_metadata_readers_once_v2(&mut funding));
        if matches!(self.cache.metadata_graph.reader_returned, Some(Err(_))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let cutoff = self.cache.metadata_graph.cutoff.as_ref()
            .and_then(|value| value.as_ref().ok()).map(|(_, cutoff)| *cutoff);
        self.cache.metadata_graph.reader_returned = Some(self.cache.native.read_metadata_once_v2(&mut funding, cutoff));
        drop(funding);
        if matches!(self.cache.metadata_graph.reader_returned, Some(Err(_))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.capture_dependency_graph_once_v2()?;
        Ok(())
    }

    fn capture_dependency_graph_once_v2(&mut self) -> Result<(), MetadataGraphQueryErrorV2> {
        use aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataDataV2 as Model;
        let count = self.cache.native.metadata_count_data_v2();
        let mut links = 0usize;
        let mut views = 0usize;
        for index in 0..count {
            let model = self.cache.native.metadata_data_v2(index).ok_or(JournalError::ProtectedBoundary)?;
            if matches!(model, Model::View { .. }) { views = views.checked_add(1).ok_or(JournalError::JournalTooLarge)?; }
        }
        for index in 0..count {
            let model = self.cache.native.metadata_data_v2(index).ok_or(JournalError::ProtectedBoundary)?;
            let reached = match model {
                Model::View { .. } => 1,
                Model::Snapshot { model: snapshot, .. } => snapshot.attachments().len()
                    .checked_add(snapshot.external_dependencies().len())
                    .and_then(|references| references.checked_mul(views))
                    .and_then(|references| references.checked_add(snapshot.ancestry().len()))
                    .ok_or(JournalError::JournalTooLarge)?,
            };
            links = links.checked_add(reached).ok_or(JournalError::JournalTooLarge)?;
        }
        let inputs = count.checked_mul(std::mem::size_of::<Model<'_>>())
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        self.cache.metadata_graph.graph_geometry = Some(self.source.dependency_graph_receiving_demand_v2(
            self.controller, links).and_then(|demand| demand.checked_add(
                ResourceVector::ZERO.with(D::MemoryBytes, inputs)).map_err(JournalError::ReceivingAccounting)));
        let demand = self.cache.metadata_graph.graph_geometry.as_ref()
            .and_then(|value| value.as_ref().ok()).copied().ok_or(JournalError::ProtectedBoundary)?;
        self.cache.metadata_graph.graph_admission = Some(self.source.reserve_additional_v1(
            self.controller, self.launch, self.profile, demand));
        if !matches!(self.cache.metadata_graph.graph_admission, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let mut metadata = Vec::new();
        metadata.try_reserve_exact(count)?;
        for index in 0..count {
            metadata.push(self.cache.native.metadata_data_v2(index).ok_or(JournalError::ProtectedBoundary)?);
        }
        let base = self.cache.metadata_graph.base.take().ok_or(JournalError::ProtectedBoundary)?;
        self.cache.metadata_graph.graph = Some(self.source.finish_dependency_graph_metadata_data_v2(
            base, self.controller, &metadata));
        if matches!(self.cache.metadata_graph.graph, Some(Ok(_))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary.into()) }
    }
}

pub(super) fn control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    use aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataDataV2;

    size_of::<Result<(), MetadataGraphQueryErrorV2>>().checked_mul(3)?
        .checked_add(size_of::<Result<(), SourceDeleteMetadataRequestErrorV2>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, CacheHeldErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<DeleteGraphMetadataDataV2<'_>>>().checked_mul(3)?)?
        .checked_add(size_of::<std::ops::Range<usize>>().checked_mul(3)?)?
        .checked_add(size_of::<Vec<DeleteGraphMetadataDataV2<'_>>>().checked_mul(3)?)?
        .checked_add(size_of::<(&CacheDeleteNativeOriginalV1<'_>, usize)>().checked_mul(3)?)
}
