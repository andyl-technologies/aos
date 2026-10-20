//! Reads every Source-recorded Snapshot manifest on the actual paid Cache query.
//!
//! No descriptor DATA constructs a native grant. Both genuine query entrances
//! retain Source/C17 and all five Cache originals through these strict reads and
//! their real outer posts. Models retain their exact content-addressed bytes.

use super::*;
use crate::cache_residency::effect_owner::delete_metadata::{
    CacheDeleteMetadataReadOriginalV2, CacheDeleteMetadataModelOriginalV2, CacheDeleteMetadataReadClosedV2,
};
use crate::journal::{SourceDeleteMetadataRequestDataV2, SourceDeleteMetadataRequestErrorV2};

#[derive(Debug, thiserror::Error)]
enum MetadataGraphQueryErrorV2 {
    #[error(transparent)]
    Source(#[from] SourceDeleteMetadataRequestErrorV2),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Physical(#[from] super::super::super::super::super::CacheOwnerErrorV1),
    #[error("the bounded Snapshot query allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error(transparent)]
    Read(#[from] CacheDeleteMetadataReadClosedV2),
}

#[derive(Default)]
pub(super) struct CacheDeleteMetadataGraphOriginalsV2<'cache> {
    source_geometry: Option<Result<ResourceVector, JournalError>>,
    source_admission: Option<Result<(), JournalError>>,
    requests: Option<Result<Vec<SourceDeleteMetadataRequestDataV2>, SourceDeleteMetadataRequestErrorV2>>,
    base: Option<aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    admission: Option<Result<(), JournalError>>,
    readers: Vec<CacheDeleteMetadataReadOriginalV2<'cache>>,
    graph_geometry: Option<Result<ResourceVector, JournalError>>,
    graph_admission: Option<Result<(), JournalError>>,
    pub(super) graph: Option<Result<crate::journal::DeleteDependencyGraphDataV2,
        crate::journal::SourceDeleteGraphErrorV2>>,
    models: Vec<CacheDeleteMetadataModelOriginalV2>,
    expected: usize,
    returned: Option<Result<(), MetadataGraphQueryErrorV2>>,
    pub(super) positive: bool,
}

impl CacheDeleteMetadataGraphOriginalsV2<'_> {
    pub(super) fn admission_failed_v2(&self) -> bool {
        self.source_admission.as_ref().is_some_and(Result::is_err)
            || self.admission.as_ref().is_some_and(Result::is_err)
            || self.graph_admission.as_ref().is_some_and(Result::is_err)
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.source_geometry).or_else(|| error(&self.source_admission))
            .or_else(|| error(&self.requests)).or_else(|| error(&self.geometry))
            .or_else(|| error(&self.admission))
            .or_else(|| self.readers.iter().find_map(CacheDeleteMetadataReadOriginalV2::failure))
            .or_else(|| error(&self.graph_geometry)).or_else(|| error(&self.graph_admission))
            .or_else(|| error(&self.graph)).or_else(|| error(&self.returned))
    }

    pub(super) fn complete_v2(&self) -> bool {
        matches!(self.returned, Some(Ok(()))) && self.models.is_empty() && self.base.is_none()
            && self.readers.len() == self.expected
            && self.readers.iter().all(CacheDeleteMetadataReadOriginalV2::is_positive_v2)
            && matches!(self.graph, Some(Ok(_)))
    }

    // Invoked only after the whole Cache/Source/C/profile/nonce post set passed,
    // while the same genuine Native disposition token still holds the slot.
    pub(super) fn retire_positive_native_once_v2(&mut self) {
        if !self.complete_v2() { std::process::abort(); }
        while let Some(reader) = self.readers.pop() {
            self.models.push(reader.complete_after_query_posts_v2());
        }
        self.positive = true;
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
        // Pay the actual complete Source family parser peak before its first
        // canonical replay or typed recorded-manifest request allocation.
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
                self.cache.metadata_graph.requests = Some(Ok(requests));
            }
            Err(cause) => { self.cache.metadata_graph.requests = Some(Err(cause)); }
        }
        let requests = self.cache.metadata_graph.requests.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        self.cache.metadata_graph.expected = requests.len();
        let physical: &'cache super::super::super::super::super::DormantCacheOwnerV1 = self.cache.originals.physical;
        let geometry = (|| {
            let mut complete = ResourceVector::ZERO;
            for request in requests {
                let bytes = CacheDeleteMetadataReadOriginalV2::receiving_bytes_v2(physical, request)
                    .map_err(|_| JournalError::JournalTooLarge)?;
                complete = complete.checked_add(ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?)
                    .with(D::OpenFiles, CacheDeleteMetadataReadOriginalV2::opened_file_bound_v2()))
                    .map_err(JournalError::ReceivingAccounting)?;
            }
            Ok(complete)
        })();
        self.cache.metadata_graph.geometry = Some(geometry);
        let demand = self.cache.metadata_graph.geometry.as_ref()
            .and_then(|value| value.as_ref().ok()).copied().ok_or(JournalError::ProtectedBoundary)?;
        self.cache.metadata_graph.admission = Some(self.source.reserve_additional_v1(
            self.controller, self.launch, self.profile, demand));
        if !matches!(self.cache.metadata_graph.admission, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        // Both arrays' exact capacities are included in the typed supplier;
        // no allocation is postponed until positive native disposition.
        self.cache.metadata_graph.readers.try_reserve_exact(self.cache.metadata_graph.expected)?;
        self.cache.metadata_graph.models.try_reserve_exact(self.cache.metadata_graph.expected)?;
        loop {
            let request = self.cache.metadata_graph.requests.as_mut()
                .and_then(|value| value.as_mut().ok()).and_then(Vec::pop);
            let Some(request) = request else { break; };
            let (_, cutoff) = self.source.coordinates_v1()?;
            self.cache.metadata_graph.readers.push(CacheDeleteMetadataReadOriginalV2::new(physical, request));
            let reader = self.cache.metadata_graph.readers.last_mut().ok_or(JournalError::ProtectedBoundary)?;
            reader.run_once_v2(cutoff)?;
        }
        self.capture_dependency_graph_once_v2()?;
        Ok(())
    }

    fn capture_dependency_graph_once_v2(&mut self) -> Result<(), MetadataGraphQueryErrorV2> {
        use aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataDataV2 as Model;
        let readers = &self.cache.metadata_graph.readers;
        let mut links = 0usize;
        let mut views = 0usize;
        for reader in readers {
            let model = reader.parsed_metadata_data_v2().ok_or(JournalError::ProtectedBoundary)?;
            if matches!(model, Model::View { .. }) { views = views.checked_add(1).ok_or(JournalError::JournalTooLarge)?; }
        }
        for reader in readers {
            let model = reader.parsed_metadata_data_v2().ok_or(JournalError::ProtectedBoundary)?;
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
        let inputs = readers.len().checked_mul(std::mem::size_of::<Model<'_>>())
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
        metadata.try_reserve_exact(self.cache.metadata_graph.readers.len())?;
        for reader in &self.cache.metadata_graph.readers {
            metadata.push(reader.parsed_metadata_data_v2().ok_or(JournalError::ProtectedBoundary)?);
        }
        let base = self.cache.metadata_graph.base.take().ok_or(JournalError::ProtectedBoundary)?;
        self.cache.metadata_graph.graph = Some(self.source.finish_dependency_graph_metadata_data_v2(
            base, self.controller, &metadata));
        if matches!(self.cache.metadata_graph.graph, Some(Ok(_))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary.into())
        }
    }
}
