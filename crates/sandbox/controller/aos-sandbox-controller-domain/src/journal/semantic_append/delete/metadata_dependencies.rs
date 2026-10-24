//! Selects exact current View and saved Snapshot descriptors from the same genuine Source/C17 history.
//!
//! These are comparison requests for the private Cache graph reader, not read
//! capabilities. Only the actual continuously held Source scope constructs the
//! set, after the complete shared schema/model peak has been admitted.

use super::*;
pub(crate) use aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataRequestDataV2 as SourceDeleteMetadataRequestDataV2;
pub(crate) type SourceDeleteMetadataRequestErrorV2 = super::SourceDeleteGraphErrorV2;

impl SourceDeleteSemanticScopeV1<'_, '_> {
    pub(crate) fn metadata_graph_receiving_demand_v2(&self, controller: &Journal) -> Result<ResourceVector, JournalError> {
        let read = self.native.semantic_read_view_v1();
        // The full-prefix semantic supplier covers the same complete seven
        // family candidates/projection/validator. Every selected claim is one
        // actual current DesiredState row. Count that concrete namespace once
        // for the extra fixed request layout and its sole bounded media string;
        // do not infer a typed model count from arbitrary raw prefix bytes.
        let rows = read.state().keys().filter(|(namespace, _)|
            *namespace == aos_sandbox_model::RecordNamespace::DesiredState).count()
            .checked_add(controller.records(aos_sandbox_model::RecordNamespace::DesiredState).count())
            .ok_or(JournalError::JournalTooLarge)?;
        let requests = std::mem::size_of::<SourceDeleteMetadataRequestDataV2>()
            .checked_add(255)
            .and_then(|width| rows.checked_mul(width))
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let current = aos_sandbox_protocol::public_api::projection::geometry::metadata_source_receiving_bytes_v2(controller.historical_read_view_v1().rows_data_v2())
            .ok_or(JournalError::JournalTooLarge)?;
        // This initial phase now retains the one complete graph/census base
        // through subsequent object reads, rather than rebuilding it afterward.
        self.dependency_graph_receiving_demand_v2(controller, 0)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                requests.checked_add(current).ok_or(JournalError::JournalTooLarge)?))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn metadata_graph_requests_v2(&self, controller: &Journal, project: aos_sandbox_model::ProjectId)
        -> Result<(aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2,
            Vec<SourceDeleteMetadataRequestDataV2>), SourceDeleteMetadataRequestErrorV2>
    {
        let base = self.prepare_dependency_graph_base_data_v2(controller, project)?;
        let requests = base.metadata_requests_data_v2()?;
        Ok((base, requests))
    }
}
