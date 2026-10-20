//! Lends same-C17 Source/C maps to the sole passive graph fold after payment.
//!
//! Historical maps are DATA only. This owner keeps its existing native Source
//! scope, current Controller/profile/Launch and all independently owed posts.

use super::*;
use aos_sandbox_core::ProjectId;
use aos_sandbox_ledger_replay::delete_graph::{
    DeleteDependencyGraphDataV2, DeleteGraphDataErrorV2, DeleteGraphMetadataDataV2,
    delete_dependency_graph_receiving_bytes_v2, prepare_delete_dependency_graph_base_data_v2,
    finish_delete_dependency_graph_metadata_data_v2, DeleteDependencyGraphBaseDataV2,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceDeleteGraphErrorV2 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Data(#[from] DeleteGraphDataErrorV2),
    #[error(transparent)]
    Capability(#[from] crate::publisher_admin::capabilities::PublisherAuthorityError),
}

impl SourceDeleteSemanticScopeV1<'_, '_> {
    pub(crate) fn dependency_graph_receiving_demand_v2(&self, controller: &Journal,
        metadata_links: usize,
    ) -> Result<ResourceVector, JournalError> {
        let source = self.native.semantic_read_view_v1();
        let source_extent = protected_journal_preopen_replay_extent_for_prefix_v1(
            source.limits(), self.native.durable_end_data_v1())?;
        let current = controller.controller_coordinator_for_bank_read_v1()?;
        let current_extent = protected_journal_preopen_replay_extent_for_prefix_v1(
            current.limits(), current.durable_prefix_end_data_v1())?;
        let registry = crate::publisher_admin::capabilities::publisher_capability_census_receiving_bytes_v2(
            crate::publisher_admin::PublisherReadDataV2::from_journal_v2(controller))
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = delete_dependency_graph_receiving_bytes_v2(source.state(),
            controller.historical_read_view_v1().materialized_state_v1(), metadata_links)
            .and_then(|bytes| bytes.checked_add(registry))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        source_extent.dominant_semantic_receiving_demand_v1()?
            .checked_add(current_extent.dominant_semantic_receiving_demand_v1()?)
            .map_err(JournalError::ReceivingAccounting)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn prepare_dependency_graph_base_data_v2(&self, controller: &Journal, project: ProjectId,
    ) -> Result<DeleteDependencyGraphBaseDataV2, SourceDeleteGraphErrorV2> {
        let source = self.native.historical_view_v1().map_err(JournalError::ControllerNative)?;
        let registry = crate::publisher_admin::capabilities::publisher_capability_census_from_rows_v2(
            crate::publisher_admin::PublisherReadDataV2::from_journal_v2(controller),
            controller.historical_read_view_v1().rows_data_v2(),
            crate::publisher_admin::capabilities::PublisherAuthorityLimits::default())?;
        prepare_delete_dependency_graph_base_data_v2(source.materialized_state_v1(),
            controller.historical_read_view_v1().materialized_state_v1(), project, registry.records)
            .map_err(Into::into)
    }

    pub(crate) fn finish_dependency_graph_metadata_data_v2(&self, base: DeleteDependencyGraphBaseDataV2,
        controller: &Journal, metadata: &[DeleteGraphMetadataDataV2<'_>],
    ) -> Result<DeleteDependencyGraphDataV2, SourceDeleteGraphErrorV2> {
        // Only the unchanged held C/Source query can supply this private finish.
        self.native.historical_view_v1().map_err(JournalError::ControllerNative)?;
        finish_delete_dependency_graph_metadata_data_v2(base,
            controller.historical_read_view_v1().materialized_state_v1(), metadata).map_err(Into::into)
    }
}
