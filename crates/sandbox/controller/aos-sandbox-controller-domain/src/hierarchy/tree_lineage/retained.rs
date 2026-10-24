//! Adapts canonical saved lineage work to the original native error boundary.
//!
//! The only implementations live in Source. This module selects the existing
//! native owning error type and projects the pure receiving overflow category.

use super::*;

pub(super) use aos_sandbox_ledger_replay::replay::tree_lineage::retained::RecordCut;
pub(super) type LineageWork = aos_sandbox_ledger_replay::replay::tree_lineage::retained::LineageWork<HierarchyProtectedJournalErrorV1>;
pub(crate) use aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeDataV1;

pub(super) fn verify_projection(
    projection: &HierarchyProtectedJournalProjectionV1,
    validator: &HierarchyProtectedReplayValidatorV1,
    work: &mut LineageWork,
    retaining: bool,
) -> Result<(), HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::replay::tree_lineage::retained::verify_projection(
        projection, validator, work, retaining,
    )
}

/// Keeps the canonical pure owner with the original native diagnostic type.
pub(crate) struct SourceCurrentTreeOriginalsV1(
    aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1<HierarchyProtectedJournalErrorV1>,
);

impl SourceCurrentTreeOriginalsV1 {
    pub(crate) fn new() -> Self {
        Self(aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1::new())
    }

    pub(crate) fn observe_once<'records>(
        &mut self,
        records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
        project: ProjectId,
    ) -> Result<(), ()> {
        self.0.observe_once(records, project)
    }

    pub(crate) fn value(&self) -> Option<SourceCurrentTreeDataV1> { self.0.value() }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.failure() }

    pub(crate) fn receiving_dynamic_demand_v1<'rows>(
        rows: impl Iterator<Item = (RecordNamespace, &'rows [u8], &'rows [u8])>,
        project: ProjectId,
    ) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1::<HierarchyProtectedJournalErrorV1>::receiving_dynamic_demand_v1(rows, project)
            .map_err(JournalError::from)
    }

    pub(crate) fn receiving_fixed_bytes_v1() -> Option<usize> {
        aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1::<HierarchyProtectedJournalErrorV1>::receiving_fixed_bytes_v1()
    }

    pub(crate) fn receiving_fixed_cells_v1() -> Option<usize> {
        aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1::<HierarchyProtectedJournalErrorV1>::receiving_fixed_cells_v1()
    }
}
