//! Selects the original Native error types for canonical Source lineage DATA.
//!
//! All pure comparison, optional work, shape and tests live with Source.

use super::*;

pub(super) type CompleteLineageOriginalsV1 = aos_sandbox_ledger_replay::replay::tree_lineage::source_family::CompleteLineageOriginalsV1<HierarchyProtectedJournalErrorV1>;
pub(crate) type SourceSuccessorMembersOriginalsV1 = aos_sandbox_ledger_replay::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<
    JournalError, HierarchyProtectedJournalErrorV1, crate::hierarchy::genesis_profile::SourceGenesisErrorV1,
>;
