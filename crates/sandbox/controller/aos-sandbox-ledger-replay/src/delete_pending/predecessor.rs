//! Compares the actual pre-Planned prefix inside the sole canonical replay.
//!
//! The current COMMIT's borrowed prior state and BEGIN position supply the V2
//! Source preimage. No row is removed, map cloned, current head reinterpreted,
//! or independent native reader opened. Successful DATA still requires the
//! caller's actual full semantic completion, native posts and role conjunction.

use super::{JournalError, SourceDeletePendingReplayDataV1};
use crate::replay::tree_lineage::delete_cut::{
    DeleteSourceCutDataErrorV2, source_predecessor_cut_data_v2,
};
use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_model::ProjectId;
use aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1;
use std::error::Error;

/// Preserves the original complete Tree fold or encoder rejection.
#[derive(Debug, thiserror::Error)]
pub enum DeleteSourceTreeDataErrorV1 {
    /// The complete saved Tree/Lineage model is malformed.
    #[error(transparent)]
    Hierarchy(#[from] aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),
    /// The existing canonical Tree commitment encoder refused its model.
    #[error(transparent)]
    Tree(#[from] crate::hierarchy::codec::HierarchyCodecError),
    /// The actual saved project has no complete Tree/Lineage head.
    #[error(transparent)]
    Data(#[from] aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentDataErrorV1),
}

/// Contains the complete canonical Tree/Lineage comparison fields.
#[derive(Clone, Copy)]
pub struct DeleteSourceTreeDataV1 {
    /// Exact canonical Tree generation.
    pub generation: u64,
    /// Canonical commitment of the complete Tree encoding.
    pub commitment: [u8; 32],
    /// Last validated Tree envelope commitment.
    pub head: [u8; 32],
    /// Last validated immutable lineage envelope commitment.
    pub lineage: [u8; 32],
}

/// Reconstructs the same complete saved project Tree comparison as Source D.
///
/// The caller pays the actual full-family model and canonical encoding peak
/// before this fold. No key, native owner or receiving authority is supplied.
///
/// # Errors
/// Preserves malformed lineage, missing project and canonical encoder errors.
pub fn source_delete_tree_data_v1<'records>(
    records: impl Iterator<
        Item = (
            aos_sandbox_model::RecordNamespace,
            &'records [u8],
            &'records [u8],
        ),
    >,
    project: ProjectId,
) -> Result<DeleteSourceTreeDataV1, DeleteSourceTreeDataErrorV1> {
    let records = records.filter(|(namespace, key, _)| {
        crate::replay::tree_lineage::retained::matching_project_tree_row(*namespace, key, project)
    });
    let mut heads = crate::replay::tree_lineage::replay_closed_tree_lineage_records_v2(records)?;
    let head = heads.remove(&project).ok_or(
        aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentDataErrorV1::Tree)?;
    Ok(DeleteSourceTreeDataV1 {
        generation: head.tree.tree_generation().get(),
        commitment: *crate::hierarchy::codec::tree_commitment_v1(&head.tree)?.as_bytes(),
        head: *head.tree_head.as_bytes(),
        lineage: *head.lineage_head.as_bytes(),
    })
}

/// Names the independent prior-state Source cut and actual final native cut.
#[derive(Clone, Copy)]
pub struct DeleteSourcePredecessorDataV2 {
    /// Whole actual native64 of the final matching pending COMMIT.
    pub native: [u8; 64],
    /// Recomputed V2 Source commitment from the actual pre-Planned prefix.
    pub source: [u8; 32],
    /// Actual pre-Planned BEGIN NEXT and byte position from the same cursor.
    pub prior_native: (u64, u64),
    /// Complete current canonical Tree/Lineage at the same captured EOF.
    pub tree: DeleteSourceTreeDataV1,
}

#[derive(Debug, thiserror::Error)]
enum PredecessorErrorV2 {
    #[error(transparent)]
    Cut(#[from] DeleteSourceCutDataErrorV2),
    #[error(transparent)]
    Tree(#[from] DeleteSourceTreeDataErrorV1),
    #[error(transparent)]
    Native(#[from] JournalError),
    #[error("Delete Source predecessor differs from the actual V2 pending commitment")]
    Binding,
}

#[derive(Clone, Copy)]
enum First {
    Pending,
    Cut,
    Complete,
    Closed,
    Graph,
}

/// Retains the actual pending/native/predecessor comparisons as passive DATA.
///
/// This constructor cannot create a Source, Root or financial owner. The
/// supplied expected native64 must be independently verified by the calling
/// role. The caller also withholds DATA until its full native posts complete.
pub struct DeleteSourcePredecessorReplayDataV2 {
    pending: SourceDeletePendingReplayDataV1,
    query: SourceDeleteCurrentQueryDataV1,
    expected_native: [u8; 64],
    cut: Option<Result<([u8; 32], (u64, u64)), PredecessorErrorV2>>,
    result: Option<Result<DeleteSourcePredecessorDataV2, PredecessorErrorV2>>,
    first: Option<First>,
    closed: JournalError,
    graph: Option<GraphCaptureDataV2>,
}

// These owned comparison inputs move from the genuine completed C holder.
// The C map itself is borrowed only during the synchronous canonical replay.
struct GraphCaptureDataV2 {
    capabilities: Option<Vec<crate::delete_graph::DeleteGraphCapabilityDataV2>>,
    base: Option<Result<crate::delete_graph::DeleteDependencyGraphBaseDataV2,
        crate::delete_graph::DeleteGraphDataErrorV2>>,
    taken: bool,
}

impl DeleteSourcePredecessorReplayDataV2 {
    /// Creates vacant comparison slots without native IO or authority.
    #[must_use]
    pub fn new(query: SourceDeleteCurrentQueryDataV1, expected_native: [u8; 64]) -> Self {
        Self {
            pending: SourceDeletePendingReplayDataV1::new(query),
            query,
            expected_native,
            cut: None,
            result: None,
            first: None,
            closed: JournalError::ProtectedBoundary,
            graph: None,
        }
    }

    /// Retains a complete supplied census for the same actual predecessor fold.
    ///
    /// Construction is inert comparison DATA. The real caller must pay the full
    /// prefix/model peak and supply its own completed protected C observations.
    #[must_use]
    pub fn with_graph_census_data_v2(
        query: SourceDeleteCurrentQueryDataV1, expected_native: [u8; 64],
        capabilities: Vec<crate::delete_graph::DeleteGraphCapabilityDataV2>,
    ) -> Self {
        let mut original = Self::new(query, expected_native);
        original.graph = Some(GraphCaptureDataV2 {
            capabilities: Some(capabilities), base: None, taken: false,
        });
        original
    }

    /// Observes the actual current COMMIT before native application.
    ///
    /// # Errors
    /// Preserves the pending decoder, actual predecessor fold or V2 binding refusal.
    pub fn observe_commit(
        &mut self,
        commit: CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        self.observe_commit_borrowed_v2(&commit)
    }

    fn observe_commit_borrowed_v2(
        &mut self, commit: &CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        if self.first.is_some() || self.result.is_some() {
            self.first.get_or_insert(First::Closed);
            return Err(JournalError::ProtectedBoundary);
        }
        if self.pending.observe_commit_borrowed(commit).is_err() {
            self.first = Some(First::Pending);
            return Err(JournalError::ProtectedBoundary);
        }
        self.cut = None;
        if self.pending.matched_current_native_v1().is_some() {
            self.cut = Some((|| {
                let expected = self
                    .pending
                    .source_commitment_v2
                    .ok_or(PredecessorErrorV2::Binding)?;
                let (next, end) = commit.begin_position();
                let actual = source_predecessor_cut_data_v2(
                    commit.prior_state(),
                    ProjectId::from_bytes(self.query.project),
                    next,
                    end,
                )?;
                if actual != expected || self.pending.source_predecessor_next_v2 != Some(next) {
                    return Err(PredecessorErrorV2::Binding);
                }
                Ok((actual, (next, end)))
            })());
            if !matches!(self.cut, Some(Ok(_))) {
                self.first = Some(First::Cut);
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }

    /// Captures graph DATA at the exact matching native COMMIT's prior state.
    ///
    /// The shared predecessor comparison runs first. No current map is edited
    /// or cloned, and a nonmatching historical pending transaction cannot consume
    /// the census. The borrowed C map never escapes this synchronous call.
    ///
    /// # Errors
    /// Retains the original predecessor rejection or the exact shared graph error.
    pub fn observe_commit_with_graph_data_v2(
        &mut self, commit: CanonicalCommitReadViewV1<'_>,
        controller: &std::collections::BTreeMap<
            (aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), JournalError> {
        self.observe_commit_borrowed_v2(&commit)?;
        if self.pending.matched_current_native_v1() != Some(self.expected_native) {
            return Ok(());
        }
        let graph = match self.graph.as_mut() {
            Some(graph) if graph.base.is_none() && !graph.taken => graph,
            _ => {
                self.first = Some(First::Closed);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        let Some(capabilities) = graph.capabilities.take() else {
            self.first = Some(First::Closed);
            return Err(JournalError::ProtectedBoundary);
        };
        graph.base = Some(crate::delete_graph::prepare_delete_dependency_graph_base_data_v2(
            commit.prior_state(), controller, ProjectId::from_bytes(self.query.project), capabilities));
        if !matches!(graph.base, Some(Ok(_))) {
            self.first = Some(First::Graph);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Prices the exact captured base's request construction without cloning it.
    ///
    /// # Errors
    /// Refuses incomplete comparison, absent graph or checked geometry overflow.
    pub fn graph_request_receiving_bytes_v2(&self) -> Result<usize, JournalError> {
        self.data_v2()?;
        let graph = self.graph.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if graph.taken { return Err(JournalError::ProtectedBoundary); }
        graph.base.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(|base| base.metadata_requests_receiving_bytes_v2())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Moves the one graph base only after the complete predecessor comparison.
    ///
    /// This returns historical DATA; physical/native posts and metadata completion
    /// remain obligations of the real calling owner.
    ///
    /// # Errors
    /// Refuses absent graph capture, any earlier failure or repeated transfer.
    pub fn take_graph_base_data_v2(&mut self)
        -> Result<crate::delete_graph::DeleteDependencyGraphBaseDataV2, JournalError>
    {
        self.data_v2()?;
        let graph = self.graph.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if graph.taken || !matches!(graph.base, Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        graph.taken = true;
        match graph.base.take() {
            Some(Ok(base)) => Ok(base),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Completes only the exact final native COMMIT and full current Tree fold.
    ///
    /// # Errors
    /// Rejects a later suffix, different native64, absent V2 predecessor or malformed current Tree.
    pub fn finish_prefix(
        &mut self,
        prefix: CanonicalReplayPrefixReadViewV1<'_>,
        captured_end: u64,
    ) -> Result<(), JournalError> {
        if self.first.is_some() || self.result.is_some() {
            self.first.get_or_insert(First::Closed);
            return Err(JournalError::ProtectedBoundary);
        }
        if self.pending.finish_prefix(prefix, captured_end).is_err() {
            self.first = Some(First::Pending);
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some((|| {
            let native = self
                .pending
                .proof(self.query)
                .map_err(|_| PredecessorErrorV2::Binding)?;
            if native != self.expected_native {
                return Err(PredecessorErrorV2::Binding);
            }
            let (source, prior_native) = self
                .cut
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied()
                .ok_or(PredecessorErrorV2::Binding)?;
            let tree = source_delete_tree_data_v1(
                prefix.state().iter().map(|((namespace, key), value)| {
                    (*namespace, key.as_slice(), value.as_slice())
                }),
                ProjectId::from_bytes(self.query.project),
            )?;
            Ok(DeleteSourcePredecessorDataV2 {
                native,
                source,
                prior_native,
                tree,
            })
        })());
        if matches!(self.result, Some(Ok(_))) {
            Ok(())
        } else {
            self.first = Some(First::Complete);
            Err(JournalError::ProtectedBoundary)
        }
    }

    /// Returns completed comparison DATA without authenticating its physical origin.
    ///
    /// # Errors
    /// Rejects incomplete or failed comparison; the real receiver separately checks full native posts.
    pub fn data_v2(&self) -> Result<DeleteSourcePredecessorDataV2, JournalError> {
        if self.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Borrows the retained chronological first pure comparison failure.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Pending => self.pending.failure(),
            First::Cut => self.cut.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Complete => self.result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Closed => Some(&self.closed),
            First::Graph => self.graph.as_ref()?.base.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
        }
    }
}
