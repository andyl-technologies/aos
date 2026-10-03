//! Private generation-one ancestry consumption on the original settled flight.
//!
//! Complete Source replay remains DATA until joined to actual Controller
//! Complete, named Source ACK and the still-live original Root Completed floor.
//! This consumer returns no capability or detached head. It neither opens the
//! public hierarchy reader nor admits a Q04 proposal, Create or later Tree.

use aos_sandbox_core::{ObjectDigest, ProjectId};

use crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::graph::SandboxTreeV1;
use crate::hierarchy::protected_journal::RetainedTreeInventoryDataV1;
use crate::hierarchy::source_genesis::HeldSourceTreeGenesisObservationV1;
use crate::policy_compiler::source_genesis_root::CompletedRootSourceGenesisFloorV1;

// Every field is an original owner borrow. Nothing here can be decoded,
// cloned, handed to an effect, or retained beyond the Root Finish boundary.
struct CurrentGen1AncestryV1<'cut, 'controller, 'source, 'completed, 'flight> {
    controller: &'cut HeldControllerSourceGenesisV1<'controller>,
    source: &'cut HeldSourceTreeGenesisObservationV1<'source>,
    inventory: &'cut RetainedTreeInventoryDataV1<'source>,
    root: &'cut CompletedRootSourceGenesisFloorV1<'completed, 'flight>,
}

impl CurrentGen1AncestryV1<'_, '_, '_, '_, '_> {
    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.root.recheck()?;
        self.source.require_retained_inventory_v1(self.inventory)?;
        self.controller.recheck_completed_source_ack(self.source)?;

        let floor = self.root.floor();
        if floor.semantic_revision() != 1
            || floor.predecessor().is_some()
            || self.source.source_uid() != self.root.source_uid()
            || self.source.project() != Some(floor.project())
            || self.controller.acceptance().project() != floor.project()
            || self.source.receipt() != Some(floor.receipt())
            || self.source.ack_floor_digest() != Some(floor.digest())
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }

        // The entire inventory was replayed under the same writer. Selecting
        // one authenticated project does not confer authority on other Trees.
        let (tree, tree_head, lineage_head) = self
            .inventory
            .trees()?
            .find(|(tree, _, _)| tree.project() == floor.project())
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        require_empty_gen1_tree(
            tree,
            tree_head,
            lineage_head,
            floor.project(),
            floor.tree_head(),
            floor.lineage_head(),
        )?;

        self.controller.recheck_completed_source_ack(self.source)?;
        self.source.require_retained_inventory_v1(self.inventory)?;
        self.root.recheck()
    }

    fn consume(self) -> Result<(), SourceGenesisErrorV1> {
        // This is the current ancestry component only. Cache, authenticated
        // compiler inputs, matching holds and Root CAS remain separate joins.
        self.recheck()
    }
}

pub(in crate::policy_compiler) fn consume_completed_gen1_ancestry_v1(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    root: &CompletedRootSourceGenesisFloorV1<'_, '_>,
) -> Result<(), SourceGenesisErrorV1> {
    CurrentGen1AncestryV1 {
        controller,
        source,
        inventory,
        root,
    }
    .consume()
}

// DATA shape checks are shared with the unrun vectors; success alone cannot
// construct the owner-borrowing loan or substitute for the completion join.
fn require_empty_gen1_tree(
    tree: &SandboxTreeV1,
    tree_head: ObjectDigest,
    lineage_head: ObjectDigest,
    project: ProjectId,
    expected_tree_head: ObjectDigest,
    expected_lineage_head: ObjectDigest,
) -> Result<(), SourceGenesisErrorV1> {
    if tree.project() != project
        || tree.tree_generation().get() != 1
        || tree.records().next().is_some()
        || tree.tombstones().next().is_some()
        || tree_head.as_bytes() == &[0; 32]
        || lineage_head.as_bytes() == &[0; 32]
        || tree_head != expected_tree_head
        || lineage_head != expected_lineage_head
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{DesiredGeneration, Revision, SandboxId};

    use super::*;
    use crate::hierarchy::model::{SandboxTreeRecordV1, TreeLimitsV1};

    fn tree(project: ProjectId, generation: u64, tombstones: Vec<SandboxId>) -> SandboxTreeV1 {
        SandboxTreeV1::from_records_and_tombstones(
            project,
            Revision::new(generation),
            TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap(),
            Vec::new(),
            tombstones,
        )
        .unwrap()
    }

    #[test]
    fn empty_generation_one_tuple_passes_data_shape_without_minting_a_loan() {
        let project = ProjectId::from_bytes([1; 16]);
        let tree = tree(project, 1, Vec::new());
        let tree_head = ObjectDigest::from_bytes([2; 32]);
        let lineage_head = ObjectDigest::from_bytes([3; 32]);

        assert!(require_empty_gen1_tree(
            &tree,
            tree_head,
            lineage_head,
            project,
            tree_head,
            lineage_head,
        )
        .is_ok());
    }

    #[test]
    fn changed_project_generation_heads_and_sentinel_tuples_fail() {
        let project = ProjectId::from_bytes([1; 16]);
        let original = tree(project, 1, Vec::new());
        let tree_head = ObjectDigest::from_bytes([2; 32]);
        let lineage_head = ObjectDigest::from_bytes([3; 32]);
        let changed = ObjectDigest::from_bytes([4; 32]);
        let zero = ObjectDigest::from_bytes([0; 32]);
        let successor = tree(project, 2, Vec::new());
        let tombstoned = tree(project, 1, vec![SandboxId::from_bytes([5; 16])]);
        let record = SandboxTreeRecordV1::new(
            project,
            SandboxId::from_bytes([7; 16]),
            None,
            DesiredGeneration::new(1),
            None,
        )
        .unwrap();
        let populated = SandboxTreeV1::from_records(
            project,
            Revision::new(1),
            original.limits(),
            vec![record],
        )
        .unwrap();
        let cases = [
            (
                "project",
                &original,
                tree_head,
                lineage_head,
                ProjectId::from_bytes([6; 16]),
            ),
            ("successor", &successor, tree_head, lineage_head, project),
            ("tree head", &original, changed, lineage_head, project),
            ("lineage head", &original, tree_head, changed, project),
            ("zero tree", &original, zero, lineage_head, project),
            ("zero lineage", &original, tree_head, zero, project),
            ("tombstone", &tombstoned, tree_head, lineage_head, project),
            ("sandbox", &populated, tree_head, lineage_head, project),
        ];

        for (name, tree, observed_tree, observed_lineage, selected) in cases {
            assert!(
                require_empty_gen1_tree(
                    tree,
                    observed_tree,
                    observed_lineage,
                    selected,
                    tree_head,
                    lineage_head,
                )
                .is_err(),
                "{name}",
            );
        }
    }
}
