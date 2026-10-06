//! Private first populated-current closure on the original Completed flight.
//!
//! This consumer joins actual Controller Complete, the same Source ACK and
//! complete inventory with the still-held Root archive. It returns no token,
//! public ancestry, live Create/Delete, retention or retirement permission.

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::protected_journal::RetainedTreeInventoryDataV1;
use crate::hierarchy::{HeldSourceFirstSuccessorObservationV2, SourceFirstSuccessorStateV2};
use crate::policy_compiler::HeldControllerFirstSourceSuccessorV2;
use crate::policy_compiler::source_genesis_root::CompletedRootFirstSourceSuccessorFloorV2;

pub(in crate::policy_compiler) fn consume_completed_first_successor_ancestry_v2(
    controller: &HeldControllerFirstSourceSuccessorV2<'_>,
    source: &HeldSourceFirstSuccessorObservationV2<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    root: &CompletedRootFirstSourceSuccessorFloorV2<'_, '_>,
) -> Result<(), SourceGenesisErrorV1> {
    root.recheck()?;
    source.require_retained_inventory_v2(inventory)?;
    controller.recheck()?;
    let floor = root.floor();
    let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
    let ack = source.ack().ok_or(SourceGenesisErrorV1::Conflict)?;
    let complete = controller.complete().ok_or(SourceGenesisErrorV1::Conflict)?;
    let intent = controller.packet().intent()?;
    if source.state() != SourceFirstSuccessorStateV2::Anchored
        || source.source_uid() != root.source_uid() || controller.source_uid() != root.source_uid()
        || floor.receipt() != receipt || receipt.approval() != controller.packet().digest()
        || receipt.begin() != controller.begin().digest() || receipt.project() != intent.project()
        || floor.predecessor_floor() != controller.begin().predecessor_floor()
        || ack.root_floor() != floor.digest() || ack.receipt() != receipt.digest()
        || complete.digest() != root.controller_complete() || complete.ack() != ack.digest()
        || ack.digest() != root.source_ack() || complete.floor() != floor.digest()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let (tree, tree_head, lineage_head) = inventory.trees()?
        .find(|(tree, _, _)| tree.project() == intent.project())
        .ok_or(SourceGenesisErrorV1::Conflict)?;
    let mut records = tree.records();
    let record = records.next().ok_or(SourceGenesisErrorV1::Conflict)?;
    let authorization = crate::publisher_policy::parse_unverified_project_authorization_claims_v2(
        &controller.packet().as_bytes()[312..536],
    )?;
    if tree.tree_generation().get() != 2 || tree_head != receipt.next_tree_head()
        || lineage_head != receipt.next_lineage_head() || tree.limits() != authorization.limits
        || tree.tombstones().next().is_some() || records.next().is_some()
        || record.sandbox() != intent.sandbox() || record.parent().is_some()
        || record.incarnation().is_some() || record.desired_generation().get() != 1
        || crate::hierarchy::codec::tree_commitment_v1(tree)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)? != receipt.next_tree_commit()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    controller.recheck()?;
    source.require_retained_inventory_v2(inventory)?;
    root.recheck()
}

/// Joins selected completion under the genuinely held mixed original flight.
pub(in crate::policy_compiler) fn consume_completed_project_successor_ancestry_v3(
    controller: &crate::policy_compiler::HeldControllerProjectSuccessorV3<'_>,
    source: &crate::hierarchy::SourceProjectContinuationObservationV3<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    root: &crate::policy_compiler::source_genesis_root::CompletedRootProjectSuccessorFloorV3<'_, '_>,
) -> Result<(), SourceGenesisErrorV1> {
    root.recheck()?;
    source.require_retained_inventory_v3(inventory)?;
    controller.recheck()?;
    let floor = root.floor();
    let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
    let ack = source.ack().ok_or(SourceGenesisErrorV1::Conflict)?;
    let complete = controller.complete().ok_or(SourceGenesisErrorV1::Conflict)?;
    let intent = controller.packet().intent()?;
    let observed = crate::hierarchy::SourceSuccessorObservationViewV3::Mixed(source);
    if observed.state()? != SourceFirstSuccessorStateV2::Anchored
        || observed.source_uid()? != root.source_uid() || controller.source_uid() != root.source_uid()
        || floor.receipt() != receipt || receipt.approval() != controller.packet().digest()
        || receipt.begin() != controller.begin().digest() || receipt.project() != intent.project()
        || floor.predecessor_floor() != controller.begin().predecessor_floor()
        || ack.root_floor() != floor.digest() || ack.receipt() != receipt.digest()
        || complete.digest() != root.controller_complete() || complete.ack() != ack.digest()
        || ack.digest() != root.source_ack() || complete.floor() != floor.digest()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let (tree, tree_head, lineage_head) = inventory.trees()?
        .find(|(tree, _, _)| tree.project() == intent.project())
        .ok_or(SourceGenesisErrorV1::Conflict)?;
    let mut records = tree.records();
    let record = records.next().ok_or(SourceGenesisErrorV1::Conflict)?;
    let authorization = crate::publisher_policy::parse_unverified_project_authorization_claims_v2(
        &controller.packet().as_bytes()[312..536],
    )?;
    if tree.tree_generation().get() != 2 || tree_head != receipt.next_tree_head()
        || lineage_head != receipt.next_lineage_head() || tree.limits() != authorization.limits
        || tree.tombstones().next().is_some() || records.next().is_some()
        || record.sandbox() != intent.sandbox() || record.parent().is_some()
        || record.incarnation().is_some() || record.desired_generation().get() != 1
        || crate::hierarchy::codec::tree_commitment_v1(tree)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)? != receipt.next_tree_commit()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    controller.recheck()?;
    source.require_retained_inventory_v3(inventory)?;
    root.recheck()
}
