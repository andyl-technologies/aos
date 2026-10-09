//! Demand-retained authenticated canonical bytes for one source catalog path.

use super::super::codec::{TreeNode, TreeRef, validate_page_envelope, validate_tree};
use super::super::object_source::{catalog_start, page_length, validate_root};
use super::{RamObjectCoordinate, RamObjectRecord, RamStore, RamStoreError, Work};

pub(super) struct PathEntry {
    region: usize,
    first: u64,
    reference: TreeRef,
    node: TreeNode,
    record: RamObjectRecord,
}

pub(super) fn read(
    store: &RamStore,
    root: &super::LeasedRamRoot,
    root_record: &mut Option<RamObjectRecord>,
    path: &mut Vec<PathEntry>,
    coordinate: &RamObjectCoordinate,
    work: &mut Work<'_>,
) -> Result<RamObjectRecord, RamStoreError> {
    // Actual canonical bytes are pinned source possession. Retention never
    // claims that the mutable backing filename was re-read for this Want.
    work.original()
        .verify_live()
        .map_err(super::super::codec_ownership::admission)?;
    if root_record.is_none() {
        let (record, envelope) = store.read_canonical_record(root.object_id(), work)?;
        validate_root(&envelope, root)?;
        *root_record = Some(record);
    }
    let (region_id, position, requested_height, page) = match coordinate {
        RamObjectCoordinate::Root => {
            return root_record
                .clone()
                .ok_or(RamStoreError::Invalid("missing source root custody"));
        }
        RamObjectCoordinate::Catalog {
            region_id,
            first_page,
            height,
        } => (region_id, *first_page, *height, false),
        RamObjectCoordinate::Page {
            region_id,
            page_index,
        } => (region_id, *page_index, 0, true),
    };
    let (mut reference, _) = catalog_start(root, region_id, position, requested_height)?;
    let region = root
        .record()
        .topology()
        .regions()
        .iter()
        .position(|region| region.id() == region_id)
        .ok_or(RamStoreError::Invalid("transfer catalog region"))?;
    let mut first = 0;
    let mut depth = 0;
    loop {
        if path.get(depth).is_some_and(|entry| {
            entry.region != region || entry.first != first || entry.reference != reference
        }) {
            path.truncate(depth);
        }
        if path.len() == depth {
            let (record, envelope) = store.read_canonical_tree_record(reference, work)?;
            let node = validate_tree(&envelope, reference)?;
            if path.len() == path.capacity() {
                return Err(RamStoreError::Invalid(
                    "source path exceeded admitted geometry",
                ));
            }
            path.push(PathEntry {
                region,
                first,
                reference,
                node,
                record,
            });
        }
        let entry = &path[depth];
        if reference.height == requested_height {
            if !page {
                return Ok(entry.record.clone());
            }
            let TreeNode::Leaf { page: id, digest } = entry.node else {
                return Err(RamStoreError::Invalid("transfer page resolves to padding"));
            };
            let length = page_length(root, region_id, position)?;
            let (record, envelope) = store.read_canonical_record(id, work)?;
            if validate_page_envelope(&envelope, digest)? != length {
                return Err(RamStoreError::Invalid("transfer page valid length"));
            }
            return Ok(record);
        }
        let TreeNode::Branch { left, right } = entry.node else {
            return Err(RamStoreError::Invalid(
                "coordinate below canonical padding subtree",
            ));
        };
        let middle = first + (1_u64 << (reference.height - 1));
        reference = if position < middle {
            left
        } else {
            first = middle;
            right
        };
        depth += 1;
    }
}
