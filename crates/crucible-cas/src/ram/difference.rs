//! One bounded logical difference walk with closed, statically selected access.
//!
//! Geometry and pruning are shared by checked single-record access and the
//! private SQLite snapshot driver. Only those implementations supply records
//! or invoke the authored visitor; the walk itself performs no storage effects.

use super::codec::{TreeNode, TreeRef};
use super::{RamStoreError, Work};
use crate::content_store::ImmutableBlobBackend;

pub(super) mod sqlite;

pub(super) trait DifferenceAccess {
    fn node(&mut self, expected: TreeRef) -> Result<TreeNode, RamStoreError>;
    fn changed(&mut self, region: &str, page: u64) -> Result<(), RamStoreError>;
}

pub(super) struct ExistingDifference<'read, 'operation, B: ImmutableBlobBackend + ?Sized> {
    pub(super) backend: &'read B,
    pub(super) work: &'read mut Work<'operation>,
    pub(super) visitor: &'read mut dyn FnMut(&str, u64) -> Result<(), RamStoreError>,
}

impl<B: ImmutableBlobBackend + ?Sized> DifferenceAccess for ExistingDifference<'_, '_, B> {
    fn node(&mut self, expected: TreeRef) -> Result<TreeNode, RamStoreError> {
        let envelope =
            super::codec::read_envelope_from(self.backend, expected.id, self.work, true)?;
        super::codec::validate_tree(&envelope, expected)
    }

    fn changed(&mut self, region: &str, page: u64) -> Result<(), RamStoreError> {
        (self.visitor)(region, page)
    }
}

pub(super) fn walk_roots<A: DifferenceAccess>(
    access: &mut A,
    before: &super::LeasedRamRoot,
    after: &super::LeasedRamRoot,
) -> Result<u64, RamStoreError> {
    let mut changed = 0;
    for ((region, before_reference), after_reference) in before
        .record
        .topology()
        .regions()
        .iter()
        .filter(|region| before.record.scope().includes(region.class()))
        .zip(before.regions.iter())
        .zip(after.regions.iter())
    {
        walk(
            access,
            region.id(),
            *before_reference,
            *after_reference,
            0,
            &mut changed,
        )?;
    }
    Ok(changed)
}

pub(super) fn walk<A: DifferenceAccess>(
    access: &mut A,
    region: &str,
    before: TreeRef,
    after: TreeRef,
    first: u64,
    changed: &mut u64,
) -> Result<(), RamStoreError> {
    // Metadata is fetched even for equal roots: opaque root digests grant
    // identity, not proof that a supplied storage realization is authentic.
    let old = access.node(before)?;
    if before.id == after.id {
        // Both references name the same canonical object in this store.
        // The first read proves its actual realization; validate the second
        // reference against that proof before pruning, even for equal IDs.
        if after.height > 52 {
            return Err(RamStoreError::Invalid("tree schema or height"));
        }
        if (before.digest, before.height, before.pages) != (after.digest, after.height, after.pages)
        {
            return Err(RamStoreError::Invalid("tree reference geometry"));
        }
        return Ok(());
    }
    let new = access.node(after)?;
    if before.digest == after.digest {
        return Ok(());
    }
    match (old, new) {
        (TreeNode::Leaf { .. }, TreeNode::Leaf { .. }) => {
            access.changed(region, first)?;
            *changed = changed
                .checked_add(1)
                .ok_or(RamStoreError::Limit("different pages"))?;
            Ok(())
        }
        (
            TreeNode::Branch {
                left: old_left,
                right: old_right,
            },
            TreeNode::Branch { left, right },
        ) => {
            walk(access, region, old_left, left, first, changed)?;
            walk(
                access,
                region,
                old_right,
                right,
                first + (1_u64 << (after.height - 1)),
                changed,
            )
        }
        _ => Err(RamStoreError::Invalid("RAM difference tree shape")),
    }
}
