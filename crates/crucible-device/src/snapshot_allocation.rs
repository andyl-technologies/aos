//! Concrete allocation purposes for converting authenticated device wires.
//!
//! The caller supplies the saved resource authority. These requests name the
//! actual target collections without importing an account or a tree layout into
//! the device crate.

/// Identifies storage admitted before an authenticated wire becomes a collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceSnapshotAllocation {
    /// One block page-map insertion with a `u64` key and one complete page.
    BlockPage,
    /// One previously absent `u64` entry in the block dirty-page set.
    BlockDirtyPage,
    /// One exact 9p request identity and resolved directive in the directive map.
    NinepDirective,
    /// One `u32` fid and its scenario-bound continuation in the virtual-fid map.
    NinepVirtualFid,
    /// The transformed 9p server fid table, whose owned paths are moved intact.
    NinepFidTable {
        /// Number of `(u32, FidEntry)` elements reserved before transformation.
        entries: usize,
    },
}
