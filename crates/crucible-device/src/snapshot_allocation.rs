//! Concrete allocation purposes for converting authenticated device wires.
//!
//! The caller supplies the saved resource authority. These requests name the
//! actual target collections without importing an account or a tree layout into
//! the device crate.

/// Identifies storage admitted before an authenticated wire becomes a collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceSnapshotAllocation {
    /// A temporary validation array with one boolean per outcome.
    ValidationFlags {
        /// Number of actual typed elements admitted before the storage birth.
        entries: usize,
    },
    /// A temporary set of request or persistence sequence numbers.
    ValidationSequences {
        /// Number of actual typed elements admitted before the storage birth.
        entries: usize,
    },
    /// A temporary set of complete contributor and request joins.
    ValidationJobs {
        /// Number of actual typed elements admitted before the storage birth.
        entries: usize,
    },
    /// An exactly reserved intermediate vector of contributor and request joins.
    ValidationJobArray {
        /// Number of actual typed elements admitted before the storage birth.
        entries: usize,
    },
    /// One contributor identity before its validation-set insertion.
    ValidationContributor,
    /// One operation code before its validation-set insertion.
    ValidationOperation,
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

pub(crate) fn admit_validation(
    admit: &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
    allocation: DeviceSnapshotAllocation,
) -> Result<(), crate::DeviceError> {
    admit(allocation).map_err(|reason| crate::DeviceError::InvalidBlockFaultDirective { reason })
}

/// Builds already-admitted validation storage without FromIterator's temporary Vec.
pub(crate) fn insert_validation_entries<T: Ord>(
    entries: impl Iterator<Item = T>,
) -> std::collections::BTreeSet<T> {
    let mut set = std::collections::BTreeSet::new();
    for entry in entries {
        set.insert(entry);
    }
    set
}
