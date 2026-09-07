//! Pre-admitted reusable storage and borrowed views for variable worker replies.

use std::iter::FusedIterator;
use std::mem::size_of;

use super::{DirectoryReadKind, IndexNodeKind, WorkerError, WorkerLimits};

#[derive(Clone, Copy)]
pub(super) struct ReadDirRecord {
    pub(super) name_start: usize,
    pub(super) name_end: usize,
    pub(super) kind: DirectoryReadKind,
    pub(super) node_kind: IndexNodeKind,
    pub(super) node_id: Option<u64>,
    pub(super) next_cookie: u64,
}

/// Retains bounded reusable storage for directory and symlink replies.
pub struct ReplyScratch {
    pub(super) names: Vec<u8>,
    pub(super) entries: Vec<ReadDirRecord>,
    pub(super) limits: WorkerLimits,
}

impl ReplyScratch {
    /// Allocates reusable storage under the exact configured heap ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::ResourceExhausted`] if modeled or actual retained
    /// capacity exceeds the heap ceiling, or [`WorkerError::AllocationRefused`]
    /// if either bounded reservation fails.
    pub fn new(limits: WorkerLimits) -> Result<Self, WorkerError> {
        let modeled_entries = modeled_capacity::<ReadDirRecord>(limits.maximum_directory_entries)?;
        let modeled = modeled_entries
            .checked_add(usize_u64(limits.maximum_variable_bytes)?)
            .ok_or(WorkerError::ResourceExhausted)?;
        if modeled > limits.maximum_scratch_heap_bytes {
            return Err(WorkerError::ResourceExhausted);
        }

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.maximum_directory_entries)
            .map_err(|_| WorkerError::AllocationRefused)?;
        let mut names = Vec::new();
        names
            .try_reserve_exact(limits.maximum_variable_bytes)
            .map_err(|_| WorkerError::AllocationRefused)?;
        let actual = modeled_capacity::<ReadDirRecord>(entries.capacity())?
            .checked_add(usize_u64(names.capacity())?)
            .ok_or(WorkerError::ResourceExhausted)?;
        if actual > limits.maximum_scratch_heap_bytes {
            return Err(WorkerError::ResourceExhausted);
        }
        Ok(Self {
            names,
            entries,
            limits,
        })
    }

    /// Returns the exact retained capacity charged to this scratch object.
    #[must_use]
    pub fn heap_bytes(&self) -> u64 {
        modeled_capacity::<ReadDirRecord>(self.entries.capacity())
            .and_then(|entries| {
                entries
                    .checked_add(usize_u64(self.names.capacity())?)
                    .ok_or(WorkerError::ResourceExhausted)
            })
            .unwrap_or(u64::MAX)
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.names.clear();
    }
}

/// Borrows one packed directory entry from reusable scratch storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadDirEntry<'a> {
    /// Byte-exact entry name.
    pub name: &'a [u8],
    /// Dot, dot-dot, or canonical child classification.
    pub kind: DirectoryReadKind,
    /// Portable kind needed by a transport directory record.
    pub node_kind: IndexNodeKind,
    /// Connection inode for dot; deliberately absent for dot-dot and children.
    pub node_id: Option<u64>,
    /// Exact resume cookie after this entry.
    pub next_cookie: u64,
}

/// Borrows one complete bounded READDIR page from caller-owned scratch storage.
///
/// ```compile_fail
/// use aos_filesystem_view::{
///     MetadataConnection, ReadDirPage, ReplyScratch, RequestBudget, Uninterrupted, WorkerError,
/// };
///
/// fn page_cannot_escape(
///     worker: &MetadataConnection<'_, '_, '_, '_>,
///     scratch: &mut ReplyScratch,
/// ) -> Result<ReadDirPage<'static>, WorkerError> {
///     worker.readdir(1, 0, RequestBudget::new(4096, 16, 1024), scratch, &Uninterrupted)
/// }
/// ```
pub struct ReadDirPage<'a> {
    pub(super) names: &'a [u8],
    pub(super) entries: &'a [ReadDirRecord],
    pub(super) continuation_cookie: u64,
    pub(super) eof: bool,
}

impl ReadDirPage<'_> {
    /// Returns the exact cookie for the next page, or the input cookie if empty.
    #[must_use]
    pub const fn continuation_cookie(&self) -> u64 {
        self.continuation_cookie
    }

    /// Reports whether the immutable stream was exhausted.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        self.eof
    }

    /// Returns the number of complete entries in this page.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether no complete entry fit.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates borrowed entry views without allocation.
    #[must_use]
    pub fn entries(&self) -> ReadDirPageEntries<'_> {
        ReadDirPageEntries {
            names: self.names,
            entries: self.entries.iter(),
        }
    }
}

/// Iterates entries in one scratch-backed directory page.
pub struct ReadDirPageEntries<'a> {
    names: &'a [u8],
    entries: std::slice::Iter<'a, ReadDirRecord>,
}

impl<'a> Iterator for ReadDirPageEntries<'a> {
    type Item = ReadDirEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(|record| ReadDirEntry {
            name: &self.names[record.name_start..record.name_end],
            kind: record.kind,
            node_kind: record.node_kind,
            node_id: record.node_id,
            next_cookie: record.next_cookie,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for ReadDirPageEntries<'_> {}
impl FusedIterator for ReadDirPageEntries<'_> {}

fn modeled_capacity<T>(capacity: usize) -> Result<u64, WorkerError> {
    let bytes = capacity
        .checked_mul(size_of::<T>())
        .ok_or(WorkerError::ResourceExhausted)?;
    u64::try_from(bytes).map_err(|_| WorkerError::ResourceExhausted)
}

pub(super) fn usize_u64(value: usize) -> Result<u64, WorkerError> {
    u64::try_from(value).map_err(|_| WorkerError::ResourceExhausted)
}
