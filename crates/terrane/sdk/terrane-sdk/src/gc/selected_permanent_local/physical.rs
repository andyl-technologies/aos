//! Indexes the first physical read at each path in one immutable selected image.
//!
//! Borrowed bytes retain observed absence and grant no current authority. Callers
//! still decode and verify each record and independently revalidate selection.

use super::{SelectedObservation, denied};
use crate::store::StoreFailure;
use std::collections::BTreeMap;
use std::path::Path;

/// Borrows first-match physical bytes from exactly one selected observation.
pub(super) struct PhysicalReads<'image> {
    first: BTreeMap<&'image Path, Option<&'image [u8]>>,
}

impl<'image> PhysicalReads<'image> {
    /// Indexes one immutable image without retaining it beyond the caller's borrow.
    pub(super) fn new(observed: &'image SelectedObservation<'_>) -> Self {
        Self::from_entries(
            observed
                .physical_reads()
                .iter()
                .map(|read| (read.path(), read.bytes())),
        )
    }

    fn from_entries(
        entries: impl IntoIterator<Item = (&'image Path, Option<&'image [u8]>)>,
    ) -> Self {
        let mut first = BTreeMap::new();
        for (path, bytes) in entries {
            // A first observed absence must not fall through to a later read.
            first.entry(path).or_insert(bytes);
        }
        Self { first }
    }

    /// Borrows the first read's bytes at the exact requested control path.
    ///
    /// # Errors
    /// Refuses missing paths and paths whose first read observed absence.
    pub(super) fn bytes(&self, control: &Path, key: &str) -> Result<&'image [u8], StoreFailure> {
        let path = control.join(key);
        self.first
            .get(path.as_path())
            .copied()
            .flatten()
            .ok_or_else(denied)
    }
}

#[cfg(test)]
#[path = "physical_tests.rs"]
mod tests;
