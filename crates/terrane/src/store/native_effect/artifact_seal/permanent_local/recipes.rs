//! Indexes original recipes within one fixed permanent observation worker.
//!
//! Only path-to-ordinal selection is retained. The complete original projection
//! still owns and checks every duplicate, and callers execute the selected
//! recipe's physical checks freshly. No observation or authority is cached.

use super::super::{ExactRead, NamedFence, Projection};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Selects the first original recipe without changing the projection's vectors.
///
/// The observation worker keeps both vectors fixed for this index's lifetime.
/// Owned path keys let that worker continue its mutable synchronization steps;
/// ordinals borrow the original recipes only for each lookup.
pub(super) struct Recipes {
    names: BTreeMap<PathBuf, usize>,
    preimages: BTreeMap<PathBuf, usize>,
}

fn first_ordinals<'a>(paths: impl Iterator<Item = &'a Path>) -> BTreeMap<PathBuf, usize> {
    let mut ordinals = BTreeMap::new();
    for (ordinal, path) in paths.enumerate() {
        // Iterator::find selects the first duplicate, even if later recipes
        // have different policies or expected bytes. All remain in projection.
        ordinals.entry(path.to_owned()).or_insert(ordinal);
    }
    ordinals
}

impl Recipes {
    /// Indexes selection only, without inspecting any physical input.
    pub(super) fn new(projection: &Projection) -> Self {
        Self {
            names: first_ordinals(projection.names.iter().map(|name| name.path.as_path())),
            preimages: first_ordinals(projection.preimages.iter().map(|read| read.path.as_path())),
        }
    }

    /// Borrows the first original name recipe for the exact path.
    pub(super) fn name<'a>(
        &self,
        projection: &'a Projection,
        path: &Path,
    ) -> Option<&'a NamedFence> {
        let ordinal = *self.names.get(path)?;
        projection
            .names
            .get(ordinal)
            .filter(|name| name.path == path)
    }

    /// Borrows the nearest retained ancestor, including the path itself.
    pub(super) fn ancestor<'a>(
        &self,
        projection: &'a Projection,
        path: &Path,
    ) -> Option<&'a NamedFence> {
        path.ancestors()
            .find_map(|ancestor| self.name(projection, ancestor))
    }

    /// Selects and compares the first exact preimage without skipping duplicates.
    ///
    /// # Errors
    /// Refuses a missing original recipe or different expected bytes, including
    /// when a later duplicate would match the requested bytes.
    pub(super) fn exact<'a>(
        &self,
        projection: &'a Projection,
        path: &Path,
        bytes: Option<&[u8]>,
    ) -> io::Result<&'a ExactRead> {
        let read = self
            .preimages
            .get(path)
            .and_then(|ordinal| projection.preimages.get(*ordinal))
            .filter(|read| read.path == path)
            .ok_or_else(|| io::Error::other("creation operation lacks an exact preimage"))?;
        if read.expected.as_deref() != bytes {
            return Err(io::Error::other(
                "creation operation differs from its retained preimage",
            ));
        }
        Ok(read)
    }
}

#[cfg(test)]
#[path = "recipes/tests.rs"]
mod tests;
