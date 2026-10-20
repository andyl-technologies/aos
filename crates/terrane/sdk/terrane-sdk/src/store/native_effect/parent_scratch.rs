//! Reuses ancestor-path capacity while freshly checking every retained parent.
//!
//! The prefix holds only temporary lexical bytes. Each call performs structural
//! validation before clearing and rebuilding it; prior contents and capacity
//! never establish physical evidence or authorize an omitted observation.

use super::{FencePolicy, MetadataStamp, ParentFence};
use std::{
    io,
    path::{Path, PathBuf},
};

/// Preserves ordered parent validation while reusing temporary path capacity.
///
/// # Errors
/// Refuses invalid paths, incomplete or misbound parent fences, unavailable
/// metadata, unsafe ancestors and changed physical incarnations.
pub(super) fn check_parents(
    path: &Path,
    parents: &[ParentFence],
    owner: u32,
    prefix: &mut PathBuf,
) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native effect path is not absolute",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing native effect parent"))?;
    let mut count = 0;
    for component in parent.components() {
        if !matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        ) {
            return Err(io::Error::other("noncanonical native effect parent"));
        }
        count += 1;
    }
    if count != parents.len() {
        return Err(io::Error::other("incomplete native parent fence"));
    }

    // Finish structural validation before fresh metadata checks, without cloning
    // every ancestor prefix into a temporary path inventory.
    prefix.clear();
    for (component, expected) in parent.components().zip(parents) {
        prefix.push(component);
        if *prefix != expected.path {
            return Err(io::Error::other("misbound native parent fence"));
        }
        let actual = MetadataStamp::checked(&std::fs::symlink_metadata(&*prefix)?)?;
        FencePolicy::ProtectedAncestor { owner }.validate(actual)?;
        if !actual.same_incarnation(expected.stamp) {
            return Err(io::Error::other("native parent incarnation changed"));
        }
    }
    Ok(())
}
