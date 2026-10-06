//! Synchronizes retained publication metadata on its original nofollow descriptor.
//!
//! Callers are closed native workers. This helper neither creates an acknowledgment
//! nor accepts a permission callback. Each boundary comes from the actual selected
//! namespace or its independently configured controls. System ancestors are checked
//! by the Frame but are never synchronized as publication directories.

use super::{
    FencePolicy, NativeEffectFailure, PathBuf, Worker, checked_body, checked_protected,
    directories_below, open_native,
};
use std::io;

/// Describes one actual Frame boundary without constructing a native result.
pub(super) struct SyncScope {
    /// Actual selected namespace or configured control directory.
    pub(super) path: PathBuf,
    /// Actual configured owner checked by the corresponding selected producer.
    pub(super) owner: u32,
    /// Distinguishes protected controls from namespace payloads.
    pub(super) protected: bool,
}

/// Synchronizes exact metadata and required directories while refreshing actual controls.
///
/// The immutable native projection has already been associated with the closed
/// producer's exact slot, transaction and snapshot. Every body verification is
/// bounded by its retained expected length plus one. The same descriptor supplies
/// verification and file synchronization, with name/body checks on both sides.
///
/// # Errors
/// Refuses mismatched policies, unsafe or replaced descriptors and parents,
/// changed preimages, expired operation checks, or any file/directory sync failure.
pub(super) fn synchronize(
    worker: &mut Worker,
    scopes: &[SyncScope],
) -> Result<(), NativeEffectFailure> {
    for scope in scopes {
        worker
            .projection
            .root(&scope.path, scope.owner, scope.protected)?;
    }
    worker.refresh(&[])?;

    let mut records = Vec::new();
    for read in &worker.projection.preimages {
        let Some(bytes) = &read.expected else {
            continue;
        };
        let Some(scope) = scopes
            .iter()
            .filter(|scope| read.path.starts_with(&scope.path))
            .max_by_key(|scope| scope.path.components().count())
        else {
            continue;
        };
        // Pack descriptors remain metadata-only. Their genuine creator or pair
        // durability is independent of selected metadata publication.
        if read
            .path
            .extension()
            .is_some_and(|extension| extension == "pack")
        {
            continue;
        }
        let stamp = read
            .metadata
            .ok_or_else(|| io::Error::other("publication lacks present metadata"))?;
        let correct = match read.policy {
            FencePolicy::ProtectedRecord { owner } => scope.protected && owner == scope.owner,
            FencePolicy::Payload { owner } => !scope.protected && owner == scope.owner,
            _ => false,
        };
        if !correct || read.identity != Some(stamp.identity) {
            return Err(io::Error::other("publication preimage policy differs").into());
        }
        let directories = directories_below(read, &scope.path, scope.owner, scope.protected)?;
        records.push((
            read.path.clone(),
            bytes.clone(),
            stamp,
            scope.owner,
            scope.protected,
            open_native(&read.path, false)?,
            directories,
        ));
    }

    for (path, bytes, stamp, owner, protected, file, directories) in &mut records {
        let check = |file: &mut std::fs::File| -> io::Result<()> {
            if *protected {
                checked_protected(file, path, *stamp, bytes, *owner)
            } else {
                checked_body(file, path, *stamp, bytes, *owner)
            }
        };
        worker.refresh(&[])?;
        check(file)?;
        worker.file_sync(file, &[])?;
        check(file)?;
        worker.refresh(&[])?;

        for directory in directories.iter().rev() {
            worker.directory_sync(directory, false, &[])?;
            check(file)?;
            worker.refresh(&[])?;
        }
    }
    // Pair reads can consume time. The real operation check runs after the last
    // such read as well as before the worker can populate its private channel.
    worker.refresh(&[])
}
