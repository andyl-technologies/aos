//! Synchronizes the closed mutation's final writes and unique required directories.
//!
//! Full original Frame preimages remain in every refresh. This file chooses
//! durability work, never which input may change or which authority may expire.
//! Completed projection repairs and removals supplement the exact checked changes;
//! The owning producer also supplies its independently checked new candidate log
//! and genuine current Original rows. The inventory grants no authority.

use super::super::super::{NativeOpenedDirectory, ParentFence};
use super::super::{checked_body, checked_protected, directories_below, open_native};
use super::{FencePolicy, MutationRequest, NativeEffectFailure, Worker};
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

struct Target {
    root: PathBuf,
    owner: u32,
    protected: bool,
    expected: Option<Vec<u8>>,
}

struct OpenedRecord {
    path: PathBuf,
    bytes: Vec<u8>,
    stamp: super::MetadataStamp,
    owner: u32,
    protected: bool,
    file: File,
}

impl OpenedRecord {
    fn check(&mut self) -> io::Result<()> {
        if self.protected {
            checked_protected(
                &mut self.file,
                &self.path,
                self.stamp,
                &self.bytes,
                self.owner,
            )
        } else {
            checked_body(
                &mut self.file,
                &self.path,
                self.stamp,
                &self.bytes,
                self.owner,
            )
        }
    }
}

fn insert_target(
    targets: &mut BTreeMap<PathBuf, Target>,
    path: PathBuf,
    target: Target,
) -> io::Result<()> {
    if let Some(previous) = targets.get(&path) {
        if previous.root != target.root
            || previous.owner != target.owner
            || previous.protected != target.protected
            || previous.expected != target.expected
        {
            return Err(io::Error::other("mutation durability targets differ"));
        }
        return Ok(());
    }
    targets.insert(path, target);
    Ok(())
}

fn targets(request: &MutationRequest) -> io::Result<BTreeMap<PathBuf, Target>> {
    let mut targets = BTreeMap::new();
    for (path, bytes, root, protected) in [
        (&request.slot_path, &request.slot, &request.control, true),
        (
            &request.transaction_path,
            &request.transaction,
            &request.control,
            true,
        ),
        (
            &request.snapshot_path,
            &request.snapshot,
            &request.root,
            false,
        ),
        (
            &request.root.join("publication/PORTABLE"),
            &request.pointer,
            &request.root,
            false,
        ),
    ] {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: root.clone(),
                owner: request.owner,
                protected,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, bytes) in &request.proofs {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: request.control.clone(),
                owner: request.owner,
                protected: true,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, bytes) in &request.changes {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: request.root.clone(),
                owner: request.owner,
                protected: false,
                expected: bytes.clone(),
            },
        )?;
    }
    for (path, write) in request.writes.records() {
        let (owner, protected) = match write.policy() {
            FencePolicy::Payload { owner } => (owner, false),
            FencePolicy::ProtectedRecord { owner } => (owner, true),
            _ => return Err(io::Error::other("completed mutation write policy differs")),
        };
        if !request.scopes.iter().any(|scope| {
            scope.path == write.root() && scope.owner == owner && scope.protected == protected
        }) {
            return Err(io::Error::other(
                "completed mutation write boundary differs",
            ));
        }
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: write.root().to_owned(),
                owner,
                protected,
                expected: write.expected().map(<[u8]>::to_vec),
            },
        )?;
    }
    Ok(targets)
}

fn same_directory(left: &NativeOpenedDirectory, right: &NativeOpenedDirectory) -> bool {
    let policy_matches = match (left.policy, right.policy) {
        (
            FencePolicy::NamespaceDirectory { owner: left },
            FencePolicy::NamespaceDirectory { owner: right },
        )
        | (
            FencePolicy::PrivateControlDirectory { owner: left },
            FencePolicy::PrivateControlDirectory { owner: right },
        ) => left == right,
        _ => false,
    };
    policy_matches
        && left.stamp.same_incarnation(right.stamp)
        && left.parents.len() == right.parents.len()
        && left
            .parents
            .iter()
            .zip(&right.parents)
            .all(|(left, right)| {
                left.path == right.path && left.stamp.same_incarnation(right.stamp)
            })
}

fn insert_directory(
    directories: &mut BTreeMap<PathBuf, NativeOpenedDirectory>,
    directory: NativeOpenedDirectory,
) -> io::Result<()> {
    directory.check()?;
    if let Some(previous) = directories.get(&directory.path) {
        previous.check()?;
        if !same_directory(previous, &directory) {
            return Err(io::Error::other("mutation directory receipts differ"));
        }
        return Ok(());
    }
    directories.insert(directory.path.clone(), directory);
    Ok(())
}

fn original_directory(
    worker: &Worker,
    path: &Path,
    owner: u32,
) -> io::Result<NativeOpenedDirectory> {
    worker.projection.root(path, owner, true)?;
    let name = worker
        .projection
        .names
        .iter()
        .find(|name| name.path == path)
        .ok_or_else(|| io::Error::other("mutation lacks its Original control receipt"))?;
    let file = open_native(path, true)?;
    let stamp = super::MetadataStamp::checked(&file.metadata()?)?;
    if !stamp.same_incarnation(name.stamp) {
        return Err(io::Error::other(
            "mutation Original directory descriptor changed",
        ));
    }
    let directory = NativeOpenedDirectory {
        file,
        path: path.to_owned(),
        stamp,
        policy: FencePolicy::PrivateControlDirectory { owner },
        parents: name
            .parents
            .iter()
            .map(|parent| ParentFence {
                path: parent.path.clone(),
                stamp: parent.stamp,
            })
            .collect(),
    };
    directory.check()?;
    Ok(directory)
}

/// Synchronizes every selected output and completed repair without dropping inputs.
///
/// Each actual write's final retained preimage supplies its body or absence and
/// every required ancestor down to the genuine namespace/control boundary. Every
/// newly created successful staging directory is such an ancestor: creation is
/// reachable only while installing a completed target; failed installs never ack.
/// Existing Original-control boundaries remain mandatory durability handoffs.
/// Deduplication requires the same path, policy, incarnation and ancestor receipts.
///
/// # Errors
/// Refuses incomplete inventories, changed bodies or descriptors, conflicting
/// directory receipts, current authority denial and any actual sync failure.
pub(super) fn synchronize(
    request: &MutationRequest,
    worker: &mut Worker,
) -> Result<(), NativeEffectFailure> {
    for scope in &request.scopes {
        worker
            .projection
            .root(&scope.path, scope.owner, scope.protected)?;
    }
    worker.refresh(&[])?;
    let mut records = Vec::new();
    let mut directories = BTreeMap::new();
    for (path, target) in targets(request)? {
        if !path.starts_with(&target.root) || path == target.root {
            return Err(io::Error::other("mutation durability target escapes its root").into());
        }
        // Pack bodies have a separate creator seal. A publication projection
        // must not materialize a pack through this bounded metadata lane.
        if path
            .extension()
            .is_some_and(|extension| extension == "pack")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mutation metadata write names a pack",
            )
            .into());
        }
        let read = worker.projection.exact(&path, target.expected.as_deref())?;
        let policy_matches = match read.policy {
            FencePolicy::Payload { owner } => !target.protected && owner == target.owner,
            FencePolicy::ProtectedRecord { owner } => target.protected && owner == target.owner,
            _ => false,
        };
        if !policy_matches {
            return Err(io::Error::other("mutation durability target policy differs").into());
        }
        for directory in directories_below(read, &target.root, target.owner, target.protected)? {
            insert_directory(&mut directories, directory)?;
        }
        if let Some(bytes) = target.expected {
            let stamp = read
                .metadata
                .ok_or_else(|| io::Error::other("mutation output metadata absent"))?;
            if read.identity != Some(stamp.identity) {
                return Err(io::Error::other("mutation output identity differs").into());
            }
            records.push(OpenedRecord {
                file: open_native(&path, false)?,
                path,
                bytes,
                stamp,
                owner: target.owner,
                protected: target.protected,
            });
        } else if read.metadata.is_some() || read.identity.is_some() {
            return Err(io::Error::other("mutation removed output remains present").into());
        }
    }
    for (path, owner) in &request.original_directories {
        insert_directory(&mut directories, original_directory(worker, path, *owner)?)?;
    }

    for record in &mut records {
        worker.refresh(&[])?;
        record.check()?;
        worker.file_sync(&record.file, &[])?;
        record.check()?;
        worker.refresh(&[])?;
        #[cfg(all(test, feature = "tokio"))]
        if let Some(sender) = &request.completed_syncs {
            let _ = sender.send(super::MutationSyncEvent::File(record.path.clone()));
        }
    }
    let mut directories: Vec<_> = directories.into_values().collect();
    directories.sort_by(|left, right| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| left.path.cmp(&right.path))
    });
    for directory in &directories {
        worker.directory_sync(directory, false, &[])?;
        #[cfg(all(test, feature = "tokio"))]
        if let Some(sender) = &request.completed_syncs {
            let _ = sender.send(super::MutationSyncEvent::Directory(directory.path.clone()));
        }
    }
    // Recheck the very same retained file descriptors after all directory
    // durability, then sample current operation checks after the final body read.
    for record in &mut records {
        record.check()?;
    }
    worker.refresh(&[])
}
