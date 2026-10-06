//! Synchronizes closed publication output inventories with complete current refresh.
//!
//! Inventories select durability work only. The actual Worker retains all
//! original inputs, controls, descriptors and operation checks.

use super::super::super::{NativeOpenedDirectory, ParentFence};
use super::super::{
    FencePolicy, MetadataStamp, NativeEffectFailure, Worker, checked_body, checked_protected,
    directories_below, open_native,
};
use super::SyncScope;
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    path::{Path, PathBuf},
};

/// Records a fixed output body or completed removal under its actual boundary.
pub(in super::super) struct Target {
    /// Actual namespace or protected control boundary.
    pub(in super::super) root: PathBuf,
    /// Independently configured native owner.
    pub(in super::super) owner: u32,
    /// Identifies protected control metadata.
    pub(in super::super) protected: bool,
    /// Exact final body or actual completed absence.
    pub(in super::super) expected: Option<Vec<u8>>,
}

/// Borrows closed producer output data without creating native authority.
pub(in super::super) struct Inventory<'a> {
    /// Actual retained namespace and configured control boundaries.
    pub(in super::super) scopes: &'a [SyncScope],
    /// Closed outputs and genuine completed repairs/removals.
    pub(in super::super) targets: BTreeMap<PathBuf, Target>,
    /// Every genuinely consumed Original-control root.
    pub(in super::super) original_directories: &'a [(PathBuf, u32)],
    #[cfg(all(test, feature = "tokio"))]
    /// Test-only actual successful-sync observations.
    pub(in super::super) completed_syncs: Option<&'a std::sync::mpsc::Sender<SyncEvent>>,
}

/// Reports completed real syscalls after their fresh checks, never acknowledgment.
#[cfg(all(test, feature = "tokio"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SyncEvent {
    /// Reports the actual synchronized metadata descriptor's path.
    File(PathBuf),
    /// Reports the actual synchronized directory descriptor's path.
    Directory(PathBuf),
}

struct OpenedRecord {
    path: PathBuf,
    bytes: Vec<u8>,
    stamp: MetadataStamp,
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

/// Inserts one exact output and refuses conflicting duplicate body or scope.
///
/// # Errors
/// Refuses differing root, owner, protection or final expected bytes for one path.
pub(in super::super) fn insert_target(
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
    let stamp = MetadataStamp::checked(&file.metadata()?)?;
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
pub(in super::super) fn synchronize(
    inventory: Inventory<'_>,
    worker: &mut Worker,
) -> Result<(), NativeEffectFailure> {
    for scope in inventory.scopes {
        worker
            .projection
            .root(&scope.path, scope.owner, scope.protected)?;
    }
    worker.refresh(&[])?;
    let mut records = Vec::new();
    let mut directories = BTreeMap::new();
    for (path, target) in inventory.targets {
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
    for (path, owner) in inventory.original_directories {
        insert_directory(&mut directories, original_directory(worker, path, *owner)?)?;
    }

    for record in &mut records {
        worker.refresh(&[])?;
        record.check()?;
        worker.file_sync(&record.file, &[])?;
        record.check()?;
        worker.refresh(&[])?;
        #[cfg(all(test, feature = "tokio"))]
        if let Some(sender) = inventory.completed_syncs {
            let _ = sender.send(SyncEvent::File(record.path.clone()));
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
        if let Some(sender) = inventory.completed_syncs {
            let _ = sender.send(SyncEvent::Directory(directory.path.clone()));
        }
    }
    // Recheck the very same retained file descriptors after all directory
    // durability, then sample current operation checks after the final body read.
    for record in &mut records {
        record.check()?;
    }
    worker.refresh(&[])
}
