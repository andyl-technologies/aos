//! Synchronizes closed publication output inventories with complete current refresh.
//!
//! Inventories select durability work only. The actual Worker retains all
//! original inputs, controls, descriptors, pairs and operation checks.

use super::super::super::{NativeOpenedDirectory, ParentFence};
use super::super::{
    FencePolicy, MetadataStamp, NativeEffectFailure, Worker, checked_body, checked_protected,
    directories_below, open_native,
};
#[path = "durability.rs"]
mod durability;
#[cfg(test)]
#[path = "raw_timings.rs"]
mod raw_timings;

use super::SyncScope;
use durability::SyncWorker;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::Arc,
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
    worker: &SyncWorker<'_>,
    path: &Path,
    owner: u32,
) -> io::Result<NativeOpenedDirectory> {
    worker.projection().root(path, owner, true)?;
    let name = worker
        .projection()
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
        file: Arc::new(file),
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
    synchronize_inner(inventory, &mut SyncWorker::ordinary(worker))
}

/// Synchronizes Raw outputs with a closed, producer-derived immutable scope.
///
/// # Errors
/// Refuses mismatched scope receipts and every ordinary durability failure.
///
/// # Panics
/// Panics in test builds if enabled Raw durability diagnostics cannot write to standard error.
pub(in super::super) fn synchronize_raw(
    inventory: Inventory<'_>,
    worker: &mut Worker,
    fresh_immutable_outputs: &BTreeSet<PathBuf>,
) -> Result<(), NativeEffectFailure> {
    let mut worker = SyncWorker::raw(fresh_immutable_outputs, &inventory.targets, worker)?;
    synchronize_inner(inventory, &mut worker)
}

fn synchronize_inner(
    inventory: Inventory<'_>,
    worker: &mut SyncWorker<'_>,
) -> Result<(), NativeEffectFailure> {
    #[cfg(test)]
    let timings = worker
        .is_raw()
        .then(|| inventory.scopes.first())
        .flatten()
        .map(|scope| raw_timings::RawTimings::new(&scope.path));
    #[cfg(test)]
    if let Some(timings) = &timings {
        timings.count("inventory-targets", inventory.targets.len());
        timings.count("retained-names", worker.projection().names.len());
        timings.count("retained-preimages", worker.projection().preimages.len());
    }
    #[cfg(test)]
    let initial_span = timings
        .as_ref()
        .map(|timings| timings.span("initial-root-and-full-refresh"));
    for scope in inventory.scopes {
        worker
            .projection()
            .root(&scope.path, scope.owner, scope.protected)
            .inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal("outputs-scope-root", Some(&scope.path), None);
            })?;
    }
    worker.full_refresh(&[]).inspect_err(|_| {
        #[cfg(test)]
        super::super::diagnostic::refusal("outputs-initial-refresh", None, None);
    })?;
    #[cfg(test)]
    drop(initial_span);
    #[cfg(test)]
    let inventory_span = timings
        .as_ref()
        .map(|timings| timings.span("inventory-construction"));
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
        let read = worker
            .projection()
            .exact(&path, target.expected.as_deref())
            .inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal("outputs-exact-target", Some(&path), None);
            })?;
        let policy_matches = match read.policy {
            FencePolicy::Payload { owner } => !target.protected && owner == target.owner,
            FencePolicy::ProtectedRecord { owner } => target.protected && owner == target.owner,
            _ => false,
        };
        if !policy_matches {
            return Err(io::Error::other("mutation durability target policy differs").into());
        }
        for directory in directories_below(read, &target.root, target.owner, target.protected)
            .inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal("outputs-target-ancestors", Some(&path), None);
            })?
        {
            insert_directory(&mut directories, directory).inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal(
                    "outputs-target-directory-receipt",
                    Some(&path),
                    None,
                );
            })?;
        }
        if let Some(bytes) = target.expected {
            let stamp = read
                .metadata
                .ok_or_else(|| io::Error::other("mutation output metadata absent"))?;
            if read.identity != Some(stamp.identity) {
                return Err(io::Error::other("mutation output identity differs").into());
            }
            records.push(OpenedRecord {
                file: open_native(&path, false).inspect_err(|_| {
                    #[cfg(test)]
                    super::super::diagnostic::refusal("outputs-open-target", Some(&path), None);
                })?,
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
        insert_directory(
            &mut directories,
            original_directory(worker, path, *owner).inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal("outputs-original-directory", Some(path), None);
            })?,
        )
        .inspect_err(|_| {
            #[cfg(test)]
            super::super::diagnostic::refusal(
                "outputs-original-directory-receipt",
                Some(path),
                None,
            );
        })?;
    }

    #[cfg(test)]
    drop(inventory_span);
    #[cfg(test)]
    if let Some(timings) = &timings {
        timings.count("inventory-records", records.len());
        timings.count(
            "inventory-body-bytes",
            records.iter().map(|record| record.bytes.len()).sum(),
        );
        timings.count("inventory-directories", directories.len());
    }
    for record in &mut records {
        #[cfg(test)]
        let file_span = timings.as_ref().map(|timings| timings.span("file-total"));
        // Raw preparation has no effect; its inner refresh checks authority
        // after this body read and immediately before the actual sync. Ordinary
        // callers retain their earlier refresh and sampling schedule.
        if !worker.is_raw() {
            worker
                .refresh(
                    #[cfg(test)]
                    timings.as_ref(),
                )
                .inspect_err(|_| {
                    #[cfg(test)]
                    super::super::diagnostic::refusal(
                        "outputs-file-before-refresh",
                        Some(&record.path),
                        None,
                    );
                })?;
        }
        #[cfg(test)]
        let body_span = timings
            .as_ref()
            .map(|timings| timings.span("record-body-before"));
        record.check().inspect_err(|_| {
            #[cfg(test)]
            super::super::diagnostic::refusal("outputs-body-before-sync", Some(&record.path), None);
        })?;
        #[cfg(test)]
        drop(body_span);
        worker
            .file_sync(
                &record.file,
                &record.path,
                #[cfg(test)]
                timings.as_ref(),
            )
            .inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal("outputs-file-sync", Some(&record.path), None);
            })?;
        #[cfg(test)]
        let body_span = timings
            .as_ref()
            .map(|timings| timings.span("record-body-after"));
        record.check().inspect_err(|_| {
            #[cfg(test)]
            super::super::diagnostic::refusal("outputs-body-after-sync", Some(&record.path), None);
        })?;
        #[cfg(test)]
        drop(body_span);
        #[cfg(all(test, feature = "tokio"))]
        worker.wait_gate(super::super::super::TestGatePhase::AfterRawSyncBody)?;
        worker
            .refresh(
                #[cfg(test)]
                timings.as_ref(),
            )
            .inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal(
                    "outputs-file-after-refresh",
                    Some(&record.path),
                    None,
                );
            })?;
        #[cfg(all(test, feature = "tokio"))]
        if let Some(sender) = inventory.completed_syncs {
            let _ = sender.send(SyncEvent::File(record.path.clone()));
        }
        #[cfg(test)]
        drop(file_span);
    }
    #[cfg(test)]
    let directories_span = timings
        .as_ref()
        .map(|timings| timings.span("directories-total"));
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
        worker
            .directory_sync(
                directory,
                #[cfg(test)]
                timings.as_ref(),
            )
            .inspect_err(|_| {
                #[cfg(test)]
                super::super::diagnostic::refusal(
                    "outputs-directory-sync",
                    Some(&directory.path),
                    None,
                );
            })?;
        #[cfg(all(test, feature = "tokio"))]
        if let Some(sender) = inventory.completed_syncs {
            let _ = sender.send(SyncEvent::Directory(directory.path.clone()));
        }
    }
    #[cfg(test)]
    drop(directories_span);
    #[cfg(test)]
    let final_body_span = timings
        .as_ref()
        .map(|timings| timings.span("final-record-bodies"));
    // Recheck the very same retained file descriptors after all directory
    // durability, then sample current operation checks after the final body read.
    for record in &mut records {
        #[cfg(test)]
        if let Some(timings) = &timings {
            timings.count("final-record-body-attempts", 1);
        }
        record.check().inspect_err(|_| {
            #[cfg(test)]
            super::super::diagnostic::refusal("outputs-final-body", Some(&record.path), None);
        })?;
    }
    #[cfg(test)]
    drop(final_body_span);
    #[cfg(test)]
    let _final_refresh_span = timings
        .as_ref()
        .map(|timings| timings.span("final-full-refresh"));
    worker.full_refresh(&[]).inspect_err(|_| {
        #[cfg(test)]
        super::super::diagnostic::refusal("outputs-final-refresh", None, None);
    })
}
