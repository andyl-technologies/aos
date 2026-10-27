//! Verifies and synchronizes actual copied-retirement selected publications.
//!
//! Exact canonical values are carried by a closed producer. The native worker
//! independently requires their protected or payload observations in its retained
//! Frame before synchronizing those same opened descriptors. This module grants
//! neither copied ownership nor elapsed barrier authority on its own.

use super::super::{
    FencePolicy, NativeEffectFailure, PathBuf, Worker, checked_body, checked_protected,
    directories_below, open_native,
};
use std::io;
use std::sync::Mutex;
use terrane_format::gc::publication::{PublicationCommit, PublicationTransaction};

/// Retains one exact selected transaction and its actual namespace associations.
pub(super) struct SelectedPublication {
    root: PathBuf,
    control: PathBuf,
    owner: u32,
    slot_path: PathBuf,
    slot: Vec<u8>,
    transaction_path: PathBuf,
    transaction: Vec<u8>,
    snapshot_path: PathBuf,
    snapshot: Vec<u8>,
    pointer: Vec<u8>,
}

struct ImmutableRecord {
    path: PathBuf,
    bytes: Vec<u8>,
    stamp: super::super::MetadataStamp,
    file: std::fs::File,
    protected: bool,
    owner: u32,
}

impl ImmutableRecord {
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

/// Retains actual immutable selected artifacts without mutable current preimages.
pub(super) struct ImmutablePublicationHold {
    records: Mutex<Vec<ImmutableRecord>>,
}

impl ImmutablePublicationHold {
    /// Rechecks the same retained descriptors and their genuine actual names.
    ///
    /// # Errors
    /// Refuses reincarnation, mutation, changed protection or poisoned retention.
    pub(super) fn check(&self) -> io::Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| io::Error::other("copied immutable publication retention poisoned"))?;
        for record in records.iter_mut() {
            record.check()?;
        }
        Ok(())
    }
}

impl SelectedPublication {
    /// Retains actual immutable slot, transaction, snapshot and checkpoint files.
    ///
    /// # Errors
    /// Refuses absent exact native observations, another policy/incarnation or
    /// failed current refresh. CAP, lease, PORTABLE and state CAS are excluded.
    pub(super) fn retain_immutable(
        &self,
        checkpoints: &[(PathBuf, Vec<u8>, bool)],
        worker: &Worker,
    ) -> Result<ImmutablePublicationHold, NativeEffectFailure> {
        self.check(worker)?;
        let mut records = Vec::new();
        for (path, bytes, protected) in [
            (&self.slot_path, self.slot.as_slice(), true),
            (&self.transaction_path, self.transaction.as_slice(), true),
            (&self.snapshot_path, self.snapshot.as_slice(), false),
        ]
        .into_iter()
        .chain(
            checkpoints
                .iter()
                .filter(|(path, _, _)| path.file_name().is_none_or(|name| name != "state"))
                .map(|(path, bytes, protected)| (path, bytes.as_slice(), *protected)),
        ) {
            let read = worker.projection.exact(path, Some(bytes))?;
            let correct = if protected {
                matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == self.owner)
            } else {
                matches!(read.policy, FencePolicy::Payload { owner } if owner == self.owner)
            };
            if !correct {
                return Err(io::Error::other("copied immutable policy differs").into());
            }
            let stamp = read
                .metadata
                .ok_or_else(|| io::Error::other("copied immutable metadata absent"))?;
            let mut record = ImmutableRecord {
                path: path.clone(),
                bytes: bytes.to_vec(),
                stamp,
                file: open_native(path, false)?,
                protected,
                owner: self.owner,
            };
            record.check()?;
            records.push(record);
        }
        self.check(worker)?;
        Ok(ImmutablePublicationHold {
            records: Mutex::new(records),
        })
    }

    /// Copies canonical values without constructing any native acknowledgment.
    ///
    /// # Errors
    /// Refuses inconsistent slot, transaction, snapshot or namespace paths.
    pub(super) fn observed(
        root: PathBuf,
        control: PathBuf,
        owner: u32,
        slot: &PublicationCommit,
        transaction: &PublicationTransaction,
        snapshot: &[u8],
    ) -> Result<Self, NativeEffectFailure> {
        let slot_path = control.join(format!("publication/commits/{}", slot.revision));
        let slot_bytes = slot.encode().map_err(io::Error::other)?;
        let transaction_bytes = transaction.encode().map_err(io::Error::other)?;
        slot.check_transaction(
            &format!("publication/commits/{}", slot.revision),
            &transaction_bytes,
        )
        .map_err(io::Error::other)?;
        transaction
            .check_snapshot(snapshot)
            .map_err(io::Error::other)?;
        if slot.revision != transaction.new.revision
            || slot.predecessor != transaction.predecessor.as_ref().map(|row| row.digest)
        {
            return Err(io::Error::other("copied publication predecessor differs").into());
        }
        let pointer = transaction.snapshot.encode().map_err(io::Error::other)?;
        Ok(Self {
            transaction_path: control.join(&slot.transaction_key),
            snapshot_path: root.join(&transaction.snapshot.key),
            root,
            control,
            owner,
            slot_path,
            slot: slot_bytes,
            transaction: transaction_bytes,
            snapshot: snapshot.to_vec(),
            pointer,
        })
    }

    /// Borrows the actual selected slot for native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(super) fn path(&self) -> &std::path::Path {
        &self.slot_path
    }

    /// Rechecks exact selected artifacts against the complete retained Frame.
    ///
    /// # Errors
    /// Refuses missing actual exclusions/final checks, policy mismatch, changed
    /// whole preimages or failed current/lease/control refresh.
    pub(super) fn check(&self, worker: &Worker) -> Result<(), NativeEffectFailure> {
        worker.projection.root(&self.root, self.owner, false)?;
        worker.projection.root(&self.control, self.owner, true)?;
        self.check_associations(worker)?;
        worker.refresh(&[])
    }

    // Worker durability commands already refresh all physical inputs after
    // every syscall. Recheck closed associations without scanning them again.
    fn check_associations(&self, worker: &Worker) -> Result<(), NativeEffectFailure> {
        for (path, protected) in [(&self.root, false), (&self.control, true)] {
            let named = worker
                .projection
                .names
                .iter()
                .find(|named| &named.path == path)
                .ok_or_else(|| io::Error::other("creation operation lacks its retained root"))?;
            let matches = if protected {
                matches!(named.policy, FencePolicy::PrivateControlDirectory { owner } if owner == self.owner)
            } else {
                matches!(named.policy, FencePolicy::NamespaceDirectory { owner } if owner == self.owner)
            };
            if !matches {
                return Err(io::Error::other(
                    "creation operation has the wrong retained root policy",
                )
                .into());
            }
        }
        if worker.projection.final_check.is_none() {
            return Err(io::Error::other("copied publication lacks current final check").into());
        }
        for (path, bytes, protected) in [
            (&self.slot_path, self.slot.as_slice(), true),
            (&self.transaction_path, self.transaction.as_slice(), true),
            (&self.snapshot_path, self.snapshot.as_slice(), false),
        ] {
            let read = worker.projection.exact(path, Some(bytes))?;
            let matches = if protected {
                matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == self.owner)
            } else {
                matches!(read.policy, FencePolicy::Payload { owner } if owner == self.owner)
            };
            if !matches {
                return Err(io::Error::other("copied publication record policy differs").into());
            }
        }
        worker
            .projection
            .exact(&self.root.join("publication/PORTABLE"), Some(&self.pointer))?;
        Ok(())
    }

    /// Synchronizes genuine selected artifact and consumed-control descriptors.
    ///
    /// # Errors
    /// Refuses physical reincarnation, changed bodies/protection, stale complete
    /// Frame predicates and actual file or directory synchronization failures.
    pub(super) fn synchronize(&self, worker: &mut Worker) -> Result<(), NativeEffectFailure> {
        self.check(worker)?;
        let mut records = Vec::new();
        for read in &worker.projection.preimages {
            let Some(bytes) = &read.expected else {
                continue;
            };
            let protected = read.path.starts_with(&self.control);
            if !protected && !read.path.starts_with(&self.root) {
                continue;
            }
            // Eligible pack metadata is handled by the independent placement
            // descriptor hold. Reachability must never read a DATA pack body.
            if read
                .path
                .extension()
                .is_some_and(|extension| extension == "pack")
            {
                continue;
            }
            let valid_policy = if protected {
                matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == self.owner)
            } else {
                matches!(read.policy, FencePolicy::Payload { owner } if owner == self.owner)
            };
            let stamp = read
                .metadata
                .ok_or_else(|| io::Error::other("copied artifact metadata missing"))?;
            if !valid_policy || read.identity != Some(stamp.identity) {
                return Err(io::Error::other("copied artifact policy or identity differs").into());
            }
            let directories = directories_below(
                read,
                if protected { &self.control } else { &self.root },
                self.owner,
                protected,
            )?;
            let file = open_native(&read.path, false)?;
            records.push((
                read.path.clone(),
                bytes.clone(),
                stamp,
                protected,
                file,
                directories,
            ));
        }
        for (path, bytes, stamp, protected, file, directories) in &mut records {
            let check = |file: &mut std::fs::File| -> io::Result<()> {
                if *protected {
                    checked_protected(file, path, *stamp, bytes, self.owner)
                } else {
                    checked_body(file, path, *stamp, bytes, self.owner)
                }
            };
            self.check(worker)?;
            check(file)?;
            worker.file_sync(file, &[])?;
            check(file)?;
            for directory in directories.iter().rev() {
                worker.directory_sync(directory, false, &[])?;
                check(file)?;
                self.check_associations(worker)?;
            }
        }
        self.check(worker)
    }
}
