//! Prepares empty fixed floor names before the strict approval interval.
//!
//! Exclusive creation and recovery of an empty root-owned creation prefix retain
//! their actual native outcomes. Nonempty, linked, foreign or compacted state
//! is never normalized, truncated or removed. The outer Source pays before IO.

use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1;

use super::*;

const LOCK: &str = "session-floor.journal.lock";
const COMPACT: &str = "session-floor.journal.compact.tmp";
const NAMES: [&str; 3] = [SIDECAR_NAME_V1, LOCK, COMPACT];

struct NameSample {
    open: Option<Result<File, rustix::io::Errno>>,
    metadata: Option<io::Result<Metadata>>,
    result: Option<Result<(), JournalError>>,
}

impl NameSample {
    fn new() -> Self {
        Self {
            open: None,
            metadata: None,
            result: None,
        }
    }

    fn capture(&mut self, journal: &Journal, index: usize, uid: u32, allow_root: bool) {
        self.open = Some(
            journal
                .native
                .native_operations()
                .open_named_child(NAMES[index])
                .map(File::from),
        );
        self.result = Some((|| {
            if self.absent() {
                return Ok(());
            }
            let file = self
                .open
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.metadata = Some(file.metadata());
            let metadata = self
                .metadata
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            if index == 2 {
                return Err(JournalError::ProtectedBoundary);
            }
            require_empty(metadata, uid, allow_root)
        })());
    }

    fn absent(&self) -> bool {
        matches!(self.open, Some(Err(rustix::io::Errno::NOENT)))
    }

    fn identity(&self) -> Option<FileIdentity> {
        self.metadata
            .as_ref()?
            .as_ref()
            .ok()
            .map(FileIdentity::from_metadata_data_v1)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.open
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .filter(|error| **error != rustix::io::Errno::NOENT)
            .map(|error| error as _)
            .or_else(|| {
                self.metadata
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.result
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
    }
}

fn require_empty(metadata: &Metadata, uid: u32, allow_root: bool) -> Result<(), JournalError> {
    if !metadata.is_file()
        || metadata.len() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || (metadata.uid() != uid && !(allow_root && metadata.uid() == 0))
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

struct EmptyFileOriginal {
    open: Option<Result<File, rustix::io::Errno>>,
    metadata: [Option<io::Result<Metadata>>; 2],
    flock: Option<Result<(), rustix::io::Errno>>,
    chown: Option<Result<(), rustix::io::Errno>>,
    sync: Option<io::Result<()>>,
    unlock: Option<Result<(), rustix::io::Errno>>,
    result: Option<Result<(), JournalError>>,
}

impl EmptyFileOriginal {
    fn new() -> Self {
        Self {
            open: None,
            metadata: [None, None],
            flock: None,
            chown: None,
            sync: None,
            unlock: None,
            result: None,
        }
    }

    fn prepare(&mut self, main: &Journal, before: &NameSample, index: usize, uid: u32) {
        self.open = Some(
            main.native
                .native_operations()
                .open_resumable_stage(NAMES[index], before.absent())
                .map(File::from),
        );
        self.result = Some((|| {
            let file = self
                .open
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.metadata[0] = Some(file.metadata());
            let metadata = self.metadata[0]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            require_empty(metadata, uid, true)?;
            if !before.absent()
                && Some(FileIdentity::from_metadata_data_v1(metadata)) != before.identity()
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }

            if index == 1 {
                self.flock = Some(rustix::fs::flock(
                    file,
                    rustix::fs::FlockOperation::NonBlockingLockExclusive,
                ));
                if !matches!(self.flock, Some(Ok(()))) {
                    return Err(JournalError::ProtectedBoundary);
                }
            }

            if metadata.uid() != uid {
                // Only an empty UID-zero creation prefix reaches this point.
                // The existing manual unit's CAP_CHOWN suffices; no UID switch
                // or capability expansion is needed for Controller ownership.
                self.chown = Some(rustix::fs::fchown(
                    file,
                    Some(rustix::process::Uid::from_raw(uid)),
                    None,
                ));
                if !matches!(self.chown, Some(Ok(()))) {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            self.metadata[1] = Some(file.metadata());
            let metadata = self.metadata[1]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            require_empty(metadata, uid, false)?;
            self.sync = Some(file.sync_all());
            if matches!(self.sync, Some(Ok(()))) {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            }
        })());
        // The actual writer engine acquires its own lock description next.
        // This bounded probe only excludes an already held foreign lock before
        // creating the missing floor; its explicit release remains owed after
        // failed ownership or sync. A later racing holder makes real acquisition
        // refuse before any physical TPM operation.
        if matches!(self.flock, Some(Ok(()))) {
            if let Some(Ok(file)) = self.open.as_ref() {
                self.unlock = Some(rustix::fs::flock(file, rustix::fs::FlockOperation::Unlock));
            }
        }
    }

    fn identity(&self) -> Option<FileIdentity> {
        self.metadata[1]
            .as_ref()?
            .as_ref()
            .ok()
            .map(FileIdentity::from_metadata_data_v1)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.open
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|error| error as _)
            .or_else(|| {
                self.metadata[0]
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.flock
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.chown
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.metadata[1]
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.sync
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.result
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.unlock
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
    }
}

pub(super) struct EmptyFloorNamesOriginal {
    before: [NameSample; 3],
    before_result: Option<Result<(), JournalError>>,
    files: [EmptyFileOriginal; 2],
    directory_sync: Option<Result<(), rustix::io::Errno>>,
    prepare: Option<Result<(), JournalError>>,
    after: [NameSample; 3],
    post: Option<Result<(), JournalError>>,
    uid: Option<u32>,
    closed: Option<JournalError>,
}

impl EmptyFloorNamesOriginal {
    pub(super) fn new() -> Self {
        Self {
            before: std::array::from_fn(|_| NameSample::new()),
            before_result: None,
            files: std::array::from_fn(|_| EmptyFileOriginal::new()),
            directory_sync: None,
            prepare: None,
            after: std::array::from_fn(|_| NameSample::new()),
            post: None,
            uid: None,
            closed: None,
        }
    }

    pub(super) fn receiving_demand() -> Result<ResourceVector, AccountingError> {
        // Six no-follow samples and two writable originals can all remain
        // resident. Fixed names bound native argument conversion overlap.
        let bytes = 2 * std::mem::size_of::<Self>() + 4096;
        let bytes = u64::try_from(bytes).map_err(|_| AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        })?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, 8)
            .with(D::MetadataEntries, 10))
    }

    pub(super) fn prepare_once(&mut self, main: &Journal, uid: u32) -> Result<(), JournalError> {
        if self.prepare.is_some() || self.uid.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.uid = Some(uid);
        for (index, sample) in self.before.iter_mut().enumerate() {
            sample.capture(main, index, uid, true);
        }
        self.before_result = Some(
            if self
                .before
                .iter()
                .all(|sample| matches!(sample.result, Some(Ok(()))))
            {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            },
        );
        self.prepare = Some((|| {
            if !matches!(self.before_result, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary);
            }
            // Observe the complete roster before the first create or chown.
            // An unsafe existing peer must not cause another name to appear.
            for index in [1, 0] {
                let file = &mut self.files[index];
                file.prepare(main, &self.before[index], index, uid);
                if file.failure().is_some() || !matches!(file.result, Some(Ok(()))) {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            Ok(())
        })());
        self.directory_sync = Some(main.native.native_operations().sync_directory());
        let _after = self.finish_after_owed(main);
        if self.ready() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn ready(&self) -> bool {
        self.failure().is_none()
            && matches!(self.prepare, Some(Ok(())))
            && matches!(self.directory_sync, Some(Ok(())))
            && matches!(self.post, Some(Ok(())))
    }

    pub(super) fn finish_after_owed(&mut self, main: &Journal) -> Result<(), JournalError> {
        let Some(uid) = self.uid else {
            return Ok(());
        };
        if self.post.is_none() {
            for (index, sample) in self.after.iter_mut().enumerate() {
                sample.capture(main, index, uid, false);
            }
            self.post = Some((|| {
                if !matches!(self.prepare, Some(Ok(()))) {
                    return Err(JournalError::ProtectedBoundary);
                }
                if self
                    .after
                    .iter()
                    .any(|sample| !matches!(sample.result, Some(Ok(()))))
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                for index in 0..2 {
                    if self.files[index].identity().is_none()
                        || self.files[index].identity() != self.after[index].identity()
                    {
                        return Err(JournalError::StaleAuthoritySnapshot);
                    }
                }
                Ok(())
            })());
        }
        if matches!(self.post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before
            .iter()
            .find_map(NameSample::failure)
            .or_else(|| {
                self.before_result
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.files.iter().find_map(EmptyFileOriginal::failure))
            .or_else(|| {
                self.prepare
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.directory_sync
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.after.iter().find_map(NameSample::failure))
            .or_else(|| {
                self.post
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}
