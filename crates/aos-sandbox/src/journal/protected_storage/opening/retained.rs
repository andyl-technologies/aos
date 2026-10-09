//! Complete partial-opening custody and first-failure recovery reservoirs.
//!
//! Every original ancestor, directory, lock, data file, replay/tail result,
//! failure scratch, returned journal/readback, and independent name bookend
//! remains in its original field and observation order. Reentry neither retries
//! a native operation nor replaces debt. The outer role still owns admission,
//! pricing, protected currentness, and semantic authority.
//!
//! Retained replay scratch is filled by the domain replay owner. Parking it
//! here does not bound transitive allocations or certify a paid receiving cut.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_sandbox_journal::recovery::{RecoveryTailMode, TailResultSlots, finish_replayed_tail};
use rustix::fs::{FileType, FlockOperation, Mode, flock, fstat, fsync};

#[cfg(target_os = "linux")]
use super::super::super::runtime_deployment_history;
use super::super::super::{
    JournalAuthorityInstance, ReadOnlyReplayScratchV1, RecoveryReport, ReplayState, replay,
    replay_read_only_retained, validate_limits,
};
use super::super::{
    FileIdentity, Journal, JournalError, JournalLimits, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES,
    ProtectedJournalLocation, ReadOnlyJournalNameWitness, ReadOnlyProtectedJournal,
    open_protected_file_into_original, open_read_only_protected_file_original,
    remove_stale_protected_compaction, require_opened_directory_identity,
    require_protected_file_names_current, resolve_protected_directory_from_root,
    resolve_protected_directory_from_root_original, rustix_io, validate_basename,
    validate_protected_fd,
};

/// Retains a read-only opening and its partial native replay originals.
///
/// This crate-private reservoir supplies custody, not admission or funding.
/// The caller must already own the receiving interval and price its reached
/// allocations before entry. In particular, an allocator abort cannot return
/// an error or establish that independent posts completed.
pub(crate) struct ReadOnlyJournalOpenOriginalsV1 {
    pub(in crate::journal) ancestors: Vec<File>,
    pub(in crate::journal) directory: Option<Result<File, JournalError>>,
    pub(in crate::journal) directory_native_error: Option<rustix::io::Errno>,
    pub(in crate::journal) directory_binding: Option<Result<(), JournalError>>,
    pub(in crate::journal) directory_identity: Option<Result<FileIdentity, JournalError>>,
    pub(in crate::journal) lock: Option<Result<File, rustix::io::Errno>>,
    pub(in crate::journal) lock_validation: Option<Result<(), JournalError>>,
    pub(in crate::journal) lock_identity: Option<Result<FileIdentity, JournalError>>,
    pub(in crate::journal) file: Option<Result<File, rustix::io::Errno>>,
    pub(in crate::journal) file_validation: Option<Result<(), JournalError>>,
    pub(in crate::journal) file_identity: Option<Result<FileIdentity, JournalError>>,
    pub(in crate::journal) protected: Option<ProtectedJournalLocation>,
    pub(in crate::journal) replay: ControllerOpenedReplayV1,
    pub(in crate::journal) scratch: Option<ReadOnlyReplayScratchV1>,
    pub(in crate::journal) returned: Option<Result<RecoveryReport, JournalError>>,
    pub(in crate::journal) readback: Option<ReadOnlyProtectedJournal>,
    pub(in crate::journal) witness: Option<ReadOnlyJournalNameWitness>,
    pub(in crate::journal) initial_name: Option<Result<(), JournalError>>,
    pub(in crate::journal) post_name: Option<Result<(), JournalError>>,
    pub(in crate::journal) attempted: bool,
    pub(in crate::journal) post_attempted: bool,
    pub(in crate::journal) closed: bool,
}

impl ReadOnlyJournalOpenOriginalsV1 {
    /// Prearms empty custody without opening a file or creating authority.
    pub(crate) const fn new() -> Self {
        Self {
            ancestors: Vec::new(),
            directory: None,
            directory_native_error: None,
            directory_binding: None,
            directory_identity: None,
            lock: None,
            lock_validation: None,
            lock_identity: None,
            file: None,
            file_validation: None,
            file_identity: None,
            protected: None,
            replay: ControllerOpenedReplayV1::new(),
            scratch: None,
            returned: None,
            readback: None,
            witness: None,
            initial_name: None,
            post_name: None,
            attempted: false,
            post_attempted: false,
            closed: false,
        }
    }

    /// Enters one retained, bound read-only opening without retry or repair.
    ///
    /// The outer owner parks this reservoir before calling it. Every native
    /// result precedes its projection; a later name failure retains the reader
    /// and report. Reentry closes positive borrowing without replacing debt.
    pub(crate) fn open_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        directory_identity: (u64, u64),
    ) {
        if self.attempted || self.closed {
            self.closed = true;
            return;
        }
        self.attempted = true;
        self.returned = Some(self.open_inner(path, name, limits, uid, directory_identity));
        self.initial_name = self.observe_names();
    }

    pub(in crate::journal) fn open_inner(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: (u64, u64),
    ) -> Result<RecoveryReport, JournalError> {
        self.directory = Some(resolve_protected_directory_from_root_original(
            path,
            uid,
            Some(&mut self.ancestors),
            Some(&mut self.directory_native_error),
        ));
        let directory = self
            .directory
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.directory_binding = Some(require_opened_directory_identity(
            directory,
            expected_directory,
        ));
        require_controller_open_step(&self.directory_binding)?;
        validate_limits(limits)?;
        if name.len() > MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES {
            return Err(JournalError::ProtectedBoundary);
        }
        validate_basename(name)?;
        self.directory_identity = Some(FileIdentity::of(directory));
        let directory_identity = self
            .directory_identity
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.lock_validation = Some(open_read_only_protected_file_original(
            directory,
            &format!("{name}.lock"),
            uid,
            &mut self.lock,
        ));
        require_controller_open_step(&self.lock_validation)?;
        let lock = self
            .lock
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.lock_identity = Some(FileIdentity::of(lock));
        let lock_identity = self
            .lock_identity
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.file_validation = Some(open_read_only_protected_file_original(
            directory,
            name,
            uid,
            &mut self.file,
        ));
        require_controller_open_step(&self.file_validation)?;
        let file = self
            .file
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.file_identity = Some(FileIdentity::of(file));
        let file_identity = self
            .file_identity
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.protected = Some(ProtectedJournalLocation {
            directory: match self.directory.take() {
                Some(Ok(directory)) => directory,
                original => {
                    self.directory = original;
                    return Err(JournalError::ProtectedBoundary);
                }
            },
            name: name.to_owned(),
            expected_uid: uid,
            #[cfg(target_os = "linux")]
            original_compaction_selection:
                runtime_deployment_history::OriginalCompactionSelectionV1::capture(path, name),
        });
        self.witness = Some(ReadOnlyJournalNameWitness {
            directory_path: path.to_owned(),
            name: name.to_owned(),
            expected_uid: uid,
            directory_identity,
            file_identity,
            lock_identity,
        });
        let (_, report) = prepare_opened_replay(
            file,
            limits,
            false,
            OpenedReplayDestinationV1::Retained(&mut self.replay, &mut self.scratch),
        )?;

        let opened_path = PathBuf::from(name);
        let authority = Arc::new(JournalAuthorityInstance);
        let originals = (
            self.file.take(),
            self.lock.take(),
            self.protected.take(),
            self.replay.replay.take(),
            self.witness.take(),
        );
        let (file, lock, protected, replay, witness) = match originals {
            (Some(Ok(file)), Some(Ok(lock)), Some(protected), Some(Ok(replay)), Some(witness)) => {
                (file, lock, protected, replay, witness)
            }
            (file, lock, protected, replay, witness) => {
                self.file = file;
                self.lock = lock;
                self.protected = protected;
                self.replay.replay = replay;
                self.witness = witness;
                return Err(JournalError::ProtectedBoundary);
            }
        };
        let journal = journal_from_original_replay!(
            opened_path,
            file,
            lock,
            limits,
            Some(protected),
            replay,
            authority
        );
        self.readback = Some(ReadOnlyProtectedJournal { journal, witness });
        Ok(report)
    }

    /// Parks one independent name post on the same reader, including after Err.
    pub(crate) fn recheck_named_once(&mut self) {
        if self.post_attempted || !self.attempted {
            self.closed = true;
            return;
        }
        self.post_attempted = true;
        self.post_name = self.observe_names();
    }

    pub(in crate::journal) fn observe_names(&self) -> Option<Result<(), JournalError>> {
        if let Some(readback) = &self.readback {
            return Some(readback.check_named_currentness());
        }
        let witness = self.witness.as_ref()?;
        let file = self.file.as_ref()?.as_ref().ok()?;
        Some((|| {
            witness.check_named_currentness()?;
            if FileIdentity::of(file)? != witness.file_identity {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })())
    }

    /// Borrows the earliest retained opening or name-check cause.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            };
        }
        self.directory_native_error
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| cause!(self.directory))
            .or_else(|| cause!(self.directory_binding))
            .or_else(|| cause!(self.directory_identity))
            .or_else(|| cause!(self.lock))
            .or_else(|| cause!(self.lock_validation))
            .or_else(|| cause!(self.lock_identity))
            .or_else(|| cause!(self.file))
            .or_else(|| cause!(self.file_validation))
            .or_else(|| cause!(self.file_identity))
            .or_else(|| self.replay.failure())
            .or_else(|| cause!(self.returned))
            .or_else(|| cause!(self.initial_name))
            .or_else(|| cause!(self.post_name))
            .or_else(|| {
                self.closed
                    .then_some(&READ_ONLY_OPEN_CLOSED as &(dyn std::error::Error + 'static))
            })
    }

    /// Borrows only a successfully returned and still-open diagnostic reader.
    pub(crate) fn readback_mut(&mut self) -> Option<&mut ReadOnlyProtectedJournal> {
        if self.closed
            || self.failure().is_some()
            || !matches!(self.returned, Some(Ok(_)))
            || !matches!(self.initial_name, Some(Ok(())))
        {
            return None;
        }
        self.readback.as_mut()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("read-only original opening is closed")]
pub(in crate::journal) struct ReadOnlyOpenClosedV1;

static READ_ONLY_OPEN_CLOSED: ReadOnlyOpenClosedV1 = ReadOnlyOpenClosedV1;

// A closed Controller constructor keeps partial originals in its parent.
// This is not a Journal/FD factory and does not issue authority or a payer.
pub(crate) struct ControllerJournalOpenOriginalsV1 {
    pub(in crate::journal) ancestors: Vec<File>,
    pub(in crate::journal) directory: Option<File>,
    pub(in crate::journal) lock: Option<File>,
    pub(in crate::journal) file: Option<File>,
    pub(in crate::journal) protected: Option<ProtectedJournalLocation>,
    pub(in crate::journal) lock_open: Option<Result<(), JournalError>>,
    pub(in crate::journal) lock_claim: Option<Result<(), JournalError>>,
    pub(in crate::journal) compaction: Option<Result<(), JournalError>>,
    pub(in crate::journal) file_open: Option<Result<(), JournalError>>,
    pub(in crate::journal) directory_sync: Option<Result<(), JournalError>>,
    pub(in crate::journal) replay: ControllerOpenedReplayV1,
    pub(in crate::journal) returned: Option<Result<RecoveryReport, JournalError>>,
    pub(in crate::journal) journal: Option<Journal>,
    pub(in crate::journal) attempted: bool,
}

/// Retains the same writable opening with Journal-owned replay failure partials.
///
/// This is custody only. Transitive validator allocations remain outside this
/// reservoir, and neither its presence nor its disposal proves paid receiving.
pub(crate) struct ProtectedWriterOpenOriginalsV1 {
    pub(in crate::journal) opening: ControllerJournalOpenOriginalsV1,
    pub(in crate::journal) retention: WritableOpenRetentionV1,
}

impl ProtectedWriterOpenOriginalsV1 {
    pub(crate) const fn new() -> Self {
        Self {
            opening: ControllerJournalOpenOriginalsV1::new(),
            retention: WritableOpenRetentionV1 {
                directory_error: None,
                directory_native_error: None,
                lock_native_error: None,
                lock_claim_native_error: None,
                file_native_error: None,
                scratch: None,
            },
        }
    }

    pub(crate) fn open_once(&mut self, path: &Path, name: &str, limits: JournalLimits) {
        if self.opening.attempted {
            return;
        }
        self.opening.attempted = true;
        self.opening.returned =
            Some(
                self.opening
                    .open_inner(path, name, limits, 0, Some(&mut self.retention)),
            );
    }

    pub(crate) fn journal_mut(&mut self) -> Option<&mut Journal> {
        self.opening.journal_mut()
    }

    /// Observes names even when replay failed before Journal materialization.
    pub(crate) fn check_named_currentness(
        &self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        if let Some(journal) = &self.opening.journal {
            // Name observation is independent of health, so an ambiguous
            // append still gets its bookend before the health refusal.
            journal.require_protected_names_current()?;
            return journal.require_protected_location(path, name, 0, limits);
        }

        let directory = self
            .opening
            .protected
            .as_ref()
            .map(|protected| &protected.directory)
            .or(self.opening.directory.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?;
        let current = resolve_protected_directory_from_root(path, 0)?;
        let held = fstat(directory).map_err(rustix_io)?;
        let named = fstat(&current).map_err(rustix_io)?;
        if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
            return Err(JournalError::ProtectedBoundary);
        }

        let lock = self
            .opening
            .lock
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let file = self
            .opening
            .file
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        require_protected_file_names_current(directory, name, 0, lock, file)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.retention
            .directory_error
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.opening.failure())
            .or_else(|| {
                self.retention
                    .directory_native_error
                    .as_ref()
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.retention
                    .lock_native_error
                    .as_ref()
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.retention
                    .lock_claim_native_error
                    .as_ref()
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.retention
                    .file_native_error
                    .as_ref()
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
    }
}

pub(in crate::journal) struct WritableOpenRetentionV1 {
    pub(in crate::journal) directory_error: Option<JournalError>,
    pub(in crate::journal) directory_native_error: Option<rustix::io::Errno>,
    pub(in crate::journal) lock_native_error: Option<rustix::io::Errno>,
    pub(in crate::journal) lock_claim_native_error: Option<rustix::io::Errno>,
    pub(in crate::journal) file_native_error: Option<rustix::io::Errno>,
    pub(in crate::journal) scratch: Option<ReadOnlyReplayScratchV1>,
}

impl ControllerJournalOpenOriginalsV1 {
    pub(crate) const fn new() -> Self {
        Self {
            ancestors: Vec::new(),
            directory: None,
            lock: None,
            file: None,
            protected: None,
            lock_open: None,
            lock_claim: None,
            compaction: None,
            file_open: None,
            directory_sync: None,
            replay: ControllerOpenedReplayV1::new(),
            returned: None,
            journal: None,
            attempted: false,
        }
    }

    pub(crate) fn open_once(&mut self, path: &Path, name: &str, limits: JournalLimits, uid: u32) {
        if self.attempted {
            return;
        }
        self.attempted = true;
        self.returned = Some(self.open_inner(path, name, limits, uid, None));
    }

    pub(in crate::journal) fn open_inner(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        mut retention: Option<&mut WritableOpenRetentionV1>,
    ) -> Result<RecoveryReport, JournalError> {
        let directory = resolve_protected_directory_from_root_original(
            path,
            uid,
            Some(&mut self.ancestors),
            retention
                .as_mut()
                .map(|originals| &mut originals.directory_native_error),
        );
        self.directory = Some(match directory {
            Ok(directory) => directory,
            Err(error) => {
                if let Some(originals) = retention.as_mut() {
                    originals.directory_error = Some(error);
                    return Err(JournalError::ProtectedBoundary);
                }
                return Err(error);
            }
        });
        validate_limits(limits)?;
        if name.len() > MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES {
            return Err(JournalError::ProtectedBoundary);
        }
        validate_basename(name)?;
        let directory = self
            .directory
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        validate_protected_fd(directory, uid, FileType::Directory, Mode::RWXU)?;
        let lock_name = format!("{name}.lock");
        self.lock_open = Some(open_protected_file_into_original(
            directory,
            &lock_name,
            uid,
            true,
            false,
            false,
            &mut self.lock,
            retention
                .as_mut()
                .map(|originals| &mut originals.lock_native_error),
        ));
        require_controller_open_step(&self.lock_open)?;
        let lock = self.lock.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.lock_claim = Some(
            flock(lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
                if let Some(originals) = retention.as_mut() {
                    originals.lock_claim_native_error = Some(error);
                }
                if error == rustix::io::Errno::WOULDBLOCK {
                    JournalError::AlreadyLocked
                } else {
                    rustix_io(error)
                }
            }),
        );
        require_controller_open_step(&self.lock_claim)?;
        self.compaction = Some(remove_stale_protected_compaction(directory, name));
        require_controller_open_step(&self.compaction)?;
        self.file_open = Some(open_protected_file_into_original(
            directory,
            name,
            uid,
            true,
            false,
            false,
            &mut self.file,
            retention
                .as_mut()
                .map(|originals| &mut originals.file_native_error),
        ));
        require_controller_open_step(&self.file_open)?;
        self.directory_sync = Some(fsync(directory).map_err(rustix_io));
        require_controller_open_step(&self.directory_sync)?;

        let protected_name = name.to_owned();
        #[cfg(target_os = "linux")]
        let selection =
            runtime_deployment_history::OriginalCompactionSelectionV1::capture(path, name);
        self.protected = Some(ProtectedJournalLocation {
            directory: self
                .directory
                .take()
                .ok_or(JournalError::ProtectedBoundary)?,
            name: protected_name,
            expected_uid: uid,
            #[cfg(target_os = "linux")]
            original_compaction_selection: selection,
        });
        let file = self.file.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let destination = match retention {
            Some(originals) => {
                OpenedReplayDestinationV1::Retained(&mut self.replay, &mut originals.scratch)
            }
            None => OpenedReplayDestinationV1::Controller(&mut self.replay),
        };
        let (_, report) = prepare_opened_replay(file, limits, true, destination)?;

        // Every fallible native/replay operation precedes these infallible
        // moves. Partial files/replay remain parked on every earlier Err.
        let opened_path = PathBuf::from(name);
        let authority = Arc::new(JournalAuthorityInstance);
        let originals = (
            self.file.take(),
            self.lock.take(),
            self.protected.take(),
            self.replay.replay.take(),
        );
        let (file, lock, protected, replay) = match originals {
            (Some(file), Some(lock), Some(protected), Some(Ok(replay))) => {
                (file, lock, protected, replay)
            }
            (file, lock, protected, replay) => {
                self.file = file;
                self.lock = lock;
                self.protected = protected;
                self.replay.replay = replay;
                return Err(JournalError::ProtectedBoundary);
            }
        };
        self.journal = Some(journal_from_original_replay!(
            opened_path,
            file,
            lock,
            limits,
            Some(protected),
            replay,
            authority
        ));
        Ok(report)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.lock_open
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.lock_claim
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.compaction
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.file_open
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.directory_sync
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| self.replay.failure())
            .or_else(|| {
                self.returned
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
    }

    pub(crate) fn journal_mut(&mut self) -> Option<&mut Journal> {
        if !matches!(self.returned, Some(Ok(_))) {
            return None;
        }
        self.journal.as_mut()
    }

    pub(crate) fn take_journal(&mut self) -> Option<Journal> {
        if !matches!(self.returned, Some(Ok(_))) {
            return None;
        }
        self.journal.take()
    }
}

pub(in crate::journal) fn require_controller_open_step(
    result: &Option<Result<(), JournalError>>,
) -> Result<(), JournalError> {
    if matches!(result, Some(Ok(()))) {
        Ok(())
    } else {
        // The genuine Err stays in its exact native stage, not this facade.
        Err(JournalError::ProtectedBoundary)
    }
}

pub(in crate::journal) struct ControllerOpenedReplayV1 {
    pub(in crate::journal) metadata: Option<Result<fs::Metadata, io::Error>>,
    pub(in crate::journal) replay: Option<Result<ReplayState, JournalError>>,
    pub(in crate::journal) truncate: Option<Result<(), io::Error>>,
    pub(in crate::journal) sync: Option<Result<(), io::Error>>,
    pub(in crate::journal) seek: Option<Result<u64, io::Error>>,
}

impl ControllerOpenedReplayV1 {
    pub(in crate::journal) const fn new() -> Self {
        Self {
            metadata: None,
            replay: None,
            truncate: None,
            sync: None,
            seek: None,
        }
    }

    pub(in crate::journal) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.metadata
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.replay
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.truncate
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.sync
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.seek
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
    }
}

pub(in crate::journal) enum OpenedReplayDestinationV1<'owner> {
    Ordinary,
    Controller(&'owner mut ControllerOpenedReplayV1),
    Retained(
        &'owner mut ControllerOpenedReplayV1,
        &'owner mut Option<ReadOnlyReplayScratchV1>,
    ),
}

// One replay/repair recipe. Selected destinations park native results, and
// Retained additionally keeps Journal-owned failure partials. Ordinary recovery
// uses the former local expressions and disposal order.
pub(in crate::journal) fn prepare_opened_replay(
    file: &mut File,
    limits: JournalLimits,
    repair_tail: bool,
    destination: OpenedReplayDestinationV1<'_>,
) -> Result<(Option<ReplayState>, RecoveryReport), JournalError> {
    let (metadata_slot, replay_slot, tail_slots, scratch_slot) = match destination {
        OpenedReplayDestinationV1::Ordinary => (None, None, None, None),
        OpenedReplayDestinationV1::Controller(originals) => (
            Some(&mut originals.metadata),
            Some(&mut originals.replay),
            Some(TailResultSlots::new(
                &mut originals.truncate,
                &mut originals.sync,
                &mut originals.seek,
            )),
            None,
        ),
        OpenedReplayDestinationV1::Retained(originals, scratch) => (
            Some(&mut originals.metadata),
            Some(&mut originals.replay),
            Some(TailResultSlots::new(
                &mut originals.truncate,
                &mut originals.sync,
                &mut originals.seek,
            )),
            Some(scratch),
        ),
    };
    let length = match metadata_slot {
        None => file.metadata()?.len(),
        Some(slot) => {
            *slot = Some(file.metadata());
            match slot.as_ref() {
                Some(Ok(metadata)) => metadata.len(),
                _ => return Err(JournalError::ProtectedBoundary),
            }
        }
    };
    if length > limits.maximum_journal_bytes {
        return Err(JournalError::JournalTooLarge);
    }
    let mut ordinary_replay = None;
    let replay = match replay_slot {
        None => {
            ordinary_replay = Some(replay(file, limits)?);
            ordinary_replay
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
        }
        Some(slot) => {
            *slot = Some(match scratch_slot {
                None => replay(file, limits),
                Some(scratch) => replay_read_only_retained(file, limits, scratch),
            });
            match slot.as_ref() {
                Some(Ok(replay)) => replay,
                _ => return Err(JournalError::ProtectedBoundary),
            }
        }
    };
    let truncated_bytes = finish_replayed_tail(
        file,
        length,
        replay.durable_end,
        if repair_tail {
            RecoveryTailMode::RepairIncomplete
        } else {
            RecoveryTailMode::RejectIncomplete
        },
        tail_slots,
    )?;
    let report = RecoveryReport {
        committed_transactions: replay.committed_transactions,
        committed_records: replay.committed_records,
        truncated_bytes,
    };
    Ok((ordinary_replay, report))
}
