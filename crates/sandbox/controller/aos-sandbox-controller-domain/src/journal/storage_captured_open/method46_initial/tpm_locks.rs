//! Retains the actual initial writer pair's duplicated lock descriptions.
//!
//! The Source pays both name/metadata intervals and both duplicates before
//! entry. Partial duplication and failed native samples stay resident. This
//! reservoir supplies lock custody only; it authenticates no helper or TPM.

use std::fs::{File, Metadata};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_journal::protected_storage::FileIdentity;
use rustix::fs::{OFlags, fcntl_getfl};

use super::*;

struct LockSample {
    metadata: Option<std::io::Result<Metadata>>,
    flags: Option<rustix::io::Result<OFlags>>,
    result: Option<Result<(), JournalError>>,
}

impl LockSample {
    fn new() -> Self {
        Self {
            metadata: None,
            flags: None,
            result: None,
        }
    }

    fn capture(&mut self, file: &File, expected: FileIdentity) {
        self.metadata = Some(file.metadata());
        self.flags = Some(fcntl_getfl(file));
        self.result = Some((|| {
            let metadata = self
                .metadata
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let flags = self
                .flags
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            if !metadata.is_file()
                || metadata.len() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600
                || *flags & OFlags::ACCMODE != OFlags::RDWR
                || FileIdentity::from_metadata_data_v1(metadata) != expected
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.metadata)
            .or_else(|| error(&self.flags))
            .or_else(|| error(&self.result))
    }
}

struct LockOriginal {
    file: Option<File>,
    duplicate: Option<std::io::Result<()>>,
    samples: [LockSample; 2],
}

impl LockOriginal {
    fn new() -> Self {
        Self {
            file: None,
            duplicate: None,
            samples: std::array::from_fn(|_| LockSample::new()),
        }
    }

    fn capture(&mut self, journal: &Journal, expected: FileIdentity) -> Result<(), JournalError> {
        // The lower operation stages any returned descriptor directly into
        // this owner, including a failed prefix. No temporary loan is dropped.
        self.duplicate = Some(
            journal
                .native
                .native_operations()
                .copy_confined_lock_description_into(&mut self.file),
        );
        if !matches!(self.duplicate, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.sample(0, expected)
    }

    fn sample(&mut self, index: usize, expected: FileIdentity) -> Result<(), JournalError> {
        let file = self.file.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.samples[index].capture(file, expected);
        if matches!(self.samples[index].result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.duplicate).or_else(|| self.samples[0].failure())
    }

    fn after_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.samples[1].failure()
    }
}

pub(super) struct InitialTpmLocksOriginal {
    quote: Option<Result<ResourceVector, JournalError>>,
    intervals: [approval_currentness::ApprovalCurrentnessOriginalV1; 2],
    locks: [LockOriginal; 2],
    expected: [Option<FileIdentity>; 2],
    before: [Option<Result<(), JournalError>>; 2],
    capture: Option<Result<(), JournalError>>,
    after: [Option<Result<(), JournalError>>; 2],
    post: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
}

impl InitialTpmLocksOriginal {
    pub(super) fn new() -> Self {
        Self {
            quote: None,
            intervals: std::array::from_fn(|_| {
                approval_currentness::ApprovalCurrentnessOriginalV1::new()
            }),
            locks: std::array::from_fn(|_| LockOriginal::new()),
            expected: [None, None],
            before: [None, None],
            capture: None,
            after: [None, None],
            post: None,
            closed: None,
        }
    }

    pub(super) fn quote_once(
        &mut self,
        journals: [&Journal; 2],
        replayed: [FileIdentity; 2],
    ) -> Option<ResourceVector> {
        if self.quote.is_some() || self.capture.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.quote = Some((|| {
            let first = self.intervals[0]
                .quote_once(journals[0], replayed[0])
                .ok_or(JournalError::ProtectedBoundary)?;
            let second = self.intervals[1]
                .quote_once(journals[1], replayed[1])
                .ok_or(JournalError::ProtectedBoundary)?;
            let memory = 2usize
                .checked_mul(std::mem::size_of::<Self>())
                .and_then(|bytes| bytes.checked_add(4096))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            first
                .checked_add(second)
                .and_then(|sum| {
                    sum.checked_add(
                        ResourceVector::ZERO
                            .with(D::MemoryBytes, memory)
                            .with(D::OpenFiles, 2)
                            .with(D::MetadataEntries, 4),
                    )
                })
                .map_err(|_| JournalError::ProtectedBoundary)
        })());
        self.quote.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn capture_once(&mut self, journals: [&Journal; 2]) -> Result<(), JournalError> {
        if self.capture.is_some() || self.closed.is_some() || !matches!(self.quote, Some(Ok(_))) {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        // The second writer's paid native sample stays owed after refusal of
        // the first. Duplication starts only after both actual before cuts.
        for (index, journal) in journals.iter().enumerate() {
            self.before[index] = Some(self.intervals[index].before_once(journal));
            self.expected[index] = self.intervals[index].lock_identity_data();
        }
        self.capture = Some((|| {
            if self
                .before
                .iter()
                .any(|result| !matches!(result, Some(Ok(()))))
            {
                return Err(JournalError::ProtectedBoundary);
            }
            for (index, journal) in journals.iter().enumerate() {
                self.locks[index].capture(
                    journal,
                    self.expected[index].ok_or(JournalError::ProtectedBoundary)?,
                )?;
            }
            let identities = self
                .identities_data()
                .ok_or(JournalError::ProtectedBoundary)?;
            if identities[0].0 == identities[1].0 && identities[0].1 == identities[1].1
                || identities[0].2 != identities[1].2
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if self.ready() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn identities_data(&self) -> Option<[(u64, u64, u32); 2]> {
        let identity = |index: usize| {
            let metadata = self.locks[index].samples[0]
                .metadata
                .as_ref()?
                .as_ref()
                .ok()?;
            Some((metadata.dev(), metadata.ino(), metadata.uid()))
        };
        Some([identity(0)?, identity(1)?])
    }

    pub(crate) fn ready(&self) -> bool {
        self.failure().is_none() && matches!(self.capture, Some(Ok(()))) && self.post.is_none()
    }

    pub(crate) fn borrowed_descriptors(&self) -> Option<[BorrowedFd<'_>; 2]> {
        if !self.ready() {
            return None;
        }
        Some([
            self.locks[0].file.as_ref()?.as_fd(),
            self.locks[1].file.as_ref()?.as_fd(),
        ])
    }

    pub(crate) fn captured_identities_data(&self) -> Option<[(u64, u64, u32); 2]> {
        self.ready().then(|| self.identities_data()).flatten()
    }

    pub(super) fn finish_after_owed(
        &mut self,
        journals: [&Journal; 2],
    ) -> Result<(), JournalError> {
        if self.capture.is_none() {
            return Ok(());
        }
        if self.post.is_none() {
            for (index, journal) in journals.iter().enumerate() {
                if self.locks[index].file.is_some() {
                    if let Some(expected) = self.expected[index] {
                        let _sample = self.locks[index].sample(1, expected);
                    }
                }
                self.after[index] = Some(self.intervals[index].finish_after_owed(journal));
            }
            self.post = Some(
                if self.failure().is_none()
                    && self
                        .after
                        .iter()
                        .all(|result| matches!(result, Some(Ok(()))))
                {
                    Ok(())
                } else {
                    Err(JournalError::ProtectedBoundary)
                },
            );
        }
        if matches!(self.post, Some(Ok(()))) && self.closed.is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.quote)
            .or_else(|| {
                self.intervals
                    .iter()
                    .find_map(|interval| interval.before_failure())
            })
            .or_else(|| self.locks.iter().find_map(LockOriginal::before_failure))
            .or_else(|| error(&self.capture))
            .or_else(|| self.locks[0].after_failure())
            .or_else(|| self.intervals[0].after_failure())
            .or_else(|| self.locks[1].after_failure())
            .or_else(|| self.intervals[1].after_failure())
            .or_else(|| {
                self.intervals
                    .iter()
                    .find_map(|interval| interval.order_failure())
            })
            .or_else(|| error(&self.post))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|error| error as _)
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn quote_initial_tpm_locks_once(&mut self) -> Option<ResourceVector> {
        if self.failure().is_some()
            || !self.initial_intent.durable_ready()
            || !self.initial_floor.ready()
            || self.post.is_some()
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        let main = self.inner.original.journal_data_v1()?;
        let main_replayed = self
            .inner
            .original
            .captured_replay_file_identity_data_v1()?;
        let (floor, floor_replayed) = self.initial_floor.journal_and_replayed_data()?;
        self.tpm_locks
            .quote_once([main, floor], [main_replayed, floor_replayed])
    }

    pub(crate) fn capture_initial_tpm_locks_once(&mut self) -> Result<(), JournalError> {
        let main = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (floor, _) = self
            .initial_floor
            .journal_and_replayed_data()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.tpm_locks.capture_once([main, floor])
    }

    pub(crate) fn initial_tpm_lock_descriptors(&self) -> Option<[BorrowedFd<'_>; 2]> {
        self.tpm_locks.borrowed_descriptors()
    }

    pub(crate) fn initial_tpm_lock_identities_data(&self) -> Option<[(u64, u64, u32); 2]> {
        self.tpm_locks.captured_identities_data()
    }

    pub(crate) fn finish_initial_tpm_locks_after_owed(&mut self) -> Result<(), JournalError> {
        let Some(main) = self.inner.original.journal_data_v1() else {
            return Ok(());
        };
        let Some((floor, _)) = self.initial_floor.journal_and_replayed_data() else {
            return Ok(());
        };
        self.tpm_locks.finish_after_owed([main, floor])
    }
}

#[cfg(test)]
mod tests;
