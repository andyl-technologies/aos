//! Publishes the separate initial intent through the same held main directory.
//!
//! This mechanical owner retains native failures and all owed name observations.
//! Its Source-funded loan supplies neither signature admission nor TPM rights.
//! Security supplies bytes only from its resident same-Source verified approval.

use std::fs::{File, Metadata};
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1;

use super::*;

mod label;
use label::{IntentContext, IntentLabelOriginal, LABEL_BYTES};

pub(crate) const INTENT_BYTES: usize = 398;
const FINAL: &str = "session-floor.initial-intent";
const STAGE: &str = "session-floor.initial-intent.pending";
const NAMES: [&str; 3] = [FINAL, STAGE, SIDECAR_NAME_V1];

struct NameOriginal {
    open: Option<Result<File, rustix::io::Errno>>,
    metadata: [Option<io::Result<Metadata>>; 2],
    read: FixedRoleCredentialReadV1,
    bytes: Option<Vec<u8>>,
    result: Option<Result<(), JournalError>>,
    label: IntentLabelOriginal,
}

impl NameOriginal {
    fn new() -> Self {
        Self {
            open: None,
            metadata: [None, None],
            read: FixedRoleCredentialReadV1::prearmed(),
            bytes: None,
            result: None,
            label: IntentLabelOriginal::new(),
        }
    }

    fn capture(
        &mut self,
        journal: &Journal,
        index: usize,
        intent_uid: u32,
        context: IntentContext,
    ) {
        self.open = Some(
            journal
                .native
                .native_operations()
                .open_named_child(NAMES[index])
                .map(File::from),
        );
        self.result = Some((|| {
            if matches!(self.open, Some(Err(rustix::io::Errno::NOENT))) {
                return Ok(());
            }
            let file = self
                .open
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            if index != 2 {
                // Retain this original label even if metadata comparison fails.
                self.label.observe(file);
            }
            self.metadata[0] = Some(file.metadata());
            let metadata = self.metadata[0]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let uid = if index == 2 {
                journal
                    .native
                    .protected_uid()
                    .ok_or(JournalError::ProtectedBoundary)?
            } else {
                intent_uid
            };
            let maximum = if index == 2 { 0 } else { INTENT_BYTES as u64 };
            require_file(metadata, uid, maximum)?;
            if index != 2 && !self.label.require(context) {
                return Err(JournalError::ProtectedBoundary);
            }
            let length =
                usize::try_from(metadata.len()).map_err(|_| JournalError::ProtectedBoundary)?;
            if index == 0 && length != INTENT_BYTES {
                return Err(JournalError::ProtectedBoundary);
            }
            if index != 2 {
                let file = self
                    .open
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                self.read.read_exact_at_once(file.as_fd(), length);
                self.bytes = self.read.take_success_bytes_once();
                if self.bytes.is_none() {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            self.metadata[1] = Some(
                self.file()
                    .ok_or(JournalError::ProtectedBoundary)?
                    .metadata(),
            );
            if self.identity(0) != self.identity(1) || self.identity(0).is_none() {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
    }

    fn file(&self) -> Option<&File> {
        self.open.as_ref()?.as_ref().ok()
    }

    fn identity(&self, index: usize) -> Option<FileIdentity> {
        self.metadata[index]
            .as_ref()?
            .as_ref()
            .ok()
            .map(FileIdentity::from_metadata_data_v1)
    }

    fn absent(&self) -> bool {
        matches!(self.open, Some(Err(rustix::io::Errno::NOENT)))
            && matches!(self.result, Some(Ok(())))
    }

    fn same(&self, other: &Self) -> bool {
        (self.absent() && other.absent())
            || (matches!(self.result, Some(Ok(())))
                && matches!(other.result, Some(Ok(())))
                && self.identity(1).is_some()
                && self.identity(1) == other.identity(1)
                && self.bytes == other.bytes)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.open
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .filter(|error| **error != rustix::io::Errno::NOENT)
            .map(|error| error as _)
            .or_else(|| {
                self.metadata[0]
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.label
                    .failure()
                    .filter(|_| self.result.as_ref().is_some_and(Result::is_err))
                    .map(|error| error as _)
            })
            .or_else(|| self.read.failure())
            .or_else(|| {
                self.metadata[1]
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

fn require_file(metadata: &Metadata, uid: u32, maximum: u64) -> Result<(), JournalError> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > maximum
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) struct InitialIntentOriginal {
    quote: Option<ResourceVector>,
    main: approval_currentness::ApprovalCurrentnessOriginalV1,
    before: [NameOriginal; 3],
    capture: Option<Result<(), JournalError>>,
    intent_uid: u32,
    context: Option<IntentContext>,
    approved: Option<[u8; INTENT_BYTES]>,
    stage_open: Option<Result<File, rustix::io::Errno>>,
    stage_metadata: [Option<io::Result<Metadata>>; 3],
    stage_labels: [IntentLabelOriginal; 2],
    stage_read: FixedRoleCredentialReadV1,
    stage_bytes: Option<Vec<u8>>,
    write: Option<io::Result<usize>>,
    file_sync: Option<io::Result<()>>,
    ready_read: FixedRoleCredentialReadV1,
    ready_bytes: Option<Vec<u8>>,
    rename: Option<Result<(), rustix::io::Errno>>,
    operation: Option<Result<(), JournalError>>,
    directory_sync: Option<Result<(), rustix::io::Errno>>,
    after: [NameOriginal; 3],
    post: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
}

impl InitialIntentOriginal {
    pub(super) fn new() -> Self {
        Self {
            quote: None,
            main:
                approval_currentness::ApprovalCurrentnessOriginalV1::for_fixed_sibling_publication(),
            before: std::array::from_fn(|_| NameOriginal::new()),
            capture: None,
            intent_uid: 0,
            context: None,
            approved: None,
            stage_open: None,
            stage_metadata: [None, None, None],
            stage_labels: std::array::from_fn(|_| IntentLabelOriginal::new()),
            stage_read: FixedRoleCredentialReadV1::prearmed(),
            stage_bytes: None,
            write: None,
            file_sync: None,
            ready_read: FixedRoleCredentialReadV1::prearmed(),
            ready_bytes: None,
            rename: None,
            operation: None,
            directory_sync: None,
            after: std::array::from_fn(|_| NameOriginal::new()),
            post: None,
            closed: None,
        }
    }

    fn quote_once(
        &mut self,
        journal: &Journal,
        replayed: FileIdentity,
        context: IntentContext,
    ) -> Option<ResourceVector> {
        if self.quote.is_some() || self.capture.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.context = Some(context);
        // Eight exact readers retain a buffer and a failed duplicate each.
        // Six named files plus the writable stage remain resident on failure.
        // Persistent and staging space are charged independently before IO.
        let memory = 2 * std::mem::size_of::<Self>() + 16 * (INTENT_BYTES + 1) + 4096;
        let native = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 16)
            .with(D::MetadataEntries, 32)
            .with(D::StorageBytes, INTENT_BYTES as u64)
            .with(D::PublicationStagingBytes, INTENT_BYTES as u64)
            .with(
                D::OutputBytes,
                (8 * (INTENT_BYTES + 1 + LABEL_BYTES)) as u64,
            );
        self.quote = Some(
            native
                .checked_add(self.main.quote_once(journal, replayed)?)
                .ok()?,
        );
        self.quote
    }

    pub(super) fn capture_once(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if self.quote.is_none() || self.capture.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let main_before = self.main.before_once(journal);
        let context = self.context.ok_or(JournalError::ProtectedBoundary)?;
        for (index, original) in self.before.iter_mut().enumerate() {
            original.capture(journal, index, self.intent_uid, context);
        }
        self.capture = Some((|| {
            main_before?;
            if self
                .before
                .iter()
                .any(|name| !matches!(name.result, Some(Ok(()))))
                || (!self.before[0].absent() && !self.before[1].absent())
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        self.require_captured()
    }

    fn require_captured(&self) -> Result<(), JournalError> {
        if self.closed.is_none() && matches!(self.capture, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn captured_intent_data(&self) -> Result<Option<[u8; INTENT_BYTES]>, JournalError> {
        self.require_captured()?;
        if self.operation.is_some() || self.post.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.before[0]
            .bytes
            .as_deref()
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)
            })
            .transpose()
    }

    pub(super) fn publish_once(
        &mut self,
        journal: &Journal,
        bytes: [u8; INTENT_BYTES],
    ) -> Result<(), JournalError> {
        if self.operation.is_some() || self.post.is_some() || self.require_captured().is_err() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.approved = Some(bytes);
        self.operation = Some(self.publish(journal));
        // Directory sync and all native posts remain owed after a partial write,
        // fsync or rename failure. No failure path unlinks or truncates a name.
        self.directory_sync = Some(journal.native.native_operations().sync_directory());
        let _post = self.finish_after_owed(journal);
        if self.failure().is_none() && matches!(self.operation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn publish(&mut self, journal: &Journal) -> Result<(), JournalError> {
        let approved = self
            .approved
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if let Some(existing) = self.before[0].bytes.as_deref() {
            if existing != approved {
                return Err(JournalError::ProtectedBoundary);
            }
            self.file_sync = Some(
                self.before[0]
                    .file()
                    .ok_or(JournalError::ProtectedBoundary)?
                    .sync_all(),
            );
            return if matches!(self.file_sync, Some(Ok(()))) {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            };
        }
        let prefix = self.before[1].bytes.as_deref().unwrap_or_default();
        if !approved.starts_with(prefix) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.stage_open = Some(
            journal
                .native
                .native_operations()
                .open_resumable_stage(STAGE, self.before[1].absent())
                .map(File::from),
        );
        let stage = self
            .stage_open
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.stage_labels[0].observe(stage);
        self.stage_metadata[0] = Some(stage.metadata());
        let metadata = self.stage_metadata[0]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        require_file(metadata, self.intent_uid, INTENT_BYTES as u64)?;
        let context = self.context.ok_or(JournalError::ProtectedBoundary)?;
        if !self.stage_labels[0].require(context) {
            return Err(JournalError::ProtectedBoundary);
        }
        if metadata.len() != prefix.len() as u64
            || (!self.before[1].absent()
                && Some(FileIdentity::from_metadata_data_v1(metadata))
                    != self.before[1].identity(1))
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.stage_read
            .read_exact_at_once(stage.as_fd(), prefix.len());
        self.stage_bytes = self.stage_read.take_success_bytes_once();
        if self.stage_bytes.as_deref() != Some(prefix) {
            return Err(JournalError::ProtectedBoundary);
        }

        // A short write is retained as failure. The next process may resume its
        // exact public prefix after a new complete signature verification.
        self.write = Some(stage.write_at(&approved[prefix.len()..], prefix.len() as u64));
        if !matches!(self.write, Some(Ok(length)) if length == INTENT_BYTES - prefix.len()) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.file_sync = Some(stage.sync_all());
        if !matches!(self.file_sync, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.ready_read
            .read_exact_at_once(stage.as_fd(), INTENT_BYTES);
        self.ready_bytes = self.ready_read.take_success_bytes_once();
        self.stage_metadata[1] = Some(stage.metadata());
        self.stage_labels[1].observe(stage);
        if !self.stage_labels[1].require(context) {
            return Err(JournalError::ProtectedBoundary);
        }
        if self.ready_bytes.as_deref() != Some(approved.as_slice()) {
            return Err(JournalError::ProtectedBoundary);
        }
        let metadata = self.stage_metadata[1]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        require_file(metadata, self.intent_uid, INTENT_BYTES as u64)?;
        if metadata.len() != INTENT_BYTES as u64 {
            return Err(JournalError::ProtectedBoundary);
        }
        self.rename = Some(
            journal
                .native
                .native_operations()
                .publish_exclusive_stage(STAGE, FINAL),
        );
        if matches!(self.rename, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn finish_after_owed(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if self.capture.is_none() {
            return Ok(());
        }
        if self.post.is_none() {
            for (index, original) in self.after.iter_mut().enumerate() {
                original.capture(
                    journal,
                    index,
                    self.intent_uid,
                    self.context.ok_or(JournalError::ProtectedBoundary)?,
                );
            }
            if let Some(Ok(stage)) = self.stage_open.as_ref() {
                self.stage_metadata[2] = Some(stage.metadata());
            }
            let main_after = self.main.finish_after_owed(journal);
            self.post = Some((|| {
                main_after?;
                if !self.before[2].same(&self.after[2]) {
                    return Err(JournalError::StaleAuthoritySnapshot);
                }
                if matches!(self.operation, Some(Ok(()))) {
                    if !self.after[1].absent()
                        || !matches!(self.after[0].result, Some(Ok(())))
                        || self.after[0].bytes.as_deref()
                            != self.approved.as_ref().map(|bytes| bytes.as_slice())
                    {
                        return Err(JournalError::StaleAuthoritySnapshot);
                    }
                    let held = if self.before[0].absent() {
                        self.stage_metadata[2]
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .map(FileIdentity::from_metadata_data_v1)
                    } else {
                        self.before[0].identity(1)
                    };
                    if held.is_none() || held != self.after[0].identity(1) {
                        return Err(JournalError::StaleAuthoritySnapshot);
                    }
                } else if self.operation.is_none()
                    && (!self.before[0].same(&self.after[0])
                        || !self.before[1].same(&self.after[1]))
                {
                    return Err(JournalError::StaleAuthoritySnapshot);
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

    pub(super) fn durable_ready(&self) -> bool {
        self.failure().is_none()
            && matches!(self.operation, Some(Ok(())))
            && matches!(self.file_sync, Some(Ok(())))
            && matches!(self.directory_sync, Some(Ok(())))
            && matches!(self.post, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.main
            .before_failure()
            .or_else(|| self.before.iter().find_map(NameOriginal::failure))
            .or_else(|| {
                self.capture
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.stage_open
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.stage_metadata[0]
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.context
                    .filter(|context| !self.stage_labels[0].require(*context))
                    .and_then(|_| self.stage_labels[0].failure())
                    .map(|error| error as _)
            })
            .or_else(|| self.stage_read.failure())
            .or_else(|| {
                self.write
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.file_sync
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.ready_read.failure())
            .or_else(|| {
                self.stage_metadata[1]
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.context
                    .filter(|context| !self.stage_labels[1].require(*context))
                    .and_then(|_| self.stage_labels[1].failure())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.rename
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.operation
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
            .or_else(|| self.after.iter().find_map(NameOriginal::failure))
            .or_else(|| {
                self.stage_metadata[2]
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.main.after_failure())
            .or_else(|| {
                self.post
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn quote_initial_intent_once(&mut self) -> Option<ResourceVector> {
        let journal = self.inner.original.journal_data_v1()?;
        let replayed = self
            .inner
            .original
            .captured_replay_file_identity_data_v1()?;
        self.initial_intent
            .quote_once(journal, replayed, self.fixed_role?.into())
    }

    pub(crate) fn capture_initial_intent_once(&mut self) -> Result<(), JournalError> {
        self.initial_intent.capture_once(
            self.inner
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?,
        )
    }

    pub(crate) fn captured_initial_intent_data(
        &self,
    ) -> Result<Option<[u8; INTENT_BYTES]>, JournalError> {
        self.initial_intent.captured_intent_data()
    }

    pub(crate) fn publish_initial_intent_once(
        &mut self,
        bytes: [u8; INTENT_BYTES],
    ) -> Result<(), JournalError> {
        self.initial_intent.publish_once(
            self.inner
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?,
            bytes,
        )
    }

    pub(crate) fn finish_initial_intent_after_owed(&mut self) -> Result<(), JournalError> {
        let Some(journal) = self.inner.original.journal_data_v1() else {
            return Ok(());
        };
        self.initial_intent.finish_after_owed(journal)
    }
}

#[cfg(test)]
mod tests;
