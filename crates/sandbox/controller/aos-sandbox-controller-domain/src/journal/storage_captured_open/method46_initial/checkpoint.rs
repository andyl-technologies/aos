//! Captures the fixed checkpoint stage before any initial TPM request.
//!
//! The sole journal encoder constructs the complete prospective transaction as
//! DATA. An existing stage must be its exact bounded prefix. Nothing is created,
//! written, renamed or truncated here; publication and its durability frontier
//! remain separate. The same Source prepays and retains every native prefix.

use std::fs::{File, Metadata};
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_journal::framing::{COMMIT_PAYLOAD_BYTES, FrameError, HEADER_BYTES};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_journal::transaction::{
    NativeRecordRef, NativeTransactionEncodeOriginalsV1, encode_transaction_retaining_v1,
};
use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::{
    CHECKPOINT_BYTES_V1, CHECKPOINT_KEY_V1, INITIAL_PENDING_NAME_V1 as STAGE,
};
use sha2::{Digest as _, Sha256};

use super::*;

mod publication;

const INITIAL_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.initial-sidecar.v1\0";
// Three native headers, BEGIN count, one record header/key/value and COMMIT.
const FRAMED_BYTES: usize =
    3 * HEADER_BYTES + 4 + 7 + CHECKPOINT_KEY_V1.len() + CHECKPOINT_BYTES_V1 + COMMIT_PAYLOAD_BYTES;

pub(super) struct InitialCheckpointOriginal {
    quote: Option<Result<ResourceVector, JournalError>>,
    main: approval_currentness::ApprovalCurrentnessOriginalV1,
    encoder: NativeTransactionEncodeOriginalsV1,
    encoded: Option<Result<Vec<Vec<u8>>, FrameError>>,
    expected: Option<[u8; FRAMED_BYTES]>,
    open: Option<Result<File, rustix::io::Errno>>,
    metadata: [Option<io::Result<Metadata>>; 2],
    read: FixedRoleCredentialReadV1,
    bytes: Option<Vec<u8>>,
    capture: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
    publication: publication::InitialCheckpointPublicationOriginal,
}

impl InitialCheckpointOriginal {
    pub(super) fn new() -> Self {
        Self {
            quote: None,
            main: approval_currentness::ApprovalCurrentnessOriginalV1::new(),
            encoder: NativeTransactionEncodeOriginalsV1::new(),
            encoded: None,
            expected: None,
            open: None,
            metadata: [None, None],
            read: FixedRoleCredentialReadV1::prearmed(),
            bytes: None,
            capture: None,
            after: None,
            closed: None,
            publication: publication::InitialCheckpointPublicationOriginal::new(),
        }
    }

    pub(super) fn quote_once(
        &mut self,
        main: &Journal,
        replayed: FileIdentity,
    ) -> Option<ResourceVector> {
        if self.quote.is_some() || self.capture.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.quote = Some((|| {
            // The frames, failed encoder scratch, bounded stage reader and
            // returned/retained construction all precede allocation or IO.
            let memory = 2 * std::mem::size_of::<Self>() + 16 * (FRAMED_BYTES + 1) + 4096;
            let native = ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(memory).map_err(|_| JournalError::ProtectedBoundary)?,
                )
                .with(D::OpenFiles, 4)
                .with(D::MetadataEntries, 24)
                .with(D::OutputBytes, (2 * (FRAMED_BYTES + 1)) as u64);
            let bookends = self
                .main
                .quote_once(main, replayed)
                .ok_or(JournalError::ProtectedBoundary)?;
            native
                .checked_add(bookends)
                .map_err(|_| JournalError::ProtectedBoundary)
        })());
        self.quote.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn capture_once(
        &mut self,
        main: &Journal,
        checkpoint: [u8; CHECKPOINT_BYTES_V1],
    ) -> Result<(), JournalError> {
        if self.capture.is_some() || self.closed.is_some() || !matches!(self.quote, Some(Ok(_))) {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.capture = Some((|| {
            self.main.before_once(main)?;
            let mut digest = Sha256::new();
            digest.update(INITIAL_DOMAIN);
            digest.update(checkpoint);
            let digest = digest.finalize();
            let id = digest[..16]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            self.encoded = Some(encode_transaction_retaining_v1(
                id,
                1,
                [NativeRecordRef {
                    namespace_byte: RecordNamespace::BrokerSessionTraffic as u8,
                    key: CHECKPOINT_KEY_V1,
                    value: Some(&checkpoint),
                }]
                .into_iter(),
                &mut self.encoder,
            ));
            let frames = self
                .encoded
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let expected = self.expected.insert([0; FRAMED_BYTES]);
            let mut offset = 0usize;
            for frame in frames {
                let end = offset
                    .checked_add(frame.len())
                    .ok_or(JournalError::ProtectedBoundary)?;
                expected
                    .get_mut(offset..end)
                    .ok_or(JournalError::ProtectedBoundary)?
                    .copy_from_slice(frame);
                offset = end;
            }
            if offset != FRAMED_BYTES {
                return Err(JournalError::ProtectedBoundary);
            }

            self.open = Some(
                main.native
                    .native_operations()
                    .open_named_child(STAGE)
                    .map(File::from),
            );
            if matches!(self.open, Some(Err(rustix::io::Errno::NOENT))) {
                return Ok(());
            }
            let file = self
                .open
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.metadata[0] = Some(file.metadata());
            let metadata = self.metadata[0]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let uid = main
                .native
                .protected_uid()
                .ok_or(JournalError::ProtectedBoundary)?;
            // The manual Source is root. A resumable stage may still be root
            // owned before the eventual fixed final-owner handoff.
            if !metadata.is_file()
                || (metadata.uid() != uid && metadata.uid() != 0)
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > FRAMED_BYTES as u64
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let length =
                usize::try_from(metadata.len()).map_err(|_| JournalError::ProtectedBoundary)?;
            let before = FileIdentity::from_metadata_data_v1(metadata);
            self.read.read_exact_at_once(file.as_fd(), length);
            self.bytes = self.read.take_success_bytes_once();
            self.metadata[1] = Some(file.metadata());
            let after = self.metadata[1]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            if before != FileIdentity::from_metadata_data_v1(after) {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            let bytes = self
                .bytes
                .as_deref()
                .ok_or(JournalError::ProtectedBoundary)?;
            if !expected.starts_with(bytes) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        let _after = self.finish_after_owed(main);
        if self.ready() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn finish_after_owed(&mut self, main: &Journal) -> Result<(), JournalError> {
        if self.capture.is_none() {
            return Ok(());
        }
        if self.after.is_none() {
            self.after = Some(self.main.finish_after_owed(main));
        }
        if self.failure().is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn ready(&self) -> bool {
        self.failure().is_none()
            && matches!(self.capture, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
            && self.expected.is_some()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.quote)
            .or_else(|| self.main.before_failure())
            .or_else(|| error(&self.encoded))
            .or_else(|| {
                error(&self.open)
                    .filter(|_| !matches!(self.open, Some(Err(rustix::io::Errno::NOENT))))
            })
            .or_else(|| error(&self.metadata[0]))
            .or_else(|| self.read.failure())
            .or_else(|| error(&self.metadata[1]))
            .or_else(|| error(&self.capture))
            .or_else(|| self.main.after_failure())
            .or_else(|| error(&self.after))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
            .or_else(|| self.publication.failure())
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn quote_initial_checkpoint_once(&mut self) -> Option<ResourceVector> {
        if self.failure().is_some() || self.post.is_some() || !self.tpm_locks.ready() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        let replayed = self
            .inner
            .original
            .captured_replay_file_identity_data_v1()?;
        self.checkpoint
            .quote_once(self.inner.original.journal_data_v1()?, replayed)
    }

    pub(crate) fn capture_initial_checkpoint_once(
        &mut self,
        checkpoint: [u8; CHECKPOINT_BYTES_V1],
    ) -> Result<(), JournalError> {
        if self.failure().is_some() || self.post.is_some() || !self.tpm_locks.ready() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.checkpoint.capture_once(
            self.inner
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?,
            checkpoint,
        )
    }

    pub(crate) fn finish_initial_checkpoint_after_owed(&mut self) -> Result<(), JournalError> {
        let main = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let capture = self.checkpoint.finish_after_owed(main);
        let sync = self.checkpoint.publication.sync_after_owed(main);
        let publication = if let Some(expected) = self.checkpoint.expected.as_ref() {
            self.checkpoint
                .publication
                .finish_after_owed(main, expected)
        } else {
            Ok(())
        };
        if capture.is_err() || sync.is_err() || publication.is_err() {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        }
    }

    pub(crate) fn quote_initial_checkpoint_publication_once(&mut self) -> Option<ResourceVector> {
        if self.failure().is_some()
            || self.post.is_some()
            || !self.tpm_locks.ready()
            || !self.initial_floor.ready()
            || !self.checkpoint.ready()
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        let replayed = self
            .inner
            .original
            .captured_replay_file_identity_data_v1()?;
        self.checkpoint
            .publication
            .quote_once(self.inner.original.journal_data_v1()?, replayed)
    }

    pub(crate) fn prepare_initial_checkpoint_publication_once(
        &mut self,
    ) -> Result<(), JournalError> {
        if self.failure().is_some()
            || self.post.is_some()
            || !self.tpm_locks.ready()
            || !self.initial_floor.ready()
            || !self.checkpoint.ready()
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        // These original paid intervals end before our own namespace mutation.
        // Both posts remain independent, and neither releases either flock.
        let locks = self.finish_initial_tpm_locks_after_owed();
        let floor = self.finish_initial_floor_after_owed();
        if locks.is_err() || floor.is_err() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (_, empty) = self
            .initial_floor
            .journal_and_replayed_data()
            .ok_or(JournalError::ProtectedBoundary)?;
        let captured = self.checkpoint.metadata[1]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(FileIdentity::from_metadata_data_v1);
        let expected = self
            .checkpoint
            .expected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.checkpoint.publication.prepare_once(
            self.inner
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?,
            empty,
            expected,
            captured,
            self.checkpoint.bytes.as_deref(),
        )
    }

    pub(crate) fn validate_initial_checkpoint_publication_once(
        &mut self,
    ) -> Result<(), JournalError> {
        let main = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let expected = self
            .checkpoint
            .expected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.checkpoint.publication.validate_once(main, expected)
    }

    pub(crate) fn exchange_initial_checkpoint_once(&mut self) -> Result<(), JournalError> {
        let main = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.checkpoint.publication.exchange_once(main)
    }

    pub(crate) fn sync_initial_checkpoint_after_owed(&mut self) -> Result<(), JournalError> {
        let main = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.checkpoint.publication.sync_after_owed(main)
    }
}

#[cfg(test)]
mod tests;
