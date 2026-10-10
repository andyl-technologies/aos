//! Retains the original initial preparation in a separate bounded durable file.
//!
//! ```text
//! record100: version:u32be=1 | lifetimeBytes:u64be | PreparePrefix:blob | AppliedInit:blob
//! record101: original QueryPrefixPreparation frame
//! record102: original PrefixPreparationFacts frame
//! record103: original AcknowledgePrefixPreparation frame
//! record104: actual PrefixPreparationAcknowledged frame
//! ```
//!
//! Records use the existing checksummed record envelope and are fsynced before
//! the next request becomes visible. This distinct schema is not a command
//! archive or native permission. Existing files are never adopted as live
//! sessions, truncated, overwritten or deleted after uncertain durability.

// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crucible_protocol::node_control::{
    NativeControlEdition, NativeFrame, NativeInitializationReceipt, NativeInitializationStatus,
    NativePrefixPreparation, encode_frame_for_edition,
};

use super::ArchiveError;
use super::codec::{MAX_RECORD, RECORD_OVERHEAD, put_blob, write_record};

const FORMAT_VERSION: u32 = 1;
const FRAME_HEADER: u64 = 16;
const INITIAL_RECORD_BYTES: u64 = 64 + 640 + 160 + 160 + 4 * FRAME_HEADER + 4 * RECORD_OVERHEAD;

/// Declares the separate initial evidence budget before initial query exposure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialEvidenceBudget {
    /// Bounds complete header, original frame bodies and checksummed envelopes.
    pub lifetime_bytes: u64,
}

/// Owns one fresh initial evidence file without issuing readiness or replay authority.
pub struct InitialEvidenceStore {
    file: File,
    path: PathBuf,
    preparation: NativePrefixPreparation,
    initialization: NativeInitializationReceipt,
    budget: InitialEvidenceBudget,
    bytes: u64,
    next_kind: u32,
    failed: bool,
}

impl InitialEvidenceStore {
    /// Creates and fsyncs the complete original preparation before querying native facts.
    ///
    /// A file collision preserves the existing bytes. This API offers no restore
    /// path because historical data cannot establish a live prepared session.
    ///
    /// # Errors
    /// Rejects invalid preparation, insufficient declared storage, an existing
    /// path, allocation failure or filesystem durability failure. A partial file
    /// remains at its original path and cannot be adopted by a later create.
    pub fn create(
        path: impl AsRef<Path>,
        preparation: NativePrefixPreparation,
        initialization: NativeInitializationReceipt,
        budget: InitialEvidenceBudget,
    ) -> Result<Self, ArchiveError> {
        preparation.validate()?;
        initialization.validate()?;
        let expected = &preparation
            .original_effect
            .original_root
            .administration
            .phase
            .initialization;
        if initialization.status != NativeInitializationStatus::Applied
            || initialization.prepared_scope_hash != expected.preparation.scope.identity_digest()?
            || initialization.initialization_commitment != expected.identity_digest()?
            || initialization.realize_request_digest != expected.realize_request_digest
            || initialization.applied_callbacks > expected.maximum_callbacks
        {
            return Err(ArchiveError::Conflict);
        }
        let prepared = encode_frame_for_edition(
            NativeControlEdition::PrefixEffect,
            &NativeFrame::PreparePrefix(Box::new(preparation.clone())),
        )?;
        let applied = encode_frame_for_edition(
            NativeControlEdition::PrefixEffect,
            &NativeFrame::InitializationStopped(Box::new(initialization.clone())),
        )?;
        let header_length = 20usize
            .checked_add(prepared.len())
            .and_then(|length| length.checked_add(applied.len()))
            .ok_or(ArchiveError::Budget)?;
        let mut header = Vec::new();
        header
            .try_reserve_exact(header_length)
            .map_err(|_| ArchiveError::Budget)?;
        header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        header.extend_from_slice(&budget.lifetime_bytes.to_be_bytes());
        put_blob(&mut header, &prepared)?;
        put_blob(&mut header, &applied)?;
        let required = (header.len() as u64)
            .checked_add(RECORD_OVERHEAD)
            .and_then(|bytes| bytes.checked_add(INITIAL_RECORD_BYTES))
            .ok_or(ArchiveError::Budget)?;
        if budget.lifetime_bytes < required || budget.lifetime_bytes > MAX_RECORD as u64 {
            return Err(ArchiveError::Budget);
        }

        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let mut store = Self {
            file,
            path,
            preparation,
            initialization,
            budget,
            bytes: 0,
            next_kind: 100,
            failed: false,
        };
        store.append(100, &header)?;
        let parent = store.path.parent().ok_or(ArchiveError::Conflict)?;
        File::open(parent)?.sync_all()?;
        Ok(store)
    }

    /// Borrows the unchanged complete preparation held before any native query.
    pub fn preparation(&self) -> &NativePrefixPreparation {
        &self.preparation
    }

    /// Borrows the independently retained original Applied receipt.
    pub fn initialization(&self) -> &NativeInitializationReceipt {
        &self.initialization
    }

    /// Borrows the retained file path without granting namespace cleanup.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reports only local durability completion of the four original records.
    pub fn complete(&self) -> bool {
        !self.failed && self.next_kind == 105
    }

    pub(super) fn retain_original(&mut self, frame: &NativeFrame) -> Result<(), ArchiveError> {
        let kind = match frame {
            NativeFrame::QueryPrefixPreparation { .. } => 101,
            NativeFrame::PrefixPreparationFacts(_) => 102,
            NativeFrame::AcknowledgePrefixPreparation(_) => 103,
            NativeFrame::PrefixPreparationAcknowledged(_) => 104,
            _ => return Err(ArchiveError::Conflict),
        };
        if kind != self.next_kind {
            return Err(ArchiveError::Conflict);
        }
        let encoded = encode_frame_for_edition(NativeControlEdition::PrefixEffect, frame)?;
        self.append(kind, &encoded)
    }

    fn append(&mut self, kind: u32, bytes: &[u8]) -> Result<(), ArchiveError> {
        if self.failed || kind != self.next_kind {
            return Err(ArchiveError::Failed);
        }
        let total = self
            .bytes
            .checked_add(bytes.len() as u64)
            .and_then(|bytes| bytes.checked_add(RECORD_OVERHEAD))
            .ok_or(ArchiveError::Budget)?;
        if total > self.budget.lifetime_bytes {
            return Err(ArchiveError::Budget);
        }
        let result = write_record(&mut self.file, kind, 1, bytes)
            .and_then(|_| self.file.sync_all().map_err(ArchiveError::Io));
        match result {
            Ok(()) => {
                self.bytes = total;
                self.next_kind += 1;
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
}
