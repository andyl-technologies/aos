//! Fences normal floor opening on unresolved initial-checkpoint artifacts.
//!
//! Atomic initial publication preserves the displaced empty inode. Normal
//! startup accepts only an absent or safely empty pending name; any other state
//! belongs to manual recovery. Both observations retain their actual failures,
//! and the second observation remains owed after a failed first observation.
//! These metadata checks grant no TPM, floor or initialization authority.

use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::INITIAL_PENDING_NAME_V1;

use super::*;

struct NameSample {
    open: Option<Result<File, rustix::io::Errno>>,
    metadata: [Option<io::Result<Metadata>>; 2],
}

impl NameSample {
    const fn new() -> Self {
        Self {
            open: None,
            metadata: [None, None],
        }
    }

    fn capture(&mut self, main: &Journal) {
        self.open = Some(
            main.native
                .native_operations()
                .open_named_child(INITIAL_PENDING_NAME_V1)
                .map(File::from),
        );
        if let Some(Ok(file)) = self.open.as_ref() {
            self.metadata[0] = Some(file.metadata());
            self.metadata[1] = Some(file.metadata());
        }
    }

    fn require_empty(&self, uid: u32) -> Result<Option<FileIdentity>, JournalError> {
        if self.missing() {
            return Ok(None);
        }
        let mut identity = None;
        for result in &self.metadata {
            let metadata = result
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            if !metadata.is_file()
                || metadata.uid() != uid
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() != 0
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let observed = FileIdentity::from_metadata_data_v1(metadata);
            if identity.is_some_and(|before| before != observed) {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            identity = Some(observed);
        }
        Ok(identity)
    }

    fn missing(&self) -> bool {
        matches!(self.open, Some(Err(rustix::io::Errno::NOENT)))
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.open)
            .filter(|_| !self.missing())
            .or_else(|| self.metadata.iter().find_map(error))
    }
}

pub(super) struct InitialCheckpointResidueOriginalV1 {
    samples: [NameSample; 2],
    result: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
}

impl InitialCheckpointResidueOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            samples: [NameSample::new(), NameSample::new()],
            result: None,
            closed: None,
        }
    }

    // Both normal facades include this supplier in the fixed demand paid by
    // their actual B/F receiver before construction or native preparation.
    // Resident Self storage is already included in each enclosing facade.
    pub(super) fn native_demand() -> Result<ResourceVector, AccountingError> {
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<Metadata>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<FileIdentity>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            })?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, 2)
            .with(D::MetadataEntries, 8))
    }

    pub(super) fn capture_once(&mut self, main: &Journal) {
        if self.result.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.samples[0].capture(main);
        self.samples[1].capture(main);
        self.finish(main);
    }

    fn finish(&mut self, main: &Journal) {
        self.result = Some((|| {
            let uid = main
                .native
                .protected_uid()
                .ok_or(JournalError::ProtectedBoundary)?;
            let before = self.samples[0].require_empty(uid)?;
            let after = self.samples[1].require_empty(uid)?;
            if before != after {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.samples
            .iter()
            .find_map(NameSample::failure)
            .or_else(|| error(&self.result))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests;
