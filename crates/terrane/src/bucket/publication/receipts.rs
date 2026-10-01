//! Retains operation-local exact read data for closed native effect refreshes.
//!
//! These observations grant no actor or mutation authority. They preserve the
//! bytes and leaf metadata already checked by a complete selected resolver; an
//! effect factory separately requires actual held descriptors and sealed inputs.

use std::path::{Path, PathBuf};

/// Carries one exact read, including explicit physical absence.
#[derive(Clone)]
pub(crate) struct RecordRead {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    metadata: Option<std::fs::Metadata>,
}

impl RecordRead {
    /// Retains exact bytes and leaf metadata already checked by the backend.
    ///
    /// This operation-local read data grants no mutation or actor authority.
    pub(in crate::bucket) fn observed(
        path: PathBuf,
        bytes: Option<Vec<u8>>,
        metadata: Option<std::fs::Metadata>,
    ) -> Self {
        Self {
            path,
            bytes,
            metadata,
        }
    }

    /// Borrows the exact name read by the backend.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Borrows the actual full bytes or the observed absence.
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }

    /// Borrows the checked final leaf metadata, absent for a missing name.
    pub(crate) fn metadata(&self) -> Option<&std::fs::Metadata> {
        self.metadata.as_ref()
    }

    /// Consumes the read data and returns its whole value or explicit absence.
    pub(in crate::bucket) fn into_bytes(self) -> Option<Vec<u8>> {
        self.bytes
    }
}
