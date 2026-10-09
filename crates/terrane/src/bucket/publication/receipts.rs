//! Retains operation-local exact read data for closed native effect refreshes.
//!
//! These observations grant no actor or mutation authority. They preserve the
//! bytes and leaf metadata already checked by a complete selected resolver; an
//! effect factory separately requires actual held descriptors and sealed inputs.

use crate::store::native_publication_effects::RetainedPayloadRead;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Carries one exact read, including explicit physical absence.
#[derive(Clone)]
pub(crate) struct RecordRead {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    metadata: Option<std::fs::Metadata>,
    retained_payload: Option<Arc<RetainedPayloadRead>>,
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
            retained_payload: None,
        }
    }

    /// Borrows the exact name read by the backend.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Attaches original ancestor observations from the actual payload reader.
    pub(in crate::bucket) fn with_retained_payload(mut self, read: RetainedPayloadRead) -> Self {
        self.retained_payload = Some(Arc::new(read));
        self
    }

    /// Borrows the original physical recipe, when captured before consumption.
    pub(crate) fn retained_payload(&self) -> Option<&RetainedPayloadRead> {
        self.retained_payload.as_deref()
    }

    /// Revalidates the complete original payload observation before reuse.
    ///
    /// # Errors
    /// Refuses missing original evidence, changed ancestry, leaf or body, unsafe
    /// metadata and unavailable actual reads.
    pub(crate) async fn revalidate_retained<
        F: crate::store::LocalFs + crate::bucket::BucketBinding,
    >(
        &self,
        fs: &F,
    ) -> Result<(), crate::store::StoreFailure> {
        let retained = self.retained_payload.as_ref().ok_or_else(|| {
            crate::store::StoreFailure::new(crate::store::StoreErrorKind::Unsupported)
        })?;
        retained.revalidate(fs).await
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
