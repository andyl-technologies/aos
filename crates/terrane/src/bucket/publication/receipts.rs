//! Separates ordinary DATA read receipts from protected effect observations.
//!
//! These observations grant no actor or mutation authority. They preserve the
//! bytes and leaf metadata already checked by a complete selected resolver; an
//! effect factory separately requires actual held descriptors and sealed inputs.

#[cfg(all(feature = "tokio", unix))]
use crate::store::native_publication_effects::RetainedPayloadRanges;
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
    #[cfg(all(feature = "tokio", unix))]
    ordinary_retained: Option<Arc<RetainedPayloadRanges>>,
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
            #[cfg(all(feature = "tokio", unix))]
            ordinary_retained: None,
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

    /// Attaches an actual ordinary descriptor recipe without protected authority.
    #[cfg(all(feature = "tokio", unix))]
    pub(in crate::bucket) fn with_ordinary_retained(mut self, read: RetainedPayloadRanges) -> Self {
        self.ordinary_retained = Some(Arc::new(read));
        self
    }

    /// Identifies ordinary receipts that cannot supply effect authority.
    pub(crate) fn is_ordinary_retained(&self) -> bool {
        #[cfg(all(feature = "tokio", unix))]
        {
            self.ordinary_retained.is_some()
        }
        #[cfg(not(all(feature = "tokio", unix)))]
        {
            false
        }
    }

    /// Refuses ordinary DATA receipts at protected effect capture boundaries.
    ///
    /// # Errors
    /// Returns unsupported for ordinary receipts, including otherwise readable
    /// public files whose metadata also happens to satisfy protected policies.
    pub(crate) fn require_effect_compatible(&self) -> Result<(), crate::store::StoreFailure> {
        if self.is_ordinary_retained() {
            return Err(crate::store::StoreFailure::new(
                crate::store::StoreErrorKind::Unsupported,
            ));
        }
        Ok(())
    }

    /// Borrows only a protected original recipe captured before consumption.
    pub(crate) fn retained_payload(&self) -> Option<&RetainedPayloadRead> {
        self.retained_payload.as_deref()
    }

    /// Revalidates the original protected or ordinary observation before reuse.
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
        #[cfg(all(feature = "tokio", unix))]
        if let Some(retained) = &self.ordinary_retained {
            return retained.revalidate(fs).await;
        }
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

/// Retains one selected detached index and actual pack metadata without its body.
///
/// This observation grants no collection, elapsed-age or deletion authority.
/// A native retirement consumer separately opens and retains the actual pack
/// descriptor and rechecks its incarnation, length and timestamp through effects.
pub(crate) struct GcPackRead {
    inventory: terrane_core::bucket::PackInventoryEntry,
    pack_path: PathBuf,
    metadata: std::fs::Metadata,
    index: RecordRead,
    snapshot: crate::pack::PackIndexSnapshot,
}

impl GcPackRead {
    /// Retains observations made by the held backend's canonical pack observer.
    pub(in crate::bucket) fn observed(
        inventory: terrane_core::bucket::PackInventoryEntry,
        pack_path: PathBuf,
        metadata: std::fs::Metadata,
        index: RecordRead,
        snapshot: crate::pack::PackIndexSnapshot,
    ) -> Self {
        Self {
            inventory,
            pack_path,
            metadata,
            index,
            snapshot,
        }
    }

    /// Borrows the complete selected inventory association.
    pub(crate) fn inventory(&self) -> &terrane_core::bucket::PackInventoryEntry {
        &self.inventory
    }

    /// Borrows the canonical backend-derived pack path.
    pub(crate) fn pack_path(&self) -> &Path {
        &self.pack_path
    }

    /// Borrows the backend's actual regular-file timestamp and length observation.
    pub(crate) fn metadata(&self) -> &std::fs::Metadata {
        &self.metadata
    }

    /// Borrows the exact independently verified detached-index read.
    pub(crate) fn index(&self) -> &RecordRead {
        &self.index
    }

    /// Borrows canonical members decoded from the inventory-bound detached index.
    pub(crate) fn snapshot(&self) -> &crate::pack::PackIndexSnapshot {
        &self.snapshot
    }
}
