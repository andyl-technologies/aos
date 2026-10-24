//! Reads exact catalog-selected objects beneath the actual Root Cache view.
//!
//! The enclosing R role pays every construction/byte/native/model peak and
//! keeps the view through its independently owed native/service/clock posts.
//! This mechanical child exposes no raw File, catalog adoption or path factory.

use super::*;
use aos_sandbox_model::ObjectDescriptor;
use aos_sandbox_linux::immutable_file::{FsVerityReadOriginalV2, FsVerityReadClosedV2};
use aos_sandbox_linux::immutable_file::FsVerityDigest;

/// Marks incomplete actual Root object IO while its concrete original stays held.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Root Cache metadata read is incomplete")]
pub struct RootCacheMetadataReadClosedV2;

#[derive(Debug, thiserror::Error)]
enum MetadataReadErrorV2 {
    #[error(transparent)]
    Native(#[from] FsVerityReadClosedV2),
    #[error(transparent)]
    Stat(#[from] rustix::io::Errno),
    #[error("the actual Root catalog or object inode differs")]
    Relation,
}

/// Retains one catalog-selected Root fs-verity file and all actual failed bytes.
///
/// Construction is inert. Only an actual prepared Root view can select a file;
/// these native bytes remain comparison DATA until the enclosing role completes
/// its whole native and financial post set.
pub struct RootCacheMetadataReadOriginalV2 {
    native: FsVerityReadOriginalV2,
    metadata: Option<rustix::io::Result<rustix::fs::Stat>>,
    opened: Option<Result<(), MetadataReadErrorV2>>,
    read: Option<Result<(), FsVerityReadClosedV2>>,
    closed: Option<RootCacheMetadataReadClosedV2>,
}

impl Default for RootCacheMetadataReadOriginalV2 {
    fn default() -> Self {
        Self { native: FsVerityReadOriginalV2::new(), metadata: None,
            opened: None, read: None, closed: None }
    }
}

impl RootCacheMetadataReadOriginalV2 {
    /// Prices this actual destination and bounded read/copy overlap.
    ///
    /// Canonical model planes and the shared complete catalog are separately
    /// admitted by the enclosing actual graph stage before either is grown.
    #[must_use]
    pub fn receiving_demand_v2(descriptor: &ObjectDescriptor) -> Option<ResourceVector> {
        let extent = usize::try_from(descriptor.encoded_size()).ok()?;
        let memory = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(extent.checked_add(1)?.checked_mul(3)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 1))
    }

    /// Opens only the exact disk entry in this Root original's own catalog.
    ///
    /// # Errors
    /// Retains reentry, absent genuine catalog/root, original fs-verity failure
    /// or actual fstat mismatch. Every reached file and stat result stays here.
    pub fn open_once_v2(&mut self, view: &CacheObjectViewOriginalV1,
        descriptor: &ObjectDescriptor,
    ) -> Result<(), RootCacheMetadataReadClosedV2> {
        if self.opened.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(RootCacheMetadataReadClosedV2);
            return Err(RootCacheMetadataReadClosedV2);
        }
        self.opened = Some((|| {
            if !matches!(view.recipe, ViewRecipeV1::RootCurrent)
                || view.first.is_some() || view.posts_entered
                || !matches!(view.metadata_root_result, Some(Ok(())))
                || !matches!(view.decoded, Some(Ok(_)))
            {
                return Err(MetadataReadErrorV2::Relation);
            }
            let catalog = view.metadata_catalog.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(MetadataReadErrorV2::Relation)?;
            let entry = catalog.disk_entries_v2().find(|entry| entry.descriptor == descriptor)
                .ok_or(MetadataReadErrorV2::Relation)?;
            let root = view.metadata_root.root_v1().ok_or(MetadataReadErrorV2::Relation)?;
            self.native.open_once_v2(root, Path::new(entry.file_name),
                FsVerityDigest::Sha256(entry.verity), descriptor.encoded_size())?;
            let file = self.native.file_v2().ok_or(MetadataReadErrorV2::Relation)?;
            self.metadata = Some(rustix::fs::fstat(file));
            let stat = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| match self.metadata.as_ref() {
                    Some(Err(cause)) => MetadataReadErrorV2::Stat(*cause),
                    _ => MetadataReadErrorV2::Relation,
                })?;
            if entry.bytes != descriptor.encoded_size()
                || !super::super::disk_object_identity_matches_data_v2(stat,
                    entry.device, entry.inode, view.signer_uid, descriptor.encoded_size())
            {
                return Err(MetadataReadErrorV2::Relation);
            }
            Ok(())
        })());
        if matches!(self.opened, Some(Ok(()))) { Ok(()) }
        else { Err(RootCacheMetadataReadClosedV2) }
    }

    /// Reads the same checked file through the sole bounded native byte engine.
    ///
    /// # Errors
    /// Refuses absent file proof/reentry or retains the exact read failure and prefix.
    pub fn read_once_v2(&mut self, maximum: usize) -> Result<(), RootCacheMetadataReadClosedV2> {
        if !matches!(self.opened, Some(Ok(()))) || self.read.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(RootCacheMetadataReadClosedV2);
            return Err(RootCacheMetadataReadClosedV2);
        }
        self.read = Some(self.native.read_once_v2(maximum));
        if matches!(self.read, Some(Ok(()))) { Ok(()) }
        else { Err(RootCacheMetadataReadClosedV2) }
    }

    /// Moves the actual completed bytes once without creating role authority.
    pub fn take_completed_bytes_v2(&mut self) -> Option<Vec<u8>> {
        if !matches!(self.read, Some(Ok(()))) || self.closed.is_some() { return None; }
        self.native.take_completed_bytes_v2()
    }

    /// Borrows the actual first native refusal while all original owners stay held.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.opened.as_ref().and_then(|result| result.as_ref().err()) {
            Some(MetadataReadErrorV2::Native(marker)) => self.native.failure().or(Some(marker)),
            Some(cause) => Some(cause),
            None => self.native.failure().or_else(|| self.closed.as_ref().map(|cause| cause as _)),
        }
    }
}
