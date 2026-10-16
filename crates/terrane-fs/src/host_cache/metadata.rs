//! Binds verified metadata lookup to retained native domain-root custody.
//!
//! The host-local domain location has no repository-routing binding. Kernel
//! inspection and the shared provisioning guard remain retained across every
//! metadata read. This type grants no guest read, admission or serving authority.

use super::NativeHostLayout;
use std::sync::Arc;
use terrane::{
    host::cache::{HostDomainLocation, HostMetadataReader, HostReadLimits},
    repository::MetadataValidator,
    store::{StoreErrorKind, StoreFailure, TokioLocalFs},
};
use terrane_core::identity::Identity;

/// Reads verified canonical metadata for a genuine inspected host-local domain.
pub struct NativeHostMetadataReader {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    reader: HostMetadataReader<TokioLocalFs, MetadataValidator>,
}

impl NativeHostMetadataReader {
    /// Opens bounded metadata verification over retained native directory facts.
    ///
    /// It accepts no caller assertion of device identity, fake repository binding
    /// or arbitrary source descriptor. The layout is actual native inspection;
    /// private-domain access remains host-local under trusted operator custody.
    ///
    /// # Errors
    /// Refuses changed roots, a mismatching observed root incarnation, invalid
    /// metadata-reader configuration and native filesystem errors.
    pub async fn open(
        layout: Arc<NativeHostLayout<HostDomainLocation>>,
        limits: HostReadLimits,
    ) -> Result<Self, StoreFailure> {
        layout.recheck().map_err(native_failure)?;
        let location = layout.layout();
        let reader = HostMetadataReader::open_existing(
            location.clone(),
            TokioLocalFs,
            MetadataValidator::new(location.chunk_profile().clone()),
            limits,
        )
        .await?;
        if reader.directory_identity()
            != layout
                .directory_binding("layout-root")
                .map_err(native_failure)?
        {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        layout.recheck().map_err(native_failure)?;
        Ok(Self { layout, reader })
    }

    /// Returns exact canonical metadata bytes after fresh native and pack checks.
    ///
    /// The returned byte length is the actual descriptor size; neither missing
    /// metadata nor lost state authorizes a guessed size or sealed plaintext.
    ///
    /// # Errors
    /// Propagates absence, capacity, schema/identity corruption, changed native
    /// roots and filesystem failures. Chunk/pack identities are unsupported.
    pub async fn get(&self, identity: &Identity) -> Result<Vec<u8>, StoreFailure> {
        self.layout.recheck().map_err(native_failure)?;
        let result = self.reader.get(identity).await;
        self.layout.recheck().map_err(native_failure)?;
        result
    }
}

fn native_failure(error: std::io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
}
