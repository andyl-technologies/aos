//! Binds verified metadata lookup to retained native domain-root custody.
//!
//! The host-local domain location has no repository-routing binding. Kernel
//! inspection and the shared provisioning guard remain retained across every
//! metadata read. This type grants no guest read, admission or serving authority.

use super::NativeHostLayout;
use std::sync::Arc;
use terrane_format::identity::Identity;
use terrane_sdk::{
    host::cache::{HostDomainLocation, HostMetadataEntry, HostMetadataReader, HostReadLimits},
    repository::MetadataValidator,
    store::{IdentityPrefix, StoreErrorKind, StoreFailure, TokioLocalFs},
};

/// Reads verified canonical metadata for a genuine inspected host-local domain.
pub struct NativeHostMetadataReader {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    reader: HostMetadataReader<TokioLocalFs, MetadataValidator>,
}

impl NativeHostMetadataReader {
    pub(super) fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        &self.layout
    }

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
        Ok(self.get_entry(identity).await?.canonical)
    }

    /// Lists advisory ordinary-content candidates under retained native roots.
    ///
    /// This performs no adoption or policy mutation and grants no deletion or
    /// presence authority. Sealed-only residences may be absent from the partial
    /// result. Callers use this only for recovery, GC candidate sets or scrub.
    ///
    /// # Errors
    /// Refuses invalid prefixes, result/allocation capacity, changed roots,
    /// corrupt ordinary content and filesystem failures.
    pub async fn list_candidates(
        &self,
        prefix: &IdentityPrefix,
        max_entries: usize,
    ) -> Result<Vec<Identity>, StoreFailure> {
        self.layout.recheck().map_err(native_failure)?;
        let result = self.reader.list_candidates(prefix, max_entries).await;
        self.layout.recheck().map_err(native_failure)?;
        result
    }

    /// Reads verified metadata together with its existing pack-body location.
    ///
    /// Retained root custody is checked before and after lookup. The returned
    /// pack identifier and range grant no native pin or durability authority;
    /// the physical writer must retain and independently verify actual pack and
    /// index descriptors before synchronizing them and recording a durable pin.
    ///
    /// # Errors
    /// Propagates metadata lookup errors and refuses replaced native roots.
    pub async fn get_entry(&self, identity: &Identity) -> Result<HostMetadataEntry, StoreFailure> {
        self.layout.recheck().map_err(native_failure)?;
        let result = self.reader.get_entry(identity).await;
        self.layout.recheck().map_err(native_failure)?;
        result
    }
}

fn native_failure(error: std::io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
}
