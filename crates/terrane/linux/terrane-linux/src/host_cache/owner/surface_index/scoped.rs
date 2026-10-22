//! Closes an original complete-root Read around physical index preparation.

use super::{NativeMetadataOwner, NativeSurfaceIndex};
use crate::host_cache::content::native_failure;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_sdk::{
    repository::{Error, PreparedRootRead},
    store::{Clock, Store, StoreErrorKind, StoreFailure},
};

impl NativeMetadataOwner {
    /// Admits an original authorized root and closes its Read before returning.
    ///
    /// The physical worker checks the exact selected storage domain before any
    /// durable state or copy effects. Only a fresh successful finish of the same
    /// SDK preparation permits returning the admission receipt. This fetches no
    /// content bodies and grants no descriptor, exposure lease or enduring Read.
    ///
    /// Failure or cancellation can leave a funded immutable cache entry. Its
    /// original physical owner retains that entry for maintenance or recovery;
    /// a failed closing authorization never acknowledges native release.
    ///
    /// # Errors
    /// Refuses disabled or oversized admission, incompatible chunk geometry,
    /// another physical domain,
    /// absent writable native custody, canonical or kernel backing failures,
    /// capacity, and any closing full-root authorization or trust failure.
    pub async fn prepare_surface_index<S: Store, C: Clock>(
        &self,
        selection: PreparedRootRead<'_, S, C>,
    ) -> Result<NativeSurfaceIndex, Error> {
        let metadata = selection.metadata();
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Node, &metadata.root())
            .map_err(|_| StoreFailure::new(StoreErrorKind::Unsupported))?;
        if metadata.minimum_chunk_size() != self.chunk_profile.minimum() as u64 {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
        }

        // Check the immutable physical bound before copying the SDK inventory.
        self.check_surface_input(metadata.nodes())
            .map_err(|error| native_failure(error, &identity))?;
        self.admission_bounds
            .check(selection.storage_domain().len(), 0)
            .map_err(|error| native_failure(error, &identity))?;

        let index = self
            .submit_surface_index(
                metadata.root(),
                metadata.nodes().clone(),
                Some(selection.storage_domain().to_owned()),
            )
            .await
            .map_err(|error| native_failure(error, &identity))?;
        selection.finish().await?;
        index
            .check_native_backing()
            .map_err(|error| native_failure(error, &identity))?;
        Ok(index)
    }
}
