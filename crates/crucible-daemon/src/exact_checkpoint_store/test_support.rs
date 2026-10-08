//! Finite checkpoint and RAM-root decoding credit for component fixtures.
//!
//! This authority retains portable descriptor and resident accounting only.
//! It does not authenticate a filesystem quota or qualify native placement;
//! production stores obtain their authority from the admitted catalog provider.

use std::sync::Arc;

#[cfg(test)]
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, ObjectKind,
    PutReceipt,
};
use crucible_cas::content_store::{StoreError, StorePhysicalQuotaGuard};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceError};

const FIXTURE_DESCRIPTORS: u64 = 128;
/// Complete independently authored resident allowance for component root loans.
pub(super) const FIXTURE_RESIDENT_BYTES: u64 = 256 * 1024 * 1024;

/// Constructs a finite portable account for component checkpoint decoders.
///
/// # Errors
/// Refuses an invalid independently authored allocator ceiling.
pub(crate) fn fixture_ram_root_resources()
-> Result<Arc<dyn StorePhysicalQuotaGuard>, HostServiceError> {
    let resources = HostServiceAllocator::new(1, FIXTURE_DESCRIPTORS, FIXTURE_RESIDENT_BYTES)?;
    Ok(Arc::new(FixtureRamRootResources(resources)))
}

struct FixtureRamRootResources(HostServiceAllocator);

impl StorePhysicalQuotaGuard for FixtureRamRootResources {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(FIXTURE_RESIDENT_BYTES)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.0
            .reserve_resources(0, descriptors, resident_bytes)
            .map(crucible_cas::owned_decode::ResourceLoan::new)
            .map_err(|_| StoreError::Quota)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// Installs one finite original account for a portable component fixture.
///
/// Returned values retain their actual shared loans after the scope closes.
/// This account supplies neither filesystem quota nor native Service admission.
#[cfg(test)]
pub(crate) fn fixture_decode_scope() -> crucible::owned_decode::DecodeScope {
    let resources = fixture_ram_root_resources()
        .unwrap_or_else(|error| panic!("finite component metadata resources: {error}"));
    let budget = crucible::owned_decode::DecodeBudget::for_store(resources)
        .unwrap_or_else(|error| panic!("finite original component decode account: {error}"));
    budget.enter()
}

/// Adds finite component metadata credit while retaining the actual backend contract.
///
/// Storage capabilities, graph headroom, and durable writes come from the
/// supplied backend. This wrapper does not certify installed physical quota.
///
#[cfg(test)]
pub(crate) fn fixture_metadata_backend(
    backend: Arc<dyn ImmutableBlobBackend>,
    resources: Arc<dyn StorePhysicalQuotaGuard>,
) -> Arc<dyn ImmutableBlobBackend> {
    Arc::new(FixtureMetadataBackend { backend, resources })
}

#[cfg(test)]
struct FixtureMetadataBackend {
    backend: Arc<dyn ImmutableBlobBackend>,
    resources: Arc<dyn StorePhysicalQuotaGuard>,
}

#[cfg(test)]
impl ImmutableBlobBackend for FixtureMetadataBackend {
    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<crucible_cas::content_store::CheckedPublicationMetadata, StoreError> {
        self.backend.checked_publication_metadata(kind)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &crucible::owned_decode::DecodeBudget,
        objects: &[(crucible_cas::content_store::ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crucible_cas::content_store::PutBatchReceipt, StoreError> {
        self.backend
            .put_many_if_absent_with_boundary(original, objects, boundary)
    }

    fn name(&self) -> &str {
        self.backend.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Ok(Arc::clone(&self.resources))
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.backend.admit_object_graph(objects)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.backend.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.backend.read(id, range)
    }

    fn read_with_boundary(
        &self,
        original: &crucible::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        self.backend
            .read_with_boundary(original, id, range, boundary)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.backend.put_if_absent(id, source)
    }

    fn put_many_if_absent(
        &self,
        objects: &[(ContentId, BlobHandle)],
    ) -> Result<Vec<PutReceipt>, StoreError> {
        self.backend.put_many_if_absent(objects)
    }
}
