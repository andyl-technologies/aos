//! Prices the actual Host catalog model and its sole canonical JSON encoder.
//!
//! These are byte requirements only. They create no catalog publication,
//! current assignment, UID allocation, authenticated inventory or native proof.

use std::mem::size_of;

use super::*;

/// Bounds reached projection rows before constructing the catalog models.
///
/// Counts come from actual complete validated inventory tables. Historical
/// encoded bytes bound the existing retired-allocation vector (each JSON value
/// consumes bytes), including a retained previous catalog and successor copy.
/// The separate exact encoder pass prices its own output before allocation.
#[must_use]
pub fn host_catalog_projection_model_receiving_bytes_v2(
    workspaces: usize,
    networks: usize,
    anchors: usize,
    historical_catalog_bytes: usize,
    retained_string_bytes: usize,
) -> Option<usize> {
    let rows = workspaces
        .checked_mul(size_of::<WorkspaceCatalogEntry>())?
        .checked_add(networks.checked_mul(size_of::<NetworkCatalogEntry>())?)?
        .checked_add(anchors.checked_mul(size_of::<AttachmentAnchorCatalogEntry>())?)?;
    let retired = historical_catalog_bytes
        .checked_add(workspaces)?
        .checked_mul(size_of::<CatalogIdentityAllocation>())?;
    // Projection, materialized successor, unchanged comparison and their Vec
    // growth overlap. Creation proof/current304 byte vectors are priced separately below.
    size_of::<HostCatalogSnapshot>().checked_mul(4)?
        .checked_add(rows.checked_mul(4)?)?
        .checked_add(workspaces.checked_mul(
            GuestRootPublicationProofV1::canonical_bytes_v1().checked_add(
                crate::semantics::storage_guest_root::STORAGE_GUEST_ROOT_CURRENT_PUBLICATION_BYTES_V2)?)?
            .checked_mul(8)?)?
        .checked_add(retired.checked_mul(4)?)?
        .checked_add(retained_string_bytes.checked_mul(8)?)?
        .checked_add(anchors.checked_mul(ATTACHMENT_ANCHOR_PIN_PREFIX.len()
            .checked_add(2 * 32 + 2 + 16)?)?.checked_mul(8)?)
}

impl HostCatalogSnapshot {
    /// Prices canonical catalog encoding without allocating its output.
    ///
    /// The SAME serde JSON encoder writes to a counting sink, then `encode`
    /// writes the admitted bytes. Model validation scratch belongs to the
    /// separately paid projection model recipe. No external IO occurs here.
    ///
    /// # Errors
    /// Refuses serialization failure, encoded overflow or the existing ceiling.
    pub fn canonical_encoding_receiving_bytes_v2(&self) -> Result<usize, HostCatalogSnapshotError> {
        let bytes = self.canonical_encoded_bytes_data_v2()?;
        // Canonical output, publication retention and comparison/reencoding
        // coexist. No second schema, hash or field-layout algorithm is used.
        bytes
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(size_of::<CountedBytes>() * 2))
            .ok_or_else(|| {
                HostCatalogSnapshotError::new("Host catalog encoding receiving overflow")
            })
    }

    /// Measures the sole canonical encoder's exact output without allocating it.
    ///
    /// This passive byte extent grants no receiving or catalog authority. The
    /// caller pays the counting frame before running this same encoder pass.
    ///
    /// # Errors
    /// Refuses serialization failure, overflow or the existing catalog ceiling.
    pub fn canonical_encoded_bytes_data_v2(&self) -> Result<usize, HostCatalogSnapshotError> {
        let mut output = CountedBytes::default();
        serde_json::to_writer(&mut output, self)
            .map_err(|error| HostCatalogSnapshotError::new(error.to_string()))?;
        if output.overflow || output.bytes > MAXIMUM_HOST_CATALOG_BYTES {
            return Err(HostCatalogSnapshotError::new(
                "Host catalog encoding receiving extent",
            ));
        }
        Ok(output.bytes)
    }
}

/// Prices the actual counting sink and serializer construction destinations.
///
/// The projection recipe separately pays recursive row/string/schema scratch.
/// This Memory-only value supplies no encoder permission or native grant.
#[must_use]
pub fn host_catalog_counting_carrier_bytes_v2() -> Option<usize> {
    size_of::<CountedBytes>()
        .checked_mul(2)?
        .checked_add(size_of::<serde_json::Serializer<CountedBytes>>().checked_mul(2)?)
}

#[derive(Default)]
struct CountedBytes {
    bytes: usize,
    overflow: bool,
}

impl std::io::Write for CountedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self.bytes.checked_add(bytes.len()) {
            Some(total) => self.bytes = total,
            None => self.overflow = true,
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Bounds the existing canonical catalog decoder and validation scratch.
///
/// A malformed JSON prefix can grow actual typed vectors before validation.
/// This is the existing Host launch supplier: the largest compiled row layout,
/// vector growth, nested strings/arrays, canonical reencoding and held bytes.
/// The returned bytes confer no catalog or resource authority. Parser carriers
/// are Memory only; real namespace entries are supplied by native callers.
#[must_use]
pub fn host_catalog_canonical_decode_receiving_bytes_v2(bytes: usize) -> Option<usize> {
    let cell = size_of::<WorkspaceCatalogEntry>()
        .max(size_of::<NetworkCatalogEntry>())
        .max(size_of::<AttachmentAnchorCatalogEntry>())
        .max(size_of::<CatalogIdentityAllocation>())
        .max(size_of::<[u8; 32]>());
    cell.checked_mul(4)?
        .checked_add(32)?
        .checked_mul(bytes.checked_add(1)?)?
        .checked_add(size_of::<HostCatalogSnapshot>().checked_mul(4)?)?
        .checked_add(64 * 1024)
}
