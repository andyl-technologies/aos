//! Canonical, bounded SourceProvider resource catalog manifest.
//!
//! The signed AOSPCP01 publication commits the digest of these exact bytes.
//! Rows are ordered by logical-binding digest, so a current protected catalog
//! head selects at most one resource and Storage export for an Acquire intent.
//! This format alone does not authenticate a publication or an attempt.
//!
//! ```text
//! AOSPCM01 | version:u16be=1 | reserved:u16be=0 |
//! catalog-generation:u64be | namespace-digest[32] | row-count:u16be |
//! row[count] = binding-digest[32] | resource-id[32] |
//! resource-generation:u64be | resource-digest[32] |
//! selection-generation:u64be | selection-digest[32] |
//! export-id[16] | export-generation:u64be | workspace-id[32] |
//! source-assignment-digest[32]
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::{SourceResourceV1, StorageLiveExportSelectorV1};

const MAGIC: &[u8; 8] = b"AOSPCM01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 54;
const ROW_BYTES: usize = 232;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.provider.catalog-manifest.v1\0";

/// Maximum number of rows in one Provider resource catalog.
pub const MAXIMUM_PROVIDER_CATALOG_ROWS_V1: usize = 64;

/// Rejects noncanonical, ambiguous, or noncurrent catalog rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderCatalogManifestErrorV1 {
    /// The manifest has invalid framing, ordering, bounds, or a sentinel field.
    #[error("Provider catalog manifest is noncanonical")]
    Noncanonical,
    /// The manifest does not match the protected current publication head.
    #[error("Provider catalog manifest is not current")]
    NotCurrent,
    /// No row names the authenticated logical-binding digest.
    #[error("Provider catalog has no selected resource")]
    NoSelection,
}

/// Binds one logical source to one Provider resource and Storage export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCatalogRowV1 {
    binding_digest: ObjectDigest,
    resource_id: [u8; 32],
    resource_generation: u64,
    resource_digest: ObjectDigest,
    selection_generation: u64,
    selection_digest: ObjectDigest,
    selector: StorageLiveExportSelectorV1,
}

impl ProviderCatalogRowV1 {
    /// Constructs one non-sentinel catalog row.
    ///
    /// # Errors
    ///
    /// Rejects zero binding, resource, or selection fields.
    pub fn new(
        binding_digest: ObjectDigest,
        resource_id: [u8; 32],
        resource_generation: u64,
        resource_digest: ObjectDigest,
        selection_generation: u64,
        selection_digest: ObjectDigest,
        selector: StorageLiveExportSelectorV1,
    ) -> Result<Self, ProviderCatalogManifestErrorV1> {
        if binding_digest.as_bytes() == &[0; 32]
            || resource_id == [0; 32]
            || resource_generation == 0
            || resource_digest.as_bytes() == &[0; 32]
            || selection_generation == 0
            || selection_digest.as_bytes() == &[0; 32]
        {
            return Err(ProviderCatalogManifestErrorV1::Noncanonical);
        }
        Ok(Self {
            binding_digest,
            resource_id,
            resource_generation,
            resource_digest,
            selection_generation,
            selection_digest,
            selector,
        })
    }

    /// Returns the exact logical-binding selector.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the exact Storage export selector committed by this row.
    #[must_use]
    pub const fn storage_selector(&self) -> StorageLiveExportSelectorV1 {
        self.selector
    }
}

/// Owns one canonical row set committed by a catalog publication digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCatalogManifestV1 {
    generation: u64,
    namespace_digest: ObjectDigest,
    rows: Vec<ProviderCatalogRowV1>,
}

impl ProviderCatalogManifestV1 {
    /// Returns the catalog generation committed by the publication.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the resource namespace committed by the publication.
    #[must_use]
    pub const fn namespace_digest(&self) -> ObjectDigest {
        self.namespace_digest
    }

    /// Constructs a nonempty manifest with strictly increasing binding digests.
    ///
    /// # Errors
    ///
    /// Rejects sentinel metadata, too many rows, or duplicate/unsorted rows.
    pub fn new(
        generation: u64,
        namespace_digest: ObjectDigest,
        rows: Vec<ProviderCatalogRowV1>,
    ) -> Result<Self, ProviderCatalogManifestErrorV1> {
        if generation == 0
            || namespace_digest.as_bytes() == &[0; 32]
            || rows.is_empty()
            || rows.len() > MAXIMUM_PROVIDER_CATALOG_ROWS_V1
            || rows
                .windows(2)
                .any(|pair| pair[0].binding_digest.as_bytes() >= pair[1].binding_digest.as_bytes())
        {
            return Err(ProviderCatalogManifestErrorV1::Noncanonical);
        }
        Ok(Self {
            generation,
            namespace_digest,
            rows,
        })
    }

    /// Decodes only the exact canonical manifest representation.
    ///
    /// # Errors
    ///
    /// Rejects truncated, oversized, unsorted, duplicate, or sentinel rows.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProviderCatalogManifestErrorV1> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > HEADER_BYTES + MAXIMUM_PROVIDER_CATALOG_ROWS_V1 * ROW_BYTES
            || &bytes[..8] != MAGIC
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
            ) != VERSION
            || bytes[10..12] != [0; 2]
        {
            return Err(ProviderCatalogManifestErrorV1::Noncanonical);
        }
        let generation = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
        );
        let namespace_digest = digest(&bytes[20..52])?;
        let count = u16::from_be_bytes(
            bytes[52..54]
                .try_into()
                .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
        ) as usize;
        if count == 0 || bytes.len() != HEADER_BYTES + count * ROW_BYTES {
            return Err(ProviderCatalogManifestErrorV1::Noncanonical);
        }

        let mut rows = Vec::with_capacity(count);
        for bytes in bytes[HEADER_BYTES..].chunks_exact(ROW_BYTES) {
            let selector = StorageLiveExportSelectorV1::new(
                bytes[144..160]
                    .try_into()
                    .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
                u64::from_be_bytes(
                    bytes[160..168]
                        .try_into()
                        .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
                ),
                bytes[168..200]
                    .try_into()
                    .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
                digest(&bytes[200..232])?,
            )
            .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?;
            rows.push(ProviderCatalogRowV1::new(
                digest(&bytes[0..32])?,
                bytes[32..64]
                    .try_into()
                    .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
                u64::from_be_bytes(
                    bytes[64..72]
                        .try_into()
                        .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
                ),
                digest(&bytes[72..104])?,
                u64::from_be_bytes(
                    bytes[104..112]
                        .try_into()
                        .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?,
                ),
                digest(&bytes[112..144])?,
                selector,
            )?);
        }
        Self::new(generation, namespace_digest, rows)
    }

    /// Encodes the only accepted manifest representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_BYTES + self.rows.len() * ROW_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(self.namespace_digest.as_bytes());
        bytes.extend_from_slice(&(self.rows.len() as u16).to_be_bytes());
        for row in &self.rows {
            bytes.extend_from_slice(row.binding_digest.as_bytes());
            bytes.extend_from_slice(&row.resource_id);
            bytes.extend_from_slice(&row.resource_generation.to_be_bytes());
            bytes.extend_from_slice(row.resource_digest.as_bytes());
            bytes.extend_from_slice(&row.selection_generation.to_be_bytes());
            bytes.extend_from_slice(row.selection_digest.as_bytes());
            bytes.extend_from_slice(&row.selector.export_id());
            bytes.extend_from_slice(&row.selector.export_generation().to_be_bytes());
            bytes.extend_from_slice(&row.selector.workspace_id());
            bytes.extend_from_slice(row.selector.source_assignment_digest().as_bytes());
        }
        bytes
    }

    /// Computes the digest that AOSPCP01 must publish as its catalog head.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Selects a row only under the exact protected current catalog head.
    ///
    /// # Errors
    ///
    /// Rejects a stale/forked head or an absent binding selection.
    pub fn select_current(
        &self,
        expected_generation: u64,
        expected_digest: ObjectDigest,
        expected_namespace: ObjectDigest,
        binding_digest: ObjectDigest,
    ) -> Result<(SourceResourceV1, StorageLiveExportSelectorV1), ProviderCatalogManifestErrorV1>
    {
        if self.generation != expected_generation
            || self.digest() != expected_digest
            || self.namespace_digest != expected_namespace
        {
            return Err(ProviderCatalogManifestErrorV1::NotCurrent);
        }
        let row = self
            .rows
            .iter()
            .find(|row| row.binding_digest == binding_digest)
            .ok_or(ProviderCatalogManifestErrorV1::NoSelection)?;
        let resource = SourceResourceV1::new(
            self.namespace_digest,
            row.resource_id,
            row.resource_generation,
            row.resource_digest,
            self.generation,
            expected_digest,
            row.selection_generation,
            row.selection_digest,
        )
        .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?;
        Ok((resource, row.selector))
    }
}

fn digest(bytes: &[u8]) -> Result<ObjectDigest, ProviderCatalogManifestErrorV1> {
    Ok(ObjectDigest::from_bytes(bytes.try_into().map_err(
        |_| ProviderCatalogManifestErrorV1::Noncanonical,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(binding: u8) -> ProviderCatalogRowV1 {
        ProviderCatalogRowV1::new(
            ObjectDigest::from_bytes([binding; 32]),
            [binding; 32],
            1,
            ObjectDigest::from_bytes([3; 32]),
            1,
            ObjectDigest::from_bytes([4; 32]),
            StorageLiveExportSelectorV1::new(
                [5; 16],
                1,
                [6; 32],
                ObjectDigest::from_bytes([7; 32]),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_selection_rejects_replay_downgrade_and_fork() {
        let namespace = ObjectDigest::from_bytes([8; 32]);
        let manifest = ProviderCatalogManifestV1::new(2, namespace, vec![row(1), row(2)]).unwrap();
        let wire = manifest.to_canonical_bytes();
        let decoded = ProviderCatalogManifestV1::from_canonical_bytes(&wire).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(
            decoded
                .select_current(2, decoded.digest(), namespace, row(2).binding_digest())
                .unwrap()
                .0
                .resource_id(),
            [2; 32]
        );
        assert_eq!(
            decoded
                .select_current(3, decoded.digest(), namespace, row(2).binding_digest())
                .unwrap_err(),
            ProviderCatalogManifestErrorV1::NotCurrent
        );
        assert_eq!(
            decoded
                .select_current(
                    2,
                    ObjectDigest::from_bytes([9; 32]),
                    namespace,
                    row(2).binding_digest()
                )
                .unwrap_err(),
            ProviderCatalogManifestErrorV1::NotCurrent
        );
        let mut fork = wire;
        fork[HEADER_BYTES + 72] ^= 1;
        let fork = ProviderCatalogManifestV1::from_canonical_bytes(&fork).unwrap();
        assert_eq!(
            fork.select_current(2, manifest.digest(), namespace, row(1).binding_digest())
                .unwrap_err(),
            ProviderCatalogManifestErrorV1::NotCurrent
        );
    }

    #[test]
    fn duplicate_unsorted_and_tail_rows_fail_closed() {
        let namespace = ObjectDigest::from_bytes([8; 32]);
        assert_eq!(
            ProviderCatalogManifestV1::new(2, namespace, vec![row(2), row(1)]).unwrap_err(),
            ProviderCatalogManifestErrorV1::Noncanonical
        );
        assert_eq!(
            ProviderCatalogManifestV1::new(2, namespace, vec![row(1), row(1)]).unwrap_err(),
            ProviderCatalogManifestErrorV1::Noncanonical
        );
        let manifest = ProviderCatalogManifestV1::new(2, namespace, vec![row(1)]).unwrap();
        let mut wire = manifest.to_canonical_bytes();
        wire.push(0);
        assert_eq!(
            ProviderCatalogManifestV1::from_canonical_bytes(&wire).unwrap_err(),
            ProviderCatalogManifestErrorV1::Noncanonical
        );
    }
}
