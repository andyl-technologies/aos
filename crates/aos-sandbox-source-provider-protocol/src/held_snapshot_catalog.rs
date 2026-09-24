//! Canonical, nonauthorizing selection of a native held ZFS snapshot.
//!
//! `AOSPCM01` rows name only LocalLive exports. This separate format reserves
//! an exact native snapshot selector without making it a current Provider
//! catalog, a Storage hold observation, or a SourceRoot acquisition. No owner
//! publishes or consumes this format for production admission yet.
//!
//! ```text
//! AOSPCZ01 | version:u16be=1 | reserved:u16be=0 |
//! catalog-generation:u64be | namespace-digest[32] | row-count:u16be |
//! row[count] = binding-digest[32] | resource-id[32] |
//! resource-generation:u64be | resource-digest[32] |
//! selection-generation:u64be | selection-digest[32] |
//! storage-handle[32] | storage-version:u64be | pool-guid:u64be |
//! dataset-guid:u64be | snapshot-guid:u64be | hold-id[16] |
//! hold-generation:u64be | active-hold-digest[32] |
//! root-policy-digest[32] | read-only-content-digest[32]
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::{ProviderCatalogManifestErrorV1, SourceResourceV1, ZfsHeldSnapshotProofV1};

const MAGIC: &[u8; 8] = b"AOSPCZ01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 54;
const ROW_BYTES: usize = 328;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.provider.held-snapshot-catalog.v1\0";

/// Maximum number of rows in one native held-snapshot catalog claim.
pub const MAXIMUM_HELD_SNAPSHOT_CATALOG_ROWS_V1: usize = 64;

/// Binds one logical source to one claimed native held snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHeldSnapshotRowV1 {
    binding_digest: ObjectDigest,
    resource_id: [u8; 32],
    resource_generation: u64,
    resource_digest: ObjectDigest,
    selection_generation: u64,
    selection_digest: ObjectDigest,
    snapshot: ZfsHeldSnapshotProofV1,
}

impl ProviderHeldSnapshotRowV1 {
    /// Constructs one complete, non-sentinel native selection claim.
    ///
    /// # Errors
    ///
    /// Rejects zero binding, resource, or selection fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding_digest: ObjectDigest,
        resource_id: [u8; 32],
        resource_generation: u64,
        resource_digest: ObjectDigest,
        selection_generation: u64,
        selection_digest: ObjectDigest,
        snapshot: ZfsHeldSnapshotProofV1,
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
            snapshot,
        })
    }

    /// Returns the authenticated logical binding this row would select.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the claimed snapshot proof for independent physical readback.
    #[must_use]
    pub const fn snapshot(&self) -> &ZfsHeldSnapshotProofV1 {
        &self.snapshot
    }
}

/// Owns one bounded, canonical native snapshot row set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHeldSnapshotCatalogV1 {
    generation: u64,
    namespace_digest: ObjectDigest,
    rows: Vec<ProviderHeldSnapshotRowV1>,
}

impl ProviderHeldSnapshotCatalogV1 {
    /// Constructs a nonempty row set ordered by logical binding.
    ///
    /// # Errors
    ///
    /// Rejects sentinel metadata, excess rows, duplicates, and unsorted rows.
    pub fn new(
        generation: u64,
        namespace_digest: ObjectDigest,
        rows: Vec<ProviderHeldSnapshotRowV1>,
    ) -> Result<Self, ProviderCatalogManifestErrorV1> {
        if generation == 0
            || namespace_digest.as_bytes() == &[0; 32]
            || rows.is_empty()
            || rows.len() > MAXIMUM_HELD_SNAPSHOT_CATALOG_ROWS_V1
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

    /// Decodes exactly one canonical native snapshot row set.
    ///
    /// # Errors
    ///
    /// Rejects wrong magic, version, padding, length, ordering, and sentinels.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProviderCatalogManifestErrorV1> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > HEADER_BYTES + MAXIMUM_HELD_SNAPSHOT_CATALOG_ROWS_V1 * ROW_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(10..12) != Some([0; 2].as_slice())
        {
            return Err(ProviderCatalogManifestErrorV1::Noncanonical);
        }
        let generation = number(bytes, 12)?;
        let namespace_digest = digest(bytes, 20)?;
        let count = u16::from_be_bytes(array(bytes, 52)?) as usize;
        if count == 0 || bytes.len() != HEADER_BYTES + count * ROW_BYTES {
            return Err(ProviderCatalogManifestErrorV1::Noncanonical);
        }

        let mut rows = Vec::with_capacity(count);
        for bytes in bytes[HEADER_BYTES..].chunks_exact(ROW_BYTES) {
            let snapshot = ZfsHeldSnapshotProofV1::new(
                array(bytes, 144)?,
                number(bytes, 176)?,
                number(bytes, 184)?,
                number(bytes, 192)?,
                number(bytes, 200)?,
                array(bytes, 208)?,
                number(bytes, 224)?,
                digest(bytes, 232)?,
                digest(bytes, 264)?,
                digest(bytes, 296)?,
            )
            .map_err(|_| ProviderCatalogManifestErrorV1::Noncanonical)?;
            rows.push(ProviderHeldSnapshotRowV1::new(
                digest(bytes, 0)?,
                array(bytes, 32)?,
                number(bytes, 64)?,
                digest(bytes, 72)?,
                number(bytes, 104)?,
                digest(bytes, 112)?,
                snapshot,
            )?);
        }
        Self::new(generation, namespace_digest, rows)
    }

    /// Encodes the sole canonical native snapshot row representation.
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
            bytes.extend_from_slice(&row.snapshot.storage_handle());
            bytes.extend_from_slice(&row.snapshot.storage_version().to_be_bytes());
            bytes.extend_from_slice(&row.snapshot.pool_guid().to_be_bytes());
            bytes.extend_from_slice(&row.snapshot.dataset_guid().to_be_bytes());
            bytes.extend_from_slice(&row.snapshot.snapshot_guid().to_be_bytes());
            bytes.extend_from_slice(&row.snapshot.hold_id());
            bytes.extend_from_slice(&row.snapshot.hold_generation().to_be_bytes());
            bytes.extend_from_slice(row.snapshot.active_hold_digest().as_bytes());
            bytes.extend_from_slice(row.snapshot.root_policy_digest().as_bytes());
            bytes.extend_from_slice(row.snapshot.read_only_content_digest().as_bytes());
        }
        bytes
    }

    /// Commits the exact canonical bytes under a native-only digest domain.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Resolves one row against a caller-supplied catalog head.
    ///
    /// This check cannot establish that the head is protected or current. The
    /// present production owner accepts only `AOSPCM01`, so this result cannot
    /// authorize a backend effect or a SourceRoot response.
    ///
    /// # Errors
    ///
    /// Rejects a differing head or absent logical binding.
    pub fn select_under_head(
        &self,
        expected_generation: u64,
        expected_digest: ObjectDigest,
        expected_namespace: ObjectDigest,
        binding_digest: ObjectDigest,
    ) -> Result<(SourceResourceV1, ZfsHeldSnapshotProofV1), ProviderCatalogManifestErrorV1> {
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
        Ok((resource, row.snapshot.clone()))
    }
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProviderCatalogManifestErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProviderCatalogManifestErrorV1::Noncanonical)
}

fn number(bytes: &[u8], offset: usize) -> Result<u64, ProviderCatalogManifestErrorV1> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}

fn digest(bytes: &[u8], offset: usize) -> Result<ObjectDigest, ProviderCatalogManifestErrorV1> {
    Ok(ObjectDigest::from_bytes(array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn row(binding: u8) -> ProviderHeldSnapshotRowV1 {
        let snapshot = ZfsHeldSnapshotProofV1::new(
            [7; 32],
            8,
            9,
            10,
            11,
            [12; 16],
            13,
            digest(14),
            digest(15),
            digest(16),
        )
        .unwrap();
        ProviderHeldSnapshotRowV1::new(
            digest(binding),
            [2; 32],
            3,
            digest(4),
            5,
            digest(6),
            snapshot,
        )
        .unwrap()
    }

    #[test]
    fn native_rows_round_trip_and_select_only_under_exact_head() {
        let catalog =
            ProviderHeldSnapshotCatalogV1::new(17, digest(18), vec![row(1), row(2)]).unwrap();
        let bytes = catalog.to_canonical_bytes();
        assert_eq!(bytes.len(), HEADER_BYTES + 2 * ROW_BYTES);
        assert_eq!(
            ProviderHeldSnapshotCatalogV1::from_canonical_bytes(&bytes),
            Ok(catalog.clone())
        );

        let (resource, snapshot) = catalog
            .select_under_head(17, catalog.digest(), digest(18), digest(2))
            .unwrap();
        assert_eq!(resource.resource_id(), [2; 32]);
        assert_eq!(snapshot.snapshot_guid(), 11);
        assert_eq!(
            catalog.select_under_head(17, digest(19), digest(18), digest(2)),
            Err(ProviderCatalogManifestErrorV1::NotCurrent)
        );
    }

    #[test]
    fn native_rows_reject_legacy_class_confusion_and_ambiguous_selection() {
        let catalog = ProviderHeldSnapshotCatalogV1::new(17, digest(18), vec![row(1)]).unwrap();
        let bytes = catalog.to_canonical_bytes();
        assert_eq!(
            crate::ProviderCatalogManifestV1::from_canonical_bytes(&bytes),
            Err(ProviderCatalogManifestErrorV1::Noncanonical)
        );
        assert_eq!(
            ProviderHeldSnapshotCatalogV1::new(17, digest(18), vec![row(1), row(1)]),
            Err(ProviderCatalogManifestErrorV1::Noncanonical)
        );
        let mut truncated = bytes.clone();
        truncated.pop();
        assert_eq!(
            ProviderHeldSnapshotCatalogV1::from_canonical_bytes(&truncated),
            Err(ProviderCatalogManifestErrorV1::Noncanonical)
        );
        let mut sentinel_hold = bytes;
        sentinel_hold[HEADER_BYTES + 208..HEADER_BYTES + 224].fill(0);
        assert_eq!(
            ProviderHeldSnapshotCatalogV1::from_canonical_bytes(&sentinel_hold),
            Err(ProviderCatalogManifestErrorV1::Noncanonical)
        );
    }
}
