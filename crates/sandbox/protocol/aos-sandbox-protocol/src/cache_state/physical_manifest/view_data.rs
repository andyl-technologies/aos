//! Decodes complete actual object-view manifests through the sole shared DATA recipe.
//!
//! No model here constructs a held physical owner, read authority, pin grant or
//! protected replay capability. The enclosing private F stage retains its own
//! native acquisition and full postchecks before using this comparison DATA.

use aos_sandbox_model::{ObjectDescriptor, ObjectDigest};
use std::collections::{BTreeMap, BTreeSet};

/// Reports the existing physical manifest grammar or capacity refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PhysicalManifestDataErrorV1 {
    /// Rejects an invalid physical limit set.
    #[error("invalid physical Cache limits")]
    InvalidLimits,
    /// Rejects an invalid complete physical manifest.
    #[error("invalid physical Cache manifest")]
    InvalidManifest,
    /// Rejects a manifest exceeding its original limits.
    #[error("physical Cache capacity exhausted")]
    CapacityExhausted,
    /// Rejects an unsafe physical basename.
    #[error("unsafe physical Cache basename")]
    UnsafeName,
    /// Rejects an invalid physical pin identity.
    #[error("invalid physical Cache pin")]
    InvalidPin,
}

/// Carries the deployed physical manifest limits as nonauthorizing DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalManifestLimitsDataV1 {
    /// Bounds the physical memory tier.
    pub maximum_memory_bytes: u64,
    /// Bounds the physical disk tier.
    pub maximum_disk_bytes: u64,
    /// Names the existing disk low-water mark.
    pub disk_low_water_bytes: u64,
    /// Bounds positive manifest entries.
    pub maximum_positive_entries: usize,
    /// Bounds negative manifest entries.
    pub maximum_negative_entries: usize,
    /// Bounds recorded physical pins.
    pub maximum_pins: usize,
    /// Bounds total pinned physical bytes.
    pub maximum_pinned_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ObjectKey {
    partition: ObjectDigest,
    descriptor: ObjectDescriptor,
}

#[derive(Clone)]
struct DiskEntry {
    file_name: String,
    staging_name: Option<String>,
    deleting_name: Option<String>,
    bytes: u64,
    device: u64,
    inode: u64,
    verity: [u8; 32],
    canonical_name: ObjectDigest,
    root_custody: ObjectDigest,
    last_used: u64,
    pins: BTreeSet<PhysicalPinId>,
}

#[derive(Clone, Copy)]
struct NegativeEntry {
    valid_until: u64,
    last_used: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PhysicalPinId([u8; 16]);

impl PhysicalPinId {
    fn from_bytes(bytes: [u8; 16]) -> Result<Self, PhysicalManifestDataErrorV1> {
        crate::cache_state::physical_manifest::validate_owner_pin_bytes_v1(bytes)
            .map(Self)
            .map_err(|_| PhysicalManifestDataErrorV1::InvalidPin)
    }

    fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct NegativeKey(ObjectDigest);

impl NegativeKey {
    fn from_digest(digest: ObjectDigest) -> Result<Self, PhysicalManifestDataErrorV1> {
        crate::cache_state::physical_manifest::validate_negative_key_digest_v1(
            digest,
        )
        .map(Self)
        .map_err(|_| PhysicalManifestDataErrorV1::InvalidManifest)
    }

    fn digest(self) -> ObjectDigest {
        self.0
    }
}

crate::define_cache_physical_manifest_data_recipe_v1!(
    PhysicalManifestDataErrorV1,
    PhysicalManifestLimitsDataV1,
    ObjectKey,
    DiskEntry,
    NegativeKey,
    NegativeEntry,
    PhysicalPinId
);

/// Summarizes an actual canonical complete physical manifest as comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalManifestSnapshotDataV1 {
    /// Identifies the observed manifest generation.
    pub generation: u64,
    /// Hashes the entire canonical manifest bytes.
    pub digest: ObjectDigest,
    /// Counts the actual positive disk entries.
    pub disk_count: u64,
    /// Counts the actual negative entries.
    pub negative_count: u64,
    /// Counts actual recorded pins.
    pub pin_count: u64,
}

/// Retains the sole complete stable physical manifest as passive comparison DATA.
///
/// Construction is confined to the existing complete decoder. These rows grant
/// no native file access or physical owner; real callers retain their own root,
/// named manifest, independent native posts and receiving admission.
pub struct PhysicalManifestInventoryDataV2 {
    snapshot: PhysicalManifestSnapshotDataV1,
    disk: BTreeMap<ObjectKey, DiskEntry>,
    _negatives: BTreeMap<NegativeKey, NegativeEntry>,
}

/// Borrows an exact settled disk entry decoded from the complete manifest.
#[derive(Clone, Copy)]
pub struct PhysicalManifestDiskEntryDataV2<'entry> {
    /// Identifies the complete protected partition.
    pub partition: ObjectDigest,
    /// Borrows the complete immutable object descriptor.
    pub descriptor: &'entry ObjectDescriptor,
    /// Borrows the strict canonical settled basename.
    pub file_name: &'entry str,
    /// Gives the exact saved object byte extent.
    pub bytes: u64,
    /// Gives the saved native device.
    pub device: u64,
    /// Gives the saved native inode.
    pub inode: u64,
    /// Gives the complete saved fs-verity measurement.
    pub verity: [u8; 32],
    /// Commits the canonical protected basename.
    pub canonical_name: ObjectDigest,
    /// Commits the protected original root custody.
    pub root_custody: ObjectDigest,
}

impl PhysicalManifestInventoryDataV2 {
    /// Returns the same whole canonical snapshot without native authority.
    #[must_use]
    pub fn snapshot_v2(&self) -> PhysicalManifestSnapshotDataV1 {
        self.snapshot
    }

    /// Borrows every complete settled disk relation in canonical key order.
    pub fn disk_entries_v2(&self)
        -> impl ExactSizeIterator<Item = PhysicalManifestDiskEntryDataV2<'_>> {
        self.disk.iter().map(|(key, entry)| PhysicalManifestDiskEntryDataV2 {
            partition: key.partition, descriptor: &key.descriptor, file_name: &entry.file_name,
            bytes: entry.bytes, device: entry.device, inode: entry.inode, verity: entry.verity,
            canonical_name: entry.canonical_name, root_custody: entry.root_custody,
        })
    }
}

/// Decodes the sole complete physical manifest and rejects unsettled entries.
///
/// # Errors
/// Rejects malformed framing, invalid names/pins, unsettled staging/deletion or
/// values exceeding the original deployed physical limits.
pub fn decode_actual_manifest_v1(
    bytes: &[u8],
    limits: PhysicalManifestLimitsDataV1,
) -> Result<PhysicalManifestSnapshotDataV1, PhysicalManifestDataErrorV1> {
    decode_actual_manifest_inventory_v2(bytes, limits).map(|inventory| inventory.snapshot_v2())
}

/// Retains all rows from the same complete stable manifest decoder.
///
/// The caller pays the actual byte/map/pin/name peak before entry and keeps this
/// historical model alongside its own genuine native original. No unknown row,
/// unsettled entry, capacity or canonical framing predicate is relaxed.
///
/// # Errors
/// Returns the same exact full-manifest grammar, settlement and capacity errors.
pub fn decode_actual_manifest_inventory_v2(
    bytes: &[u8], limits: PhysicalManifestLimitsDataV1,
) -> Result<PhysicalManifestInventoryDataV2, PhysicalManifestDataErrorV1> {
    use crate::cache_state::physical_manifest::{Digest as _, Sha256};
    let (generation, disk, negatives) = decode_manifest(bytes, limits)?;
    // A staging or deleting inventory is not a stable signed snapshot. The
    // same existing Native readback refuses that unresolved physical state.
    if disk
        .values()
        .any(|entry| entry.staging_name.is_some() || entry.deleting_name.is_some())
    {
        return Err(PhysicalManifestDataErrorV1::InvalidManifest);
    }
    let pin_count = disk.values().try_fold(0_u64, |count, entry| {
        count
            .checked_add(
                u64::try_from(entry.pins.len())
                    .map_err(|_| PhysicalManifestDataErrorV1::CapacityExhausted)?,
            )
            .ok_or(PhysicalManifestDataErrorV1::CapacityExhausted)
    })?;
    let snapshot = PhysicalManifestSnapshotDataV1 {
        generation,
        digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
        disk_count: u64::try_from(disk.len())
            .map_err(|_| PhysicalManifestDataErrorV1::CapacityExhausted)?,
        negative_count: u64::try_from(negatives.len())
            .map_err(|_| PhysicalManifestDataErrorV1::CapacityExhausted)?,
        pin_count,
    };
    Ok(PhysicalManifestInventoryDataV2 { snapshot, disk, _negatives: negatives })
}

impl PhysicalManifestLimitsDataV1 {
    /// Hashes the same seven physical limit fields through the canonical recipe.
    ///
    /// # Errors
    /// Rejects a cardinality that cannot be represented in the wire grammar.
    pub fn digest_v1(self) -> Result<ObjectDigest, PhysicalManifestDataErrorV1> {
        let positive = u64::try_from(self.maximum_positive_entries)
            .map_err(|_| PhysicalManifestDataErrorV1::InvalidLimits)?;
        let negative = u64::try_from(self.maximum_negative_entries)
            .map_err(|_| PhysicalManifestDataErrorV1::InvalidLimits)?;
        let pins = u64::try_from(self.maximum_pins)
            .map_err(|_| PhysicalManifestDataErrorV1::InvalidLimits)?;
        Ok(crate::cache_state::physical_manifest::cache_physical_limit_fields_digest_v1([
            self.maximum_memory_bytes, self.maximum_disk_bytes, self.disk_low_water_bytes,
            positive, negative, pins, self.maximum_pinned_bytes,
        ]))
    }
}

/// Prices the actual manifest byte extent and one simultaneously decoded map.
///
/// Before and after raw bytes remain resident. The maps and their owned names
/// have the existing parser's sequential scope, so one complete node peak is
/// sufficient. Every pin consumes at least sixteen encoded bytes; every disk
/// or negative row consumes more. That same bound covers the aggregate map
/// and nested pin-set entries without multiplying configured quota maxima.
pub fn dynamic_receiving_demand_v1(
    length: usize,
) -> Option<aos_sandbox_model::ResourceVector> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
    let entries = length / 16;
    let node_bytes = nodes::<ObjectKey, DiskEntry>(entries)?
        .max(nodes::<NegativeKey, NegativeEntry>(entries)?)
        .max(nodes::<PhysicalPinId, ()>(entries)?);
    // Two retained byte owners, owned strings and their conversion/growth
    // overlap. The fixed typed owners are covered before native preparation.
    let construction = std::mem::size_of::<PhysicalManifestInventoryDataV2>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<(ObjectKey, DiskEntry)>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<(NegativeKey, NegativeEntry)>().checked_mul(2)?)?
        .checked_add(
            std::mem::size_of::<(
                u64,
                BTreeMap<ObjectKey, DiskEntry>,
                BTreeMap<NegativeKey, NegativeEntry>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(std::mem::size_of::<ObjectDescriptor>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<u64>().checked_mul(16)?)?;
    let memory = length
        .checked_mul(5)?
        .checked_add(node_bytes)?
        .checked_add(construction)?;
    Some(
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::MetadataEntries, u64::try_from(entries).ok()?),
    )
}

pub fn quota_derivation_receiving_demand_v1(
    rows: usize,
) -> Option<aos_sandbox_model::ResourceVector> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    let nodes =
        aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<[u8; 32], ()>(rows)?;
    let construction = std::mem::size_of::<crate::cache_state::NodeCacheQuotaV1>()
        .checked_mul(2)?
        .checked_add(std::mem::size_of::<BTreeSet<[u8; 32]>>())?
        .checked_add(std::mem::size_of::<PhysicalManifestLimitsDataV1>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<u64>().checked_mul(8)?)?;
    let memory = nodes.checked_add(construction)?;
    Some(
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::MetadataEntries, u64::try_from(rows).ok()?),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::MediaType;
    use aos_sandbox_model::registry::PortableMediaType;

    fn fixture(staging: Option<&str>) -> (Vec<u8>, PhysicalManifestLimitsDataV1, ObjectDescriptor) {
        let descriptor = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::Snapshot.as_str()).unwrap(),
            ObjectDigest::from_bytes([7; 32]), 128,
        );
        let disk = BTreeMap::from([(
            ObjectKey { partition: ObjectDigest::from_bytes([3; 32]), descriptor: descriptor.clone() },
            DiskEntry { file_name: "snapshot.cbor".into(), staging_name: staging.map(str::to_owned),
                deleting_name: None, bytes: 128, device: 11, inode: 12, verity: [13; 32],
                canonical_name: ObjectDigest::from_bytes([14; 32]),
                root_custody: ObjectDigest::from_bytes([15; 32]), last_used: 16, pins: BTreeSet::new() },
        )]);
        let limits = PhysicalManifestLimitsDataV1 { maximum_memory_bytes: 512,
            maximum_disk_bytes: 1024, disk_low_water_bytes: 512, maximum_positive_entries: 8,
            maximum_negative_entries: 8, maximum_pins: 8, maximum_pinned_bytes: 1024 };
        (encode_manifest(5, &disk, &BTreeMap::new()).unwrap(), limits, descriptor)
    }

    #[test]
    fn full_catalog_preserves_the_canonical_native_object_preimage() {
        let (bytes, limits, descriptor) = fixture(None);
        let ordinary = decode_actual_manifest_v1(&bytes, limits).unwrap();
        let inventory = decode_actual_manifest_inventory_v2(&bytes, limits).unwrap();

        assert_eq!(inventory.snapshot_v2(), ordinary);
        let mut entries = inventory.disk_entries_v2();
        let entry = entries.next().unwrap();
        assert!(entries.next().is_none());
        assert_eq!(entry.partition, ObjectDigest::from_bytes([3; 32]));
        assert_eq!(entry.descriptor, &descriptor);
        assert_eq!(entry.file_name, "snapshot.cbor");
        assert_eq!((entry.bytes, entry.device, entry.inode), (128, 11, 12));
        assert_eq!(entry.verity, [13; 32]);
        assert_eq!(entry.canonical_name, ObjectDigest::from_bytes([14; 32]));
        assert_eq!(entry.root_custody, ObjectDigest::from_bytes([15; 32]));
    }

    #[test]
    fn unsettled_or_mutated_manifest_never_yields_a_catalog() {
        let (unsettled, limits, _) = fixture(Some(".admit-incomplete.tmp"));
        assert!(matches!(decode_actual_manifest_inventory_v2(&unsettled, limits),
            Err(PhysicalManifestDataErrorV1::InvalidManifest)));
        assert_eq!(decode_actual_manifest_v1(&unsettled, limits),
            Err(PhysicalManifestDataErrorV1::InvalidManifest));

        let (mut corrupted, limits, _) = fixture(None);
        let last = corrupted.last_mut().unwrap();
        *last ^= 1;
        assert!(matches!(decode_actual_manifest_inventory_v2(&corrupted, limits),
            Err(PhysicalManifestDataErrorV1::InvalidManifest)));
        assert_eq!(decode_actual_manifest_v1(&corrupted, limits),
            Err(PhysicalManifestDataErrorV1::InvalidManifest));
    }
}
