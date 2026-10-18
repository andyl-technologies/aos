//! Canonical physical formats for the packed content-store leaf.
//!
//! This module owns strict v1 pack manifests, generation-bound v2 repack
//! plans, and the fixed-width binary record encodings shared by the index
//! base, pack table, and journal. All decoders reject trailing data and every
//! checksum is domain-separated from logical [`ContentId`] identity.
//!
//! Fixed-width records encode a [`ContentId`] as 37 bytes:
//!
//! ```text
//! object_kind_code_u8      # 0 campaign-fact through 13 trace
//! schema_version_u32
//! content_digest[32]
//! ```
//!
//! Codes follow [`ObjectKind`] declaration order, so the byte order of an
//! encoded identity equals the derived `Ord` of [`ContentId`].

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::{
    ContentId, IndexEntry, MAX_PACK_BYTES, MAX_PACK_ENTRIES, ObjectKind, PACK_ID_DOMAIN,
    PACK_MAGIC, PACK_MANIFEST_DOMAIN, PackId, PackManifestEntry, PackedRepackPlan,
    PackedRepackPlanId, PackedStorageAccounting, REPACK_PLAN_CHECKSUM_DOMAIN,
    REPACK_PLAN_ID_DOMAIN, REPACK_PLAN_MAGIC, StoreError,
};

/// Encoded width of one binary [`ContentId`].
pub(super) const CONTENT_ID_BYTES: usize = 1 + 4 + 32;

/// Upper bound on one pack's encoded manifest.
///
/// Canonical content-ID text is at most 93 bytes, so 128 bytes per identity
/// leaves headroom without letting a corrupt header request a large buffer.
const MAX_PACK_MANIFEST_BYTES: u64 = MAX_PACK_ENTRIES as u64 * (2 + 128 + 16);

/// Returns the registered fixed-width record code of `kind`.
///
/// The match is exhaustive, so a new [`ObjectKind`] cannot be encoded until it
/// receives a code here and in [`object_kind_from_code`].
const fn object_kind_code(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::CampaignFact => 0,
        ObjectKind::CampaignSnapshot => 1,
        ObjectKind::MerkleNode => 2,
        ObjectKind::Scenario => 3,
        ObjectKind::Configuration => 4,
        ObjectKind::Policy => 5,
        ObjectKind::ExactManifest => 6,
        ObjectKind::RamExtent => 7,
        ObjectKind::DiskExtent => 8,
        ObjectKind::DeviceState => 9,
        ObjectKind::Observation => 10,
        ObjectKind::Finding => 11,
        ObjectKind::Projection => 12,
        ObjectKind::Trace => 13,
    }
}

/// Inverts [`object_kind_code`]; unknown codes indicate a corrupt record.
const fn object_kind_from_code(code: u8) -> Option<ObjectKind> {
    Some(match code {
        0 => ObjectKind::CampaignFact,
        1 => ObjectKind::CampaignSnapshot,
        2 => ObjectKind::MerkleNode,
        3 => ObjectKind::Scenario,
        4 => ObjectKind::Configuration,
        5 => ObjectKind::Policy,
        6 => ObjectKind::ExactManifest,
        7 => ObjectKind::RamExtent,
        8 => ObjectKind::DiskExtent,
        9 => ObjectKind::DeviceState,
        10 => ObjectKind::Observation,
        11 => ObjectKind::Finding,
        12 => ObjectKind::Projection,
        13 => ObjectKind::Trace,
        _ => return None,
    })
}

/// Writes the fixed-width binary form of `id` into `output`.
pub(super) fn encode_content_id(id: ContentId, output: &mut [u8; CONTENT_ID_BYTES]) {
    output[0] = object_kind_code(id.kind());
    output[1..5].copy_from_slice(&id.schema_version().to_be_bytes());
    output[5..].copy_from_slice(&id.digest());
}

/// Decodes one fixed-width binary [`ContentId`].
pub(super) fn decode_content_id(bytes: &[u8]) -> Result<ContentId, StoreError> {
    let bytes: &[u8; CONTENT_ID_BYTES] = bytes.try_into().map_err(|_| StoreError::Incompatible)?;
    let kind = object_kind_from_code(bytes[0]).ok_or(StoreError::Incompatible)?;
    let mut cursor = PackedCursor::new(&bytes[1..]);
    Ok(ContentId {
        kind,
        schema_version: cursor.u32()?,
        digest: cursor.array_32()?,
    })
}

/// Validates one index entry's pack geometry.
pub(super) fn validate_index_entry(entry: IndexEntry) -> Result<(), StoreError> {
    if entry
        .offset
        .checked_add(entry.length)
        .is_none_or(|end| end > MAX_PACK_BYTES)
    {
        return Err(StoreError::Incompatible);
    }
    Ok(())
}

pub(super) fn new_repack_plan(
    configuration: [u8; 32],
    instance: [u8; 32],
    generation: u64,
    root_digest: [u8; 32],
    before: PackedStorageAccounting,
) -> PackedRepackPlan {
    let mut plan = PackedRepackPlan {
        id: PackedRepackPlanId([0; 32]),
        configuration,
        instance,
        generation,
        root_digest,
        before,
    };
    plan.id = repack_plan_id(&encode_repack_plan(&plan));
    plan
}

pub(super) fn encode_repack_plan(plan: &PackedRepackPlan) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REPACK_PLAN_MAGIC.len() + 32 * 4 + 8 * 6);
    bytes.extend_from_slice(REPACK_PLAN_MAGIC);
    bytes.extend_from_slice(&plan.configuration);
    bytes.extend_from_slice(&plan.instance);
    bytes.extend_from_slice(&plan.generation.to_be_bytes());
    bytes.extend_from_slice(&plan.root_digest);
    bytes.extend_from_slice(&plan.before.generation.to_be_bytes());
    bytes.extend_from_slice(&plan.before.logical_objects.to_be_bytes());
    bytes.extend_from_slice(&plan.before.logical_bytes.to_be_bytes());
    bytes.extend_from_slice(&plan.before.packs.to_be_bytes());
    bytes.extend_from_slice(&plan.before.physical_bytes.to_be_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(REPACK_PLAN_CHECKSUM_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}

pub(super) fn decode_repack_plan(bytes: &[u8]) -> Result<PackedRepackPlan, StoreError> {
    let exact_length = REPACK_PLAN_MAGIC.len() + 32 + 32 + 8 + 32 + 8 * 5 + 32;
    if bytes.len() != exact_length {
        return Err(StoreError::Incompatible);
    }
    let checksum_offset = bytes.len() - 32;
    let (payload, checksum) = bytes.split_at(checksum_offset);
    let mut hasher = blake3::Hasher::new();
    hasher.update(REPACK_PLAN_CHECKSUM_DOMAIN);
    hasher.update(payload);
    if hasher.finalize().as_bytes() != checksum {
        return Err(StoreError::Incompatible);
    }

    let mut cursor = PackedCursor::new(payload);
    if cursor.fixed(REPACK_PLAN_MAGIC.len())? != REPACK_PLAN_MAGIC {
        return Err(StoreError::Incompatible);
    }
    let configuration = cursor.array_32()?;
    let instance = cursor.array_32()?;
    let generation = cursor.u64()?;
    let root_digest = cursor.array_32()?;
    let before = PackedStorageAccounting {
        generation: cursor.u64()?,
        logical_objects: cursor.u64()?,
        logical_bytes: cursor.u64()?,
        packs: cursor.u64()?,
        physical_bytes: cursor.u64()?,
    };
    if !cursor.is_empty() || generation != before.generation {
        return Err(StoreError::Incompatible);
    }
    validate_repack_accounting(before)?;
    Ok(new_repack_plan(
        configuration,
        instance,
        generation,
        root_digest,
        before,
    ))
}

/// Checks the structural relationships every authentic accounting satisfies.
///
/// Object and pack counts have no store-wide ceiling; each pack is still
/// bounded by [`MAX_PACK_BYTES`], which bounds referenced physical bytes.
fn validate_repack_accounting(accounting: PackedStorageAccounting) -> Result<(), StoreError> {
    let physical_bound_exceeded = accounting
        .packs
        .checked_mul(MAX_PACK_BYTES)
        .is_some_and(|maximum| accounting.physical_bytes > maximum);
    if accounting.packs > accounting.logical_objects
        || accounting.logical_bytes > accounting.physical_bytes
        || physical_bound_exceeded
        || (accounting.logical_objects != 0 && accounting.packs == 0)
        || (accounting.logical_objects == 0
            && (accounting.logical_bytes != 0
                || accounting.packs != 0
                || accounting.physical_bytes != 0))
        || (accounting.packs == 0 && accounting.physical_bytes != 0)
        || (accounting.packs != 0 && accounting.physical_bytes == 0)
    {
        return Err(StoreError::Incompatible);
    }
    Ok(())
}

fn repack_plan_id(bytes: &[u8]) -> PackedRepackPlanId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REPACK_PLAN_ID_DOMAIN);
    hasher.update(bytes);
    PackedRepackPlanId(*hasher.finalize().as_bytes())
}

pub(super) fn encode_pack_manifest(entries: &[PackManifestEntry]) -> Result<Vec<u8>, StoreError> {
    if entries.is_empty() || entries.len() > MAX_PACK_ENTRIES {
        return Err(StoreError::Quota);
    }
    let mut bytes = Vec::new();
    for entry in entries {
        let id = entry.id.to_string();
        let id_length = u16::try_from(id.len()).map_err(|_| StoreError::Quota)?;
        bytes.extend_from_slice(&id_length.to_be_bytes());
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&entry.offset.to_be_bytes());
        bytes.extend_from_slice(&entry.length.to_be_bytes());
    }
    Ok(bytes)
}

pub(super) fn write_pack_header(
    output: &mut File,
    configuration: [u8; 32],
    entries: &[PackManifestEntry],
    manifest: &[u8],
) -> Result<(), StoreError> {
    let entry_count = u32::try_from(entries.len()).map_err(|_| StoreError::Quota)?;
    let manifest_length = u32::try_from(manifest.len()).map_err(|_| StoreError::Quota)?;
    output
        .write_all(PACK_MAGIC)
        .and_then(|()| output.write_all(&configuration))
        .and_then(|()| output.write_all(&entry_count.to_be_bytes()))
        .and_then(|()| output.write_all(&manifest_length.to_be_bytes()))
        .and_then(|()| output.write_all(manifest))
        .map_err(|source| StoreError::StreamIo {
            operation: "write packed manifest",
            source,
        })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PACK_MANIFEST_DOMAIN);
    hasher.update(PACK_MAGIC);
    hasher.update(&configuration);
    hasher.update(&entry_count.to_be_bytes());
    hasher.update(&manifest_length.to_be_bytes());
    hasher.update(manifest);
    output
        .write_all(hasher.finalize().as_bytes())
        .map_err(|source| StoreError::StreamIo {
            operation: "write packed manifest checksum",
            source,
        })
}

pub(super) fn read_pack_header(
    input: &mut File,
    configuration: [u8; 32],
) -> Result<Vec<PackManifestEntry>, StoreError> {
    input
        .seek(SeekFrom::Start(0))
        .map_err(|source| StoreError::StreamIo {
            operation: "seek packed manifest",
            source,
        })?;
    let mut fixed = vec![0_u8; PACK_MAGIC.len() + 32 + 4 + 4];
    input
        .read_exact(&mut fixed)
        .map_err(|_| StoreError::Incompatible)?;
    let mut cursor = PackedCursor::new(&fixed);
    if cursor.fixed(PACK_MAGIC.len())? != PACK_MAGIC || cursor.array_32()? != configuration {
        return Err(StoreError::Incompatible);
    }
    let count = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
    let manifest_length = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
    if count == 0
        || count > MAX_PACK_ENTRIES
        || u64::try_from(manifest_length).map_err(|_| StoreError::Quota)? > MAX_PACK_MANIFEST_BYTES
    {
        return Err(StoreError::Incompatible);
    }
    let mut manifest = vec![0_u8; manifest_length];
    input
        .read_exact(&mut manifest)
        .map_err(|_| StoreError::Incompatible)?;
    let mut checksum = [0_u8; 32];
    input
        .read_exact(&mut checksum)
        .map_err(|_| StoreError::Incompatible)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PACK_MANIFEST_DOMAIN);
    hasher.update(&fixed);
    hasher.update(&manifest);
    if *hasher.finalize().as_bytes() != checksum {
        return Err(StoreError::Incompatible);
    }
    let entries = decode_pack_manifest(&manifest, count)?;
    let header_length = u64::try_from(fixed.len())
        .map_err(|_| StoreError::Quota)?
        .checked_add(u64::try_from(manifest.len()).map_err(|_| StoreError::Quota)?)
        .and_then(|value| value.checked_add(32))
        .ok_or(StoreError::Quota)?;
    if entries
        .first()
        .is_none_or(|entry| entry.offset != header_length)
    {
        return Err(StoreError::Incompatible);
    }
    Ok(entries)
}

fn decode_pack_manifest(
    manifest: &[u8],
    count: usize,
) -> Result<Vec<PackManifestEntry>, StoreError> {
    let mut cursor = PackedCursor::new(manifest);
    let mut entries = Vec::with_capacity(count);
    let mut prior = None;
    let mut prior_end = None;
    for _ in 0..count {
        let id_length = usize::from(cursor.u16()?);
        let id = std::str::from_utf8(cursor.fixed(id_length)?)
            .map_err(|_| StoreError::Incompatible)
            .and_then(|id| ContentId::parse(id).map_err(|_| StoreError::Incompatible))?;
        let offset = cursor.u64()?;
        let length = cursor.u64()?;
        if prior.is_some_and(|prior| id <= prior) || prior_end.is_some_and(|end| offset != end) {
            return Err(StoreError::Incompatible);
        }
        prior = Some(id);
        prior_end = offset.checked_add(length);
        if prior_end.is_none() {
            return Err(StoreError::Incompatible);
        }
        entries.push(PackManifestEntry { id, offset, length });
    }
    if !cursor.is_empty() {
        return Err(StoreError::Incompatible);
    }
    Ok(entries)
}

pub(super) fn pack_id(configuration: [u8; 32], manifest: &[u8]) -> PackId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PACK_ID_DOMAIN);
    hasher.update(&configuration);
    hasher.update(manifest);
    PackId(*hasher.finalize().as_bytes())
}

pub(super) fn pack_fixed_header_length() -> u64 {
    PACK_MAGIC.len() as u64 + 32 + 4 + 4 + 32
}

/// Strict forward reader over one bounded byte slice.
pub(super) struct PackedCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> PackedCursor<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(super) fn fixed(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(StoreError::Incompatible)?;
        let bytes = &self.bytes[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    pub(super) fn array_32(&mut self) -> Result<[u8; 32], StoreError> {
        self.fixed(32)?
            .try_into()
            .map_err(|_| StoreError::Incompatible)
    }

    pub(super) fn u8(&mut self) -> Result<u8, StoreError> {
        self.fixed(1)?
            .first()
            .copied()
            .ok_or(StoreError::Incompatible)
    }

    pub(super) fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(
            self.fixed(2)?
                .try_into()
                .map_err(|_| StoreError::Incompatible)?,
        ))
    }

    pub(super) fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(
            self.fixed(4)?
                .try_into()
                .map_err(|_| StoreError::Incompatible)?,
        ))
    }

    pub(super) fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(
            self.fixed(8)?
                .try_into()
                .map_err(|_| StoreError::Incompatible)?,
        ))
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn binary_content_ids_round_trip_and_preserve_identity_order() {
        let mut encoded = Vec::new();
        for code in 0..=u8::MAX {
            let Some(kind) = object_kind_from_code(code) else {
                continue;
            };
            assert_eq!(object_kind_code(kind), code);
            for schema_version in [0, 1, u32::MAX] {
                let id = ContentId::for_bytes(kind, schema_version, &[code]);
                let mut bytes = [0_u8; CONTENT_ID_BYTES];
                encode_content_id(id, &mut bytes);
                assert_eq!(decode_content_id(&bytes).expect("decode content id"), id);
                encoded.push((bytes, id));
            }
        }

        let mut by_bytes = encoded.clone();
        by_bytes.sort_by_key(|(bytes, _id)| *bytes);
        let mut by_identity = encoded;
        by_identity.sort_by_key(|(_bytes, id)| *id);
        assert_eq!(by_bytes, by_identity);

        assert_eq!(by_bytes.len(), 14 * 3);
        let mut unknown = [0_u8; CONTENT_ID_BYTES];
        unknown[0] = 14;
        assert!(matches!(
            decode_content_id(&unknown),
            Err(StoreError::Incompatible)
        ));
    }
}
