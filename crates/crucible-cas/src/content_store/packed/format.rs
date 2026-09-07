//! Canonical physical formats for the packed content-store leaf.
//!
//! This module owns strict v1 pack manifests, durable index bodies, and
//! generation-bound repack plans. All decoders reject trailing data and every
//! checksum is domain-separated from logical [`ContentId`] identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::{
    ContentId, INDEX_CHECKSUM_DOMAIN, INDEX_DIGEST_DOMAIN, INDEX_MAGIC, IndexEntry, IndexState,
    MAX_INDEX_BYTES, MAX_LOGICAL_OBJECTS, MAX_PACK_BYTES, MAX_PACK_ENTRIES, MAX_PACKS,
    PACK_ID_DOMAIN, PACK_MAGIC, PACK_MANIFEST_DOMAIN, PackId, PackManifestEntry, PackedRepackPlan,
    PackedRepackPlanId, PackedStorageAccounting, REPACK_PLAN_CHECKSUM_DOMAIN,
    REPACK_PLAN_ID_DOMAIN, REPACK_PLAN_MAGIC, StoreError,
};

pub(super) fn encode_index(
    index: &IndexState,
    configuration: [u8; 32],
) -> Result<Vec<u8>, StoreError> {
    if index.entries.len() > MAX_LOGICAL_OBJECTS || index.pack_ids().len() > MAX_PACKS {
        return Err(StoreError::Quota);
    }
    let entry_count = u32::try_from(index.entries.len()).map_err(|_| StoreError::Quota)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INDEX_MAGIC);
    bytes.extend_from_slice(&configuration);
    bytes.extend_from_slice(&index.instance);
    bytes.extend_from_slice(&index.generation.to_be_bytes());
    match index.last_repack_plan {
        None => bytes.push(0),
        Some(plan) => {
            bytes.push(1);
            bytes.extend_from_slice(&plan.0);
        }
    }
    bytes.extend_from_slice(&entry_count.to_be_bytes());
    for (id, entry) in &index.entries {
        let id = id.to_string();
        let id_length = u16::try_from(id.len()).map_err(|_| StoreError::Quota)?;
        bytes.extend_from_slice(&id_length.to_be_bytes());
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&entry.pack.0);
        bytes.extend_from_slice(&entry.offset.to_be_bytes());
        bytes.extend_from_slice(&entry.length.to_be_bytes());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(INDEX_CHECKSUM_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    Ok(bytes)
}

pub(super) fn decode_index(
    bytes: &[u8],
    configuration: [u8; 32],
) -> Result<IndexState, StoreError> {
    let fixed = INDEX_MAGIC.len() + 32 + 32 + 8 + 1 + 4 + 32;
    if bytes.len() < fixed || bytes.len() as u64 > MAX_INDEX_BYTES {
        return Err(StoreError::Incompatible);
    }
    let checksum_offset = bytes.len() - 32;
    let (payload, checksum) = bytes.split_at(checksum_offset);
    let mut hasher = blake3::Hasher::new();
    hasher.update(INDEX_CHECKSUM_DOMAIN);
    hasher.update(payload);
    if hasher.finalize().as_bytes() != checksum {
        return Err(StoreError::Incompatible);
    }
    let mut cursor = PackedCursor::new(payload);
    if cursor.fixed(INDEX_MAGIC.len())? != INDEX_MAGIC || cursor.array_32()? != configuration {
        return Err(StoreError::Incompatible);
    }
    let instance = cursor.array_32()?;
    let generation = cursor.u64()?;
    let last_repack_plan = match cursor.u8()? {
        0 => None,
        1 => Some(PackedRepackPlanId(cursor.array_32()?)),
        _ => return Err(StoreError::Incompatible),
    };
    let count = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
    if count > MAX_LOGICAL_OBJECTS {
        return Err(StoreError::Quota);
    }
    let mut entries = BTreeMap::new();
    let mut prior = None;
    for _ in 0..count {
        let id_length = usize::from(cursor.u16()?);
        let id = std::str::from_utf8(cursor.fixed(id_length)?)
            .map_err(|_| StoreError::Incompatible)
            .and_then(|id| ContentId::parse(id).map_err(|_| StoreError::Incompatible))?;
        let entry = IndexEntry {
            pack: PackId(cursor.array_32()?),
            offset: cursor.u64()?,
            length: cursor.u64()?,
        };
        if prior.is_some_and(|prior| id <= prior) || entries.insert(id, entry).is_some() {
            return Err(StoreError::Incompatible);
        }
        prior = Some(id);
    }
    if !cursor.is_empty() {
        return Err(StoreError::Incompatible);
    }
    if entries
        .values()
        .map(|entry| entry.pack)
        .collect::<BTreeSet<_>>()
        .len()
        > MAX_PACKS
    {
        return Err(StoreError::Quota);
    }
    Ok(IndexState {
        instance,
        generation,
        last_repack_plan,
        entries,
    })
}

pub(super) fn packed_index_digest(
    index: &IndexState,
    configuration: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    let bytes = encode_index(index, configuration)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(INDEX_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn new_repack_plan(
    configuration: [u8; 32],
    instance: [u8; 32],
    generation: u64,
    index_digest: [u8; 32],
    before: PackedStorageAccounting,
) -> PackedRepackPlan {
    let mut plan = PackedRepackPlan {
        id: PackedRepackPlanId([0; 32]),
        configuration,
        instance,
        generation,
        index_digest,
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
    bytes.extend_from_slice(&plan.index_digest);
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
    let index_digest = cursor.array_32()?;
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
        index_digest,
        before,
    ))
}

fn validate_repack_accounting(accounting: PackedStorageAccounting) -> Result<(), StoreError> {
    let maximum_physical_bytes = (MAX_PACKS as u64)
        .checked_mul(MAX_PACK_BYTES)
        .ok_or(StoreError::Quota)?;
    if accounting.logical_objects > MAX_LOGICAL_OBJECTS as u64
        || accounting.packs > MAX_PACKS as u64
        || accounting.packs > accounting.logical_objects
        || accounting.logical_bytes > accounting.physical_bytes
        || accounting.physical_bytes > maximum_physical_bytes
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
        || u64::try_from(manifest_length).map_err(|_| StoreError::Quota)? > MAX_INDEX_BYTES
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

struct PackedCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> PackedCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn fixed(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(StoreError::Incompatible)?;
        let bytes = &self.bytes[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn array_32(&mut self) -> Result<[u8; 32], StoreError> {
        self.fixed(32)?
            .try_into()
            .map_err(|_| StoreError::Incompatible)
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        self.fixed(1)?
            .first()
            .copied()
            .ok_or(StoreError::Incompatible)
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(
            self.fixed(2)?
                .try_into()
                .map_err(|_| StoreError::Incompatible)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(
            self.fixed(4)?
                .try_into()
                .map_err(|_| StoreError::Incompatible)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(
            self.fixed(8)?
                .try_into()
                .map_err(|_| StoreError::Incompatible)?,
        ))
    }

    const fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
