//! Validation for SHA-256 Git pack/index pairs published at stable URLs.
//!
//! A pack index's wire encoding is replaceable, but it is safe to replace only
//! when every indexed object id, CRC, and offset is derived from the exact
//! companion pack. This module parses bounded v2 SHA-256 indexes and Git packs,
//! resolves base and delta objects, and compares the complete computed index.

use std::collections::BTreeMap;
use std::io::Read as _;

use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};

use crate::keymap::is_git_pack_index_path;
use crate::object::{hash_object, ObjectKind};

/// Maximum pack-index size accepted by a publication.
pub const MAX_PUBLISHED_PACK_INDEX_BYTES: u64 = 4 * 1024 * 1024;

/// Maximum companion-pack size accepted by a registry publication.
///
/// Registry packs contain metadata rather than package payloads. Bounding the
/// encoded pack keeps exact semantic verification viable in Worker runtimes;
/// NARs and system images use their dedicated large-object protocols.
pub const MAX_PUBLISHED_PACK_BYTES: u64 = 8 * 1024 * 1024;

const MAX_PACK_OBJECT_BYTES: usize = 4 * 1024 * 1024;
const MAX_DECODED_PACK_BYTES: usize = 12 * 1024 * 1024;
const MAX_PUBLISHED_PACK_OBJECTS: usize = 65_536;
const MAX_DELTA_DEPTH: usize = 128;
const HEADER_BYTES: usize = 8;
const FANOUT_BYTES: usize = 256 * 4;
const OBJECT_ID_BYTES: usize = 32;
const TRAILER_BYTES: usize = 64;
const PACK_TRAILER_BYTES: usize = 32;
const MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexEntry {
    oid: [u8; OBJECT_ID_BYTES],
    crc: u32,
    offset: u64,
}

#[derive(Debug, Clone, Copy)]
enum PackedKind {
    Base(ObjectKind),
    OffsetDelta(u64),
    ReferenceDelta([u8; OBJECT_ID_BYTES]),
}

#[derive(Debug)]
struct PackedEntry {
    offset: u64,
    crc: u32,
    kind: PackedKind,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ResolvedEntry {
    kind: ObjectKind,
    data: Vec<u8>,
    oid: [u8; OBJECT_ID_BYTES],
}

/// Returns the companion pack path for a canonical pack-index path.
#[must_use]
pub fn companion_pack_path(path: &str) -> Option<String> {
    is_git_pack_index_path(path)
        .then(|| path.strip_suffix(".idx"))
        .flatten()
        .map(|prefix| format!("{prefix}.pack"))
}

/// Validates the structure and checksums of a complete v2 SHA-256 index.
///
/// This is a format check. Publication admission should use
/// [`validate_against_pack`] to establish the semantic object mapping.
///
/// # Errors
///
/// Returns an error when the path is non-canonical, the input exceeds its
/// ceiling, or any index table or checksum is malformed.
pub fn validate(path: &str, bytes: &[u8]) -> Result<()> {
    parse_index(path, bytes).map(|_| ())
}

/// Validates that a pack's trailer and stable path identify its exact payload.
///
/// # Errors
///
/// Returns an error when the path is non-canonical, the pack is malformed, or
/// its bounded object graph, trailer, and filename checksum are inconsistent.
pub fn validate_pack(path: &str, bytes: &[u8]) -> Result<()> {
    if !crate::keymap::is_git_pack_path(path) {
        bail!("path is not a canonical SHA-256 Git pack");
    }
    parse_pack_entries(path, bytes).map(|_| ())
}

/// Validates an index against the exact bytes of its companion pack.
///
/// # Errors
///
/// Returns an error for either malformed input, a pack checksum/path mismatch,
/// unresolved or invalid deltas, resource-limit violations, or any discrepancy
/// between the index's object ids/CRCs/offsets and the parsed pack.
pub fn validate_against_pack(path: &str, index: &[u8], pack: &[u8]) -> Result<()> {
    let expected = parse_index(path, index)?;
    let packed = parse_pack_entries(path, pack)?;
    if packed.len() != expected.len() {
        bail!("pack index object count does not match its companion pack");
    }
    let mut actual = resolve_pack_entries(packed, &expected)?;
    actual.sort_by(|left, right| left.oid.cmp(&right.oid));
    if actual != expected {
        bail!("pack index does not describe its companion pack");
    }
    Ok(())
}

fn parse_index(path: &str, bytes: &[u8]) -> Result<Vec<IndexEntry>> {
    if !is_git_pack_index_path(path) {
        bail!("path is not a canonical SHA-256 Git pack index");
    }
    if bytes.len() as u64 > MAX_PUBLISHED_PACK_INDEX_BYTES {
        bail!("pack index exceeds its publication limit");
    }
    if bytes.len() < HEADER_BYTES + FANOUT_BYTES + TRAILER_BYTES {
        bail!("pack index is truncated");
    }
    if bytes[..4] != MAGIC || read_u32(bytes, 4)? != 2 {
        bail!("pack index must use the v2 SHA-256 format");
    }

    let fanout = &bytes[HEADER_BYTES..HEADER_BYTES + FANOUT_BYTES];
    let mut previous = 0_u32;
    for index in 0..256 {
        let current = read_u32(fanout, index * 4)?;
        if current < previous {
            bail!("pack index fanout table is not monotonic");
        }
        previous = current;
    }
    let object_count = usize::try_from(previous).context("pack index object count is too large")?;
    if object_count > MAX_PUBLISHED_PACK_OBJECTS {
        bail!("pack index exceeds its object-count limit");
    }
    let object_ids_start = HEADER_BYTES + FANOUT_BYTES;
    let object_ids_end = checked_table_end(object_ids_start, object_count, 32)?;
    let crc_end = checked_table_end(object_ids_end, object_count, 4)?;
    let offsets_end = checked_table_end(crc_end, object_count, 4)?;
    let trailer_start = bytes.len() - TRAILER_BYTES;
    if offsets_end > trailer_start || (trailer_start - offsets_end) % 8 != 0 {
        bail!("pack index tables are truncated or misaligned");
    }

    let object_ids = &bytes[object_ids_start..object_ids_end];
    let mut counts = [0_u32; 256];
    let mut prior: Option<&[u8]> = None;
    for oid in object_ids.chunks_exact(OBJECT_ID_BYTES) {
        if prior.is_some_and(|value| value >= oid) {
            bail!("pack index object ids are not strictly sorted");
        }
        counts[usize::from(oid[0])] += 1;
        prior = Some(oid);
    }
    let mut cumulative = 0_u32;
    for (index, count) in counts.into_iter().enumerate() {
        cumulative = cumulative
            .checked_add(count)
            .context("pack index fanout count overflows")?;
        if read_u32(fanout, index * 4)? != cumulative {
            bail!("pack index fanout table does not match its object ids");
        }
    }

    let large_count = (trailer_start - offsets_end) / 8;
    let mut large_seen = vec![false; large_count];
    let mut entries = Vec::with_capacity(object_count);
    for index in 0..object_count {
        let oid: [u8; OBJECT_ID_BYTES] = object_ids[index * 32..(index + 1) * 32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("pack index object id has the wrong length"))?;
        let crc = read_u32(bytes, object_ids_end + index * 4)?;
        let encoded_offset = read_u32(bytes, crc_end + index * 4)?;
        let offset = if encoded_offset & 0x8000_0000 == 0 {
            u64::from(encoded_offset)
        } else {
            let large_index = (encoded_offset & 0x7fff_ffff) as usize;
            let seen = large_seen
                .get_mut(large_index)
                .context("pack index references a missing large offset")?;
            if *seen {
                bail!("pack index reuses a large-offset entry");
            }
            *seen = true;
            read_u64(bytes, offsets_end + large_index * 8)?
        };
        entries.push(IndexEntry { oid, crc, offset });
    }
    if large_seen.iter().any(|seen| !seen) {
        bail!("pack index has an unreferenced large offset");
    }

    let expected_pack = expected_pack_checksum(path)?;
    if bytes[trailer_start..trailer_start + OBJECT_ID_BYTES] != expected_pack {
        bail!("pack index checksum does not match its companion pack filename");
    }
    let checksum_start = bytes.len() - OBJECT_ID_BYTES;
    let actual_checksum = Sha256::digest(&bytes[..checksum_start]);
    if actual_checksum[..] != bytes[checksum_start..] {
        bail!("pack index self-checksum is invalid");
    }
    Ok(entries)
}

fn parse_pack_entries(path: &str, bytes: &[u8]) -> Result<Vec<PackedEntry>> {
    if bytes.len() as u64 > MAX_PUBLISHED_PACK_BYTES {
        bail!("companion pack exceeds its publication limit");
    }
    if bytes.len() < 12 + PACK_TRAILER_BYTES || &bytes[..4] != b"PACK" {
        bail!("companion pack is truncated or has invalid magic");
    }
    let version = read_u32(bytes, 4)?;
    if !matches!(version, 2 | 3) {
        bail!("companion pack version is unsupported");
    }
    let entry_count =
        usize::try_from(read_u32(bytes, 8)?).context("companion pack entry count is too large")?;
    if entry_count > MAX_PUBLISHED_PACK_OBJECTS {
        bail!("companion pack exceeds its object-count limit");
    }
    let trailer_start = bytes.len() - PACK_TRAILER_BYTES;
    let expected_checksum = expected_pack_checksum(path)?;
    let actual_checksum = Sha256::digest(&bytes[..trailer_start]);
    if actual_checksum[..] != expected_checksum || bytes[trailer_start..] != expected_checksum {
        bail!("companion pack bytes do not match their filename checksum");
    }

    let mut position = 12_usize;
    let mut decoded_bytes = 0_usize;
    let mut packed = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let start = position;
        let first = read_byte(bytes, &mut position, trailer_start)?;
        let type_code = (first >> 4) & 7;
        let mut declared_size = usize::from(first & 0x0f);
        let mut shift = 4_u32;
        let mut continuation = first & 0x80 != 0;
        while continuation {
            let byte = read_byte(bytes, &mut position, trailer_start)?;
            let part = usize::from(byte & 0x7f)
                .checked_shl(shift)
                .context("packed object size overflows")?;
            declared_size = declared_size
                .checked_add(part)
                .context("packed object size overflows")?;
            shift = shift
                .checked_add(7)
                .context("packed object size overflows")?;
            if shift >= usize::BITS && byte & 0x80 != 0 {
                bail!("packed object size overflows");
            }
            continuation = byte & 0x80 != 0;
        }
        if declared_size > MAX_PACK_OBJECT_BYTES {
            bail!("packed object exceeds its decoded-size limit");
        }

        let kind = match type_code {
            1 => PackedKind::Base(ObjectKind::Commit),
            2 => PackedKind::Base(ObjectKind::Tree),
            3 => PackedKind::Base(ObjectKind::Blob),
            4 => PackedKind::Base(ObjectKind::Tag),
            6 => PackedKind::OffsetDelta(parse_offset_delta_base(
                bytes,
                &mut position,
                trailer_start,
                start,
            )?),
            7 => {
                let end = position
                    .checked_add(OBJECT_ID_BYTES)
                    .context("reference-delta header overflows")?;
                let oid = bytes
                    .get(position..end)
                    .context("reference-delta base is truncated")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("reference-delta base has the wrong length"))?;
                position = end;
                PackedKind::ReferenceDelta(oid)
            }
            _ => bail!("companion pack contains a reserved object type"),
        };

        let mut decoder = flate2::bufread::ZlibDecoder::new(std::io::Cursor::new(
            &bytes[position..trailer_start],
        ));
        let mut data = Vec::with_capacity(declared_size);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = decoder
                .read(&mut buffer)
                .context("inflating packed object")?;
            if count == 0 {
                break;
            }
            if data.len().saturating_add(count) > declared_size {
                bail!("packed object inflates past its declared size");
            }
            data.extend_from_slice(&buffer[..count]);
        }
        if data.len() != declared_size {
            bail!("packed object does not match its declared size");
        }
        let consumed = usize::try_from(decoder.total_in())
            .context("compressed packed-object size is too large")?;
        if consumed == 0 {
            bail!("packed object has an empty zlib stream");
        }
        position = position
            .checked_add(consumed)
            .context("packed object position overflows")?;
        if position > trailer_start {
            bail!("packed object overlaps the pack trailer");
        }
        decoded_bytes = decoded_bytes
            .checked_add(data.len())
            .context("decoded pack size overflows")?;
        if decoded_bytes > MAX_DECODED_PACK_BYTES {
            bail!("companion pack exceeds its aggregate decoded-size limit");
        }
        let crc = crc32fast::hash(&bytes[start..position]);
        packed.push(PackedEntry {
            offset: start as u64,
            crc,
            kind,
            data,
        });
    }
    if position != trailer_start {
        bail!("companion pack has trailing or unparsed entry bytes");
    }
    Ok(packed)
}

fn resolve_pack_entries(
    mut entries: Vec<PackedEntry>,
    expected: &[IndexEntry],
) -> Result<Vec<IndexEntry>> {
    let offsets = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.offset, index))
        .collect::<BTreeMap<_, _>>();
    if offsets.len() != entries.len() {
        bail!("companion pack contains duplicate entry offsets");
    }
    let expected_bases = expected
        .iter()
        .map(|entry| {
            offsets
                .get(&entry.offset)
                .copied()
                .map(|index| (entry.oid, index))
                .context("pack index references an absent object offset")
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    if expected_bases.len() != expected.len() {
        bail!("pack index contains a duplicate object id");
    }

    let mut resolved: Vec<Option<ResolvedEntry>> = vec![None; entries.len()];
    let mut state = vec![0_u8; entries.len()];
    let mut unresolved_bytes = entries.iter().try_fold(0_usize, |total, entry| {
        total
            .checked_add(entry.data.len())
            .context("decoded pack size overflows")
    })?;
    let mut resolved_bytes = 0_usize;
    for start in 0..entries.len() {
        if state[start] == 2 {
            continue;
        }
        let mut chain = Vec::new();
        let mut current = start;
        loop {
            match state[current] {
                2 => break,
                1 => bail!("companion pack has a cyclic delta base"),
                _ => {}
            }
            if chain.len() >= MAX_DELTA_DEPTH {
                bail!("companion pack exceeds its delta-depth limit");
            }
            state[current] = 1;
            chain.push(current);
            let dependency = match entries[current].kind {
                PackedKind::Base(_) => None,
                PackedKind::OffsetDelta(base_offset) => Some(
                    offsets
                        .get(&base_offset)
                        .copied()
                        .context("offset delta references an absent base")?,
                ),
                PackedKind::ReferenceDelta(base_oid) => Some(
                    expected_bases
                        .get(&base_oid)
                        .copied()
                        .context("reference delta names an unindexed base")?,
                ),
            };
            let Some(dependency) = dependency else {
                break;
            };
            current = dependency;
        }

        while let Some(index) = chain.pop() {
            let packed_kind = entries[index].kind;
            let packed_data = std::mem::take(&mut entries[index].data);
            unresolved_bytes = unresolved_bytes
                .checked_sub(packed_data.len())
                .context("decoded pack accounting underflows")?;
            let (kind, data) = match packed_kind {
                PackedKind::Base(kind) => (kind, packed_data),
                PackedKind::OffsetDelta(base_offset) => {
                    let base_index = offsets[&base_offset];
                    let base = resolved[base_index]
                        .as_ref()
                        .context("offset-delta base was not resolved")?;
                    (base.kind, apply_delta(&base.data, &packed_data)?)
                }
                PackedKind::ReferenceDelta(base_oid) => {
                    let base_index = expected_bases[&base_oid];
                    let base = resolved[base_index]
                        .as_ref()
                        .context("reference-delta base was not resolved")?;
                    (base.kind, apply_delta(&base.data, &packed_data)?)
                }
            };
            resolved_bytes = resolved_bytes
                .checked_add(data.len())
                .context("resolved pack size overflows")?;
            if unresolved_bytes.saturating_add(resolved_bytes) > MAX_DECODED_PACK_BYTES {
                bail!("companion pack exceeds its aggregate resolved-size limit");
            }
            let oid = *hash_object(kind, &data).as_bytes();
            resolved[index] = Some(ResolvedEntry { oid, kind, data });
            state[index] = 2;
        }
    }

    entries
        .into_iter()
        .zip(resolved)
        .map(|(packed, resolved)| {
            let resolved = resolved.context("companion pack object was not resolved")?;
            Ok(IndexEntry {
                oid: resolved.oid,
                crc: packed.crc,
                offset: packed.offset,
            })
        })
        .collect()
}

fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    let mut position = 0_usize;
    let base_size = read_delta_varint(delta, &mut position)?;
    let result_size = read_delta_varint(delta, &mut position)?;
    if base_size != base.len() || result_size > MAX_PACK_OBJECT_BYTES {
        bail!("pack delta declares an invalid base or result size");
    }
    let mut result = Vec::with_capacity(result_size);
    while position < delta.len() {
        let command = delta[position];
        position += 1;
        if command & 0x80 == 0 {
            let length = usize::from(command);
            if length == 0 {
                bail!("pack delta contains a reserved zero command");
            }
            let end = position
                .checked_add(length)
                .context("pack delta insert overflows")?;
            result.extend_from_slice(
                delta
                    .get(position..end)
                    .context("pack delta insert is truncated")?,
            );
            position = end;
        } else {
            let mut offset = 0_usize;
            let mut size = 0_usize;
            for byte_index in 0..4 {
                if command & (1 << byte_index) != 0 {
                    offset |=
                        usize::from(read_delta_byte(delta, &mut position)?) << (byte_index * 8);
                }
            }
            for byte_index in 0..3 {
                if command & (1 << (4 + byte_index)) != 0 {
                    size |= usize::from(read_delta_byte(delta, &mut position)?) << (byte_index * 8);
                }
            }
            if size == 0 {
                size = 0x1_0000;
            }
            let end = offset
                .checked_add(size)
                .context("pack delta copy overflows")?;
            result.extend_from_slice(
                base.get(offset..end)
                    .context("pack delta copy exceeds its base")?,
            );
        }
        if result.len() > result_size {
            bail!("pack delta expands past its declared result size");
        }
    }
    if result.len() != result_size {
        bail!("pack delta does not produce its declared result size");
    }
    Ok(result)
}

fn parse_offset_delta_base(
    bytes: &[u8],
    position: &mut usize,
    limit: usize,
    entry_offset: usize,
) -> Result<u64> {
    let mut byte = read_byte(bytes, position, limit)?;
    let mut distance = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = read_byte(bytes, position, limit)?;
        distance = distance
            .checked_add(1)
            .and_then(|value| value.checked_shl(7))
            .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
            .context("offset-delta distance overflows")?;
    }
    let entry_offset = entry_offset as u64;
    entry_offset
        .checked_sub(distance)
        .context("offset-delta base precedes the pack")
}

fn read_delta_varint(bytes: &[u8], position: &mut usize) -> Result<usize> {
    let mut value = 0_usize;
    let mut shift = 0_u32;
    loop {
        let byte = read_delta_byte(bytes, position)?;
        value |= usize::from(byte & 0x7f)
            .checked_shl(shift)
            .context("pack delta size overflows")?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift.checked_add(7).context("pack delta size overflows")?;
        if shift >= usize::BITS {
            bail!("pack delta size overflows");
        }
    }
}

fn read_delta_byte(bytes: &[u8], position: &mut usize) -> Result<u8> {
    let byte = bytes
        .get(*position)
        .copied()
        .context("pack delta is truncated")?;
    *position += 1;
    Ok(byte)
}

fn read_byte(bytes: &[u8], position: &mut usize, limit: usize) -> Result<u8> {
    if *position >= limit {
        bail!("companion pack entry is truncated");
    }
    let byte = bytes[*position];
    *position += 1;
    Ok(byte)
}

fn checked_table_end(start: usize, count: usize, width: usize) -> Result<usize> {
    start
        .checked_add(
            count
                .checked_mul(width)
                .context("pack index table overflows")?,
        )
        .context("pack index table overflows")
}

fn expected_pack_checksum(path: &str) -> Result<[u8; OBJECT_ID_BYTES]> {
    let filename = path
        .rsplit('/')
        .next()
        .context("pack index has no filename")?;
    let digest = filename
        .strip_prefix("pack-")
        .and_then(|value| {
            value
                .strip_suffix(".idx")
                .or_else(|| value.strip_suffix(".pack"))
        })
        .context("pack index filename is malformed")?;
    let decoded = hex::decode(digest).context("decoding pack checksum from filename")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("pack checksum has the wrong length"))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .context("pack index offset overflows")?;
    let value = bytes
        .get(offset..end)
        .context("pack index is truncated")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pack index field has the wrong length"))?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .context("pack index offset overflows")?;
    let value = bytes
        .get(offset..end)
        .context("pack index is truncated")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pack index field has the wrong length"))?;
    Ok(u64::from_be_bytes(value))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn pack_and_index() -> (String, Vec<u8>, Vec<u8>) {
        let content = b"hello";
        let oid_hex = hash_object(ObjectKind::Blob, content).to_hex();
        let oid: [u8; 32] = hex::decode(oid_hex).unwrap().try_into().unwrap();
        let mut compressed =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        compressed.write_all(content).unwrap();
        let compressed = compressed.finish().unwrap();

        let mut pack = b"PACK".to_vec();
        pack.extend_from_slice(&2_u32.to_be_bytes());
        pack.extend_from_slice(&1_u32.to_be_bytes());
        let entry_offset = pack.len();
        pack.push(0x35);
        pack.extend_from_slice(&compressed);
        let entry_crc = crc32fast::hash(&pack[entry_offset..]);
        let pack_checksum: [u8; 32] = Sha256::digest(&pack).into();
        pack.extend_from_slice(&pack_checksum);

        let index = make_index(&[(oid, entry_crc, entry_offset as u32)], pack_checksum);
        (
            format!("objects/pack/pack-{}.idx", hex::encode(pack_checksum)),
            index,
            pack,
        )
    }

    fn make_index(entries: &[([u8; 32], u32, u32)], pack_checksum: [u8; 32]) -> Vec<u8> {
        let mut entries = entries.to_vec();
        entries.sort_by_key(|entry| entry.0);
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        for first in 0..256_u16 {
            let count = entries
                .iter()
                .filter(|entry| u16::from(entry.0[0]) <= first)
                .count() as u32;
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        for entry in &entries {
            bytes.extend_from_slice(&entry.0);
        }
        for entry in &entries {
            bytes.extend_from_slice(&entry.1.to_be_bytes());
        }
        for entry in &entries {
            bytes.extend_from_slice(&entry.2.to_be_bytes());
        }
        bytes.extend_from_slice(&pack_checksum);
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn compressed(bytes: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn append_delta(base_len: u8, byte: u8) -> Vec<u8> {
        vec![base_len, base_len + 1, 0x90, base_len, 1, byte]
    }

    fn finish_pack(
        mut pack: Vec<u8>,
        entries: Vec<([u8; 32], u32, u32)>,
    ) -> (String, Vec<u8>, Vec<u8>) {
        let checksum: [u8; 32] = Sha256::digest(&pack).into();
        pack.extend_from_slice(&checksum);
        (
            format!("objects/pack/pack-{}.idx", hex::encode(checksum)),
            make_index(&entries, checksum),
            pack,
        )
    }

    #[test]
    fn accepts_an_index_derived_from_the_exact_pack() {
        let (path, index, pack) = pack_and_index();
        validate_against_pack(&path, &index, &pack).unwrap();
        validate_against_pack(&format!("releases/1/0/0/{path}"), &index, &pack).unwrap();
        assert_eq!(
            companion_pack_path(&path).unwrap(),
            path.replace(".idx", ".pack")
        );
    }

    #[test]
    fn rejects_a_self_consistent_index_that_lies_about_pack_contents() {
        let (path, index, pack) = pack_and_index();
        validate(&path, &index).unwrap();
        let pack_checksum: [u8; 32] = pack[pack.len() - 32..].try_into().unwrap();
        let empty = make_index(&[], pack_checksum);
        validate(&path, &empty).unwrap();
        assert!(validate_against_pack(&path, &empty, &pack).is_err());

        let wrong_path = path.replace(&hex::encode(pack_checksum), &"43".repeat(32));
        assert!(validate_against_pack(&wrong_path, &index, &pack).is_err());
    }

    #[test]
    fn rejects_corrupt_index_or_pack_bytes() {
        let (path, mut index, mut pack) = pack_and_index();
        let last = index.len() - 1;
        index[last] ^= 1;
        assert!(validate_against_pack(&path, &index, &pack).is_err());

        let byte = pack.len() - 33;
        pack[byte] ^= 1;
        assert!(validate_against_pack(&path, &make_index(&[], [0; 32]), &pack).is_err());
    }

    #[test]
    fn resolves_offset_delta_entries() {
        let base = b"hello";
        let result = b"hello!";
        let mut pack = b"PACK".to_vec();
        pack.extend_from_slice(&2_u32.to_be_bytes());
        pack.extend_from_slice(&2_u32.to_be_bytes());

        let base_offset = pack.len();
        pack.push(0x35);
        pack.extend_from_slice(&compressed(base));
        let base_end = pack.len();
        let delta_offset = pack.len();
        let delta = append_delta(base.len() as u8, b'!');
        pack.push(0x60 | delta.len() as u8);
        let distance = delta_offset - base_offset;
        assert!(distance < 128);
        pack.push(distance as u8);
        pack.extend_from_slice(&compressed(&delta));
        let delta_end = pack.len();

        let entries = vec![
            (
                *hash_object(ObjectKind::Blob, base).as_bytes(),
                crc32fast::hash(&pack[base_offset..base_end]),
                base_offset as u32,
            ),
            (
                *hash_object(ObjectKind::Blob, result).as_bytes(),
                crc32fast::hash(&pack[delta_offset..delta_end]),
                delta_offset as u32,
            ),
        ];
        let (path, index, pack) = finish_pack(pack, entries);
        validate_against_pack(&path, &index, &pack).unwrap();
    }

    #[test]
    fn resolves_forward_reference_delta_chain_once_per_entry() {
        let contents: [&[u8]; 4] = [b"abcd", b"abc", b"ab", b"a"];
        let oids = contents
            .iter()
            .map(|content| *hash_object(ObjectKind::Blob, content).as_bytes())
            .collect::<Vec<_>>();
        let mut pack = b"PACK".to_vec();
        pack.extend_from_slice(&2_u32.to_be_bytes());
        pack.extend_from_slice(&(contents.len() as u32).to_be_bytes());
        let mut entries = Vec::new();

        for index in 0..contents.len() - 1 {
            let offset = pack.len();
            let delta = append_delta(
                contents[index + 1].len() as u8,
                contents[index][contents[index].len() - 1],
            );
            pack.push(0x70 | delta.len() as u8);
            pack.extend_from_slice(&oids[index + 1]);
            pack.extend_from_slice(&compressed(&delta));
            entries.push((oids[index], crc32fast::hash(&pack[offset..]), offset as u32));
        }
        let base_offset = pack.len();
        pack.push(0x31);
        pack.extend_from_slice(&compressed(contents[3]));
        entries.push((
            oids[3],
            crc32fast::hash(&pack[base_offset..]),
            base_offset as u32,
        ));

        let (path, index, pack) = finish_pack(pack, entries);
        validate_against_pack(&path, &index, &pack).unwrap();
    }
}
