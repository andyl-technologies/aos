//! Actual current boundary-pair builders adapted only for private file export.

use std::io::Write as _;
use anyhow::{ensure, Context as _, Result};
use flate2::{write::ZlibEncoder, Compression};
use sha2::{Digest as _, Sha256};
use aos_registry_surface::object::{hash_object, ObjectKind, Oid};
use aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_BYTES;

const MAX_PACK_OBJECT_BYTES: usize = 4 * 1024 * 1024;
const MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];

struct IndexEntry {
    oid: [u8; 32],
    crc: u32,
    offset: u64,
}

pub(super) struct PairFixture {
    pub(super) path: String,
    pub(super) pack: Vec<u8>,
    pub(super) index: Vec<u8>,
    pub(super) selected_oid: Oid,
}

fn append_entry(
    pack: &mut Vec<u8>,
    entries: &mut Vec<IndexEntry>,
    kind: u8,
    data: &[u8],
    oid: Oid,
    base_oid: Option<Oid>,
) -> Result<()> {
    let offset = pack.len();
    let mut remaining = data.len() >> 4;
    pack.push((kind << 4) | (data.len() & 15) as u8 | if remaining > 0 { 0x80 } else { 0 });
    while remaining > 0 {
        let byte = (remaining & 127) as u8;
        remaining >>= 7;
        pack.push(byte | if remaining > 0 { 0x80 } else { 0 });
    }
    if let Some(base_oid) = base_oid {
        pack.extend_from_slice(base_oid.as_bytes());
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).context("compressing boundary entry")?;
    pack.extend_from_slice(&encoder.finish().context("finishing boundary entry")?);
    entries.push(IndexEntry {
        oid: *oid.as_bytes(),
        crc: crc32fast::hash(&pack[offset..]),
        offset: u64::try_from(offset).context("entry offset exceeds u64")?,
    });
    Ok(())
}

fn append_varint(bytes: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value > 0 { 0x80 } else { 0 });
        if value == 0 {
            break;
        }
    }
}

fn reference_delta(full_input: bool) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut delta = Vec::new();
    append_varint(&mut delta, MAX_PACK_OBJECT_BYTES);
    append_varint(&mut delta, MAX_PACK_OBJECT_BYTES);
    let mut output = Vec::new();
    if full_input {
        // Reserve the four-byte copy command, then fill the delta's exact
        // 4 MiB input with literal commands. The copied suffix closes the
        // result at 4 MiB despite the literal-command overhead.
        let mut available = MAX_PACK_OBJECT_BYTES - delta.len() - 4;
        while available > 0 {
            let encoded = if available == 129 {
                127
            } else {
                available.min(128)
            };
            ensure!(encoded >= 2, "boundary delta has no literal capacity");
            let literal_bytes = encoded - 1;
            delta.push(literal_bytes as u8);
            delta.resize(delta.len() + literal_bytes, b'z');
            output.resize(output.len() + literal_bytes, b'z');
            available -= encoded;
        }
    } else {
        delta.extend_from_slice(&[1, b'z']);
        output.push(b'z');
    }
    let copied = MAX_PACK_OBJECT_BYTES.checked_sub(output.len())
        .context("boundary delta output exceeds object limit")?;
    delta.push(0xf0); // Copy from offset zero, with all three size bytes present.
    delta.extend_from_slice(&u32::try_from(copied)?.to_le_bytes()[..3]);
    output.resize(MAX_PACK_OBJECT_BYTES, b'a');
    ensure!(
        delta.len() ==
        if full_input {
            MAX_PACK_OBJECT_BYTES
        } else {
            14
        },
        "boundary delta encoded geometry changed"
    );
    Ok((delta, output))
}

pub(super) fn pair(delta: Option<bool>, extra_byte: bool) -> Result<PairFixture> {
    let mut pack = b"PACK".to_vec();
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(&(8_u32 + u32::from(extra_byte)).to_be_bytes());
    let mut entries = Vec::new();
    let mut selected_oid = None;
    let mut base_oid = None;
    for position in 0..if delta.is_some() { 7 } else { 8 } {
        let data = vec![b'a' + position; MAX_PACK_OBJECT_BYTES];
        let oid = hash_object(ObjectKind::Blob, &data);
        append_entry(&mut pack, &mut entries, 3, &data, oid, None)?;
        if position == 0 {
            base_oid = Some(oid);
        }
        selected_oid = Some(oid);
    }
    if let Some(full_input) = delta {
        let (data, output) = reference_delta(full_input)?;
        let oid = hash_object(ObjectKind::Blob, &output);
        append_entry(&mut pack, &mut entries, 7, &data, oid, base_oid)?;
        selected_oid = Some(oid);
    }
    if extra_byte {
        let data = b"!";
        append_entry(
            &mut pack,
            &mut entries,
            3,
            data,
            hash_object(ObjectKind::Blob, data),
            None,
        )?;
    }

    let checksum: [u8; 32] = Sha256::digest(&pack).into();
    pack.extend_from_slice(&checksum);
    entries.sort_by_key(|entry| entry.oid);
    let mut index = MAGIC.to_vec();
    index.extend_from_slice(&2_u32.to_be_bytes());
    for byte in 0..256_u16 {
        let count = entries
            .iter()
            .filter(|entry| u16::from(entry.oid[0]) <= byte)
            .count();
        index.extend_from_slice(&u32::try_from(count)?.to_be_bytes());
    }
    for entry in &entries {
        index.extend_from_slice(&entry.oid);
    }
    for entry in &entries {
        index.extend_from_slice(&entry.crc.to_be_bytes());
    }
    for entry in &entries {
        index.extend_from_slice(&u32::try_from(entry.offset)?.to_be_bytes());
    }
    index.extend_from_slice(&checksum);
    let index_checksum = Sha256::digest(&index);
    index.extend_from_slice(&index_checksum);
    ensure!(u64::try_from(pack.len())? <= MAX_PUBLISHED_PACK_BYTES, "boundary pack exceeds encoded limit");
    Ok(PairFixture {
        path: format!("objects/pack/pack-{}.idx", hex::encode(checksum)),
        pack,
        index,
        selected_oid: selected_oid.context("boundary pair contains no selected object")?,
    })
}
