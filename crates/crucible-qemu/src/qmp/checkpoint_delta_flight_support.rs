//! RAM-image parsing and byte helpers for the checkpoint-delta live flight.

#![cfg(test)]

use std::error::Error;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};

use crucible::ContentHash;
use sha2::{Digest as _, Sha256};

use super::{
    PAGE_BYTES, QmpCheckpointIdentity, QmpCheckpointRamKind, RamLayer, RamRecord, RamRegion,
};

pub(super) fn parse_ram_layer(bytes: &[u8]) -> Result<RamLayer, Box<dyn Error>> {
    let mut cursor = Cursor::new(bytes);
    let mut magic = [0; 8];
    cursor.read_exact(&mut magic)?;
    if &magic != b"CRUCRAM2" || read_u32(&mut cursor)? != 2 {
        return Err("invalid CRUCRAM2 header".into());
    }
    let kind = match read_u32(&mut cursor)? {
        1 => QmpCheckpointRamKind::Direct,
        2 => QmpCheckpointRamKind::Delta,
        _ => return Err("invalid CRUCRAM2 kind".into()),
    };
    let page_size = read_u32(&mut cursor)?;
    let region_count = read_u32(&mut cursor)? as usize;
    let record_count = read_u64(&mut cursor)? as usize;
    if read_u64(&mut cursor)? != bytes.len() as u64 {
        return Err("CRUCRAM2 total length does not match input".into());
    }
    cursor.seek(SeekFrom::Current(32 * 6))?;

    let mut regions = Vec::with_capacity(region_count);
    for _ in 0..region_count {
        let length = read_u64(&mut cursor)?;
        let _maximum_length = read_u64(&mut cursor)?;
        let _backing_page_size = read_u64(&mut cursor)?;
        let name_length = read_u32(&mut cursor)? as usize;
        let mut name = vec![0; name_length];
        cursor.read_exact(&mut name)?;
        regions.push(RamRegion {
            name: String::from_utf8(name)?,
            length,
        });
    }

    let mut records = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let region = read_u32(&mut cursor)? as usize;
        let length = read_u32(&mut cursor)? as usize;
        let offset = read_u64(&mut cursor)?;
        let region_length = regions
            .get(region)
            .ok_or("RAM record region is out of range")?
            .length;
        if offset > region_length || length as u64 > region_length - offset {
            return Err("RAM record exceeds its region".into());
        }
        let mut record_bytes = vec![0; length];
        cursor.read_exact(&mut record_bytes)?;
        records.push(RamRecord {
            region,
            offset,
            bytes: record_bytes,
        });
    }
    if cursor.position() != bytes.len() as u64 {
        return Err("CRUCRAM2 contains trailing bytes".into());
    }

    Ok(RamLayer {
        kind,
        page_size,
        regions,
        records,
    })
}

#[test]
fn prior_nanosecond_ram_sidecar_is_rejected() {
    let mut header = Vec::from(&b"CRUCRAM1"[..]);
    header.extend_from_slice(&1_u32.to_le_bytes());

    assert!(parse_ram_layer(&header).is_err());
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, Box<dyn Error>> {
    let mut bytes = [0; 4];
    cursor.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, Box<dyn Error>> {
    let mut bytes = [0; 8];
    cursor.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn read_all(file: &mut File) -> Result<Vec<u8>, Box<dyn Error>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn sha256_hash(bytes: &[u8]) -> ContentHash {
    ContentHash {
        bytes: Sha256::digest(bytes).into(),
    }
}

pub(super) fn identity(byte: u8) -> QmpCheckpointIdentity {
    QmpCheckpointIdentity::new(
        ContentHash { bytes: [byte; 32] },
        ContentHash {
            bytes: [byte.wrapping_add(1); 32],
        },
        ContentHash {
            bytes: [byte.wrapping_add(2); 32],
        },
    )
}

pub(super) fn patterned_page(seed: u8) -> Vec<u8> {
    (0..PAGE_BYTES)
        .map(|offset| seed.wrapping_add(offset as u8))
        .collect()
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(super) fn decode_hex(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !encoded.len().is_multiple_of(2) {
        return Err("qtest returned an odd-length hexadecimal payload".into());
    }
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|digits| {
            let digits = std::str::from_utf8(digits)?;
            Ok(u8::from_str_radix(digits, 16)?)
        })
        .collect()
}
