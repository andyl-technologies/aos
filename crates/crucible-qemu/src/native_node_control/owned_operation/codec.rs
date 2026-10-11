//! Checks bounded archive extents and hashes complete record bodies.
//!
//! ```text
//! record: kind:u32be | length:u32be | sequence:u64be | body | sha256:[32]
//! body identity: SHA256("crucible.native-command-archive.record.v1\0" | header | body)
//! ```

// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use super::ArchiveError;

pub(crate) const RECORD_OVERHEAD: u64 = 48;
pub(crate) const MAX_RECORD: usize = 65_536;

pub(crate) fn write_record(
    writer: &mut impl Write,
    kind: u32,
    sequence: u64,
    payload: &[u8],
) -> Result<[u8; 32], ArchiveError> {
    if payload.len() > MAX_RECORD {
        return Err(ArchiveError::Budget);
    }
    let mut header = [0; 16];
    header[..4].copy_from_slice(&kind.to_be_bytes());
    header[4..8].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    header[8..].copy_from_slice(&sequence.to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(b"crucible.native-command-archive.record.v1\0");
    digest.update(header);
    digest.update(payload);
    let digest: [u8; 32] = digest.finalize().into();

    writer.write_all(&header)?;
    writer.write_all(payload)?;
    writer.write_all(&digest)?;
    Ok(digest)
}

pub(crate) struct Record {
    pub(crate) kind: u32,
    pub(crate) sequence: u64,
    pub(crate) payload: Vec<u8>,
    pub(crate) digest: [u8; 32],
}

pub(crate) fn read_record(reader: &mut impl Read) -> Result<Option<Record>, ArchiveError> {
    let mut header = [0; 16];
    if reader.read(&mut header[..1])? == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut header[1..])
        .map_err(|_| ArchiveError::Corrupt)?;
    let mut cursor = Cursor(&header);
    let kind = cursor.u32()?;
    let length = cursor.u32()? as usize;
    let sequence = cursor.u64()?;
    if length > MAX_RECORD {
        return Err(ArchiveError::Corrupt);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| ArchiveError::Budget)?;
    payload.resize(length, 0);
    reader
        .read_exact(&mut payload)
        .map_err(|_| ArchiveError::Corrupt)?;
    let mut expected = [0; 32];
    reader
        .read_exact(&mut expected)
        .map_err(|_| ArchiveError::Corrupt)?;
    let mut digest = Sha256::new();
    digest.update(b"crucible.native-command-archive.record.v1\0");
    digest.update(header);
    digest.update(&payload);
    if <[u8; 32]>::from(digest.finalize()) != expected {
        return Err(ArchiveError::Corrupt);
    }
    Ok(Some(Record {
        kind,
        sequence,
        payload,
        digest: expected,
    }))
}

pub(crate) fn put_blob(target: &mut Vec<u8>, blob: &[u8]) -> Result<(), ArchiveError> {
    let length = u32::try_from(blob.len()).map_err(|_| ArchiveError::Budget)?;
    target
        .try_reserve(4 + blob.len())
        .map_err(|_| ArchiveError::Budget)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(blob);
    Ok(())
}

pub(crate) struct Cursor<'a>(pub(crate) &'a [u8]);

impl<'a> Cursor<'a> {
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], ArchiveError> {
        if self.0.len() < length {
            return Err(ArchiveError::Corrupt);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ArchiveError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ArchiveError::Corrupt)?,
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ArchiveError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ArchiveError::Corrupt)?,
        ))
    }

    pub(crate) fn blob(&mut self, maximum: usize) -> Result<&'a [u8], ArchiveError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(ArchiveError::Corrupt);
        }
        self.take(length)
    }

    pub(crate) fn finish(self) -> Result<(), ArchiveError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ArchiveError::Corrupt)
        }
    }
}
