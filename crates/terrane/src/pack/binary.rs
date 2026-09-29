//! Adapts native pack types to the sole portable byte-format implementation.
//!
//! Header, index, footer, and CRC encoding live in `terrane-core`; these
//! conversions contain no independent format serializer.

use super::{Codec, EntryKind, IndexEntry, PackClass, PackError, PackHeader, PackId};
use terrane_core::pack_format::{self, Header, Record};

#[cfg(test)]
pub(super) use pack_format::crc32c;

pub(super) fn core_header(header: PackHeader) -> Header {
    Header::new(
        *header.id.as_bytes(),
        header.class == PackClass::Meta,
        header.compressed_default,
    )
}

pub(super) fn native_header(header: Header) -> PackHeader {
    PackHeader {
        id: PackId::from_random_bytes(*header.id()),
        class: if header.is_meta() {
            PackClass::Meta
        } else {
            PackClass::Data
        },
        compressed_default: header.compressed_default(),
    }
}

pub(super) fn core_record(entry: &IndexEntry) -> Record {
    Record {
        hash: entry.hash,
        offset: entry.offset,
        body_len: entry.body_len,
        plaintext_len: entry.plaintext_len,
        codec: entry.codec as u8,
        kind: entry.kind as u8,
        dictionary_id: entry.dictionary_id,
    }
}

pub(super) fn native_record(record: &Record) -> Result<IndexEntry, PackError> {
    Ok(IndexEntry {
        hash: record.hash,
        offset: record.offset,
        body_len: record.body_len,
        plaintext_len: record.plaintext_len,
        codec: Codec::try_from(record.codec)?,
        kind: EntryKind::try_from(record.kind)?,
        dictionary_id: record.dictionary_id,
    })
}

pub(super) fn encode_header(header: PackHeader) -> Vec<u8> {
    core_header(header).encode()
}

pub(super) fn encode_index(entries: &[IndexEntry]) -> Vec<u8> {
    pack_format::encode_index(&entries.iter().map(core_record).collect::<Vec<_>>())
}

pub(super) fn validate_entry(entry: &IndexEntry, class: PackClass) -> Result<(), PackError> {
    Ok(pack_format::validate_record(
        &core_record(entry),
        class == PackClass::Meta,
    )?)
}
