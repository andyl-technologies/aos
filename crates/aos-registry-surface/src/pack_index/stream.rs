//! Incremental SHA-256 Git pack entry decoding without retained encoded packs.
//!
//! The parser consumes fixed header bytes and zlib input immediately. Only the
//! bounded decoded graph survives a feed; its entries use the same delta
//! resolver as publication validation. A trailer closes the stream, and any
//! trailing input or failed feed permanently invalidates the parser.

use anyhow::{bail, ensure, Context as _, Result};
use flate2::{Decompress, FlushDecompress, Status};
use sha2::{Digest as _, Sha256};

use super::{
    PackedEntry, PackedKind, MAX_DECODED_PACK_BYTES, MAX_PACK_OBJECT_BYTES,
    MAX_PUBLISHED_PACK_BYTES, MAX_PUBLISHED_PACK_OBJECTS,
};
use crate::object::ObjectKind;

pub(super) const CHUNK_BYTES: usize = 64 * 1024;

pub(super) struct PackStream {
    state: State,
    entries: Vec<PackedEntry>,
    expected_count: usize,
    position: u64,
    encoded_bytes: u64,
    encoded_hash: Sha256,
    payload_hash: Sha256,
    expected_checksum: [u8; 32],
    decoded_bytes: usize,
}

enum State {
    Header {
        bytes: [u8; 12],
        length: usize,
    },
    Object(EntryHeader),
    Offset {
        header: EntryHeader,
        distance: u64,
        first: bool,
    },
    Reference {
        header: EntryHeader,
        bytes: [u8; 32],
        length: usize,
    },
    Inflate(Inflating),
    Trailer {
        bytes: [u8; 32],
        length: usize,
    },
    Complete,
    Failed,
}

struct EntryHeader {
    offset: u64,
    crc: crc32fast::Hasher,
    type_code: u8,
    declared_size: usize,
    shift: u32,
    first: bool,
}

struct Inflating {
    header: EntryHeader,
    kind: PackedKind,
    decoder: Decompress,
    data: Vec<u8>,
}

pub(super) struct ParsedPack {
    pub(super) entries: Vec<PackedEntry>,
    pub(super) encoded_hash: [u8; 32],
    pub(super) encoded_bytes: u64,
    pub(super) decoded_bytes: usize,
}

impl EntryHeader {
    fn new(offset: u64) -> Self {
        Self {
            offset,
            crc: crc32fast::Hasher::new(),
            type_code: 0,
            declared_size: 0,
            shift: 4,
            first: true,
        }
    }

    fn inflate(self, kind: PackedKind) -> State {
        State::Inflate(Inflating {
            header: self,
            kind,
            decoder: Decompress::new(true),
            data: Vec::new(),
        })
    }
}

impl PackStream {
    pub(super) fn new(expected_checksum: [u8; 32]) -> Self {
        Self {
            state: State::Header {
                bytes: [0; 12],
                length: 0,
            },
            entries: Vec::new(),
            expected_count: 0,
            position: 0,
            encoded_bytes: 0,
            encoded_hash: Sha256::new(),
            payload_hash: Sha256::new(),
            expected_checksum,
            decoded_bytes: 0,
        }
    }

    pub(super) fn feed(&mut self, input: &[u8]) -> Result<()> {
        let result = self.feed_inner(input);
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }

    fn consume(&mut self, input: &[u8]) {
        // Every payload byte is consumed once; the fixed trailer is excluded.
        self.payload_hash.update(input);
        self.position += input.len() as u64;
    }

    fn feed_inner(&mut self, mut input: &[u8]) -> Result<()> {
        ensure!(
            !matches!(self.state, State::Failed),
            "pack stream previously failed"
        );
        ensure!(
            input.len() <= CHUNK_BYTES,
            "pack feed exceeds its chunk limit"
        );
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(input.len() as u64)
            .context("encoded pack size overflows")?;
        ensure!(
            self.encoded_bytes <= MAX_PUBLISHED_PACK_BYTES,
            "pack stream exceeds its encoded-size limit"
        );
        self.encoded_hash.update(input);

        while !input.is_empty() || matches!(self.state, State::Inflate(_)) {
            let state = std::mem::replace(&mut self.state, State::Failed);
            self.state = match state {
                State::Header {
                    mut bytes,
                    mut length,
                } => {
                    let count = (12 - length).min(input.len());
                    bytes[length..length + count].copy_from_slice(&input[..count]);
                    self.consume(&input[..count]);
                    input = &input[count..];
                    length += count;
                    if length < 12 {
                        State::Header { bytes, length }
                    } else {
                        ensure!(&bytes[..4] == b"PACK", "pack stream header is invalid");
                        let version = u32::from_be_bytes(bytes[4..8].try_into()?);
                        ensure!(
                            matches!(version, 2 | 3),
                            "pack stream version is unsupported"
                        );
                        self.expected_count = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
                        ensure!(
                            self.expected_count <= MAX_PUBLISHED_PACK_OBJECTS,
                            "pack stream exceeds its object-count limit"
                        );
                        self.next_entry()
                    }
                }
                State::Object(mut header) => {
                    let byte = input[0];
                    header.crc.update(&input[..1]);
                    self.consume(&input[..1]);
                    input = &input[1..];
                    if header.first {
                        header.first = false;
                        header.type_code = (byte >> 4) & 7;
                        header.declared_size = usize::from(byte & 0x0f);
                    } else {
                        let factor = 1_usize
                            .checked_shl(header.shift)
                            .context("packed object size overflows")?;
                        let part = usize::from(byte & 0x7f)
                            .checked_mul(factor)
                            .context("packed object size overflows")?;
                        header.declared_size = header
                            .declared_size
                            .checked_add(part)
                            .context("packed object size overflows")?;
                        header.shift = header
                            .shift
                            .checked_add(7)
                            .context("packed object size overflows")?;
                    }
                    ensure!(
                        header.declared_size <= MAX_PACK_OBJECT_BYTES,
                        "packed object exceeds its decoded-size limit"
                    );
                    if byte & 0x80 != 0 {
                        ensure!(header.shift < usize::BITS, "packed object size overflows");
                        State::Object(header)
                    } else {
                        match header.type_code {
                            1 => header.inflate(PackedKind::Base(ObjectKind::Commit)),
                            2 => header.inflate(PackedKind::Base(ObjectKind::Tree)),
                            3 => header.inflate(PackedKind::Base(ObjectKind::Blob)),
                            4 => header.inflate(PackedKind::Base(ObjectKind::Tag)),
                            6 => State::Offset {
                                header,
                                distance: 0,
                                first: true,
                            },
                            7 => State::Reference {
                                header,
                                bytes: [0; 32],
                                length: 0,
                            },
                            _ => bail!("pack stream contains a reserved object type"),
                        }
                    }
                }
                State::Offset {
                    mut header,
                    mut distance,
                    first,
                } => {
                    let byte = input[0];
                    header.crc.update(&input[..1]);
                    self.consume(&input[..1]);
                    input = &input[1..];
                    distance = if first {
                        u64::from(byte & 0x7f)
                    } else {
                        distance
                            .checked_add(1)
                            .and_then(|value| value.checked_mul(128))
                            .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
                            .context("offset-delta distance overflows")?
                    };
                    if byte & 0x80 != 0 {
                        State::Offset {
                            header,
                            distance,
                            first: false,
                        }
                    } else {
                        ensure!(distance > 0, "offset delta has no earlier base");
                        let base = header
                            .offset
                            .checked_sub(distance)
                            .context("offset-delta base precedes the pack")?;
                        header.inflate(PackedKind::OffsetDelta(base))
                    }
                }
                State::Reference {
                    mut header,
                    mut bytes,
                    mut length,
                } => {
                    let count = (32 - length).min(input.len());
                    bytes[length..length + count].copy_from_slice(&input[..count]);
                    header.crc.update(&input[..count]);
                    self.consume(&input[..count]);
                    input = &input[count..];
                    length += count;
                    if length < 32 {
                        State::Reference {
                            header,
                            bytes,
                            length,
                        }
                    } else {
                        header.inflate(PackedKind::ReferenceDelta(bytes))
                    }
                }
                State::Inflate(mut entry) => {
                    let mut scratch = [0_u8; CHUNK_BYTES];
                    let before_in = entry.decoder.total_in();
                    let before_out = entry.decoder.total_out();
                    let status = entry
                        .decoder
                        .decompress(input, &mut scratch, FlushDecompress::None)
                        .context("inflating streamed packed object")?;
                    let consumed = usize::try_from(entry.decoder.total_in() - before_in)?;
                    let produced = usize::try_from(entry.decoder.total_out() - before_out)?;
                    let size = entry
                        .data
                        .len()
                        .checked_add(produced)
                        .context("decoded pack size overflows")?;
                    ensure!(
                        size <= entry.header.declared_size,
                        "packed object inflates past its declared size"
                    );
                    ensure!(
                        self.decoded_bytes
                            .checked_add(size)
                            .is_some_and(|total| total <= MAX_DECODED_PACK_BYTES),
                        "pack stream exceeds its aggregate decoded-size limit"
                    );
                    // Reserve only the independently bounded output being retained.
                    entry.data.try_reserve_exact(produced)?;
                    entry.data.extend_from_slice(&scratch[..produced]);
                    entry.header.crc.update(&input[..consumed]);
                    self.consume(&input[..consumed]);
                    input = &input[consumed..];
                    if status == Status::StreamEnd {
                        ensure!(
                            size == entry.header.declared_size,
                            "packed object does not match its declared size"
                        );
                        ensure!(
                            entry.decoder.total_in() > 0,
                            "packed object zlib stream is empty"
                        );
                        self.decoded_bytes += size;
                        self.entries.push(PackedEntry {
                            offset: entry.header.offset,
                            crc: entry.header.crc.finalize(),
                            kind: entry.kind,
                            data: entry.data,
                        });
                        self.next_entry()
                    } else if consumed == 0 && produced == 0 {
                        ensure!(input.is_empty(), "packed object inflater made no progress");
                        self.state = State::Inflate(entry);
                        break;
                    } else {
                        State::Inflate(entry)
                    }
                }
                State::Trailer {
                    mut bytes,
                    mut length,
                } => {
                    let count = (32 - length).min(input.len());
                    bytes[length..length + count].copy_from_slice(&input[..count]);
                    input = &input[count..];
                    length += count;
                    if length < 32 {
                        State::Trailer { bytes, length }
                    } else {
                        ensure!(
                            bytes == self.expected_checksum
                                && self.payload_hash.clone().finalize()[..]
                                    == self.expected_checksum,
                            "pack bytes do not match their filename checksum"
                        );
                        State::Complete
                    }
                }
                State::Complete => bail!("pack stream has trailing bytes"),
                State::Failed => bail!("pack stream previously failed"),
            };
        }
        Ok(())
    }

    fn next_entry(&self) -> State {
        if self.entries.len() == self.expected_count {
            State::Trailer {
                bytes: [0; 32],
                length: 0,
            }
        } else {
            State::Object(EntryHeader::new(self.position))
        }
    }

    pub(super) fn finish(self) -> Result<ParsedPack> {
        ensure!(
            matches!(self.state, State::Complete),
            "pack stream is incomplete or failed"
        );
        Ok(ParsedPack {
            entries: self.entries,
            encoded_hash: self.encoded_hash.finalize().into(),
            encoded_bytes: self.encoded_bytes,
            decoded_bytes: self.decoded_bytes,
        })
    }
}
