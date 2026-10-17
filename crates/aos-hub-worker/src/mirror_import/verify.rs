//! Incremental mirror file and NAR verification with fixed allocation ceilings.
//!
//! Zstandard frames are decoded one complete block at a time. The decoder's
//! window is checked before allocation, and output goes directly into a bounded
//! SHA-256 writer. Neither compressed nor uncompressed whole objects are kept.

use std::io::{Cursor, Write};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::mirror_work::MirrorVerification;
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use sha2::{Digest as _, Sha256};

#[cfg(test)]
mod tests;

const MAX_WINDOW: u64 = 8 * 1024 * 1024;
const MAX_BLOCK: usize = 128 * 1024;
const MAX_PENDING: usize = MAX_BLOCK + 32;
const INPUT_SLICE: usize = 64 * 1024;

struct MeasuredHash {
    hash: Sha256,
    bytes: u64,
    maximum: u64,
}

impl MeasuredHash {
    fn new(maximum: u64) -> Self {
        Self {
            hash: Sha256::new(),
            bytes: 0,
            maximum,
        }
    }

    fn update(&mut self, bytes: &[u8]) -> Result<()> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .context("mirror hash byte count overflowed")?;
        ensure!(
            next <= self.maximum,
            "mirror source exceeds its original byte bound"
        );
        self.hash.update(bytes);
        self.bytes = next;
        Ok(())
    }

    fn finish(self) -> (u64, String) {
        (self.bytes, hex::encode(self.hash.finalize()))
    }
}

impl Write for MeasuredHash {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.update(bytes)
            .map_err(|_| std::io::Error::other("mirror decoded bytes exceed original bound"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Verifies a representation and its Native-selected plain identity incrementally.
pub(crate) struct Verifier {
    original: MirrorVerification,
    file: MeasuredHash,
    plain: Option<MeasuredHash>,
    decoder: FrameDecoder,
    pending: Vec<u8>,
    window_limit: u64,
    frame_active: bool,
    frame_checksum: bool,
    frames: usize,
    peak_pending: usize,
}

impl Verifier {
    pub(crate) fn new(original: &MirrorVerification) -> Result<Self> {
        original.validate()?;
        let plain = match original {
            MirrorVerification::Nar { nar_size, .. } => Some(MeasuredHash::new(*nar_size)),
            _ => None,
        };
        let decoded = match original {
            MirrorVerification::Nar { nar_size, .. } => *nar_size,
            _ => original.size(),
        };
        let zstd = matches!(original, MirrorVerification::Nar { compression, .. } if compression == "zstd");
        let window_limit = if !zstd
            && decoded.max(original.size())
                <= aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFER_BYTES
        {
            aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFER_BYTES
        } else {
            MAX_WINDOW
        };
        Ok(Self {
            window_limit,
            original: original.clone(),
            file: MeasuredHash::new(original.size()),
            plain,
            decoder: FrameDecoder::new(),
            pending: Vec::with_capacity(MAX_PENDING),
            frame_active: false,
            frame_checksum: false,
            frames: 0,
            peak_pending: 0,
        })
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.update(bytes)?;
        match &self.original {
            MirrorVerification::Sha256 { .. } => return Ok(()),
            MirrorVerification::Nar { compression, .. } if compression == "none" => {
                self.plain
                    .as_mut()
                    .context("mirror plain hash missing")?
                    .update(bytes)?;
                return Ok(());
            }
            _ => {}
        }
        for slice in bytes.chunks(INPUT_SLICE) {
            let mut rest = slice;
            while !rest.is_empty() {
                self.decode_pending()?;
                let count = rest.len().min(MAX_PENDING - self.pending.len());
                ensure!(count > 0, "mirror compressed block exceeds decoder bound");
                self.pending.extend_from_slice(&rest[..count]);
                self.peak_pending = self.peak_pending.max(self.pending.len());
                rest = &rest[count..];
            }
        }
        self.decode_pending()
    }

    fn decode_pending(&mut self) -> Result<()> {
        loop {
            if !self.frame_active {
                let Some((header_bytes, checksum)) =
                    frame_header(&self.pending, self.window_limit)?
                else {
                    return Ok(());
                };
                self.decoder
                    .init(Cursor::new(&self.pending[..header_bytes]))?;
                self.pending.drain(..header_bytes);
                self.frame_checksum = checksum;
                self.frame_active = true;
                self.frames += 1;
                ensure!(
                    self.frames <= 16_384,
                    "mirror source exceeds frame count bound"
                );
            }
            if self.pending.len() < 3 {
                return Ok(());
            }
            let header = u32::from_le_bytes([self.pending[0], self.pending[1], self.pending[2], 0]);
            let last = header & 1 != 0;
            let kind = (header >> 1) & 3;
            let declared = (header >> 3) as usize;
            ensure!(
                kind != 3 && declared <= MAX_BLOCK,
                "mirror compressed block is invalid"
            );
            let body = if kind == 1 { 1 } else { declared };
            let consumed = 3 + body + usize::from(last && self.frame_checksum) * 4;
            if self.pending.len() < consumed {
                return Ok(());
            }
            self.decoder.decode_blocks(
                Cursor::new(&self.pending[..consumed]),
                BlockDecodingStrategy::UptoBlocks(1),
            )?;
            self.pending.drain(..consumed);
            self.decoder
                .collect_to_writer(self.plain.as_mut().context("mirror plain hash missing")?)?;
            if last {
                ensure!(self.decoder.is_finished(), "mirror frame did not finish");
                if self.frame_checksum {
                    ensure!(
                        self.decoder.get_checksum_from_data()
                            == self.decoder.get_calculated_checksum(),
                        "mirror frame checksum differs"
                    );
                }
                self.decoder = FrameDecoder::new();
                self.frame_active = false;
            }
        }
    }

    pub(crate) fn finish(mut self) -> Result<(String, Option<(u64, String)>)> {
        self.decode_pending()?;
        ensure!(
            !self.frame_active && self.pending.is_empty(),
            "mirror compressed stream is truncated"
        );
        let (size, file_sha256) = self.file.finish();
        ensure!(
            size == self.original.size(),
            "mirror representation has a different length"
        );
        let plain = self.plain.map(MeasuredHash::finish);
        match &self.original {
            MirrorVerification::Sha256 { sha256, .. } => ensure!(
                &file_sha256 == sha256,
                "mirror bytes differ from verified metadata"
            ),
            MirrorVerification::Nar {
                compression,
                file_sha256: expected_file,
                nar_sha256,
                nar_size,
                ..
            } => {
                ensure!(
                    compression != "zstd" || self.frames > 0,
                    "mirror compressed source has no frame"
                );
                ensure!(
                    expected_file
                        .as_ref()
                        .is_none_or(|value| value == &file_sha256),
                    "mirror compressed file hash differs"
                );
                ensure!(
                    plain.as_ref() == Some(&(*nar_size, nar_sha256.clone())),
                    "mirror bytes differ from selected NAR identity"
                );
            }
        }
        Ok((file_sha256, plain))
    }
}

/// Checks the advertised decoder window before allocating any decoder state.
fn frame_header(bytes: &[u8], window_limit: u64) -> Result<Option<(usize, bool)>> {
    if bytes.len() < 5 {
        return Ok(None);
    }
    ensure!(
        bytes[..4] == [0x28, 0xb5, 0x2f, 0xfd],
        "mirror source has an unsupported frame"
    );
    let descriptor = bytes[4];
    ensure!(descriptor & 0x18 == 0, "mirror frame descriptor is invalid");
    let single = descriptor & 0x20 != 0;
    let fcs = match descriptor >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let dictionary = match descriptor & 3 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let length = 5 + usize::from(!single) + dictionary + fcs;
    if bytes.len() < length {
        return Ok(None);
    }
    let dictionary_start = 5 + usize::from(!single);
    ensure!(
        bytes[dictionary_start..dictionary_start + dictionary]
            .iter()
            .all(|byte| *byte == 0),
        "mirror zstd dictionaries are unsupported"
    );
    let window = if single {
        let mut encoded = [0u8; 8];
        encoded[..fcs].copy_from_slice(&bytes[length - fcs..length]);
        u64::from_le_bytes(encoded) + if fcs == 2 { 256 } else { 0 }
    } else {
        let descriptor = bytes[5];
        let base = 1u64
            .checked_shl(10 + u32::from(descriptor >> 3))
            .context("mirror window overflowed")?;
        base + (base / 8) * u64::from(descriptor & 7)
    };
    ensure!(
        window <= window_limit,
        "mirror decoder window exceeds its allocation bound"
    );
    Ok(Some((length, descriptor & 4 != 0)))
}
