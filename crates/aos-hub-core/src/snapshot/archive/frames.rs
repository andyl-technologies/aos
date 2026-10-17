//! Fixed v1 stream headers, bounded AEAD frames and terminal commitments.

use std::fmt;
use std::io::{Read, Write};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{FreshStreamKey, StreamContext, StreamDecryptionKey};

pub(super) const HEADER_BYTES: usize = 36;
pub(super) const PREFIX_BYTES: usize = 16;
pub(super) const COMMITMENT_BYTES: usize = 48;
pub(super) const TAG_BYTES: usize = 16;
pub(super) const FRAME_CAP: usize = 256 * 1024;
const END_BYTES: usize = PREFIX_BYTES + COMMITMENT_BYTES + TAG_BYTES;
const MAX_DATA_FRAMES: u64 = 1 << 24;
const MAX_PLAINTEXT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES: u64 = MAX_PLAINTEXT_BYTES
    + MAX_DATA_FRAMES * (PREFIX_BYTES + TAG_BYTES) as u64
    + (HEADER_BYTES + END_BYTES) as u64;
const DOMAIN: &[u8] = b"aos.hub.snapshot-stream-frame/v1\0";
const DATA: u8 = 0;
const END: u8 = 1;

/// Local bounded verification/capture budgets, never selected by stream bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    /// Maximum DATA frames, at most 2^24; zero admits only an empty stream.
    pub max_data_frames: u64,
    /// Maximum total original plaintext bytes, at most 64 GiB.
    pub max_plaintext_bytes: u64,
    /// Maximum complete encoded bytes, including header and END.
    pub max_ciphertext_bytes: u64,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_data_frames: MAX_DATA_FRAMES,
            max_plaintext_bytes: MAX_PLAINTEXT_BYTES,
            max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        }
    }
}

impl StreamLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            self.max_data_frames <= MAX_DATA_FRAMES
                && self.max_plaintext_bytes <= MAX_PLAINTEXT_BYTES
                && self.max_ciphertext_bytes >= (HEADER_BYTES + END_BYTES) as u64
                && self.max_ciphertext_bytes <= MAX_CIPHERTEXT_BYTES,
            "snapshot stream limits are invalid"
        );
        Ok(())
    }
}

/// Counts and hashes verified by stream framing, never a recovery permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSummary {
    /// Number of authenticated DATA frames, excluding END.
    pub data_frames: u64,
    /// Total original plaintext bytes, independent of encoded overhead.
    pub plaintext_bytes: u64,
    /// Exact total encoded byte length, including END.
    pub ciphertext_bytes: u64,
    /// SHA-256 of the exact entire ciphertext stream, including END.
    pub ciphertext_sha256: [u8; 32],
}

/// One bounded authenticated plaintext chunk behind a private boundary.
///
/// A DATA frame is authenticated independently. Whole-stream completion is
/// established only after the decoder accepts END and observes clean EOF.
/// The wrapper has redacted Debug and no automatic serialization.
pub struct PrivateStreamChunk(Zeroizing<Vec<u8>>);

impl fmt::Debug for PrivateStreamChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateStreamChunk { <redacted> }")
    }
}

impl PrivateStreamChunk {
    /// Returns the chunk length without exposing plaintext.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the chunk is empty; valid DATA chunks are nonempty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Runs an explicitly private callback on authenticated frame bytes.
    ///
    /// Copies, logs, transports and typed interpretation remain caller-owned.
    pub fn with_private_bytes<T>(&self, callback: impl FnOnce(&[u8]) -> T) -> T {
        callback(&self.0)
    }
}

/// A fresh one-use encoder buffering at most one bounded plaintext frame.
///
/// A write/authentication failure poisons the encoder. No nonce reset, retry,
/// resume, raw cipher/key access, or partial-completion summary is exposed.
pub struct StreamEncoder<W: Write> {
    writer: W,
    cipher: Aes256Gcm,
    header: [u8; HEADER_BYTES],
    limits: StreamLimits,
    buffer: Zeroizing<Vec<u8>>,
    data_frames: u64,
    plaintext_bytes: u64,
    ciphertext_bytes: u64,
    hash: Sha256,
    failed: bool,
}

impl<W: Write> fmt::Debug for StreamEncoder<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamEncoder { <redacted> }")
    }
}

impl<W: Write> StreamEncoder<W> {
    /// Starts a stream with fixed v1 header semantics and a fresh consumed key.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, key initialization, or writer failure with
    /// value-free errors. The sink may retain an incomplete ciphertext prefix.
    pub fn new(
        mut writer: W,
        key: FreshStreamKey,
        context: StreamContext,
        limits: StreamLimits,
    ) -> Result<Self> {
        limits.validate()?;
        let cipher = Aes256Gcm::new_from_slice(&key.0[..])
            .map_err(|_| anyhow::anyhow!("snapshot stream key is invalid"))?;
        let header = header(context);
        write_bytes(&mut writer, &header)?;
        let mut hash = Sha256::new();
        hash.update(header);

        Ok(Self {
            writer,
            cipher,
            header,
            limits,
            buffer: Zeroizing::new(Vec::with_capacity(FRAME_CAP)),
            data_frames: 0,
            plaintext_bytes: 0,
            ciphertext_bytes: HEADER_BYTES as u64,
            hash,
            failed: false,
        })
    }

    /// Streams arbitrary bytes into fixed-size encrypted DATA frames.
    ///
    /// Empty writes create no DATA frame. Frame boundaries may split any typed
    /// record; no record grammar or end marker is inferred from these bytes.
    ///
    /// # Errors
    ///
    /// Rejects cumulative limits, a previously failed encoder, or encryption/
    /// writer failure. Any failure poisons the encoder and clears pending bytes.
    pub fn write_plaintext(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(!self.failed, "snapshot stream encoder has failed");
        let result = self.write_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.buffer.zeroize();
            self.buffer.clear();
        }
        result
    }

    fn write_inner(&mut self, mut bytes: &[u8]) -> Result<()> {
        let total = checked_add(self.plaintext_bytes, bytes.len() as u64)?;
        let frames = total.div_ceil(FRAME_CAP as u64);
        ensure!(
            total <= self.limits.max_plaintext_bytes && frames <= self.limits.max_data_frames,
            "snapshot stream plaintext or frame limit exceeded"
        );
        let projected = checked_add(
            checked_add(total, frames * (PREFIX_BYTES + TAG_BYTES) as u64)?,
            (HEADER_BYTES + END_BYTES) as u64,
        )?;
        ensure!(
            projected <= self.limits.max_ciphertext_bytes,
            "snapshot stream ciphertext limit exceeded"
        );
        self.plaintext_bytes = total;

        while !bytes.is_empty() {
            let take = bytes.len().min(FRAME_CAP - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() == FRAME_CAP {
                self.flush_data()?;
            }
        }
        Ok(())
    }

    fn flush_data(&mut self) -> Result<()> {
        ensure!(
            !self.buffer.is_empty() && self.data_frames < self.limits.max_data_frames,
            "snapshot stream data frame is invalid"
        );
        let length = self.buffer.len() + TAG_BYTES;
        let prefix = prefix(self.data_frames, DATA, length as u32);
        let nonce = nonce(self.data_frames);
        let aad = aad(&self.header, &prefix, None);
        let mut ciphertext = Zeroizing::new(Vec::with_capacity(length));
        ciphertext.extend_from_slice(&self.buffer);
        self.cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut *ciphertext)
            .map_err(|_| anyhow::anyhow!("snapshot stream encryption failed"))?;
        self.write_hashed(&prefix)?;
        self.write_hashed(&ciphertext)?;
        self.data_frames = checked_add(self.data_frames, 1)?;
        self.buffer.zeroize();
        self.buffer.clear();
        Ok(())
    }

    fn write_hashed(&mut self, bytes: &[u8]) -> Result<()> {
        let total = checked_add(self.ciphertext_bytes, bytes.len() as u64)?;
        ensure!(
            total <= self.limits.max_ciphertext_bytes,
            "snapshot stream ciphertext limit exceeded"
        );
        write_bytes(&mut self.writer, bytes)?;
        self.hash.update(bytes);
        self.ciphertext_bytes = total;
        Ok(())
    }

    /// Finishes with an authenticated empty END frame and returns framing proof.
    ///
    /// The caller owns durable sink synchronization and artifact publication.
    /// This does not authenticate typed record counts or capture completeness.
    ///
    /// # Errors
    ///
    /// Rejects a failed encoder or any remaining limit/encryption/writer error.
    /// A failure consumes the encoder and yields no completion summary.
    pub fn finish(mut self) -> Result<(W, StreamSummary)> {
        ensure!(!self.failed, "snapshot stream encoder has failed");
        if !self.buffer.is_empty() {
            self.flush_data()?;
        }
        let prior: [u8; 32] = self.hash.clone().finalize().into();
        let commitment = commitment(self.data_frames, self.plaintext_bytes, prior);
        let prefix = prefix(self.data_frames, END, TAG_BYTES as u32);
        let nonce = nonce(self.data_frames);
        let aad = aad(&self.header, &prefix, Some(&commitment));
        let mut tag = Zeroizing::new(Vec::new());
        self.cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut *tag)
            .map_err(|_| anyhow::anyhow!("snapshot stream encryption failed"))?;
        self.write_hashed(&prefix)?;
        self.write_hashed(&commitment)?;
        self.write_hashed(&tag)?;
        let summary = StreamSummary {
            data_frames: self.data_frames,
            plaintext_bytes: self.plaintext_bytes,
            ciphertext_bytes: self.ciphertext_bytes,
            ciphertext_sha256: self.hash.finalize().into(),
        };
        Ok((self.writer, summary))
    }
}

/// A bounded decoder requiring authenticated END and clean EOF for completion.
///
/// A returned DATA chunk is individually authenticated but does not establish
/// whole-stream completeness. A read/authentication failure poisons this decoder.
pub struct StreamDecoder<R: Read> {
    reader: R,
    cipher: Aes256Gcm,
    header: [u8; HEADER_BYTES],
    limits: StreamLimits,
    data_frames: u64,
    plaintext_bytes: u64,
    ciphertext_bytes: u64,
    hash: Sha256,
    failed: bool,
    summary: Option<StreamSummary>,
}

impl<R: Read> fmt::Debug for StreamDecoder<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamDecoder { <redacted> }")
    }
}

impl<R: Read> StreamDecoder<R> {
    /// Accepts only the fixed header matching an externally expected context.
    ///
    /// # Errors
    ///
    /// Rejects unsupported/altered context, header, limits, or input/key errors.
    /// Errors contain no input bytes, key material, or reader error context.
    pub fn new(
        mut reader: R,
        key: StreamDecryptionKey,
        context: StreamContext,
        limits: StreamLimits,
    ) -> Result<Self> {
        limits.validate()?;
        let mut encoded = [0u8; HEADER_BYTES];
        read_bytes(&mut reader, &mut encoded)?;
        ensure!(encoded == header(context), "snapshot stream header differs");
        let cipher = Aes256Gcm::new_from_slice(&key.0[..])
            .map_err(|_| anyhow::anyhow!("snapshot stream key is invalid"))?;
        let mut hash = Sha256::new();
        hash.update(encoded);

        Ok(Self {
            reader,
            cipher,
            header: encoded,
            limits,
            data_frames: 0,
            plaintext_bytes: 0,
            ciphertext_bytes: HEADER_BYTES as u64,
            hash,
            failed: false,
            summary: None,
        })
    }

    /// Returns one private DATA chunk, or None after END and exact clean EOF.
    ///
    /// The caller must reach None and inspect [`Self::summary`] before claiming
    /// framing completion. Subsequent calls after verified END return None.
    ///
    /// # Errors
    ///
    /// Rejects limits, invalid lengths/sequence/kind/reserved fields, tampering,
    /// missing/truncated END, counters/hash mismatch, trailing bytes, or I/O.
    /// A failure poisons the decoder and exposes no unauthenticated plaintext.
    pub fn next_chunk(&mut self) -> Result<Option<PrivateStreamChunk>> {
        ensure!(!self.failed, "snapshot stream decoder has failed");
        if self.summary.is_some() {
            return Ok(None);
        }
        let result = self.next_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn next_inner(&mut self) -> Result<Option<PrivateStreamChunk>> {
        let mut prefix = [0u8; PREFIX_BYTES];
        read_bytes(&mut self.reader, &mut prefix)?;
        let sequence = u64_at(&prefix, 0)?;
        ensure!(
            sequence == self.data_frames && prefix[9..12] == [0u8; 3],
            "snapshot stream frame sequence or reserved fields differ"
        );
        let length = u32_at(&prefix, 12)? as usize;
        match prefix[8] {
            DATA => self.read_data(prefix, length),
            END => self.read_end(prefix, length),
            _ => anyhow::bail!("snapshot stream frame kind is unknown"),
        }
    }

    fn read_data(
        &mut self,
        prefix: [u8; PREFIX_BYTES],
        length: usize,
    ) -> Result<Option<PrivateStreamChunk>> {
        ensure!(
            length > TAG_BYTES && length <= FRAME_CAP + TAG_BYTES,
            "snapshot stream data length is invalid"
        );
        let plaintext_total = checked_add(self.plaintext_bytes, (length - TAG_BYTES) as u64)?;
        let frame_total = checked_add(self.data_frames, 1)?;
        let encoded_total = checked_add(self.ciphertext_bytes, (PREFIX_BYTES + length) as u64)?;
        ensure!(
            plaintext_total <= self.limits.max_plaintext_bytes
                && frame_total <= self.limits.max_data_frames
                && checked_add(encoded_total, END_BYTES as u64)?
                    <= self.limits.max_ciphertext_bytes,
            "snapshot stream data limits exceeded"
        );
        let mut ciphertext = Zeroizing::new(vec![0u8; length]);
        read_bytes(&mut self.reader, &mut ciphertext)?;
        let nonce = nonce(self.data_frames);
        let aad = aad(&self.header, &prefix, None);
        // Hash the exact ciphertext before in-place decryption transforms it.
        let mut next_hash = self.hash.clone();
        next_hash.update(prefix);
        next_hash.update(&ciphertext[..]);
        self.cipher
            .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut *ciphertext)
            .map_err(|_| anyhow::anyhow!("snapshot stream authentication failed"))?;
        self.hash = next_hash;
        self.data_frames = frame_total;
        self.plaintext_bytes = plaintext_total;
        self.ciphertext_bytes = encoded_total;
        Ok(Some(PrivateStreamChunk(ciphertext)))
    }

    fn read_end(
        &mut self,
        prefix: [u8; PREFIX_BYTES],
        length: usize,
    ) -> Result<Option<PrivateStreamChunk>> {
        ensure!(length == TAG_BYTES, "snapshot stream end length is invalid");
        let total = checked_add(self.ciphertext_bytes, END_BYTES as u64)?;
        ensure!(
            total <= self.limits.max_ciphertext_bytes,
            "snapshot stream ciphertext limit exceeded"
        );
        let mut encoded_commitment = [0u8; COMMITMENT_BYTES];
        read_bytes(&mut self.reader, &mut encoded_commitment)?;
        let mut tag = Zeroizing::new(vec![0u8; TAG_BYTES]);
        read_bytes(&mut self.reader, &mut tag)?;
        let nonce = nonce(self.data_frames);
        let aad = aad(&self.header, &prefix, Some(&encoded_commitment));
        let mut next_hash = self.hash.clone();
        next_hash.update(prefix);
        next_hash.update(encoded_commitment);
        next_hash.update(&tag[..]);
        self.cipher
            .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut *tag)
            .map_err(|_| anyhow::anyhow!("snapshot stream authentication failed"))?;
        let prior: [u8; 32] = self.hash.clone().finalize().into();
        ensure!(
            tag.is_empty()
                && encoded_commitment == commitment(self.data_frames, self.plaintext_bytes, prior),
            "snapshot stream end commitment differs"
        );
        clean_eof(&mut self.reader)?;
        self.hash = next_hash;
        self.ciphertext_bytes = total;
        self.summary = Some(StreamSummary {
            data_frames: self.data_frames,
            plaintext_bytes: self.plaintext_bytes,
            ciphertext_bytes: total,
            ciphertext_sha256: self.hash.clone().finalize().into(),
        });
        Ok(None)
    }

    /// Borrows framing completion only after authenticated END and clean EOF.
    pub fn summary(&self) -> Option<&StreamSummary> {
        self.summary.as_ref()
    }
}

fn header(context: StreamContext) -> [u8; HEADER_BYTES] {
    let mut bytes = [0u8; HEADER_BYTES];
    bytes[..8].copy_from_slice(b"AOSHSTRM");
    bytes[8..10].copy_from_slice(&1u16.to_be_bytes());
    bytes[10] = 1;
    bytes[11] = context.role.tag();
    bytes[12..28].copy_from_slice(&context.archive_id);
    bytes[28..32].copy_from_slice(&(FRAME_CAP as u32).to_be_bytes());
    bytes
}

fn prefix(sequence: u64, kind: u8, length: u32) -> [u8; PREFIX_BYTES] {
    let mut bytes = [0u8; PREFIX_BYTES];
    bytes[..8].copy_from_slice(&sequence.to_be_bytes());
    bytes[8] = kind;
    bytes[12..].copy_from_slice(&length.to_be_bytes());
    bytes
}

fn commitment(frames: u64, plaintext_bytes: u64, digest: [u8; 32]) -> [u8; COMMITMENT_BYTES] {
    let mut bytes = [0u8; COMMITMENT_BYTES];
    bytes[..8].copy_from_slice(&frames.to_be_bytes());
    bytes[8..16].copy_from_slice(&plaintext_bytes.to_be_bytes());
    bytes[16..].copy_from_slice(&digest);
    bytes
}

fn nonce(sequence: u64) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(b"AOSH");
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    bytes
}

fn aad(
    header: &[u8; HEADER_BYTES],
    prefix: &[u8; PREFIX_BYTES],
    commitment: Option<&[u8; COMMITMENT_BYTES]>,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(DOMAIN.len() + HEADER_BYTES + PREFIX_BYTES + COMMITMENT_BYTES);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(prefix);
    if let Some(commitment) = commitment {
        bytes.extend_from_slice(commitment);
    }
    bytes
}

fn checked_add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| anyhow::anyhow!("snapshot stream counter overflow"))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let encoded = bytes
        .get(offset..offset + 8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .ok_or_else(|| anyhow::anyhow!("snapshot stream fixed field is invalid"))?;
    Ok(u64::from_be_bytes(encoded))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let encoded = bytes
        .get(offset..offset + 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or_else(|| anyhow::anyhow!("snapshot stream fixed field is invalid"))?;
    Ok(u32::from_be_bytes(encoded))
}

fn read_bytes(reader: &mut impl Read, bytes: &mut [u8]) -> Result<()> {
    reader
        .read_exact(bytes)
        .map_err(|_| anyhow::anyhow!("snapshot stream input is truncated or unavailable"))
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    writer
        .write_all(bytes)
        .map_err(|_| anyhow::anyhow!("snapshot stream output failed"))
}

fn clean_eof(reader: &mut impl Read) -> Result<()> {
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => anyhow::bail!("snapshot stream has trailing bytes"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => anyhow::bail!("snapshot stream input failed"),
        }
    }
}
