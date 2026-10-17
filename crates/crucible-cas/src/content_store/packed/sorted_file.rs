//! Checksummed block files of fixed-width records sorted by a strict key.
//!
//! The packed index base and the pack table share one immutable layout. A
//! reader binary-searches whole blocks with positioned reads, so a lookup
//! costs `O(log blocks)` reads of about 4 KiB and never maps or loads the file.
//! Every block checksum binds the file header and the block ordinal, so a
//! probed block cannot be transplanted from another file, position, backend
//! instance, or generation. A complete iteration also recomputes the
//! whole-file digest that names the file and that the index root commits.
//!
//! ```text
//! SortedFile =
//!   magic                         # per record type, NUL terminated
//!   configuration[32]
//!   backend_instance[32]
//!   generation_u64
//!   repeated block_count {
//!     record[record_width] * n    # n = block_records except in the final block
//!     block_checksum[32]          # BLAKE3(block_domain || header || BE64(block) || records)
//!   }
//!   record_count_u64
//!   trailer_checksum[32]          # BLAKE3(trailer_domain || header || record_count_u64)
//!
//! file_digest = BLAKE3(digest_domain || every file byte)
//! ```
//!
//! Records are strictly increasing by key across the whole file. The file
//! length must equal the length implied by `record_count`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::marker::PhantomData;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::{StoreError, create_temporary, io_error, open_regular_file, remove_temporary};

/// Static description of one sorted-file record type.
pub(super) struct SortedFileFormat {
    /// Leading magic, including its trailing NUL.
    pub(super) magic: &'static [u8],
    /// Domain of each block checksum.
    pub(super) block_domain: &'static [u8],
    /// Domain of the trailer checksum.
    pub(super) trailer_domain: &'static [u8],
    /// Domain of the whole-file digest.
    pub(super) digest_domain: &'static [u8],
    /// Exact encoded record width.
    pub(super) record_width: usize,
    /// Records in every block except the final one.
    pub(super) block_records: usize,
}

/// Fixed-width record stored in a [`SortedFile`].
pub(super) trait SortedRecord: Copy {
    /// Strictly increasing sort key.
    type Key: Ord + Copy;

    /// Layout and domains for this record type.
    const FORMAT: SortedFileFormat;

    /// Returns this record's sort key.
    fn key(&self) -> Self::Key;

    /// Writes exactly `FORMAT.record_width` bytes.
    fn encode(&self, output: &mut [u8]);

    /// Strictly decodes exactly `FORMAT.record_width` bytes.
    fn decode(bytes: &[u8]) -> Result<Self, StoreError>;
}

/// Header fields that every block and the trailer bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SortedFileIdentity {
    pub(super) configuration: [u8; 32],
    pub(super) instance: [u8; 32],
    pub(super) generation: u64,
}

/// Number of blocks read by one positioned read during iteration.
const ITERATION_CHUNK_BLOCKS: u64 = 16;

/// Opened immutable sorted file.
pub(super) struct SortedFile<R> {
    file: File,
    path: PathBuf,
    header: Vec<u8>,
    record_count: u64,
    block_count: u64,
    generation: u64,
    _record: PhantomData<R>,
}

impl<R: SortedRecord> SortedFile<R> {
    /// Opens `path` and checks its header, trailer, and exact length.
    ///
    /// Opening does not read blocks; [`Self::iter`] authenticates the whole
    /// file and each lookup authenticates the blocks it probes.
    pub(super) fn open(
        path: &Path,
        configuration: [u8; 32],
        instance: [u8; 32],
    ) -> Result<Self, StoreError> {
        let file = open_regular_file(path, "open packed sorted file")?;
        let length = file
            .metadata()
            .map_err(|source| io_error("inspect packed sorted file", path, source))?
            .len();
        let header_length = header_length::<R>();
        let minimum = header_length + TRAILER_BYTES;
        if length < minimum as u64 {
            return Err(StoreError::Incompatible);
        }

        let mut header = vec![0_u8; header_length];
        read_exact_at(&file, &mut header, 0, path)?;
        let magic_length = R::FORMAT.magic.len();
        if &header[..magic_length] != R::FORMAT.magic
            || header[magic_length..magic_length + 32] != configuration
            || header[magic_length + 32..magic_length + 64] != instance
        {
            return Err(StoreError::Incompatible);
        }
        let generation = be_u64(&header[magic_length + 64..])?;

        let mut trailer = [0_u8; TRAILER_BYTES];
        read_exact_at(&file, &mut trailer, length - TRAILER_BYTES as u64, path)?;
        let record_count = be_u64(&trailer[..8])?;
        if trailer[8..] != trailer_checksum::<R>(&header, record_count) {
            return Err(StoreError::Incompatible);
        }
        let block_count = block_count::<R>(record_count);
        if file_length::<R>(record_count)? != length {
            return Err(StoreError::Incompatible);
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header,
            record_count,
            block_count,
            generation,
            _record: PhantomData,
        })
    }

    /// Returns the number of records in the file.
    pub(super) const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Returns the index generation the file was written at.
    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Finds the record whose key equals `key`.
    ///
    /// Each probed block is authenticated before any of its records is used.
    pub(super) fn find(&self, key: R::Key) -> Result<Option<R>, StoreError> {
        let mut buffer = Vec::new();
        let mut low = 0_u64;
        let mut high = self.block_count;
        while low < high {
            let middle = low + (high - low) / 2;
            let records = self.read_block(middle, &mut buffer)?;
            let (Some(first), Some(last)) = (records.first(), records.last()) else {
                return Err(StoreError::Incompatible);
            };
            if key < first.key() {
                high = middle;
            } else if key > last.key() {
                low = middle + 1;
            } else {
                return Ok(records
                    .binary_search_by_key(&key, R::key)
                    .ok()
                    .map(|index| records[index]));
            }
        }
        Ok(None)
    }

    /// Streams every record in key order, then checks the whole-file digest.
    pub(super) fn iter(&self, expected_digest: [u8; 32]) -> SortedFileIter<'_, R> {
        let mut digest = blake3::Hasher::new();
        digest.update(R::FORMAT.digest_domain);
        digest.update(&self.header);
        SortedFileIter {
            file: self,
            expected_digest,
            digest,
            next_block: 0,
            chunk: Vec::new(),
            chunk_records: Vec::new(),
            chunk_position: 0,
            last_key: None,
            finished: false,
        }
    }

    fn read_block(&self, block: u64, buffer: &mut Vec<u8>) -> Result<Vec<R>, StoreError> {
        let length = self.block_length(block)?;
        buffer.resize(length, 0);
        read_exact_at(&self.file, buffer, self.block_offset(block)?, &self.path)?;
        decode_block::<R>(&self.header, block, buffer)
    }

    fn block_offset(&self, block: u64) -> Result<u64, StoreError> {
        u64::try_from(full_block_bytes::<R>())
            .ok()
            .and_then(|size| size.checked_mul(block))
            .and_then(|offset| offset.checked_add(self.header.len() as u64))
            .ok_or(StoreError::Incompatible)
    }

    fn block_length(&self, block: u64) -> Result<usize, StoreError> {
        let first_record = block
            .checked_mul(R::FORMAT.block_records as u64)
            .ok_or(StoreError::Incompatible)?;
        let records = self
            .record_count
            .checked_sub(first_record)
            .filter(|remaining| *remaining != 0)
            .ok_or(StoreError::Incompatible)?
            .min(R::FORMAT.block_records as u64);
        usize::try_from(records)
            .ok()
            .and_then(|records| records.checked_mul(R::FORMAT.record_width))
            .and_then(|bytes| bytes.checked_add(CHECKSUM_BYTES))
            .ok_or(StoreError::Incompatible)
    }
}

/// Authenticating sequential reader over one [`SortedFile`].
pub(super) struct SortedFileIter<'a, R: SortedRecord> {
    file: &'a SortedFile<R>,
    expected_digest: [u8; 32],
    digest: blake3::Hasher,
    next_block: u64,
    chunk: Vec<u8>,
    chunk_records: Vec<R>,
    chunk_position: usize,
    last_key: Option<R::Key>,
    finished: bool,
}

impl<R: SortedRecord> SortedFileIter<'_, R> {
    fn fill_chunk(&mut self) -> Result<bool, StoreError> {
        if self.next_block == self.file.block_count {
            self.finish_digest()?;
            return Ok(false);
        }

        let blocks = (self.file.block_count - self.next_block).min(ITERATION_CHUNK_BLOCKS);
        let start = self.file.block_offset(self.next_block)?;
        let mut lengths = Vec::new();
        for block in self.next_block..self.next_block + blocks {
            lengths.push(self.file.block_length(block)?);
        }
        self.chunk.resize(lengths.iter().sum(), 0);
        read_exact_at(&self.file.file, &mut self.chunk, start, &self.file.path)?;
        self.digest.update(&self.chunk);

        self.chunk_records.clear();
        self.chunk_position = 0;
        let mut offset = 0;
        for (block, length) in (self.next_block..).zip(lengths) {
            let records = decode_block::<R>(
                &self.file.header,
                block,
                &self.chunk[offset..offset + length],
            )?;
            self.chunk_records.extend(records);
            offset += length;
        }
        self.next_block += blocks;
        Ok(true)
    }

    fn finish_digest(&mut self) -> Result<(), StoreError> {
        let mut trailer = [0_u8; TRAILER_BYTES];
        let offset = file_length::<R>(self.file.record_count)? - TRAILER_BYTES as u64;
        read_exact_at(&self.file.file, &mut trailer, offset, &self.file.path)?;
        self.digest.update(&trailer);
        if *self.digest.finalize().as_bytes() != self.expected_digest {
            return Err(StoreError::Incompatible);
        }
        Ok(())
    }

    fn next_record(&mut self) -> Result<Option<R>, StoreError> {
        while self.chunk_position == self.chunk_records.len() {
            if !self.fill_chunk()? {
                return Ok(None);
            }
        }
        let record = self.chunk_records[self.chunk_position];
        self.chunk_position += 1;
        if self.last_key.is_some_and(|last| record.key() <= last) {
            return Err(StoreError::Incompatible);
        }
        self.last_key = Some(record.key());
        Ok(Some(record))
    }
}

impl<R: SortedRecord> Iterator for SortedFileIter<'_, R> {
    type Item = Result<R, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let result = self.next_record().transpose();
        if !matches!(result, Some(Ok(_))) {
            self.finished = true;
        }
        result
    }
}

/// Streaming writer that produces one immutable digest-named sorted file.
pub(super) struct SortedFileWriter<R: SortedRecord> {
    directory: PathBuf,
    temporary: PathBuf,
    output: BufWriter<File>,
    header: Vec<u8>,
    digest: blake3::Hasher,
    block: Vec<u8>,
    block_index: u64,
    record_count: u64,
    last_key: Option<R::Key>,
    finished: bool,
}

impl<R: SortedRecord> SortedFileWriter<R> {
    /// Creates a staging file in `directory` for one new sorted file.
    pub(super) fn create(
        directory: &Path,
        label: &str,
        identity: SortedFileIdentity,
    ) -> Result<Self, StoreError> {
        let (temporary, file) = create_temporary(directory, label)?;
        let mut header = Vec::with_capacity(header_length::<R>());
        header.extend_from_slice(R::FORMAT.magic);
        header.extend_from_slice(&identity.configuration);
        header.extend_from_slice(&identity.instance);
        header.extend_from_slice(&identity.generation.to_be_bytes());

        let mut writer = Self {
            directory: directory.to_path_buf(),
            temporary,
            output: BufWriter::with_capacity(64 * 1024, file),
            header,
            digest: blake3::Hasher::new(),
            block: Vec::with_capacity(full_block_bytes::<R>()),
            block_index: 0,
            record_count: 0,
            last_key: None,
            finished: false,
        };
        writer.digest.update(R::FORMAT.digest_domain);
        let header = writer.header.clone();
        writer.write(&header)?;
        Ok(writer)
    }

    /// Appends one record whose key is strictly greater than the previous one.
    pub(super) fn push(&mut self, record: R) -> Result<(), StoreError> {
        if self.last_key.is_some_and(|last| record.key() <= last) {
            return Err(StoreError::Incompatible);
        }
        self.last_key = Some(record.key());

        let start = self.block.len();
        self.block.resize(start + R::FORMAT.record_width, 0);
        record.encode(&mut self.block[start..]);
        self.record_count = self.record_count.checked_add(1).ok_or(StoreError::Quota)?;
        if self.block.len() == R::FORMAT.record_width * R::FORMAT.block_records {
            self.flush_block()?;
        }
        Ok(())
    }

    /// Makes the file durable under `<prefix><hex digest>` and returns the digest.
    ///
    /// The caller syncs the directory once every file of one index publication
    /// has been renamed into place.
    pub(super) fn finish(mut self, prefix: &str) -> Result<[u8; 32], StoreError> {
        if !self.block.is_empty() {
            self.flush_block()?;
        }
        let mut trailer = Vec::with_capacity(TRAILER_BYTES);
        trailer.extend_from_slice(&self.record_count.to_be_bytes());
        trailer.extend_from_slice(&trailer_checksum::<R>(&self.header, self.record_count));
        self.write(&trailer)?;
        self.output
            .flush()
            .and_then(|()| self.output.get_ref().sync_all())
            .map_err(|source| io_error("sync packed sorted file", &self.temporary, source))?;

        let digest = *self.digest.finalize().as_bytes();
        let path = self
            .directory
            .join(format!("{prefix}{}", super::encode_hex(digest)));
        std::fs::rename(&self.temporary, &path)
            .map_err(|source| io_error("publish packed sorted file", &path, source))?;
        self.finished = true;
        Ok(digest)
    }

    fn flush_block(&mut self) -> Result<(), StoreError> {
        let checksum = block_checksum::<R>(&self.header, self.block_index, &self.block);
        self.block.extend_from_slice(&checksum);
        let block = std::mem::take(&mut self.block);
        self.write(&block)?;
        self.block = block;
        self.block.clear();
        self.block_index = self.block_index.checked_add(1).ok_or(StoreError::Quota)?;
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        self.digest.update(bytes);
        self.output
            .write_all(bytes)
            .map_err(|source| io_error("write packed sorted file", &self.temporary, source))
    }
}

impl<R: SortedRecord> Drop for SortedFileWriter<R> {
    fn drop(&mut self) {
        if !self.finished {
            let _ignored = remove_temporary(&self.temporary, false);
        }
    }
}

const CHECKSUM_BYTES: usize = 32;
const TRAILER_BYTES: usize = 8 + CHECKSUM_BYTES;

fn header_length<R: SortedRecord>() -> usize {
    R::FORMAT.magic.len() + 32 + 32 + 8
}

fn full_block_bytes<R: SortedRecord>() -> usize {
    R::FORMAT.record_width * R::FORMAT.block_records + CHECKSUM_BYTES
}

fn block_count<R: SortedRecord>(record_count: u64) -> u64 {
    record_count.div_ceil(R::FORMAT.block_records as u64)
}

/// Returns the exact file length implied by `record_count`.
fn file_length<R: SortedRecord>(record_count: u64) -> Result<u64, StoreError> {
    let blocks = block_count::<R>(record_count);
    let width = R::FORMAT.record_width as u64;
    record_count
        .checked_mul(width)
        .and_then(|records| records.checked_add(blocks.checked_mul(CHECKSUM_BYTES as u64)?))
        .and_then(|body| body.checked_add(header_length::<R>() as u64))
        .and_then(|length| length.checked_add(TRAILER_BYTES as u64))
        .ok_or(StoreError::Incompatible)
}

fn block_checksum<R: SortedRecord>(header: &[u8], block: u64, records: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(R::FORMAT.block_domain);
    hasher.update(header);
    hasher.update(&block.to_be_bytes());
    hasher.update(records);
    *hasher.finalize().as_bytes()
}

fn trailer_checksum<R: SortedRecord>(header: &[u8], record_count: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(R::FORMAT.trailer_domain);
    hasher.update(header);
    hasher.update(&record_count.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Authenticates and decodes one complete block, including its checksum.
fn decode_block<R: SortedRecord>(
    header: &[u8],
    block: u64,
    bytes: &[u8],
) -> Result<Vec<R>, StoreError> {
    let (records, checksum) = bytes
        .split_at_checked(
            bytes
                .len()
                .checked_sub(CHECKSUM_BYTES)
                .ok_or(StoreError::Incompatible)?,
        )
        .ok_or(StoreError::Incompatible)?;
    if records.is_empty()
        || records.len() % R::FORMAT.record_width != 0
        || checksum != block_checksum::<R>(header, block, records)
    {
        return Err(StoreError::Incompatible);
    }

    let mut decoded = Vec::with_capacity(records.len() / R::FORMAT.record_width);
    // The length check above makes every chunk a complete record.
    for encoded in records.chunks(R::FORMAT.record_width) {
        let record = R::decode(encoded)?;
        if decoded
            .last()
            .is_some_and(|prior: &R| record.key() <= prior.key())
        {
            return Err(StoreError::Incompatible);
        }
        decoded.push(record);
    }
    Ok(decoded)
}

fn read_exact_at(
    file: &File,
    output: &mut [u8],
    offset: u64,
    path: &Path,
) -> Result<(), StoreError> {
    file.read_exact_at(output, offset).map_err(|source| {
        if source.kind() == std::io::ErrorKind::UnexpectedEof {
            StoreError::Incompatible
        } else {
            io_error("read packed sorted file", path, source)
        }
    })
}

fn be_u64(bytes: &[u8]) -> Result<u64, StoreError> {
    bytes
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(StoreError::Incompatible)
}
