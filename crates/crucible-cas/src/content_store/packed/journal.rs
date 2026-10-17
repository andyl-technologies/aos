//! Append-only, hash-chained mutation journal over one immutable index base.
//!
//! Each index base has exactly one journal, named by the base digest. The
//! authoritative index root commits a journal prefix by its byte length,
//! record count, and final chain value; bytes beyond that prefix are an
//! uncommitted tail left by an interrupted mutation and are truncated before
//! the next append. A committed prefix that is shorter on disk than the root
//! records is lost data, and loading fails closed.
//!
//! ```text
//! PackIndexJournalV2 =
//!   "crucible.content-store.pack-index-journal.v2\0"
//!   configuration[32]
//!   backend_instance[32]
//!   base_digest[32]
//!   repeated {
//!     operation_u8                # 1 put, 2 delete
//!     content_id[37]              # binary identity, see the format module
//!     pack_id[32]
//!     absolute_body_offset_u64
//!     logical_length_u64
//!     pack_physical_bytes_u64     # exact length of the referenced pack file
//!     chain[32]                   # BLAKE3(domain || previous chain || preceding record bytes)
//!   }
//!
//! initial chain = BLAKE3("crucible.content-store.pack-index-journal.v2" || header)
//! ```
//!
//! A delete record repeats the complete removed entry, so replay verifies it
//! against the current view instead of trusting a bare identity.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::OFlags;

use super::format::{CONTENT_ID_BYTES, decode_content_id, encode_content_id, validate_index_entry};
use super::{
    ContentId, IndexEntry, MAX_PACK_BYTES, PackId, StoreError, create_temporary, io_error,
    remove_temporary,
};

const JOURNAL_MAGIC: &[u8] = b"crucible.content-store.pack-index-journal.v2\0";
const JOURNAL_CHAIN_DOMAIN: &[u8] = b"crucible.content-store.pack-index-journal.v2";

/// Exact encoded length of one journal record, including its chain value.
pub(super) const JOURNAL_RECORD_BYTES: usize = 1 + CONTENT_ID_BYTES + 32 + 8 + 8 + 8 + 32;

/// Records replayed per positioned read.
const REPLAY_CHUNK_RECORDS: usize = 512;

/// Logical mutation recorded by one journal record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum JournalOperation {
    /// Adds an absent logical object.
    Put,
    /// Removes the exact recorded entry.
    Delete,
}

/// One decoded journal mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct JournalRecord {
    pub(super) operation: JournalOperation,
    pub(super) id: ContentId,
    pub(super) entry: IndexEntry,
    pub(super) pack_physical_bytes: u64,
}

/// Returns the canonical journal header for one base.
pub(super) fn journal_header(
    configuration: [u8; 32],
    instance: [u8; 32],
    base_digest: [u8; 32],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(JOURNAL_MAGIC.len() + 96);
    header.extend_from_slice(JOURNAL_MAGIC);
    header.extend_from_slice(&configuration);
    header.extend_from_slice(&instance);
    header.extend_from_slice(&base_digest);
    header
}

/// Returns the chain value that precedes the first record.
pub(super) fn initial_chain(header: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOURNAL_CHAIN_DOMAIN);
    hasher.update(header);
    *hasher.finalize().as_bytes()
}

/// Encodes `record` after `previous_chain` and returns its bytes and chain.
pub(super) fn encode_record(
    record: &JournalRecord,
    previous_chain: [u8; 32],
) -> ([u8; JOURNAL_RECORD_BYTES], [u8; 32]) {
    let mut bytes = [0_u8; JOURNAL_RECORD_BYTES];
    bytes[0] = match record.operation {
        JournalOperation::Put => 1,
        JournalOperation::Delete => 2,
    };
    let mut id = [0_u8; CONTENT_ID_BYTES];
    encode_content_id(record.id, &mut id);
    bytes[1..38].copy_from_slice(&id);
    bytes[38..70].copy_from_slice(&record.entry.pack.0);
    bytes[70..78].copy_from_slice(&record.entry.offset.to_be_bytes());
    bytes[78..86].copy_from_slice(&record.entry.length.to_be_bytes());
    bytes[86..94].copy_from_slice(&record.pack_physical_bytes.to_be_bytes());
    let chain = chain_value(previous_chain, &bytes[..94]);
    bytes[94..].copy_from_slice(&chain);
    (bytes, chain)
}

/// Authenticates and decodes one record that follows `previous_chain`.
fn decode_record(
    bytes: &[u8; JOURNAL_RECORD_BYTES],
    previous_chain: [u8; 32],
) -> Result<(JournalRecord, [u8; 32]), StoreError> {
    let chain = chain_value(previous_chain, &bytes[..94]);
    if bytes[94..] != chain {
        return Err(StoreError::Incompatible);
    }

    let operation = match bytes[0] {
        1 => JournalOperation::Put,
        2 => JournalOperation::Delete,
        _ => return Err(StoreError::Incompatible),
    };
    let id = decode_content_id(&bytes[1..38])?;
    let entry = IndexEntry {
        pack: PackId(
            bytes[38..70]
                .try_into()
                .map_err(|_| StoreError::Incompatible)?,
        ),
        offset: be_u64(&bytes[70..78])?,
        length: be_u64(&bytes[78..86])?,
    };
    let pack_physical_bytes = be_u64(&bytes[86..94])?;
    validate_index_entry(entry)?;
    if pack_physical_bytes > MAX_PACK_BYTES || entry.offset + entry.length > pack_physical_bytes {
        return Err(StoreError::Incompatible);
    }
    Ok((
        JournalRecord {
            operation,
            id,
            entry,
            pack_physical_bytes,
        },
        chain,
    ))
}

fn chain_value(previous_chain: [u8; 32], record: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOURNAL_CHAIN_DOMAIN);
    hasher.update(&previous_chain);
    hasher.update(record);
    *hasher.finalize().as_bytes()
}

/// Opened journal file for one base.
pub(super) struct JournalFile {
    file: File,
    path: PathBuf,
}

impl JournalFile {
    /// Durably creates an empty journal at `path` containing only `header`.
    ///
    /// The caller syncs the directory with the rest of the index publication.
    pub(super) fn create(directory: &Path, path: &Path, header: &[u8]) -> Result<(), StoreError> {
        let (temporary, mut output) = create_temporary(directory, "index-journal")?;
        let result = output
            .write_all(header)
            .and_then(|()| output.sync_all())
            .map_err(|source| io_error("write packed index journal", &temporary, source))
            .and_then(|()| {
                std::fs::rename(&temporary, path)
                    .map_err(|source| io_error("publish packed index journal", path, source))
            });
        remove_temporary(&temporary, result.is_ok())?;
        result
    }

    /// Opens the journal at `path` and requires its exact `header`.
    pub(super) fn open(path: &Path, header: &[u8]) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
            .open(path)
            .map_err(|source| io_error("open packed index journal", path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| io_error("inspect packed index journal", path, source))?;
        if !metadata.file_type().is_file() {
            return Err(StoreError::InvalidComposition {
                reason: "packed index journal is not a regular file",
            });
        }

        let mut observed = vec![0_u8; header.len()];
        file.read_exact_at(&mut observed, 0)
            .map_err(|_| StoreError::Incompatible)?;
        if observed != header {
            return Err(StoreError::Incompatible);
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    /// Replays committed records in `[from, to)` starting at `chain`.
    ///
    /// Returns the final chain value and the number of records replayed.
    pub(super) fn replay(
        &self,
        from: u64,
        to: u64,
        mut chain: [u8; 32],
        mut visitor: impl FnMut(JournalRecord) -> Result<(), StoreError>,
    ) -> Result<([u8; 32], u64), StoreError> {
        let span = to.checked_sub(from).ok_or(StoreError::Incompatible)?;
        if span % JOURNAL_RECORD_BYTES as u64 != 0 || self.length()? < to {
            return Err(StoreError::Incompatible);
        }

        let mut records = 0_u64;
        let mut offset = from;
        let mut buffer = Vec::new();
        while offset < to {
            let chunk = (to - offset).min((REPLAY_CHUNK_RECORDS * JOURNAL_RECORD_BYTES) as u64);
            buffer.resize(usize::try_from(chunk).map_err(|_| StoreError::Quota)?, 0);
            self.file
                .read_exact_at(&mut buffer, offset)
                .map_err(|source| io_error("read packed index journal", &self.path, source))?;
            let (encoded_records, remainder) = buffer.as_chunks::<JOURNAL_RECORD_BYTES>();
            if !remainder.is_empty() {
                return Err(StoreError::Incompatible);
            }
            for encoded in encoded_records {
                let (record, next) = decode_record(encoded, chain)?;
                visitor(record)?;
                chain = next;
                records += 1;
            }
            offset += chunk;
        }
        Ok((chain, records))
    }

    /// Durably appends `bytes` at the committed length.
    ///
    /// Any uncommitted tail is discarded first. The record becomes part of
    /// the index only when a root naming the new length is published.
    pub(super) fn append(&self, committed: u64, bytes: &[u8]) -> Result<(), StoreError> {
        self.file
            .set_len(committed)
            .and_then(|()| self.file.write_all_at(bytes, committed))
            .and_then(|()| self.file.sync_all())
            .map_err(|source| io_error("append packed index journal", &self.path, source))
    }

    /// Removes bytes beyond `committed`, returning whether a tail existed.
    pub(super) fn truncate_uncommitted(&self, committed: u64) -> Result<bool, StoreError> {
        let length = self.length()?;
        if length < committed {
            return Err(StoreError::Incompatible);
        }
        if length == committed {
            return Ok(false);
        }
        self.file
            .set_len(committed)
            .and_then(|()| self.file.sync_all())
            .map_err(|source| io_error("truncate packed index journal", &self.path, source))?;
        Ok(true)
    }

    fn length(&self) -> Result<u64, StoreError> {
        Ok(self
            .file
            .metadata()
            .map_err(|source| io_error("inspect packed index journal", &self.path, source))?
            .len())
    }
}

fn be_u64(bytes: &[u8]) -> Result<u64, StoreError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| StoreError::Incompatible)?,
    ))
}
