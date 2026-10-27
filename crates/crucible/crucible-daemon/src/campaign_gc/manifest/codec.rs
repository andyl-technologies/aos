//! Canonical field codec, hashing, and sealed-file output for GC manifests.
//!
//! Every helper reads or writes one field of the formats documented on the
//! parent module, enforcing its bound before any allocation. A
//! [`PendingManifest`] writes a placeholder count, patches it once the last
//! entry is known, synchronizes the file, and removes it unless sealed.

use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crucible_store::content_store::ContentId;

use super::super::spill::GcWorkDirectory;
use super::{
    CampaignGcCandidate, CampaignGcCandidateReason, CampaignGcManifestError, IO_BUFFER_BYTES,
    MAX_CAMPAIGN_GC_BACKEND_ID_BYTES, MAX_CAMPAIGN_GC_MANIFEST_ENTRIES, MAX_CONTENT_ID_BYTES,
    compare_content_id,
};

/// Buffered file reader that tracks its byte position for range indexing.
pub(super) struct CountingReader {
    inner: BufReader<File>,
    position: u64,
}

impl CountingReader {
    pub(super) fn new(file: File) -> Self {
        Self {
            inner: BufReader::with_capacity(IO_BUFFER_BYTES, file),
            position: 0,
        }
    }

    pub(super) const fn position(&self) -> u64 {
        self.position
    }
}

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.position += read as u64;
        Ok(read)
    }
}

pub(super) fn manifest_hasher(domain: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher
}

/// Manifest file being written, removed unless it is sealed.
pub(super) struct PendingManifest {
    path: PathBuf,
    directory: Arc<GcWorkDirectory>,
    pub(super) writer: BufWriter<File>,
    count_offset: u64,
    sealed: bool,
}

impl PendingManifest {
    pub(super) fn create(
        directory: &Arc<GcWorkDirectory>,
        label: &str,
        magic: &[u8],
    ) -> Result<Self, CampaignGcManifestError> {
        let path = directory.file_path(label);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut pending = Self {
            path,
            directory: Arc::clone(directory),
            writer: BufWriter::with_capacity(IO_BUFFER_BYTES, file),
            count_offset: magic.len() as u64,
            sealed: false,
        };
        pending.writer.write_all(magic)?;
        // The count is unknown until the last entry; it is patched on seal.
        pending.writer.write_all(&0_u64.to_be_bytes())?;
        Ok(pending)
    }

    /// Patches the entry count and synchronizes the complete file.
    pub(super) fn seal(
        mut self,
        count: u64,
    ) -> Result<(PathBuf, Arc<GcWorkDirectory>), CampaignGcManifestError> {
        self.writer.flush()?;
        let file = self.writer.get_mut();
        file.seek(SeekFrom::Start(self.count_offset))?;
        file.write_all(&count.to_be_bytes())?;
        // A journal may hard-link this file, so it must be durable on its own.
        file.sync_all()?;
        self.sealed = true;
        Ok((self.path.clone(), Arc::clone(&self.directory)))
    }
}

impl Drop for PendingManifest {
    fn drop(&mut self) {
        if !self.sealed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(super) fn hash_bounded_string(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u16).to_be_bytes());
    hasher.update(value.as_bytes());
}

pub(super) fn hash_candidate(hasher: &mut blake3::Hasher, candidate: &CampaignGcCandidate) {
    hash_bounded_string(hasher, candidate.backend());
    hash_bounded_string(hasher, &candidate.id().encode());
    hasher.update(&candidate.logical_length().to_be_bytes());
    match candidate.reason() {
        CampaignGcCandidateReason::Unreachable => {
            hasher.update(&[0]);
        }
        CampaignGcCandidateReason::ReachableCache { required_backend } => {
            hasher.update(&[1]);
            hash_bounded_string(hasher, required_backend);
        }
    }
}

pub(super) fn next_entry_count(count: u64) -> Result<u64, CampaignGcManifestError> {
    let next = count
        .checked_add(1)
        .ok_or(CampaignGcManifestError::EntryLimit)?;
    if usize::try_from(next).map_or(true, |next| next > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES) {
        return Err(CampaignGcManifestError::EntryLimit);
    }
    Ok(next)
}

pub(super) fn read_count(reader: &mut dyn Read) -> Result<u64, CampaignGcManifestError> {
    let count = read_u64(reader)?;
    if usize::try_from(count).map_or(true, |count| count > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES) {
        return Err(CampaignGcManifestError::EntryLimit);
    }
    Ok(count)
}

pub(super) fn read_ordered_root(
    reader: &mut dyn Read,
    previous: &mut Option<ContentId>,
) -> Result<ContentId, CampaignGcManifestError> {
    let root = read_content_id(reader)?;
    if previous.is_some_and(|prior| compare_content_id(prior, root) != Ordering::Less) {
        return Err(CampaignGcManifestError::Noncanonical);
    }
    *previous = Some(root);
    Ok(root)
}

pub(super) fn read_candidate(
    reader: &mut dyn Read,
) -> Result<CampaignGcCandidate, CampaignGcManifestError> {
    let backend = read_bounded_string(reader, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?;
    let id = read_content_id(reader)?;
    let logical_length = read_u64(reader)?;
    match read_u8(reader)? {
        0 => CampaignGcCandidate::new(backend, id, logical_length),
        1 => CampaignGcCandidate::new_reachable_cache(
            backend,
            id,
            logical_length,
            read_bounded_string(reader, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?,
        ),
        _ => Err(CampaignGcManifestError::InvalidField),
    }
}

pub(super) fn write_candidate(
    writer: &mut dyn Write,
    candidate: &CampaignGcCandidate,
) -> Result<(), CampaignGcManifestError> {
    write_bounded_string(
        writer,
        candidate.backend(),
        MAX_CAMPAIGN_GC_BACKEND_ID_BYTES,
    )?;
    write_bounded_string(writer, &candidate.id().encode(), MAX_CONTENT_ID_BYTES)?;
    writer.write_all(&candidate.logical_length().to_be_bytes())?;
    match candidate.reason() {
        CampaignGcCandidateReason::Unreachable => writer.write_all(&[0])?,
        CampaignGcCandidateReason::ReachableCache { required_backend } => {
            writer.write_all(&[1])?;
            write_bounded_string(writer, required_backend, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?;
        }
    }
    Ok(())
}

pub(super) fn require_magic(
    reader: &mut dyn Read,
    expected: &[u8],
) -> Result<(), CampaignGcManifestError> {
    let mut actual = vec![0_u8; expected.len()];
    reader.read_exact(&mut actual)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CampaignGcManifestError::UnsupportedSchema)
    }
}

pub(super) fn read_u16(reader: &mut dyn Read) -> Result<u16, CampaignGcManifestError> {
    let mut bytes = [0_u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

pub(super) fn read_u8(reader: &mut dyn Read) -> Result<u8, CampaignGcManifestError> {
    let mut byte = [0_u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

pub(super) fn read_u64(reader: &mut dyn Read) -> Result<u64, CampaignGcManifestError> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

pub(super) fn read_bounded_string(
    reader: &mut dyn Read,
    maximum: usize,
) -> Result<String, CampaignGcManifestError> {
    let length = usize::from(read_u16(reader)?);
    if length == 0 || length > maximum {
        return Err(CampaignGcManifestError::InvalidField);
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| CampaignGcManifestError::InvalidField)
}

pub(super) fn read_content_id(reader: &mut dyn Read) -> Result<ContentId, CampaignGcManifestError> {
    let encoded = read_bounded_string(reader, MAX_CONTENT_ID_BYTES)?;
    ContentId::parse(&encoded).map_err(|_| CampaignGcManifestError::InvalidField)
}

pub(super) fn write_bounded_string(
    writer: &mut dyn Write,
    value: &str,
    maximum: usize,
) -> Result<(), CampaignGcManifestError> {
    if value.is_empty() || value.len() > maximum {
        return Err(CampaignGcManifestError::InvalidField);
    }
    let length = u16::try_from(value.len()).map_err(|_| CampaignGcManifestError::InvalidField)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(value.as_bytes())?;
    Ok(())
}

pub(super) fn require_eof(reader: &mut dyn Read) -> Result<(), CampaignGcManifestError> {
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? == 0 {
        Ok(())
    } else {
        Err(CampaignGcManifestError::Noncanonical)
    }
}
