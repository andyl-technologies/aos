//! Reads a coherent, bounded page stream retained until checkpoint disposition.
//!
//! The file is a private capture spool, never a portable RAM realization. Its
//! root record and ordered page records feed immutable catalog publication.
//! Checkpoint commit is separate and occurs only after the complete closure is
//! durable; reading this stream never acknowledges dirty obligations.
//!
//! ```text
//! header = "CRURCP01" | edition:u32be | initial:u32be | generation:u64be
//!          | records:u64be | root-length:u32be | reserved:u32be | root:32
//!          | RootRecord
//! page = region-ordinal:u32be | length:u32be | page-index:u64be
//!        | version:u64be | valid-page-bytes
//! ```

#[cfg(test)]
mod tests;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub use crucible_engine::exact_checkpoint::CaptureReadError;
use crucible_ram::{Limits, RootRecord, Scope};

use super::QemuNodeError;

const MAGIC: &[u8; 8] = b"CRURCP01";
const EDITION: u32 = 1;
const HEADER_BYTES: usize = 72;
const PAGE_HEADER_BYTES: usize = 24;
const MAX_ROOT_BYTES: usize = 3 * 1024 * 1024;

/// One immutable page version captured after the device pre-save barrier.
#[derive(Debug)]
pub struct QemuCapturedRamPage {
    /// Stable owner identifier from the complete canonical region inventory.
    pub region_id: String,
    /// Logical 4096-byte page index within the region.
    pub page_index: u64,
    /// Positive operational page version, excluded from logical identities.
    pub version: u64,
    /// Valid page bytes, including a short final page without padding.
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct QemuPagedRamCapture {
    file: File,
    original: Option<super::CheckpointOriginalLoan>,
    root: RootRecord,
    generation: u64,
    initial: bool,
    remaining_records: u64,
    remaining_bytes: u64,
    previous: Option<(u32, u64)>,
}

impl QemuPagedRamCapture {
    #[cfg(test)]
    pub(super) fn admit(file: File, expected_bytes: u64) -> Result<Self, QemuNodeError> {
        Self::admit_inner(file, expected_bytes, None)
    }

    pub(super) fn admit_under_original(
        file: File,
        expected_bytes: u64,
        original: super::CheckpointOriginalLoan,
    ) -> Result<Self, QemuNodeError> {
        original.check().map_err(original_node_error)?;
        let work = Self::admit_inner(file, expected_bytes, Some(original.clone()));
        match (work, original.check().err()) {
            (Err(source), Some(original_after)) => Err(QemuNodeError::CheckpointPostcut {
                source: Box::new(source),
                original_after,
            }),
            (Ok(_), Some(source)) => Err(original_node_error(source)),
            (work, None) => work,
        }
    }

    fn admit_inner(
        mut file: File,
        expected_bytes: u64,
        original: Option<super::CheckpointOriginalLoan>,
    ) -> Result<Self, QemuNodeError> {
        if expected_bytes < HEADER_BYTES as u64
            || file.metadata().map_err(capture_io)?.len() != expected_bytes
        {
            return Err(invalid("page capture spool length"));
        }
        file.seek(SeekFrom::Start(0)).map_err(capture_io)?;
        let mut header = [0; HEADER_BYTES];
        file.read_exact(&mut header).map_err(capture_io)?;
        check_node_original(original.as_ref())?;
        let initial = u32be(&header[12..16]);
        let generation = u64be(&header[16..24]);
        let records = u64be(&header[24..32]);
        let root_length = u32be(&header[32..36]) as usize;
        if &header[..8] != MAGIC
            || u32be(&header[8..12]) != EDITION
            || initial > 1
            || generation == 0
            || root_length == 0
            || root_length > MAX_ROOT_BYTES
            || header[36..40] != [0; 4]
            || expected_bytes - (HEADER_BYTES as u64) < root_length as u64
        {
            return Err(invalid("page capture header"));
        }

        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(root_length)
            .map_err(|_| invalid("root allocation"))?;
        encoded.resize(root_length, 0);
        check_node_original(original.as_ref())?;
        file.read_exact(&mut encoded).map_err(capture_io)?;
        check_node_original(original.as_ref())?;
        let root = RootRecord::decode(&encoded, Limits::default())
            .map_err(|error| invalid(format!("page capture root record: {error}")))?;
        check_node_original(original.as_ref())?;
        if root.scope() != Scope::Exact || root.digest().as_bytes() != &header[40..72] {
            return Err(invalid("page capture root or scope"));
        }
        let total_pages = root
            .topology()
            .regions()
            .iter()
            .try_fold(0_u64, |count, region| {
                count.checked_add(region.geometry().page_count())
            })
            .ok_or_else(|| invalid("page capture page count overflow"))?;
        let remaining_bytes = expected_bytes - HEADER_BYTES as u64 - root_length as u64;
        if records > total_pages
            || (initial == 1 && records != total_pages)
            || records > remaining_bytes / (PAGE_HEADER_BYTES as u64 + 1)
        {
            return Err(invalid("page capture record bounds"));
        }
        Ok(Self {
            file,
            original,
            root,
            generation,
            initial: initial == 1,
            remaining_records: records,
            remaining_bytes,
            previous: None,
        })
    }

    pub(super) fn original_loan(&self) -> Result<super::CheckpointOriginalLoan, QemuNodeError> {
        self.original
            .clone()
            .ok_or_else(|| QemuNodeError::CheckpointOriginal {
                source: super::capture_original::CheckpointOriginalError::before(
                    super::capture_original::CheckpointOriginalCause::MissingOwner,
                ),
            })
    }

    pub(super) fn record(&self) -> &RootRecord {
        &self.root
    }

    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) const fn initial(&self) -> bool {
        self.initial
    }

    pub(super) fn next_page(&mut self) -> Result<Option<QemuCapturedRamPage>, CaptureReadError> {
        self.check_original()?;
        let work = self.next_page_inner();
        let original_after = self
            .original
            .as_ref()
            .and_then(|original| original.check().err());
        match (work, original_after) {
            (Err(source), Some(original_after)) => Err(CaptureReadError::Io(
                std::io::Error::other(CheckpointReadPostcut {
                    source,
                    original_after,
                }),
            )),
            (Ok(_), Some(source)) => Err(CaptureReadError::Io(std::io::Error::other(source))),
            (work, None) => work,
        }
    }

    fn check_original(&self) -> Result<(), CaptureReadError> {
        if let Some(original) = &self.original {
            original
                .check()
                .map_err(|source| CaptureReadError::Io(std::io::Error::other(source)))?;
        }
        Ok(())
    }

    fn next_page_inner(&mut self) -> Result<Option<QemuCapturedRamPage>, CaptureReadError> {
        if self.remaining_records == 0 {
            if self.remaining_bytes != 0 {
                return Err(CaptureReadError::Malformed("trailing page capture bytes"));
            }
            return Ok(None);
        }
        if self.remaining_bytes < PAGE_HEADER_BYTES as u64 {
            return Err(CaptureReadError::Malformed("truncated page capture record"));
        }
        let mut header = [0; PAGE_HEADER_BYTES];
        self.file.read_exact(&mut header)?;
        self.check_original()?;
        let region_ordinal = u32be(&header[..4]);
        let length = u32be(&header[4..8]);
        let page_index = u64be(&header[8..16]);
        let version = u64be(&header[16..24]);
        let coordinate = (region_ordinal, page_index);
        let region = self
            .root
            .topology()
            .regions()
            .get(region_ordinal as usize)
            .ok_or(CaptureReadError::Malformed("page capture region ordinal"))?;
        let valid_length = region.geometry().valid_length(page_index)?;
        let encoded_bytes = PAGE_HEADER_BYTES as u64 + u64::from(length);
        if length != valid_length
            || version == 0
            || self.previous.is_some_and(|previous| previous >= coordinate)
            || encoded_bytes > self.remaining_bytes
        {
            return Err(CaptureReadError::Malformed(
                "page capture ordering, version, or length",
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length as usize)?;
        bytes.resize(length as usize, 0);
        self.check_original()?;
        self.file.read_exact(&mut bytes)?;
        self.check_original()?;
        self.previous = Some(coordinate);
        self.remaining_records -= 1;
        self.remaining_bytes -= encoded_bytes;
        Ok(Some(QemuCapturedRamPage {
            region_id: region.id().to_owned(),
            page_index,
            version,
            bytes,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{source}; checkpoint original postcut: {original_after}")]
struct CheckpointReadPostcut {
    #[source]
    source: CaptureReadError,
    original_after: crucible_host_resources::host_supervision::HostSupervisionError,
}

fn original_node_error(
    source: crucible_host_resources::host_supervision::HostSupervisionError,
) -> QemuNodeError {
    QemuNodeError::CheckpointOriginal {
        source: super::capture_original::CheckpointOriginalError::before(
            super::capture_original::CheckpointOriginalCause::Original(source),
        ),
    }
}

fn check_node_original(
    original: Option<&super::CheckpointOriginalLoan>,
) -> Result<(), QemuNodeError> {
    if let Some(original) = original {
        original.check().map_err(original_node_error)?;
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> QemuNodeError {
    QemuNodeError::checkpoint(message)
}

fn capture_io(error: std::io::Error) -> QemuNodeError {
    invalid(format!("read retained RAM page capture: {error}"))
}

fn u32be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn u64be(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}
