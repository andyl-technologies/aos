//! Checked pinned-file lookup and bounded whole-object authentication.

use super::*;
use crate::content_store::checked_reader::{self, AuditedCheckedBlobReader};
use crate::owned_decode::{DecodeBudget, ResourceLoanSlot};

use super::file_pin::FilePin;

const READ_BYTES: usize = 64 * 1024;

pub(super) fn reader_metadata_bytes() -> u64 {
    // The retained file pin carries its original loan independently of readers.
    (std::mem::size_of::<Reader>() + READ_BYTES) as u64
}

pub(super) fn lookup(
    backend: &DirectoryBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    range: Option<ByteRange>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    checked_reader::check(original, boundary)?;
    let path_bytes = backend
        .root
        .as_os_str()
        .len()
        .checked_add(256)
        .ok_or(StoreError::Quota)?;
    let _path_credit = original
        .reserve_scratch_bytes(
            (path_bytes as u64)
                .checked_mul(8)
                .ok_or(StoreError::Quota)?,
        )
        .map_err(|error| batch::admission_under(original, error))?;
    let credit = original
        .reserve_scratch_bytes(
            BlobHandle::source_allocation_bytes::<Source>()
                .checked_add(FilePin::allocation_bytes())
                .ok_or(StoreError::Quota)?,
        )
        .map_err(|error| batch::admission_under(original, error))?;
    let path = object_path(backend, original, id)?;
    checked_reader::check(original, boundary)?;
    let file = loop {
        checked_reader::check(original, boundary)?;
        match File::open(&path) {
            Ok(file) => break file,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound { id });
            }
            Err(source) => {
                return Err(StoreError::StreamIo {
                    operation: "open-directory-object",
                    source,
                });
            }
        }
    };
    checked_reader::check(original, boundary)?;
    let length = file
        .metadata()
        .map_err(|source| StoreError::StreamIo {
            operation: "inspect-directory-object",
            source,
        })?
        .len();
    checked_reader::check(original, boundary)?;
    let range = range.unwrap_or(ByteRange { offset: 0, length });
    validate_range(length, range)?;
    let source = Source {
        file: FilePin::new(file, credit),
        id,
        length,
        range,
    };
    let handle = if range.offset == 0 && range.length == length {
        BlobHandle::authenticated(id, source)
    } else {
        BlobHandle::integrity_checked(id, source)
    };
    checked_reader::check(original, boundary)?;
    Ok(handle)
}

pub(super) fn object_path(
    backend: &DirectoryBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
) -> Result<PathBuf, StoreError> {
    let capacity = backend
        .root
        .as_os_str()
        .len()
        .checked_add(128)
        .ok_or(StoreError::Quota)?;
    let mut path = PathBuf::new();
    path.try_reserve_exact(capacity)
        .map_err(|error| batch::allocation_under(original, error))?;
    path.push(&backend.root);
    path.push(OBJECT_DIRECTORY);

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let first = id.digest()[0];
    let prefix = [HEX[(first >> 4) as usize], HEX[(first & 0x0f) as usize]];
    path.push(std::str::from_utf8(&prefix).map_err(|_| StoreError::InvalidId)?);
    id.with_encoded_text(|encoded| {
        path.push(std::str::from_utf8(encoded).map_err(|_| StoreError::InvalidId)?);
        Ok(path)
    })
}

struct Source {
    file: FilePin,
    id: ContentId,
    length: u64,
    range: ByteRange,
}

impl BlobSource for Source {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Owning
    }

    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(AuthenticatingFileReader::new(
            self.file.clone(),
            self.id,
            self.length,
            self.range,
        )))
    }

    fn open_with_boundary(
        &self,
        caller: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        checked_reader::check(caller, boundary)?;
        // Full reads authenticate directly from the caller's output chunks.
        // Only a partial range needs storage for scanning its hidden bytes.
        let scratch_bytes = if self.range.offset == 0 && self.range.length == self.length {
            0
        } else {
            READ_BYTES
        };
        let credit = caller
            .reserve_scratch_bytes((std::mem::size_of::<Reader>() + scratch_bytes) as u64)
            .map_err(|error| batch::admission_under(caller, error))?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(scratch_bytes)
            .map_err(|error| batch::allocation_under(caller, error))?;
        scratch.resize(scratch_bytes, 0);
        let reader = Reader {
            file: self.file.clone(),
            id: self.id,
            length: self.length,
            range: self.range,
            scan_offset: 0,
            output_offset: 0,
            hasher: content_hasher(self.id.kind(), self.id.schema_version(), self.length),
            scratch,
            original: caller.clone(),
            finalized: false,
            failed: false,
        };
        checked_reader::check(caller, boundary)?;
        Ok(CheckedReader::admitted(
            Box::new(reader),
            credit,
            ResourceLoanSlot::default(),
        ))
    }
}

struct Reader {
    file: FilePin,
    id: ContentId,
    length: u64,
    range: ByteRange,
    scan_offset: u64,
    output_offset: u64,
    hasher: blake3::Hasher,
    scratch: Vec<u8>,
    original: DecodeBudget,
    finalized: bool,
    failed: bool,
}

impl Reader {
    fn scan_until(
        &mut self,
        target: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        while self.scan_offset < target {
            let limit = usize::try_from((target - self.scan_offset).min(READ_BYTES as u64))
                .map_err(|_| StoreError::Quota)?;
            let read = read_at(
                &self.file,
                &mut self.scratch[..limit],
                self.scan_offset,
                &self.original,
                boundary,
            )?;
            if read == 0 {
                return Err(StoreError::Corrupt { id: self.id });
            }
            self.hasher.update(&self.scratch[..read]);
            self.scan_offset += read as u64;
        }
        Ok(())
    }

    fn read_checked(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        checked_reader::check(&self.original, boundary)?;
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        self.scan_until(self.range.offset, boundary)?;
        if self.output_offset < self.range.length {
            let limit = usize::try_from(
                (self.range.length - self.output_offset).min(output.len().min(READ_BYTES) as u64),
            )
            .map_err(|_| StoreError::Quota)?;
            let read = read_at(
                &self.file,
                &mut output[..limit],
                self.range.offset + self.output_offset,
                &self.original,
                boundary,
            )?;
            if read == 0 {
                return Err(StoreError::Corrupt { id: self.id });
            }
            self.hasher.update(&output[..read]);
            self.scan_offset += read as u64;
            self.output_offset += read as u64;
            checked_reader::check(&self.original, boundary)?;
            return Ok(read);
        }
        self.scan_until(self.length, boundary)?;
        let mut extra = [0_u8; 1];
        if read_at(
            &self.file,
            &mut extra,
            self.length,
            &self.original,
            boundary,
        )? != 0
            || *self.hasher.finalize().as_bytes() != self.id.digest()
        {
            return Err(StoreError::Corrupt { id: self.id });
        }
        checked_reader::check(&self.original, boundary)?;
        self.finalized = true;
        Ok(0)
    }
}

impl AuditedCheckedBlobReader for Reader {}

impl CheckedBlobReader for Reader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn full_eof_identity(&self) -> Option<ContentId> {
        Some(self.id)
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(checked_reader::failed());
        }
        let result = self.read_checked(output, boundary);
        self.failed = result.is_err();
        result
    }
}

fn read_at(
    file: &FilePin,
    output: &mut [u8],
    offset: u64,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<usize, StoreError> {
    loop {
        checked_reader::check(original, boundary)?;
        let file = match file.file() {
            Some(file) => file,
            None => {
                return Err(StoreError::StreamIo {
                    operation: "read-directory-object",
                    source: io::Error::from_raw_os_error(rustix::io::Errno::BADF.raw_os_error()),
                });
            }
        };
        match file.read_at(output, offset) {
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(StoreError::StreamIo {
                    operation: "read-directory-object",
                    source,
                });
            }
            Ok(read) => {
                checked_reader::check(original, boundary)?;
                return Ok(read);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_pin_preserves_reader_pointer_geometry_and_prepays_exact_controls() {
        assert_eq!(
            std::mem::size_of::<FilePin>(),
            std::mem::size_of::<Arc<File>>()
        );
        assert_eq!(
            std::mem::size_of::<AuthenticatingFileReader<FilePin>>(),
            std::mem::size_of::<AuthenticatingFileReader>()
        );
        println!(
            "source body={} alignment={} control={} file control={} checked reader={} ordinary reader={}",
            std::mem::size_of::<Source>(),
            std::mem::align_of::<Source>(),
            BlobHandle::source_allocation_bytes::<Source>(),
            FilePin::allocation_bytes(),
            std::mem::size_of::<Reader>(),
            std::mem::size_of::<AuthenticatingFileReader>(),
        );
    }
}
