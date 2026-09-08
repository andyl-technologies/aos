//! Durable compressed directory storage below plaintext content identity.
//!
//! Each logical object retains the ordinary kind/version/digest path while its
//! physical file uses this private, versioned representation:
//!
//! ```text
//! +------------------+----------------------+-----------------------+
//! | magic (8 bytes)  | logical bytes (u64)  | compressed bytes (u64)|
//! +------------------+----------------------+-----------------------+
//! | one complete Zstandard frame                                    |
//! +-----------------------------------------------------------------+
//! ```
//!
//! The fixed compression profile is an operational placement detail. Reads
//! stream-decompress and authenticate the complete plaintext object even for a
//! range request. No compressed bytes participate in [`ContentId`].

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{Mode, OFlags, open};

use super::admin::{InventoryCounter, persistent_inventory_generation};
use super::directory::{
    DirectoryBlobBackend, DirectoryInventoryState, create_dir_all_durable, directory_receipt,
    inventory_directory_entry, is_lower_hex, path_name, read_directory_entries, require_directory,
    sync_directory,
};
use super::*;

const COMPRESSED_OBJECT_MAGIC: &[u8; 8] = b"CRUCZ001";
const COMPRESSED_OBJECT_HEADER_BYTES: u64 = 24;
const COMPRESSION_LEVEL: i32 = 3;
const MAXIMUM_DECOMPRESSION_WINDOW_LOG: u32 = 23;

/// Durable loose-object leaf using bounded Zstandard compression.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CompressedDirectoryBlobBackend {
    directory: DirectoryBlobBackend,
    maximum_logical_object_bytes: u64,
}

impl CompressedDirectoryBlobBackend {
    /// Opens a compressed directory leaf with one hard logical-object limit.
    ///
    /// The limit is checked before a source stream is opened and before a
    /// declared on-disk object can be exposed to decompression.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the limit is zero.
    pub fn new(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        maximum_logical_object_bytes: u64,
    ) -> Result<Self, StoreError> {
        if maximum_logical_object_bytes == 0 {
            return Err(StoreError::InvalidComposition {
                reason: "compressed directory requires a nonzero logical-object byte limit",
            });
        }
        Ok(Self {
            directory: DirectoryBlobBackend::new(name, root),
            maximum_logical_object_bytes,
        })
    }

    /// Returns the physical compressed-object root.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.directory.root()
    }

    /// Returns the hard plaintext limit for one object.
    #[must_use]
    pub const fn maximum_logical_object_bytes(&self) -> u64 {
        self.maximum_logical_object_bytes
    }

    fn read_handle(
        &self,
        id: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let path = self.directory.object_path(id);
        let (file, header) = open_compressed_object(&path, id, self.maximum_logical_object_bytes)?;
        let range = range.unwrap_or(ByteRange {
            offset: 0,
            length: header.logical_length,
        });
        validate_range(header.logical_length, range)?;
        let source: Arc<dyn BlobSource> = Arc::new(CompressedDirectoryBlobSource {
            file,
            id,
            header,
            range,
        });
        if range.offset == 0 && range.length == header.logical_length {
            Ok(BlobHandle::authenticated(id, source))
        } else {
            Ok(BlobHandle::integrity_checked(id, source))
        }
    }
}

impl ImmutableBlobBackend for CompressedDirectoryBlobBackend {
    fn name(&self) -> &str {
        self.directory.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: false,
            planned_delete: false,
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_handle(id, None) {
            Ok(handle) => {
                validate_source(id, &handle)?;
                Ok(true)
            }
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.read_handle(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        if source.logical_length() > self.maximum_logical_object_bytes {
            return Err(StoreError::Quota);
        }
        let _inventory_lock = self.directory.acquire_inventory_lock()?;
        let mut inventory_state = self.directory.load_or_create_inventory_state()?;
        self.directory
            .advance_inventory_state(&mut inventory_state)?;

        let path = self.directory.object_path(id);
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "compressed object path has no containing directory",
        })?;
        create_dir_all_durable(directory)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                source.verified_as(id)?;
                if !self.contains(id)? {
                    return Err(StoreError::NotFound { id });
                }
                sync_directory(directory)?;
                return Ok(directory_receipt(self.name(), id, source.logical_length()));
            }
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "compressed object placement is not a regular file",
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "inspect-compressed-object",
                    path,
                    source,
                });
            }
        }

        let (staging_path, mut staging) = self.directory.create_staging(directory)?;
        let publish_result = (|| {
            write_compressed_header(
                &mut staging,
                CompressedObjectHeader {
                    logical_length: source.logical_length(),
                    compressed_length: 0,
                },
            )?;
            let mut encoder = zstd::stream::write::Encoder::new(staging, COMPRESSION_LEVEL)
                .map_err(|source| StoreError::Io {
                    operation: "open-compressed-object-encoder",
                    path: staging_path.clone(),
                    source,
                })?;
            encoder
                .window_log(MAXIMUM_DECOMPRESSION_WINDOW_LOG)
                .and_then(|()| encoder.include_checksum(true))
                .map_err(|source| StoreError::Io {
                    operation: "configure-compressed-object-encoder",
                    path: staging_path.clone(),
                    source,
                })?;
            let authenticated_length = copy_source(id, source, &mut encoder)?;
            staging = encoder.finish().map_err(|source| StoreError::Io {
                operation: "finish-compressed-object",
                path: staging_path.clone(),
                source,
            })?;
            let physical_length = staging
                .metadata()
                .map_err(|source| StoreError::Io {
                    operation: "inspect-compressed-object-staging",
                    path: staging_path.clone(),
                    source,
                })?
                .len();
            let compressed_length = physical_length
                .checked_sub(COMPRESSED_OBJECT_HEADER_BYTES)
                .ok_or(StoreError::Corrupt { id })?;
            if maximum_compressed_length(authenticated_length)
                .is_none_or(|maximum| compressed_length > maximum)
            {
                return Err(StoreError::Corrupt { id });
            }
            staging
                .seek(SeekFrom::Start(0))
                .map_err(|source| StoreError::Io {
                    operation: "seek-compressed-object-header",
                    path: staging_path.clone(),
                    source,
                })?;
            write_compressed_header(
                &mut staging,
                CompressedObjectHeader {
                    logical_length: authenticated_length,
                    compressed_length,
                },
            )?;
            staging.sync_all().map_err(|source| StoreError::Io {
                operation: "sync-compressed-object-staging",
                path: staging_path.clone(),
                source,
            })?;

            match fs::hard_link(&staging_path, &path) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !self.contains(id)? {
                        return Err(StoreError::NotFound { id });
                    }
                }
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "publish-compressed-object",
                        path: path.clone(),
                        source,
                    });
                }
            }
            sync_directory(directory)?;
            Ok(authenticated_length)
        })();

        let remove_result = fs::remove_file(&staging_path);
        if let Err(source) = remove_result
            && source.kind() != std::io::ErrorKind::NotFound
            && publish_result.is_ok()
        {
            return Err(StoreError::Io {
                operation: "remove-compressed-object-staging",
                path: staging_path,
                source,
            });
        }
        let authenticated_length = publish_result?;
        Ok(directory_receipt(self.name(), id, authenticated_length))
    }
}

impl BlobStoreAdmin for CompressedDirectoryBlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lock = self.directory.acquire_inventory_lock()?;
        let state = self.directory.load_or_create_inventory_state()?;
        Ok(Box::new(CompressedDirectoryInventoryFence {
            backend: self,
            _lock: lock,
            state,
        }))
    }
}

#[derive(Clone, Copy)]
struct CompressedObjectHeader {
    logical_length: u64,
    compressed_length: u64,
}

fn write_compressed_header(
    file: &mut File,
    header: CompressedObjectHeader,
) -> Result<(), StoreError> {
    file.write_all(COMPRESSED_OBJECT_MAGIC)
        .and_then(|()| file.write_all(&header.logical_length.to_be_bytes()))
        .and_then(|()| file.write_all(&header.compressed_length.to_be_bytes()))
        .map_err(|source| StoreError::StreamIo {
            operation: "write-compressed-object-header",
            source,
        })
}

fn open_compressed_object(
    path: &Path,
    id: ContentId,
    maximum_logical_object_bytes: u64,
) -> Result<(Arc<File>, CompressedObjectHeader), StoreError> {
    let descriptor = match open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(source) if source == rustix::io::Errno::NOENT => {
            return Err(StoreError::NotFound { id });
        }
        Err(source) => {
            return Err(StoreError::Io {
                operation: "open-compressed-object",
                path: path.to_path_buf(),
                source: std::io::Error::from_raw_os_error(source.raw_os_error()),
            });
        }
    };
    let file = File::from(descriptor);
    let physical_length = file
        .metadata()
        .map_err(|source| StoreError::Io {
            operation: "inspect-compressed-object",
            path: path.to_path_buf(),
            source,
        })?
        .len();
    let mut header_bytes = [0_u8; COMPRESSED_OBJECT_HEADER_BYTES as usize];
    read_exact_at(&file, &mut header_bytes, 0).map_err(|_| StoreError::Corrupt { id })?;
    if &header_bytes[..8] != COMPRESSED_OBJECT_MAGIC {
        return Err(StoreError::Corrupt { id });
    }
    let logical_length = u64::from_be_bytes(
        header_bytes[8..16]
            .try_into()
            .map_err(|_| StoreError::Corrupt { id })?,
    );
    let compressed_length = u64::from_be_bytes(
        header_bytes[16..24]
            .try_into()
            .map_err(|_| StoreError::Corrupt { id })?,
    );
    if logical_length > maximum_logical_object_bytes
        || compressed_length == 0
        || maximum_compressed_length(logical_length)
            .is_none_or(|maximum| compressed_length > maximum)
        || COMPRESSED_OBJECT_HEADER_BYTES.checked_add(compressed_length) != Some(physical_length)
    {
        return Err(StoreError::Corrupt { id });
    }
    Ok((
        Arc::new(file),
        CompressedObjectHeader {
            logical_length,
            compressed_length,
        },
    ))
}

struct CompressedDirectoryBlobSource {
    file: Arc<File>,
    id: ContentId,
    header: CompressedObjectHeader,
    range: ByteRange,
}

impl BlobSource for CompressedDirectoryBlobSource {
    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let compressed = CompressedFrameReader {
            file: Arc::clone(&self.file),
            offset: COMPRESSED_OBJECT_HEADER_BYTES,
            remaining: self.header.compressed_length,
        };
        let mut decoder = zstd::stream::read::Decoder::new(compressed).map_err(|source| {
            StoreError::StreamIo {
                operation: "open-compressed-object-decoder",
                source,
            }
        })?;
        decoder
            .window_log_max(MAXIMUM_DECOMPRESSION_WINDOW_LOG)
            .map_err(|source| StoreError::StreamIo {
                operation: "configure-compressed-object-decoder",
                source,
            })?;
        Ok(Box::new(AuthenticatingCompressedReader::new(
            Box::new(decoder),
            self.id,
            self.header.logical_length,
            self.range,
        )))
    }
}

struct CompressedFrameReader {
    file: Arc<File>,
    offset: u64,
    remaining: u64,
}

impl Read for CompressedFrameReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 || output.is_empty() {
            return Ok(0);
        }
        let limit = usize::try_from(self.remaining.min(output.len() as u64))
            .map_err(|_| invalid_compressed_data())?;
        let read = read_at_retry(&self.file, &mut output[..limit], self.offset)?;
        self.offset = self
            .offset
            .checked_add(read as u64)
            .ok_or_else(invalid_compressed_data)?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

struct AuthenticatingCompressedReader {
    reader: Box<dyn Read + Send>,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
    scan_offset: u64,
    output_offset: u64,
    hasher: blake3::Hasher,
    finalized: bool,
}

impl AuthenticatingCompressedReader {
    fn new(
        reader: Box<dyn Read + Send>,
        id: ContentId,
        logical_length: u64,
        range: ByteRange,
    ) -> Self {
        Self {
            reader,
            id,
            logical_length,
            range,
            scan_offset: 0,
            output_offset: 0,
            hasher: content_hasher(id.kind(), id.schema_version(), logical_length),
            finalized: false,
        }
    }

    fn scan_until(&mut self, target: u64) -> std::io::Result<()> {
        let mut buffer = [0_u8; 64 * 1024];
        while self.scan_offset < target {
            let remaining = target - self.scan_offset;
            let limit = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| invalid_compressed_data())?;
            let read = read_retry(&mut self.reader, &mut buffer[..limit])?;
            if read == 0 {
                return Err(invalid_compressed_data());
            }
            self.hasher.update(&buffer[..read]);
            self.scan_offset += read as u64;
        }
        Ok(())
    }

    fn finalize(&mut self) -> std::io::Result<()> {
        self.scan_until(self.logical_length)?;
        let mut extra = [0_u8; 1];
        if read_retry(&mut self.reader, &mut extra)? != 0
            || *self.hasher.finalize().as_bytes() != self.id.digest()
        {
            return Err(invalid_compressed_data());
        }
        self.finalized = true;
        Ok(())
    }
}

impl Read for AuthenticatingCompressedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        self.scan_until(self.range.offset)?;
        if self.output_offset < self.range.length {
            let remaining = self.range.length - self.output_offset;
            let limit = usize::try_from(remaining.min(output.len() as u64))
                .map_err(|_| invalid_compressed_data())?;
            let read = read_retry(&mut self.reader, &mut output[..limit])?;
            if read == 0 {
                return Err(invalid_compressed_data());
            }
            self.hasher.update(&output[..read]);
            self.scan_offset += read as u64;
            self.output_offset += read as u64;
            return Ok(read);
        }
        self.finalize()?;
        Ok(0)
    }
}

fn invalid_compressed_data() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "compressed content authentication failed",
    )
}

fn maximum_compressed_length(logical_length: u64) -> Option<u64> {
    let logical_length = usize::try_from(logical_length).ok()?;
    u64::try_from(zstd::zstd_safe::compress_bound(logical_length)).ok()
}

fn read_exact_at(file: &File, mut output: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !output.is_empty() {
        let read = read_at_retry(file, output, offset)?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(invalid_compressed_data)?;
        output = &mut output[read..];
    }
    Ok(())
}

fn read_at_retry(file: &File, output: &mut [u8], offset: u64) -> std::io::Result<usize> {
    loop {
        match file.read_at(output, offset) {
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

struct CompressedDirectoryInventoryFence<'a> {
    backend: &'a CompressedDirectoryBlobBackend,
    _lock: File,
    state: DirectoryInventoryState,
}

impl BlobInventoryFence for CompressedDirectoryInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let generation = persistent_inventory_generation(
            self.backend.name(),
            self.state.instance,
            self.state.generation,
        )?;
        let mut inventory = InventoryCounter::new(generation);
        visit_compressed_inventory(self.backend, visitor, &mut inventory)?;
        Ok(inventory.finish(self.backend.name().to_owned()))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        self.backend
            .directory
            .advance_inventory_state(&mut self.state)?;
        let path = self.backend.directory.object_path(id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "planned compressed-object candidate is not a regular file",
                });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PlannedDeleteDisposition::AlreadyAbsent);
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "inspect-compressed-delete-candidate",
                    path,
                    source,
                });
            }
        }
        fs::remove_file(&path).map_err(|source| StoreError::Io {
            operation: "remove-planned-compressed-object",
            path: path.clone(),
            source,
        })?;
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "planned compressed-object candidate has no parent directory",
        })?;
        sync_directory(directory)?;
        Ok(PlannedDeleteDisposition::Deleted)
    }
}

fn visit_compressed_inventory(
    backend: &CompressedDirectoryBlobBackend,
    visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    inventory: &mut InventoryCounter,
) -> Result<(), StoreError> {
    let root = backend.root();
    for kind_entry in read_directory_entries(root, "read-compressed-inventory-root")? {
        let kind_entry =
            inventory_directory_entry(kind_entry, root, "read-compressed-inventory-root")?;
        let kind_path = kind_entry.path();
        let kind_name = path_name(&kind_path)?;
        if kind_name == ".inventory-admin" {
            require_directory(&kind_path)?;
            continue;
        }
        let kind = ObjectKind::parse(kind_name).ok_or(StoreError::InvalidComposition {
            reason: "compressed inventory contains an unknown object-kind directory",
        })?;
        require_directory(&kind_path)?;

        for version_entry in read_directory_entries(&kind_path, "read-compressed-inventory-kind")? {
            let version_entry = inventory_directory_entry(
                version_entry,
                &kind_path,
                "read-compressed-inventory-kind",
            )?;
            let version_path = version_entry.path();
            require_directory(&version_path)?;
            let version_name = path_name(&version_path)?;
            let version = version_name
                .parse::<u32>()
                .ok()
                .filter(|version| version.to_string() == version_name)
                .ok_or(StoreError::InvalidComposition {
                    reason: "compressed inventory contains a noncanonical schema version",
                })?;

            for prefix_entry in
                read_directory_entries(&version_path, "read-compressed-inventory-version")?
            {
                let prefix_entry = inventory_directory_entry(
                    prefix_entry,
                    &version_path,
                    "read-compressed-inventory-version",
                )?;
                let prefix_path = prefix_entry.path();
                require_directory(&prefix_path)?;
                let prefix = path_name(&prefix_path)?;
                if prefix.len() != 2 || !prefix.bytes().all(is_lower_hex) {
                    return Err(StoreError::InvalidComposition {
                        reason: "compressed inventory has a noncanonical digest prefix",
                    });
                }

                for object_entry in
                    read_directory_entries(&prefix_path, "read-compressed-inventory-prefix")?
                {
                    let object_entry = inventory_directory_entry(
                        object_entry,
                        &prefix_path,
                        "read-compressed-inventory-prefix",
                    )?;
                    let object_path = object_entry.path();
                    let digest = path_name(&object_path)?;
                    if digest.len() != 64
                        || !digest.bytes().all(is_lower_hex)
                        || !digest.starts_with(prefix)
                    {
                        return Err(StoreError::InvalidComposition {
                            reason: "compressed inventory has a noncanonical object digest",
                        });
                    }
                    let id =
                        ContentId::parse(&format!("{}.{}.{}", kind.as_str(), version, digest))?;
                    let (_, header) = open_compressed_object(
                        &object_path,
                        id,
                        backend.maximum_logical_object_bytes,
                    )?;
                    let record = BlobInventoryRecord::new(id, header.logical_length);
                    inventory.push(record)?;
                    visitor(record)?;
                }
            }
        }
    }
    Ok(())
}
