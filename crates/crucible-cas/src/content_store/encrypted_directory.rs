//! Authenticated encrypted directory storage below plaintext content identity.
//!
//! The leaf encrypts fixed-size plaintext chunks independently with
//! AES-256-GCM. Per-chunk nonces are derived from the secret key, exact
//! [`ContentId`], and chunk ordinal; associated data additionally binds the
//! physical schema, logical length, key identifier, final-chunk marker, and
//! plaintext chunk length. Reads authenticate every chunk and the complete
//! plaintext digest, including when returning only a range.
//!
//! Secret key bytes are supplied through [`StoreGraphKeyring`] and never enter
//! graph introspection, placement receipts, or the physical record. The
//! non-secret key identifier enters graph configuration identity and its hash
//! binding enters each physical record and chunk authentication basis.
//!
//! ```text
//! "CRUCE001" || logical_length:u64be || chunk_bytes:u32be
//! || key_id_binding[32]
//! || repeated AES-256-GCM(plaintext_chunk, derived_nonce, bound_aad)
//! ```
//!
//! The inventory administration directory also pins one key generation before
//! any object access can proceed:
//!
//! ```text
//! "CRUCK001" || key_id_binding[32] || keyed_verifier[32] || checksum[32]
//! ```

use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rustix::fs::{Mode, OFlags, open};
use zeroize::Zeroizing;

use super::admin::{InventoryCounter, persistent_inventory_generation};
use super::directory::{
    DirectoryBlobBackend, DirectoryInventoryState, create_dir_all_durable, directory_receipt,
    inventory_directory_entry, is_lower_hex, path_name, read_directory_entries, require_directory,
    sync_directory,
};
use super::*;

const ENCRYPTED_OBJECT_MAGIC: &[u8; 8] = b"CRUCE001";
const ENCRYPTION_KEY_STATE_MAGIC: &[u8; 8] = b"CRUCK001";
const ENCRYPTION_KEY_STATE_BYTES: u64 = 104;
const ENCRYPTION_KEY_STATE_FILE: &str = "encryption-key-v1";
const ENCRYPTED_OBJECT_HEADER_BYTES: u64 = 52;
const ENCRYPTED_CHUNK_BYTES: u64 = 64 * 1024;
const AES_GCM_TAG_BYTES: u64 = 16;
pub(super) const MAXIMUM_ENCRYPTED_LOGICAL_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const KEY_ID_BINDING_DOMAIN: &[u8] = b"crucible.content-store.encryption-key-id.v1";
const AES_KEY_DOMAIN: &[u8] = b"crucible.content-store.encrypted-aes-key.v1";
const KEY_STATE_VERIFIER_DOMAIN: &[u8] = b"crucible.content-store.encryption-key-verifier.v1";
const KEY_STATE_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.encryption-key-state.v1";
const CHUNK_NONCE_DOMAIN: &[u8] = b"crucible.content-store.encrypted-chunk-nonce.v1";
const CHUNK_AAD_DOMAIN: &[u8] = b"crucible.content-store.encrypted-chunk-aad.v1";

/// Non-secret operational identifier for one encryption-key generation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreEncryptionKeyId(String);

impl StoreEncryptionKeyId {
    /// Validates one bounded ASCII key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the identifier is empty,
    /// exceeds 64 bytes, or contains characters outside letters, digits, `.`,
    /// `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(StoreError::InvalidComposition {
                reason: "encrypted store key identifier is invalid",
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated non-secret spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Zeroizing 256-bit AES key held outside graph configuration.
pub struct StoreEncryptionKey(Zeroizing<[u8; 32]>);

impl StoreEncryptionKey {
    /// Wraps one nonzero 256-bit encryption key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] for an all-zero key, which is
    /// treated as an unprovisioned operator secret rather than a usable key.
    pub fn new(bytes: [u8; 32]) -> Result<Self, StoreError> {
        if bytes == [0; 32] {
            return Err(StoreError::InvalidComposition {
                reason: "encrypted store key is not provisioned",
            });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// External secret capability used while constructing encrypted graph leaves.
#[derive(Default)]
pub struct StoreGraphKeyring {
    keys: BTreeMap<StoreEncryptionKeyId, Arc<StoreEncryptionKey>>,
}

impl StoreGraphKeyring {
    /// Creates an empty key capability.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Inserts one exact key generation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the identifier already
    /// names a key in this capability.
    pub fn insert(
        &mut self,
        id: StoreEncryptionKeyId,
        key: StoreEncryptionKey,
    ) -> Result<(), StoreError> {
        match self.keys.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(key));
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::InvalidComposition {
                reason: "encrypted store key capability contains a duplicate identifier",
            }),
        }
    }

    pub(super) fn resolve(
        &self,
        id: &StoreEncryptionKeyId,
    ) -> Result<Arc<StoreEncryptionKey>, StoreError> {
        self.keys.get(id).cloned().ok_or(StoreError::Unauthorized)
    }
}

/// Durable loose-object leaf using bounded authenticated encryption.
#[derive(Clone)]
pub struct EncryptedDirectoryBlobBackend {
    directory: DirectoryBlobBackend,
    maximum_logical_object_bytes: u64,
    key_id: StoreEncryptionKeyId,
    key_id_binding: [u8; 32],
    key: Arc<StoreEncryptionKey>,
}

impl fmt::Debug for EncryptedDirectoryBlobBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDirectoryBlobBackend")
            .field("directory", &self.directory)
            .field(
                "maximum_logical_object_bytes",
                &self.maximum_logical_object_bytes,
            )
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl EncryptedDirectoryBlobBackend {
    /// Opens one encrypted directory leaf from an external secret capability.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the per-object limit is
    /// zero or exceeds 64 MiB.
    pub fn new(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        maximum_logical_object_bytes: u64,
        key_id: StoreEncryptionKeyId,
        key: StoreEncryptionKey,
    ) -> Result<Self, StoreError> {
        Self::open(
            name,
            root.into(),
            maximum_logical_object_bytes,
            key_id,
            Arc::new(key),
        )
    }

    pub(super) fn open(
        name: impl Into<String>,
        root: PathBuf,
        maximum_logical_object_bytes: u64,
        key_id: StoreEncryptionKeyId,
        key: Arc<StoreEncryptionKey>,
    ) -> Result<Self, StoreError> {
        if maximum_logical_object_bytes == 0
            || maximum_logical_object_bytes > MAXIMUM_ENCRYPTED_LOGICAL_OBJECT_BYTES
        {
            return Err(StoreError::InvalidComposition {
                reason: "encrypted directory has an invalid logical-object byte limit",
            });
        }
        let key_id_binding = key_id_binding(&key_id)?;
        Ok(Self {
            directory: DirectoryBlobBackend::new(name, root),
            maximum_logical_object_bytes,
            key_id,
            key_id_binding,
            key,
        })
    }

    /// Returns the physical encrypted-object root.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.directory.root()
    }

    /// Returns the hard plaintext limit for one object.
    #[must_use]
    pub const fn maximum_logical_object_bytes(&self) -> u64 {
        self.maximum_logical_object_bytes
    }

    /// Returns the non-secret key-generation identifier.
    #[must_use]
    pub const fn key_id(&self) -> &StoreEncryptionKeyId {
        &self.key_id
    }

    fn read_handle(
        &self,
        id: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let _inventory_lock = self.directory.acquire_inventory_lock()?;
        self.validate_or_create_key_state_locked()?;
        self.read_handle_with_key_state(id, range)
    }

    fn read_handle_with_key_state(
        &self,
        id: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let path = self.directory.object_path(id);
        let (file, header) = open_encrypted_object(
            &path,
            id,
            self.maximum_logical_object_bytes,
            self.key_id_binding,
        )?;
        let range = range.unwrap_or(ByteRange {
            offset: 0,
            length: header.logical_length,
        });
        validate_range(header.logical_length, range)?;
        let source: Arc<dyn BlobSource> = Arc::new(EncryptedDirectoryBlobSource {
            file,
            id,
            header,
            range,
            key: Arc::clone(&self.key),
        });
        if range.offset == 0 && range.length == header.logical_length {
            Ok(BlobHandle::authenticated(id, source))
        } else {
            Ok(BlobHandle::integrity_checked(id, source))
        }
    }

    fn contains_with_key_state(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_handle_with_key_state(id, None) {
            Ok(handle) => {
                validate_source(id, &handle)?;
                Ok(true)
            }
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn validate_or_create_key_state_locked(&self) -> Result<(), StoreError> {
        let directory = self.root().join(".inventory-admin");
        create_dir_all_durable(&directory)?;
        let path = directory.join(ENCRYPTION_KEY_STATE_FILE);
        match read_key_state(&path, self.key_id_binding, self.key.bytes()) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => return Err(error),
        }

        let bytes = encryption_key_state(self.key_id_binding, self.key.bytes());
        let (staging_path, mut staging) = self.directory.create_staging(&directory)?;
        let publish_result = (|| {
            staging
                .write_all(&bytes)
                .and_then(|()| staging.sync_all())
                .map_err(|source| StoreError::Io {
                    operation: "write-encryption-key-state-staging",
                    path: staging_path.clone(),
                    source,
                })?;
            match fs::hard_link(&staging_path, &path) {
                Ok(()) => sync_directory(&directory),
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    if read_key_state(&path, self.key_id_binding, self.key.bytes())? {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidComposition {
                            reason: "encrypted directory key state disappeared during publication",
                        })
                    }
                }
                Err(source) => Err(StoreError::Io {
                    operation: "publish-encryption-key-state",
                    path: path.clone(),
                    source,
                }),
            }
        })();
        let remove_result = fs::remove_file(&staging_path);
        if let Err(source) = remove_result
            && source.kind() != std::io::ErrorKind::NotFound
            && publish_result.is_ok()
        {
            return Err(StoreError::Io {
                operation: "remove-encryption-key-state-staging",
                path: staging_path,
                source,
            });
        }
        publish_result
    }
}

impl ImmutableBlobBackend for EncryptedDirectoryBlobBackend {
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
        let _inventory_lock = self.directory.acquire_inventory_lock()?;
        self.validate_or_create_key_state_locked()?;
        self.contains_with_key_state(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.read_handle(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        if source.logical_length() > self.maximum_logical_object_bytes {
            return Err(StoreError::Quota);
        }
        let _inventory_lock = self.directory.acquire_inventory_lock()?;
        self.validate_or_create_key_state_locked()?;
        let mut inventory_state = self.directory.load_or_create_inventory_state()?;
        self.directory
            .advance_inventory_state(&mut inventory_state)?;

        let path = self.directory.object_path(id);
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "encrypted object path has no containing directory",
        })?;
        create_dir_all_durable(directory)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                source.verified_as(id)?;
                if !self.contains_with_key_state(id)? {
                    return Err(StoreError::NotFound { id });
                }
                sync_directory(directory)?;
                return Ok(directory_receipt(self.name(), id, source.logical_length()));
            }
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "encrypted object placement is not a regular file",
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "inspect-encrypted-object",
                    path,
                    source,
                });
            }
        }

        let (staging_path, mut staging) = self.directory.create_staging(directory)?;
        let publish_result = (|| {
            let header = EncryptedObjectHeader {
                logical_length: source.logical_length(),
                key_id_binding: self.key_id_binding,
            };
            write_encrypted_header(&mut staging, header)?;
            encrypt_source(id, source, header, self.key.bytes(), &mut staging)?;
            staging.sync_all().map_err(|source| StoreError::Io {
                operation: "sync-encrypted-object-staging",
                path: staging_path.clone(),
                source,
            })?;
            match fs::hard_link(&staging_path, &path) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !self.contains_with_key_state(id)? {
                        return Err(StoreError::NotFound { id });
                    }
                }
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "publish-encrypted-object",
                        path: path.clone(),
                        source,
                    });
                }
            }
            sync_directory(directory)
        })();

        let remove_result = fs::remove_file(&staging_path);
        if let Err(source) = remove_result
            && source.kind() != std::io::ErrorKind::NotFound
            && publish_result.is_ok()
        {
            return Err(StoreError::Io {
                operation: "remove-encrypted-object-staging",
                path: staging_path,
                source,
            });
        }
        publish_result?;
        Ok(directory_receipt(self.name(), id, source.logical_length()))
    }
}

impl BlobStoreAdmin for EncryptedDirectoryBlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lock = self.directory.acquire_inventory_lock()?;
        self.validate_or_create_key_state_locked()?;
        let state = self.directory.load_or_create_inventory_state()?;
        Ok(Box::new(EncryptedDirectoryInventoryFence {
            backend: self,
            _lock: lock,
            state,
        }))
    }
}

#[derive(Clone, Copy)]
struct EncryptedObjectHeader {
    logical_length: u64,
    key_id_binding: [u8; 32],
}

fn encryption_key_state(key_id_binding: [u8; 32], key: &[u8; 32]) -> [u8; 104] {
    let mut bytes = [0_u8; 104];
    bytes[..8].copy_from_slice(ENCRYPTION_KEY_STATE_MAGIC);
    bytes[8..40].copy_from_slice(&key_id_binding);
    let mut verifier = blake3::Hasher::new_keyed(key);
    verifier.update(KEY_STATE_VERIFIER_DOMAIN);
    verifier.update(&key_id_binding);
    bytes[40..72].copy_from_slice(verifier.finalize().as_bytes());
    let mut checksum = blake3::Hasher::new();
    checksum.update(KEY_STATE_CHECKSUM_DOMAIN);
    checksum.update(&bytes[..72]);
    bytes[72..].copy_from_slice(checksum.finalize().as_bytes());
    bytes
}

fn read_key_state(
    path: &Path,
    expected_key_id_binding: [u8; 32],
    key: &[u8; 32],
) -> Result<bool, StoreError> {
    let descriptor = match open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(source) if source == rustix::io::Errno::NOENT => return Ok(false),
        Err(source) => {
            return Err(StoreError::Io {
                operation: "open-encryption-key-state",
                path: path.to_path_buf(),
                source: std::io::Error::from_raw_os_error(source.raw_os_error()),
            });
        }
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspect-encryption-key-state",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() != ENCRYPTION_KEY_STATE_BYTES {
        return Err(StoreError::InvalidComposition {
            reason: "encrypted directory key state is malformed",
        });
    }
    let mut bytes = [0_u8; 104];
    read_exact_at(&file, &mut bytes, 0).map_err(|_| StoreError::InvalidComposition {
        reason: "encrypted directory key state is malformed",
    })?;
    if bytes[..8] != *ENCRYPTION_KEY_STATE_MAGIC {
        return Err(StoreError::InvalidComposition {
            reason: "encrypted directory key state is corrupt or belongs to another generation",
        });
    }
    let mut checksum = blake3::Hasher::new();
    checksum.update(KEY_STATE_CHECKSUM_DOMAIN);
    checksum.update(&bytes[..72]);
    if bytes[72..] != *checksum.finalize().as_bytes() || bytes[8..40] != expected_key_id_binding {
        return Err(StoreError::InvalidComposition {
            reason: "encrypted directory key state is corrupt or belongs to another generation",
        });
    }
    let mut verifier = blake3::Hasher::new_keyed(key);
    verifier.update(KEY_STATE_VERIFIER_DOMAIN);
    verifier.update(&expected_key_id_binding);
    if verifier.finalize() != bytes[40..72] {
        return Err(StoreError::Unauthorized);
    }
    Ok(true)
}

fn write_encrypted_header(
    file: &mut File,
    header: EncryptedObjectHeader,
) -> Result<(), StoreError> {
    file.write_all(ENCRYPTED_OBJECT_MAGIC)
        .and_then(|()| file.write_all(&header.logical_length.to_be_bytes()))
        .and_then(|()| file.write_all(&(ENCRYPTED_CHUNK_BYTES as u32).to_be_bytes()))
        .and_then(|()| file.write_all(&header.key_id_binding))
        .map_err(|source| StoreError::StreamIo {
            operation: "write-encrypted-object-header",
            source,
        })
}

fn open_encrypted_object(
    path: &Path,
    id: ContentId,
    maximum_logical_object_bytes: u64,
    expected_key_id_binding: [u8; 32],
) -> Result<(Arc<File>, EncryptedObjectHeader), StoreError> {
    let descriptor = match open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(source) if source == rustix::io::Errno::NOENT => {
            return Err(StoreError::NotFound { id });
        }
        Err(source) => {
            return Err(StoreError::Io {
                operation: "open-encrypted-object",
                path: path.to_path_buf(),
                source: std::io::Error::from_raw_os_error(source.raw_os_error()),
            });
        }
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspect-encrypted-object",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::InvalidComposition {
            reason: "encrypted object placement is not a regular file",
        });
    }
    let physical_length = metadata.len();
    let mut bytes = [0_u8; ENCRYPTED_OBJECT_HEADER_BYTES as usize];
    read_exact_at(&file, &mut bytes, 0).map_err(|_| StoreError::Corrupt { id })?;
    if &bytes[..8] != ENCRYPTED_OBJECT_MAGIC {
        return Err(StoreError::Corrupt { id });
    }
    let logical_length = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| StoreError::Corrupt { id })?,
    );
    let chunk_bytes = u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| StoreError::Corrupt { id })?,
    );
    let key_id_binding = bytes[20..52]
        .try_into()
        .map_err(|_| StoreError::Corrupt { id })?;
    if logical_length > maximum_logical_object_bytes
        || chunk_bytes != ENCRYPTED_CHUNK_BYTES as u32
        || key_id_binding != expected_key_id_binding
        || encrypted_physical_length(logical_length) != Some(physical_length)
    {
        return Err(StoreError::Corrupt { id });
    }
    Ok((
        Arc::new(file),
        EncryptedObjectHeader {
            logical_length,
            key_id_binding,
        },
    ))
}

fn encrypt_source(
    id: ContentId,
    source: &BlobHandle,
    header: EncryptedObjectHeader,
    key: &[u8; 32],
    output: &mut File,
) -> Result<(), StoreError> {
    let aes_key = derived_aes_key(key);
    let cipher =
        Aes256Gcm::new_from_slice(&*aes_key).map_err(|_| StoreError::InvalidComposition {
            reason: "encrypted store AES-256 key construction failed",
        })?;
    let mut reader = source.open()?;
    let mut remaining = header.logical_length;
    let mut chunk_index = 0_u32;
    let mut hasher = content_hasher(id.kind(), id.schema_version(), header.logical_length);
    loop {
        let plaintext_length = remaining.min(ENCRYPTED_CHUNK_BYTES);
        let capacity = usize::try_from(plaintext_length).map_err(|_| StoreError::Quota)?;
        let mut plaintext = Zeroizing::new(vec![0_u8; capacity]);
        read_source_exact(
            &mut reader,
            &mut plaintext,
            header.logical_length,
            header.logical_length - remaining,
        )?;
        hasher.update(&plaintext);
        remaining -= plaintext_length;
        let last = remaining == 0;
        let nonce = chunk_nonce(key, id, chunk_index);
        let aad = chunk_aad(id, header, chunk_index, last, plaintext_length)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::InvalidComposition {
                reason: "encrypted store chunk encryption failed",
            })?;
        output
            .write_all(&ciphertext)
            .map_err(|source| StoreError::StreamIo {
                operation: "write-encrypted-object-chunk",
                source,
            })?;
        if last {
            break;
        }
        chunk_index = chunk_index.checked_add(1).ok_or(StoreError::Quota)?;
    }
    let mut extra = [0_u8; 1];
    let has_extra = read_retry(&mut reader, &mut extra).map_err(|source| StoreError::StreamIo {
        operation: "verify-encrypted-source-length",
        source,
    })? != 0;
    if has_extra {
        return Err(StoreError::InvalidSourceLength {
            declared: header.logical_length,
            observed: header.logical_length.saturating_add(1),
        });
    }
    if *hasher.finalize().as_bytes() != id.digest() {
        return Err(StoreError::Corrupt { id });
    }
    Ok(())
}

fn read_source_exact(
    reader: &mut dyn Read,
    mut output: &mut [u8],
    declared: u64,
    already_read: u64,
) -> Result<(), StoreError> {
    let mut observed = 0_u64;
    while !output.is_empty() {
        let read = read_retry(reader, output).map_err(|source| StoreError::StreamIo {
            operation: "read-encrypted-object-source",
            source,
        })?;
        if read == 0 {
            return Err(StoreError::InvalidSourceLength {
                declared,
                observed: already_read.saturating_add(observed),
            });
        }
        observed += read as u64;
        output = &mut output[read..];
    }
    Ok(())
}

struct EncryptedDirectoryBlobSource {
    file: Arc<File>,
    id: ContentId,
    header: EncryptedObjectHeader,
    range: ByteRange,
    key: Arc<StoreEncryptionKey>,
}

impl BlobSource for EncryptedDirectoryBlobSource {
    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let plaintext = EncryptedPlaintextReader::new(
            Arc::clone(&self.file),
            self.id,
            self.header,
            Arc::clone(&self.key),
        )?;
        Ok(Box::new(AuthenticatingEncryptedReader::new(
            plaintext,
            self.id,
            self.header.logical_length,
            self.range,
        )))
    }
}

struct EncryptedPlaintextReader {
    file: Arc<File>,
    id: ContentId,
    header: EncryptedObjectHeader,
    cipher: Aes256Gcm,
    key: Arc<StoreEncryptionKey>,
    chunk_index: u32,
    remaining: u64,
    physical_offset: u64,
    plaintext: Zeroizing<Vec<u8>>,
    plaintext_offset: usize,
    finished: bool,
}

impl EncryptedPlaintextReader {
    fn new(
        file: Arc<File>,
        id: ContentId,
        header: EncryptedObjectHeader,
        key: Arc<StoreEncryptionKey>,
    ) -> Result<Self, StoreError> {
        let aes_key = derived_aes_key(key.bytes());
        let cipher =
            Aes256Gcm::new_from_slice(&*aes_key).map_err(|_| StoreError::InvalidComposition {
                reason: "encrypted store AES-256 key construction failed",
            })?;
        Ok(Self {
            file,
            id,
            header,
            cipher,
            key,
            chunk_index: 0,
            remaining: header.logical_length,
            physical_offset: ENCRYPTED_OBJECT_HEADER_BYTES,
            plaintext: Zeroizing::new(Vec::new()),
            plaintext_offset: 0,
            finished: false,
        })
    }

    fn load_chunk(&mut self) -> std::io::Result<()> {
        let plaintext_length = self.remaining.min(ENCRYPTED_CHUNK_BYTES);
        let ciphertext_length = plaintext_length
            .checked_add(AES_GCM_TAG_BYTES)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or_else(invalid_encrypted_data)?;
        let mut ciphertext = vec![0_u8; ciphertext_length];
        read_exact_at(&self.file, &mut ciphertext, self.physical_offset)
            .map_err(|_| invalid_encrypted_data())?;
        let last = self.remaining == plaintext_length;
        let nonce = chunk_nonce(self.key.bytes(), self.id, self.chunk_index);
        let aad = chunk_aad(
            self.id,
            self.header,
            self.chunk_index,
            last,
            plaintext_length,
        )
        .map_err(|_| invalid_encrypted_data())?;
        self.plaintext = Zeroizing::new(
            self.cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| invalid_encrypted_data())?,
        );
        if self.plaintext.len() as u64 != plaintext_length {
            return Err(invalid_encrypted_data());
        }
        self.plaintext_offset = 0;
        self.remaining -= plaintext_length;
        self.physical_offset = self
            .physical_offset
            .checked_add(ciphertext_length as u64)
            .ok_or_else(invalid_encrypted_data)?;
        self.finished = last;
        if !last {
            self.chunk_index = self
                .chunk_index
                .checked_add(1)
                .ok_or_else(invalid_encrypted_data)?;
        }
        Ok(())
    }
}

impl Read for EncryptedPlaintextReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.plaintext_offset < self.plaintext.len() {
                let available = self.plaintext.len() - self.plaintext_offset;
                let copied = available.min(output.len());
                output[..copied].copy_from_slice(
                    &self.plaintext[self.plaintext_offset..self.plaintext_offset + copied],
                );
                self.plaintext_offset += copied;
                return Ok(copied);
            }
            if self.finished {
                return Ok(0);
            }
            self.load_chunk()?;
        }
    }
}

struct AuthenticatingEncryptedReader {
    reader: EncryptedPlaintextReader,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
    scan_offset: u64,
    output_offset: u64,
    hasher: blake3::Hasher,
    finalized: bool,
}

impl AuthenticatingEncryptedReader {
    fn new(
        reader: EncryptedPlaintextReader,
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
                .map_err(|_| invalid_encrypted_data())?;
            let read = read_retry(&mut self.reader, &mut buffer[..limit])?;
            if read == 0 {
                return Err(invalid_encrypted_data());
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
            return Err(invalid_encrypted_data());
        }
        self.finalized = true;
        Ok(())
    }
}

impl Read for AuthenticatingEncryptedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        self.scan_until(self.range.offset)?;
        if self.output_offset < self.range.length {
            let remaining = self.range.length - self.output_offset;
            let limit = usize::try_from(remaining.min(output.len() as u64))
                .map_err(|_| invalid_encrypted_data())?;
            let read = read_retry(&mut self.reader, &mut output[..limit])?;
            if read == 0 {
                return Err(invalid_encrypted_data());
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

struct EncryptedDirectoryInventoryFence<'a> {
    backend: &'a EncryptedDirectoryBlobBackend,
    _lock: File,
    state: DirectoryInventoryState,
}

impl BlobInventoryFence for EncryptedDirectoryInventoryFence<'_> {
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
        visit_encrypted_inventory(self.backend, visitor, &mut inventory)?;
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
                    reason: "planned encrypted-object candidate is not a regular file",
                });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PlannedDeleteDisposition::AlreadyAbsent);
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "inspect-encrypted-delete-candidate",
                    path,
                    source,
                });
            }
        }
        fs::remove_file(&path).map_err(|source| StoreError::Io {
            operation: "remove-planned-encrypted-object",
            path: path.clone(),
            source,
        })?;
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "planned encrypted-object candidate has no parent directory",
        })?;
        sync_directory(directory)?;
        Ok(PlannedDeleteDisposition::Deleted)
    }
}

fn visit_encrypted_inventory(
    backend: &EncryptedDirectoryBlobBackend,
    visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    inventory: &mut InventoryCounter,
) -> Result<(), StoreError> {
    let root = backend.root();
    for kind_entry in read_directory_entries(root, "read-encrypted-inventory-root")? {
        let kind_entry =
            inventory_directory_entry(kind_entry, root, "read-encrypted-inventory-root")?;
        let kind_path = kind_entry.path();
        let kind_name = path_name(&kind_path)?;
        if kind_name == ".inventory-admin" {
            require_directory(&kind_path)?;
            continue;
        }
        let kind = ObjectKind::parse(kind_name).ok_or(StoreError::InvalidComposition {
            reason: "encrypted inventory contains an unknown object-kind directory",
        })?;
        require_directory(&kind_path)?;
        for version_entry in read_directory_entries(&kind_path, "read-encrypted-inventory-kind")? {
            let version_entry = inventory_directory_entry(
                version_entry,
                &kind_path,
                "read-encrypted-inventory-kind",
            )?;
            let version_path = version_entry.path();
            require_directory(&version_path)?;
            let version_name = path_name(&version_path)?;
            let version = version_name
                .parse::<u32>()
                .ok()
                .filter(|version| version.to_string() == version_name)
                .ok_or(StoreError::InvalidComposition {
                    reason: "encrypted inventory contains a noncanonical schema version",
                })?;
            for prefix_entry in
                read_directory_entries(&version_path, "read-encrypted-inventory-version")?
            {
                let prefix_entry = inventory_directory_entry(
                    prefix_entry,
                    &version_path,
                    "read-encrypted-inventory-version",
                )?;
                let prefix_path = prefix_entry.path();
                require_directory(&prefix_path)?;
                let prefix = path_name(&prefix_path)?;
                if prefix.len() != 2 || !prefix.bytes().all(is_lower_hex) {
                    return Err(StoreError::InvalidComposition {
                        reason: "encrypted inventory has a noncanonical digest prefix",
                    });
                }
                for object_entry in
                    read_directory_entries(&prefix_path, "read-encrypted-inventory-prefix")?
                {
                    let object_entry = inventory_directory_entry(
                        object_entry,
                        &prefix_path,
                        "read-encrypted-inventory-prefix",
                    )?;
                    let object_path = object_entry.path();
                    let digest = path_name(&object_path)?;
                    if digest.len() != 64
                        || !digest.bytes().all(is_lower_hex)
                        || !digest.starts_with(prefix)
                    {
                        return Err(StoreError::InvalidComposition {
                            reason: "encrypted inventory has a noncanonical object digest",
                        });
                    }
                    let id =
                        ContentId::parse(&format!("{}.{}.{}", kind.as_str(), version, digest))?;
                    let (_, header) = open_encrypted_object(
                        &object_path,
                        id,
                        backend.maximum_logical_object_bytes,
                        backend.key_id_binding,
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

fn key_id_binding(id: &StoreEncryptionKeyId) -> Result<[u8; 32], StoreError> {
    let length = u64::try_from(id.as_str().len()).map_err(|_| StoreError::Quota)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_ID_BINDING_DOMAIN);
    hasher.update(&length.to_be_bytes());
    hasher.update(id.as_str().as_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn derived_aes_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(AES_KEY_DOMAIN);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn encrypted_physical_length(logical_length: u64) -> Option<u64> {
    let chunks = if logical_length == 0 {
        1
    } else {
        logical_length.checked_add(ENCRYPTED_CHUNK_BYTES - 1)? / ENCRYPTED_CHUNK_BYTES
    };
    ENCRYPTED_OBJECT_HEADER_BYTES
        .checked_add(logical_length)?
        .checked_add(chunks.checked_mul(AES_GCM_TAG_BYTES)?)
}

fn chunk_nonce(key: &[u8; 32], id: ContentId, chunk_index: u32) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(CHUNK_NONCE_DOMAIN);
    hasher.update(id.encode().as_bytes());
    hasher.update(&chunk_index.to_be_bytes());
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&hasher.finalize().as_bytes()[..12]);
    nonce
}

fn chunk_aad(
    id: ContentId,
    header: EncryptedObjectHeader,
    chunk_index: u32,
    last: bool,
    plaintext_length: u64,
) -> Result<Vec<u8>, StoreError> {
    let encoded_id = id.encode();
    let id_length = u16::try_from(encoded_id.len()).map_err(|_| StoreError::Quota)?;
    let mut aad =
        Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 2 + encoded_id.len() + 8 + 4 + 32 + 4 + 1 + 8);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(&id_length.to_be_bytes());
    aad.extend_from_slice(encoded_id.as_bytes());
    aad.extend_from_slice(&header.logical_length.to_be_bytes());
    aad.extend_from_slice(&(ENCRYPTED_CHUNK_BYTES as u32).to_be_bytes());
    aad.extend_from_slice(&header.key_id_binding);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(u8::from(last));
    aad.extend_from_slice(&plaintext_length.to_be_bytes());
    Ok(aad)
}

fn invalid_encrypted_data() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "encrypted content authentication failed",
    )
}

fn read_exact_at(file: &File, mut output: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !output.is_empty() {
        let read = read_at_retry(file, output, offset)?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(invalid_encrypted_data)?;
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
