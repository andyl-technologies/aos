//! One authenticated key generation within the held directory inventory lock.
//!
//! Key publication and validation precede inventory-state creation. Checked
//! callers prepay paths and descriptors and supply the same original boundary;
//! ordinary callers retain the existing no-op boundary behavior.
//!
//! ```text
//! "CRUCK001" || key_id_binding[32] || keyed_verifier[32] || checksum[32]
//! ```

use super::*;

const ENCRYPTION_KEY_STATE_MAGIC: &[u8; 8] = b"CRUCK001";
const ENCRYPTION_KEY_STATE_BYTES: u64 = 104;
const ENCRYPTION_KEY_STATE_FILE: &str = "encryption-key-v1";
const KEY_STATE_VERIFIER_DOMAIN: &[u8] = b"crucible.content-store.encryption-key-verifier.v1";
const KEY_STATE_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.encryption-key-state.v1";

impl EncryptedDirectoryBlobBackend {
    pub(super) fn validate_or_create_key_state_locked(&self) -> Result<(), StoreError> {
        self.validate_or_create_key_state_with_boundary(&mut || Ok(()))
    }

    pub(super) fn validate_or_create_key_state_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        boundary()?;
        let directory = self.root().join(".inventory-admin");
        create_dir_all_durable(&directory)?;
        boundary()?;
        let path = directory.join(ENCRYPTION_KEY_STATE_FILE);
        match read_key_state_with_boundary(&path, self.key_id_binding, self.key.bytes(), boundary) {
            Ok(true) => return boundary(),
            Ok(false) => {}
            Err(error) => return Err(error),
        }

        boundary()?;
        let bytes = encryption_key_state(self.key_id_binding, self.key.bytes());
        let (staging_path, mut staging) = self
            .directory
            .create_staging_with_boundary(&directory, boundary)?;
        let publish_result = (|| {
            boundary()?;
            let mut remaining = bytes.as_slice();
            while !remaining.is_empty() {
                boundary()?;
                match staging.write(remaining) {
                    Ok(0) => {
                        return Err(StoreError::Io {
                            operation: "write-encryption-key-state-staging",
                            path: staging_path.clone(),
                            source: std::io::ErrorKind::WriteZero.into(),
                        });
                    }
                    Ok(count) => remaining = &remaining[count..],
                    Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(source) => {
                        return Err(StoreError::Io {
                            operation: "write-encryption-key-state-staging",
                            path: staging_path.clone(),
                            source,
                        });
                    }
                }
            }
            boundary()?;
            staging.sync_all().map_err(|source| StoreError::Io {
                operation: "write-encryption-key-state-staging",
                path: staging_path.clone(),
                source,
            })?;
            boundary()?;
            match fs::hard_link(&staging_path, &path) {
                Ok(()) => sync_directory(&directory),
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    if read_key_state_with_boundary(
                        &path,
                        self.key_id_binding,
                        self.key.bytes(),
                        boundary,
                    )? {
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
        publish_result?;
        boundary()
    }
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

fn read_key_state_with_boundary(
    path: &Path,
    expected_key_id_binding: [u8; 32],
    key: &[u8; 32],
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<bool, StoreError> {
    boundary()?;
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
    boundary()?;
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
    let mut offset = 0;
    while offset < bytes.len() {
        boundary()?;
        match file.read_at(&mut bytes[offset..], offset as u64) {
            Ok(0) => {
                return Err(StoreError::InvalidComposition {
                    reason: "encrypted directory key state is malformed",
                });
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "encrypted directory key state is malformed",
                });
            }
        }
    }
    boundary()?;
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
    let observed_verifier: [u8; 32] =
        bytes[40..72]
            .try_into()
            .map_err(|_| StoreError::InvalidComposition {
                reason: "encrypted directory key state is malformed",
            })?;
    if !constant_time_equal_32(verifier.finalize().as_bytes(), &observed_verifier) {
        return Err(StoreError::Unauthorized);
    }
    Ok(true)
}
