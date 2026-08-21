//! Persistent generation fencing for the directory ref namespace.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{FlockOperation, flock};

use super::*;
use crate::content_store::admin::persistent_ref_inventory_generation;

static REF_INVENTORY_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

const REF_ADMIN_DIRECTORY: &str = ".ref-admin";
const REF_INVENTORY_LOCK_FILE: &str = "lock";
const REF_INVENTORY_STATE_FILE: &str = "state-v1";
const REF_INVENTORY_STATE_DOMAIN: &str = "crucible.content-store.directory-ref-inventory-state.v1";
const MAX_REF_INVENTORY_STATE_BYTES: u64 = 256;
const MAX_REF_DIRECTORY_DEPTH: u16 = 512;

#[derive(Clone, Copy)]
pub(super) struct DirectoryRefInventoryState {
    instance: [u8; 32],
    generation: u64,
}

impl DirectoryRefBackend {
    fn ref_inventory_admin_directory(&self) -> PathBuf {
        self.root.join(REF_ADMIN_DIRECTORY)
    }

    pub(super) fn acquire_ref_inventory_lock(
        &self,
        operation: FlockOperation,
    ) -> Result<File, StoreError> {
        let directory = self.ref_inventory_admin_directory();
        create_dir_all_durable(&directory)?;
        let path = directory.join(REF_INVENTORY_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "open-ref-inventory-lock",
                path: path.clone(),
                source,
            })?;
        flock(&file, operation).map_err(|source| StoreError::Io {
            operation: "lock-ref-inventory",
            path,
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        Ok(file)
    }

    pub(super) fn load_or_create_ref_inventory_state(
        &self,
    ) -> Result<DirectoryRefInventoryState, StoreError> {
        let directory = self.ref_inventory_admin_directory();
        let path = directory.join(REF_INVENTORY_STATE_FILE);
        match File::open(&path) {
            Ok(file) => read_ref_inventory_state(file, &path),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let state = DirectoryRefInventoryState {
                    instance: new_ref_inventory_instance(&self.root)?,
                    generation: 1,
                };
                persist_ref_inventory_state(&directory, &path, state)?;
                Ok(state)
            }
            Err(source) => Err(StoreError::Io {
                operation: "read-ref-inventory-state",
                path,
                source,
            }),
        }
    }

    pub(super) fn advance_ref_inventory_state(
        &self,
        state: &mut DirectoryRefInventoryState,
    ) -> Result<(), StoreError> {
        state.generation = state.generation.checked_add(1).ok_or(StoreError::Quota)?;
        let directory = self.ref_inventory_admin_directory();
        let path = directory.join(REF_INVENTORY_STATE_FILE);
        persist_ref_inventory_state(&directory, &path, *state)
    }
}

impl RefStoreAdmin for DirectoryRefBackend {
    fn acquire_ref_inventory_fence(&self) -> Result<Box<dyn RefInventoryFence + '_>, StoreError> {
        let lock = self.acquire_ref_inventory_lock(FlockOperation::LockExclusive)?;
        let state = self.load_or_create_ref_inventory_state()?;
        Ok(Box::new(DirectoryRefInventoryFence {
            backend: self,
            _lock: lock,
            state,
        }))
    }
}

struct DirectoryRefInventoryFence<'a> {
    backend: &'a DirectoryRefBackend,
    _lock: File,
    state: DirectoryRefInventoryState,
}

impl RefInventoryFence for DirectoryRefInventoryFence<'_> {
    fn visit_refs(
        &mut self,
        visitor: &mut dyn FnMut(RefInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<RefInventorySummary, StoreError> {
        let generation =
            persistent_ref_inventory_generation(self.state.instance, self.state.generation);
        let mut refs = 0_u64;
        let root = self.backend.root.join("refs");
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "authoritative ref root is not a directory",
                });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RefInventorySummary::new(generation, 0));
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "inspect-ref-inventory-root",
                    path: root,
                    source,
                });
            }
        }
        visit_ref_directory(self.backend, &root, &root, 0, visitor, &mut refs)?;
        Ok(RefInventorySummary::new(generation, refs))
    }
}

fn visit_ref_directory(
    backend: &DirectoryRefBackend,
    root: &Path,
    directory: &Path,
    depth: u16,
    visitor: &mut dyn FnMut(RefInventoryRecord) -> Result<(), StoreError>,
    refs: &mut u64,
) -> Result<(), StoreError> {
    let entries = fs::read_dir(directory).map_err(|source| StoreError::Io {
        operation: "read-ref-inventory-directory",
        path: directory.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| StoreError::Io {
            operation: "read-ref-inventory-entry",
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| StoreError::Io {
            operation: "inspect-ref-inventory-entry",
            path: path.clone(),
            source,
        })?;
        if file_type.is_dir() {
            if depth >= MAX_REF_DIRECTORY_DEPTH {
                return Err(StoreError::InvalidComposition {
                    reason: "authoritative ref path exceeds its depth limit",
                });
            }
            validate_relative_ref_name(root, &path)?;
            visit_ref_directory(backend, root, &path, depth.saturating_add(1), visitor, refs)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(StoreError::InvalidComposition {
                reason: "authoritative ref inventory entry is not a regular file",
            });
        }
        let ref_name = validate_relative_ref_name(root, &path)?;
        if backend.ref_path(&ref_name) != path {
            return Err(StoreError::InvalidComposition {
                reason: "authoritative ref path is not canonical",
            });
        }
        let target = backend
            .read_unlocked(&ref_name)?
            .ok_or(StoreError::InvalidComposition {
                reason: "authoritative ref disappeared during fenced inventory",
            })?;
        *refs = refs.checked_add(1).ok_or(StoreError::Quota)?;
        visitor(RefInventoryRecord::new(ref_name, target))?;
    }
    Ok(())
}

fn validate_relative_ref_name(root: &Path, path: &Path) -> Result<RefName, StoreError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| StoreError::InvalidComposition {
            reason: "authoritative ref escaped its inventory root",
        })?;
    let value = relative
        .to_str()
        .ok_or(StoreError::InvalidComposition {
            reason: "authoritative ref path is not canonical UTF-8",
        })?
        .to_owned();
    RefName::new(value)
}

fn new_ref_inventory_instance(root: &Path) -> Result<[u8; 32], StoreError> {
    let ordinal = REF_INVENTORY_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let random_path = Path::new("/dev/urandom");
    let mut random = [0_u8; 32];
    File::open(random_path)
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|source| StoreError::Io {
            operation: "read-ref-inventory-instance-randomness",
            path: random_path.to_path_buf(),
            source,
        })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.content-store.directory-ref-inventory-instance.v1");
    hasher.update(root.as_os_str().as_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&ordinal.to_le_bytes());
    hasher.update(&random);
    Ok(*hasher.finalize().as_bytes())
}

fn ref_inventory_state_material(state: DirectoryRefInventoryState) -> String {
    format!(
        "version=1\ninstance={}\ngeneration={}\n",
        encode_digest(state.instance),
        state.generation
    )
}

fn ref_inventory_state_bytes(state: DirectoryRefInventoryState) -> Vec<u8> {
    let material = ref_inventory_state_material(state);
    let mut hasher = blake3::Hasher::new();
    hasher.update(REF_INVENTORY_STATE_DOMAIN.as_bytes());
    hasher.update(material.as_bytes());
    format!(
        "{material}checksum={}\n",
        encode_digest(*hasher.finalize().as_bytes())
    )
    .into_bytes()
}

fn read_ref_inventory_state(
    file: File,
    path: &Path,
) -> Result<DirectoryRefInventoryState, StoreError> {
    let mut bytes = Vec::new();
    file.take(MAX_REF_INVENTORY_STATE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            operation: "read-ref-inventory-state",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)? > MAX_REF_INVENTORY_STATE_BYTES {
        return Err(StoreError::InvalidComposition {
            reason: "directory ref inventory state exceeds its byte limit",
        });
    }
    parse_ref_inventory_state(&bytes)
}

fn parse_ref_inventory_state(bytes: &[u8]) -> Result<DirectoryRefInventoryState, StoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| StoreError::InvalidComposition {
        reason: "directory ref inventory state is not UTF-8",
    })?;
    let mut lines = text.lines();
    if lines.next() != Some("version=1") {
        return Err(StoreError::InvalidComposition {
            reason: "directory ref inventory state has the wrong version",
        });
    }
    let instance = lines
        .next()
        .and_then(|line| line.strip_prefix("instance="))
        .and_then(decode_digest)
        .ok_or(StoreError::InvalidComposition {
            reason: "directory ref inventory state has an invalid instance",
        })?;
    let generation = lines
        .next()
        .and_then(|line| line.strip_prefix("generation="))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(StoreError::InvalidComposition {
            reason: "directory ref inventory state has an invalid generation",
        })?;
    let checksum = lines
        .next()
        .and_then(|line| line.strip_prefix("checksum="))
        .and_then(decode_digest)
        .ok_or(StoreError::InvalidComposition {
            reason: "directory ref inventory state has an invalid checksum",
        })?;
    if lines.next().is_some() {
        return Err(StoreError::InvalidComposition {
            reason: "directory ref inventory state has trailing fields",
        });
    }
    let state = DirectoryRefInventoryState {
        instance,
        generation,
    };
    let material = ref_inventory_state_material(state);
    let mut hasher = blake3::Hasher::new();
    hasher.update(REF_INVENTORY_STATE_DOMAIN.as_bytes());
    hasher.update(material.as_bytes());
    if checksum != *hasher.finalize().as_bytes() {
        return Err(StoreError::InvalidComposition {
            reason: "directory ref inventory state checksum does not match",
        });
    }
    if bytes != ref_inventory_state_bytes(state) {
        return Err(StoreError::InvalidComposition {
            reason: "directory ref inventory state is not canonical",
        });
    }
    Ok(state)
}

fn persist_ref_inventory_state(
    directory: &Path,
    path: &Path,
    state: DirectoryRefInventoryState,
) -> Result<(), StoreError> {
    let bytes = ref_inventory_state_bytes(state);
    let (staging_path, mut staging) = loop {
        let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let staging_path = directory.join(format!(
            ".ref-inventory-state-staging-{}-{ordinal}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
        {
            Ok(staging) => break (staging_path, staging),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "create-ref-inventory-state-staging",
                    path: staging_path,
                    source,
                });
            }
        }
    };
    let result = (|| {
        staging
            .write_all(&bytes)
            .and_then(|()| staging.sync_all())
            .map_err(|source| StoreError::Io {
                operation: "write-ref-inventory-state-staging",
                path: staging_path.clone(),
                source,
            })?;
        fs::rename(&staging_path, path).map_err(|source| StoreError::Io {
            operation: "publish-ref-inventory-state",
            path: path.to_path_buf(),
            source,
        })?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging_path);
    }
    result
}
