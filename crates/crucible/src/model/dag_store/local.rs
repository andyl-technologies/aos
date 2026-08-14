//! Filesystem-backed content-addressed DAG storage.

use super::*;

/// Filesystem-backed [`DagStore`] using the RFC-0010 two-level layout.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalDagStore {
    root: PathBuf,
}

/// Local lookup record from a checkpoint id to its persisted closure artifact.
///
/// The record itself is stored as normal content-addressed bytes. The local
/// store keeps only a sidecar pointer from checkpoint id to this record so CLI
/// commands can resolve `blake3:<checkpoint>` without scanning the whole store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalCheckpointClosureIndex {
    /// Checkpoint/configuration id accepted by resume and fork commands.
    pub checkpoint: ContentHash,
    /// Store key for the self-contained `(seed, scenario, schedule)` artifact.
    pub reproduction_artifact: ContentHash,
    /// Shared virtual-time frontier of the saved configuration.
    pub frontier: VirtualTime,
}

impl LocalDagStore {
    /// Builds a local DAG store rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the two-level object path for `key`.
    ///
    /// The layout is `{root}/{first 2 hex chars}/{full hex hash}`.
    #[must_use]
    pub fn object_path(&self, key: &ContentHash) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(&hex[0..2]).join(hex)
    }

    /// Writes a checkpoint lookup record and returns its content-addressed key.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when the record cannot be stored or when the
    /// local sidecar pointer cannot be written.
    pub fn write_checkpoint_closure_index(
        &self,
        checkpoint: ContentHash,
        reproduction_artifact: ContentHash,
        frontier: VirtualTime,
    ) -> Result<ContentHash, DagStoreError> {
        let bytes = checkpoint_closure_index_bytes(checkpoint, reproduction_artifact, frontier);
        let index_key = self.put(&bytes)?;
        let path = self.checkpoint_closure_index_path(&checkpoint);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| DagStoreError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let temp_path = local_store_temp_path(&path, &index_key);
        fs::write(
            &temp_path,
            format!(
                "{}\n",
                ContentAddressedBlobRef::from_hash(index_key).to_uri()
            ),
        )
        .map_err(|source| DagStoreError::Io {
            operation: "write",
            path: temp_path.clone(),
            source,
        })?;
        if let Err(source) = fs::rename(&temp_path, &path) {
            let _ = fs::remove_file(&temp_path);
            return Err(DagStoreError::Io {
                operation: "rename",
                path,
                source,
            });
        }
        Ok(index_key)
    }

    /// Reads a checkpoint lookup record previously written by this store.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError::NotFound`] when no lookup exists for
    /// `checkpoint`. Returns [`DagStoreError::CorruptIndex`] when the sidecar or
    /// content-addressed record is malformed or names a different checkpoint.
    pub fn read_checkpoint_closure_index(
        &self,
        checkpoint: ContentHash,
    ) -> Result<LocalCheckpointClosureIndex, DagStoreError> {
        let path = self.checkpoint_closure_index_path(&checkpoint);
        let sidecar = fs::read_to_string(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                DagStoreError::NotFound { key: checkpoint }
            } else {
                DagStoreError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let index_key = parse_checkpoint_closure_index_sidecar(checkpoint, &sidecar)?;
        let bytes = self.get(&index_key)?;
        parse_checkpoint_closure_index_bytes(checkpoint, &bytes)
    }

    fn checkpoint_closure_index_path(&self, checkpoint: &ContentHash) -> PathBuf {
        let hex = checkpoint.to_hex();
        self.root
            .join("_indexes")
            .join("checkpoint-closures")
            .join(&hex[0..2])
            .join(hex)
    }
}

impl DagStore for LocalDagStore {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError> {
        let key = ContentHash::from_bytes(bytes);
        let path = self.object_path(&key);
        let replace_existing = match fs::read(&path) {
            Ok(existing) => {
                if ContentHash::from_bytes(&existing) == key && existing == bytes {
                    return Ok(key);
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(DagStoreError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| DagStoreError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let temp_path = local_store_temp_path(&path, &key);
        fs::write(&temp_path, bytes).map_err(|source| DagStoreError::Io {
            operation: "write",
            path: temp_path.clone(),
            source,
        })?;
        if replace_existing {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(DagStoreError::Io {
                        operation: "remove",
                        path,
                        source,
                    });
                }
            }
        }
        if let Err(source) = fs::rename(&temp_path, &path) {
            if let Ok(existing) = fs::read(&path)
                && ContentHash::from_bytes(&existing) == key
                && existing == bytes
            {
                let _ = fs::remove_file(&temp_path);
                return Ok(key);
            }
            let _ = fs::remove_file(&temp_path);
            return Err(DagStoreError::Io {
                operation: "rename",
                path,
                source,
            });
        }
        Ok(key)
    }

    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError> {
        let path = self.object_path(key);
        let bytes = fs::read(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                DagStoreError::NotFound { key: *key }
            } else {
                DagStoreError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let actual = ContentHash::from_bytes(&bytes);
        if actual != *key {
            return Err(DagStoreError::ContentMismatch {
                expected: *key,
                actual,
            });
        }
        Ok(bytes)
    }

    fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        match self.get(key) {
            Ok(_) => Ok(true),
            Err(DagStoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn delete(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        let path = self.object_path(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(DagStoreError::Io {
                operation: "delete",
                path,
                source,
            }),
        }
    }
}
