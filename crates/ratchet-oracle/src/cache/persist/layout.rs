//! Filesystem layout for one persistent eval-cache root.
//!
//! Resolves the per-store packfile, index, and schema paths beneath a cache
//! root directory.

use super::*;

/// Filesystem paths for one persistent eval-cache root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistLayout {
    root: PathBuf,
}

impl PersistLayout {
    /// Creates paths rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the schema metadata path.
    pub fn schema_path(&self) -> PathBuf {
        self.root.join("schema.toml")
    }

    /// Returns the mutable node metadata directory.
    pub fn nodes_dir(&self) -> PathBuf {
        self.root.join("nodes")
    }

    /// Returns the durable value store directory.
    pub fn values_dir(&self) -> PathBuf {
        self.root.join("values")
    }

    /// Returns the durable file/frontend artifact directory.
    pub fn files_dir(&self) -> PathBuf {
        self.root.join("files")
    }

    /// Returns the append-only packfile path for immutable blobs in `store`.
    ///
    /// The helper only computes the path; callers remain responsible for the
    /// packfile format, memory mapping, append protocol, and hash-to-offset
    /// index updates.
    pub fn blob_packfile_path(&self, store: PersistBlobStore) -> PathBuf {
        self.blob_store_dir(store).join("pack.blob")
    }

    /// Returns the fixed-record hash-to-offset index path for blobs in `store`.
    pub fn blob_index_path(&self, store: PersistBlobStore) -> PathBuf {
        self.blob_store_dir(store).join("index.blob")
    }

    /// Returns the fixed-record file-artifact mapping index path.
    pub fn file_artifact_index_path(&self) -> PathBuf {
        self.nodes_dir().join("file-artifacts.index")
    }

    /// Returns the append-only packfile path for serialized value blobs.
    pub fn value_packfile_path(&self) -> PathBuf {
        self.blob_packfile_path(PersistBlobStore::Values)
    }

    /// Returns the append-only packfile path for serialized file blobs.
    pub fn file_packfile_path(&self) -> PathBuf {
        self.blob_packfile_path(PersistBlobStore::Files)
    }

    /// Returns the fixed-record hash-to-offset index path for serialized values.
    pub fn value_index_path(&self) -> PathBuf {
        self.blob_index_path(PersistBlobStore::Values)
    }

    /// Returns the fixed-record hash-to-offset index path for serialized files.
    pub fn file_index_path(&self) -> PathBuf {
        self.blob_index_path(PersistBlobStore::Files)
    }

    fn blob_store_dir(&self, store: PersistBlobStore) -> PathBuf {
        match store {
            PersistBlobStore::Values => self.values_dir(),
            PersistBlobStore::Files => self.files_dir(),
        }
    }
}
