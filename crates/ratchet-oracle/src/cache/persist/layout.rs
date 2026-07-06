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

    /// Returns the directory for advisory lock files.
    pub fn locks_dir(&self) -> PathBuf {
        self.root.join(".locks")
    }

    /// Returns the advisory lock path for root initialization.
    pub fn open_lock_path(&self) -> PathBuf {
        self.locks_dir().join("open.lock")
    }

    /// Returns the advisory lock path for cache-level blob-store writes.
    pub fn blob_store_lock_path(&self, store: PersistBlobStore) -> PathBuf {
        let name = match store {
            PersistBlobStore::Values => "values.lock",
            PersistBlobStore::Files => "files.lock",
        };
        self.locks_dir().join(name)
    }

    /// Returns the advisory lock path for file-artifact mapping writes.
    pub fn file_artifact_lock_path(&self) -> PathBuf {
        self.locks_dir().join("file-artifacts.lock")
    }

    /// Returns the advisory lock path for parse-artifact mapping writes.
    pub fn parse_artifact_lock_path(&self) -> PathBuf {
        self.locks_dir().join("parse-artifacts.lock")
    }

    /// Returns the advisory lock path for node-metadata writes.
    pub fn node_metadata_lock_path(&self) -> PathBuf {
        self.locks_dir().join("node-metadata.lock")
    }

    /// Returns the advisory lock path for node-trace writes.
    pub fn node_traces_lock_path(&self) -> PathBuf {
        self.locks_dir().join("node-traces.lock")
    }

    /// Returns the advisory lock path for root-record index writes.
    pub fn root_record_lock_path(&self) -> PathBuf {
        self.locks_dir().join("root-records.lock")
    }

    /// Returns the mutable node metadata directory.
    pub fn nodes_dir(&self) -> PathBuf {
        self.root.join("nodes")
    }

    /// Returns the durable root-instantiation record directory.
    pub fn roots_dir(&self) -> PathBuf {
        self.root.join("roots")
    }

    /// Returns the fixed-record root-instantiation record index path.
    pub fn root_record_index_path(&self) -> PathBuf {
        self.roots_dir().join("instantiations.index")
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

    /// Returns the fixed-record parse-artifact mapping index path.
    pub fn parse_artifact_index_path(&self) -> PathBuf {
        self.nodes_dir().join("parse-artifacts.index")
    }

    /// Returns the fixed-record demand-node metadata index path.
    pub fn node_metadata_index_path(&self) -> PathBuf {
        self.nodes_dir().join("metadata.index")
    }

    /// Returns the append-only node verifying-trace log path.
    pub fn node_trace_log_path(&self) -> PathBuf {
        self.nodes_dir().join("traces.log")
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
