//! Durable materialization decisions and reuse metadata.
//!
//! Encodes the [`MaterializationReuse`] counters as stable on-disk metadata and
//! reports whether a blob or file artifact was written or skipped.

use super::*;

impl MaterializationReuse {
    /// Encodes the counters as stable persistent metadata.
    ///
    /// The first little-endian `u64` is the previous-run demand count; the
    /// second is the current-run demand count. This only defines the record
    /// payload a future node-metadata index can store.
    pub fn encode_persist_metadata(self) -> [u8; PERSIST_MATERIALIZATION_REUSE_LEN] {
        let mut bytes = [0; PERSIST_MATERIALIZATION_REUSE_LEN];
        bytes[..8].copy_from_slice(&self.previous_run_demands().to_le_bytes());
        bytes[8..16].copy_from_slice(&self.current_run_demands().to_le_bytes());
        bytes
    }

    /// Decodes materialization reuse counters from stable persistent metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError::ShortMaterializationReuseMetadata`]
    /// if `bytes` is shorter than [`PERSIST_MATERIALIZATION_REUSE_LEN`].
    pub fn decode_persist_metadata(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_MATERIALIZATION_REUSE_LEN {
            return Err(PersistPackFormatError::ShortMaterializationReuseMetadata {
                expected: PERSIST_MATERIALIZATION_REUSE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self::new(read_u64(&bytes[..8]), read_u64(&bytes[8..16])))
    }
}

/// The result of applying a durable materialization decision to a blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistMaterialization {
    /// The blob was appended to the selected persistent packfile.
    Materialized(PersistBlobLocation),
    /// The blob stayed in the in-process tier and no persistent bytes were written.
    Skipped,
}

impl PersistMaterialization {
    /// Returns the complete blob index entry when materialized.
    ///
    /// The caller must pass the same key that was used to materialize the blob;
    /// this type only records the pack location returned by the append path.
    pub const fn index_entry(self, key: PersistBlobKey) -> Option<PersistBlobIndexEntry> {
        match self {
            Self::Materialized(location) => Some(PersistBlobIndexEntry::new(key, location)),
            Self::Skipped => None,
        }
    }
}

/// The result of applying a durable materialization decision to a file artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistFileArtifactMaterialization {
    /// The artifact was appended to the `files/` pack and has index metadata.
    Materialized {
        /// The source realpath/content mapping key for the artifact.
        artifact_key: PersistFileArtifactKey,
        /// The file-blob lookup value a future durable index would store.
        index_value: PersistFileArtifactIndexValue,
    },
    /// The artifact stayed in the in-process tier and no persistent bytes were written.
    Skipped {
        /// The source realpath/content mapping key for the artifact.
        artifact_key: PersistFileArtifactKey,
    },
}

impl PersistFileArtifactMaterialization {
    /// Returns the source realpath/content mapping key.
    pub const fn artifact_key(self) -> PersistFileArtifactKey {
        match self {
            Self::Materialized { artifact_key, .. } | Self::Skipped { artifact_key } => {
                artifact_key
            }
        }
    }

    /// Returns the file-blob index value when the artifact was materialized.
    pub const fn index_value(self) -> Option<PersistFileArtifactIndexValue> {
        match self {
            Self::Materialized { index_value, .. } => Some(index_value),
            Self::Skipped { .. } => None,
        }
    }

    /// Returns the complete file-artifact index entry when materialized.
    pub const fn index_entry(self) -> Option<PersistFileArtifactIndexEntry> {
        match self {
            Self::Materialized {
                artifact_key,
                index_value,
            } => Some(PersistFileArtifactIndexEntry::new(
                artifact_key,
                index_value,
            )),
            Self::Skipped { .. } => None,
        }
    }
}

/// The result of applying a durable materialization decision to a parse artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistParseArtifactMaterialization {
    /// The artifact was appended to the `files/` pack and has index metadata.
    Materialized {
        /// The parse-cache mapping key for the artifact.
        artifact_key: PersistParseArtifactKey,
        /// The file-blob lookup value a durable parse-artifact index stores.
        index_value: PersistParseArtifactIndexValue,
    },
    /// The artifact stayed in the in-process tier and no persistent bytes were written.
    Skipped {
        /// The parse-cache mapping key for the artifact.
        artifact_key: PersistParseArtifactKey,
    },
}

impl PersistParseArtifactMaterialization {
    /// Returns the parse-cache mapping key.
    pub const fn artifact_key(self) -> PersistParseArtifactKey {
        match self {
            Self::Materialized { artifact_key, .. } | Self::Skipped { artifact_key } => {
                artifact_key
            }
        }
    }

    /// Returns the file-blob index value when the artifact was materialized.
    pub const fn index_value(self) -> Option<PersistParseArtifactIndexValue> {
        match self {
            Self::Materialized { index_value, .. } => Some(index_value),
            Self::Skipped { .. } => None,
        }
    }

    /// Returns the complete parse-artifact index entry when materialized.
    pub const fn index_entry(self) -> Option<PersistParseArtifactIndexEntry> {
        match self {
            Self::Materialized {
                artifact_key,
                index_value,
            } => Some(PersistParseArtifactIndexEntry::new(
                artifact_key,
                index_value,
            )),
            Self::Skipped { .. } => None,
        }
    }
}
