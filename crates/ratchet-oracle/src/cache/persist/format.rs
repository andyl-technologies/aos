//! On-disk format primitives for the persistent eval cache.
//!
//! Owns the typed blob namespaces, content-addressed lookup keys, packfile and
//! record headers, blob locations, artifact indexes, demand-node metadata, and
//! verifying trace encodings shared by the persistent cache stores.

use super::*;

mod blob_index;
mod file_artifact_index;
mod node_metadata;
mod node_trace;
mod parse_artifact_index;
mod root_record;
mod root_record_bundle;
mod root_record_index;

pub use blob_index::{
    PersistBlobIndex, PersistBlobIndexEntry, PersistBlobKey, PersistBlobLocation,
    PersistBlobPackHeader, PersistBlobRecordHeader, PersistBlobStore,
};
pub use file_artifact_index::{
    PersistFileArtifactIndex, PersistFileArtifactIndexEntry, PersistFileArtifactIndexValue,
    PersistFileArtifactKey,
};
pub use node_metadata::{
    PersistNodeMetadataIndex, PersistNodeMetadataIndexEntry, PersistNodeMetadataIndexValue,
    PersistNodeMetadataKey,
};
pub use node_trace::{PersistNodeTraceLog, PersistNodeTraceLogEntry, PersistNodeTracePayload};
pub use parse_artifact_index::{
    PersistParseArtifactIndex, PersistParseArtifactIndexEntry, PersistParseArtifactIndexValue,
    PersistParseArtifactKey,
};
pub use root_record::RootInstantiationRecord;
pub use root_record_bundle::{
    PERSIST_ROOT_RECORD_BUNDLE_MAGIC, PERSIST_ROOT_RECORD_BUNDLE_VERSION, RootRecordBundle,
    RootRecordBundleError,
};
pub use root_record_index::{
    PersistRootRecordIndex, PersistRootRecordIndexEntry, PersistRootRecordIndexValue,
    PersistRootRecordKey,
};
