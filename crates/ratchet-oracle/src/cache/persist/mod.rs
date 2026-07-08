//! Versioned persistent-cache layout.
//!
//! The full Phase-2 storage engine will fill `nodes/`, `values/`, and `files/`
//! with verifying traces and content-addressed artifacts. This module owns the
//! on-disk layout contract and schema-version guard those stores share.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use thiserror::Error;

use super::parse::{
    CachedParse, PARSE_CACHE_SCHEMA_VERSION, ParseArtifactBundle, ParseCache, ParseCacheEntry,
    ParseCacheError, ParseCacheKey, ParseFileKey,
};
use super::{
    CacheExprIdentity, CacheableInputFingerprint, CachedExpressionValue,
    CachedExpressionValuePayloadError, DurableBlake3Hash, ImpureInputFingerprint,
    ImpureInputIdentityHash, ImpureInputKind, ImpureInputMode, ImpureInputRevalidator,
    InputFingerprintError, MaterializationCosts, MaterializationDecision, MaterializationReuse,
    MaterializationSignals, ParseFileContentHash, PersistFileBlobHash, UncacheableInput, ValueHash,
    ValueHashError,
};

/// The persistent eval-cache schema format marker.
pub const PERSIST_CACHE_FORMAT: &str = "aos-nix-eval-cache";
/// The persistent eval-cache schema version.
pub const PERSIST_CACHE_SCHEMA_VERSION: u32 = 8;
/// The fixed magic bytes at the start of every immutable blob packfile.
pub const PERSIST_BLOB_PACK_MAGIC: [u8; 16] = *b"AOS-NIX-BLOBPACK";
/// The immutable blob packfile format version.
pub const PERSIST_BLOB_PACK_VERSION: u32 = 1;
/// The encoded length of an immutable blob packfile header.
pub const PERSIST_BLOB_PACK_HEADER_LEN: usize = 24;
/// The encoded length of an immutable blob record header.
pub const PERSIST_BLOB_RECORD_HEADER_LEN: usize = 40;
/// The encoded length of a hash-to-offset index key.
pub const PERSIST_BLOB_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a hash-to-offset index value.
pub const PERSIST_BLOB_INDEX_VALUE_LEN: usize = 16;
/// The encoded length of a complete hash-to-offset index entry.
pub const PERSIST_BLOB_INDEX_ENTRY_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a file-artifact index key.
pub const PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a file-artifact index value.
pub const PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a complete file-artifact index entry.
pub const PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN: usize =
    PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN + PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN;
/// The encoded length of a parse-artifact index key.
pub const PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a parse-artifact index value.
pub const PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a complete parse-artifact index entry.
pub const PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN: usize =
    PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN + PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN;
/// The encoded length of a root-record index key.
pub const PERSIST_ROOT_RECORD_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a root-record index value.
pub const PERSIST_ROOT_RECORD_INDEX_VALUE_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a complete root-record index entry.
pub const PERSIST_ROOT_RECORD_INDEX_ENTRY_LEN: usize =
    PERSIST_ROOT_RECORD_INDEX_KEY_LEN + PERSIST_ROOT_RECORD_INDEX_VALUE_LEN;
/// The fixed magic bytes at the start of a root-instantiation record payload.
pub const PERSIST_ROOT_RECORD_PAYLOAD_MAGIC: [u8; 16] = *b"AOS-NIX-ROOTREC0";
/// The root-instantiation record payload format version.
pub const PERSIST_ROOT_RECORD_PAYLOAD_VERSION: u32 = 1;
/// The encoded length of a demand-node metadata index key.
pub const PERSIST_NODE_METADATA_INDEX_KEY_LEN: usize = 33;
/// The encoded length of an optional materialized value-hash metadata field.
pub const PERSIST_NODE_METADATA_VALUE_HASH_LEN: usize = 33;
/// The encoded length of a demand-node metadata index value.
pub const PERSIST_NODE_METADATA_INDEX_VALUE_LEN: usize =
    PERSIST_MATERIALIZATION_REUSE_LEN + PERSIST_NODE_METADATA_VALUE_HASH_LEN;
/// The encoded length of a complete demand-node metadata index entry.
pub const PERSIST_NODE_METADATA_INDEX_ENTRY_LEN: usize =
    PERSIST_NODE_METADATA_INDEX_KEY_LEN + PERSIST_NODE_METADATA_INDEX_VALUE_LEN;
/// The encoded length of durable materialization reuse metadata.
pub const PERSIST_MATERIALIZATION_REUSE_LEN: usize = 16;
/// The fixed magic bytes at the start of a node verifying-trace payload.
pub const PERSIST_NODE_TRACE_PAYLOAD_MAGIC: [u8; 16] = *b"AOS-NIX-NTRACE01";
/// The node verifying-trace payload format version.
pub const PERSIST_NODE_TRACE_PAYLOAD_VERSION: u32 = 5;
/// The encoded length of a node verifying-trace payload header.
pub const PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN: usize = 28;
const PERSIST_NODE_TRACE_PAYLOAD_MIN_VERSION: u32 = 1;
const PERSIST_NODE_TRACE_PAYLOAD_TOMBSTONE_COUNT: u64 = u64::MAX;
/// The fixed encoded bytes in one node verifying-trace input record.
pub const PERSIST_NODE_TRACE_INPUT_FIXED_LEN: usize = 42;
/// The fixed encoded bytes in one node verifying-trace memo-read dependency record.
const PERSIST_NODE_TRACE_DEPENDENCY_FIXED_LEN: usize =
    PERSIST_NODE_METADATA_INDEX_KEY_LEN + PERSIST_NODE_METADATA_VALUE_HASH_LEN;
/// The encoded length of a trace-associated materialized value hash.
pub const PERSIST_NODE_TRACE_LOG_VALUE_HASH_LEN: usize = 32;
/// The fixed header bytes in one node trace log record.
pub const PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN: usize =
    PERSIST_NODE_METADATA_INDEX_KEY_LEN + PERSIST_NODE_TRACE_LOG_VALUE_HASH_LEN + 8;

static INDEX_REWRITE_ID: AtomicU64 = AtomicU64::new(0);
const PERSIST_FILE_ARTIFACT_INDEX_TAG: u8 = 3;
const PERSIST_FILE_ARTIFACT_KEY_PERSONALIZATION: &[u8] = b"aos-nix-persist-file-artifact-key-v1";
const PERSIST_PARSE_ARTIFACT_INDEX_TAG: u8 = 4;
const PERSIST_NODE_METADATA_INDEX_TAG: u8 = 5;
const PERSIST_ROOT_RECORD_INDEX_TAG: u8 = 6;
const PERSIST_NODE_METADATA_VALUE_HASH_NONE_TAG: u8 = 0;
const PERSIST_NODE_METADATA_VALUE_HASH_PRESENT_TAG: u8 = 1;
const PERSIST_NODE_METADATA_EXPRESSION_KEY_PERSONALIZATION: &[u8] =
    b"aos-nix-persist-node-expression-key-v1";
const PERSIST_NODE_METADATA_IMPURE_INPUT_KEY_PERSONALIZATION: &[u8] =
    b"aos-nix-persist-node-impure-input-key-v1";

mod cache;
mod disk;
mod error;
mod format;
mod layout;
mod locations;
mod materialization;
mod pack;

pub use cache::{
    HydratedRootInstantiation, PersistBlobIndexRebuild, PersistBlobIndexRebuildPlan,
    PersistBlobIndexStaleEntry, PersistBlobLiveRoot, PersistBlobLiveRootSource,
    PersistBlobPackLivenessPlan, PersistBlobPackRepackPlan, PersistBlobPackTrim,
    PersistBlobPacksRepack, PersistBlobRecordRelocation, PersistCache, PersistCompaction,
    PersistFileBlobReachabilityPlan, PersistMissingNodeValueRoot, PersistNodeValueRoot,
    PersistNodeValueRootPlan, PersistStorageMaintenance, PersistStorageMaintenanceAction,
    PersistStorageMaintenanceOutcome, PersistStorageMaintenancePlan,
    PersistStorageMaintenancePolicy, PersistStorageRepack, PersistValueBlobReachabilityPlan,
};
pub use error::{
    PersistBlobIndexError, PersistBlobIndexRebuildError, PersistBlobIndexRebuildPlanError,
    PersistBlobIndexedReadError, PersistBlobIndexedWriteError, PersistBlobIndexesRebuildError,
    PersistBlobLiveRootError, PersistBlobPackError, PersistBlobPackLivenessPlanError,
    PersistBlobPackRepackPlanError, PersistBlobPackTrimError, PersistBlobPacksRepackError,
    PersistCachedExpressionNodeValueIndexedLoadError,
    PersistCachedExpressionNodeValueIndexedWriteError,
    PersistCachedExpressionNodeValueTraceLoadError, PersistCachedExpressionValueIndexedLoadError,
    PersistCachedExpressionValueIndexedWriteError, PersistCompactionError, PersistError,
    PersistFileArtifactHydrationError, PersistFileArtifactIndexError,
    PersistFileArtifactIndexedHydrationError, PersistFileArtifactIndexedWriteError,
    PersistFileBlobPackRepackError, PersistFileBlobReachabilityPlanError,
    PersistNodeMetadataIndexError, PersistNodeTraceLogError, PersistNodeTraceLogFormatError,
    PersistNodeTracePayloadError, PersistNodeValueRootPlanError, PersistPackFormatError,
    PersistParseArtifactHydrationError, PersistParseArtifactIndexError,
    PersistParseArtifactIndexedHydrationError, PersistParseArtifactIndexedWriteError,
    PersistParseArtifactMaterializationError, PersistParseBytesIndexedLoadError,
    PersistParseFileIndexedHydrationError, PersistParseFileIndexedLoadError,
    PersistParseSourceIndexedLoadError, PersistRootRecordError, PersistRootRecordIndexError,
    PersistStorageAutoMaintenanceError, PersistStorageMaintenanceError,
    PersistStorageMaintenancePlanError, PersistStorageRepackError, PersistValueBlobPackRepackError,
    PersistValueBlobReachabilityPlanError,
};
pub use format::{
    PersistBlobIndex, PersistBlobIndexEntry, PersistBlobKey, PersistBlobLocation,
    PersistBlobPackHeader, PersistBlobRecordHeader, PersistBlobStore, PersistFileArtifactIndex,
    PersistFileArtifactIndexEntry, PersistFileArtifactIndexValue, PersistFileArtifactKey,
    PersistNodeMetadataIndex, PersistNodeMetadataIndexEntry, PersistNodeMetadataIndexValue,
    PersistNodeMetadataKey, PersistNodeTraceLog, PersistNodeTraceLogEntry, PersistNodeTracePayload,
    PERSIST_ROOT_RECORD_BUNDLE_MAGIC, PERSIST_ROOT_RECORD_BUNDLE_VERSION,
    PersistParseArtifactIndex, PersistParseArtifactIndexEntry, PersistParseArtifactIndexValue,
    PersistParseArtifactKey, PersistRootRecordIndex, PersistRootRecordIndexEntry,
    PersistRootRecordIndexValue, PersistRootRecordKey, RootInstantiationRecord, RootRecordBundle,
    RootRecordBundleError,
};
pub use layout::PersistLayout;
pub use locations::{
    PersistCacheLocations, PersistDiskLocation, PersistDiskLocationSpecError, PersistLatencyClass,
    PersistLocationHit, open_secondary_caches,
};
pub use materialization::{
    PersistFileArtifactMaterialization, PersistMaterialization, PersistParseArtifactMaterialization,
};
pub use pack::{PersistBlobPack, PersistBlobPackRecord, PersistBlobPayloadWindow};

// The `io` helpers are `persist`-internal; re-import them here so this module
// and sibling modules can name them through `use super::*`.
use disk::*;

#[cfg(test)]
mod tests;
