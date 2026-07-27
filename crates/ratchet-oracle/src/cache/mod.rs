//! Content-addressed evaluator caches.
//!
//! The cache layer starts with the frontend parse cache: a durable filesystem
//! layout keyed by source bytes, schema version, and parse flags, plus an
//! in-process import/file memo keyed by canonical realpath and file-content
//! hash.

pub mod boundary_identity;
pub mod cutoff;
pub mod dcg;
pub mod hashing;
pub mod input;
pub mod key;
pub(crate) mod key_hash_probe;
pub mod parse;
pub mod persist;
pub mod policy;
pub mod runtime;

pub use cutoff::{CutoffDecision, EarlyCutoff, ValueHash, ValueHashError};
pub use dcg::{
    BlockedDirtyNode, DemandDependencyGroup, DemandGraph, DemandGraphError, DemandNode,
    DemandNodeAdmission, DemandNodeId, DirtyFrontier, ImpureInputObservation,
    ImpureTraceObservation, ImpureTraceStatus, NodeFreshness, RecomputeReadyDirty, Reconsideration,
    SharedDemandGraph, SharedDemandGraphError,
};
pub use hashing::{
    AttrPositionSourceHash, CacheDigestHasher, CacheExprSourceHash, CacheHashFamily,
    CompiledBodyRecordHash, DurableBlake3Hash, HotXxh3Hash, ImpureInputIdentityHash,
    ImpureInputObservationHash, LoweredIrFingerprint, NixSha256Digest, ParseFileContentHash,
    PersistFileBlobHash, cache_hash_family,
};
pub use input::{
    CacheableInputFingerprint, DirEntryInput, FileTypeForInput, ImpureInputFingerprint,
    ImpureInputIdentity, ImpureInputKind, ImpureInputMode, InputFingerprintError, UncacheableInput,
};
pub use key::{CacheExprIdentity, CacheKeyError, DemandCacheKey};
pub use parse::{
    CachedAnalyzedParse, CachedFileParse, CachedParse, FileParseMemo, PARSE_CACHE_SCHEMA_VERSION,
    ParseArtifactBundle, ParseCache, ParseCacheEntry, ParseCacheError, ParseCacheFlags,
    ParseCacheKey, ParseCacheMeta, ParseFactRefreshError, ParseFileKey, lowered_ir_fingerprint,
};
pub use persist::{
    HydratedRootInstantiation, PERSIST_BLOB_INDEX_ENTRY_LEN, PERSIST_BLOB_INDEX_KEY_LEN,
    PERSIST_BLOB_INDEX_VALUE_LEN, PERSIST_BLOB_PACK_HEADER_LEN, PERSIST_BLOB_PACK_MAGIC,
    PERSIST_BLOB_PACK_VERSION, PERSIST_BLOB_RECORD_HEADER_LEN, PERSIST_CACHE_FORMAT,
    PERSIST_CACHE_SCHEMA_VERSION, PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
    PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN, PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN,
    PERSIST_MATERIALIZATION_REUSE_LEN, PERSIST_NODE_METADATA_INDEX_ENTRY_LEN,
    PERSIST_NODE_METADATA_INDEX_KEY_LEN, PERSIST_NODE_METADATA_INDEX_VALUE_LEN,
    PERSIST_NODE_METADATA_VALUE_HASH_LEN, PERSIST_NODE_TRACE_INPUT_FIXED_LEN,
    PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN, PERSIST_NODE_TRACE_LOG_VALUE_HASH_LEN,
    PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN, PERSIST_NODE_TRACE_PAYLOAD_MAGIC,
    PERSIST_NODE_TRACE_PAYLOAD_VERSION, PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN,
    PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN, PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN,
    PERSIST_ROOT_RECORD_INDEX_ENTRY_LEN, PERSIST_ROOT_RECORD_INDEX_KEY_LEN,
    PERSIST_ROOT_RECORD_INDEX_VALUE_LEN, PERSIST_ROOT_RECORD_PAYLOAD_MAGIC,
    PERSIST_ROOT_RECORD_PAYLOAD_VERSION, PersistBlobIndex, PersistBlobIndexEntry,
    PersistBlobIndexError, PersistBlobIndexRebuild, PersistBlobIndexRebuildError,
    PersistBlobIndexRebuildPlan, PersistBlobIndexRebuildPlanError, PersistBlobIndexStaleEntry,
    PersistBlobIndexedReadError, PersistBlobIndexedWriteError, PersistBlobIndexesRebuildError,
    PersistBlobKey, PersistBlobLocation, PersistBlobPack, PersistBlobPackError,
    PersistBlobPackHeader, PersistBlobPackRecord, PersistBlobPackTrim, PersistBlobPackTrimError,
    PersistBlobRecordHeader, PersistBlobStore, PersistCache, PersistCacheLocations,
    PersistCachedExpressionNodeValueIndexedLoadError,
    PersistCachedExpressionNodeValueIndexedWriteError,
    PersistCachedExpressionNodeValueTraceLoadError, PersistCachedExpressionValueIndexedLoadError,
    PersistCachedExpressionValueIndexedWriteError, PersistCompaction, PersistCompactionError,
    PersistDiskLocation, PersistDiskLocationSpecError, PersistError, PersistFileArtifactFlushError,
    PersistFileArtifactHydrationError, PersistFileArtifactIndex, PersistFileArtifactIndexEntry,
    PersistFileArtifactIndexError, PersistFileArtifactIndexValue,
    PersistFileArtifactIndexedHydrationError, PersistFileArtifactIndexedWriteError,
    PersistFileArtifactKey, PersistFileArtifactMaterialization, PersistLatencyClass, PersistLayout,
    PersistLocationHit, PersistMaterialization, PersistNodeMetadataIndex,
    PersistNodeMetadataIndexEntry, PersistNodeMetadataIndexError, PersistNodeMetadataIndexValue,
    PersistNodeMetadataKey, PersistNodeTraceLog, PersistNodeTraceLogEntry,
    PersistNodeTraceLogError, PersistNodeTraceLogFormatError, PersistNodeTracePayload,
    PersistNodeTracePayloadError, PersistPackFormatError, PersistParseArtifactHydrationError,
    PersistParseArtifactIndex, PersistParseArtifactIndexEntry, PersistParseArtifactIndexError,
    PersistParseArtifactIndexValue, PersistParseArtifactIndexedHydrationError,
    PersistParseArtifactIndexedWriteError, PersistParseArtifactKey,
    PersistParseArtifactMaterialization, PersistParseArtifactMaterializationError,
    PersistParseBytesIndexedLoadError, PersistParseFileIndexedHydrationError,
    PersistParseFileIndexedLoadError, PersistParseSourceIndexedLoadError, PersistRootRecordError,
    PersistRootRecordIndex, PersistRootRecordIndexEntry, PersistRootRecordIndexError,
    PersistRootRecordIndexValue, PersistRootRecordKey, PersistStorageMaintenance,
    PersistStorageMaintenanceError, RootInstantiationRecord, RootRecordBundle,
    RootRecordBundleError,
};
pub use policy::{
    MaterializationCostObservation, MaterializationCosts, MaterializationDecision,
    MaterializationReuse, MaterializationSignals, MemoizationClass, MemoizationDecision,
    MemoizationDemand, MemoizationSignals, MemoizationSubject,
};
pub(crate) use runtime::{
    CachedDerivationAtermPath, CachedDerivationOutputPath, CachedDerivationOutputPaths,
    CachedStaticDerivationOutputPathsPayload,
};
pub use runtime::{
    CachedExpressionValue, CachedExpressionValuePayloadError, EvalCache, EvalCacheRuntime,
    ExpressionCacheability, ExpressionTraceObservation, ImpureInputRevalidator,
    ImpureInputTraceSource, MemoizationObservation,
};
