//! Content-addressed evaluator caches.
//!
//! The cache layer starts with the frontend parse cache: a durable filesystem
//! layout keyed by source bytes, schema version, and parse flags, plus an
//! in-process import/file memo keyed by canonical realpath and file-content
//! hash.

pub mod cutoff;
pub mod dcg;
pub mod hashing;
pub mod input;
pub mod key;
pub mod parse;
pub mod persist;
pub mod policy;
pub mod runtime;

pub use cutoff::{CutoffDecision, EarlyCutoff, ValueHash, ValueHashError};
pub use dcg::{
    DemandGraph, DemandGraphError, DemandNode, DemandNodeId, ImpureInputObservation,
    ImpureTraceObservation, ImpureTraceStatus, NodeFreshness, Reconsideration,
};
pub use hashing::{DurableBlake3Hash, HotXxh3Hash};
pub use input::{
    CacheableInputFingerprint, DirEntryInput, FileTypeForInput, ImpureInputFingerprint,
    ImpureInputIdentity, ImpureInputKind, ImpureInputMode, InputFingerprintError, UncacheableInput,
};
pub use key::{CacheExprIdentity, CacheKeyError, DemandCacheKey};
pub use parse::{
    CachedFileParse, CachedParse, FileParseMemo, PARSE_CACHE_SCHEMA_VERSION, ParseArtifactBundle,
    ParseCache, ParseCacheEntry, ParseCacheError, ParseCacheFlags, ParseCacheKey, ParseCacheMeta,
    ParseFileKey,
};
pub use persist::{
    PERSIST_BLOB_INDEX_ENTRY_LEN, PERSIST_BLOB_INDEX_KEY_LEN, PERSIST_BLOB_INDEX_VALUE_LEN,
    PERSIST_BLOB_PACK_HEADER_LEN, PERSIST_BLOB_PACK_MAGIC, PERSIST_BLOB_PACK_VERSION,
    PERSIST_BLOB_RECORD_HEADER_LEN, PERSIST_CACHE_FORMAT, PERSIST_CACHE_SCHEMA_VERSION,
    PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN, PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN,
    PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN, PERSIST_MATERIALIZATION_REUSE_LEN, PersistBlobIndex,
    PersistBlobIndexEntry, PersistBlobIndexError, PersistBlobKey, PersistBlobLocation,
    PersistBlobPack, PersistBlobPackError, PersistBlobPackHeader, PersistBlobRecordHeader,
    PersistBlobStore, PersistCache, PersistError, PersistFileArtifactHydrationError,
    PersistFileArtifactIndexEntry, PersistFileArtifactIndexValue, PersistFileArtifactKey,
    PersistFileArtifactMaterialization, PersistLayout, PersistMaterialization,
    PersistPackFormatError, PersistParseArtifactMaterializationError,
};
pub use policy::{
    MaterializationCosts, MaterializationDecision, MaterializationReuse, MaterializationSignals,
    MemoizationClass, MemoizationDecision, MemoizationSignals, MemoizationSubject,
};
pub use runtime::{
    EvalCache, EvalCacheRuntime, ExpressionCacheability, ExpressionTraceObservation,
    ImpureInputTraceSource,
};
