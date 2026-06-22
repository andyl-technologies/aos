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
    CachedFileParse, CachedParse, FileParseMemo, PARSE_CACHE_SCHEMA_VERSION, ParseCache,
    ParseCacheEntry, ParseCacheError, ParseCacheFlags, ParseCacheKey, ParseCacheMeta, ParseFileKey,
};
pub use persist::{
    PERSIST_CACHE_FORMAT, PERSIST_CACHE_SCHEMA_VERSION, PersistCache, PersistError, PersistLayout,
};
pub use policy::{
    MaterializationCosts, MaterializationDecision, MaterializationSignals, MemoizationClass,
    MemoizationDecision, MemoizationSignals, MemoizationSubject,
};
pub use runtime::{
    EvalCache, EvalCacheRuntime, ExpressionTraceObservation, ImpureInputTraceSource,
};
