//! Content-addressed evaluator caches.
//!
//! The cache layer starts with the frontend parse cache: a durable filesystem
//! layout keyed by source bytes, schema version, and parse flags, plus an
//! in-process import/file memo keyed by canonical realpath and file-content
//! hash.

pub mod cutoff;
pub mod hashing;
pub mod key;
pub mod parse;

pub use cutoff::{CutoffDecision, EarlyCutoff, ValueHash};
pub use hashing::{DurableBlake3Hash, HotXxh3Hash};
pub use key::{CacheExprIdentity, CacheKeyError, DemandCacheKey};
pub use parse::{
    CachedFileParse, CachedParse, FileParseMemo, PARSE_CACHE_SCHEMA_VERSION, ParseCache,
    ParseCacheEntry, ParseCacheError, ParseCacheFlags, ParseCacheKey, ParseCacheMeta, ParseFileKey,
};
