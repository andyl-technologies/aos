//! Content-addressed evaluator caches.
//!
//! The cache layer starts with the frontend parse cache: a durable filesystem
//! layout keyed by source bytes, schema version, and parse flags. Binary IR
//! serialization plugs into this module once the lowered IR format exists.

pub mod parse;

pub use parse::{
    CachedParse, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheEntry, ParseCacheError,
    ParseCacheFlags, ParseCacheKey, ParseCacheMeta,
};
