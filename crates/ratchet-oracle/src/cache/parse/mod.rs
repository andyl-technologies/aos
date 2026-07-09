//! Content-addressed parse artifact cache.
//!
//! The parse cache is keyed only by deterministic inputs to frontend parsing:
//! source bytes, the evaluator schema version, and relevant parser flags. Entry
//! paths follow the RFC-0007 layout:
//!
//! ```text
//! $AOS_NIX_CACHE/parse/<blake3-key>/
//!   ir.bin
//!   resolved.bin
//!   symbols.bin
//!   facts.bin      # optional analysis fact sidecar
//!   meta.toml
//! ```
//!
//! The durable cache key is independent of path. Import/file-resolution
//! memoization sits above it and keys in-process reuse by canonical realpath
//! plus BLAKE3 content hash, allowing symlinked paths to share the same resolved
//! artifact while still reparsing changed files.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

use thiserror::Error;

use crate::cache::hashing::ParseCacheSourceHash;
use crate::cache::{DurableBlake3Hash, LoweredIrFingerprint, ParseFileContentHash};
use crate::compile::{
    CapturePlan, Cardinality, EffectClass, Escape, ExprFacts, FrameId, FrameInfo,
    IR_ANALYSIS_VERSION,
    InheritGroupId, SharedChainReason,
    InheritResolution, InheritSource, Ir, IrAnalysisError, IrAnalysisReport, IrArena, IrAttrPathId,
    IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData, IrDialectOp, IrError,
    IrFacts, IrId, IrInlineCacheSiteId, IrKind, IrNode, IrShape, IrShapeId, IrWithChain,
    ResolvedAst, ScopeError, ScopeTables, Strictness, Upvalue, WithChain, annotate_ir, resolve,
};
use crate::runtime::builtins::{BuiltinDirect, direct_builtin};
use crate::syntax::{
    AstArena, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind, ParseError, Span, Symbol,
    SymbolTable, UnaryOpKind, parse_bytes,
};
use aos_nix_dialect::nix_lower;

/// The schema version included in every parse-cache key and metadata file.
pub const PARSE_CACHE_SCHEMA_VERSION: u32 = 11;

const KEY_PERSONALIZATION: &[u8] = b"aos-nix-parse-cache-key-v1";
const LOWERED_IR_FINGERPRINT_DOMAIN: &[u8] = b"aos-nix-lowered-ir-fingerprint-v1";
const FLAG_ENCODING_VERSION: u8 = 1;
const IR_MAGIC: &[u8; 8] = b"AOSNIXIR";
const RESOLVED_MAGIC: &[u8; 8] = b"AOSNIXRS";
const SYMBOL_MAGIC: &[u8; 8] = b"AOSNIXSY";
const FACTS_MAGIC: &[u8; 8] = b"AOSNIXFT";
const BUNDLE_MAGIC: &[u8; 8] = b"AOSNIXAF";
const ARTIFACT_VERSION: u32 = 1;
static ATOMIC_WRITE_ID: AtomicU64 = AtomicU64::new(0);

/// Parser options that affect parse-cache identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseCacheFlags {
    /// Whether retained trivia is part of the parse artifact.
    pub retain_trivia: bool,
}

impl Default for ParseCacheFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl ParseCacheFlags {
    /// Creates parser flags matching the current evaluator frontend.
    pub const fn new() -> Self {
        Self {
            retain_trivia: true,
        }
    }

    fn update_hasher(self, hasher: &mut blake3::Hasher) {
        hasher.update(&[FLAG_ENCODING_VERSION]);
        hasher.update(&[u8::from(self.retain_trivia)]);
    }
}

/// A typed parse-cache source key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParseCacheKey(ParseCacheSourceHash);

impl ParseCacheKey {
    /// Computes a parse-cache key for source bytes.
    pub fn for_source(source: &[u8], schema_version: u32, flags: ParseCacheFlags) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEY_PERSONALIZATION);
        hasher.update(&schema_version.to_le_bytes());
        flags.update_hasher(&mut hasher);
        hasher.update(source);
        Self(ParseCacheSourceHash::from_durable_hash(
            DurableBlake3Hash::from_hasher(hasher),
        ))
    }

    /// Returns the underlying durable BLAKE3 digest.
    ///
    /// This is used at explicit persistent-format and leak-canary boundaries.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0.as_durable_hash()
    }

    /// Returns the lowercase hexadecimal cache-entry directory name.
    pub fn cache_dir_name(self) -> String {
        self.as_durable_hash().to_hex()
    }
}

impl fmt::Display for ParseCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.cache_dir_name())
    }
}

/// Computes a durable fingerprint for a lowered IR artifact and its symbols.
///
/// This hashes the same stable `ir.bin` and `symbols.bin` encodings that the
/// parse cache stores, salted with the parse-cache schema version. It is used
/// when callers need a source-independent identity for an already-lowered
/// expression.
///
/// # Errors
///
/// Returns [`ParseCacheError`] if the lowered IR or symbol-table artifact cannot
/// be encoded.
pub fn lowered_ir_fingerprint(ir: &Ir) -> Result<LoweredIrFingerprint, ParseCacheError> {
    let ir_bytes = encode_lowered_ir(ir)?;
    let symbol_bytes = encode_symbols(&ir.symbols)?;
    Ok(lowered_ir_artifact_fingerprint(&ir_bytes, &symbol_bytes))
}

fn lowered_ir_artifact_fingerprint(ir_bytes: &[u8], symbol_bytes: &[u8]) -> LoweredIrFingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOWERED_IR_FINGERPRINT_DOMAIN);
    hasher.update(&PARSE_CACHE_SCHEMA_VERSION.to_le_bytes());
    update_fingerprint_chunk(&mut hasher, &ir_bytes);
    update_fingerprint_chunk(&mut hasher, &symbol_bytes);
    LoweredIrFingerprint::from_durable_hash(DurableBlake3Hash::from_hasher(hasher))
}

fn update_fingerprint_chunk(hasher: &mut blake3::Hasher, chunk: &[u8]) {
    hasher.update(&(chunk.len() as u128).to_le_bytes());
    hasher.update(chunk);
}

/// A canonical import/file-resolution memo key.
///
/// The key combines the resolved realpath with the BLAKE3 hash of the bytes
/// read from that path. The realpath preserves Nix import identity semantics,
/// while the content hash makes edits observable without relying on mtimes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParseFileKey {
    realpath: PathBuf,
    content_hash: ParseFileContentHash,
}

impl ParseFileKey {
    /// Creates a file memo key from a canonical path and content hash.
    pub fn new(realpath: impl Into<PathBuf>, content_hash: ParseFileContentHash) -> Self {
        Self {
            realpath: realpath.into(),
            content_hash,
        }
    }

    /// Creates a file memo key by hashing source bytes with BLAKE3.
    pub fn for_source(realpath: impl Into<PathBuf>, source: &[u8]) -> Self {
        Self::new(realpath, ParseFileContentHash::for_source(source))
    }

    /// Returns the canonical path component of the key.
    pub fn realpath(&self) -> &Path {
        &self.realpath
    }

    /// Returns the typed BLAKE3 content hash.
    pub const fn content_hash(&self) -> ParseFileContentHash {
        self.content_hash
    }
}

/// An in-process memo table for parsed imports/files.
///
/// The table is deliberately layered over [`ParseCache`]: the durable cache
/// remains content-addressed by source bytes, while this table provides
/// Nix-compatible realpath identity and shares parse artifacts reached through
/// symlinks or other path-resolution indirection.
#[derive(Clone, Debug)]
pub struct FileParseMemo {
    cache: ParseCache,
    entries: BTreeMap<ParseFileKey, CachedParse>,
}

impl FileParseMemo {
    /// Creates an empty file memo table backed by `cache`.
    pub fn new(cache: ParseCache) -> Self {
        Self {
            cache,
            entries: BTreeMap::new(),
        }
    }

    /// Creates an empty file memo table backed by a parse cache at `root`.
    pub fn with_cache_root(root: impl Into<PathBuf>) -> Self {
        Self::new(ParseCache::new(root))
    }

    /// Returns the durable parse cache backing this file memo table.
    pub fn parse_cache(&self) -> &ParseCache {
        &self.cache
    }

    /// Returns the number of memoized realpath/content pairs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether this file memo table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clears all in-process file memo entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Loads a resolved parse artifact for a filesystem path.
    ///
    /// The path is canonicalized before bytes are read. The in-process memo key
    /// is `(canonical realpath, blake3(file bytes))`; cache misses delegate to
    /// [`ParseCache::load_or_parse_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the path cannot be canonicalized, the
    /// source file cannot be read, or parsing/scope resolution fails.
    pub fn load_or_parse_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<CachedFileParse, ParseCacheError> {
        let requested = path.as_ref();
        let realpath =
            fs::canonicalize(requested).map_err(|source| ParseCacheError::CanonicalizeSource {
                path: requested.to_path_buf(),
                source,
            })?;
        let source = fs::read(&realpath).map_err(|source| ParseCacheError::ReadSource {
            path: realpath.clone(),
            source,
        })?;
        let file_key = ParseFileKey::for_source(realpath.clone(), &source);
        if let Some(parsed) = self.entries.get(&file_key) {
            return Ok(CachedFileParse {
                file_key,
                parsed: parsed.clone(),
                memo_hit: true,
            });
        }

        let parsed = self
            .cache
            .load_or_parse_bytes(&source, Some(realpath.to_string_lossy().into_owned()))?;
        self.entries.insert(file_key.clone(), parsed.clone());
        Ok(CachedFileParse {
            file_key,
            parsed,
            memo_hit: false,
        })
    }
}

/// The result of [`FileParseMemo::load_or_parse_file`].
#[derive(Clone, Debug)]
pub struct CachedFileParse {
    /// The canonical realpath/content key used for in-process reuse.
    pub file_key: ParseFileKey,
    /// The durable content-addressed parse-cache result.
    ///
    /// Its [`CachedParse::hit`] flag describes the durable artifact lookup that
    /// produced this value, while [`Self::memo_hit`] describes this file-memo
    /// lookup.
    pub parsed: CachedParse,
    /// Whether the result came from the in-process file memo table.
    pub memo_hit: bool,
}

/// A parse-cache rooted at `$AOS_NIX_CACHE/parse`.
#[derive(Clone, Debug)]
pub struct ParseCache {
    root: PathBuf,
    schema_version: u32,
    flags: ParseCacheFlags,
}

impl ParseCache {
    /// Creates a parse cache with the current schema version and parser flags.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_schema(root, PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags::new())
    }

    /// Creates a parse cache with explicit identity parameters.
    pub fn with_schema(
        root: impl Into<PathBuf>,
        schema_version: u32,
        flags: ParseCacheFlags,
    ) -> Self {
        Self {
            root: root.into(),
            schema_version,
            flags,
        }
    }

    /// Returns the cache root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the schema version included in keys produced by this cache.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the parser flags included in keys produced by this cache.
    pub const fn flags(&self) -> ParseCacheFlags {
        self.flags
    }

    /// Computes this cache's key for source bytes.
    pub fn key_for_source(&self, source: &[u8]) -> ParseCacheKey {
        ParseCacheKey::for_source(source, self.schema_version, self.flags)
    }

    /// Returns the entry directory and file paths for a cache key.
    pub fn entry_for_key(&self, key: ParseCacheKey) -> ParseCacheEntry {
        ParseCacheEntry::new(self.root.join(key.cache_dir_name()))
    }

    /// Computes the cache key for source bytes and returns its entry paths.
    pub fn entry_for_source(&self, source: &[u8]) -> ParseCacheEntry {
        self.entry_for_key(self.key_for_source(source))
    }

    /// Loads a complete cached parse artifact for source bytes without parsing.
    ///
    /// Missing or incomplete entries return `Ok(None)`. Complete entries are
    /// decoded as resolved and lowered artifacts and returned as cache hits.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if a complete cache entry cannot be read or
    /// decoded.
    pub fn load_cached_bytes(&self, source: &[u8]) -> Result<Option<CachedParse>, ParseCacheError> {
        let key = self.key_for_source(source);
        let entry = self.entry_for_key(key);
        if !entry.is_complete() {
            return Ok(None);
        }
        let resolved = entry.read_resolved()?;
        let (ir, facts_current) = entry.read_ir()?;
        Ok(Some(CachedParse {
            key,
            entry,
            resolved,
            ir,
            hit: true,
            stored: true,
            facts_current,
        }))
    }

    /// Loads a resolved parse artifact from cache or parses and stores it.
    ///
    /// Cache misses and corrupt artifacts both fall back to parsing `source`.
    /// The optional `source_hint` is written only to diagnostic metadata; it is
    /// not part of the cache key.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] when parsing or scope resolution fails. Cache
    /// write failures are reported through [`CachedParse::stored`] rather than
    /// returned as errors, keeping the cache performance-only for evaluator
    /// callers.
    pub fn load_or_parse_bytes(
        &self,
        source: &[u8],
        source_hint: Option<String>,
    ) -> Result<CachedParse, ParseCacheError> {
        let key = self.key_for_source(source);
        let entry = self.entry_for_key(key);
        if let Ok(Some(cached)) = self.load_cached_bytes(source) {
            return Ok(cached);
        }

        let parsed = parse_bytes(source).map_err(|source| ParseCacheError::Parse { source })?;
        let resolved = resolve(parsed).map_err(|source| ParseCacheError::Scope { source })?;
        let cached_resolved = file_local_resolved(&resolved)?;
        let ir = nix_lower(cached_resolved.clone())
            .map_err(|source| ParseCacheError::LowerIr { source })?;
        let meta = ParseCacheMeta::new(self.schema_version, source_hint, 0, 0);
        let stored = entry.write_resolved(&resolved, &meta).is_ok();
        Ok(CachedParse {
            key,
            entry,
            resolved: cached_resolved,
            ir,
            hit: false,
            stored,
            facts_current: false,
        })
    }

    /// Loads or parses source bytes and refreshes analysis facts.
    ///
    /// This is an opt-in analysis entry point. It preserves the base parse
    /// cache's performance-only storage policy: mandatory artifact write
    /// failures are still reflected through [`CachedParse::stored`], and the
    /// refreshed `facts.bin` sidecar is attempted without failing the analyzed
    /// load.
    ///
    /// # Errors
    ///
    /// Returns [`ParseFactRefreshError`] when parsing, scope resolution, IR
    /// lowering, or analysis fails.
    pub fn load_or_parse_analyzed_bytes(
        &self,
        source: &[u8],
        source_hint: Option<String>,
    ) -> Result<CachedAnalyzedParse, ParseFactRefreshError> {
        let mut parsed = self.load_or_parse_bytes(source, source_hint)?;
        let analysis = parsed.refresh_facts()?;
        let facts_stored = parsed.entry.write_fact_sidecar(&parsed.ir).is_ok();
        Ok(CachedAnalyzedParse {
            parsed,
            analysis,
            facts_stored,
        })
    }
}

/// The result of [`ParseCache::load_or_parse_bytes`].
#[derive(Clone, Debug)]
pub struct CachedParse {
    /// The content-addressed key for the source bytes.
    pub key: ParseCacheKey,
    /// The cache entry used for this source.
    pub entry: ParseCacheEntry,
    /// The loaded or freshly parsed resolved AST.
    pub resolved: ResolvedAst,
    /// The loaded or freshly lowered evaluator IR.
    pub ir: Ir,
    /// Whether the artifact was loaded from cache.
    pub hit: bool,
    /// Whether a valid artifact is present in the cache after this operation.
    pub stored: bool,
    /// Whether [`Self::ir`] carries analysis facts produced by the current
    /// analysis pipeline version (loaded from a fingerprint-valid,
    /// version-current `facts.bin` sidecar or refreshed in this process), so
    /// re-analysis can be skipped.
    pub facts_current: bool,
}

impl CachedParse {
    /// Refreshes this parsed module's in-memory analysis facts.
    ///
    /// The analysis pipeline starts from conservative facts, so a failed refresh
    /// leaves [`Self::ir`] with conservative per-node facts.
    ///
    /// # Errors
    ///
    /// Returns [`ParseFactRefreshError`] if analysis rejects malformed IR.
    pub fn refresh_facts(&mut self) -> Result<IrAnalysisReport, ParseFactRefreshError> {
        let report =
            annotate_ir(&mut self.ir).map_err(|source| ParseFactRefreshError::Analyze { source })?;
        // Capture-plan distribution telemetry (RFC-0007 Phase 4 Chunk D):
        // per-module free-variable histogram for FLAT_CAPTURE_MAX_SLOTS
        // sizing. Debug-level so production evals pay one disabled check.
        tracing::debug!(
            target: "aos_nix::analysis::capture",
            lambda_sites = report.capture.lambda_sites,
            thunk_sites = report.capture.thunk_sites,
            flat_plans = report.capture.flat_plans,
            shared_chain_plans = report.capture.shared_chain_plans,
            max_free_vars = report.capture.max_free_vars,
            pure_silent_thunk_bodies = report.capture.pure_silent_thunk_bodies,
            free_var_histogram = ?report.capture.free_var_histogram,
            "capture-plan analysis report"
        );
        Ok(report)
    }

    /// Refreshes this parsed module's analysis facts and writes its sidecar.
    ///
    /// The in-memory IR is refreshed before the sidecar write. If the sidecar
    /// write fails, the refreshed facts remain available through [`Self::ir`]
    /// and the storage failure is returned to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ParseFactRefreshError`] if analysis rejects malformed IR or the
    /// refreshed fact sidecar cannot be written for this parse-cache entry.
    pub fn refresh_and_store_facts(&mut self) -> Result<IrAnalysisReport, ParseFactRefreshError> {
        let report = self.refresh_facts()?;
        self.facts_current = true;
        self.entry.write_fact_sidecar(&self.ir)?;
        Ok(report)
    }

    /// Ensures analysis facts are current, refreshing and storing on demand.
    ///
    /// This is the warm-path entry point: when the parse artifact was loaded
    /// with a fingerprint-valid `facts.bin` sidecar recording the current
    /// analysis version, the call returns `Ok(None)` without re-running any
    /// analysis or touching the sidecar. Otherwise the facts are refreshed
    /// in memory (making them current for this handle even if the sidecar
    /// write then fails) and persisted.
    ///
    /// # Errors
    ///
    /// Returns [`ParseFactRefreshError`] if analysis rejects malformed IR or
    /// the refreshed fact sidecar cannot be written for this entry.
    pub fn ensure_facts_current_and_stored(
        &mut self,
    ) -> Result<Option<IrAnalysisReport>, ParseFactRefreshError> {
        if self.facts_current {
            return Ok(None);
        }
        let report = self.refresh_facts()?;
        self.facts_current = true;
        self.entry.write_fact_sidecar(&self.ir)?;
        Ok(Some(report))
    }
}

/// The result of [`ParseCache::load_or_parse_analyzed_bytes`].
#[derive(Clone, Debug)]
pub struct CachedAnalyzedParse {
    /// The loaded or freshly parsed module with refreshed in-memory facts.
    pub parsed: CachedParse,
    /// The analysis report produced while refreshing facts.
    pub analysis: IrAnalysisReport,
    /// Whether the refreshed `facts.bin` sidecar was written successfully.
    pub facts_stored: bool,
}

fn encode_bundle_section(
    out: &mut Vec<u8>,
    bytes: &[u8],
    what: &'static str,
) -> Result<(), ParseCacheError> {
    write_len(out, bytes.len(), what)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_bundle_section(
    reader: &mut BinaryReader<'_>,
    what: &'static str,
) -> Result<Vec<u8>, String> {
    let len = reader.read_len(what)?;
    let bytes = reader.read_bytes(len)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| format!("{what} is too large"))?;
    out.extend_from_slice(bytes);
    Ok(out)
}

fn write_cache_file_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp_path = atomic_write_temp_path(path)?;
    let result = fs::write(&temp_path, bytes).and_then(|()| fs::rename(&temp_path, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn atomic_write_temp_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "parse-cache path has no file name",
        )
    })?;
    let id = ATOMIC_WRITE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".tmp-{}-{id}", std::process::id()));
    Ok(parent.join(temp_name))
}

fn push_toml_string(value: &str, out: &mut String) {
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if character.is_control() => {
                out.push_str(&format!("\\u{:04X}", character as u32));
            }
            character => out.push(character),
        }
    }
}

fn decode_meta_u32(
    table: &toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<u32, ParseCacheError> {
    let integer = table
        .get(field)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| ParseCacheError::DecodeMeta {
            message: format!("{field} must be an integer"),
        })?;
    u32::try_from(integer).map_err(|_| ParseCacheError::DecodeMeta {
        message: format!("{field} value {integer} is outside u32 range"),
    })
}

mod bundle;
mod codec;
mod entry;
mod error;
mod format;
mod meta;
mod remap;
mod validate;

// Re-export the child-module items into the module's own namespace so the
// `ParseCache`/`ParseCacheEntry`/`ParseCacheMeta` impls above (and the test
// module via `use super::*`) reach them by their original unqualified paths.
use codec::*;
use format::*;
use remap::*;
use validate::*;

// Public parse-cache types live in dedicated submodules but remain reachable as
// `crate::cache::parse::<Type>`, so the parent module's `pub use parse::{...}`
// and the sibling/test modules' `use super::*` resolve them unqualified.
pub use bundle::ParseArtifactBundle;
pub use entry::ParseCacheEntry;
pub use error::{ParseCacheError, ParseFactRefreshError};
pub use meta::ParseCacheMeta;

#[cfg(test)]
mod tests;
