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

use crate::cache::DurableBlake3Hash;
use crate::compile::{
    EffectClass, FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, Ir, IrArena,
    IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData, IrError,
    IrId, IrInlineCacheSiteId, IrKind, IrNode, IrShape, IrShapeId, IrWithChain, ResolvedAst,
    ScopeError, ScopeTables, Upvalue, WithChain, lower, resolve,
};
use crate::runtime::builtins::{BuiltinDirect, BuiltinEffect, direct_builtin};
use crate::syntax::{
    AstArena, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind, ParseError, Span, Symbol,
    SymbolTable, UnaryOpKind, parse_bytes,
};

/// The schema version included in every parse-cache key and metadata file.
pub const PARSE_CACHE_SCHEMA_VERSION: u32 = 6;

const KEY_PERSONALIZATION: &[u8] = b"aos-nix-parse-cache-key-v1";
const FLAG_ENCODING_VERSION: u8 = 1;
const IR_MAGIC: &[u8; 8] = b"AOSNIXIR";
const RESOLVED_MAGIC: &[u8; 8] = b"AOSNIXRS";
const SYMBOL_MAGIC: &[u8; 8] = b"AOSNIXSY";
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

/// A BLAKE3 parse-cache key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParseCacheKey(DurableBlake3Hash);

impl ParseCacheKey {
    /// Computes a parse-cache key for source bytes.
    pub fn for_source(source: &[u8], schema_version: u32, flags: ParseCacheFlags) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEY_PERSONALIZATION);
        hasher.update(&schema_version.to_le_bytes());
        flags.update_hasher(&mut hasher);
        hasher.update(source);
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Returns the raw 32-byte BLAKE3 digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0.as_bytes()
    }

    /// Returns the lowercase hexadecimal representation used as the directory
    /// name.
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }
}

impl fmt::Display for ParseCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// A canonical import/file-resolution memo key.
///
/// The key combines the resolved realpath with the BLAKE3 hash of the bytes
/// read from that path. The realpath preserves Nix import identity semantics,
/// while the content hash makes edits observable without relying on mtimes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParseFileKey {
    realpath: PathBuf,
    content_hash: DurableBlake3Hash,
}

impl ParseFileKey {
    /// Creates a file memo key from a canonical path and content hash.
    pub fn new(realpath: impl Into<PathBuf>, content_hash: DurableBlake3Hash) -> Self {
        Self {
            realpath: realpath.into(),
            content_hash,
        }
    }

    /// Creates a file memo key by hashing source bytes with BLAKE3.
    pub fn for_source(realpath: impl Into<PathBuf>, source: &[u8]) -> Self {
        Self::new(realpath, file_content_hash(source))
    }

    /// Returns the canonical path component of the key.
    pub fn realpath(&self) -> &Path {
        &self.realpath
    }

    /// Returns the typed BLAKE3 content hash.
    pub const fn content_hash(&self) -> DurableBlake3Hash {
        self.content_hash
    }

    /// Returns the lowercase hexadecimal content hash.
    pub fn content_hash_hex(&self) -> String {
        self.content_hash.to_hex()
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
        ParseCacheEntry::new(self.root.join(key.to_hex()))
    }

    /// Computes the cache key for source bytes and returns its entry paths.
    pub fn entry_for_source(&self, source: &[u8]) -> ParseCacheEntry {
        self.entry_for_key(self.key_for_source(source))
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
        if entry.is_complete() {
            if let Ok(resolved) = entry.read_resolved() {
                if let Ok(ir) = entry.read_ir() {
                    return Ok(CachedParse {
                        key,
                        entry,
                        resolved,
                        ir,
                        hit: true,
                        stored: true,
                    });
                }
            }
        }

        let parsed = parse_bytes(source).map_err(|source| ParseCacheError::Parse { source })?;
        let resolved = resolve(parsed).map_err(|source| ParseCacheError::Scope { source })?;
        let cached_resolved = file_local_resolved(&resolved)?;
        let ir =
            lower(cached_resolved.clone()).map_err(|source| ParseCacheError::LowerIr { source })?;
        let meta = ParseCacheMeta::new(self.schema_version, source_hint, 0, 0);
        let stored = entry.write_resolved(&resolved, &meta).is_ok();
        Ok(CachedParse {
            key,
            entry,
            resolved: cached_resolved,
            ir,
            hit: false,
            stored,
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
}

/// Raw bytes for one complete parse-cache artifact bundle.
///
/// The bundle frames the same payloads that [`ParseCacheEntry`] stores as
/// separate files: `resolved.bin`, `ir.bin`, `symbols.bin`, and `meta.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseArtifactBundle {
    resolved: Vec<u8>,
    ir: Vec<u8>,
    symbols: Vec<u8>,
    meta_toml: Vec<u8>,
}

impl ParseArtifactBundle {
    /// Creates a bundle from raw parse-cache artifact bytes.
    pub fn new(
        resolved: impl Into<Vec<u8>>,
        ir: impl Into<Vec<u8>>,
        symbols: impl Into<Vec<u8>>,
        meta_toml: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            resolved: resolved.into(),
            ir: ir.into(),
            symbols: symbols.into(),
            meta_toml: meta_toml.into(),
        }
    }

    /// Returns the serialized resolved AST bytes.
    pub fn resolved_bytes(&self) -> &[u8] {
        &self.resolved
    }

    /// Returns the serialized lowered IR bytes.
    pub fn ir_bytes(&self) -> &[u8] {
        &self.ir
    }

    /// Returns the file-local symbol table bytes.
    pub fn symbols_bytes(&self) -> &[u8] {
        &self.symbols
    }

    /// Returns the diagnostic metadata TOML bytes.
    pub fn meta_toml_bytes(&self) -> &[u8] {
        &self.meta_toml
    }

    /// Decodes the bundled diagnostic metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if `meta.toml` is not UTF-8 or does not
    /// match the parse-cache metadata schema.
    pub fn decode_meta(&self) -> Result<ParseCacheMeta, ParseCacheError> {
        let text =
            std::str::from_utf8(&self.meta_toml).map_err(|source| ParseCacheError::DecodeMeta {
                message: format!("metadata is not UTF-8: {source}"),
            })?;
        ParseCacheMeta::from_toml(text)
    }

    /// Encodes this bundle as one stable little-endian payload.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if any section length does not fit in the
    /// bundle's fixed `u32` length fields.
    pub fn encode(&self) -> Result<Vec<u8>, ParseCacheError> {
        let mut out = Vec::new();
        out.extend_from_slice(BUNDLE_MAGIC);
        write_u32(&mut out, ARTIFACT_VERSION);
        encode_bundle_section(&mut out, &self.resolved, "resolved artifact byte count")?;
        encode_bundle_section(&mut out, &self.ir, "IR artifact byte count")?;
        encode_bundle_section(&mut out, &self.symbols, "symbol artifact byte count")?;
        encode_bundle_section(&mut out, &self.meta_toml, "metadata byte count")?;
        Ok(out)
    }

    /// Decodes one stable parse-cache artifact bundle payload.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the bundle has invalid magic/version
    /// metadata, truncated sections, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ParseCacheError> {
        let mut reader = BinaryReader::new(bytes);
        reader
            .expect_magic(BUNDLE_MAGIC)
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        let version = reader
            .read_u32()
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        if version != ARTIFACT_VERSION {
            return Err(ParseCacheError::DecodeArtifactBundle {
                message: format!("unsupported parse artifact bundle version {version}"),
            });
        }
        let resolved = decode_bundle_section(&mut reader, "resolved artifact byte count")
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        let ir = decode_bundle_section(&mut reader, "IR artifact byte count")
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        let symbols = decode_bundle_section(&mut reader, "symbol artifact byte count")
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        let meta_toml = decode_bundle_section(&mut reader, "metadata byte count")
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        reader
            .expect_eof()
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        Ok(Self {
            resolved,
            ir,
            symbols,
            meta_toml,
        })
    }
}

/// Filesystem paths for one parse-cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseCacheEntry {
    dir: PathBuf,
}

impl ParseCacheEntry {
    /// Creates an entry from its directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Returns the entry directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the serialized IR arena path.
    pub fn ir_path(&self) -> PathBuf {
        self.dir.join("ir.bin")
    }

    /// Returns the serialized resolved frontend artifact path.
    pub fn resolved_path(&self) -> PathBuf {
        self.dir.join("resolved.bin")
    }

    /// Returns the file-local symbol table path.
    pub fn symbols_path(&self) -> PathBuf {
        self.dir.join("symbols.bin")
    }

    /// Returns the diagnostic metadata path.
    pub fn meta_path(&self) -> PathBuf {
        self.dir.join("meta.toml")
    }

    /// Returns whether all mandatory cache-entry files exist.
    pub fn is_complete(&self) -> bool {
        self.ir_path().is_file()
            && self.resolved_path().is_file()
            && self.symbols_path().is_file()
            && self.meta_path().is_file()
    }

    /// Creates the entry directory when it is missing.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the directory cannot be created.
    pub fn ensure_dir(&self) -> Result<(), ParseCacheError> {
        fs::create_dir_all(&self.dir).map_err(|source| ParseCacheError::CreateDir {
            path: self.dir.clone(),
            source,
        })
    }

    /// Writes diagnostic metadata for this cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the entry directory cannot be created or
    /// the metadata file cannot be written.
    pub fn write_meta(&self, meta: &ParseCacheMeta) -> Result<(), ParseCacheError> {
        self.ensure_dir()?;
        let path = self.meta_path();
        let toml = meta.to_toml();
        write_cache_file_atomic(&path, toml.as_bytes())
            .map_err(|source| ParseCacheError::WriteMeta { path, source })
    }

    /// Writes the serialized resolved arena, file-local symbols, and metadata.
    ///
    /// Symbol ids are rewritten into a deterministic file-local table before
    /// `resolved.bin`, `ir.bin`, and `symbols.bin` are written, so artifacts do
    /// not inherit process-global interner allocation order. Diagnostic node and
    /// symbol counts are derived from the lowered IR artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the entry directory cannot be created, the
    /// resolved artifact cannot be encoded, or any output file cannot be
    /// written.
    pub fn write_resolved(
        &self,
        resolved: &ResolvedAst,
        meta: &ParseCacheMeta,
    ) -> Result<(), ParseCacheError> {
        self.ensure_dir()?;
        let resolved = file_local_resolved(resolved)?;
        let ir = lower(resolved.clone()).map_err(|source| ParseCacheError::LowerIr { source })?;
        let meta = ParseCacheMeta::for_serialized_resolved(
            meta.schema_version,
            meta.source_hint.clone(),
            &resolved,
            &ir,
        )?;
        let ir_path = self.ir_path();
        let resolved_path = self.resolved_path();
        let symbols_path = self.symbols_path();
        let meta_path = self.meta_path();
        let resolved_bytes = encode_resolved_ir(&resolved)?;
        let ir_bytes = encode_lowered_ir(&ir)?;
        let symbols_bytes = encode_symbols(&resolved.symbols)?;
        let meta_toml = meta.to_toml();

        let _ = fs::remove_file(&meta_path);
        write_cache_file_atomic(&resolved_path, &resolved_bytes).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: resolved_path,
                source,
            }
        })?;
        write_cache_file_atomic(&ir_path, &ir_bytes).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: ir_path,
                source,
            }
        })?;
        write_cache_file_atomic(&symbols_path, &symbols_bytes).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: symbols_path,
                source,
            }
        })?;
        write_cache_file_atomic(&meta_path, meta_toml.as_bytes()).map_err(|source| {
            ParseCacheError::WriteMeta {
                path: meta_path,
                source,
            }
        })
    }

    /// Reads the raw bytes for a complete parse-cache artifact bundle.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if any mandatory artifact file cannot be
    /// read. The returned bundle is raw bytes; callers that need semantic
    /// validation should decode the individual sections.
    pub fn read_artifact_bundle(&self) -> Result<ParseArtifactBundle, ParseCacheError> {
        let resolved_path = self.resolved_path();
        let ir_path = self.ir_path();
        let symbols_path = self.symbols_path();
        let meta_path = self.meta_path();
        let resolved =
            fs::read(&resolved_path).map_err(|source| ParseCacheError::ReadArtifact {
                path: resolved_path,
                source,
            })?;
        let ir = fs::read(&ir_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: ir_path,
            source,
        })?;
        let symbols = fs::read(&symbols_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: symbols_path,
            source,
        })?;
        let meta_toml = fs::read(&meta_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: meta_path,
            source,
        })?;
        Ok(ParseArtifactBundle::new(resolved, ir, symbols, meta_toml))
    }

    /// Writes a raw parse-cache artifact bundle into this entry.
    ///
    /// The metadata file is removed before payload files are written and
    /// rewritten last, so incomplete bundle hydration does not look like a
    /// complete cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the entry directory cannot be created or
    /// any bundled artifact file cannot be written.
    pub fn write_artifact_bundle(
        &self,
        bundle: &ParseArtifactBundle,
    ) -> Result<(), ParseCacheError> {
        self.ensure_dir()?;
        let resolved_path = self.resolved_path();
        let ir_path = self.ir_path();
        let symbols_path = self.symbols_path();
        let meta_path = self.meta_path();

        let _ = fs::remove_file(&meta_path);
        write_cache_file_atomic(&resolved_path, bundle.resolved_bytes()).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: resolved_path,
                source,
            }
        })?;
        write_cache_file_atomic(&ir_path, bundle.ir_bytes()).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: ir_path,
                source,
            }
        })?;
        write_cache_file_atomic(&symbols_path, bundle.symbols_bytes()).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: symbols_path,
                source,
            }
        })?;
        write_cache_file_atomic(&meta_path, bundle.meta_toml_bytes()).map_err(|source| {
            ParseCacheError::WriteMeta {
                path: meta_path,
                source,
            }
        })
    }

    /// Reads a resolved AST artifact from this cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if `resolved.bin` or `symbols.bin` cannot be
    /// read or decoded.
    pub fn read_resolved(&self) -> Result<ResolvedAst, ParseCacheError> {
        let resolved_path = self.resolved_path();
        let symbols_path = self.symbols_path();
        let resolved =
            fs::read(&resolved_path).map_err(|source| ParseCacheError::ReadArtifact {
                path: resolved_path.clone(),
                source,
            })?;
        let symbols = fs::read(&symbols_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: symbols_path.clone(),
            source,
        })?;
        let symbols =
            decode_symbols(&symbols).map_err(|message| ParseCacheError::DecodeArtifact {
                path: symbols_path,
                message,
            })?;
        decode_resolved_ir(&resolved, symbols).map_err(|message| ParseCacheError::DecodeArtifact {
            path: resolved_path,
            message,
        })
    }

    /// Reads a lowered IR artifact from this cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if `ir.bin` or `symbols.bin` cannot be read
    /// or decoded.
    fn read_ir(&self) -> Result<Ir, ParseCacheError> {
        let ir_path = self.ir_path();
        let symbols_path = self.symbols_path();
        let ir = fs::read(&ir_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: ir_path.clone(),
            source,
        })?;
        let symbols = fs::read(&symbols_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: symbols_path.clone(),
            source,
        })?;
        let symbols =
            decode_symbols(&symbols).map_err(|message| ParseCacheError::DecodeArtifact {
                path: symbols_path,
                message,
            })?;
        decode_lowered_ir(&ir, symbols).map_err(|message| ParseCacheError::DecodeArtifact {
            path: ir_path,
            message,
        })
    }
}

/// Diagnostic metadata written beside a parse-cache artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseCacheMeta {
    /// The schema version used to produce the cache artifact.
    pub schema_version: u32,
    /// A human-facing source path hint. It is never part of cache identity.
    pub source_hint: Option<String>,
    /// Number of lowered IR arena nodes in the serialized artifact.
    pub node_count: u32,
    /// Number of file-local symbols in the serialized artifact.
    pub symbol_count: u32,
}

impl ParseCacheMeta {
    /// Creates diagnostic metadata for one parse-cache artifact.
    pub fn new(
        schema_version: u32,
        source_hint: Option<String>,
        node_count: u32,
        symbol_count: u32,
    ) -> Self {
        Self {
            schema_version,
            source_hint,
            node_count,
            symbol_count,
        }
    }

    /// Creates metadata for a resolved AST artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the arena node count or symbol count does
    /// not fit in the metadata's `u32` fields.
    pub fn for_resolved(
        schema_version: u32,
        source_hint: Option<String>,
        resolved: &ResolvedAst,
    ) -> Result<Self, ParseCacheError> {
        let resolved = file_local_resolved(resolved)?;
        let ir = lower(resolved.clone()).map_err(|source| ParseCacheError::LowerIr { source })?;
        Self::for_serialized_resolved(schema_version, source_hint, &resolved, &ir)
    }

    fn for_serialized_resolved(
        schema_version: u32,
        source_hint: Option<String>,
        resolved: &ResolvedAst,
        ir: &Ir,
    ) -> Result<Self, ParseCacheError> {
        let node_count = u32::try_from(ir.arena.nodes().len())
            .map_err(|_| ParseCacheError::EncodeArtifact("node count exceeds u32".to_owned()))?;
        let symbol_count = u32::try_from(resolved.symbols.len())
            .map_err(|_| ParseCacheError::EncodeArtifact("symbol count exceeds u32".to_owned()))?;
        Ok(Self::new(
            schema_version,
            source_hint,
            node_count,
            symbol_count,
        ))
    }

    /// Formats this metadata as TOML.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("schema_version = {}\n", self.schema_version));
        if let Some(source_hint) = &self.source_hint {
            out.push_str("source_hint = \"");
            push_toml_string(source_hint, &mut out);
            out.push_str("\"\n");
        }
        out.push_str(&format!("node_count = {}\n", self.node_count));
        out.push_str(&format!("symbol_count = {}\n", self.symbol_count));
        out
    }

    /// Parses diagnostic metadata from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the TOML is malformed, required fields
    /// are missing, fields have the wrong type, or integer fields do not fit in
    /// `u32`.
    pub fn from_toml(text: &str) -> Result<Self, ParseCacheError> {
        let value = text
            .parse::<toml::Value>()
            .map_err(|source| ParseCacheError::DecodeMeta {
                message: source.to_string(),
            })?;
        let table = value
            .as_table()
            .ok_or_else(|| ParseCacheError::DecodeMeta {
                message: "metadata root is not a table".to_owned(),
            })?;
        let schema_version = decode_meta_u32(table, "schema_version")?;
        let node_count = decode_meta_u32(table, "node_count")?;
        let symbol_count = decode_meta_u32(table, "symbol_count")?;
        let source_hint = match table.get("source_hint") {
            Some(value) => {
                let hint = value.as_str().ok_or_else(|| ParseCacheError::DecodeMeta {
                    message: "source_hint must be a string".to_owned(),
                })?;
                Some(hint.to_owned())
            }
            None => None,
        };
        Ok(Self::new(
            schema_version,
            source_hint,
            node_count,
            symbol_count,
        ))
    }
}

/// A parse-cache or file-memoization failure.
#[derive(Debug, Error)]
pub enum ParseCacheError {
    /// Source bytes could not be parsed.
    #[error("failed to parse source for parse cache")]
    Parse {
        /// The parser failure.
        source: ParseError,
    },
    /// A parsed AST could not be scope-resolved.
    #[error("failed to resolve source for parse cache")]
    Scope {
        /// The scope-resolution failure.
        source: ScopeError,
    },
    /// A scope-resolved artifact could not be lowered to IR.
    #[error("failed to lower source for parse cache")]
    LowerIr {
        /// The IR lowering failure.
        source: IrError,
    },
    /// A source path could not be canonicalized for file memoization.
    #[error("failed to canonicalize source path {path:?}")]
    CanonicalizeSource {
        /// The requested source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A canonicalized source file could not be read for file memoization.
    #[error("failed to read source file {path:?}")]
    ReadSource {
        /// The canonical source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The cache entry directory could not be created.
    #[error("failed to create parse-cache directory {path:?}")]
    CreateDir {
        /// The directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The diagnostic metadata file could not be written.
    #[error("failed to write parse-cache metadata {path:?}")]
    WriteMeta {
        /// The metadata file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A binary cache artifact could not be written.
    #[error("failed to write parse-cache artifact {path:?}")]
    WriteArtifact {
        /// The artifact file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A binary cache artifact could not be read.
    #[error("failed to read parse-cache artifact {path:?}")]
    ReadArtifact {
        /// The artifact file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A binary cache artifact could not be decoded.
    #[error("failed to decode parse-cache artifact {path:?}: {message}")]
    DecodeArtifact {
        /// The artifact file path.
        path: PathBuf,
        /// The decode failure.
        message: String,
    },
    /// A raw parse-cache artifact bundle could not be decoded.
    #[error("failed to decode parse-cache artifact bundle: {message}")]
    DecodeArtifactBundle {
        /// The decode failure.
        message: String,
    },
    /// Parse-cache diagnostic metadata could not be decoded.
    #[error("failed to decode parse-cache metadata: {message}")]
    DecodeMeta {
        /// The decode failure.
        message: String,
    },
    /// A resolved artifact could not be encoded.
    #[error("failed to encode parse-cache artifact: {0}")]
    EncodeArtifact(String),
}

fn file_content_hash(source: &[u8]) -> DurableBlake3Hash {
    DurableBlake3Hash::for_bytes(source)
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

mod codec;
mod format;
mod remap;
mod validate;

// Re-export the child-module items into the module's own namespace so the
// `ParseCache`/`ParseCacheEntry`/`ParseCacheMeta` impls above (and the test
// module via `use super::*`) reach them by their original unqualified paths.
use codec::*;
use format::*;
use remap::*;
use validate::*;

#[cfg(test)]
mod tests;
