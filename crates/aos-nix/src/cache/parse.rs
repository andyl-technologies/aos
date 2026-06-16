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
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::compile::{
    EffectClass, FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, Ir, IrArena,
    IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData, IrError,
    IrId, IrInlineCacheSiteId, IrKind, IrNode, IrShape, IrShapeId, IrWithChain, ResolvedAst,
    ScopeError, ScopeTables, Upvalue, WithChain, lower, resolve,
};
use crate::syntax::{
    AstArena, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind, ParseError, Span, Symbol,
    SymbolTable, UnaryOpKind, parse_bytes,
};

/// The schema version included in every parse-cache key and metadata file.
pub const PARSE_CACHE_SCHEMA_VERSION: u32 = 4;

const KEY_PERSONALIZATION: &[u8] = b"aos-nix-parse-cache-key-v1";
const FLAG_ENCODING_VERSION: u8 = 1;
const IR_MAGIC: &[u8; 8] = b"AOSNIXIR";
const RESOLVED_MAGIC: &[u8; 8] = b"AOSNIXRS";
const SYMBOL_MAGIC: &[u8; 8] = b"AOSNIXSY";
const ARTIFACT_VERSION: u32 = 1;

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
pub struct ParseCacheKey([u8; 32]);

impl ParseCacheKey {
    /// Computes a parse-cache key for source bytes.
    pub fn for_source(source: &[u8], schema_version: u32, flags: ParseCacheFlags) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEY_PERSONALIZATION);
        hasher.update(&schema_version.to_le_bytes());
        flags.update_hasher(&mut hasher);
        hasher.update(source);
        Self(*hasher.finalize().as_bytes())
    }

    /// Returns the raw 32-byte BLAKE3 digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the lowercase hexadecimal representation used as the directory
    /// name.
    pub fn to_hex(self) -> String {
        blake3::Hash::from(self.0).to_hex().to_string()
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
    content_hash: [u8; 32],
}

impl ParseFileKey {
    /// Creates a file memo key from a canonical path and content hash.
    pub fn new(realpath: impl Into<PathBuf>, content_hash: [u8; 32]) -> Self {
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

    /// Returns the raw 32-byte BLAKE3 content hash.
    pub const fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }

    /// Returns the lowercase hexadecimal content hash.
    pub fn content_hash_hex(&self) -> String {
        blake3::Hash::from(self.content_hash).to_hex().to_string()
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
                    if let Ok(expected_ir) = lower(resolved.clone()) {
                        if lowered_ir_matches(&ir, &expected_ir) {
                            return Ok(CachedParse {
                                key,
                                entry,
                                resolved,
                                hit: true,
                                stored: true,
                            });
                        }
                    }
                }
            }
        }

        let parsed = parse_bytes(source).map_err(|source| ParseCacheError::Parse { source })?;
        let resolved = resolve(parsed).map_err(|source| ParseCacheError::Scope { source })?;
        let meta = ParseCacheMeta::new(self.schema_version, source_hint, 0, 0);
        let stored = entry.write_resolved(&resolved, &meta).is_ok();
        Ok(CachedParse {
            key,
            entry,
            resolved,
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
    /// Whether the artifact was loaded from cache.
    pub hit: bool,
    /// Whether a valid artifact is present in the cache after this operation.
    pub stored: bool,
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
        fs::write(&path, meta.to_toml())
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
        fs::write(&resolved_path, encode_resolved_ir(&resolved)?).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: resolved_path,
                source,
            }
        })?;
        fs::write(&ir_path, encode_lowered_ir(&ir)?).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: ir_path,
                source,
            }
        })?;
        fs::write(&symbols_path, encode_symbols(&resolved.symbols)?).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: symbols_path,
                source,
            }
        })?;
        self.write_meta(&meta)
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
    /// A resolved artifact could not be encoded.
    #[error("failed to encode parse-cache artifact: {0}")]
    EncodeArtifact(String),
}

fn file_content_hash(source: &[u8]) -> [u8; 32] {
    *blake3::hash(source).as_bytes()
}

fn file_local_resolved(resolved: &ResolvedAst) -> Result<ResolvedAst, ParseCacheError> {
    let mut remapper = SymbolRemapper::new();
    let mut nodes = Vec::with_capacity(resolved.arena.nodes().len());
    for node in resolved.arena.nodes() {
        nodes.push(Node::new(
            node.kind,
            node.span,
            remapper.remap_node_data(&resolved.symbols, node.data)?,
        ));
    }

    let mut inherit_resolutions = Vec::with_capacity(resolved.scopes.inherit_resolutions().len());
    for inherit in resolved.scopes.inherit_resolutions() {
        let mut sources = Vec::with_capacity(inherit.sources.len());
        for source in inherit.sources.as_ref() {
            sources.push(InheritSource {
                target: remapper.local_symbol(&resolved.symbols, source.target)?,
                source: source.source,
            });
        }
        inherit_resolutions.push(InheritResolution {
            from: inherit.from,
            sources: sources.into_boxed_slice(),
        });
    }

    Ok(ResolvedAst {
        root: resolved.root,
        arena: AstArena::from_raw_parts(nodes, resolved.arena.child_pool().to_vec()),
        symbols: remapper.symbols,
        scopes: ScopeTables::from_raw_parts(
            resolved.scopes.frames().to_vec(),
            resolved.scopes.node_frames().to_vec(),
            resolved.scopes.with_chains().to_vec(),
            inherit_resolutions,
            resolved.scopes.node_inherits().to_vec(),
        ),
    })
}

struct SymbolRemapper {
    symbols: SymbolTable,
    by_old: BTreeMap<Symbol, Symbol>,
}

impl SymbolRemapper {
    fn new() -> Self {
        Self {
            symbols: SymbolTable::new(),
            by_old: BTreeMap::new(),
        }
    }

    fn local_symbol(
        &mut self,
        source_symbols: &SymbolTable,
        symbol: Symbol,
    ) -> Result<Symbol, ParseCacheError> {
        if let Some(local) = self.by_old.get(&symbol) {
            return Ok(*local);
        }

        let bytes = source_symbols.resolve(symbol).ok_or_else(|| {
            ParseCacheError::EncodeArtifact(
                "symbol id out of range before serialization".to_owned(),
            )
        })?;
        let local = self.symbols.intern(bytes).map_err(|error| {
            ParseCacheError::EncodeArtifact(format!(
                "failed to build file-local symbol table: {error}"
            ))
        })?;
        self.by_old.insert(symbol, local);
        Ok(local)
    }

    fn remap_node_data(
        &mut self,
        source_symbols: &SymbolTable,
        data: NodeData,
    ) -> Result<NodeData, ParseCacheError> {
        match data {
            NodeData::Symbol(symbol) => {
                Ok(NodeData::Symbol(self.local_symbol(source_symbols, symbol)?))
            }
            NodeData::FormalSet {
                formals,
                ellipsis,
                alias,
            } => Ok(NodeData::FormalSet {
                formals,
                ellipsis,
                alias: alias
                    .map(|symbol| self.local_symbol(source_symbols, symbol))
                    .transpose()?,
            }),
            NodeData::Formal { name, default } => Ok(NodeData::Formal {
                name: self.local_symbol(source_symbols, name)?,
                default,
            }),
            NodeData::WithVar { symbol, chain } => Ok(NodeData::WithVar {
                symbol: self.local_symbol(source_symbols, symbol)?,
                chain,
            }),
            other => Ok(other),
        }
    }
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

fn encode_resolved_ir(resolved: &ResolvedAst) -> Result<Vec<u8>, ParseCacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(RESOLVED_MAGIC);
    write_u32(&mut out, ARTIFACT_VERSION);
    write_u32(&mut out, resolved.root.as_u32());
    write_len(&mut out, resolved.arena.nodes().len(), "node count")?;
    write_len(&mut out, resolved.arena.child_pool().len(), "child count")?;
    write_len(&mut out, resolved.scopes.frames().len(), "frame count")?;
    write_len(
        &mut out,
        resolved.scopes.node_frames().len(),
        "node-frame count",
    )?;
    write_len(
        &mut out,
        resolved.scopes.with_chains().len(),
        "with-chain count",
    )?;
    write_len(
        &mut out,
        resolved.scopes.inherit_resolutions().len(),
        "inherit-resolution count",
    )?;
    write_len(
        &mut out,
        resolved.scopes.node_inherits().len(),
        "node-inherit count",
    )?;

    for node in resolved.arena.nodes() {
        encode_node(&mut out, *node);
    }
    for child in resolved.arena.child_pool() {
        write_u32(&mut out, child.as_u32());
    }
    for frame in resolved.scopes.frames() {
        encode_frame(&mut out, frame)?;
    }
    for frame in resolved.scopes.node_frames() {
        encode_option_u32(&mut out, frame.map(FrameId::as_u32));
    }
    for chain in resolved.scopes.with_chains() {
        write_len(&mut out, chain.scopes.len(), "with-chain scope count")?;
        for scope in chain.scopes.as_ref() {
            write_u32(&mut out, scope.as_u32());
        }
    }
    for inherit in resolved.scopes.inherit_resolutions() {
        encode_option_u32(&mut out, inherit.from.map(NodeId::as_u32));
        write_len(&mut out, inherit.sources.len(), "inherit source count")?;
        for source in inherit.sources.as_ref() {
            write_u32(&mut out, source.target.as_u32());
            write_u32(&mut out, source.source.as_u32());
        }
    }
    for inherit in resolved.scopes.node_inherits() {
        encode_option_u32(&mut out, inherit.map(InheritGroupId::as_u32));
    }
    Ok(out)
}

fn decode_resolved_ir(bytes: &[u8], symbols: SymbolTable) -> Result<ResolvedAst, String> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_magic(RESOLVED_MAGIC)?;
    let version = reader.read_u32()?;
    if version != ARTIFACT_VERSION {
        return Err(format!("unsupported IR artifact version {version}"));
    }
    let root = NodeId::new(reader.read_u32()?);
    let node_count = reader.read_len("node count")?;
    let child_count = reader.read_len("child count")?;
    let frame_count = reader.read_len("frame count")?;
    let node_frame_count = reader.read_len("node-frame count")?;
    let with_chain_count = reader.read_len("with-chain count")?;
    let inherit_resolution_count = reader.read_len("inherit-resolution count")?;
    let node_inherit_count = reader.read_len("node-inherit count")?;

    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(decode_node(&mut reader)?);
    }
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        children.push(NodeId::new(reader.read_u32()?));
    }
    let mut frames = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        frames.push(decode_frame(&mut reader)?);
    }
    let mut node_frames = Vec::with_capacity(node_frame_count);
    for _ in 0..node_frame_count {
        node_frames.push(reader.read_option_u32()?.map(FrameId::new));
    }
    let mut with_chains = Vec::with_capacity(with_chain_count);
    for _ in 0..with_chain_count {
        let scope_count = reader.read_len("with-chain scope count")?;
        let mut scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            scopes.push(NodeId::new(reader.read_u32()?));
        }
        with_chains.push(WithChain {
            scopes: scopes.into_boxed_slice(),
        });
    }
    let mut inherit_resolutions = Vec::with_capacity(inherit_resolution_count);
    for _ in 0..inherit_resolution_count {
        let from = reader.read_option_u32()?.map(NodeId::new);
        let source_count = reader.read_len("inherit source count")?;
        let mut sources = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            sources.push(InheritSource {
                target: Symbol::new(reader.read_u32()?),
                source: NodeId::new(reader.read_u32()?),
            });
        }
        inherit_resolutions.push(InheritResolution {
            from,
            sources: sources.into_boxed_slice(),
        });
    }
    let mut node_inherits = Vec::with_capacity(node_inherit_count);
    for _ in 0..node_inherit_count {
        node_inherits.push(reader.read_option_u32()?.map(InheritGroupId::new));
    }
    reader.expect_eof()?;

    if node_frames.len() != nodes.len() {
        return Err("node-frame side table length does not match node count".to_owned());
    }
    if node_inherits.len() != nodes.len() {
        return Err("node-inherit side table length does not match node count".to_owned());
    }

    let resolved = ResolvedAst {
        root,
        arena: AstArena::from_raw_parts(nodes, children),
        symbols,
        scopes: ScopeTables::from_raw_parts(
            frames,
            node_frames,
            with_chains,
            inherit_resolutions,
            node_inherits,
        ),
    };
    validate_resolved_artifact(&resolved)?;
    Ok(resolved)
}

fn encode_lowered_ir(ir: &Ir) -> Result<Vec<u8>, ParseCacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(IR_MAGIC);
    write_u32(&mut out, ARTIFACT_VERSION);
    write_u32(&mut out, ir.root.as_u32());
    write_len(&mut out, ir.arena.nodes().len(), "IR node count")?;
    write_len(&mut out, ir.arena.child_pool().len(), "IR child count")?;
    write_len(&mut out, ir.frames.len(), "IR frame count")?;
    write_len(&mut out, ir.with_chains.len(), "IR with-chain count")?;
    write_len(&mut out, ir.attr_paths.len(), "IR attr-path count")?;
    write_len(&mut out, ir.bindings.len(), "IR binding count")?;
    write_len(&mut out, ir.shapes.len(), "IR shape count")?;

    for node in ir.arena.nodes() {
        encode_ir_node(&mut out, *node);
    }
    for child in ir.arena.child_pool() {
        write_u32(&mut out, child.as_u32());
    }
    for frame in ir.frames.as_ref() {
        encode_frame(&mut out, frame)?;
    }
    for chain in ir.with_chains.as_ref() {
        write_len(&mut out, chain.scopes.len(), "IR with-chain scope count")?;
        for scope in chain.scopes.as_ref() {
            write_u32(&mut out, scope.as_u32());
        }
    }
    for path in ir.attr_paths.as_ref() {
        write_len(&mut out, path.len(), "IR attr-path segment count")?;
        for segment in path.as_ref() {
            encode_ir_attr_path_segment(&mut out, *segment);
        }
    }
    for binding in ir.bindings.as_ref() {
        encode_ir_attr_path_segment(&mut out, binding.key);
        write_u32(&mut out, binding.value.as_u32());
    }
    for shape in ir.shapes.as_ref() {
        write_len(&mut out, shape.keys.len(), "IR shape key count")?;
        for key in shape.keys.as_ref() {
            write_u32(&mut out, key.as_u32());
        }
    }
    Ok(out)
}

fn decode_lowered_ir(bytes: &[u8], symbols: SymbolTable) -> Result<Ir, String> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_magic(IR_MAGIC)?;
    let version = reader.read_u32()?;
    if version != ARTIFACT_VERSION {
        return Err(format!("unsupported lowered IR artifact version {version}"));
    }
    let root = IrId::new(reader.read_u32()?);
    let node_count = reader.read_len("IR node count")?;
    let child_count = reader.read_len("IR child count")?;
    let frame_count = reader.read_len("IR frame count")?;
    let with_chain_count = reader.read_len("IR with-chain count")?;
    let attr_path_count = reader.read_len("IR attr-path count")?;
    let binding_count = reader.read_len("IR binding count")?;
    let shape_count = reader.read_len("IR shape count")?;

    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(decode_ir_node(&mut reader)?);
    }
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        children.push(IrId::new(reader.read_u32()?));
    }
    let mut frames = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        frames.push(decode_frame(&mut reader)?);
    }
    let mut with_chains = Vec::with_capacity(with_chain_count);
    for _ in 0..with_chain_count {
        let scope_count = reader.read_len("IR with-chain scope count")?;
        let mut scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            scopes.push(IrId::new(reader.read_u32()?));
        }
        with_chains.push(IrWithChain::new(scopes.into_boxed_slice()));
    }
    let mut attr_paths = Vec::with_capacity(attr_path_count);
    for _ in 0..attr_path_count {
        let segment_count = reader.read_len("IR attr-path segment count")?;
        let mut segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            segments.push(decode_ir_attr_path_segment(&mut reader)?);
        }
        attr_paths.push(segments.into_boxed_slice());
    }
    let mut bindings = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let key = decode_ir_attr_path_segment(&mut reader)?;
        let value = IrId::new(reader.read_u32()?);
        bindings.push(IrBinding { key, value });
    }
    let mut shapes = Vec::with_capacity(shape_count);
    for _ in 0..shape_count {
        let key_count = reader.read_len("IR shape key count")?;
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            keys.push(Symbol::new(reader.read_u32()?));
        }
        shapes.push(IrShape::new(keys.into_boxed_slice()));
    }
    reader.expect_eof()?;

    let ir = Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, children),
        symbols,
        frames: frames.into_boxed_slice(),
        with_chains: with_chains.into_boxed_slice(),
        attr_paths: attr_paths.into_boxed_slice(),
        bindings: bindings.into_boxed_slice(),
        shapes: shapes.into_boxed_slice(),
    };
    validate_lowered_ir_artifact(&ir)?;
    Ok(ir)
}

fn lowered_ir_matches(left: &Ir, right: &Ir) -> bool {
    left.root == right.root
        && left.arena.nodes() == right.arena.nodes()
        && left.arena.child_pool() == right.arena.child_pool()
        && left.symbols.symbols() == right.symbols.symbols()
        && left.frames == right.frames
        && left.with_chains == right.with_chains
        && left.attr_paths == right.attr_paths
        && left.bindings == right.bindings
        && left.shapes == right.shapes
}

fn encode_symbols(symbols: &SymbolTable) -> Result<Vec<u8>, ParseCacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(SYMBOL_MAGIC);
    write_u32(&mut out, ARTIFACT_VERSION);
    write_len(&mut out, symbols.symbols().len(), "symbol count")?;
    for symbol in symbols.symbols() {
        write_len(&mut out, symbol.len(), "symbol byte length")?;
        out.extend_from_slice(symbol);
    }
    Ok(out)
}

fn decode_symbols(bytes: &[u8]) -> Result<SymbolTable, String> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_magic(SYMBOL_MAGIC)?;
    let version = reader.read_u32()?;
    if version != ARTIFACT_VERSION {
        return Err(format!("unsupported symbols artifact version {version}"));
    }
    let count = reader.read_len("symbol count")?;
    let mut symbols = SymbolTable::new();
    for _ in 0..count {
        let len = reader.read_len("symbol byte length")?;
        let bytes = reader.read_bytes(len)?;
        let expected = u32::try_from(symbols.len())
            .map_err(|_| "symbol table length exceeds u32".to_owned())?;
        let symbol = symbols
            .intern(bytes)
            .map_err(|error| format!("invalid symbol table: {error}"))?;
        if symbol.as_u32() != expected {
            return Err("duplicate symbol in serialized symbol table".to_owned());
        }
    }
    reader.expect_eof()?;
    Ok(symbols)
}

fn validate_resolved_artifact(resolved: &ResolvedAst) -> Result<(), String> {
    check_node_id(resolved, resolved.root, "root")?;
    for child in resolved.arena.child_pool() {
        check_node_id(resolved, *child, "child pool")?;
    }
    for node in resolved.arena.nodes() {
        validate_node_data(resolved, node.data)?;
    }
    for frame in resolved.scopes.node_frames() {
        if let Some(frame) = frame {
            check_frame_id(resolved, *frame)?;
        }
    }
    for chain in resolved.scopes.with_chains() {
        for scope in chain.scopes.as_ref() {
            check_node_id(resolved, *scope, "with chain")?;
        }
    }
    for inherit in resolved.scopes.inherit_resolutions() {
        if let Some(from) = inherit.from {
            check_node_id(resolved, from, "inherit source")?;
        }
        for source in inherit.sources.as_ref() {
            check_symbol(resolved, source.target)?;
            check_node_id(resolved, source.source, "inherit source")?;
        }
    }
    for inherit in resolved.scopes.node_inherits() {
        if let Some(inherit) = inherit {
            check_inherit_id(resolved, *inherit)?;
        }
    }
    Ok(())
}

fn validate_node_data(resolved: &ResolvedAst, data: NodeData) -> Result<(), String> {
    match data {
        NodeData::None | NodeData::Int(_) | NodeData::Float(_) => Ok(()),
        NodeData::Symbol(symbol) => check_symbol(resolved, symbol),
        NodeData::Node(node) => check_node_id(resolved, node, "node payload"),
        NodeData::Pair { first, second } => {
            check_node_id(resolved, first, "pair first")?;
            check_node_id(resolved, second, "pair second")
        }
        NodeData::Triple {
            first,
            second,
            third,
        } => {
            check_node_id(resolved, first, "triple first")?;
            check_node_id(resolved, second, "triple second")?;
            check_node_id(resolved, third, "triple third")
        }
        NodeData::Children(slice) => check_child_slice(resolved, slice),
        NodeData::Binary { lhs, rhs, .. } => {
            check_node_id(resolved, lhs, "binary lhs")?;
            check_node_id(resolved, rhs, "binary rhs")
        }
        NodeData::Unary { operand, .. } => check_node_id(resolved, operand, "unary operand"),
        NodeData::Select {
            receiver,
            path,
            default,
        } => {
            check_node_id(resolved, receiver, "select receiver")?;
            check_child_slice(resolved, path)?;
            if let Some(default) = default {
                check_node_id(resolved, default, "select default")?;
            }
            Ok(())
        }
        NodeData::HasAttr { receiver, path } => {
            check_node_id(resolved, receiver, "has-attr receiver")?;
            check_child_slice(resolved, path)
        }
        NodeData::Binding { path, value } => {
            check_child_slice(resolved, path)?;
            check_node_id(resolved, value, "binding value")
        }
        NodeData::LetIn { bindings, body } => {
            check_child_slice(resolved, bindings)?;
            check_node_id(resolved, body, "let body")
        }
        NodeData::Inherit { from, names } => {
            if let Some(from) = from {
                check_node_id(resolved, from, "inherit from")?;
            }
            check_child_slice(resolved, names)
        }
        NodeData::FormalSet { formals, alias, .. } => {
            check_child_slice(resolved, formals)?;
            if let Some(alias) = alias {
                check_symbol(resolved, alias)?;
            }
            Ok(())
        }
        NodeData::Formal { name, default } => {
            check_symbol(resolved, name)?;
            if let Some(default) = default {
                check_node_id(resolved, default, "formal default")?;
            }
            Ok(())
        }
        NodeData::Local { .. } | NodeData::Upval { .. } => Ok(()),
        NodeData::WithVar { symbol, chain } => {
            check_symbol(resolved, symbol)?;
            let chain = usize::try_from(chain).map_err(|_| "with-chain id overflow".to_owned())?;
            if chain >= resolved.scopes.with_chains().len() {
                return Err("with-chain id out of range".to_owned());
            }
            Ok(())
        }
    }
}

fn check_node_id(resolved: &ResolvedAst, id: NodeId, what: &'static str) -> Result<(), String> {
    if id.index() < resolved.arena.len() {
        Ok(())
    } else {
        Err(format!("{what} node id out of range"))
    }
}

fn check_symbol(resolved: &ResolvedAst, symbol: Symbol) -> Result<(), String> {
    if resolved.symbols.resolve(symbol).is_some() {
        Ok(())
    } else {
        Err("symbol id out of range".to_owned())
    }
}

fn check_child_slice(resolved: &ResolvedAst, slice: ChildSlice) -> Result<(), String> {
    let end = slice
        .checked_end()
        .ok_or_else(|| "child slice overflow".to_owned())? as usize;
    if end <= resolved.arena.child_pool().len() {
        Ok(())
    } else {
        Err("child slice out of range".to_owned())
    }
}

fn check_frame_id(resolved: &ResolvedAst, id: FrameId) -> Result<(), String> {
    if id.index() < resolved.scopes.frames().len() {
        Ok(())
    } else {
        Err("frame id out of range".to_owned())
    }
}

fn check_inherit_id(resolved: &ResolvedAst, id: InheritGroupId) -> Result<(), String> {
    if id.index() < resolved.scopes.inherit_resolutions().len() {
        Ok(())
    } else {
        Err("inherit id out of range".to_owned())
    }
}

fn validate_lowered_ir_artifact(ir: &Ir) -> Result<(), String> {
    check_ir_id(ir, ir.root, "root")?;
    for child in ir.arena.child_pool() {
        check_ir_id(ir, *child, "child pool")?;
    }
    for node in ir.arena.nodes() {
        validate_ir_node(ir, *node)?;
    }
    for path in ir.attr_paths.as_ref() {
        for segment in path.as_ref() {
            validate_ir_attr_path_segment(ir, *segment)?;
        }
    }
    for binding in ir.bindings.as_ref() {
        validate_ir_attr_path_segment(ir, binding.key)?;
        check_ir_id(ir, binding.value, "binding value")?;
    }
    for chain in ir.with_chains.as_ref() {
        for scope in chain.scopes.as_ref() {
            check_ir_id(ir, *scope, "with-chain scope")?;
        }
    }
    for shape in ir.shapes.as_ref() {
        for key in shape.keys.as_ref() {
            check_ir_symbol(ir, *key)?;
        }
    }
    Ok(())
}

fn validate_ir_node(ir: &Ir, node: IrNode) -> Result<(), String> {
    validate_ir_node_shape(node)?;
    validate_ir_node_effect(ir, node)?;
    validate_ir_data(ir, node.data)?;
    if let IrData::AttrSet {
        shape,
        bindings,
        has_dynamic,
        ..
    } = node.data
    {
        validate_ir_attrset_shape(ir, shape, bindings, has_dynamic)?;
    }
    Ok(())
}

fn validate_ir_node_shape(node: IrNode) -> Result<(), String> {
    let valid = matches!(
        (node.kind, node.data),
        (IrKind::Int, IrData::Int(_))
            | (IrKind::Float, IrData::Float(_))
            | (IrKind::Bool, IrData::Bool(_))
            | (IrKind::Null, IrData::None)
            | (IrKind::Str, IrData::Symbol(_))
            | (IrKind::Path, IrData::Symbol(_))
            | (IrKind::SearchPath, IrData::Symbol(_))
            | (IrKind::Uri, IrData::Symbol(_))
            | (IrKind::LocalVar, IrData::Local { .. })
            | (IrKind::UpvalVar, IrData::Upval { .. })
            | (IrKind::GlobalVar, IrData::Symbol(_))
            | (IrKind::WithVar, IrData::WithVar { .. })
            | (IrKind::List, IrData::Children(_))
            | (IrKind::AttrSet, IrData::AttrSet { .. })
            | (IrKind::Lambda, IrData::Lambda { .. })
            | (IrKind::FormalSet, IrData::FormalSet { .. })
            | (IrKind::Formal, IrData::Formal { .. })
            | (IrKind::Apply, IrData::Pair { .. })
            | (IrKind::Select, IrData::Select { .. })
            | (IrKind::HasAttr, IrData::HasAttr { .. })
            | (IrKind::Let, IrData::Let { .. })
            | (IrKind::With, IrData::Pair { .. })
            | (IrKind::Assert, IrData::Pair { .. })
            | (IrKind::If, IrData::Triple { .. })
            | (IrKind::BinOp, IrData::Binary { .. })
            | (IrKind::UnaryOp, IrData::Unary { .. })
            | (IrKind::Interp, IrData::None)
            | (IrKind::Interp, IrData::Node(_))
            | (IrKind::Interp, IrData::Children(_))
            | (IrKind::ThunkAlloc, IrData::Node(_))
            | (IrKind::PrimOp, IrData::PrimOp { .. })
            | (IrKind::DerivationStrict, IrData::Node(_))
    );
    if valid {
        Ok(())
    } else {
        Err(format!("invalid IR data for {:?} node", node.kind))
    }
}

fn validate_ir_node_effect(ir: &Ir, node: IrNode) -> Result<(), String> {
    let expected = match node.kind {
        IrKind::PrimOp => match node.data {
            IrData::PrimOp { symbol, .. } => primop_effect(ir.symbols.resolve(symbol))
                .ok_or_else(|| format!("unknown IR primop symbol {symbol:?}"))?,
            _ => node.effect,
        },
        IrKind::DerivationStrict => EffectClass::Effectful,
        _ => EffectClass::Pure,
    };
    if node.effect == expected {
        Ok(())
    } else {
        Err(format!("invalid IR effect for {:?} node", node.kind))
    }
}

fn primop_effect(name: Option<&[u8]>) -> Option<EffectClass> {
    match name {
        Some(
            b"getEnv" | b"import" | b"pathExists" | b"readDir" | b"readFile" | b"readFileType",
        ) => Some(EffectClass::Effectful),
        Some(
            b"isAttrs" | b"isList" | b"isFunction" | b"isString" | b"isInt" | b"isFloat"
            | b"isBool" | b"isNull" | b"isPath" | b"typeOf" | b"length",
        ) => Some(EffectClass::Pure),
        _ => None,
    }
}

fn validate_ir_data(ir: &Ir, data: IrData) -> Result<(), String> {
    match data {
        IrData::None | IrData::Int(_) | IrData::Float(_) | IrData::Bool(_) => Ok(()),
        IrData::Symbol(symbol) => check_ir_symbol(ir, symbol),
        IrData::Node(node) => check_ir_id(ir, node, "node payload"),
        IrData::Pair { first, second } => {
            check_ir_id(ir, first, "pair first")?;
            check_ir_id(ir, second, "pair second")
        }
        IrData::Triple {
            first,
            second,
            third,
        } => {
            check_ir_id(ir, first, "triple first")?;
            check_ir_id(ir, second, "triple second")?;
            check_ir_id(ir, third, "triple third")
        }
        IrData::Children(slice) => check_ir_child_slice(ir, slice),
        IrData::Bindings(slice) => check_ir_binding_slice(ir, slice),
        IrData::Binary { lhs, rhs, .. } => {
            check_ir_id(ir, lhs, "binary lhs")?;
            check_ir_id(ir, rhs, "binary rhs")
        }
        IrData::Unary { operand, .. } => check_ir_id(ir, operand, "unary operand"),
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            check_ir_id(ir, receiver, "select receiver")?;
            check_ir_attr_path_id(ir, path)?;
            if let Some(default) = default {
                check_ir_id(ir, default, "select default")?;
            }
            Ok(())
        }
        IrData::HasAttr { receiver, path, .. } => {
            check_ir_id(ir, receiver, "has-attr receiver")?;
            check_ir_attr_path_id(ir, path)
        }
        IrData::PrimOp { symbol, args } => {
            check_ir_symbol(ir, symbol)?;
            check_ir_child_slice(ir, args)
        }
        IrData::Lambda {
            pattern,
            body,
            frame,
        } => {
            check_ir_id(ir, pattern, "lambda pattern")?;
            check_ir_id(ir, body, "lambda body")?;
            if let Some(frame) = frame {
                check_ir_frame_id(ir, frame)?;
            }
            Ok(())
        }
        IrData::Let {
            bindings,
            body,
            frame,
        } => {
            check_ir_binding_slice(ir, bindings)?;
            check_ir_id(ir, body, "let body")?;
            if let Some(frame) = frame {
                check_ir_frame_id(ir, frame)?;
            }
            Ok(())
        }
        IrData::AttrSet {
            shape,
            bindings,
            frame,
            ..
        } => {
            check_ir_shape_id(ir, shape)?;
            check_ir_binding_slice(ir, bindings)?;
            if let Some(frame) = frame {
                check_ir_frame_id(ir, frame)?;
            }
            Ok(())
        }
        IrData::FormalSet { formals, alias, .. } => {
            check_ir_child_slice(ir, formals)?;
            if let Some(alias) = alias {
                check_ir_symbol(ir, alias)?;
            }
            Ok(())
        }
        IrData::Formal { name, default } => {
            check_ir_symbol(ir, name)?;
            if let Some(default) = default {
                check_ir_id(ir, default, "formal default")?;
            }
            Ok(())
        }
        IrData::Local { .. } | IrData::Upval { .. } => Ok(()),
        IrData::WithVar { symbol, chain } => {
            check_ir_symbol(ir, symbol)?;
            let chain = usize::try_from(chain).map_err(|_| "with-chain id overflow".to_owned())?;
            if chain >= ir.with_chains.len() {
                return Err("with-chain id out of range".to_owned());
            }
            Ok(())
        }
    }
}

fn validate_ir_attrset_shape(
    ir: &Ir,
    shape: IrShapeId,
    bindings: IrBindingSlice,
    has_dynamic: bool,
) -> Result<(), String> {
    let shape = ir
        .shapes
        .get(shape.index())
        .ok_or_else(|| "IR shape id out of range".to_owned())?;
    let bindings = ir_binding_slice(ir, bindings)?;
    let mut static_keys = Vec::new();
    let mut saw_dynamic = false;
    for binding in bindings {
        match binding.key {
            IrAttrPathSegment::Static(symbol) => static_keys.push(symbol),
            IrAttrPathSegment::Dynamic(_) => saw_dynamic = true,
        }
    }
    if shape.keys.as_ref() != static_keys.as_slice() {
        return Err("IR attrset shape does not match static binding keys".to_owned());
    }
    if has_dynamic != saw_dynamic {
        return Err("IR attrset dynamic flag does not match binding keys".to_owned());
    }
    Ok(())
}

fn validate_ir_attr_path_segment(ir: &Ir, segment: IrAttrPathSegment) -> Result<(), String> {
    match segment {
        IrAttrPathSegment::Static(symbol) => check_ir_symbol(ir, symbol),
        IrAttrPathSegment::Dynamic(node) => check_ir_id(ir, node, "dynamic attr-path segment"),
    }
}

fn check_ir_id(ir: &Ir, id: IrId, what: &'static str) -> Result<(), String> {
    if id.index() < ir.arena.nodes().len() {
        Ok(())
    } else {
        Err(format!("{what} IR id out of range"))
    }
}

fn check_ir_symbol(ir: &Ir, symbol: Symbol) -> Result<(), String> {
    if ir.symbols.resolve(symbol).is_some() {
        Ok(())
    } else {
        Err("IR symbol id out of range".to_owned())
    }
}

fn check_ir_child_slice(ir: &Ir, slice: IrChildSlice) -> Result<(), String> {
    let start = usize::try_from(slice.start).map_err(|_| "IR child slice overflow".to_owned())?;
    let len = usize::try_from(slice.len).map_err(|_| "IR child slice overflow".to_owned())?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "IR child slice overflow".to_owned())?;
    if end <= ir.arena.child_pool().len() {
        Ok(())
    } else {
        Err("IR child slice out of range".to_owned())
    }
}

fn check_ir_binding_slice(ir: &Ir, slice: IrBindingSlice) -> Result<(), String> {
    ir_binding_slice(ir, slice).map(|_| ())
}

fn ir_binding_slice(ir: &Ir, slice: IrBindingSlice) -> Result<&[IrBinding], String> {
    let start = usize::try_from(slice.start).map_err(|_| "IR binding slice overflow".to_owned())?;
    let len = usize::try_from(slice.len).map_err(|_| "IR binding slice overflow".to_owned())?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "IR binding slice overflow".to_owned())?;
    ir.bindings
        .get(start..end)
        .ok_or_else(|| "IR binding slice out of range".to_owned())
}

fn check_ir_attr_path_id(ir: &Ir, id: IrAttrPathId) -> Result<(), String> {
    if id.index() < ir.attr_paths.len() {
        Ok(())
    } else {
        Err("IR attr-path id out of range".to_owned())
    }
}

fn check_ir_shape_id(ir: &Ir, id: IrShapeId) -> Result<(), String> {
    if id.index() < ir.shapes.len() {
        Ok(())
    } else {
        Err("IR shape id out of range".to_owned())
    }
}

fn check_ir_frame_id(ir: &Ir, id: FrameId) -> Result<(), String> {
    if id.index() < ir.frames.len() {
        Ok(())
    } else {
        Err("IR frame id out of range".to_owned())
    }
}

fn encode_ir_node(out: &mut Vec<u8>, node: IrNode) {
    out.push(ir_kind_tag(node.kind));
    write_u32(out, node.span.start);
    write_u32(out, node.span.end);
    out.push(effect_class_tag(node.effect));
    encode_ir_data(out, node.data);
}

fn decode_ir_node(reader: &mut BinaryReader<'_>) -> Result<IrNode, String> {
    let kind = decode_ir_kind(reader.read_u8()?)?;
    let span = Span::new(reader.read_u32()?, reader.read_u32()?);
    let effect = decode_effect_class(reader.read_u8()?)?;
    let data = decode_ir_data(reader)?;
    Ok(IrNode::new(kind, span, effect, data))
}

fn encode_ir_data(out: &mut Vec<u8>, data: IrData) {
    match data {
        IrData::None => out.push(0),
        IrData::Int(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        IrData::Float(value) => {
            out.push(2);
            out.extend_from_slice(&value.to_le_bytes());
        }
        IrData::Bool(value) => {
            out.push(3);
            out.push(u8::from(value));
        }
        IrData::Symbol(symbol) => {
            out.push(4);
            write_u32(out, symbol.as_u32());
        }
        IrData::Node(node) => {
            out.push(5);
            write_u32(out, node.as_u32());
        }
        IrData::Pair { first, second } => {
            out.push(6);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
        }
        IrData::Triple {
            first,
            second,
            third,
        } => {
            out.push(7);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
            write_u32(out, third.as_u32());
        }
        IrData::Children(slice) => {
            out.push(8);
            encode_ir_child_slice(out, slice);
        }
        IrData::Bindings(slice) => {
            out.push(9);
            encode_ir_binding_slice(out, slice);
        }
        IrData::Binary { op, lhs, rhs } => {
            out.push(10);
            out.push(bin_op_tag(op));
            write_u32(out, lhs.as_u32());
            write_u32(out, rhs.as_u32());
        }
        IrData::Unary { op, operand } => {
            out.push(11);
            out.push(unary_op_tag(op));
            write_u32(out, operand.as_u32());
        }
        IrData::Select {
            site,
            receiver,
            path,
            default,
        } => {
            out.push(12);
            write_u32(out, site.as_u32());
            write_u32(out, receiver.as_u32());
            write_u32(out, path.as_u32());
            encode_option_u32(out, default.map(IrId::as_u32));
        }
        IrData::HasAttr {
            site,
            receiver,
            path,
        } => {
            out.push(13);
            write_u32(out, site.as_u32());
            write_u32(out, receiver.as_u32());
            write_u32(out, path.as_u32());
        }
        IrData::PrimOp { symbol, args } => {
            out.push(14);
            write_u32(out, symbol.as_u32());
            encode_ir_child_slice(out, args);
        }
        IrData::Lambda {
            pattern,
            body,
            frame,
        } => {
            out.push(15);
            write_u32(out, pattern.as_u32());
            write_u32(out, body.as_u32());
            encode_option_u32(out, frame.map(FrameId::as_u32));
        }
        IrData::Let {
            bindings,
            body,
            frame,
        } => {
            out.push(16);
            encode_ir_binding_slice(out, bindings);
            write_u32(out, body.as_u32());
            encode_option_u32(out, frame.map(FrameId::as_u32));
        }
        IrData::AttrSet {
            shape,
            bindings,
            recursive,
            has_dynamic,
            frame,
        } => {
            out.push(17);
            write_u32(out, shape.as_u32());
            encode_ir_binding_slice(out, bindings);
            out.push(u8::from(recursive));
            out.push(u8::from(has_dynamic));
            encode_option_u32(out, frame.map(FrameId::as_u32));
        }
        IrData::FormalSet {
            formals,
            ellipsis,
            alias,
        } => {
            out.push(18);
            encode_ir_child_slice(out, formals);
            out.push(u8::from(ellipsis));
            encode_option_u32(out, alias.map(Symbol::as_u32));
        }
        IrData::Formal { name, default } => {
            out.push(19);
            write_u32(out, name.as_u32());
            encode_option_u32(out, default.map(IrId::as_u32));
        }
        IrData::Local { slot } => {
            out.push(20);
            write_u32(out, slot);
        }
        IrData::Upval { depth, slot } => {
            out.push(21);
            write_u32(out, depth);
            write_u32(out, slot);
        }
        IrData::WithVar { symbol, chain } => {
            out.push(22);
            write_u32(out, symbol.as_u32());
            write_u32(out, chain);
        }
    }
}

fn decode_ir_data(reader: &mut BinaryReader<'_>) -> Result<IrData, String> {
    let tag = reader.read_u8()?;
    match tag {
        0 => Ok(IrData::None),
        1 => Ok(IrData::Int(reader.read_i64()?)),
        2 => Ok(IrData::Float(reader.read_f64()?)),
        3 => Ok(IrData::Bool(reader.read_bool()?)),
        4 => Ok(IrData::Symbol(Symbol::new(reader.read_u32()?))),
        5 => Ok(IrData::Node(IrId::new(reader.read_u32()?))),
        6 => Ok(IrData::Pair {
            first: IrId::new(reader.read_u32()?),
            second: IrId::new(reader.read_u32()?),
        }),
        7 => Ok(IrData::Triple {
            first: IrId::new(reader.read_u32()?),
            second: IrId::new(reader.read_u32()?),
            third: IrId::new(reader.read_u32()?),
        }),
        8 => Ok(IrData::Children(decode_ir_child_slice(reader)?)),
        9 => Ok(IrData::Bindings(decode_ir_binding_slice(reader)?)),
        10 => Ok(IrData::Binary {
            op: decode_bin_op(reader.read_u8()?)?,
            lhs: IrId::new(reader.read_u32()?),
            rhs: IrId::new(reader.read_u32()?),
        }),
        11 => Ok(IrData::Unary {
            op: decode_unary_op(reader.read_u8()?)?,
            operand: IrId::new(reader.read_u32()?),
        }),
        12 => Ok(IrData::Select {
            site: IrInlineCacheSiteId::new(reader.read_u32()?),
            receiver: IrId::new(reader.read_u32()?),
            path: IrAttrPathId::new(reader.read_u32()?),
            default: reader.read_option_u32()?.map(IrId::new),
        }),
        13 => Ok(IrData::HasAttr {
            site: IrInlineCacheSiteId::new(reader.read_u32()?),
            receiver: IrId::new(reader.read_u32()?),
            path: IrAttrPathId::new(reader.read_u32()?),
        }),
        14 => Ok(IrData::PrimOp {
            symbol: Symbol::new(reader.read_u32()?),
            args: decode_ir_child_slice(reader)?,
        }),
        15 => Ok(IrData::Lambda {
            pattern: IrId::new(reader.read_u32()?),
            body: IrId::new(reader.read_u32()?),
            frame: reader.read_option_u32()?.map(FrameId::new),
        }),
        16 => Ok(IrData::Let {
            bindings: decode_ir_binding_slice(reader)?,
            body: IrId::new(reader.read_u32()?),
            frame: reader.read_option_u32()?.map(FrameId::new),
        }),
        17 => Ok(IrData::AttrSet {
            shape: IrShapeId::new(reader.read_u32()?),
            bindings: decode_ir_binding_slice(reader)?,
            recursive: reader.read_bool()?,
            has_dynamic: reader.read_bool()?,
            frame: reader.read_option_u32()?.map(FrameId::new),
        }),
        18 => Ok(IrData::FormalSet {
            formals: decode_ir_child_slice(reader)?,
            ellipsis: reader.read_bool()?,
            alias: reader.read_option_u32()?.map(Symbol::new),
        }),
        19 => Ok(IrData::Formal {
            name: Symbol::new(reader.read_u32()?),
            default: reader.read_option_u32()?.map(IrId::new),
        }),
        20 => Ok(IrData::Local {
            slot: reader.read_u32()?,
        }),
        21 => Ok(IrData::Upval {
            depth: reader.read_u32()?,
            slot: reader.read_u32()?,
        }),
        22 => Ok(IrData::WithVar {
            symbol: Symbol::new(reader.read_u32()?),
            chain: reader.read_u32()?,
        }),
        tag => Err(format!("invalid IR data tag {tag}")),
    }
}

fn encode_ir_attr_path_segment(out: &mut Vec<u8>, segment: IrAttrPathSegment) {
    match segment {
        IrAttrPathSegment::Static(symbol) => {
            out.push(0);
            write_u32(out, symbol.as_u32());
        }
        IrAttrPathSegment::Dynamic(node) => {
            out.push(1);
            write_u32(out, node.as_u32());
        }
    }
}

fn decode_ir_attr_path_segment(reader: &mut BinaryReader<'_>) -> Result<IrAttrPathSegment, String> {
    match reader.read_u8()? {
        0 => Ok(IrAttrPathSegment::Static(Symbol::new(reader.read_u32()?))),
        1 => Ok(IrAttrPathSegment::Dynamic(IrId::new(reader.read_u32()?))),
        tag => Err(format!("invalid IR attr-path segment tag {tag}")),
    }
}

fn encode_ir_child_slice(out: &mut Vec<u8>, slice: IrChildSlice) {
    write_u32(out, slice.start);
    write_u32(out, slice.len);
}

fn decode_ir_child_slice(reader: &mut BinaryReader<'_>) -> Result<IrChildSlice, String> {
    Ok(IrChildSlice::new(reader.read_u32()?, reader.read_u32()?))
}

fn encode_ir_binding_slice(out: &mut Vec<u8>, slice: IrBindingSlice) {
    write_u32(out, slice.start);
    write_u32(out, slice.len);
}

fn decode_ir_binding_slice(reader: &mut BinaryReader<'_>) -> Result<IrBindingSlice, String> {
    Ok(IrBindingSlice::new(reader.read_u32()?, reader.read_u32()?))
}

fn encode_node(out: &mut Vec<u8>, node: Node) {
    out.push(node_kind_tag(node.kind));
    write_u32(out, node.span.start);
    write_u32(out, node.span.end);
    encode_node_data(out, node.data);
}

fn decode_node(reader: &mut BinaryReader<'_>) -> Result<Node, String> {
    let kind = decode_node_kind(reader.read_u8()?)?;
    let span = Span::new(reader.read_u32()?, reader.read_u32()?);
    let data = decode_node_data(reader)?;
    Ok(Node::new(kind, span, data))
}

fn encode_node_data(out: &mut Vec<u8>, data: NodeData) {
    match data {
        NodeData::None => out.push(0),
        NodeData::Int(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        NodeData::Float(value) => {
            out.push(2);
            out.extend_from_slice(&value.to_le_bytes());
        }
        NodeData::Symbol(symbol) => {
            out.push(3);
            write_u32(out, symbol.as_u32());
        }
        NodeData::Node(node) => {
            out.push(4);
            write_u32(out, node.as_u32());
        }
        NodeData::Pair { first, second } => {
            out.push(5);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
        }
        NodeData::Triple {
            first,
            second,
            third,
        } => {
            out.push(6);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
            write_u32(out, third.as_u32());
        }
        NodeData::Children(slice) => {
            out.push(7);
            encode_child_slice(out, slice);
        }
        NodeData::Binary { op, lhs, rhs } => {
            out.push(8);
            out.push(bin_op_tag(op));
            write_u32(out, lhs.as_u32());
            write_u32(out, rhs.as_u32());
        }
        NodeData::Unary { op, operand } => {
            out.push(9);
            out.push(unary_op_tag(op));
            write_u32(out, operand.as_u32());
        }
        NodeData::Select {
            receiver,
            path,
            default,
        } => {
            out.push(10);
            write_u32(out, receiver.as_u32());
            encode_child_slice(out, path);
            encode_option_u32(out, default.map(NodeId::as_u32));
        }
        NodeData::HasAttr { receiver, path } => {
            out.push(11);
            write_u32(out, receiver.as_u32());
            encode_child_slice(out, path);
        }
        NodeData::Binding { path, value } => {
            out.push(12);
            encode_child_slice(out, path);
            write_u32(out, value.as_u32());
        }
        NodeData::LetIn { bindings, body } => {
            out.push(13);
            encode_child_slice(out, bindings);
            write_u32(out, body.as_u32());
        }
        NodeData::Inherit { from, names } => {
            out.push(14);
            encode_option_u32(out, from.map(NodeId::as_u32));
            encode_child_slice(out, names);
        }
        NodeData::FormalSet {
            formals,
            ellipsis,
            alias,
        } => {
            out.push(15);
            encode_child_slice(out, formals);
            out.push(u8::from(ellipsis));
            encode_option_u32(out, alias.map(Symbol::as_u32));
        }
        NodeData::Formal { name, default } => {
            out.push(16);
            write_u32(out, name.as_u32());
            encode_option_u32(out, default.map(NodeId::as_u32));
        }
        NodeData::Local { slot } => {
            out.push(17);
            write_u32(out, slot);
        }
        NodeData::Upval { depth, slot } => {
            out.push(18);
            write_u32(out, depth);
            write_u32(out, slot);
        }
        NodeData::WithVar { symbol, chain } => {
            out.push(19);
            write_u32(out, symbol.as_u32());
            write_u32(out, chain);
        }
    }
}

fn decode_node_data(reader: &mut BinaryReader<'_>) -> Result<NodeData, String> {
    let tag = reader.read_u8()?;
    match tag {
        0 => Ok(NodeData::None),
        1 => Ok(NodeData::Int(reader.read_i64()?)),
        2 => Ok(NodeData::Float(reader.read_f64()?)),
        3 => Ok(NodeData::Symbol(Symbol::new(reader.read_u32()?))),
        4 => Ok(NodeData::Node(NodeId::new(reader.read_u32()?))),
        5 => Ok(NodeData::Pair {
            first: NodeId::new(reader.read_u32()?),
            second: NodeId::new(reader.read_u32()?),
        }),
        6 => Ok(NodeData::Triple {
            first: NodeId::new(reader.read_u32()?),
            second: NodeId::new(reader.read_u32()?),
            third: NodeId::new(reader.read_u32()?),
        }),
        7 => Ok(NodeData::Children(decode_child_slice(reader)?)),
        8 => Ok(NodeData::Binary {
            op: decode_bin_op(reader.read_u8()?)?,
            lhs: NodeId::new(reader.read_u32()?),
            rhs: NodeId::new(reader.read_u32()?),
        }),
        9 => Ok(NodeData::Unary {
            op: decode_unary_op(reader.read_u8()?)?,
            operand: NodeId::new(reader.read_u32()?),
        }),
        10 => Ok(NodeData::Select {
            receiver: NodeId::new(reader.read_u32()?),
            path: decode_child_slice(reader)?,
            default: reader.read_option_u32()?.map(NodeId::new),
        }),
        11 => Ok(NodeData::HasAttr {
            receiver: NodeId::new(reader.read_u32()?),
            path: decode_child_slice(reader)?,
        }),
        12 => Ok(NodeData::Binding {
            path: decode_child_slice(reader)?,
            value: NodeId::new(reader.read_u32()?),
        }),
        13 => Ok(NodeData::LetIn {
            bindings: decode_child_slice(reader)?,
            body: NodeId::new(reader.read_u32()?),
        }),
        14 => Ok(NodeData::Inherit {
            from: reader.read_option_u32()?.map(NodeId::new),
            names: decode_child_slice(reader)?,
        }),
        15 => Ok(NodeData::FormalSet {
            formals: decode_child_slice(reader)?,
            ellipsis: reader.read_bool()?,
            alias: reader.read_option_u32()?.map(Symbol::new),
        }),
        16 => Ok(NodeData::Formal {
            name: Symbol::new(reader.read_u32()?),
            default: reader.read_option_u32()?.map(NodeId::new),
        }),
        17 => Ok(NodeData::Local {
            slot: reader.read_u32()?,
        }),
        18 => Ok(NodeData::Upval {
            depth: reader.read_u32()?,
            slot: reader.read_u32()?,
        }),
        19 => Ok(NodeData::WithVar {
            symbol: Symbol::new(reader.read_u32()?),
            chain: reader.read_u32()?,
        }),
        tag => Err(format!("invalid node data tag {tag}")),
    }
}

fn encode_frame(out: &mut Vec<u8>, frame: &FrameInfo) -> Result<(), ParseCacheError> {
    write_u32(out, frame.slot_count);
    out.push(u8::from(frame.rec));
    out.push(u8::from(frame.has_with));
    write_len(out, frame.captures.len(), "frame capture count")?;
    for capture in frame.captures.as_ref() {
        out.extend_from_slice(&capture.depth.to_le_bytes());
        out.extend_from_slice(&capture.slot.to_le_bytes());
    }
    Ok(())
}

fn decode_frame(reader: &mut BinaryReader<'_>) -> Result<FrameInfo, String> {
    let slot_count = reader.read_u32()?;
    let rec = reader.read_bool()?;
    let has_with = reader.read_bool()?;
    let capture_count = reader.read_len("frame capture count")?;
    let mut captures = Vec::with_capacity(capture_count);
    for _ in 0..capture_count {
        captures.push(Upvalue {
            depth: reader.read_u16()?,
            slot: reader.read_u16()?,
        });
    }
    Ok(FrameInfo {
        slot_count,
        captures: captures.into_boxed_slice(),
        rec,
        has_with,
    })
}

fn encode_child_slice(out: &mut Vec<u8>, slice: ChildSlice) {
    write_u32(out, slice.start);
    write_u32(out, slice.len);
}

fn decode_child_slice(reader: &mut BinaryReader<'_>) -> Result<ChildSlice, String> {
    Ok(ChildSlice::new(reader.read_u32()?, reader.read_u32()?))
}

fn encode_option_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u32(out, value);
        }
        None => out.push(0),
    }
}

fn write_len(out: &mut Vec<u8>, len: usize, what: &'static str) -> Result<(), ParseCacheError> {
    let len = u32::try_from(len)
        .map_err(|_| ParseCacheError::EncodeArtifact(format!("{what} exceeds u32")))?;
    write_u32(out, len);
    Ok(())
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn ir_kind_tag(kind: IrKind) -> u8 {
    match kind {
        IrKind::Int => 0,
        IrKind::Float => 1,
        IrKind::Bool => 2,
        IrKind::Null => 3,
        IrKind::Str => 4,
        IrKind::Path => 5,
        IrKind::SearchPath => 6,
        IrKind::Uri => 7,
        IrKind::LocalVar => 8,
        IrKind::UpvalVar => 9,
        IrKind::GlobalVar => 10,
        IrKind::WithVar => 11,
        IrKind::List => 12,
        IrKind::AttrSet => 13,
        IrKind::Lambda => 14,
        IrKind::FormalSet => 15,
        IrKind::Formal => 16,
        IrKind::Apply => 17,
        IrKind::Select => 18,
        IrKind::HasAttr => 19,
        IrKind::Let => 20,
        IrKind::With => 21,
        IrKind::Assert => 22,
        IrKind::If => 23,
        IrKind::BinOp => 24,
        IrKind::UnaryOp => 25,
        IrKind::Interp => 26,
        IrKind::ThunkAlloc => 27,
        IrKind::PrimOp => 28,
        IrKind::DerivationStrict => 29,
    }
}

fn decode_ir_kind(tag: u8) -> Result<IrKind, String> {
    match tag {
        0 => Ok(IrKind::Int),
        1 => Ok(IrKind::Float),
        2 => Ok(IrKind::Bool),
        3 => Ok(IrKind::Null),
        4 => Ok(IrKind::Str),
        5 => Ok(IrKind::Path),
        6 => Ok(IrKind::SearchPath),
        7 => Ok(IrKind::Uri),
        8 => Ok(IrKind::LocalVar),
        9 => Ok(IrKind::UpvalVar),
        10 => Ok(IrKind::GlobalVar),
        11 => Ok(IrKind::WithVar),
        12 => Ok(IrKind::List),
        13 => Ok(IrKind::AttrSet),
        14 => Ok(IrKind::Lambda),
        15 => Ok(IrKind::FormalSet),
        16 => Ok(IrKind::Formal),
        17 => Ok(IrKind::Apply),
        18 => Ok(IrKind::Select),
        19 => Ok(IrKind::HasAttr),
        20 => Ok(IrKind::Let),
        21 => Ok(IrKind::With),
        22 => Ok(IrKind::Assert),
        23 => Ok(IrKind::If),
        24 => Ok(IrKind::BinOp),
        25 => Ok(IrKind::UnaryOp),
        26 => Ok(IrKind::Interp),
        27 => Ok(IrKind::ThunkAlloc),
        28 => Ok(IrKind::PrimOp),
        29 => Ok(IrKind::DerivationStrict),
        tag => Err(format!("invalid IR kind tag {tag}")),
    }
}

fn effect_class_tag(effect: EffectClass) -> u8 {
    match effect {
        EffectClass::Pure => 0,
        EffectClass::Effectful => 1,
    }
}

fn decode_effect_class(tag: u8) -> Result<EffectClass, String> {
    match tag {
        0 => Ok(EffectClass::Pure),
        1 => Ok(EffectClass::Effectful),
        tag => Err(format!("invalid IR effect tag {tag}")),
    }
}

fn node_kind_tag(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Int => 0,
        NodeKind::Float => 1,
        NodeKind::Str => 2,
        NodeKind::Path => 3,
        NodeKind::SearchPath => 4,
        NodeKind::Uri => 5,
        NodeKind::Ident => 6,
        NodeKind::List => 7,
        NodeKind::AttrSet => 8,
        NodeKind::RecAttrSet => 9,
        NodeKind::Lambda => 10,
        NodeKind::FormalSet => 11,
        NodeKind::Formal => 12,
        NodeKind::Apply => 13,
        NodeKind::Select => 14,
        NodeKind::HasAttr => 15,
        NodeKind::LetIn => 16,
        NodeKind::Binding => 17,
        NodeKind::With => 18,
        NodeKind::Assert => 19,
        NodeKind::IfThenElse => 20,
        NodeKind::BinOp => 21,
        NodeKind::UnaryOp => 22,
        NodeKind::Inherit => 23,
        NodeKind::Interp => 24,
        NodeKind::AttrPath => 25,
        NodeKind::LocalVar => 26,
        NodeKind::UpvalVar => 27,
        NodeKind::GlobalVar => 28,
        NodeKind::WithVar => 29,
    }
}

fn decode_node_kind(tag: u8) -> Result<NodeKind, String> {
    match tag {
        0 => Ok(NodeKind::Int),
        1 => Ok(NodeKind::Float),
        2 => Ok(NodeKind::Str),
        3 => Ok(NodeKind::Path),
        4 => Ok(NodeKind::SearchPath),
        5 => Ok(NodeKind::Uri),
        6 => Ok(NodeKind::Ident),
        7 => Ok(NodeKind::List),
        8 => Ok(NodeKind::AttrSet),
        9 => Ok(NodeKind::RecAttrSet),
        10 => Ok(NodeKind::Lambda),
        11 => Ok(NodeKind::FormalSet),
        12 => Ok(NodeKind::Formal),
        13 => Ok(NodeKind::Apply),
        14 => Ok(NodeKind::Select),
        15 => Ok(NodeKind::HasAttr),
        16 => Ok(NodeKind::LetIn),
        17 => Ok(NodeKind::Binding),
        18 => Ok(NodeKind::With),
        19 => Ok(NodeKind::Assert),
        20 => Ok(NodeKind::IfThenElse),
        21 => Ok(NodeKind::BinOp),
        22 => Ok(NodeKind::UnaryOp),
        23 => Ok(NodeKind::Inherit),
        24 => Ok(NodeKind::Interp),
        25 => Ok(NodeKind::AttrPath),
        26 => Ok(NodeKind::LocalVar),
        27 => Ok(NodeKind::UpvalVar),
        28 => Ok(NodeKind::GlobalVar),
        29 => Ok(NodeKind::WithVar),
        tag => Err(format!("invalid node kind tag {tag}")),
    }
}

fn bin_op_tag(op: BinOpKind) -> u8 {
    match op {
        BinOpKind::Add => 0,
        BinOpKind::Sub => 1,
        BinOpKind::Mul => 2,
        BinOpKind::Div => 3,
        BinOpKind::Concat => 4,
        BinOpKind::Update => 5,
        BinOpKind::Lt => 6,
        BinOpKind::Gt => 7,
        BinOpKind::Le => 8,
        BinOpKind::Ge => 9,
        BinOpKind::Eq => 10,
        BinOpKind::Ne => 11,
        BinOpKind::And => 12,
        BinOpKind::Or => 13,
        BinOpKind::Impl => 14,
        BinOpKind::PipeRight => 15,
        BinOpKind::PipeLeft => 16,
    }
}

fn decode_bin_op(tag: u8) -> Result<BinOpKind, String> {
    match tag {
        0 => Ok(BinOpKind::Add),
        1 => Ok(BinOpKind::Sub),
        2 => Ok(BinOpKind::Mul),
        3 => Ok(BinOpKind::Div),
        4 => Ok(BinOpKind::Concat),
        5 => Ok(BinOpKind::Update),
        6 => Ok(BinOpKind::Lt),
        7 => Ok(BinOpKind::Gt),
        8 => Ok(BinOpKind::Le),
        9 => Ok(BinOpKind::Ge),
        10 => Ok(BinOpKind::Eq),
        11 => Ok(BinOpKind::Ne),
        12 => Ok(BinOpKind::And),
        13 => Ok(BinOpKind::Or),
        14 => Ok(BinOpKind::Impl),
        15 => Ok(BinOpKind::PipeRight),
        16 => Ok(BinOpKind::PipeLeft),
        tag => Err(format!("invalid binary operator tag {tag}")),
    }
}

fn unary_op_tag(op: UnaryOpKind) -> u8 {
    match op {
        UnaryOpKind::Neg => 0,
        UnaryOpKind::Not => 1,
    }
}

fn decode_unary_op(tag: u8) -> Result<UnaryOpKind, String> {
    match tag {
        0 => Ok(UnaryOpKind::Neg),
        1 => Ok(UnaryOpKind::Not),
        tag => Err(format!("invalid unary operator tag {tag}")),
    }
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn expect_magic(&mut self, magic: &[u8]) -> Result<(), String> {
        let actual = self.read_bytes(magic.len())?;
        if actual == magic {
            Ok(())
        } else {
            Err("invalid artifact magic".to_owned())
        }
    }

    fn expect_eof(&self) -> Result<(), String> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err("trailing bytes in artifact".to_owned())
        }
    }

    fn read_len(&mut self, what: &'static str) -> Result<usize, String> {
        usize::try_from(self.read_u32()?).map_err(|_| format!("{what} does not fit usize"))
    }

    fn read_option_u32(&mut self) -> Result<Option<u32>, String> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u32()?)),
            tag => Err(format!("invalid option tag {tag}")),
        }
    }

    fn read_bool(&mut self) -> Result<bool, String> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(format!("invalid bool tag {tag}")),
        }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_i64(&mut self) -> Result<i64, String> {
        let bytes = self.read_array::<8>()?;
        Ok(i64::from_le_bytes(bytes))
    }

    fn read_f64(&mut self) -> Result<f64, String> {
        let bytes = self.read_array::<8>()?;
        Ok(f64::from_le_bytes(bytes))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| "artifact cursor overflow".to_owned())?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| "unexpected end of artifact".to_owned())?;
        self.cursor = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::compile::resolve;
    use crate::syntax::parse_str;

    static TEST_ID: AtomicUsize = AtomicUsize::new(0);

    fn temp_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("aos-nix-parse-cache-{id}-{}", std::process::id()))
    }

    fn resolved_single_symbol(symbols: SymbolTable, symbol: Symbol) -> ResolvedAst {
        ResolvedAst {
            root: NodeId::new(0),
            arena: AstArena::from_raw_parts(
                vec![Node::new(
                    NodeKind::GlobalVar,
                    Span::new(0, 1),
                    NodeData::Symbol(symbol),
                )],
                Vec::new(),
            ),
            symbols,
            scopes: ScopeTables::from_raw_parts(
                Vec::new(),
                vec![None],
                Vec::new(),
                Vec::new(),
                vec![None],
            ),
        }
    }

    #[test]
    fn keys_depend_on_source_schema_and_flags() {
        let flags = ParseCacheFlags::new();
        assert_eq!(flags, ParseCacheFlags::default());
        let key = ParseCacheKey::for_source(b"let x = 1; in x", 7, flags);
        assert_eq!(key, ParseCacheKey::for_source(b"let x = 1; in x", 7, flags));
        assert_ne!(key, ParseCacheKey::for_source(b"let x = 2; in x", 7, flags));
        assert_ne!(key, ParseCacheKey::for_source(b"let x = 1; in x", 8, flags));
        assert_ne!(
            key,
            ParseCacheKey::for_source(
                b"let x = 1; in x",
                7,
                ParseCacheFlags {
                    retain_trivia: false,
                },
            )
        );
        assert_eq!(key.to_hex().len(), 64);
    }

    #[test]
    fn entry_paths_follow_rfc_layout() {
        let cache = ParseCache::new("/cache/parse");
        let entry = cache.entry_for_source(b"true");
        assert_eq!(entry.ir_path().file_name().expect("file name"), "ir.bin");
        assert_eq!(
            entry.resolved_path().file_name().expect("file name"),
            "resolved.bin"
        );
        assert_eq!(
            entry.symbols_path().file_name().expect("file name"),
            "symbols.bin"
        );
        assert_eq!(
            entry.meta_path().file_name().expect("file name"),
            "meta.toml"
        );
        assert_eq!(
            entry.dir().parent().expect("parent"),
            Path::new("/cache/parse")
        );
    }

    #[test]
    fn metadata_is_diagnostic_and_escaped_toml() {
        let meta = ParseCacheMeta::new(7, Some("pkgs/foo\"bar\n\u{7}baz.nix".to_owned()), 12, 3);
        assert_eq!(
            meta.to_toml(),
            "schema_version = 7\nsource_hint = \"pkgs/foo\\\"bar\\n\\u0007baz.nix\"\nnode_count = 12\nsymbol_count = 3\n"
        );
    }

    #[test]
    fn write_meta_creates_entry_directory() {
        let root = temp_root();
        let cache = ParseCache::new(root.join("parse"));
        let entry = cache.entry_for_source(b"builtins");
        let meta = ParseCacheMeta::new(cache.schema_version(), Some("expr".to_owned()), 1, 1);

        entry.write_meta(&meta).expect("metadata writes");
        let text = fs::read_to_string(entry.meta_path()).expect("metadata is readable");
        assert!(text.contains("schema_version = 4"));
        assert!(!entry.is_complete());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_or_parse_writes_then_hits_by_source_content() {
        let root = temp_root();
        let cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";

        let miss = cache
            .load_or_parse_bytes(source, Some("first.nix".to_owned()))
            .expect("source parses on miss");
        assert!(!miss.hit);
        assert!(miss.stored);
        assert!(miss.entry.is_complete());

        let hit = cache
            .load_or_parse_bytes(source, Some("second-name-is-not-identity.nix".to_owned()))
            .expect("source loads on hit");
        assert!(hit.hit);
        assert!(hit.stored);
        assert_eq!(hit.key, miss.key);
        assert_eq!(hit.resolved.arena.nodes(), miss.resolved.arena.nodes());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_or_parse_recovers_from_corrupt_artifact() {
        let root = temp_root();
        let cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";
        let first = cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses on miss");
        fs::write(first.entry.ir_path(), b"not an ir artifact").expect("corrupt ir writes");

        let recovered = cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source reparses after corrupt cache");
        assert!(!recovered.hit);
        assert!(recovered.stored);
        assert!(recovered.entry.is_complete());
        assert_eq!(
            recovered.resolved.arena.nodes(),
            first.resolved.arena.nodes()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_or_parse_recovers_from_mismatched_valid_artifacts() {
        let root = temp_root();
        let cache = ParseCache::new(root.join("parse"));
        let source = b"1";
        let first = cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses on miss");
        let other_resolved =
            resolve(parse_str("2").expect("other source parses")).expect("other source resolves");
        let other_ir = lower(file_local_resolved(&other_resolved).expect("other symbols remap"))
            .expect("other source lowers");
        fs::write(
            first.entry.ir_path(),
            encode_lowered_ir(&other_ir).expect("other IR encodes"),
        )
        .expect("mismatched IR writes");

        let recovered = cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source reparses after mismatched cache");
        assert!(!recovered.hit);
        assert!(recovered.stored);
        assert!(recovered.entry.is_complete());
        assert_eq!(
            recovered.resolved.arena.nodes(),
            first.resolved.arena.nodes()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_or_parse_treats_write_failures_as_cache_misses() {
        let root = temp_root();
        fs::write(&root, b"not a directory").expect("file cache root writes");
        let cache = ParseCache::new(root.join("parse"));

        let parsed = cache
            .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
            .expect("parse succeeds despite cache write failure");
        assert!(!parsed.hit);
        assert!(!parsed.stored);

        let _ = fs::remove_file(root);
    }

    #[cfg(unix)]
    #[test]
    fn file_memo_shares_artifacts_across_symlinked_paths() {
        use std::os::unix::fs::symlink;

        let root = temp_root();
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).expect("source dir creates");
        let source_path = src_dir.join("expr.nix");
        let link_path = src_dir.join("linked-expr.nix");
        fs::write(&source_path, b"let x = 1; in x").expect("source writes");
        symlink(&source_path, &link_path).expect("symlink creates");
        let mut memo = FileParseMemo::with_cache_root(root.join("parse"));

        let first = memo
            .load_or_parse_file(&source_path)
            .expect("source parses through real path");
        assert!(!first.memo_hit);
        assert!(!first.parsed.hit);
        assert!(first.parsed.stored);
        assert_eq!(
            first.file_key.realpath(),
            fs::canonicalize(&source_path)
                .expect("source canonicalizes")
                .as_path()
        );

        let second = memo
            .load_or_parse_file(&link_path)
            .expect("source parses through symlink path");
        assert!(second.memo_hit);
        assert_eq!(second.file_key, first.file_key);
        assert_eq!(second.parsed.key, first.parsed.key);
        assert_eq!(memo.len(), 1);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_memo_rekeys_when_file_content_changes() {
        let root = temp_root();
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).expect("source dir creates");
        let source_path = src_dir.join("expr.nix");
        fs::write(&source_path, b"let x = 1; in x").expect("source writes");
        let mut memo = FileParseMemo::with_cache_root(root.join("parse"));

        let first = memo
            .load_or_parse_file(&source_path)
            .expect("initial source parses");
        assert!(!first.memo_hit);
        assert_eq!(memo.len(), 1);

        fs::write(&source_path, b"let x = 2; in x").expect("changed source writes");
        let changed = memo
            .load_or_parse_file(&source_path)
            .expect("changed source parses");
        assert!(!changed.memo_hit);
        assert_eq!(first.file_key.realpath(), changed.file_key.realpath());
        assert_ne!(
            first.file_key.content_hash(),
            changed.file_key.content_hash()
        );
        assert_ne!(first.parsed.key, changed.parsed.key);
        assert_eq!(memo.len(), 2);

        let repeated = memo
            .load_or_parse_file(&source_path)
            .expect("changed source memoizes");
        assert!(repeated.memo_hit);
        assert_eq!(repeated.file_key, changed.file_key);
        assert_eq!(memo.len(), 2);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn serialization_remaps_symbols_to_file_local_ids() {
        let mut shifted_symbols = SymbolTable::new();
        shifted_symbols
            .intern(b"unused")
            .expect("unused symbol interns");
        let shifted_x = shifted_symbols.intern(b"x").expect("x symbol interns");
        let shifted = resolved_single_symbol(shifted_symbols, shifted_x);

        let mut local_symbols = SymbolTable::new();
        let local_x = local_symbols.intern(b"x").expect("local x interns");
        let local = resolved_single_symbol(local_symbols, local_x);

        let root = temp_root();
        let cache = ParseCache::new(root.join("parse"));
        let entry = cache.entry_for_source(b"symbol-remap");
        let meta = ParseCacheMeta::for_resolved(
            cache.schema_version(),
            Some("expr.nix".to_owned()),
            &shifted,
        )
        .expect("metadata counts file-local symbols");
        assert_eq!(meta.symbol_count, 1);

        entry
            .write_resolved(&shifted, &meta)
            .expect("shifted artifact writes");
        let loaded = entry.read_resolved().expect("shifted artifact reads");
        assert_eq!(loaded.symbols.symbols(), &[b"x".to_vec()]);
        assert_eq!(loaded.arena.nodes(), local.arena.nodes());
        assert_eq!(
            loaded.scopes.inherit_resolutions(),
            local.scopes.inherit_resolutions()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_serialized_symbols_are_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SYMBOL_MAGIC);
        write_u32(&mut bytes, ARTIFACT_VERSION);
        write_u32(&mut bytes, 2);
        write_u32(&mut bytes, 1);
        bytes.push(b'a');
        write_u32(&mut bytes, 1);
        bytes.push(b'a');

        let error = decode_symbols(&bytes).expect_err("duplicate symbol is invalid");
        assert!(error.contains("duplicate symbol"));
    }

    #[test]
    fn lowered_ir_rejects_inconsistent_node_payload_and_effect() {
        let invalid_payload = Ir {
            root: IrId::new(0),
            arena: IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::Null,
                    Span::new(0, 4),
                    EffectClass::Pure,
                    IrData::Bool(true),
                )],
                Vec::new(),
            ),
            symbols: SymbolTable::new(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        };
        let bytes = encode_lowered_ir(&invalid_payload).expect("invalid payload encodes");
        let error = decode_lowered_ir(&bytes, SymbolTable::new())
            .expect_err("invalid kind/data pair is rejected");
        assert!(error.contains("invalid IR data"));

        let invalid_effect = Ir {
            root: IrId::new(0),
            arena: IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::DerivationStrict,
                    Span::new(0, 16),
                    EffectClass::Pure,
                    IrData::Node(IrId::new(0)),
                )],
                Vec::new(),
            ),
            symbols: SymbolTable::new(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        };
        let bytes = encode_lowered_ir(&invalid_effect).expect("invalid effect encodes");
        let error = decode_lowered_ir(&bytes, SymbolTable::new())
            .expect_err("invalid node effect is rejected");
        assert!(error.contains("invalid IR effect"));

        let mut symbols = SymbolTable::new();
        let type_of = symbols.intern(b"typeOf").expect("typeOf interns");
        let invalid_primop_effect = Ir {
            root: IrId::new(1),
            arena: IrArena::from_raw_parts(
                vec![
                    IrNode::new(
                        IrKind::Bool,
                        Span::new(16, 20),
                        EffectClass::Pure,
                        IrData::Bool(true),
                    ),
                    IrNode::new(
                        IrKind::PrimOp,
                        Span::new(0, 20),
                        EffectClass::Effectful,
                        IrData::PrimOp {
                            symbol: type_of,
                            args: IrChildSlice::new(0, 1),
                        },
                    ),
                ],
                vec![IrId::new(0)],
            ),
            symbols: symbols.clone(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        };
        let bytes =
            encode_lowered_ir(&invalid_primop_effect).expect("invalid primop effect encodes");
        let error = decode_lowered_ir(&bytes, symbols).expect_err("pure primop effect is rejected");
        assert!(error.contains("invalid IR effect"));

        let mut symbols = SymbolTable::new();
        let future = symbols.intern(b"futurePrimop").expect("future interns");
        let unknown_primop = Ir {
            root: IrId::new(1),
            arena: IrArena::from_raw_parts(
                vec![
                    IrNode::new(
                        IrKind::Bool,
                        Span::new(20, 24),
                        EffectClass::Pure,
                        IrData::Bool(false),
                    ),
                    IrNode::new(
                        IrKind::PrimOp,
                        Span::new(0, 24),
                        EffectClass::Pure,
                        IrData::PrimOp {
                            symbol: future,
                            args: IrChildSlice::new(0, 1),
                        },
                    ),
                ],
                vec![IrId::new(0)],
            ),
            symbols: symbols.clone(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        };
        let bytes = encode_lowered_ir(&unknown_primop).expect("unknown primop encodes");
        let error = decode_lowered_ir(&bytes, symbols).expect_err("unknown primop is rejected");
        assert!(error.contains("unknown IR primop symbol"));
    }

    #[test]
    fn lowered_ir_rejects_inconsistent_attrset_shapes() {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("a interns");
        let b = symbols.intern(b"b").expect("b interns");
        let static_binding = IrBinding {
            key: IrAttrPathSegment::Static(a),
            value: IrId::new(0),
        };
        let invalid_shape = Ir {
            root: IrId::new(0),
            arena: IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::AttrSet,
                    Span::new(0, 9),
                    EffectClass::Pure,
                    IrData::AttrSet {
                        shape: IrShapeId::new(0),
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                )],
                Vec::new(),
            ),
            symbols: symbols.clone(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: vec![static_binding].into_boxed_slice(),
            shapes: vec![IrShape::new(vec![b].into_boxed_slice())].into_boxed_slice(),
        };
        let bytes = encode_lowered_ir(&invalid_shape).expect("invalid shape encodes");
        let error = decode_lowered_ir(&bytes, symbols.clone())
            .expect_err("invalid attrset shape is rejected");
        assert!(error.contains("shape does not match"));

        let invalid_dynamic_flag = Ir {
            root: IrId::new(0),
            arena: IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::AttrSet,
                    Span::new(0, 9),
                    EffectClass::Pure,
                    IrData::AttrSet {
                        shape: IrShapeId::new(0),
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: true,
                        frame: None,
                    },
                )],
                Vec::new(),
            ),
            symbols: symbols.clone(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: vec![static_binding].into_boxed_slice(),
            shapes: vec![IrShape::new(vec![a].into_boxed_slice())].into_boxed_slice(),
        };
        let bytes = encode_lowered_ir(&invalid_dynamic_flag).expect("invalid flag encodes");
        let error = decode_lowered_ir(&bytes, symbols)
            .expect_err("invalid attrset dynamic flag is rejected");
        assert!(error.contains("dynamic flag"));
    }

    #[test]
    fn resolved_artifacts_roundtrip_through_entry_files() {
        let root = temp_root();
        let cache = ParseCache::new(root.join("parse"));
        let source = "let outer = {}; x = 1; in with outer; rec { inherit x; y = x; }";
        let resolved = resolve(parse_str(source).expect("source parses")).expect("scope resolves");
        let entry = cache.entry_for_source(source.as_bytes());
        let meta = ParseCacheMeta::new(
            cache.schema_version(),
            Some("expr.nix".to_owned()),
            resolved.arena.len() as u32,
            resolved.symbols.len() as u32,
        );

        entry
            .write_resolved(&resolved, &meta)
            .expect("resolved artifact writes");
        assert!(entry.is_complete());

        let loaded = entry.read_resolved().expect("resolved artifact reads");
        assert_eq!(loaded.root, resolved.root);
        assert_eq!(loaded.arena.nodes(), resolved.arena.nodes());
        assert_eq!(loaded.arena.child_pool(), resolved.arena.child_pool());
        assert_eq!(loaded.symbols.symbols(), resolved.symbols.symbols());
        assert_eq!(loaded.scopes.frames(), resolved.scopes.frames());
        assert_eq!(loaded.scopes.node_frames(), resolved.scopes.node_frames());
        assert_eq!(loaded.scopes.with_chains(), resolved.scopes.with_chains());
        assert_eq!(
            loaded.scopes.inherit_resolutions(),
            resolved.scopes.inherit_resolutions()
        );
        assert_eq!(
            loaded.scopes.node_inherits(),
            resolved.scopes.node_inherits()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lowered_ir_artifacts_roundtrip_through_entry_files() {
        let root = temp_root();
        let cache = ParseCache::new(root.join("parse"));
        let source = r#"
            let
              name = "dyn";
            in rec {
              ${name} = builtins.getEnv "HOME";
              drv = derivationStrict { name = "x"; };
              flag = true;
              kind = builtins.typeOf flag;
              none = null;
              picked = with { fallback = 2; }; fallback;
            }
        "#;
        let resolved = resolve(parse_str(source).expect("source parses")).expect("scope resolves");
        let expected = lower(file_local_resolved(&resolved).expect("symbols remap"))
            .expect("resolved AST lowers");
        let entry = cache.entry_for_source(source.as_bytes());
        let meta = ParseCacheMeta::new(
            cache.schema_version(),
            Some("expr.nix".to_owned()),
            resolved.arena.len() as u32,
            resolved.symbols.len() as u32,
        );

        entry
            .write_resolved(&resolved, &meta)
            .expect("resolved artifact writes");
        assert!(entry.is_complete());

        let loaded = entry.read_ir().expect("lowered IR artifact reads");
        assert!(lowered_ir_matches(&loaded, &expected));

        let _ = fs::remove_dir_all(root);
    }
}
