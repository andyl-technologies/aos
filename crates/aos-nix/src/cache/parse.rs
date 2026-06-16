//! Content-addressed parse artifact cache.
//!
//! The parse cache is keyed only by deterministic inputs to frontend parsing:
//! source bytes, the evaluator schema version, and relevant parser flags. Entry
//! paths follow the RFC-0007 layout:
//!
//! ```text
//! $AOS_NIX_CACHE/parse/<blake3-key>/
//!   ir.bin
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
    FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, ResolvedAst, ScopeError,
    ScopeTables, Upvalue, WithChain, resolve,
};
use crate::syntax::{
    AstArena, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind, ParseError, Span, Symbol,
    SymbolTable, UnaryOpKind, parse_bytes,
};

/// The schema version included in every parse-cache key and metadata file.
pub const PARSE_CACHE_SCHEMA_VERSION: u32 = 1;

const KEY_PERSONALIZATION: &[u8] = b"aos-nix-parse-cache-key-v1";
const FLAG_ENCODING_VERSION: u8 = 1;
const IR_MAGIC: &[u8; 8] = b"AOSNIXIR";
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
                return Ok(CachedParse {
                    key,
                    entry,
                    resolved,
                    hit: true,
                    stored: true,
                });
            }
        }

        let parsed = parse_bytes(source).map_err(|source| ParseCacheError::Parse { source })?;
        let resolved = resolve(parsed).map_err(|source| ParseCacheError::Scope { source })?;
        let meta = ParseCacheMeta::for_resolved(self.schema_version, source_hint, &resolved)?;
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
        self.ir_path().is_file() && self.symbols_path().is_file() && self.meta_path().is_file()
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
        let ir_path = self.ir_path();
        let symbols_path = self.symbols_path();
        fs::write(&ir_path, encode_resolved_ir(resolved)?).map_err(|source| {
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
        self.write_meta(meta)
    }

    /// Reads a resolved AST artifact from this cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if `ir.bin` or `symbols.bin` cannot be read
    /// or decoded.
    pub fn read_resolved(&self) -> Result<ResolvedAst, ParseCacheError> {
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
        decode_resolved_ir(&ir, symbols).map_err(|message| ParseCacheError::DecodeArtifact {
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
    /// Number of arena nodes in the serialized artifact.
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
        let node_count = u32::try_from(resolved.arena.len())
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
    out.extend_from_slice(IR_MAGIC);
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
    reader.expect_magic(IR_MAGIC)?;
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
        assert!(text.contains("schema_version = 1"));
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
}
