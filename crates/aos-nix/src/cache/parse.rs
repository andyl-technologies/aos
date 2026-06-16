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
//! `ir.bin` and `symbols.bin` serialization are intentionally left to the IR
//! serialization pass. This module owns the stable key and entry layout those
//! writers use.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// The schema version included in every parse-cache key and metadata file.
pub const PARSE_CACHE_SCHEMA_VERSION: u32 = 1;

const KEY_PERSONALIZATION: &[u8] = b"aos-nix-parse-cache-key-v1";
const FLAG_ENCODING_VERSION: u8 = 1;

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

/// A parse-cache filesystem failure.
#[derive(Debug, Error)]
pub enum ParseCacheError {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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
}
