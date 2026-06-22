//! The [`ParseCacheEntry`] type owning one parse-cache entry's filesystem layout.

use super::*;

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

    /// Validates bundled metadata and artifact counts before writing a bundle.
    ///
    /// The bundle's metadata must decode, carry `expected_schema_version`, and
    /// match the decoded symbol and lowered-IR node counts before any
    /// cache-entry files are created or overwritten. On success the raw bundle
    /// is written with [`Self::write_artifact_bundle`] and the decoded metadata
    /// is returned.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if bundle validation fails, the entry
    /// directory cannot be created, or any bundled artifact file cannot be
    /// written.
    pub fn write_artifact_bundle_validated(
        &self,
        bundle: &ParseArtifactBundle,
        expected_schema_version: u32,
    ) -> Result<ParseCacheMeta, ParseCacheError> {
        let meta = bundle.validate_meta(expected_schema_version)?;
        self.write_artifact_bundle(bundle)?;
        Ok(meta)
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
    pub(super) fn read_ir(&self) -> Result<Ir, ParseCacheError> {
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
