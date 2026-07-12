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

    /// Returns the optional analysis fact sidecar path.
    pub fn facts_path(&self) -> PathBuf {
        self.dir.join("facts.bin")
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

    /// Writes the serialized resolved arena, file-local symbols, facts, and metadata.
    ///
    /// Symbol ids are rewritten into a deterministic file-local table before
    /// `resolved.bin`, `ir.bin`, and `symbols.bin` are written, so artifacts do
    /// not inherit process-global interner allocation order. Diagnostic node and
    /// symbol counts are derived from the lowered IR artifact. The optional
    /// `facts.bin` sidecar is written on a best-effort basis; mandatory
    /// artifacts determine cache-entry completeness.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the entry directory cannot be created, the
    /// resolved artifact cannot be encoded, or any mandatory output file cannot
    /// be written.
    pub fn write_resolved(
        &self,
        resolved: &ResolvedAst,
        meta: &ParseCacheMeta,
    ) -> Result<(), ParseCacheError> {
        self.ensure_dir()?;
        let resolved = file_local_resolved(resolved)?;
        let mut ir =
            nix_lower(resolved.clone()).map_err(|source| ParseCacheError::LowerIr { source })?;
        let facts_version = simplify_lowered_ir(&mut ir)?;
        let meta = ParseCacheMeta::for_serialized_resolved(
            meta.schema_version,
            meta.source_hint.clone(),
            &resolved,
            &ir,
        )?;
        let ir_path = self.ir_path();
        let resolved_path = self.resolved_path();
        let symbols_path = self.symbols_path();
        let facts_path = self.facts_path();
        let meta_path = self.meta_path();
        let resolved_bytes = encode_resolved_ir(&resolved)?;
        let ir_bytes = encode_lowered_ir(&ir)?;
        let symbols_bytes = encode_symbols(&resolved.symbols)?;
        let ir_fingerprint = lowered_ir_artifact_fingerprint(&ir_bytes, &symbols_bytes);
        // Persist the facts under the version the simplifier left them at: a
        // freshly-lowered table is conservative (version 0, analysis-not-run), but
        // a fact-reading simplifier pass leaves them current at the real analysis
        // version, so a warm load can reuse them instead of re-analyzing.
        let facts_bytes = encode_ir_facts(&ir.facts, ir_fingerprint, facts_version)?;
        let meta_toml = meta.to_toml();

        let _ = fs::remove_file(&meta_path);
        let _ = fs::remove_file(&facts_path);
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
        let _ = write_cache_file_atomic(&facts_path, &facts_bytes);
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
        let facts_path = self.facts_path();
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
        let facts = read_valid_fact_sidecar(&facts_path, &ir, &symbols);
        Ok(match facts {
            Some(facts) => {
                ParseArtifactBundle::new_with_facts(resolved, ir, symbols, meta_toml, facts)
            }
            None => ParseArtifactBundle::new(resolved, ir, symbols, meta_toml),
        })
    }

    /// Writes a raw parse-cache artifact bundle into this entry.
    ///
    /// The metadata file is removed before payload files are written and
    /// rewritten last, so incomplete bundle hydration does not look like a
    /// complete cache entry. If the raw bundle carries a valid `facts.bin`
    /// sidecar for its lowered-IR artifact, it is written best-effort before
    /// metadata is committed; missing or invalid fact sections remove any stale
    /// sidecar and leave the hydrated entry conservative.
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
        let facts_path = self.facts_path();
        let meta_path = self.meta_path();

        let _ = fs::remove_file(&meta_path);
        let _ = fs::remove_file(&facts_path);
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
        if let Some(facts) = validated_bundle_fact_sidecar(bundle) {
            let _ = write_cache_file_atomic(&facts_path, facts);
        }
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

    /// Writes refreshed analysis facts for this entry's lowered IR artifact.
    ///
    /// The supplied IR is encoded and fingerprinted against the `ir.bin` and
    /// `symbols.bin` artifacts that are already present in the cache entry.
    /// Only `facts.bin` is updated; mandatory artifacts and diagnostic
    /// metadata are left unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the stored lowered IR artifacts cannot be
    /// read or decoded, the supplied IR or fact table cannot be encoded, the
    /// supplied IR does not match the stored artifact fingerprint, the fact
    /// table length does not match the stored node count, or `facts.bin` cannot
    /// be written.
    pub fn write_fact_sidecar(&self, ir: &Ir) -> Result<(), ParseCacheError> {
        let ir_path = self.ir_path();
        let symbols_path = self.symbols_path();
        let facts_path = self.facts_path();
        let stored_ir = fs::read(&ir_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: ir_path.clone(),
            source,
        })?;
        let stored_symbols =
            fs::read(&symbols_path).map_err(|source| ParseCacheError::ReadArtifact {
                path: symbols_path.clone(),
                source,
            })?;
        let stored_fingerprint = lowered_ir_artifact_fingerprint(&stored_ir, &stored_symbols);
        let stored_symbols =
            decode_symbols(&stored_symbols).map_err(|message| ParseCacheError::DecodeArtifact {
                path: symbols_path,
                message,
            })?;
        let stored_ir = decode_lowered_ir(&stored_ir, stored_symbols).map_err(|message| {
            ParseCacheError::DecodeArtifact {
                path: ir_path,
                message,
            }
        })?;
        let supplied_fingerprint = lowered_ir_fingerprint(ir)?;
        if supplied_fingerprint != stored_fingerprint {
            return Err(ParseCacheError::InvalidFactSidecarUpdate {
                path: facts_path,
                message: "supplied IR fingerprint does not match cached lowered IR artifact"
                    .to_owned(),
            });
        }

        let stored_node_count = stored_ir.arena.nodes().len();
        let fact_count = ir.facts.len();
        if fact_count != stored_node_count {
            return Err(ParseCacheError::InvalidFactSidecarUpdate {
                path: facts_path,
                message: format!(
                    "fact table length {fact_count} does not match lowered IR node count {stored_node_count}"
                ),
            });
        }

        let facts_bytes = encode_ir_facts(&ir.facts, stored_fingerprint, IR_ANALYSIS_VERSION)?;
        write_cache_file_atomic(&facts_path, &facts_bytes).map_err(|source| {
            ParseCacheError::WriteArtifact {
                path: facts_path,
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
    /// Returns the decoded IR and whether a valid `facts.bin` sidecar carrying
    /// the current [`IR_ANALYSIS_VERSION`] was applied — i.e. whether the
    /// analysis pipeline already ran for this artifact and needs no refresh.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if `ir.bin` or `symbols.bin` cannot be read
    /// or decoded. An unreadable or invalid optional `facts.bin` sidecar is
    /// ignored, leaving the decoded IR with conservative facts.
    pub(super) fn read_ir(&self) -> Result<(Ir, bool), ParseCacheError> {
        let ir_path = self.ir_path();
        let symbols_path = self.symbols_path();
        let facts_path = self.facts_path();
        let ir = fs::read(&ir_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: ir_path.clone(),
            source,
        })?;
        let symbols = fs::read(&symbols_path).map_err(|source| ParseCacheError::ReadArtifact {
            path: symbols_path.clone(),
            source,
        })?;
        let ir_fingerprint = lowered_ir_artifact_fingerprint(&ir, &symbols);
        let symbols =
            decode_symbols(&symbols).map_err(|message| ParseCacheError::DecodeArtifact {
                path: symbols_path,
                message,
            })?;
        let mut ir =
            decode_lowered_ir(&ir, symbols).map_err(|message| ParseCacheError::DecodeArtifact {
                path: ir_path,
                message,
            })?;
        let mut facts_current = false;
        if facts_path.is_file() {
            if let Ok(facts) = fs::read(&facts_path) {
                if let Ok((facts, analysis_version)) =
                    decode_ir_facts(&facts, ir.arena.nodes().len(), ir_fingerprint)
                {
                    let conservative = std::mem::replace(&mut ir.facts, facts);
                    if validate_lowered_ir_artifact(&ir).is_ok() {
                        facts_current = analysis_version == IR_ANALYSIS_VERSION;
                    } else {
                        ir.facts = conservative;
                    }
                }
            }
        }
        Ok((ir, facts_current))
    }
}

fn read_valid_fact_sidecar(path: &Path, ir_bytes: &[u8], symbols_bytes: &[u8]) -> Option<Vec<u8>> {
    let facts = fs::read(path).ok()?;
    valid_fact_sidecar(&facts, ir_bytes, symbols_bytes).then_some(facts)
}

fn validated_bundle_fact_sidecar(bundle: &ParseArtifactBundle) -> Option<&[u8]> {
    let facts = bundle.facts_bytes()?;
    valid_fact_sidecar(facts, bundle.ir_bytes(), bundle.symbols_bytes()).then_some(facts)
}

fn valid_fact_sidecar(facts: &[u8], ir_bytes: &[u8], symbols_bytes: &[u8]) -> bool {
    let ir_fingerprint = lowered_ir_artifact_fingerprint(ir_bytes, symbols_bytes);
    let Ok(symbols) = decode_symbols(symbols_bytes) else {
        return false;
    };
    let Ok(mut ir) = decode_lowered_ir(ir_bytes, symbols) else {
        return false;
    };
    let Ok((facts, _)) = decode_ir_facts(facts, ir.arena.nodes().len(), ir_fingerprint) else {
        return false;
    };
    ir.facts = facts;
    validate_lowered_ir_artifact(&ir).is_ok()
}
