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

    /// Returns the single-file artifact bundle path.
    ///
    /// One entry stores all of its artifacts — resolved AST, lowered IR,
    /// file-local symbols, diagnostic metadata, and the optional analysis fact
    /// sidecar — framed into this one file by [`ParseArtifactBundle::encode`],
    /// rather than the five separate files of the pre-v12 layout. Collapsing
    /// the per-entry fan-out to one file cuts the parse cache's cold-populate
    /// and warm-read syscall count ~5x (RFC-0007 persist-write-batching-plan
    /// §11): the sys-time floor tracked the file *count*, not the payload size.
    pub fn bundle_path(&self) -> PathBuf {
        self.dir.join("bundle.bin")
    }

    /// Returns whether the entry's artifact bundle is present.
    pub fn is_complete(&self) -> bool {
        self.bundle_path().is_file()
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

        let bundle = ParseArtifactBundle::new_with_facts(
            resolved_bytes,
            ir_bytes,
            symbols_bytes,
            meta_toml.into_bytes(),
            facts_bytes,
        );
        self.write_bundle(&bundle)
    }

    /// Encodes and atomically writes an artifact bundle to this entry's file.
    ///
    /// The bundle is framed by [`ParseArtifactBundle::encode`] and written with
    /// [`write_cache_file_atomic`] (temp + `rename`), so a reader sees either
    /// the previous complete bundle or the new one, never a torn write.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the entry directory cannot be created,
    /// the bundle cannot be encoded, or the bundle file cannot be written.
    fn write_bundle(&self, bundle: &ParseArtifactBundle) -> Result<(), ParseCacheError> {
        self.ensure_dir()?;
        let payload = bundle.encode()?;
        let path = self.bundle_path();
        write_cache_file_atomic(&path, &payload)
            .map_err(|source| ParseCacheError::WriteArtifact { path, source })
    }

    /// Reads and decodes this entry's artifact bundle.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the bundle file cannot be read or its
    /// framing is invalid.
    fn read_bundle(&self) -> Result<ParseArtifactBundle, ParseCacheError> {
        let path = self.bundle_path();
        let bytes = fs::read(&path).map_err(|source| ParseCacheError::ReadArtifact {
            path: path.clone(),
            source,
        })?;
        ParseArtifactBundle::decode(&bytes)
    }

    /// Reads a complete parse-cache artifact bundle from this entry's file.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the bundle file cannot be read or its
    /// framing is invalid. The returned bundle carries raw section bytes;
    /// callers that need semantic validation should decode the sections.
    pub fn read_artifact_bundle(&self) -> Result<ParseArtifactBundle, ParseCacheError> {
        let bundle = self.read_bundle()?;
        // Drop a fact section that no longer validates against the bundle's own
        // lowered-IR artifact, preserving the pre-v12 behavior where an invalid
        // `facts.bin` sidecar was simply not carried into the hydrated bundle.
        if bundle.facts_bytes().is_some() && validated_bundle_fact_sidecar(&bundle).is_none() {
            return Ok(ParseArtifactBundle::new(
                bundle.resolved_bytes().to_vec(),
                bundle.ir_bytes().to_vec(),
                bundle.symbols_bytes().to_vec(),
                bundle.meta_toml_bytes().to_vec(),
            ));
        }
        Ok(bundle)
    }

    /// Writes a raw parse-cache artifact bundle into this entry's single file.
    ///
    /// The whole bundle is committed with one atomic write, so a reader sees
    /// either the previous complete entry or the new one. A fact section that
    /// does not validate against the bundle's own lowered-IR artifact is
    /// dropped, leaving the hydrated entry conservative — preserving the
    /// pre-v12 behavior where an invalid `facts.bin` sidecar was not written.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the entry directory cannot be created or
    /// the bundle file cannot be encoded or written.
    pub fn write_artifact_bundle(
        &self,
        bundle: &ParseArtifactBundle,
    ) -> Result<(), ParseCacheError> {
        if bundle.facts_bytes().is_some() && validated_bundle_fact_sidecar(bundle).is_none() {
            let conservative = ParseArtifactBundle::new(
                bundle.resolved_bytes().to_vec(),
                bundle.ir_bytes().to_vec(),
                bundle.symbols_bytes().to_vec(),
                bundle.meta_toml_bytes().to_vec(),
            );
            return self.write_bundle(&conservative);
        }
        self.write_bundle(bundle)
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
    /// The supplied IR is fingerprinted against the lowered-IR and symbol
    /// sections already stored in this entry's bundle. On a match the bundle is
    /// rewritten with the refreshed fact section replacing the previous one;
    /// the mandatory sections and diagnostic metadata are re-serialized
    /// byte-for-byte from the stored bundle, so only the fact section changes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the stored bundle cannot be read or
    /// decoded, the supplied fact table cannot be encoded, the supplied IR does
    /// not match the stored artifact fingerprint, the fact table length does
    /// not match the stored node count, or the bundle cannot be written.
    pub fn write_fact_sidecar(&self, ir: &Ir) -> Result<(), ParseCacheError> {
        let bundle_path = self.bundle_path();
        let stored = self.read_bundle()?;
        let stored_fingerprint =
            lowered_ir_artifact_fingerprint(stored.ir_bytes(), stored.symbols_bytes());
        let stored_symbols = decode_symbols(stored.symbols_bytes()).map_err(|message| {
            ParseCacheError::DecodeArtifact {
                path: bundle_path.clone(),
                message,
            }
        })?;
        let stored_ir =
            decode_lowered_ir(stored.ir_bytes(), stored_symbols).map_err(|message| {
                ParseCacheError::DecodeArtifact {
                    path: bundle_path.clone(),
                    message,
                }
            })?;
        let supplied_fingerprint = lowered_ir_fingerprint(ir)?;
        if supplied_fingerprint != stored_fingerprint {
            return Err(ParseCacheError::InvalidFactSidecarUpdate {
                path: bundle_path,
                message: "supplied IR fingerprint does not match cached lowered IR artifact"
                    .to_owned(),
            });
        }

        let stored_node_count = stored_ir.arena.nodes().len();
        let fact_count = ir.facts.len();
        if fact_count != stored_node_count {
            return Err(ParseCacheError::InvalidFactSidecarUpdate {
                path: bundle_path,
                message: format!(
                    "fact table length {fact_count} does not match lowered IR node count {stored_node_count}"
                ),
            });
        }

        let facts_bytes = encode_ir_facts(&ir.facts, stored_fingerprint, IR_ANALYSIS_VERSION)?;
        let refreshed = ParseArtifactBundle::new_with_facts(
            stored.resolved_bytes().to_vec(),
            stored.ir_bytes().to_vec(),
            stored.symbols_bytes().to_vec(),
            stored.meta_toml_bytes().to_vec(),
            facts_bytes,
        );
        self.write_bundle(&refreshed)
    }

    /// Reads a resolved AST artifact from this cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the bundle cannot be read or its resolved
    /// or symbol sections cannot be decoded.
    pub fn read_resolved(&self) -> Result<ResolvedAst, ParseCacheError> {
        self.decode_resolved(&self.read_bundle()?)
    }

    /// Reads a lowered IR artifact from this cache entry.
    ///
    /// Returns the decoded IR and whether a valid fact section carrying the
    /// current [`IR_ANALYSIS_VERSION`] was applied — i.e. whether the analysis
    /// pipeline already ran for this artifact and needs no refresh.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the bundle cannot be read or its IR or
    /// symbol sections cannot be decoded. An invalid optional fact section is
    /// ignored, leaving the decoded IR with conservative facts.
    pub(super) fn read_ir(&self) -> Result<(Ir, bool), ParseCacheError> {
        self.decode_ir_with_facts(&self.read_bundle()?)
    }

    /// Reads both the resolved AST and lowered IR from this entry in one open.
    ///
    /// The single warm-load read: the bundle file is read once and both
    /// artifacts are decoded from the in-memory sections, replacing the pre-v12
    /// [`read_resolved`](Self::read_resolved) + [`read_ir`](Self::read_ir)
    /// pair's per-section reopen storm.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the bundle cannot be read or any mandatory
    /// section cannot be decoded.
    pub(super) fn read_resolved_and_ir(
        &self,
    ) -> Result<(ResolvedAst, Ir, bool), ParseCacheError> {
        let bundle = self.read_bundle()?;
        let resolved = self.decode_resolved(&bundle)?;
        let (ir, facts_current) = self.decode_ir_with_facts(&bundle)?;
        Ok((resolved, ir, facts_current))
    }

    /// Decodes the resolved AST from an already-read bundle.
    fn decode_resolved(&self, bundle: &ParseArtifactBundle) -> Result<ResolvedAst, ParseCacheError> {
        let path = self.bundle_path();
        let symbols = decode_symbols(bundle.symbols_bytes())
            .map_err(|message| ParseCacheError::DecodeArtifact { path: path.clone(), message })?;
        decode_resolved_ir(bundle.resolved_bytes(), symbols)
            .map_err(|message| ParseCacheError::DecodeArtifact { path, message })
    }

    /// Decodes the lowered IR and fact-currency flag from an already-read bundle.
    fn decode_ir_with_facts(
        &self,
        bundle: &ParseArtifactBundle,
    ) -> Result<(Ir, bool), ParseCacheError> {
        let path = self.bundle_path();
        let ir_fingerprint =
            lowered_ir_artifact_fingerprint(bundle.ir_bytes(), bundle.symbols_bytes());
        let symbols = decode_symbols(bundle.symbols_bytes())
            .map_err(|message| ParseCacheError::DecodeArtifact { path: path.clone(), message })?;
        let mut ir = decode_lowered_ir(bundle.ir_bytes(), symbols)
            .map_err(|message| ParseCacheError::DecodeArtifact { path, message })?;
        let mut facts_current = false;
        if let Some(facts) = bundle.facts_bytes() {
            if let Ok((facts, analysis_version)) =
                decode_ir_facts(facts, ir.arena.nodes().len(), ir_fingerprint)
            {
                let conservative = std::mem::replace(&mut ir.facts, facts);
                if validate_lowered_ir_artifact(&ir).is_ok() {
                    facts_current = analysis_version == IR_ANALYSIS_VERSION;
                } else {
                    ir.facts = conservative;
                }
            }
        }
        Ok((ir, facts_current))
    }
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
