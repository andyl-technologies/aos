//! The [`ParseArtifactBundle`] framing one complete parse-cache artifact set.

use super::*;

/// Raw bytes for one complete parse-cache artifact bundle.
///
/// The bundle frames the mandatory payloads that [`ParseCacheEntry`] stores as
/// separate files: `resolved.bin`, `ir.bin`, `symbols.bin`, and `meta.toml`.
/// It may also carry the optional `facts.bin` analysis sidecar; fact bytes are
/// still validated against the lowered-IR fingerprint before hydration writes
/// them to a cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseArtifactBundle {
    resolved: Vec<u8>,
    ir: Vec<u8>,
    symbols: Vec<u8>,
    meta_toml: Vec<u8>,
    facts: Option<Vec<u8>>,
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
            facts: None,
        }
    }

    /// Creates a bundle from raw parse-cache artifact bytes plus facts.
    pub fn new_with_facts(
        resolved: impl Into<Vec<u8>>,
        ir: impl Into<Vec<u8>>,
        symbols: impl Into<Vec<u8>>,
        meta_toml: impl Into<Vec<u8>>,
        facts: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            resolved: resolved.into(),
            ir: ir.into(),
            symbols: symbols.into(),
            meta_toml: meta_toml.into(),
            facts: Some(facts.into()),
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

    /// Returns the optional serialized fact sidecar bytes.
    pub fn facts_bytes(&self) -> Option<&[u8]> {
        self.facts.as_deref()
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

    /// Validates bundled metadata against the bundled parser artifacts.
    ///
    /// The metadata must decode, carry `expected_schema_version`, and report
    /// symbol and lowered-IR node counts that match the decoded `symbols.bin`
    /// and `ir.bin` payloads. The bundled `resolved.bin` artifact must also
    /// decode against the bundled symbols before any hydrated parse-cache entry
    /// is written.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCacheError`] if the metadata is malformed, carries a
    /// different schema version, a bundled artifact cannot be decoded, or the
    /// decoded artifact counts do not match metadata.
    pub fn validate_meta(
        &self,
        expected_schema_version: u32,
    ) -> Result<ParseCacheMeta, ParseCacheError> {
        let meta = self.decode_meta()?;
        if meta.schema_version != expected_schema_version {
            return Err(ParseCacheError::DecodeMeta {
                message: format!(
                    "metadata schema_version {} does not match expected {}",
                    meta.schema_version, expected_schema_version
                ),
            });
        }

        let symbols = decode_symbols(&self.symbols).map_err(|message| {
            ParseCacheError::DecodeArtifactBundle {
                message: format!("failed to decode bundled symbols.bin: {message}"),
            }
        })?;
        let symbol_count =
            u32::try_from(symbols.len()).map_err(|_| ParseCacheError::DecodeArtifactBundle {
                message: "bundled symbol_count exceeds u32".to_owned(),
            })?;
        if symbol_count != meta.symbol_count {
            return Err(ParseCacheError::DecodeMeta {
                message: format!(
                    "metadata symbol_count {} does not match bundled symbols.bin count {}",
                    meta.symbol_count, symbol_count
                ),
            });
        }

        let resolved = decode_resolved_ir(&self.resolved, symbols).map_err(|message| {
            ParseCacheError::DecodeArtifactBundle {
                message: format!("failed to decode bundled resolved.bin: {message}"),
            }
        })?;

        let ir = decode_lowered_ir(&self.ir, resolved.symbols).map_err(|message| {
            ParseCacheError::DecodeArtifactBundle {
                message: format!("failed to decode bundled ir.bin: {message}"),
            }
        })?;
        let node_count = u32::try_from(ir.arena.nodes().len()).map_err(|_| {
            ParseCacheError::DecodeArtifactBundle {
                message: "bundled node_count exceeds u32".to_owned(),
            }
        })?;
        if node_count != meta.node_count {
            return Err(ParseCacheError::DecodeMeta {
                message: format!(
                    "metadata node_count {} does not match bundled ir.bin node count {}",
                    meta.node_count, node_count
                ),
            });
        }

        Ok(meta)
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
        if let Some(facts) = &self.facts {
            encode_bundle_section(&mut out, facts, "fact artifact byte count")?;
        }
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
        let facts = if reader.is_eof() {
            None
        } else {
            Some(
                decode_bundle_section(&mut reader, "fact artifact byte count")
                    .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?,
            )
        };
        reader
            .expect_eof()
            .map_err(|message| ParseCacheError::DecodeArtifactBundle { message })?;
        Ok(Self {
            resolved,
            ir,
            symbols,
            meta_toml,
            facts,
        })
    }
}
