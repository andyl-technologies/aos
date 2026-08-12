//! Diagnostic metadata ([`ParseCacheMeta`]) written beside each parse-cache artifact.

use super::*;

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
        let ir =
            nix_lower(resolved.clone()).map_err(|source| ParseCacheError::LowerIr { source })?;
        Self::for_serialized_resolved(schema_version, source_hint, &resolved, &ir)
    }

    pub(super) fn for_serialized_resolved(
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
