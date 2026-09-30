//! Shared readers and renderers for native AOS module documentation.
//!
//! [`runtime`] validates evaluator-generated declarations and desired
//! transactions, renders them, and derives search and comparison views.
//! [`artifact_consumption`] checks independent realized-file evidence. NAR
//! readers preserve exact immutable document bytes for publication consumers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use aos_ability_model::{OptionType, OptionVisibility as Visibility};

pub mod artifact_consumption;
mod nar;
pub mod runtime;

pub use nar::{
    NarRoot, decode_document_root_nar, decode_native_artifact_nar, decode_native_documentation_nar,
    decode_single_file_nar,
};

/// Bounds a single-document regular-file NAR.
pub const MAX_DOCUMENT_BYTES: usize = 12 * 1024 * 1024;

/// Reports decoding, validation, and rendering failures for native documents.
#[derive(Debug, Error)]
pub enum DocumentationError {
    /// The input cannot be decoded as the requested JSON contract.
    #[error("invalid native documentation JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A native document or artifact invariant is violated.
    #[error("invalid native documentation: {0}")]
    Invalid(String),
}

/// Returns a value or a native documentation failure.
pub type Result<T> = std::result::Result<T, DocumentationError>;

/// Carries a deterministic search row generated from native declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchDocument {
    /// Result kind (`package`, `option`, or native `operation`).
    pub kind: String,
    /// Stable document-local key.
    pub key: String,
    /// Human title.
    pub title: String,
    /// Bounded plain-text summary.
    pub summary: String,
    /// Normalized deterministic terms with integer weights.
    pub terms: BTreeMap<String, u16>,
}

/// Returns a stable, collision-free HTML anchor for a kind and literal key.
///
/// Hex encoding preserves punctuation and UTF-8 bytes without joining path
/// segments or accepting author-supplied HTML attribute syntax.
#[must_use]
pub fn documentation_anchor(kind: &str, key: &str) -> String {
    let mut anchor = String::from("doc");
    for value in [kind, key] {
        anchor.push(':');
        for byte in value.bytes() {
            let _ = write!(anchor, "{byte:02x}");
        }
    }
    anchor
}

/// Tokenizes bounded document text into deterministic lowercase search terms.
///
/// Terms contain Unicode letters or numbers, have at most 64 UTF-8 bytes, and
/// are deduplicated and sorted. At most 2,048 terms are returned.
pub fn tokenize(input: &str) -> Vec<String> {
    let mut terms = BTreeSet::new();
    let normalized = input.to_lowercase();
    for token in normalized
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| token.len() >= 2 && token.len() <= 64)
    {
        terms.insert(token.to_string());
    }
    terms.into_iter().take(2048).collect()
}

fn validate_option_type(option_type: &OptionType) -> Result<()> {
    if option_type.is_within_limits(&aos_ability_model::ABILITY_LIMITS_V1) {
        Ok(())
    } else {
        Err(invalid("option type exceeds the canonical ability limits"))
    }
}

fn invalid(message: impl Into<String>) -> DocumentationError {
    DocumentationError::Invalid(message.into())
}

fn search_row<'a, const N: usize>(
    kind: &str,
    key: &str,
    title: &str,
    summary: &str,
    sources: [(&'a str, u16); N],
) -> SearchDocument {
    let mut terms: BTreeMap<String, u16> = BTreeMap::new();
    for (source, weight) in sources {
        for term in tokenize(source) {
            terms
                .entry(term)
                .and_modify(|existing| *existing = (*existing).max(weight))
                .or_insert(weight);
        }
    }
    SearchDocument {
        kind: kind.to_string(),
        key: key.to_string(),
        title: title.to_string(),
        summary: summary.chars().take(1024).collect(),
        terms,
    }
}

fn escape_html_into(input: &str, output: &mut String) {
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
}
