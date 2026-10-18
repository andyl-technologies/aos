//! Data model for the documentation index.
//!
//! The index is a flat list of [`DocEntry`] records, each identified by a
//! dotted path (`functions.lists.head`, `builtins.map`, ...) and tagged with a
//! [`DocCategory`]. The whole
//! [`DocIndex`] serializes to JSON via serde so it can be cached on disk
//! between runs (see [`crate::cache`]).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current schema version for serialized documentation indexes.
pub const DOC_INDEX_SCHEMA_VERSION: u32 = 2;

/// The complete documentation index, serialized to JSON for caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocIndex {
    /// Cache schema version used to reject indexes with older body semantics.
    #[serde(default)]
    pub schema_version: u32,
    /// Unix timestamp when the index was built.
    pub built_at: u64,
    /// All documented entries.
    pub entries: Vec<DocEntry>,
}

/// A single documented language or library item.
///
/// Entries are produced by [`crate::extract::build_index`] from Nix doc
/// comments and compiled-in reference data. Most optional fields are only
/// populated when the corresponding markdown section (`# Type`,
/// `# Examples`, ...) is present in the source doc comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocEntry {
    /// Dotted path, e.g. `functions.lists.head` or `builtins.map`.
    pub path: String,
    /// What kind of thing this documents.
    pub category: DocCategory,
    /// First paragraph of the doc comment.
    pub summary: String,
    /// Additional markdown prose after the summary, excluding structured sections.
    pub body: String,
    /// Type signature from a `# Type` section.
    pub type_sig: Option<String>,
    /// Optional documented default value.
    pub default: Option<String>,
    /// Code examples from `# Examples` section.
    pub examples: Vec<String>,
    /// Cross-references from `# See Also` section.
    pub see_also: Vec<String>,
    /// Named parameters from `# Parameters` section: (name, description).
    pub parameters: Vec<(String, String)>,
    /// Source file path relative to the repo root.
    pub source_file: Option<String>,
    /// Line number in the source file (1-based).
    pub source_line: Option<usize>,
    /// Grouping section within a module (from `## # Heading` markers).
    pub section: Option<String>,
    /// Extensible metadata such as lifecycle notes from source comments.
    pub extra: BTreeMap<String, String>,
}

/// The kind of documented item.
///
/// The `Display` impl renders the short lowercase form used in CLI output
/// and JSON (`function`, `type`, or `language`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DocCategory {
    /// Nix builtins and lib.* functions.
    Function,
    /// Type definitions from lib.types.*.
    Type,
    /// Nix language reference entries.
    LanguageRef,
}

impl std::fmt::Display for DocCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocCategory::Function => write!(f, "function"),
            DocCategory::Type => write!(f, "type"),
            DocCategory::LanguageRef => write!(f, "language"),
        }
    }
}
