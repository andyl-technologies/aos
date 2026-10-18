//! Bounded admission profile for portable artifact evidence.
//!
//! These ceilings preserve version-1 evidence decoding independently of module
//! graph limits. They are consumer admission settings, not serialized fields in
//! the artifact-consumption evidence envelope.

/// Defines effective bounds for decoding one canonical evidence document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitProfile {
    /// Maximum canonical document size in bytes.
    pub max_document_bytes: u64,
    /// Maximum JSON nesting depth.
    pub max_structural_depth: u32,
    /// Maximum total collection members in one document.
    pub max_collection_items: u64,
    /// Maximum UTF-8 byte length of one string or member name.
    pub max_string_bytes: u64,
}

/// Supplies the admission ceilings fixed by the version-1 evidence format.
pub const EVIDENCE_LIMITS_V1: LimitProfile = LimitProfile {
    max_document_bytes: 32 * 1024 * 1024,
    max_structural_depth: 64,
    max_collection_items: 2_000_000,
    max_string_bytes: 1024 * 1024,
};

impl LimitProfile {
    /// Reports whether every bound is nonzero and fits the version-1 ceiling.
    #[must_use]
    pub fn is_admissible_v1(&self) -> bool {
        let ceiling = EVIDENCE_LIMITS_V1;
        self.max_document_bytes > 0
            && self.max_document_bytes <= ceiling.max_document_bytes
            && self.max_structural_depth > 0
            && self.max_structural_depth <= ceiling.max_structural_depth
            && self.max_collection_items > 0
            && self.max_collection_items <= ceiling.max_collection_items
            && self.max_string_bytes > 0
            && self.max_string_bytes <= ceiling.max_string_bytes
    }
}
