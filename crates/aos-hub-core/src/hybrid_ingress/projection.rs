//! Closed parse results crossing from storage compute to logical admission.
//!
//! A source SHA/size authenticates the exact original file separately from the
//! normalized semantic fields. Unknown file content stays at object storage.

mod narinfo;

pub use narinfo::{
    HybridNarinfoProjection, HybridNarinfoSignature, MAX_HYBRID_NARINFO_PROJECTION_BYTES,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Closed storage-side semantic result used by metadata-only completion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "projection",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HybridObjectProjection {
    /// Nix signing and normalized cache-index metadata.
    Narinfo(HybridNarinfoProjection),
}

impl HybridObjectProjection {
    /// Validates the closed result and its encoded bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid semantic fields or original source identity.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Narinfo(projection) => projection.validate(),
        }
    }

    /// Returns the original file SHA and byte size, never the parsed JSON hash.
    #[must_use]
    pub fn source_identity(&self) -> (&str, u32) {
        match self {
            Self::Narinfo(projection) => (&projection.source_sha256, projection.source_size),
        }
    }
}

pub(super) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
