//! Closed parse results crossing from storage compute to logical admission.
//!
//! A source SHA/size authenticates the exact original file separately from the
//! normalized semantic fields. Unknown file content stays at object storage.

mod narinfo;
mod oci;

pub use oci::{
    aos_system, measure_oci_layer_metadata, parse_oci_zstd_content_size,
    validate_config_inspection_request, HybridOciDocumentProjection, HybridOciManifestProjection,
    OciImageConfigLayerSemantics, OciImageConfigSemanticsV1, OciInspectionDescriptor,
    OciLayerSizeMeasurement, MAX_HYBRID_OCI_PROJECTION_BYTES,
};

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
    /// Bounded OCI descriptor graph with separately attested source identity.
    OciManifest(HybridOciManifestProjection),
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
            Self::OciManifest(projection) => projection.validate(),
        }
    }

    /// Returns the original file SHA and byte size, never the parsed JSON hash.
    #[must_use]
    pub fn source_identity(&self) -> (&str, u32) {
        match self {
            Self::Narinfo(projection) => (&projection.source_sha256, projection.source_size),
            Self::OciManifest(projection) => (&projection.source_sha256, projection.source_size),
        }
    }
}

pub(super) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
