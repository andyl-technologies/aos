//! Closed OCI metadata parsed beside the exact stored object bytes.
//!
//! Original SHA-256 and byte length identify storage content independently of
//! this semantic projection. Re-encoding a projection never establishes an
//! uploaded object's digest. All three parsers retain the shared 4 MiB input
//! and canonical metadata bounds used by every Hub runtime.
//!
//! ```text
//! stored projection = exact descriptor + parsed manifest | index | config
//! ```

use anyhow::{ensure, Result};
use aos_oci_types::{Descriptor, ImageConfig, ImageIndex, ImageManifest, MediaType, Sha256Digest};
use serde::{Deserialize, Serialize};

pub mod guard;

/// Bounds one document projection and its explicit control envelope.
///
/// Each accepted OCI type already limits its canonical encoding to 4 MiB.
/// The extra 64 KiB covers the closed original, provider identity and challenge;
/// it does not reduce the ordinary document input limit.
pub const MAX_OCI_PROJECTION_BYTES: usize = aos_oci_types::limits::MAX_JSON_BYTES + 64 * 1024;

/// Carries parsed metadata without the original document serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "document",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OciDocumentProjection {
    /// An OCI or Docker schema 2 image manifest.
    Manifest(ImageManifest),
    /// An OCI index or Docker manifest list.
    Index(ImageIndex),
    /// An OCI or Docker image configuration.
    Config(ImageConfig),
}

impl OciDocumentProjection {
    /// Parses exact stored bytes after checking their original descriptor.
    ///
    /// # Errors
    /// Returns an error for changed digest/size, oversized input, unsupported
    /// media type, malformed JSON or any shared OCI structural violation.
    pub fn from_stored_bytes(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        descriptor.validate()?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= aos_oci_types::limits::MAX_JSON_BYTES
                && bytes.len() as u64 == descriptor.size
                && Sha256Digest::digest(bytes) == descriptor.digest,
            "stored OCI document differs from its exact descriptor"
        );
        let projection = if descriptor.media_type.is_image_manifest() {
            Self::Manifest(ImageManifest::from_json(bytes)?)
        } else if descriptor.media_type.is_image_index() {
            Self::Index(ImageIndex::from_json(bytes)?)
        } else if descriptor.media_type.is_image_config() {
            Self::Config(ImageConfig::from_json(bytes)?)
        } else {
            anyhow::bail!("stored OCI document has an unsupported media type");
        };
        projection.validate(descriptor.media_type)?;
        Ok(projection)
    }

    /// Validates a decoded projection against its original media type.
    ///
    /// This establishes semantic shape, never original-byte identity.
    ///
    /// # Errors
    /// Returns an error for a different document kind, conflicting outer media
    /// type, invalid nested OCI metadata or an oversized canonical projection.
    pub fn validate(&self, media_type: MediaType) -> Result<()> {
        match self {
            Self::Manifest(document) => {
                ensure!(
                    media_type.is_image_manifest(),
                    "OCI projection kind differs"
                );
                document.validate()?;
                ensure!(
                    document.media_type.is_none_or(|outer| outer == media_type),
                    "manifest Content-Type conflicts with its mediaType field"
                );
            }
            Self::Index(document) => {
                ensure!(media_type.is_image_index(), "OCI projection kind differs");
                document.validate()?;
                ensure!(
                    document.media_type.is_none_or(|outer| outer == media_type),
                    "index Content-Type conflicts with its mediaType field"
                );
            }
            Self::Config(document) => {
                ensure!(media_type.is_image_config(), "OCI projection kind differs");
                document.validate()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

// This private commitment is retained in the upload's existing idempotency
// field. Both request preparation and the final SQL plan derive it from the
// same exact current target tuple; no timestamp acts as an incarnation.
pub(crate) fn manifest_original_digest(
    registry_id: i64,
    repository_id: i64,
    owner: &str,
    reference: &aos_oci_types::ManifestReference,
    media_type: aos_oci_types::MediaType,
    placement: &crate::db::SurfacePlacementRecord,
    binding: &crate::db::BindingRecord,
    write_revision: i64,
    authority: &crate::db::SurfaceWriteAuthorityRecord,
) -> anyhow::Result<String> {
    use sha2::{Digest as _, Sha256};
    let original = (
        (
            registry_id,
            repository_id,
            owner,
            reference.to_string(),
            media_type,
        ),
        (
            placement.id,
            placement.resource_version,
            placement.write_spec_version,
            &placement.prefix,
        ),
        (
            binding.id,
            &binding.stable_id,
            binding.resource_version,
            write_revision,
        ),
        (
            authority.id,
            &authority.incarnation_id,
            authority.resource_version,
            authority.desired_generation,
            authority.observed_generation,
        ),
    );
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&original)?)))
}
