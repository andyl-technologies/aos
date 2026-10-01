//! Immutable per-object mirror originals and bounded storage-local progress.
//!
//! Native selects upstream trust and a reconciled managed R2 writer. A Worker
//! moves and verifies bytes under this original; fresh storage-work plans admit
//! each bounded mutation. Scheduler leases never replace originals or settle
//! unknown effects. The private stage and final provider incarnations are part
//! of positive progress, rather than inferred from HTTP success or absence.
//!
//! ```json
//! {"kind":"upload_parts","first_part":1,"maximum_parts":4}
//! ```

use anyhow::{ensure, Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::storage_work::{valid_provider_version, StorageObjectIdentity, StorageWorkPlan};

/// Maximum bytes buffered for one producer multipart part.
pub const MIRROR_PART_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum independent parts admitted by one bounded storage control.
pub const MIRROR_MAX_PARTS_PER_STEP: u32 = 4;
/// Maximum compressed or decompressed source admitted by the mirror verifier.
/// Both limits apply independently: a representation smaller than this bound
/// is refused when its selected uncompressed NAR size exceeds the bound.
pub const MIRROR_MAX_OBJECT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Selects the exact content proof required before mirror publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorVerification {
    /// Exact bounded metadata or decoded-then-verified loose-object bytes.
    Sha256 {
        /// Native-observed digest of the exact verified representation.
        sha256: String,
        /// Exact representation length.
        size: u64,
    },
    /// Native-selected uncompressed NAR identity and optional compressed checksum.
    Nar {
        /// Optional upstream compressed file checksum, never a trust substitute.
        file_sha256: Option<String>,
        /// Exact compressed representation size selected from bounded metadata.
        file_size: u64,
        /// Explicit supported wire compression (`none` or `zstd`).
        compression: String,
        /// SHA-256 from the exact Native-selected narinfo. Native verifies its
        /// signature when the pinned mirror configuration requires signatures;
        /// deliberate unsigned policy supplies consistency, not authentication.
        nar_sha256: String,
        /// Uncompressed length selected under that same pinned trust policy.
        nar_size: u64,
    },
}

impl MirrorVerification {
    /// Returns the exact encoded source length.
    #[must_use]
    pub fn size(&self) -> u64 {
        match self {
            Self::Sha256 { size, .. } => *size,
            Self::Nar { file_size, .. } => *file_size,
        }
    }

    /// Checks bounded identities without reading an object body.
    ///
    /// # Errors
    /// Returns an error for malformed hashes, unsupported compression or size.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.size() <= MIRROR_MAX_OBJECT_BYTES,
            "mirror source exceeds its bound"
        );
        match self {
            Self::Sha256 { sha256, .. } => ensure!(hex_digest(sha256), "mirror digest is invalid"),
            Self::Nar {
                file_sha256,
                compression,
                nar_sha256,
                nar_size,
                ..
            } => {
                ensure!(
                    self.size() > 0
                        && file_sha256.as_ref().is_none_or(|value| hex_digest(value))
                        && hex_digest(nar_sha256)
                        && (1..=MIRROR_MAX_OBJECT_BYTES).contains(nar_size)
                        && matches!(compression.as_str(), "none" | "zstd"),
                    "mirror NAR identity or compression is unsupported"
                );
            }
        }
        Ok(())
    }
}

/// Retains one trust-selected source and its original managed destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorOriginal {
    /// Closed format version.
    pub version: u32,
    /// Deterministic SHA-256 identity of this immutable original.
    pub job_id: String,
    /// Native business operation retained independently of leases and retries.
    /// Absent only in canonical originals admitted before generation 6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_operation_id: Option<String>,
    /// Registry whose Native controller selected the source.
    pub registry_id: i64,
    /// Current registry configuration version at original admission.
    pub registry_resource_version: i64,
    /// Original mirror source configuration version, including trust policy.
    pub mirror_resource_version: i64,
    /// Exact configured upstream base; never a provider bearer URL.
    pub upstream_base: String,
    /// Surface-relative source and final destination path.
    pub path: String,
    /// Exact reconciled destination placement.
    pub placement_id: i64,
    /// Original placement resource version.
    pub placement_resource_version: i64,
    /// Original writer specification version.
    pub write_spec_version: i64,
    /// Original managed deployment binding.
    pub binding_id: i64,
    /// Original binding resource version.
    pub binding_resource_version: i64,
    /// Exact physical placement prefix.
    pub placement_prefix: String,
    /// Independently accepted managed profile, private policy and runtime digest.
    pub protected_profile_digest: String,
    /// Content proof selected by Native after trust verification.
    pub verification: MirrorVerification,
}

impl MirrorOriginal {
    /// Derives the immutable operation identity from every original field.
    ///
    /// # Errors
    /// Returns an error when the original cannot be encoded.
    pub fn identity(&self) -> Result<String> {
        let mut original = self.clone();
        original.job_id.clear();
        digest(&original)
    }

    /// Commits the complete source path without shortening its existing bound.
    #[must_use]
    pub fn source_path_digest(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"aos.hub.mirror-source-path.v1\0");
        hash.update(self.path.as_bytes());
        hex::encode(hash.finalize())
    }

    /// Validates a retained original independently of an invocation lease.
    ///
    /// # Errors
    /// Returns an error for changed identity, unsafe source or invalid pins.
    pub fn validate(&self) -> Result<()> {
        let upstream = url::Url::parse(&self.upstream_base)?;
        ensure!(
            self.version == 1
                && self.job_id == self.identity()?
                && self
                    .copy_operation_id
                    .as_ref()
                    .is_none_or(|id| id.len() == 32
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
                && self.registry_id > 0
                && self.registry_resource_version > 0
                && self.mirror_resource_version > 0
                && self.placement_id > 0
                && self.placement_resource_version > 0
                && self.write_spec_version > 0
                && self.binding_id > 0
                && self.binding_resource_version > 0
                && hex_digest(&self.protected_profile_digest)
                && upstream.scheme() == "https"
                && upstream.username().is_empty()
                && upstream.password().is_none()
                && upstream.query().is_none()
                && upstream.fragment().is_none()
                && crate::storage_work::valid_relative_path(&self.path, false)
                && crate::storage_work::valid_relative_path(&self.placement_prefix, true)
                && !self
                    .path
                    .split('/')
                    .any(|segment| segment.starts_with(".aos-")),
            "mirror original has invalid source, destination or identity"
        );
        crate::url_guard::is_safe_remote_url(&self.upstream_base)?;
        ensure!(
            serde_json::to_vec(self)?.len() <= 64 * 1024,
            "mirror original exceeds its retained bound"
        );
        self.verification.validate()
    }

    /// Binds a fresh mutation plan to the exact retained original.
    ///
    /// # Errors
    /// Returns an error when any managed destination pin differs.
    pub fn validate_plan(&self, plan: &StorageWorkPlan) -> Result<()> {
        self.validate()?;
        ensure!(
            plan.binding_kind == "deployment_r2"
                && plan.binding_snapshot_revision.is_none()
                && plan.credential_references.is_empty()
                && plan.placement_id == self.placement_id
                && plan.placement_resource_version == self.placement_resource_version
                && plan.binding_id == self.binding_id
                && plan.binding_resource_version == self.binding_resource_version
                && plan.placement_prefix == self.placement_prefix,
            "mirror plan changed its original destination"
        );
        Ok(())
    }

    /// Returns the reserved private physical source key for this original.
    #[must_use]
    pub fn stage_key(&self) -> String {
        format!(".aos-direct-upload/mirror/{}/source", self.job_id)
    }
}

/// Admits one bounded phase under fresh Native authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorStep {
    /// Reads retained progress without provider mutation or uncertainty replay.
    Status { destination: bool },
    /// Retains the original and creates its private stage upload.
    Begin,
    /// Fetches and uploads a contiguous bounded group of source parts.
    UploadParts { first_part: u32, maximum_parts: u32 },
    /// Completes the private stage with the exact retained part manifest.
    CloseStage,
    /// Hashes the immutable stage and incrementally verifies its NAR identity.
    VerifyStage,
    /// Reserves the final physical key and creates a destination upload.
    BeginPromotion,
    /// Copies a bounded group of exact source ranges beside R2.
    CopyParts { first_part: u32, maximum_parts: u32 },
    /// Completes the exact retained final manifest under the final-key guard.
    CompletePromotion,
    /// Releases only a positively acknowledged, Native-committed original.
    Acknowledge { commit_digest: String },
}

impl MirrorStep {
    /// Validates bounded dispatch geometry and exact acknowledgement identity.
    ///
    /// # Errors
    /// Returns an error for invalid part bounds or commit digest.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::UploadParts {
                first_part,
                maximum_parts,
            }
            | Self::CopyParts {
                first_part,
                maximum_parts,
            } => ensure!(
                (1..=256).contains(first_part)
                    && (1..=MIRROR_MAX_PARTS_PER_STEP).contains(maximum_parts),
                "mirror part step exceeds its bound"
            ),
            Self::Acknowledge { commit_digest } => ensure!(
                hex_digest(commit_digest),
                "mirror commit identity is invalid"
            ),
            _ => {}
        }
        Ok(())
    }
}

/// Retains one positive part receipt and the exact bytes dispatched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorPart {
    /// Contiguous one-based part number.
    pub part_number: u32,
    /// Exact byte count of the original part.
    pub size: u64,
    /// SHA-256 of the original uploaded source bytes.
    pub sha256: String,
    /// Actual provider part ETag.
    pub etag: String,
}

/// Binds verified bytes to one positive provider incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorVerifiedObject {
    /// Actual acknowledged provider metadata.
    pub object: StorageObjectIdentity,
    /// SHA-256 of the encoded representation.
    pub sha256: String,
    /// Verified uncompressed NAR digest when the source is a NAR.
    pub nar_sha256: Option<String>,
    /// Verified uncompressed byte count when the source is a NAR.
    pub nar_size: Option<u64>,
}

/// Returns only bounded positive observations, never source bodies or URLs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorProgress {
    /// Commitment to the complete immutable original.
    pub original_digest: String,
    /// Strong upstream identity observed before fetching parts, if supplied.
    pub upstream_etag: Option<String>,
    /// Actual positive private multipart identity.
    pub stage_upload_id: Option<String>,
    /// Exact private stage manifest, in contiguous part order.
    pub stage_parts: Vec<MirrorPart>,
    /// Acknowledged private stage identity before content verification.
    pub stage_object: Option<StorageObjectIdentity>,
    /// Positive stage content proof under the retained provider incarnation.
    pub verified: Option<MirrorVerifiedObject>,
    /// Positive final multipart upload identity under the physical-key guard.
    pub destination_upload_id: Option<String>,
    /// Exact final destination part manifest.
    pub destination_parts: Vec<MirrorPart>,
    /// Positive final receipt, derived only from the verified immutable stage.
    pub destination: Option<MirrorVerifiedObject>,
}

impl MirrorProgress {
    /// Checks every retained observation against its immutable original.
    ///
    /// # Errors
    /// Returns an error for changed original, invalid geometry or provider proof.
    pub fn validate(&self, original: &MirrorOriginal) -> Result<()> {
        original.validate()?;
        ensure!(
            self.original_digest == digest(original)?,
            "mirror progress changed its original"
        );
        if let Some(etag) = &self.upstream_etag {
            crate::surface_write::strong_if_match_etag(etag)?;
        }
        ensure!(
            self.stage_parts.is_empty() || self.stage_upload_id.is_some(),
            "mirror parts lack positive Create"
        );
        ensure!(
            (self.destination_upload_id.is_none() && self.destination_parts.is_empty())
                || self.verified.is_some(),
            "mirror destination lacks verified source"
        );
        ensure!(
            self.destination_parts.is_empty() || self.destination_upload_id.is_some(),
            "mirror destination parts lack positive Create"
        );
        for upload in [&self.stage_upload_id, &self.destination_upload_id]
            .into_iter()
            .flatten()
        {
            ensure!(
                !upload.is_empty() && upload.len() <= 2048 && !upload.chars().any(char::is_control),
                "mirror multipart identity is invalid"
            );
        }
        for parts in [&self.stage_parts, &self.destination_parts] {
            ensure!(parts.len() <= 256, "mirror manifest exceeds its part bound");
            for (index, part) in parts.iter().enumerate() {
                let offset = index as u64 * MIRROR_PART_BYTES;
                let remaining = original
                    .verification
                    .size()
                    .checked_sub(offset)
                    .context("mirror part exceeds source")?;
                ensure!(
                    part.part_number as usize == index + 1
                        && part.size > 0
                        && part.size == remaining.min(MIRROR_PART_BYTES)
                        && hex_digest(&part.sha256)
                        && crate::surface_write::strong_if_match_etag(&part.etag).is_ok(),
                    "mirror manifest changed its original geometry"
                );
            }
        }
        if let Some(object) = &self.stage_object {
            validate_object(object, &original.stage_key(), original.verification.size())?;
            ensure!(
                self.stage_parts.iter().map(|part| part.size).sum::<u64>()
                    == original.verification.size(),
                "mirror stage has an incomplete original manifest"
            );
        }
        if let Some(verified) = &self.verified {
            validate_verified(verified, original, &original.stage_key())?;
            ensure!(
                self.stage_object.as_ref() == Some(&verified.object),
                "mirror verified a different private incarnation"
            );
        }
        if let Some(destination) = &self.destination {
            validate_verified(
                destination,
                original,
                &crate::keymap::r2_key(&original.placement_prefix, &original.path),
            )?;
            let verified = self
                .verified
                .as_ref()
                .context("mirror final receipt lacks verified source")?;
            ensure!(
                destination.sha256 == verified.sha256,
                "mirror destination changed verified bytes"
            );
            ensure!(
                self.destination_parts.len() == self.stage_parts.len()
                    && self
                        .destination_parts
                        .iter()
                        .zip(&self.stage_parts)
                        .all(|(destination, source)| destination.size == source.size
                            && destination.sha256 == source.sha256),
                "mirror destination changed its original source ranges"
            );
        }
        // A receipt wraps this progress in the existing 128 KiB Durable
        // Object value ceiling. Keep space for its exact physical key and
        // effect identity; the public control ceiling remains 256 KiB.
        ensure!(
            serde_json::to_vec(self)?.len() <= 112 * 1024,
            "mirror progress exceeds its retained receipt bound"
        );
        Ok(())
    }

    /// Derives the exact Native commit identity from original and final proof.
    ///
    /// # Errors
    /// Returns an error without a validated final destination receipt.
    pub fn commit_digest(&self, original: &MirrorOriginal) -> Result<String> {
        self.validate(original)?;
        let destination = self
            .destination
            .as_ref()
            .context("mirror has no positive destination")?;
        digest(&(original, destination))
    }
}

fn validate_object(object: &StorageObjectIdentity, key: &str, size: u64) -> Result<()> {
    ensure!(
        object.key == key
            && object.size == size
            && object
                .provider_version
                .as_deref()
                .is_some_and(valid_provider_version)
            && crate::surface_write::strong_if_match_etag(&object.etag).is_ok(),
        "mirror provider incarnation differs from original"
    );
    Ok(())
}

fn validate_verified(
    verified: &MirrorVerifiedObject,
    original: &MirrorOriginal,
    key: &str,
) -> Result<()> {
    validate_object(&verified.object, key, original.verification.size())?;
    ensure!(
        hex_digest(&verified.sha256),
        "mirror observed digest is invalid"
    );
    match &original.verification {
        MirrorVerification::Sha256 { sha256, .. } => ensure!(
            &verified.sha256 == sha256
                && verified.nar_sha256.is_none()
                && verified.nar_size.is_none(),
            "mirror metadata differs from verified original"
        ),
        MirrorVerification::Nar {
            file_sha256,
            nar_sha256,
            nar_size,
            ..
        } => ensure!(
            file_sha256
                .as_ref()
                .is_none_or(|sha| sha == &verified.sha256)
                && verified.nar_sha256.as_ref() == Some(nar_sha256)
                && verified.nar_size == Some(*nar_size),
            "mirror NAR differs from Native-selected original"
        ),
    }
    Ok(())
}

/// Commits a canonical mirror original, progress record or receipt.
///
/// # Errors
/// Returns an error when the closed value cannot be encoded.
pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
