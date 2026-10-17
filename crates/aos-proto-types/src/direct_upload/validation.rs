//! Pure geometry checks and versioned length-delimited binary commitments.

use std::fmt;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use super::*;

/// Value-free failure for a closed direct-upload declaration or commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectUploadError(pub(crate) &'static str);

impl fmt::Display for DirectUploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for DirectUploadError {}

/// Result of pure direct-upload protocol validation.
pub type DirectUploadResult<T> = Result<T, DirectUploadError>;

pub(crate) fn require(value: bool, message: &'static str) -> DirectUploadResult<()> {
    if value {
        Ok(())
    } else {
        Err(DirectUploadError(message))
    }
}

/// Checks a bounded canonical opaque identity without embedding it in errors.
pub fn valid_direct_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Checks one lowercase hexadecimal SHA-256 or stable operation identifier.
pub fn valid_direct_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Checks a canonical relative object path, without assigning provider authority.
pub fn valid_direct_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.trim() == value
        && !value.starts_with('/')
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#'))
        && !is_direct_staging_key(value)
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl DirectUploadTarget {
    /// Checks the closed owner selector without granting ACL or provider authority.
    ///
    /// # Errors
    /// Returns a value-free error for an invalid owner identity or relative path.
    pub fn validate(&self) -> DirectUploadResult<()> {
        match self {
            DirectUploadTarget::CacheObject { cache_id, path } => {
                require(
                    valid_direct_identity(cache_id) && valid_direct_path(path),
                    "invalid cache upload owner",
                )?;
            }
            DirectUploadTarget::PublicationObject {
                publication_id,
                surface_object_id,
                path,
            } => {
                require(
                    valid_direct_identity(publication_id)
                        && (1..=i64::MAX as u64).contains(&surface_object_id.get())
                        && valid_direct_path(path),
                    "invalid publication upload owner",
                )?;
            }
            DirectUploadTarget::OciBlob { upload_id } => {
                require(valid_direct_identity(upload_id), "invalid OCI upload owner")?;
            }
        }
        Ok(())
    }
}

impl DirectUploadIntent {
    /// Validates the closed logical owner, full source and multipart geometry.
    ///
    /// Native must separately resolve ACL, quota, owner and dependency phase.
    ///
    /// # Errors
    /// Returns a value-free error for unknown version, invalid identity/hash,
    /// excessive source size or unsupported provider part geometry.
    pub fn validate(&self) -> DirectUploadResult<()> {
        require(self.version == 1, "unsupported direct-upload version")?;
        require(
            valid_direct_digest(&self.client_operation_id),
            "invalid client operation identity",
        )?;
        require(
            valid_direct_digest(&self.expected_sha256),
            "invalid source digest",
        )?;
        require(
            self.byte_size.get() <= MAX_DIRECT_OBJECT_BYTES,
            "direct-upload source exceeds limit",
        )?;
        require(
            (MIN_DIRECT_PART_BYTES..=MAX_DIRECT_PART_BYTES).contains(&self.part_size.get()),
            "invalid direct-upload part geometry",
        )?;

        self.target.validate()?;

        if self.byte_size.get() == 0 {
            require(
                self.expected_sha256
                    == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "empty source digest mismatch",
            )?;
        }

        let count = self.byte_size.get().div_ceil(self.part_size.get());
        require(
            count <= u64::from(MAX_DIRECT_PARTS),
            "direct-upload part count exceeds limit",
        )
    }

    /// Returns the exact part count; zero-byte objects have no delegated parts.
    ///
    /// # Errors
    /// Returns an error for an invalid source declaration or geometry.
    pub fn part_count(&self) -> DirectUploadResult<u32> {
        self.validate()?;
        u32::try_from(self.byte_size.get().div_ceil(self.part_size.get()))
            .map_err(|_| DirectUploadError("direct-upload part count overflow"))
    }

    /// Returns exact offset and length for one eligible part number.
    ///
    /// # Errors
    /// Returns an error for invalid geometry or a nonexistent part.
    pub fn part_range(&self, number: u32) -> DirectUploadResult<(u64, u64)> {
        let count = self.part_count()?;
        require(
            number > 0 && number <= count,
            "invalid direct-upload part number",
        )?;
        let offset = u64::from(number - 1)
            .checked_mul(self.part_size.get())
            .ok_or(DirectUploadError("direct-upload offset overflow"))?;
        let size = (self.byte_size.get() - offset).min(self.part_size.get());
        Ok((offset, size))
    }

    /// Computes the version-one immutable intent commitment.
    ///
    /// Fields use explicit variant tags, big-endian integer widths and checked
    /// length-prefixed UTF-8 bytes. This commitment is distinct from stable
    /// business-operation identity, so changed source inputs cannot evade CAS.
    ///
    /// # Errors
    /// Returns an error for an invalid declaration or bounded encoding failure.
    pub fn fingerprint(&self) -> DirectUploadResult<String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"aos.direct-upload.intent.v1\0");
        hash.update(self.version.to_be_bytes());
        hash_text(&mut hash, &self.client_operation_id)?;
        match &self.target {
            DirectUploadTarget::CacheObject { cache_id, path } => {
                hash.update([1]);
                hash_text(&mut hash, cache_id)?;
                hash_text(&mut hash, path)?;
            }
            DirectUploadTarget::PublicationObject {
                publication_id,
                surface_object_id,
                path,
            } => {
                hash.update([2]);
                hash_text(&mut hash, publication_id)?;
                hash.update(surface_object_id.get().to_be_bytes());
                hash_text(&mut hash, path)?;
            }
            DirectUploadTarget::OciBlob { upload_id } => {
                hash.update([3]);
                hash_text(&mut hash, upload_id)?;
            }
        }
        hash_text(&mut hash, &self.expected_sha256)?;
        hash.update(self.byte_size.get().to_be_bytes());
        hash.update(self.part_size.get().to_be_bytes());
        hash.update([match self.dependency_phase {
            DirectDependencyPhase::Content => 1,
            DirectDependencyPhase::LeafMetadata => 2,
            DirectDependencyPhase::Visibility => 3,
        }]);
        hash.update([1]); // Closed DirectRequired transfer mode.
        Ok(hex::encode(hash.finalize()))
    }
}

impl DirectPartChecksum {
    /// Returns the exact required provider checksum header name.
    #[must_use]
    pub const fn header_name(&self) -> &'static str {
        match self.algorithm {
            DirectChecksumAlgorithm::Md5 => "content-md5",
            DirectChecksumAlgorithm::Sha256 => "x-amz-checksum-sha256",
        }
    }

    /// Validates and decodes a canonical checksum of the declared algorithm.
    ///
    /// # Errors
    /// Returns an error for invalid padding, bytes, length or alternate spelling.
    pub fn decoded(&self) -> DirectUploadResult<Vec<u8>> {
        let length = match self.algorithm {
            DirectChecksumAlgorithm::Md5 => 16,
            DirectChecksumAlgorithm::Sha256 => 32,
        };
        require(self.value.len() <= 44, "invalid direct-upload checksum")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.value)
            .map_err(|_| DirectUploadError("invalid direct-upload checksum"))?;
        require(
            bytes.len() == length
                && base64::engine::general_purpose::STANDARD.encode(&bytes) == self.value,
            "invalid direct-upload checksum",
        )?;
        Ok(bytes)
    }
}

impl DirectPart {
    /// Checks exact immutable part geometry and canonical checksum declarations.
    ///
    /// # Errors
    /// Returns an error for a mismatched range, digest or provider checksum.
    pub fn validate(&self, intent: &DirectUploadIntent) -> DirectUploadResult<()> {
        let (offset, size) = intent.part_range(self.part_number)?;
        require(
            self.offset.get() == offset && self.byte_size.get() == size,
            "direct-upload part geometry mismatch",
        )?;
        require(
            valid_direct_digest(&self.sha256),
            "invalid direct-upload part digest",
        )?;
        let checksum = self.checksum.decoded()?;
        if self.checksum.algorithm == DirectChecksumAlgorithm::Sha256 {
            require(
                hex::encode(checksum) == self.sha256,
                "direct-upload part checksum mismatch",
            )?;
        }
        Ok(())
    }
}

/// Checks a bounded canonical strong ETag without including it in errors.
pub fn valid_direct_etag(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 1024
        && value.starts_with('"')
        && value.ends_with('"')
        && !value[1..value.len() - 1]
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '<' | '>' | '&'))
}

/// Computes the per-destination complete ordered-part manifest commitment.
///
/// The hash streams exact big-endian numbers and length-delimited strings. It
/// binds the immutable intent and placement, not JSON formatting or URL grants.
/// Parts must cover the complete source exactly; client reports remain observations.
///
/// # Errors
/// Returns an error for an incomplete, reordered, duplicate or malformed part
/// set, invalid placement commitment, geometry, checksum or strong ETag.
pub fn canonical_manifest_digest(
    intent: &DirectUploadIntent,
    placement: &DirectPlacementRef,
    parts: &[DirectManifestPart],
) -> DirectUploadResult<String> {
    let mut accumulator = DirectManifestHasher::new(intent, placement)?;
    for member in parts {
        accumulator.push(member)?;
    }
    accumulator.finish()
}

/// Streaming ordered manifest commitment with bounded immutable source metadata.
///
/// Clients can consume sparse retained pages without accumulating every part
/// descriptor per destination. Failed pushes do not advance the hash or count.
pub struct DirectManifestHasher {
    intent: DirectUploadIntent,
    placement: DirectPlacementRef,
    count: u32,
    expected: u32,
    hash: Sha256,
}

impl DirectManifestHasher {
    /// Initializes the exact version-one commitment for one required destination.
    ///
    /// # Errors
    /// Returns an error for invalid source geometry or placement commitment.
    pub fn new(
        intent: &DirectUploadIntent,
        placement: &DirectPlacementRef,
    ) -> DirectUploadResult<Self> {
        let expected = intent.part_count()?;
        placement.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"aos.direct-upload.manifest.v1\0");
        hash_text(&mut hash, &intent.fingerprint()?)?;
        hash_placement(&mut hash, placement)?;
        hash.update(expected.to_be_bytes());
        Ok(Self {
            intent: intent.clone(),
            placement: placement.clone(),
            count: 0,
            expected,
            hash,
        })
    }

    /// Adds the next exact ordered member, without retaining its content.
    ///
    /// # Errors
    /// Returns an error for extra/reordered parts, geometry, checksum or ETag.
    pub fn push(&mut self, member: &DirectManifestPart) -> DirectUploadResult<()> {
        require(
            self.count < self.expected && member.part.part_number == self.count + 1,
            "unordered direct-upload manifest",
        )?;
        member.part.validate(&self.intent)?;
        require(
            member.part.checksum.algorithm == self.placement.checksum_algorithm,
            "direct-upload placement checksum mismatch",
        )?;
        require(
            valid_direct_etag(&member.etag),
            "invalid direct-upload provider ETag",
        )?;
        self.hash.update(member.part.part_number.to_be_bytes());
        self.hash.update(member.part.offset.get().to_be_bytes());
        self.hash.update(member.part.byte_size.get().to_be_bytes());
        hash_text(&mut self.hash, &member.part.sha256)?;
        self.hash.update([match member.part.checksum.algorithm {
            DirectChecksumAlgorithm::Md5 => 1,
            DirectChecksumAlgorithm::Sha256 => 2,
        }]);
        hash_text(&mut self.hash, &member.part.checksum.value)?;
        hash_text(&mut self.hash, &member.etag)?;
        self.count += 1;
        Ok(())
    }

    /// Finishes only after all exact expected members were included.
    ///
    /// # Errors
    /// Returns an error for an incomplete manifest. Zero-byte manifests are valid
    /// commitments to real server-owned EmptyPut, never a synthetic UploadId.
    pub fn finish(self) -> DirectUploadResult<String> {
        require(
            self.count == self.expected,
            "incomplete direct-upload manifest",
        )?;
        Ok(hex::encode(self.hash.finalize()))
    }
}

/// Computes a restore-independent reservation identity for one business operation.
///
/// Owner, SQL session, source, geometry and placement coordinates are excluded.
/// Their immutable original fingerprint must be retained at this address before
/// any provider effect, so changed rows after SQL restore cannot fork creation.
///
/// # Errors
/// Returns an error for malformed deployment, principal or operation identities.
pub fn deterministic_business_operation_id(
    deployment: &str,
    principal: &str,
    client_operation_id: &str,
) -> DirectUploadResult<String> {
    require(
        valid_direct_identity(deployment)
            && valid_direct_identity(principal)
            && valid_direct_digest(client_operation_id),
        "invalid direct-upload business identity",
    )?;
    let mut hash = Sha256::new();
    hash.update(b"aos.direct-upload.business-operation.v1\0");
    hash_text(&mut hash, deployment)?;
    hash_text(&mut hash, principal)?;
    hash_text(&mut hash, client_operation_id)?;
    Ok(hex::encode(hash.finalize()))
}

fn hash_text(hash: &mut Sha256, value: &str) -> DirectUploadResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| DirectUploadError("direct-upload field length overflow"))?;
    hash.update(length.to_be_bytes());
    hash.update(value.as_bytes());
    Ok(())
}

impl DirectCompleteRequest {
    /// Computes the immutable per-item Complete commitment independent of batching.
    ///
    /// Native and broker retain this before freeze. Moving the same item between
    /// batches changes transport correlation, not its original operation intent.
    ///
    /// # Errors
    /// Returns an error for invalid session/operation/CAS or unordered manifests.
    pub fn fingerprint(&self) -> DirectUploadResult<String> {
        self.session.validate()?;
        require(
            valid_direct_digest(&self.operation_id)
                && (1..=i64::MAX as u64).contains(&self.expected_resource_version.get())
                && !self.manifests.is_empty()
                && self.manifests.len() <= MAX_DIRECT_PLACEMENTS,
            "invalid direct complete intent",
        )?;
        let mut hash = Sha256::new();
        hash.update(b"aos.direct-upload.complete-intent.v1\0");
        for value in [
            &self.session.session_id,
            &self.session.logical_fingerprint,
            &self.operation_id,
        ] {
            hash_text(&mut hash, value)?;
        }
        hash.update(self.expected_resource_version.get().to_be_bytes());
        hash.update(
            u32::try_from(self.manifests.len())
                .map_err(|_| DirectUploadError("direct complete count overflow"))?
                .to_be_bytes(),
        );
        let mut previous = 0;
        for manifest in &self.manifests {
            manifest.placement.validate()?;
            require(
                manifest.placement.placement_id.get() > previous
                    && manifest.part_count <= MAX_DIRECT_PARTS
                    && valid_direct_digest(&manifest.manifest_digest),
                "invalid direct complete manifest",
            )?;
            previous = manifest.placement.placement_id.get();
            hash_placement(&mut hash, &manifest.placement)?;
            hash_text(&mut hash, &manifest.manifest_digest)?;
            hash.update(manifest.part_count.to_be_bytes());
        }
        Ok(hex::encode(hash.finalize()))
    }
}

// All public placement commitments use this exact ordered binary projection.
fn hash_placement(hash: &mut Sha256, placement: &DirectPlacementRef) -> DirectUploadResult<()> {
    for counter in [
        placement.placement_id,
        placement.placement_resource_version,
        placement.write_spec_version,
        placement.binding_id,
        placement.binding_resource_version,
        placement.binding_write_revision,
    ] {
        hash.update(counter.get().to_be_bytes());
    }
    for digest in [
        &placement.placement_fingerprint,
        &placement.profile_fingerprint,
        &placement.private_policy_digest,
    ] {
        hash_text(hash, digest)?;
    }
    hash.update([match placement.checksum_algorithm {
        DirectChecksumAlgorithm::Md5 => 1,
        DirectChecksumAlgorithm::Sha256 => 2,
    }]);
    Ok(())
}

/// Detects the reserved direct staging segment in an already resolved physical key.
///
/// Public readers and inventory must call this after their existing canonical
/// route/key resolution. This helper never decodes URLs or establishes provider
/// privacy, and it does not grant privileged broker access to staging objects.
#[must_use]
pub fn is_direct_staging_key(canonical_resolved_key: &str) -> bool {
    canonical_resolved_key
        .split('/')
        .any(|segment| segment == ".aos-direct-upload")
}
