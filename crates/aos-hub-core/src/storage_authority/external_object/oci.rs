//! Retained originals for storage-local external OCI uploads.
//!
//! These records project actual OCI upload reservations and current writer
//! authority. They never create a direct-upload admission or topology copy.
//! A short-lived signed control permits a bounded next phase; the permanent
//! full-key guard retains the original and every dispatched effect independently
//! of that control's expiry.
//!
//! ```text
//! chunk original = {upload, writer, placement, binding, profile, chunk}
//! destination original = {upload, writer, placement, binding, profile, sources}
//! provider version != guard incarnation
//! unknown effect -> held original (never a new create, abort or delete)
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::db::{
    BindingRecord, BindingWriteRevisionRecord, OciSha256State, OciUploadRecord,
    SurfacePlacementRecord, SurfaceWriteAuthorityRecord,
};
use crate::storage_authority::{canonical_digest, lease::LeaseInteger, StorageGuardStamp};

/// Fresh OCI application controls over these originals.
pub mod control;

/// Real Native reservation and signed public staging admission metadata.
pub mod admission;

/// Bounded, purpose-specific independently reviewed producer evidence.
pub mod qualification;

/// Independently authenticated compact physical progress and closure receipts.
pub mod reply;

/// Terminal upload cleanup claims and independently authenticated delete receipts.
pub mod cleanup;

#[cfg(test)]
mod tests;

/// Maximum canonical immutable original stored by a physical guard.
pub const MAX_EXTERNAL_OCI_ORIGINAL_BYTES: usize = 64 * 1024;
/// Fixed buffer size used by the storage-local external OCI producer.
pub const EXTERNAL_OCI_PART_BYTES: u64 = 8 * 1024 * 1024;
/// Largest resumable public chunk; this does not increase generic metadata PUT.
pub const MAX_EXTERNAL_OCI_CHUNK_BYTES: u64 = 20 * 1024 * 1024;
/// Largest ordered source chunk batch admitted by one composition original.
pub const MAX_EXTERNAL_OCI_SOURCE_CHUNKS: usize = crate::storage_work::MAX_OCI_COMPOSE_CHUNKS;

/// Retains the authenticated OCI actor independently of the upload owner label.
///
/// The shared account slot is an identity projection only. It grants no direct
/// upload permission and does not derive an OCI actor from provider material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciActorOriginal {
    /// Actual account incarnation selected by the OCI authentication resolver.
    pub account: crate::direct_upload::DirectActorSlot,
    /// Actual current IAM token record, rather than a public upload owner label.
    pub token_id: String,
    /// Original exclusive OCI grant deadline, never renewed by phase controls.
    pub expires_at: LeaseInteger,
}

impl OciActorOriginal {
    /// Projects the existing authenticated OCI resolver's exact account and grant.
    ///
    /// # Errors
    /// Refuses a malformed account, missing IAM token or invalid grant deadline.
    pub fn from_authenticated(
        account: crate::direct_upload::DirectActorSlot,
        token_id: String,
        expires_at: i64,
    ) -> Result<Self> {
        let value = Self {
            account,
            token_id,
            expires_at: LeaseInteger::new(expires_at)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks retained identity shape without proving present IAM permission.
    ///
    /// # Errors
    /// Refuses invalid account incarnation, token identity or nonpositive expiry.
    pub fn validate(&self) -> Result<()> {
        self.account.validate()?;
        ensure!(
            identifier(&self.token_id) && self.expires_at.get() > 0,
            "invalid external OCI authenticated actor"
        );
        Ok(())
    }
}

/// Freezes the actual existing OCI business reservation without provider material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciUploadOriginal {
    /// Existing SQL upload identity, never a fresh retry or provider identity.
    pub upload_id: String,
    /// Exact resource version selected before the first physical effect.
    pub resource_version: LeaseInteger,
    /// Registry whose OCI quota and catalogue own this upload.
    pub registry_id: LeaseInteger,
    /// Repository selected by the original authenticated request.
    pub repository_id: LeaseInteger,
    /// Actual stable writer captured by the OCI reservation.
    pub writer_id: String,
    /// Actual token/session identity captured by the OCI reservation.
    pub token_id: String,
    /// Existing quota reservation; physical success cannot replace it.
    pub quota_reservation_id: String,
    /// Existing verified publication when present.
    pub publication_id: Option<String>,
    /// Original creation time, never moved by control renewal.
    pub created_at: LeaseInteger,
    /// Original upload deadline, never moved by control renewal.
    pub expires_at: LeaseInteger,
    /// Full upload's existing server-side size ceiling.
    pub maximum_size: u64,
}

impl OciUploadOriginal {
    /// Projects a genuine active or completing OCI upload record.
    ///
    /// # Errors
    /// Refuses another lifecycle state, missing identities or invalid bounds.
    pub fn from_record(upload: &OciUploadRecord) -> Result<Self> {
        ensure!(
            matches!(upload.state.as_str(), "active" | "completing"),
            "external OCI original requires a live upload reservation"
        );
        let value = Self {
            upload_id: upload.id.clone(),
            resource_version: LeaseInteger::new(upload.resource_version)?,
            registry_id: LeaseInteger::new(upload.registry_id)?,
            repository_id: LeaseInteger::new(upload.repository_id)?,
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            quota_reservation_id: upload.quota_reservation_id.clone(),
            publication_id: upload.publication_id.clone(),
            created_at: LeaseInteger::new(upload.created_at)?,
            expires_at: LeaseInteger::new(upload.expires_at)?,
            maximum_size: upload.maximum_size,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks immutable reservation shape without creating current permission.
    ///
    /// # Errors
    /// Refuses missing ownership, invalid times or excessive upload geometry.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            hex_id(&self.upload_id, 32)
                && self.resource_version.get() > 0
                && self.registry_id.get() > 0
                && self.repository_id.get() > 0
                && identifier(&self.writer_id)
                && identifier(&self.token_id)
                && identifier(&self.quota_reservation_id)
                && self.publication_id.as_ref().is_none_or(|id| identifier(id))
                && self.created_at.get() > 0
                && self.expires_at.get() > self.created_at.get()
                && self.maximum_size <= crate::storage_work::MAX_OCI_COMPOSE_BYTES,
            "invalid external OCI upload original"
        );
        Ok(())
    }
}

/// Freezes actual writer, placement and binding generations for one OCI original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciWriterOriginal {
    /// Exact placement containing the staging or canonical key.
    pub placement_id: LeaseInteger,
    /// Original placement resource version.
    pub placement_resource_version: LeaseInteger,
    /// Original writer-critical placement version.
    pub write_spec_version: LeaseInteger,
    /// Original surface-relative prefix; it is never reselected on retry.
    pub placement_prefix: String,
    /// Original binding-owned prefix, independently joined with the placement.
    pub binding_prefix: String,
    /// Existing storage binding identity.
    pub binding_id: LeaseInteger,
    /// Never-reused binding lifetime identity.
    pub binding_stable_id: String,
    /// Exact binding resource version.
    pub binding_resource_version: LeaseInteger,
    /// Exact immutable binding write revision.
    pub binding_write_revision: LeaseInteger,
    /// Existing SQL writer authority identity.
    pub authority_id: LeaseInteger,
    /// Never-reused SQL writer authority lifetime identity.
    pub authority_incarnation: String,
    /// Original authority resource version.
    pub authority_resource_version: LeaseInteger,
    /// Exact ready desired and observed authority generation.
    pub authority_generation: LeaseInteger,
}

impl OciWriterOriginal {
    /// Projects only a currently ready writer for the reservation's registry.
    ///
    /// # Errors
    /// Refuses a managed/local binding, changed placement, stale write revision
    /// or authority without exact matching desired and observed writer pins.
    pub fn from_records(
        upload: &OciUploadOriginal,
        placement: &SurfacePlacementRecord,
        binding: &BindingRecord,
        revision: &BindingWriteRevisionRecord,
        authority: &SurfaceWriteAuthorityRecord,
    ) -> Result<Self> {
        upload.validate()?;
        Self::from_registry_records(upload.registry_id.get(), placement, binding, revision, authority)
    }

    /// Projects exact current writer pins for read-only retained source discovery.
    ///
    /// This identity projection grants no mutation, upload or IAM permission.
    ///
    /// # Errors
    /// Refuses a nonexternal binding or stale ready writer generation.
    pub fn from_registry_records(
        registry_id: i64,
        placement: &SurfacePlacementRecord,
        binding: &BindingRecord,
        revision: &BindingWriteRevisionRecord,
        authority: &SurfaceWriteAuthorityRecord,
    ) -> Result<Self> {
        ensure!(
            registry_id > 0 && !binding.is_instance_default
                && matches!(binding.kind.as_str(), "s3" | "r2")
                && placement.registry_id == Some(registry_id)
                && placement.cache_id.is_none()
                && placement.effective_write_enabled
                && placement.binding_id == binding.id
                && revision.binding_id == binding.id
                && revision.writes_supported
                && authority.registry_id == Some(registry_id)
                && authority.cache_id.is_none()
                && authority.mode == "single_writer"
                && authority.reconciliation_state == "ready"
                && authority.desired_placement_id == placement.id
                && authority.observed_placement_id == Some(placement.id)
                && authority.desired_write_spec_version == placement.write_spec_version
                && authority.observed_write_spec_version == Some(placement.write_spec_version)
                && authority.desired_binding_write_revision == revision.revision
                && authority.observed_binding_write_revision == Some(revision.revision)
                && authority.observed_generation == Some(authority.desired_generation),
            "external OCI writer differs from actual ready authority"
        );
        let value = Self {
            placement_id: LeaseInteger::new(placement.id)?,
            placement_resource_version: LeaseInteger::new(placement.resource_version)?,
            write_spec_version: LeaseInteger::new(placement.write_spec_version)?,
            placement_prefix: placement.prefix.clone(),
            binding_prefix: binding.object_prefix.clone().unwrap_or_default(),
            binding_id: LeaseInteger::new(binding.id)?,
            binding_stable_id: binding.stable_id.clone(),
            binding_resource_version: LeaseInteger::new(binding.resource_version)?,
            binding_write_revision: LeaseInteger::new(revision.revision)?,
            authority_id: LeaseInteger::new(authority.id)?,
            authority_incarnation: authority.incarnation_id.clone(),
            authority_resource_version: LeaseInteger::new(authority.resource_version)?,
            authority_generation: LeaseInteger::new(authority.desired_generation)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks retained exact pins without selecting a different current writer.
    ///
    /// # Errors
    /// Refuses unsafe prefixes, missing lifetime identities or zero versions.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.placement_id.get() > 0
                && self.placement_resource_version.get() > 0
                && self.write_spec_version.get() > 0
                && crate::storage_work::valid_relative_path(&self.placement_prefix, true)
                && self.placement_prefix.len() <= 512
                && crate::storage_work::valid_relative_path(&self.binding_prefix, true)
                && self.binding_prefix.len() <= 512
                && self.binding_id.get() > 0
                && identifier(&self.binding_stable_id)
                && self.binding_resource_version.get() > 0
                && self.binding_write_revision.get() > 0
                && self.authority_id.get() > 0
                && identifier(&self.authority_incarnation)
                && self.authority_resource_version.get() > 0
                && self.authority_generation.get() > 0,
            "invalid external OCI writer pins"
        );
        Ok(())
    }
}

/// Retains actual provider identity without disguising a guard stamp as a version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OciProviderIncarnation {
    /// Actual non-null provider version returned by a positive OCI write.
    Versioned {
        /// Provider-issued immutable version identifier.
        provider_version: String,
        /// Actual positive full-key guard incarnation, independently retained.
        guard_stamp: StorageGuardStamp,
    },
    /// Versionless provider with separately qualified physical writer closure.
    Guarded {
        /// Actual monotonically advanced full-key guard incarnation.
        guard_stamp: StorageGuardStamp,
    },
}

impl OciProviderIncarnation {
    /// Checks provider identity and the independently selected physical domain.
    ///
    /// This does not qualify a versionless provider. The OCI workflow acceptance
    /// must independently permit this representation for its exact raw profile.
    ///
    /// # Errors
    /// Refuses malformed, null or foreign provider/guard identity.
    pub fn validate(&self, authority_id: &str) -> Result<()> {
        let stamp = match self {
            Self::Versioned {
                provider_version,
                guard_stamp,
            } => {
                ensure!(
                    crate::storage_work::valid_provider_version(provider_version)
                        && provider_version != "null",
                    "external OCI provider version is absent or invalid"
                );
                guard_stamp
            }
            Self::Guarded { guard_stamp } => guard_stamp,
        };
        ensure!(
            stamp.physical_authority_id.as_str() == authority_id,
            "external OCI guard incarnation differs"
        );
        Ok(())
    }
}

/// Selects a bounded OCI chunk or the actual ordered materialization source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OciObjectOriginal {
    /// One resumable public chunk at an exact contiguous upload offset.
    Chunk {
        /// Existing zero-based ordinal from the actual SQL chunk inventory.
        ordinal: u32,
        /// Existing contiguous accepted byte count.
        offset: u64,
        /// Original upper bound, never increased by producer renewals.
        maximum_bytes: u64,
        /// Portable continuation selected by Native before the body is consumed.
        prior_sha256: OciSha256State,
        /// Exact declared bytes and SHA for a manifest reservation, when known.
        expected: Option<OciBytes>,
    },
    /// Canonical blob materialization owned by the existing completing upload.
    Compose {
        /// Exact final content identity frozen by the SQL materialization claim.
        expected: OciBytes,
        /// Commitment to all ordered sources; bounded pages must be retained
        /// and verified before any destination effect.
        sources: OciSourceManifest,
    },
}

/// Exact bytes of one positively known OCI object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciBytes {
    /// Complete lowercase SHA-256, excluding the `sha256:` prefix.
    pub sha256: String,
    /// Complete independently counted byte size.
    pub size: u64,
}

/// Exact retained source for storage-local composition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciSourceOriginal {
    /// Complete provider key, including binding and placement prefixes.
    pub key: String,
    /// Exact complete content SHA and size from the SQL chunk reservation.
    pub bytes: OciBytes,
    /// Positive guard receipt commitment, never inferred from HEAD alone.
    pub receipt_digest: String,
    /// Actual strong ETag condition used for every source read.
    pub etag: String,
    /// Actual provider version or qualified guard incarnation.
    pub incarnation: OciProviderIncarnation,
}

/// Commits all ordered private sources without duplicating an unbounded manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciSourceManifest {
    /// Exact number of source descriptors, including zero for an empty blob.
    pub count: u32,
    /// Exact sum of complete source sizes.
    pub bytes: u64,
    /// Domain-separated ordered descriptor commitment.
    pub sha256: String,
}

impl OciSourceManifest {
    /// Commits actual positive sources in their SQL chunk order.
    ///
    /// The guard repeats this same computation over bounded retained pages. No
    /// source page grants permission until the complete commitment matches.
    ///
    /// # Errors
    /// Refuses excessive counts, malformed sources or checked size overflow.
    pub fn from_sources(sources: &[OciSourceOriginal]) -> Result<Self> {
        ensure!(
            sources.len() <= MAX_EXTERNAL_OCI_SOURCE_CHUNKS,
            "external OCI source manifest exceeds bound"
        );
        let mut state = Self::initial_hash()?;
        let mut bytes = 0_u64;
        let mut keys = std::collections::BTreeSet::new();
        for source in sources {
            source.bytes.validate()?;
            ensure!(
                source.bytes.size > 0
                    && source.bytes.size <= MAX_EXTERNAL_OCI_CHUNK_BYTES
                    && crate::storage_work::valid_relative_path(&source.key, false)
                    && keys.insert(&source.key)
                    && digest_string(&source.receipt_digest)
                    && crate::surface_write::strong_if_match_etag(&source.etag)? == source.etag,
                "invalid or duplicate external OCI source"
            );
            Self::append_hash(&mut state, source)?;
            bytes = bytes
                .checked_add(source.bytes.size)
                .ok_or_else(|| anyhow::anyhow!("external OCI source size overflow"))?;
        }
        let value = Self {
            count: sources.len() as u32,
            bytes,
            sha256: state.final_digest()?.encoded(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Starts the fixed-domain descriptor continuation used by both peers.
    ///
    /// # Errors
    /// Returns an error if the portable hash state cannot accept its domain.
    pub fn initial_hash() -> Result<OciSha256State> {
        let mut state = OciSha256State::initial();
        state.update(b"aos.external-oci-source-manifest.v1\0")?;
        Ok(state)
    }

    /// Adds one length-framed canonical descriptor to a retained continuation.
    ///
    /// # Errors
    /// Refuses malformed continuation state or descriptor encoding errors.
    pub fn append_hash(state: &mut OciSha256State, source: &OciSourceOriginal) -> Result<()> {
        let encoded = serde_json::to_vec(source)?;
        ensure!(
            encoded.len() <= 4096,
            "external OCI source descriptor oversized"
        );
        state.update(&(encoded.len() as u64).to_be_bytes())?;
        state.update(&encoded)
    }

    /// Checks a closed whole-manifest commitment without exposing its sources.
    ///
    /// # Errors
    /// Refuses unsupported counts, hashes, geometry or a nonempty zero source.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.count as usize <= MAX_EXTERNAL_OCI_SOURCE_CHUNKS
                && self.bytes <= crate::storage_work::MAX_OCI_COMPOSE_BYTES
                && digest_string(&self.sha256)
                && ((self.count == 0) == (self.bytes == 0)),
            "invalid external OCI source manifest"
        );
        if self.count == 0 {
            ensure!(
                self.sha256 == Self::initial_hash()?.final_digest()?.encoded(),
                "empty external OCI manifest commitment differs"
            );
        }
        Ok(())
    }
}

/// Retains one real upload and its immutable physical OCI producer original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciOriginal {
    /// Closed original version, currently one.
    pub version: u8,
    /// Actual shared deployment identity.
    pub deployment_id: String,
    /// Real existing OCI reservation and authenticated owner.
    pub upload: OciUploadOriginal,
    /// Actual authenticated account and immutable current grant deadline.
    pub actor: OciActorOriginal,
    /// Exact SQL writer authority, placement and binding generations.
    pub writer: OciWriterOriginal,
    /// Immutable raw binding coordinates; fresh snapshot time belongs to each control.
    pub binding_spec_revision: String,
    /// Exact separately reviewed OCI workflow profile digest.
    pub profile_digest: String,
    /// Physical authority namespace shared by every alias of this full key.
    pub scope: crate::storage_authority::control::StorageAuthorityObjectScope,
    /// Exact chunk or canonical blob declaration.
    pub object: OciObjectOriginal,
}

impl ExternalOciOriginal {
    /// Validates bounded immutable ownership without issuing provider permission.
    ///
    /// # Errors
    /// Refuses invalid ownership, unsafe keys, oversized sources, changed
    /// continuation geometry or a canonical destination different from its hash.
    pub fn validate(&self) -> Result<()> {
        self.upload.validate()?;
        self.actor.validate()?;
        self.writer.validate()?;
        self.scope.guard_name()?;
        ensure!(
            self.version == 1
                && identifier(&self.deployment_id)
                && digest_string(&self.binding_spec_revision)
                && digest_string(&self.profile_digest),
            "invalid external OCI original identity"
        );
        let prefix =
            crate::keymap::r2_key(&self.writer.binding_prefix, &self.writer.placement_prefix);
        let relative = if prefix.is_empty() {
            self.scope.full_key.as_str()
        } else {
            self.scope
                .full_key
                .strip_prefix(&format!("{prefix}/"))
                .ok_or_else(|| anyhow::anyhow!("external OCI key escapes exact original prefix"))?
        };
        match &self.object {
            OciObjectOriginal::Chunk {
                ordinal,
                offset,
                maximum_bytes,
                prior_sha256,
                expected,
            } => {
                prior_sha256.validate()?;
                let suffix = relative
                    .strip_prefix(&format!("oci/uploads/{}/chunks/", self.upload.upload_id))
                    .ok_or_else(|| anyhow::anyhow!("external OCI private stage path differs"))?;
                ensure!(
                    suffix
                        .strip_prefix(&format!("{ordinal}-"))
                        .is_some_and(|attempt| {
                            let mut fields = attempt.split('-');
                            fields.next().is_some_and(|id| hex_id(id, 32))
                                && fields.next().is_none_or(|hash| hex_id(hash, 64))
                                && fields.next().is_none()
                        })
                        && *maximum_bytes > 0
                        && *maximum_bytes <= MAX_EXTERNAL_OCI_CHUNK_BYTES
                        && prior_sha256.total_bytes == *offset
                        && offset
                            .checked_add(*maximum_bytes)
                            .is_some_and(|end| end <= self.upload.maximum_size),
                    "external OCI chunk geometry differs"
                );
                if let Some(expected) = expected {
                    expected.validate()?;
                    ensure!(
                        expected.size > 0 && expected.size <= *maximum_bytes,
                        "external OCI manifest identity exceeds reservation"
                    );
                }
            }
            OciObjectOriginal::Compose { expected, sources } => {
                expected.validate()?;
                let path = format!("oci/blobs/sha256/{}", expected.sha256);
                ensure!(
                    relative == path,
                    "external OCI canonical destination differs"
                );
                sources.validate()?;
                ensure!(
                    sources.bytes == expected.size && expected.size <= self.upload.maximum_size,
                    "external OCI composition differs from claimed size"
                );
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_OCI_ORIGINAL_BYTES,
            "external OCI original exceeds retained budget"
        );
        Ok(())
    }

    /// Commits the full immutable original independently of fresh controls.
    ///
    /// # Errors
    /// Refuses invalid originals or canonical encoding errors.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(&("aos.external-oci-original.v1", self))
    }

    /// Commits the exact business selection independently of renewed grant time.
    ///
    /// Initial grant expiry is excluded. A canonical composition also excludes
    /// the claim's observational upload version: lease reacquisition must find
    /// its first original. The actual upload ID, account/token, upload deadline,
    /// writer, profile, path and complete source manifest remain immutable.
    /// This locator grants no effect; every phase rechecks the real SQL claim.
    ///
    /// # Errors
    /// Refuses a malformed original or canonical encoding failure.
    pub fn selection_digest(&self) -> Result<String> {
        self.validate()?;
        let mut selected = self.clone();
        selected.actor.expires_at = LeaseInteger::new(1)?;
        if matches!(selected.object, OciObjectOriginal::Compose { .. }) {
            selected.upload.resource_version = LeaseInteger::new(1)?;
        }
        canonical_digest(&("aos.external-oci-selection.v1", selected))
    }
}

impl OciBytes {
    /// Checks the exact existing OCI size and content hash contract.
    ///
    /// # Errors
    /// Refuses malformed hashes or sizes above the upload contract.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            digest_string(&self.sha256) && self.size <= crate::storage_work::MAX_OCI_COMPOSE_BYTES,
            "invalid external OCI byte identity"
        );
        Ok(())
    }
}

pub(super) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

pub(super) fn digest_string(value: &str) -> bool {
    hex_id(value, 64)
}

fn hex_id(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Read-only independent discovery of retained positive OCI sources.
pub mod source;

/// Actual checked OCI claim and current business authority for materialization.
pub mod materialization;

#[cfg(any(test, feature = "do-e2e-test-support"))]
pub mod candidate;
