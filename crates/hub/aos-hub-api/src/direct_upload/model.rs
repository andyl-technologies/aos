//! Immutable logical upload owners and bounded sparse multipart projections.

use serde::{Deserialize, Serialize};

use super::WireInteger;

/// Logical owner resolved and authorized by Native, never a provider key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectUploadTarget {
    /// An admitted object in a managed cache.
    CacheObject {
        /// Stable configured cache identity.
        cache_id: String,
        /// Canonical cache-relative path.
        path: String,
    },
    /// One retained object in an immutable publication admission.
    PublicationObject {
        /// Retained publication identity.
        publication_id: String,
        /// Retained surface object row identity.
        surface_object_id: WireInteger,
        /// Exact canonical publication-relative path.
        path: String,
    },
    /// A writer-bound existing OCI logical upload session.
    OciBlob {
        /// Existing logical upload identity; Native resolves registry/ACL.
        upload_id: String,
    },
}

/// Client dependency declaration; Native independently classifies verified metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectDependencyPhase {
    /// Independently verified NARs, blobs and content objects.
    Content,
    /// Independent leaf metadata, including narinfos.
    LeafMetadata,
    /// Final release, catalog, root, tag or channel visibility.
    Visibility,
}

/// Immutable source declaration bound separately from stable session identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectUploadIntent {
    /// Protocol version, currently one.
    pub version: u32,
    /// Stable client operation identity, exactly 64 lowercase hexadecimal bytes.
    pub client_operation_id: String,
    /// Authenticated logical owner.
    pub target: DirectUploadTarget,
    /// Expected full-object lowercase hexadecimal SHA-256.
    pub expected_sha256: String,
    /// Immutable full-object length.
    #[serde(default)]
    pub byte_size: WireInteger,
    /// Immutable multipart geometry; final parts may be smaller.
    #[serde(default)]
    pub part_size: WireInteger,
    /// Dependency phase independently resolved and checked by Native.
    pub dependency_phase: DirectDependencyPhase,
    /// Required transfer mode; compatibility transports are never a fallback.
    pub transfer_mode: DirectTransferMode,
}

/// Closed transfer policy for the new API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectTransferMode {
    /// Fails if direct staging and storage-side verification are unavailable.
    DirectRequired,
}

/// Provider-enforced part checksum selected by a qualified broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectChecksumAlgorithm {
    /// Canonical base64 MD5 sent as Content-MD5.
    Md5,
    /// Canonical base64 SHA-256 sent as x-amz-checksum-sha256.
    Sha256,
}

/// Exact checksum algorithm/value bound by a part grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPartChecksum {
    /// Closed checksum algorithm.
    pub algorithm: DirectChecksumAlgorithm,
    /// Canonical padded standard base64 checksum.
    pub value: String,
}

/// Exact part geometry and byte identity, computed against the original intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPart {
    /// One-based part number.
    pub part_number: u32,
    /// Immutable full-object offset.
    #[serde(default)]
    pub offset: WireInteger,
    /// Exact length, including the final-part exception.
    #[serde(default)]
    pub byte_size: WireInteger,
    /// Expected lowercase SHA-256 of this part.
    pub sha256: String,
    /// Provider checksum signed into the exact request.
    pub checksum: DirectPartChecksum,
}

/// Exact ordered provider completion manifest member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectManifestPart {
    /// Exact immutable part descriptor.
    pub part: DirectPart,
    /// Canonical strong ETag, including quotes, observed for this part.
    pub etag: String,
}

/// One explicitly required header of a delegated provider request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectRequiredHeader {
    /// Canonical lowercase header name.
    pub name: String,
    /// Exact canonical header value.
    pub value: String,
}

/// Bearer UploadPart capability; URLs are transport data and always Debug-redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPartGrant {
    /// Stable logical session identity.
    pub session_id: String,
    /// Immutable logical admission fingerprint.
    pub logical_fingerprint: String,
    /// Exact required physical destination from the original admission.
    pub placement: DirectPlacementRef,
    /// Stable retained grant identity.
    pub grant_id: String,
    /// Exact monotonic grant revision.
    #[serde(default)]
    pub grant_revision: WireInteger,
    /// Exact part descriptor.
    pub part: DirectPart,
    /// Closed provider method, always PUT.
    pub method: String,
    /// Exact provider UploadPart URL, never logged or checkpointed.
    pub url: String,
    /// Only headers explicitly granted; no Hub Authorization or Cookie.
    #[serde(default)]
    pub required_headers: Vec<DirectRequiredHeader>,
    /// Exclusive capability expiry; this does not settle in-flight requests.
    #[serde(default)]
    pub expires_at: WireInteger,
}

/// Public commitment to one required destination, without provider coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPlacementRef {
    /// Required placement row identity.
    #[serde(default)]
    pub placement_id: WireInteger,
    /// Immutable fingerprint of the complete admitted placement snapshot.
    pub placement_fingerprint: String,
    /// Exact placement row revision reviewed by discovery.
    pub placement_resource_version: WireInteger,
    /// Exact placement writer specification revision.
    pub write_spec_version: WireInteger,
    /// Exact storage binding row identity.
    pub binding_id: WireInteger,
    /// Exact storage binding row revision.
    pub binding_resource_version: WireInteger,
    /// Exact binding writer revision.
    pub binding_write_revision: WireInteger,
    /// Actual protected presign credential/coordinate publication commitment.
    pub profile_fingerprint: String,
    /// Independently qualified private staging policy commitment.
    pub private_policy_digest: String,
    /// Qualified provider checksum required before a stable part grant is requested.
    pub checksum_algorithm: DirectChecksumAlgorithm,
}

/// Compact completion commitment for one destination's provider-specific ETags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectManifestCommitment {
    /// Exact required destination.
    pub placement: DirectPlacementRef,
    /// Exact canonical ordered-part digest for this destination.
    pub manifest_digest: String,
    /// Exact complete part count.
    pub part_count: u32,
}

impl std::fmt::Debug for DirectPartGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectPartGrant")
            .field("session_id", &self.session_id)
            .field("grant_id", &self.grant_id)
            .field("grant_revision", &self.grant_revision)
            .field("part_number", &self.part.part_number)
            .field("url", &"[REDACTED]")
            .field("required_headers", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Session lifecycle; unknown provider outcomes cannot return to active by time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectSessionState {
    /// Initial provider creation is pending.
    Creating,
    /// Exact staged UploadPart grants may be issued.
    Active,
    /// New grants are closed while the retained manifest freezes.
    Freezing,
    /// Server-owned staging completion is pending.
    CompletingStaging,
    /// Immutable staging bytes passed independent full-size/SHA verification.
    StagedVerified,
    /// Guarded final-key materialization is pending.
    Promoting,
    /// Native has committed verified destinations and logical visibility.
    Committed,
    /// Exact server-owned abort is pending.
    Aborting,
    /// Abort is terminal; outstanding capability accounting remains separate.
    Aborted,
    /// A provider operation has an unknown outcome requiring reconciliation.
    BlockedUnknown,
    /// Terminal session retains private-resource cleanup obligations.
    CleanupPending,
}

impl std::fmt::Debug for DirectRequiredHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectRequiredHeader")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}
