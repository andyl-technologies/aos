//! Immutable storage addresses, bounded metadata, and provider observation values.

use anyhow::Result;

/// One multipart-upload part's identity: its 1-based `part_number` and the
/// backend's entity tag.
///
/// `etag` is the value the backend returns for an uploaded part and requires
/// back at completion. S3/R2 return their native opaque ETag; local disk
/// returns a SHA-256 tag and verifies it before assembly. The hub and client
/// carry the value through the wire protocol and echo the full ordered set
/// back at the multipart completion operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartTag {
    /// 1-based, contiguous part index.
    pub part_number: u32,
    /// Backend-returned part identity.
    pub etag: String,
}

/// Immutable physical address and topology fence for one provider operation.
///
/// Durable cleanup claims construct this value from their reviewed snapshot;
/// adapters must use [`Self::placement_prefix`] directly and must never select
/// a current writer. A binding row may be reopened only when its id and
/// resource version still match this fence. Plan and Apply validate the current
/// conditional-delete capability, while the durable claim revalidates this
/// frozen snapshot and its retained credential hold. The adapter therefore
/// resolves the exact frozen credential without consulting a capability or
/// credential head that may legitimately advance after Apply. For R2, the same
/// physical bucket/prefix must retain its guard namespace and authority identity
/// for its lifetime: upload versions do not settle an already dispatched DELETE
/// or make an authority rotation safe. The frozen
/// capability identity remains part of durable audit evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenSurfaceAccess {
    /// Registry whose physical object is being inspected or deleted.
    pub registry_id: i64,
    /// Frozen placement database id.
    pub placement_id: i64,
    /// Frozen placement display name for bounded diagnostics.
    pub placement_name: String,
    /// Frozen binding-relative placement prefix.
    pub placement_prefix: String,
    /// Frozen placement optimistic-concurrency version.
    pub placement_resource_version: i64,
    /// Frozen placement writer-critical topology version.
    pub placement_write_spec_version: i64,
    /// Frozen ready/complete observation version.
    pub placement_observation_version: i64,
    /// Frozen storage binding id.
    pub binding_id: i64,
    /// Frozen binding optimistic-concurrency version.
    pub binding_resource_version: i64,
    /// Frozen immutable binding-write revision.
    pub binding_write_revision: i64,
    /// Exact delete credential purpose, absent for credential-free local IO.
    pub delete_credential_purpose: Option<String>,
    /// Exact delete credential generation, absent for credential-free local IO.
    pub delete_credential_generation: Option<i64>,
    /// Fingerprint of the positively observed conditional-delete capability.
    pub delete_capability_fingerprint: String,
    /// Minimum capability observation resource version frozen for audit.
    pub delete_capability_resource_version: i64,
}

/// Durable-cleanup significance of a multipart abort attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultipartAbortOutcome {
    /// The backend confirmed that the staged upload was aborted.
    Aborted,
    /// The backend confirmed that no staged upload exists.
    Absent,
    /// The backend cannot distinguish an absent upload from one already completed.
    PossiblyCompleted,
}

impl FrozenSurfaceAccess {
    /// Validates the common frozen-address fence.
    ///
    /// # Errors
    ///
    /// Returns an error for missing identities, invalid versions, an unsafe
    /// prefix, or a half-populated delete credential pair.
    pub fn validate(&self) -> Result<()> {
        if self.registry_id <= 0
            || self.placement_id <= 0
            || self.placement_name.is_empty()
            || self.placement_name.len() > 255
            || self.placement_resource_version <= 0
            || self.placement_write_spec_version <= 0
            || self.placement_observation_version <= 0
            || self.binding_id <= 0
            || self.binding_resource_version <= 0
            || self.binding_write_revision <= 0
            || self.delete_capability_fingerprint.is_empty()
            || self.delete_capability_fingerprint.len() > 255
            || self.delete_capability_resource_version <= 0
            || self.delete_credential_purpose.is_some()
                != self.delete_credential_generation.is_some()
            || self
                .delete_credential_generation
                .is_some_and(|generation| generation <= 0)
        {
            anyhow::bail!("frozen surface access fence is invalid");
        }
        if self.placement_prefix.len() > 512
            || self.placement_prefix != self.placement_prefix.trim_matches('/')
            || self.placement_prefix != self.placement_prefix.trim()
            || self.placement_prefix.contains("//")
            || self
                .placement_prefix
                .split('/')
                .any(|component| matches!(component, "." | ".."))
            || self.placement_prefix.chars().any(char::is_control)
        {
            anyhow::bail!("frozen surface access prefix is invalid");
        }
        Ok(())
    }
}

/// Maximum narinfo body accepted by the inventory parser.
pub const MAX_CACHE_NARINFO_BYTES: usize = 256 * 1024;

/// Maximum bytes accepted for a Worker backend cursor.
pub const WORKER_MAX_SURFACE_LIST_CURSOR_BYTES: usize = 1024;

/// Bounded search fields derived from an authenticated Native document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationInspection {
    /// Digest of the exact document bytes bound by the signed artifact.
    pub document_sha256: String,
    /// Deterministic search rows extracted from the checked document.
    pub search: Vec<aos_module_docs::SearchDocument>,
}

/// Purpose-specific evidence from a controller-owned storage credential probe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialProbeEvidence {
    /// Whether the exact credential generation exercised its declared purpose.
    pub valid: bool,
    /// Whether a write probe proved create-if-absent semantics.
    pub conditional_writes_supported: bool,
    /// Sanitized failure classification when `valid` is false.
    pub error: Option<String>,
    /// Provider-neutral evidence safe to retain in operation detail.
    pub evidence: serde_json::Value,
}

/// Idle lifetime of an exclusive mutable-pointer publication lease.
pub const LEASE_TTL_SECS: i64 = 300;
