//! Bounded manifest staging decisions shared by Worker ingress and Native.

use serde::{Deserialize, Serialize};

/// Largest exact OCI manifest or index accepted by any Hub runtime.
pub const MAX_HYBRID_OCI_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Private completion query parameter bound by the ingress request signature.
pub const HYBRID_OCI_MANIFEST_UPLOAD_QUERY: &str = "aos_hybrid_manifest_upload";

/// Worker-computed byte identity for reserving one manifest staging attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridOciManifestPreflight {
    /// Original client Content-Type, checked by the shared OCI parser.
    pub media_type: aos_oci_types::MediaType,
    /// Portable hash continuation after reading the bounded manifest body.
    pub sha256_state: crate::db::OciSha256State,
}

/// Completes a reservation without relaying original OCI bytes to Native.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridOciManifestCompletion {}

/// Native's durable reservation for writing exact manifest bytes beside R2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridOciManifestAdmission {
    /// Commitment to the exact Native target, actor, reference and writer pins.
    pub original_digest: String,
    /// Upload reservation owned by the authenticated manifest writer.
    pub upload_id: String,
    /// Frozen placement prefix within the deployment R2 bucket.
    pub placement_prefix: String,
    /// Attempt-unique object path already retained in SQL for cleanup.
    pub staging_object_key: String,
    /// Exact byte count reserved by Native before the Worker writes.
    pub byte_size: u64,
    /// Lowercase SHA-256 computed over the client body.
    pub sha256: String,
}
