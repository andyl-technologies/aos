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
    /// Original Managed effect permission; External uses its own closed original.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_effect: Option<OciDocumentEffect>,
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
    /// Separate signed OCI control for an independently qualified external writer.
    /// Managed omits this field and preserves its historical canonical admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external:
        Option<crate::storage_authority::external_object::oci::admission::ExternalOciStagePermit>,
    /// Original Managed effect permission; External uses its own closed original.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_effect: Option<OciDocumentEffect>,
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

/// Immutable permission for new Managed OCI document SDK effects.
///
/// This is retained in the private manifest commitment and completion intent.
/// A later qualification lookup cannot replace its profile or extend its cutoff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciDocumentEffect {
    /// Exact independently accepted Managed provider and policy.
    pub protected_profile_digest: String,
    /// Exact independently signed acceptance evidence.
    pub acceptance_digest: String,
    /// Original acceptance issue time in UTC seconds.
    pub issued_at: u64,
    /// Exclusive cutoff clipped to the original upload and actor permission.
    pub expires_at: u64,
    /// Installed conservative UTC uncertainty, preserved across every hop.
    pub clock_uncertainty_seconds: u64,
}

impl OciDocumentEffect {
    /// Rejects malformed, expired, or backwards-clock dispatch permission.
    ///
    /// # Errors
    /// Returns an error for invalid commitments, clock bounds, or expiry.
    pub fn check(&self, raw_now: u64) -> anyhow::Result<()> {
        anyhow::ensure!(
            crate::direct_upload::valid_direct_digest(&self.protected_profile_digest)
                && crate::direct_upload::valid_direct_digest(&self.acceptance_digest)
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && self.issued_at <= raw_now
                && self.issued_at < self.expires_at
                && raw_now
                    .checked_add(self.clock_uncertainty_seconds)
                    .is_some_and(|latest| latest < self.expires_at),
            "original OCI document effect permission is unavailable"
        );
        Ok(())
    }
}
