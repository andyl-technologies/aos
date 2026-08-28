//! Typed boundary for verified AOS container publication.
//!
//! Standard Distribution uploads remain independent of Hub internals. This
//! module carries the strict signed release declaration and versioned
//! begin/get/commit/abort lifecycle that a ConnectRPC adapter implements.

use anyhow::Result;
use aos_oci_types::{ContainerRelease, RepositoryName, Sha256Digest};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

/// Exact inputs that a Hub publication hook binds to a verified release root.
///
/// Standard Distribution pushes do not create this record. A first-party Hub
/// adapter implements [`VerifiedPublicationHook`] and supplies the concurrency
/// identities required by the control plane.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedPublicationRequest {
    /// Stable Hub registry identifier or slug resolved by the adapter.
    pub registry: String,
    /// Destination repository within the registry.
    pub repository: RepositoryName,
    /// Strict signed release declaration shared with `containers/v1/index.json`.
    pub release: ContainerRelease,
    /// Optional target tag advanced only by the verified commit.
    pub target_tag: Option<String>,
    /// Verified tag ownership: `release` or `channel`.
    pub target_kind: String,
    /// Expected target-tag resource version for compare-and-swap admission.
    pub expected_tag_version: Option<String>,
    /// Expected current target-tag digest for compare-and-swap admission.
    pub expected_tag_digest: Option<Sha256Digest>,
    /// Stable retry identity for begin/commit recovery.
    pub idempotency_key: String,
}

/// Result returned after a Hub commits a verified container publication.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedPublicationResult {
    /// Stable Hub publication identifier.
    pub publication_id: String,
    /// New publication resource version.
    pub resource_version: String,
    /// Exact verified signed-release root digest.
    pub verified_release_root: Sha256Digest,
    /// Exact root/index digest bound by the release.
    pub root_index_digest: Sha256Digest,
    /// Target tag advanced by the commit, when requested.
    pub target_tag: Option<String>,
    /// Digest of the complete frozen placement capability set.
    pub topology_digest: Sha256Digest,
    /// Number of placements required to hold every graph object.
    pub required_placement_count: u64,
    /// Authenticated owner of the tag: `release` or `channel`.
    pub source_kind: String,
}

/// Resumable state returned by begin/get publication operations.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedPublicationSession {
    /// Stable Hub publication identifier.
    pub publication_id: String,
    /// Current version required by commit or abort.
    pub resource_version: String,
    /// Absolute Unix expiry timestamp in seconds.
    pub expires_at: i64,
    /// Current durable lifecycle state used to resume or reject terminal work.
    pub state: String,
    /// Hash the caller must echo when committing this frozen publication plan.
    pub confirmation_hash: Sha256Digest,
    /// Digest of the complete frozen placement capability set.
    pub topology_digest: Sha256Digest,
    /// Number of placements required to hold every graph object.
    pub required_placement_count: u64,
    /// Authenticated owner of the tag: `release` or `channel`.
    pub source_kind: String,
}

/// Versioned confirmation that commits one admitted publication.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedPublicationCommit {
    /// Stable Hub publication identifier.
    pub publication_id: String,
    /// Expected publication resource version.
    pub resource_version: String,
    /// Stable retry identity for commit recovery.
    pub idempotency_key: String,
    /// Hash over the exact frozen upload/evidence confirmation.
    pub confirmation_hash: Sha256Digest,
}

/// Typed adapter for the Hub's versioned verified-publication control plane.
///
/// The Distribution client intentionally knows nothing about ConnectRPC paths
/// or Hub database models. The strict [`ContainerRelease`] is the single source
/// of truth for the signed sidecar and control-plane declaration.
#[allow(async_fn_in_trait)]
pub trait VerifiedPublicationHook: Send + Sync {
    /// Begins or resumes admission of a fully uploaded descriptor graph.
    ///
    /// # Errors
    ///
    /// Returns an error when publication admission or idempotent recovery fails.
    async fn begin(
        &self,
        request: &VerifiedPublicationRequest,
        cancellation: &CancellationToken,
    ) -> Result<VerifiedPublicationSession>;

    /// Gets the current resumable publication state.
    ///
    /// # Errors
    ///
    /// Returns an error when the publication is absent, unauthorized, expired,
    /// or cannot be queried.
    async fn get(
        &self,
        publication_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<VerifiedPublicationSession>;

    /// Commits a confirmed publication to one verified release root.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, incomplete placement/evidence,
    /// confirmation mismatch, signing failure, or tag compare-and-swap failure.
    async fn commit(
        &self,
        request: &VerifiedPublicationCommit,
        cancellation: &CancellationToken,
    ) -> Result<VerifiedPublicationResult>;

    /// Aborts a publication with versioned, idempotent recovery semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, authorization failure, or a control
    /// plane failure that prevents confirming the abort.
    async fn abort(
        &self,
        publication_id: &str,
        resource_version: &str,
        idempotency_key: &str,
        cancellation: &CancellationToken,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_session_exposes_recovery_and_commit_identity() {
        let confirmation_hash = Sha256Digest::digest(b"frozen publication plan");
        let session = VerifiedPublicationSession {
            publication_id: "publication-1".to_string(),
            resource_version: "3".to_string(),
            expires_at: 1_800_000_000,
            state: "uploading".to_string(),
            confirmation_hash,
            topology_digest: Sha256Digest::digest(b"frozen placement topology"),
            required_placement_count: 2,
            source_kind: "channel".to_string(),
        };

        let Ok(value) = serde_json::to_value(session) else {
            panic!("publication session must serialize");
        };
        assert_eq!(value["state"], "uploading");
        assert_eq!(value["confirmation_hash"], confirmation_hash.to_string());
        assert_eq!(value["required_placement_count"], 2);
        assert_eq!(value["source_kind"], "channel");
    }
}
