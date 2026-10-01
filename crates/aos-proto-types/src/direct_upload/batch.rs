//! Bounded public batched admission, sparse progress and delegated part controls.

use serde::{Deserialize, Serialize};

use super::{
    DirectManifestCommitment, DirectManifestPart, DirectPart, DirectPartGrant, DirectPlacementRef,
    DirectSessionState, DirectUploadIntent,
};

/// One exact authenticated logical session reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectSessionRef {
    /// Stable session identity returned by the original admission.
    pub session_id: String,
    /// Exact immutable logical admission fingerprint.
    pub logical_fingerprint: String,
}

/// Logical authorization reference shared by Native and broker adapters.
pub type DirectUploadSessionRef = DirectSessionRef;

/// Sparse pagination position ordered by placement then part number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPartCursor {
    /// Required destination represented by this position.
    pub placement: DirectPlacementRef,
    /// Last part number included, or zero before the first part.
    pub part_number: u32,
}

/// Retained observation and unknown-operation state for one part/destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPartStatus {
    /// Required destination.
    pub placement: DirectPlacementRef,
    /// One-based immutable part number.
    pub part_number: u32,
    /// Last exact observed provider part; not a settled capability assertion.
    #[serde(default)]
    pub observed: Option<DirectManifestPart>,
    /// Retained provider-operation identity if an attempt remains pending.
    #[serde(default)]
    pub pending_operation_id: Option<String>,
    /// True if an operation outcome remains unknown and must be reconciled.
    #[serde(default)]
    pub unknown: bool,
}

/// Resume projection containing no bearer URLs, credentials or provider UploadId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectSessionStatus {
    /// Exact admitted session and fingerprint.
    pub session: DirectSessionRef,
    /// Exact Native logical version used by complete/abort CAS.
    #[serde(default)]
    pub resource_version: super::WireInteger,
    /// Exact immutable source/owner/geometry echoed for resume validation.
    pub intent: DirectUploadIntent,
    /// Sorted complete required destination set.
    #[serde(default)]
    pub placements: Vec<DirectPlacementRef>,
    /// Retained session lifecycle.
    pub state: DirectSessionState,
    /// Bounded sparse part page across the required destinations.
    #[serde(default)]
    pub parts: Vec<DirectPartStatus>,
    /// Next exact pagination position, absent only at the end of this snapshot.
    #[serde(default)]
    pub next_cursor: Option<DirectPartCursor>,
    /// True while any delegated capability has retained accounting obligations.
    #[serde(default)]
    pub outstanding_grants: bool,
}

/// Immutable logical declarations in one admission batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectBeginBatch {
    /// Stable batch operation identity, independent of retry nonce/timestamps.
    pub operation_id: String,
    /// Independently idempotent logical object intents.
    #[serde(default)]
    pub items: Vec<DirectUploadIntent>,
}

/// One bounded sparse-status request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectStatusQuery {
    /// Exact admitted session.
    pub session: DirectSessionRef,
    /// Exclusive starting position; absent starts before the first part.
    #[serde(default)]
    pub after: Option<DirectPartCursor>,
    /// Requested part count; batch aggregate remains at most 64.
    pub maximum_parts: u32,
}

/// One direct part grant request; server recomputes all geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectGrantPartRequest {
    /// Exact admitted session.
    pub session: DirectSessionRef,
    /// Exact required destination, making post-fanout grant budgets explicit.
    pub placement: DirectPlacementRef,
    /// Stable delegated grant operation identity.
    pub operation_id: String,
    /// Exact requested geometry and independent part checksum declaration.
    pub part: DirectPart,
}

/// Authenticated client observation, never proof of provider/grant settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPartReport {
    /// Exact admitted session.
    pub session: DirectSessionRef,
    /// Exact physical destination of this observation.
    pub placement: DirectPlacementRef,
    /// Stable report operation identity.
    pub operation_id: String,
    /// Exact grant identity that authorized the observed transfer.
    pub grant_id: String,
    /// Exact original retained grant revision.
    #[serde(default)]
    pub grant_revision: super::WireInteger,
    /// Observed provider result and the original byte/checksum declaration.
    pub observed: DirectManifestPart,
}

/// Compact complete request, referencing retained per-part records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectCompleteRequest {
    /// Exact admitted session.
    pub session: DirectSessionRef,
    /// Stable server-owned completion operation identity.
    pub operation_id: String,
    /// Expected Native logical session version; part progress never advances it.
    #[serde(default)]
    pub expected_resource_version: super::WireInteger,
    /// Sorted complete required destination manifest commitments.
    #[serde(default)]
    pub manifests: Vec<DirectManifestCommitment>,
}

/// Exact server-owned abort request; success does not settle grant resource tails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectAbortRequest {
    /// Exact admitted session.
    pub session: DirectSessionRef,
    /// Stable abort operation identity.
    pub operation_id: String,
    /// Expected Native logical session version for abort authorization/CAS.
    #[serde(default)]
    pub expected_resource_version: super::WireInteger,
}

/// One explicitly correlated bounded batch of typed operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct DirectBatch<T> {
    /// Stable public batch identity.
    pub operation_id: String,
    /// Typed bounded operations; aggregate part limits apply after fanout.
    #[serde(default)]
    pub items: Vec<T>,
}

/// Closed public request shape shared by Native, broker and generated clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DirectUploadRequest {
    /// Admits a bounded set of immutable logical objects.
    BeginBatch(DirectBeginBatch),
    /// Queries a bounded sparse progress page.
    StatusBatch(DirectBatch<DirectStatusQuery>),
    /// Delegates bounded exact private-stage UploadPart operations.
    GrantPartsBatch(DirectBatch<DirectGrantPartRequest>),
    /// Records bounded authenticated client observations.
    ReportPartsBatch(DirectBatch<DirectPartReport>),
    /// Completes bounded logical sessions from compact manifest commitments.
    CompleteBatch(DirectBatch<DirectCompleteRequest>),
    /// Aborts bounded exact logical sessions without erasing unknown fences.
    Abort(DirectBatch<DirectAbortRequest>),
}

/// Closed item failure codes, with no raw provider response or capability URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectItemErrorCode {
    /// Invalid immutable declaration or geometry.
    Invalid,
    /// Logical owner, ACL or quota refused admission.
    Denied,
    /// A stable operation was retried with different immutable inputs.
    Conflict,
    /// Required direct topology or provider semantics are unavailable.
    Unsupported,
    /// A retained provider operation has an unknown outcome.
    BlockedUnknown,
    /// A control dependency is temporarily unavailable.
    Unavailable,
}

/// Independent per-item error; no other item becomes committed by this failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectItemError {
    /// Stable item operation or session identity correlated by the caller.
    pub item_id: String,
    /// Closed failure classification.
    pub code: DirectItemErrorCode,
}

/// Bounded public batch reply; physical completion proofs remain server-private.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectUploadResponse {
    /// Exact public batch operation identity.
    pub operation_id: String,
    /// Bounded admitted/resumed/committed logical session projections.
    #[serde(default)]
    pub sessions: Vec<DirectSessionStatus>,
    /// At most 64 exact bearer part grants after placement fanout.
    #[serde(default)]
    pub grants: Vec<DirectPartGrant>,
    /// Value-free independent per-item refusals.
    #[serde(default)]
    pub errors: Vec<DirectItemError>,
}

impl std::fmt::Debug for DirectUploadResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectUploadResponse")
            .field("operation_id", &self.operation_id)
            .field("session_count", &self.sessions.len())
            .field("grant_count", &self.grants.len())
            .field("errors", &self.errors)
            .finish()
    }
}
