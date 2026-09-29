//! Typed private Native phases; public bodies cannot choose provider effects.

use serde::{Deserialize, Serialize};

use super::*;

/// Public action whose exact request/body is bound by Native authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectLogicalAction {
    /// Sparse status without provider settlement inference.
    Status,
    /// Exact bounded delegated grant batch.
    GrantParts,
    /// Exact bounded client observation batch.
    ReportParts,
    /// Compact server-owned completion and verified Native commit.
    Complete,
    /// Exact server-owned logical abort.
    Abort,
}

/// Session identity and optional exact Native mutation CAS version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectSessionAuthorization {
    /// Original session and immutable fingerprint.
    pub session: DirectSessionRef,
    /// Required for Complete/Abort; absent for progress reads and part controls.
    pub expected_resource_version: Option<WireInteger>,
    /// Stable original public item operation identity, including promotion authorization.
    pub operation_id: String,
    /// Exact original per-item Complete intent retained before freeze, Complete only.
    pub complete_intent: Option<DirectCompleteRequest>,
}

/// Closed provider abort observation; none implies delegated grant settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectAbortOutcome {
    /// Server-owned abort intent is retained and awaiting provider completion.
    Pending,
    /// Provider effect outcome is unknown and independent fences remain.
    Unknown,
    /// Provider abort has a terminal positive receipt; resource tails remain.
    Aborted,
}

/// Compact abort effect evidence bound to an original session and operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectAbortEvidence {
    /// Exact original session.
    pub session: DirectSessionRef,
    /// Stable server-owned abort operation identity.
    pub operation_id: String,
    /// Explicit retained effect outcome.
    pub outcome: DirectAbortOutcome,
    /// Terminal retained receipt commitment, mandatory only when Aborted.
    pub receipt_digest: Option<String>,
}

/// Exact private logical phase selected by a protected signed request header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectUploadLogicalRequest {
    /// BeginBatch-only logical admission, before any provider session effect.
    Admission {
        /// Immutable per-object intents from the original request.
        intents: Vec<DirectUploadIntent>,
    },
    /// Exact matching public action and original request authorization.
    Authorize {
        /// Public action bound by the request context.
        action: DirectLogicalAction,
        /// Complete-only fresh authorization before freeze or final promotion.
        complete_step: Option<DirectCompleteStep>,
        /// Complete/Promote-only exact parsed immutable stage proofs, before finals.
        stage_evidence: Vec<DirectVerifiedStageEvidence>,
        /// Exact logical sessions and mutation CAS versions.
        sessions: Vec<DirectSessionAuthorization>,
    },
    /// CompleteBatch-only verified final placement commit.
    Commit {
        /// Broker-signed independent source and final promotion proofs.
        evidence: Vec<DirectCompletionEvidence>,
    },
    /// Abort-only compact effect reporting, preserving unknown/provider history.
    AbortReport {
        /// Independently correlated explicit server-owned abort observations.
        outcomes: Vec<DirectAbortEvidence>,
    },
}

/// Exact private reply consumed by the broker before provider/control effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectUploadLogicalReply {
    /// Resolved immutable admission snapshots; never provider credentials.
    pub admissions: Vec<DirectUploadAdmission>,
    /// Authoritative logical statuses and versions after admission/commit/abort.
    pub sessions: Vec<DirectSessionStatus>,
    /// Exact session/action authorizations, empty for non-authorize phases.
    pub authorizations: Vec<DirectSessionAuthorization>,
    /// Independent value-free per-item refusals.
    pub errors: Vec<DirectItemError>,
}

/// Separately refreshed Native authority before each long-running complete boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectCompleteStep {
    /// Closes grants and freezes original retained parts for staging completion.
    Freeze,
    /// Fresh ACL/CAS authorization before final provider-key promotion.
    Promote,
}

impl DirectUploadLogicalRequest {
    /// Returns the exact private upload-phase header selected by this arm.
    #[must_use]
    pub const fn phase(&self) -> &'static str {
        match self {
            Self::Admission { .. } => "admission",
            Self::Authorize { .. } => "authorize",
            Self::Commit { .. } => "commit",
            Self::AbortReport { .. } => "abort-report",
        }
    }
}
