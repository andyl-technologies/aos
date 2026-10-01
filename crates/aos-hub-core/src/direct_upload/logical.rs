//! Typed private Native phases; public bodies cannot choose provider effects.

use anyhow::{ensure, Result};
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

/// Positively published original placement retained during partial promotion replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectSettledPlacement {
    /// Exact positive original promotion receipt for one required destination.
    pub evidence: DirectPlacementEvidence,
    /// Independently readable final guard bound to the original reservation.
    pub guard: DirectFinalGuardRecord,
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
        /// Baseline-only exact parsed immutable stage proofs, before finals.
        stage_evidence: Vec<DirectVerifiedStageEvidence>,
        /// Promote-only exact commitments to the independently retained verified stages.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        retained_stage_digests: Vec<DirectRetainedStageDigest>,
        /// Immutable first destination observations; Native requires them for cache Promote.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        baseline_evidence: Vec<DirectDestinationBaselineEvidence>,
        /// Distinct current witnesses for the same first baselines and held reservations.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        baseline_witnesses: Vec<DirectDestinationBaselineWitness>,
        /// Promote-only fresh witnesses omitting their already paired full baseline binding.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        baseline_witness_refs: Vec<DirectBaselineWitnessRef>,
        /// Positively published destinations; fresh witnesses cover only remaining destinations.
        settled_placements: Vec<DirectSettledPlacement>,
        /// Exact logical sessions and mutation CAS versions.
        sessions: Vec<DirectSessionAuthorization>,
    },
    /// CompleteBatch-only verified final placement commit.
    Commit {
        /// Broker-signed independent source and final promotion proofs.
        evidence: Vec<DirectCompletionEvidence>,
        /// Original final reservations and exact guard receipts; Native performs
        /// a fresh independent lookup before committing any logical target.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        final_guards: Vec<DirectFinalGuardRecord>,
        /// Exact full-record commitments expanded from Native-retained original reservations.
        final_guard_refs: Vec<DirectFinalGuardRef>,
    },
    /// Abort-only compact effect reporting, preserving unknown/provider history.
    AbortReport {
        /// Independently correlated explicit server-owned abort observations.
        outcomes: Vec<DirectAbortEvidence>,
    },
}

/// Compact retained Freeze status paired with the full original admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectLogicalSessionSummary {
    /// Exact retained session and logical fingerprint.
    pub session: DirectSessionRef,
    /// Current Native resource version, never reconstructed by the broker.
    pub resource_version: WireInteger,
    /// Current retained lifecycle state.
    pub state: DirectSessionState,
    /// Native's current grant fence projection.
    pub outstanding_grants: bool,
}

impl DirectLogicalSessionSummary {
    /// Reconstructs public status from an exactly correlated immutable admission.
    ///
    /// # Errors
    /// Returns an error for a foreign original, malformed retained status or projection.
    pub fn status(
        &self,
        admission: &DirectUploadAdmission,
        deployment: &str,
    ) -> Result<DirectSessionStatus> {
        admission.validate(deployment)?;
        ensure!(
            self.session.session_id == admission.session_id
                && self.session.logical_fingerprint == admission.logical_fingerprint,
            "direct summary original admission mismatch"
        );
        let status = DirectSessionStatus {
            session: self.session.clone(),
            resource_version: self.resource_version,
            intent: admission.intent.clone(),
            placements: admission
                .placements
                .iter()
                .map(|placement| placement.public_ref(deployment))
                .collect::<Result<Vec<_>>>()?,
            state: self.state,
            parts: Vec::new(),
            next_cursor: None,
            outstanding_grants: self.outstanding_grants,
        };
        status.validate()?;
        Ok(status)
    }
}

/// Exact private reply consumed by the broker before provider/control effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectUploadLogicalReply {
    /// Originals omitted from Complete Baseline and Promote; never provider credentials.
    pub admissions: Vec<DirectUploadAdmission>,
    /// Authoritative statuses, omitted from Complete Baseline and Promote replies.
    pub sessions: Vec<DirectSessionStatus>,
    /// Compact Freeze states and versions paired with exact full admissions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_summaries: Vec<DirectLogicalSessionSummary>,
    /// Exact session/action authorizations, empty for non-authorize phases.
    pub authorizations: Vec<DirectSessionAuthorization>,
    /// Exact committed Native baseline activations and fresh per-placement permissions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub baseline_permissions: Vec<DirectDestinationBaselinePermission>,
    /// Independent value-free per-item refusals.
    pub errors: Vec<DirectItemError>,
}

/// Separately refreshed Native authority before each long-running complete boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectCompleteStep {
    /// Closes grants and freezes original retained parts for staging completion.
    Freeze,
    /// Reserves and observes final keys; authorizes no destination mutation.
    Baseline,
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
