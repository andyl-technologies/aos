//! Metadata-only logical direct-upload dispatch and retained lifecycle ordering.
//!
//! The configured authority resolves current IAM, topology and independently
//! qualified storage receipts. SQL retains immutable originals before effects;
//! final target statements, receipt and session progress share one transaction.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::backend::CheckedStatement;
use crate::db::Database;
use crate::db::DirectSqlOwner;
use crate::db::DirectUploadSessionRecord;
use aos_hub_model::auth::jwt::Claims;

use super::*;

/// Value-free refusal classification shared by configured authorities and SQL.
#[derive(Debug, thiserror::Error)]
#[error("direct logical control refused")]
pub struct DirectUploadRefusal {
    /// Stable public item failure code, without provider or private values.
    pub code: DirectItemErrorCode,
}

/// Server-resolved target reservation and immutable admission.
pub struct ResolvedDirectAdmission {
    /// Complete original admission, including independently pinned profiles.
    pub admission: DirectUploadAdmission,
    /// Current stable target scope used for every later authorization.
    pub owner_scope_key: String,
    /// Existing target accounting reservation retained before provider effects.
    pub owner: DirectSqlOwner,
    /// Current credential and scoped IAM fences executed with retained admission.
    pub authority_statements: Vec<CheckedStatement>,
}

/// Exact metadata phases eligible for held-positive recovery after producer expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectPositiveMetadataPhase {
    /// Reads the already retained original Complete without new provider effects.
    Freeze,
    /// Commits exact independently verified final receipts and logical accounting.
    Commit,
}

/// Configured current target and independent receipt authority.
///
/// Every method accepts bounded typed metadata. Implementations must refuse
/// absent qualification and must never replace guard lookup with broker MAC,
/// a client report, provider HEAD, or a structurally valid receipt document.
#[async_trait]
pub trait DirectUploadAuthority: Send + Sync {
    /// Creates isolated discovery state for exactly one logical invocation.
    ///
    /// A prepared profile readback may be shared only within this invocation;
    /// every reuse checks its exact context and current qualification deadline.
    fn invocation(&self) -> Arc<dyn DirectUploadAuthority>;

    /// Observes the current conservative bound from the qualified mutation clock.
    ///
    /// # Errors
    /// Returns an error for unavailable qualification, rollback or clock failure.
    fn current_time(&self) -> Result<i64>;

    /// Resolves current reusable target IAM and independently qualified profiles.
    ///
    /// # Errors
    /// Returns an error for revoked IAM, unavailable profiles or stale topology.
    async fn capabilities(
        &self,
        claims: &Claims,
        target: &DirectCapabilitiesTarget,
        now: i64,
    ) -> Result<DirectUploadCapabilities>;

    /// Resolves current IAM, target reservation, required placements and profiles.
    ///
    /// # Errors
    /// Returns an error for refused IAM, quota, stale topology or qualification.
    async fn resolve_admission(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        intent: &DirectUploadIntent,
        now: i64,
    ) -> Result<ResolvedDirectAdmission>;

    /// Checks live target IAM and the original actor for the requested action.
    ///
    /// # Errors
    /// Returns an error for changed target ownership, revoked authority or barriers.
    async fn authorize_session(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        action: DirectLogicalAction,
        metadata_phase: Option<DirectPositiveMetadataPhase>,
        now: i64,
    ) -> Result<()>;

    /// Independently verifies immutable stage provenance and classifies semantics.
    ///
    /// # Errors
    /// Returns an error for missing independent provenance or invalid semantics.
    async fn verify_stage(
        &self,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectVerifiedStageEvidence,
        now: i64,
    ) -> Result<DirectDependencyPhase>;

    /// Activates retained destination baselines and returns fresh permissions.
    ///
    /// # Errors
    /// Returns an error for changed originals, stale guard witnesses or quota.
    async fn baseline_permissions(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &[DirectDestinationBaselineEvidence],
        witnesses: &[DirectDestinationBaselineWitness],
        settled: &[DirectSettledPlacement],
        now: i64,
    ) -> Result<Vec<DirectDestinationBaselinePermission>>;

    /// Looks up exact current receipts independently and prepares target SQL.
    ///
    /// All target accounting, object presence, links and upload completion must
    /// be returned as checked statements without executing them separately.
    ///
    /// # Errors
    /// Returns an error for unavailable or changed guard receipts and target fences.
    async fn verify_final(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectCompletionEvidence,
        guards: &[DirectFinalGuardRecord],
        now: i64,
    ) -> Result<Vec<CheckedStatement>>;

    /// Verifies explicit abort progress and builds atomic terminal target settlement.
    ///
    /// # Errors
    /// Returns an error for uncorrelated or unsupported terminal abort evidence.
    async fn verify_abort(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectAbortEvidence,
        now: i64,
    ) -> Result<Vec<CheckedStatement>>;
}
