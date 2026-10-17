//! Closed file selections for an independently reviewed functional Mirror probe.
//!
//! Paths locate retained evidence; only byte commitments enter the candidate.
//! No selection field is a permission, qualification flag or measured counter.
//!
//! ```text
//! selection = {version, reviewerKeyId, reviewerPublicKey, deploymentId,
//! publicOrigin, sourceDigest, scriptVersion, profileDigest, upstreamBase,
//! placementPrefix, maximumObjectBytes, issuedAt, validUntil, inputs, clocks}
//! file = {path, sha256, byteSize}
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) use crate::direct_upload_review::ReviewedFile;

/// Selects exact retained bytes; paths may be absolute or relative to selection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorReviewFile {
    /// Private locator, excluded from public candidates.
    pub path: PathBuf,
    /// Independently selected lowercase SHA-256 of the complete file.
    pub sha256: String,
    /// Exact complete byte count, checked in addition to the hash.
    pub byte_size: u64,
}

/// Selects one original authenticated Clock exchange and reference bracket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorClockFiles {
    /// Actual original request body.
    pub request: MirrorReviewFile,
    /// Actual received reply body.
    pub reply: MirrorReviewFile,
    /// Actual signature, status and send/receive observation.
    pub authentication: MirrorReviewFile,
}

/// Selects the independently retained inputs used during prepare and sign.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorReviewInputs {
    /// Current signed Direct prerequisite, not a Mirror approval.
    pub prerequisite_artifact: MirrorReviewFile,
    /// Separately trusted Direct reviewer identity map.
    pub prerequisite_review_keys: MirrorReviewFile,
    /// Actual common tuple, including the selected serving role provenance.
    pub artifact_manifest: MirrorReviewFile,
    /// Actual current installation report in the shared Direct format.
    pub worker_installation: MirrorReviewFile,
    /// Complete installed Wasm bytes.
    pub wasm: MirrorReviewFile,
    /// Complete installed Worker shim bytes.
    pub script: MirrorReviewFile,
    /// Complete current source-built runner bytes.
    pub runner: MirrorReviewFile,
    /// Complete actual source-built runtime executable bytes.
    pub runtime_executable: MirrorReviewFile,
    /// Exact serving-role executable, which may be a controlled test helper.
    pub native_serving_executable: MirrorReviewFile,
    /// Actual initially installed Worker configuration bytes.
    pub configuration: MirrorReviewFile,
    /// Actual External namespace readback, with runner process identity.
    pub namespace: MirrorReviewFile,
    /// Independently pinned live Native serving process and constructor inputs.
    pub native_observation: MirrorReviewFile,
    /// Exact retained helper input consumed before its real readiness report.
    pub native_input: MirrorReviewFile,
    /// Exact actual post-constructor serving readiness report.
    pub native_readiness: MirrorReviewFile,
    /// Actual current List/publication export, not a supplied cohort approval.
    pub list_export: MirrorReviewFile,
    /// Actual retained provider report with its full bounded original.
    pub provider_report: MirrorReviewFile,
    /// Source-built conformance executable that produced this exact report.
    pub provider_conformance_executable: MirrorReviewFile,
    /// Source-built Nix store observer used only for actual installed deriver queries.
    pub nix_store_executable: MirrorReviewFile,
    /// Actual private complete journal; the unchanged projector checks all phases.
    pub provider_journal: PathBuf,
    /// Private conformance verifier used solely to authenticate Clock captures.
    pub conformance_key: MirrorReviewFile,
}

/// Selects a finite functional probe under one actual current External profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalMirrorReviewSelection {
    /// Closed selection version, currently one.
    pub version: u32,
    /// Separately installed functional reviewer identity.
    pub reviewer_key_id: String,
    /// Separately installed public verifier, distinct from other reviewer roles.
    pub reviewer_public_key: MirrorReviewFile,
    /// Actual current paired deployment.
    pub deployment_id: String,
    /// Actual current public Worker HTTPS origin.
    pub public_origin: String,
    /// Exact current compiled Worker source identity.
    pub source_digest: String,
    /// Exact source-derived emulator script identity.
    pub script_version: String,
    /// Exact independently accepted External profile to select, not construct.
    pub profile_digest: String,
    /// Exact reserved signed fixture upstream selected before the probe.
    pub upstream_base: String,
    /// Exact reserved relative root with full and pull-through children.
    pub placement_prefix: String,
    /// Administrative bound beneath the accepted prerequisite; not measured peaks.
    pub maximum_object_bytes: u64,
    /// Immutable issue time, which sign never renews.
    pub issued_at: u64,
    /// Immutable exclusive cutoff within the prerequisite and fifteen minutes.
    pub valid_until: u64,
    /// Explicit file selection, re-opened during prepare and sign.
    pub inputs: MirrorReviewInputs,
    /// At least two distinct original authenticated Clock captures.
    pub clocks: Vec<MirrorClockFiles>,
}

/// Carries the unsigned functional-only statement for explicit independent review.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalMirrorReviewCandidate {
    /// Closed candidate version, currently one.
    pub version: u32,
    /// Commitment to exact private selection bytes, without disclosing locators.
    pub selection_sha256: String,
    /// Separately installed functional reviewer public key.
    pub trusted_public_key: String,
    /// Exact unsigned shared artifact; no Hosted qualification can be represented.
    pub artifact:
        aos_hub_core::mirror_acceptance::external_controlled::ControlledExternalMirrorArtifact,
}
