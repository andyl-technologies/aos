//! Closed owner-private selection for the OCI-only local SDK reviewer.
//!
//! All paths are private input locators. They are excluded from the candidate;
//! selected digests identify exact retained bytes, never caller readiness flags.

use std::path::PathBuf;

use aos_hub_core::{direct_upload::DirectClockPolicy, oci_sdk_emulation::OciSdkEmulationArtifact};
use serde::{Deserialize, Serialize};

pub use crate::direct_upload_review::ReviewedFile;

/// Selects the three exact files retained for one authenticated Clock exchange.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkClockCapture {
    /// Exact request bytes retained before dispatch.
    pub request: ReviewedFile,
    /// Exact signed response bytes retained after dispatch.
    pub reply: ReviewedFile,
    /// Actual send/receive brackets and observed reply signature.
    pub authentication: ReviewedFile,
}

/// Selects independently installed regular files for byte-by-byte rechecking.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkInstalledFiles {
    /// Actual Native ELF selected for this pair.
    pub native_executable: ReviewedFile,
    /// Actual Worker Wasm selected for this pair.
    pub wasm: ReviewedFile,
    /// Actual installed Worker shim.
    pub shim: ReviewedFile,
    /// Actual owner-private runner configuration.
    pub configuration: ReviewedFile,
    /// Actual selected runner source.
    pub runner: ReviewedFile,
    /// Actual installed Miniflare module.
    pub miniflare_module: ReviewedFile,
    /// Actual installed R2 entry worker.
    pub miniflare_entry_worker: ReviewedFile,
    /// Actual installed R2 bucket worker.
    pub miniflare_bucket_worker: ReviewedFile,
    /// Actual workerd executable.
    pub workerd_executable: ReviewedFile,
    /// Source-built Nix executable used to stream both immutable NARs.
    pub nix_executable: ReviewedFile,
}

/// Selects one independently retained local Native/Worker pair and anchor.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkReviewSelection {
    /// Closed selection version, currently one.
    pub version: u32,
    /// Separately installed fixture reviewer identity.
    pub reviewer_key_id: String,
    /// Separately installed fixture reviewer public key.
    pub reviewer_public_key: ReviewedFile,
    /// Expected deployment selected independently from the raw observations.
    pub deployment_id: String,
    /// Exact local Worker HTTPS origin.
    pub public_origin: String,
    /// Exact local Native HTTPS origin.
    pub native_origin: String,
    /// Expected current compiled source; an old source cannot be relabeled.
    pub expected_source_digest: String,
    /// Expected source-derived script identity.
    pub expected_script_version: String,
    /// Actual immutable filtered source store path used by the build.
    pub source_store_path: PathBuf,
    /// Actual immutable installed Worker distribution store path.
    pub distribution_store_path: PathBuf,
    /// Explicitly reviewed actual source NAR SHA-256.
    pub source_nar_sha256: String,
    /// Explicitly reviewed actual distribution NAR SHA-256.
    pub distribution_nar_sha256: String,
    /// Original artifact issue time; preparation does not renew it.
    pub issued_at: u64,
    /// Original artifact exclusive cutoff; signing does not renew it.
    pub expires_at: u64,
    /// Exact installed conservative clock policy.
    pub clock_policy: DirectClockPolicy,
    /// Exact installed OCI provider capacity.
    pub maximum_provider_requests: u32,
    /// Independently reviewed private namespace policy identity.
    pub private_stage_policy_id: String,
    /// Independently observed live namespace/process mapping.
    pub namespace_observation: ReviewedFile,
    /// Independently observed Native process and executable projection.
    pub native_observation: ReviewedFile,
    /// Exact private Native argv/environment capture referenced by that report.
    pub native_configuration: ReviewedFile,
    /// Retained one-shot SDK original persisted before dispatch.
    pub anchor_original: ReviewedFile,
    /// Exact positive SDK response, never an unknown or SQL reconstruction.
    pub anchor_receipt: ReviewedFile,
    /// At least two independently retained authenticated Clock exchanges.
    pub clocks: Vec<OciSdkClockCapture>,
    /// Protected UTF-8 conformance key used solely to authenticate Clock captures.
    pub conformance_key_file: PathBuf,
    /// Installed file selections rehashed during prepare and sign.
    pub installed: OciSdkInstalledFiles,
}

/// Carries an unsigned candidate and explicit measured-operation scope.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkReviewCandidate {
    /// Closed candidate version, currently one.
    pub version: u32,
    /// Commitment to the exact private selection without exposing its paths.
    pub selection_sha256: String,
    /// Separately installed fixture reviewer verifier.
    pub trusted_public_key: String,
    /// Narrow scope of the observed zero post-cutoff effects.
    pub observed_operation_scope: OciSdkObservedOperationScope,
    /// Exact unsigned OCI-only acceptance; no other authority is representable.
    pub artifact: OciSdkEmulationArtifact,
}

/// Identifies the only actual provider operations measured by this fixture.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciSdkObservedOperationScope {
    /// One create-only anchor PUT and one exact conditional full GET.
    AnchorCreateAndConditionalRead,
}
