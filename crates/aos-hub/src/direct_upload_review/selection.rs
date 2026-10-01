//! Closed reviewer selection manifests and their unsigned candidate format.
//!
//! ```text
//! selection = {version, executionKind, reviewerKeyId, deploymentId, publicOrigin,
//! sourceDigest, scriptVersion, workerName, runtimeBounds, issuedAt, validUntil,
//! documents, reports, captureFiles, privacyFiles, installedFiles}
//! candidate = {version, selectionSha256, trustedPublicKey, artifact}
//! ```

use std::path::PathBuf;

use aos_hub_core::direct_upload::*;
use serde::{Deserialize, Serialize};

/// Exact selected file bytes; relative paths resolve beside the selection file.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewedFile {
    /// Local input locator, excluded from the public candidate output.
    pub path: PathBuf,
    /// Explicit independently reviewed lowercase SHA-256 of the file bytes.
    pub sha256: String,
}

/// Explicit runtime bounds selected by the independent reviewer.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewRuntimeBounds {
    /// Largest object size to qualify from actual positive measurements.
    pub maximum_object_bytes: WireInteger,
    /// Actual accepted verification budget, in seconds.
    pub maximum_verification_seconds: WireInteger,
    /// Actual accepted settlement reserve, in seconds.
    pub settlement_reserve_seconds: WireInteger,
    /// Participating isolate aggregate object capacity.
    pub maximum_parallel_objects: WireInteger,
    /// Participating isolate aggregate provider request capacity.
    pub maximum_parallel_provider_requests: WireInteger,
}

/// Exact measured documents selected for candidate assembly.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewDocuments {
    /// Independently installed reviewer verifier bytes.
    pub reviewer_public_key: ReviewedFile,
    /// Actual protected deployment discovery projection.
    pub deployment_identity: ReviewedFile,
    /// Actual ordinary SDK observations, required for managed execution.
    pub sdk_probe: Option<ReviewedFile>,
    /// Independently reviewed privacy observations, required for managed execution.
    pub privacy: Option<ReviewedFile>,
    /// Actual installed bytes report, required for emulator execution.
    pub installation: Option<ReviewedFile>,
}

/// Raw retained report classes referenced by the measured documents.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectReviewReportKind {
    /// Mutation-clock observations.
    Clock,
    /// Source size, duration and participating isolate capacity observations.
    Runtime,
    /// Bulk queue delivery and positive verification observations.
    BulkQueue,
    /// Metadata queue delivery and positive verification observations.
    MetadataQueue,
    /// Actual bulk consumer configuration readback.
    BulkConfiguration,
    /// Actual metadata consumer configuration readback.
    MetadataConfiguration,
    /// Same-isolate metadata progress during live bulk work.
    MixedLoad,
    /// Positive exact-object and complete anonymous privacy observations.
    Privacy,
    /// Actual provider public/custom-domain policy API readback.
    PrivacyPolicy,
    /// Complete actual direct-S3 checksum rejection response.
    SdkChecksumRejection,
}

/// One explicitly selected raw observation report.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewReport {
    /// Unique closed observation class.
    pub kind: DirectReviewReportKind,
    /// Exact retained report bytes and reviewed hash.
    pub file: ReviewedFile,
}

/// Installed artifact components hashed directly by the reviewer tool.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectReviewInstalledKind {
    /// Exact source NAR bytes retained by the observer.
    SourceNar,
    /// Exact distribution NAR bytes retained by the observer.
    DistributionNar,
    /// Exact installed Worker Wasm bytes.
    Wasm,
    /// Exact installed generated shim bytes.
    Shim,
    /// Actual routing and bindings configuration bytes.
    RuntimeBindings,
    /// Actual emulator runner script bytes.
    Runner,
    /// Actual source-built emulator executable bytes.
    RuntimeExecutable,
}

/// One explicitly selected installed artifact component.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewInstalledFile {
    /// Unique closed installed artifact class.
    pub kind: DirectReviewInstalledKind,
    /// Actual retained bytes and independently reviewed hash.
    pub file: ReviewedFile,
}

/// Explicit reviewer audience, bounds and measurement selection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewSelection {
    /// Closed selection format, currently one.
    pub version: u32,
    /// Exact execution mode observed during measurement.
    pub execution_kind: DirectWorkerExecutionKind,
    /// Independent reviewer publication identity.
    pub reviewer_key_id: String,
    /// Exact reviewed deployment audience.
    pub deployment_id: String,
    /// Exact reviewed public executor origin.
    pub public_origin: String,
    /// Explicit current compiled source identity to qualify.
    pub source_digest: String,
    /// Explicit current actual script identity to qualify.
    pub script_version: String,
    /// Actual deployed consumer Worker name for provider API correlation.
    pub worker_name: String,
    /// Explicit candidate ceilings; measurements cannot invent these bounds.
    pub runtime_bounds: DirectReviewRuntimeBounds,
    /// Explicit earliest accepted UTC time.
    pub issued_at: WireInteger,
    /// Explicit immutable acceptance cutoff; no automatic renewal.
    pub valid_until: WireInteger,
    /// Exact measured document and protected projection inputs.
    pub documents: DirectReviewDocuments,
    /// Exact raw observation inputs referenced by those documents.
    pub reports: Vec<DirectReviewReport>,
    /// Retained complete authenticated reply bytes referenced by raw observation rows.
    pub capture_files: Vec<ReviewedFile>,
    /// Complete privacy HTTP metadata/body captures and independent writer review.
    pub privacy_files: Vec<ReviewedFile>,
    /// Actual installed component bytes, when an installation report is selected.
    pub installed_files: Vec<DirectReviewInstalledFile>,
}

/// Unsigned closed artifact prepared for explicit independent review.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DirectReviewCandidate {
    /// Closed review candidate version, currently one.
    pub version: u32,
    /// Exact raw selection file commitment, including independently chosen hashes.
    pub selection_sha256: String,
    /// Exact independently installed public verifier, with no private material.
    pub trusted_public_key: String,
    /// Complete unsigned measured artifact, granting no runtime authority.
    pub artifact: DirectWorkerQualificationArtifact,
}
