//! Closed numeric observations emitted from retained actual qualification replies.
//!
//! All quantities use decimal strings. These reports contain no readiness flags
//! and confer no acceptance. The reviewer chooses their exact file commitments.
//!
//! ```text
//! report = {version, executionKind, deploymentId, publicOrigin, sourceDigest,
//!           scriptVersion, observations: {samples: [...]}}
//! ```

use aos_hub_core::direct_upload::{DirectWorkerExecutionKind, WireInteger};
use serde::{Deserialize, Serialize};

/// Exact observed audience and raw measurement rows.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewRawReport<T> {
    /// Closed raw report format, currently one.
    pub version: u32,
    /// Actual observed hosted or external emulator execution.
    pub execution_kind: DirectWorkerExecutionKind,
    /// Actual authenticated deployment audience.
    pub deployment_id: String,
    /// Actual authenticated executor origin.
    pub public_origin: String,
    /// Actual compiled source reported by the unchanged Worker.
    pub source_digest: String,
    /// Actual current script reported by the unchanged Worker.
    pub script_version: String,
    /// Actual numeric observations, retaining missing evidence as a refusal.
    pub observations: T,
}

/// Reference-clock send/receive bracket and actual Worker clock observation.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewClockSample {
    /// Actual operator request send time in UTC milliseconds.
    pub sent_at_millis: WireInteger,
    /// Actual operator reply receive time in UTC milliseconds.
    pub received_at_millis: WireInteger,
    /// Actual Worker observed time in UTC milliseconds.
    pub observed_at_millis: WireInteger,
    /// Exact retained authenticated reply bytes.
    pub reply_sha256: String,
}

/// Actual post-cutoff mutation attempt with unchanged same-isolate dispatch count.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewExpiredMutation {
    /// Actual immutable attempted operation cutoff in UTC seconds.
    pub cutoff: WireInteger,
    /// Actual authenticated reply UTC time, distinct from conservative latest-now.
    pub observed_at_millis: WireInteger,
    /// Actual isolate containing both provider counter observations.
    pub isolate_id: String,
    /// Actual provider dispatch counter immediately before the attempt.
    pub provider_dispatches_before: WireInteger,
    /// Actual provider dispatch counter immediately after the attempt.
    pub provider_dispatches_after: WireInteger,
    /// Exact retained authenticated refusal reply bytes.
    pub reply_sha256: String,
}

/// Actual clock bracket and expired mutation observations.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewClockObservations {
    /// Actual reference-clock brackets.
    pub samples: Vec<DirectReviewClockSample>,
    /// Actual attempts after their original cutoffs.
    pub expired_mutations: Vec<DirectReviewExpiredMutation>,
}

/// Positive runtime verification and settlement observation.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewRuntimeSample {
    /// Exact immutable original object identity.
    pub object_id: String,
    /// Actual participating isolate identity.
    pub isolate_id: String,
    /// Positively streamed and verified source size.
    pub byte_size: WireInteger,
    /// Positively streamed whole-source SHA-256.
    pub sha256: String,
    /// SHA-256 of retained canonical proof JSON with sorted object keys.
    pub proof_sha256: String,
    /// Actual end-to-end verification interval in milliseconds.
    pub verification_millis: WireInteger,
    /// Actual protected control settlement interval in milliseconds.
    pub settlement_millis: WireInteger,
    /// Actual simultaneous aggregate object count observed in this isolate.
    pub peak_parallel_objects: WireInteger,
    /// Actual simultaneous aggregate provider count observed in this isolate.
    pub peak_parallel_provider_requests: WireInteger,
    /// Actual isolate counter difference during fresh verification, not object attribution.
    pub fresh_provider_dispatches: WireInteger,
    /// Exact retained authenticated Inspect reply containing the proof.
    pub reply_sha256: String,
}

/// Actual runtime sample set.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewRuntimeObservations {
    /// Positive actual verification and settlement samples.
    pub samples: Vec<DirectReviewRuntimeSample>,
}

/// Positive queue proof and live local aggregate/class observations.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewQueueSample {
    /// Exact immutable original object identity.
    pub object_id: String,
    /// Actual participating isolate identity.
    pub isolate_id: String,
    /// Actual provider queue message identity.
    pub message_id: String,
    /// Actual verification start UTC milliseconds.
    pub started_at_millis: WireInteger,
    /// Actual positive verification completion UTC milliseconds.
    pub finished_at_millis: WireInteger,
    /// Positively streamed source size.
    pub byte_size: WireInteger,
    /// Positively streamed whole-source SHA-256.
    pub sha256: String,
    /// SHA-256 of retained canonical proof JSON with sorted object keys.
    pub proof_sha256: String,
    /// Actual simultaneous aggregate object count at admission.
    pub aggregate_active: WireInteger,
    /// Actual simultaneous bulk object count at admission.
    pub bulk_active: WireInteger,
    /// Actual simultaneous metadata object count at admission.
    pub metadata_active: WireInteger,
    /// Actual isolate counter difference during fresh verification, not object attribution.
    pub fresh_provider_dispatches: WireInteger,
    /// Exact retained authenticated Inspect reply containing the receipt.
    pub reply_sha256: String,
}

/// Actual observations for one independent queue class.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewQueueObservations {
    /// Actual observed queue name.
    pub queue_name: String,
    /// Actual closed class, content or metadata.
    pub dependency_phase: String,
    /// Actual positive queue receipts, excluding terminal replay.
    pub samples: Vec<DirectReviewQueueSample>,
}

/// Actual metadata completion overlapping held bulk work in the same isolate.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewMixedSample {
    /// Actual shared isolate identity for both intervals.
    pub isolate_id: String,
    /// Actual bulk verification start UTC milliseconds.
    pub bulk_started_at_millis: WireInteger,
    /// Actual bulk verification end UTC milliseconds.
    pub bulk_finished_at_millis: WireInteger,
    /// Actual metadata verification start UTC milliseconds.
    pub metadata_started_at_millis: WireInteger,
    /// Actual positive metadata completion UTC milliseconds.
    pub metadata_finished_at_millis: WireInteger,
    /// Actual bulk object count while metadata was admitted.
    pub bulk_active: WireInteger,
    /// Actual metadata-under-bulk permit counter before the attempt.
    pub metadata_admissions_before: WireInteger,
    /// Actual metadata-under-bulk permit counter after the attempt.
    pub metadata_admissions_after: WireInteger,
    /// Exact retained authenticated positive metadata reply bytes.
    pub metadata_reply_sha256: String,
}

/// Actual same-isolate mixed-load observations.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReviewMixedObservations {
    /// Actual overlapping positive metadata receipts and held bulk intervals.
    pub samples: Vec<DirectReviewMixedSample>,
}
