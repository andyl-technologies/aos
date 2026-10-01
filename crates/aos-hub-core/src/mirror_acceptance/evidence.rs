//! Closed mirror observation reports, workload examples and release pack pins.
//!
//! ```text
//! evidence = {reportSha256, roundtrips, workload, safety, memory, release}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{MirrorAcceptanceArtifact, MirrorAcceptanceExecution};
use crate::direct_upload::{valid_direct_digest, DirectProtectedProfile};
use crate::mirror_work::{
    MirrorOriginal, MirrorProgress, MirrorVerification, MIRROR_MAX_OBJECT_BYTES,
};

/// Identifies a required observed mirror failure or recovery experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorSafetyCase {
    /// Lost provider create response retains its unknown original.
    UnknownCreate,
    /// Lost part response never resends a mutable same-number part.
    UnknownPart,
    /// Lost close response is not settled by HEAD or time.
    UnknownClose,
    /// Lost final response preserves destination exclusion.
    UnknownPromotion,
    /// Lost private cleanup response retains its unknown deletion.
    UnknownCleanup,
    /// Positive part prefix replays without another mutation.
    PositivePrefixReplay,
    /// Lost Native acknowledgement replays the exact committed original.
    LostNativeAcknowledgement,
    /// Historical acknowledgement remains readable after a later owner.
    ArchivedAcknowledgement,
    /// Actual persistent runtime restart retains originals and unknown effects.
    Restart,
    /// Changed managed profile or binding refuses dispatch.
    ChangedBinding,
    /// Changed upstream or source incarnation refuses publication.
    ChangedSource,
    /// Native revocation or stale SQL originals refuse further promotion.
    NativeRevocation,
    /// Expired original plan causes zero new provider dispatches.
    ExpiredPlan,
    /// Private staging namespace rejects unauthorized reads and writes.
    PrivateNamespace,
    /// Small metadata controls complete while bulk work is active.
    MetadataDuringBulk,
}

/// Retains counts and raw report commitment for one actual safety experiment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorSafetyMeasurement {
    /// Exact experiment; duplicate cases are rejected.
    pub case: MirrorSafetyCase,
    /// Digest of actual requests, retained originals and dispatch observations.
    pub observation_sha256: String,
    /// Positive observed executions of the selected experiment.
    pub samples: u64,
    /// Actual forbidden mutations, settlements or admissions; must be zero.
    pub violations: u64,
}

/// Retains an exact positively published and independently read back example.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorRoundtripMeasurement {
    /// Genuine Native-selected immutable original.
    pub original: MirrorOriginal,
    /// Positive retained stage, verification and final provider records.
    pub progress: MirrorProgress,
    /// Exact Native durable acknowledgement commitment.
    pub commit_digest: String,
    /// Actual independently read final SHA-256.
    pub readback_sha256: String,
    /// Actual independently read final representation size.
    pub readback_bytes: u64,
    /// Commitment to actual HTTP, provider, journal and SQL acknowledgement evidence.
    pub observation_sha256: String,
}

/// Describes the measured full release workload, not a configured promise.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorWorkloadMeasurement {
    /// Commitment to the complete raw workload report, including failed attempts.
    pub observation_sha256: String,
    /// Positively acknowledged large originals at the admitted ceiling.
    pub large_objects: u64,
    /// Positively acknowledged independent small metadata originals.
    pub metadata_objects: u64,
    /// Largest positively verified encoded representation.
    pub maximum_encoded_bytes: u64,
    /// Largest positively verified uncompressed NAR.
    pub maximum_plain_bytes: u64,
    /// Actual peak participating provider requests, including upstream HTTP.
    pub peak_provider_requests: u32,
    /// Actual positive metadata completions while a bulk operation was active.
    pub metadata_completed_during_bulk: u64,
    /// Actual full object bytes sent through Native; must be zero.
    pub native_bulk_bytes: u64,
    /// Largest captured Native control body in bytes.
    pub maximum_native_control_bytes: u64,
    /// Actual worst control latency, including safety and capacity refusals.
    pub maximum_control_millis: u64,
    /// Actual worst whole producer invocation wall time, including verification.
    pub maximum_step_wall_millis: u64,
    /// Actual worst whole producer invocation CPU time.
    pub maximum_step_cpu_millis: u64,
    /// Actual installed CPU ceiling read back for the measured script.
    pub installed_cpu_limit_millis: u64,
}

/// Retains whole Worker memory measurements alongside actual buffer geometry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorMemoryMeasurement {
    /// Raw whole Worker measurement, including Wasm, JavaScript and SDK copies.
    pub observation_sha256: String,
    /// Number of measured producer invocations.
    pub samples: u64,
    /// Actual largest whole Worker resident memory, never just the Rust payload.
    pub peak_worker_bytes: u64,
    /// Actual peak simultaneous bulk part or decoder producers.
    pub peak_bulk_buffered_producers: u32,
    /// Actual peak reserved metadata producers overlapping a bulk verifier.
    pub peak_metadata_buffered_producers_during_bulk: u32,
    /// Actual peak retained Rust part buffers.
    pub peak_rust_part_bytes: u64,
    /// Actual observed JavaScript and SDK retained buffer bytes.
    pub peak_js_sdk_bytes: u64,
    /// Actual aggregate allocated decoding windows, including metadata overlap.
    pub peak_decoder_window_bytes: u64,
}

/// Pins the ordinary script release pack and actual startup observations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorReleaseMeasurement {
    /// Complete source-built release pack and provenance manifest digest.
    pub release_pack_sha256: String,
    /// Exact installed Wasm digest, correlated by the retained release manifest.
    pub wasm_sha256: String,
    /// Exact installed JavaScript digest.
    pub script_sha256: String,
    /// Exact compressed ordinary script digest.
    pub compressed_script_sha256: String,
    /// Actual uploaded script's uncompressed size.
    pub script_bytes: u64,
    /// Actual uploaded script's compressed size.
    pub compressed_script_bytes: u64,
    /// Commitment to actual upload and runtime startup observations.
    pub observation_sha256: String,
    /// Number of measured cold starts of the exact installed artifact.
    pub cold_start_samples: u64,
    /// Largest observed startup time.
    pub maximum_startup_millis: u64,
}

/// Collects the public measured evidence independently accepted for a mirror.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorAcceptanceEvidence {
    /// Manifest of all raw reports, installation identities and failed attempts.
    pub report_sha256: String,
    /// Bounded full-original examples for metadata and none/zstd NARs.
    pub roundtrips: Vec<MirrorRoundtripMeasurement>,
    /// Aggregate full release workload observations.
    pub workload: MirrorWorkloadMeasurement,
    /// Actual safety, uncertainty, acknowledgement and capacity observations.
    pub safety: Vec<MirrorSafetyMeasurement>,
    /// Actual whole Worker memory observations under admitted geometry.
    pub memory: MirrorMemoryMeasurement,
    /// Actual measured script release pack and startup.
    pub release: MirrorReleaseMeasurement,
}

impl MirrorAcceptanceEvidence {
    pub(super) fn validate(&self, artifact: &MirrorAcceptanceArtifact) -> Result<()> {
        let hashes = [
            &self.report_sha256,
            &self.workload.observation_sha256,
            &self.memory.observation_sha256,
            &self.release.release_pack_sha256,
            &self.release.wasm_sha256,
            &self.release.script_sha256,
            &self.release.compressed_script_sha256,
            &self.release.observation_sha256,
        ];
        ensure!(
            hashes.into_iter().all(|hash| valid_direct_digest(hash)),
            "mirror raw report or release commitment absent"
        );
        ensure!(
            (3..=16).contains(&self.roundtrips.len()),
            "mirror roundtrip examples absent or excessive"
        );
        let profile_digest = match artifact.execution {
            MirrorAcceptanceExecution::Hosted => artifact
                .protected_profile
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("mirror accepted profile absent"))?
                .digest()?,
            MirrorAcceptanceExecution::Controlled => {
                let profile = artifact
                    .candidate_profile
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("mirror candidate profile absent"))?;
                super::mirror_candidate_profile_digest(
                    &profile.profile,
                    &profile.private_stage_policy,
                )?
            }
        };
        let mut none = false;
        let mut zstd = false;
        let mut metadata = false;
        let mut jobs = std::collections::BTreeSet::new();
        for sample in &self.roundtrips {
            sample.original.validate()?;
            sample.progress.validate(&sample.original)?;
            let final_object = sample
                .progress
                .destination
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("mirror roundtrip final proof absent"))?;
            ensure!(
                jobs.insert(&sample.original.job_id)
                    && sample.original.protected_profile_digest == profile_digest
                    && sample.original.verification.size() <= artifact.maximum_object_bytes
                    && sample.progress.commit_digest(&sample.original)? == sample.commit_digest
                    && sample.readback_sha256 == final_object.sha256
                    && sample.readback_bytes == final_object.object.size
                    && valid_direct_digest(&sample.observation_sha256),
                "mirror roundtrip original, acknowledgement or readback differs"
            );
            if artifact.execution == MirrorAcceptanceExecution::Controlled {
                ensure!(
                    sample
                        .original
                        .placement_prefix
                        .starts_with(".aos-mirror-qualification/")
                        && sample.original.placement_prefix.ends_with("/final"),
                    "controlled mirror escaped fixture namespace"
                );
            }
            match &sample.original.verification {
                MirrorVerification::Sha256 { size, .. } => metadata |= *size <= 128 * 1024,
                MirrorVerification::Nar {
                    compression,
                    nar_size,
                    ..
                } => {
                    ensure!(
                        *nar_size <= artifact.maximum_object_bytes,
                        "mirror plain measurement exceeds admitted ceiling"
                    );
                    none |= compression == "none";
                    zstd |= compression == "zstd";
                }
            }
        }
        ensure!(
            none && zstd && metadata,
            "mirror none, zstd or metadata roundtrip absent"
        );

        let workload = &self.workload;
        ensure!(
            workload.maximum_encoded_bytes == artifact.maximum_object_bytes
                && workload.maximum_plain_bytes == artifact.maximum_object_bytes
                && workload.peak_provider_requests >= 2
                && workload.metadata_completed_during_bulk > 0
                && workload.native_bulk_bytes == 0
                && (1..=256 * 1024).contains(&workload.maximum_native_control_bytes)
                && workload.maximum_control_millis > 0
                && (1..=600_000).contains(&workload.maximum_step_wall_millis)
                && workload.maximum_step_cpu_millis > 0
                && workload.maximum_step_cpu_millis <= workload.installed_cpu_limit_millis,
            "mirror workload does not cover admitted size, capacity or Native byte boundary"
        );
        if let Some(DirectProtectedProfile::Managed {
            runtime_qualification,
            ..
        }) = &artifact.protected_profile
        {
            ensure!(
                u64::from(workload.peak_provider_requests)
                    == runtime_qualification
                        .maximum_parallel_provider_requests
                        .get(),
                "mirror provider capacity was not measured at accepted ceiling"
            );
        }

        let mut cases = std::collections::BTreeSet::new();
        for measurement in &self.safety {
            ensure!(
                cases.insert(measurement.case)
                    && measurement.samples > 0
                    && measurement.violations == 0
                    && valid_direct_digest(&measurement.observation_sha256),
                "mirror safety measurement duplicates, fails or lacks evidence"
            );
        }
        ensure!(
            self.safety.len() <= 15,
            "mirror safety reports exceed bound"
        );
        if artifact.execution == MirrorAcceptanceExecution::Hosted {
            ensure!(
                artifact.maximum_object_bytes == MIRROR_MAX_OBJECT_BYTES
                    && workload.large_objects >= 3
                    && workload.metadata_objects >= 1000
                    && self.safety.len() == 15,
                "hosted mirror full release workload or safety pack incomplete"
            );
        }

        let memory = &self.memory;
        ensure!(
            memory.samples > 0
                && (1..128 * 1024 * 1024).contains(&memory.peak_worker_bytes)
                && memory.peak_bulk_buffered_producers == artifact.geometry.bulk_buffered_producers
                && memory.peak_metadata_buffered_producers_during_bulk
                    == artifact.geometry.metadata_buffered_producers
                && memory.peak_rust_part_bytes > 0
                && memory.peak_rust_part_bytes < memory.peak_worker_bytes
                && memory.peak_rust_part_bytes
                    <= artifact.geometry.part_bytes
                        + u64::from(artifact.geometry.metadata_buffered_producers)
                            * artifact.geometry.metadata_buffer_bytes
                && memory.peak_js_sdk_bytes > 0
                && memory.peak_js_sdk_bytes < memory.peak_worker_bytes
                && memory.peak_decoder_window_bytes > 0
                && memory.peak_decoder_window_bytes < memory.peak_worker_bytes
                && memory.peak_decoder_window_bytes
                    <= artifact.geometry.decoder_window_bytes
                        + u64::from(artifact.geometry.metadata_buffered_producers)
                            * artifact.geometry.metadata_buffer_bytes,
            "mirror whole Worker memory or enforced geometry unmeasured"
        );
        let release = &self.release;
        ensure!(
            (1..=64 * 1024 * 1024).contains(&release.script_bytes)
                && (1..=release.script_bytes).contains(&release.compressed_script_bytes)
                && release.cold_start_samples > 0
                && (1..=1000).contains(&release.maximum_startup_millis),
            "mirror ordinary release size or startup gate failed"
        );
        Ok(())
    }
}
