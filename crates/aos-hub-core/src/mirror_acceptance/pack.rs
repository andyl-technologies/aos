//! Separate reviewer purpose for bounded upstream Git pack/index inspection.
//!
//! Approval of none/Zstandard mirror publication does not qualify this parser.
//! The same authorized reviewer role reviews actual pair/selection, whole-worker
//! memory, capacity and release observations under a distinct signed purpose.
//! Controlled reports remain evidence only.
//!
//! ```text
//! pack artifact = SHA256(exact signed mirror artifact) + fixed parser geometry
//!                 + measured pair/selection reports + independent review
//! ```

use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{MirrorAcceptanceArtifact, MirrorAcceptanceExecution};
use crate::{direct_upload::valid_direct_digest, mirror_work::digest};

const DOMAIN: &[u8] = b"aos.hub.accepted-managed-mirror-pack-inspection.v1\0";

/// Bounds the separately installed pack review document.
pub const MIRROR_PACK_ACCEPTANCE_MAX_BYTES: usize = 64 * 1024;

/// Names the bounded parser purpose, distinct from mirror publication approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorPackAcceptancePurpose {
    /// Upstream SHA-256 Git pair and bounded decoded selection inspection.
    ManagedR2PackInspectionV1,
}

/// Pins all parser allocations and independently reserved producer capacity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackGeometry {
    /// Complete encoded pack ceiling; encoded bytes are streamed, not retained.
    pub pack_bytes: u64,
    /// Retained companion index ceiling.
    pub index_bytes: u64,
    /// Peak simultaneously retained decoded graph, including delta results.
    pub decoded_graph_bytes: u64,
    /// Maximum decoded content of one Git object.
    pub object_bytes: u64,
    /// Maximum complete pair entry count.
    pub objects: u64,
    /// Maximum distinct selected OIDs.
    pub selected_objects: u64,
    /// Total decoded content returned across all selections.
    pub selected_bytes: u64,
    /// Native input feed view ceiling.
    pub feed_bytes: u64,
    /// Bulk buffered producer admission; inspection shares this slot.
    pub bulk_producers: u64,
    /// Independent small metadata producer admission.
    pub metadata_producers: u64,
}

impl MirrorPackGeometry {
    /// Returns fixed implementation bounds without claiming measured safety.
    #[must_use]
    pub fn current() -> Self {
        Self {
            pack_bytes: 8 * 1024 * 1024,
            index_bytes: 4 * 1024 * 1024,
            decoded_graph_bytes: 12 * 1024 * 1024,
            object_bytes: 4 * 1024 * 1024,
            objects: 65_536,
            selected_objects: 8,
            selected_bytes: 128 * 1024,
            feed_bytes: 64 * 1024,
            bulk_producers: 1,
            metadata_producers: 2,
        }
    }
}

/// Identifies an actual parser or dispatch boundary observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorPackSafetyCase {
    /// A valid base-object pair and exact selection were read beside storage.
    BaseSelection,
    /// A valid offset-delta chain was fully checked before selection.
    OffsetDeltaSelection,
    /// A valid reference-delta chain was fully checked before selection.
    ReferenceDeltaSelection,
    /// A foreign whole encoded checksum was refused.
    EncodedChecksumRefusal,
    /// A changed index CRC or offset was refused.
    IndexCrcRefusal,
    /// A selected decoded object with a foreign OID was refused.
    SelectedOidRefusal,
    /// Over-limit encoded input was refused before exceeding the bound.
    EncodedLimitRefusal,
    /// Object, entry count or decoded graph overflow was refused.
    DecodedLimitRefusal,
    /// An expired read plan produced no provider dispatch.
    ExpiredReadRefusal,
    /// Both metadata producers completed while bulk inspection was active.
    MetadataDuringInspection,
}

/// Commits one actual raw case report, including its control/result binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackSafetyMeasurement {
    /// Closed case exercised by the report.
    pub case: MirrorPackSafetyCase,
    /// Exact raw observation transcript or manifest.
    pub observation_sha256: String,
    /// Exact canonical signed query body commitment.
    pub query_sha256: String,
    /// Exact bounded semantic result or refusal transcript commitment.
    pub result_sha256: String,
    /// Count of this case actually executed.
    pub samples: u64,
    /// Actual mismatched results or boundary violations found by this case.
    pub violations: u64,
    /// Definitive provider dispatch count for this case, not configured capacity.
    pub provider_dispatches: u64,
}

/// Retains a verified pair's actual byte and decoded-selection observations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackPairMeasurement {
    /// Positive base, offset-delta or reference-delta case from the raw report.
    pub case: MirrorPackSafetyCase,
    /// Full canonical query/result transcript commitment.
    pub observation_sha256: String,
    /// Whole encoded pack SHA-256 returned by the actual streaming inspector.
    pub pack_sha256: String,
    /// Whole encoded index SHA-256 returned by that same inspector.
    pub index_sha256: String,
    /// Pack payload trailer/path checksum, distinct from whole encoded SHA.
    pub pack_trailer_sha256: String,
    /// Actual encoded pack bytes consumed.
    pub pack_bytes: u64,
    /// Actual encoded index bytes consumed.
    pub index_bytes: u64,
    /// Actual peak simultaneously retained decoded graph from the parser.
    pub peak_decoded_graph_bytes: u64,
    /// Largest whole decoded Git object in this pair.
    pub maximum_object_bytes: u64,
    /// Selected OIDs in their exact strict request order.
    pub selected_oids: Vec<String>,
    /// SHA-256 of complete canonical bounded selected projections and content.
    pub selected_result_sha256: String,
    /// Total decoded content returned across all exact selected ranges.
    pub selected_bytes: u64,
}

/// Accepts one measured pack inspector against an exact existing mirror review.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackAcceptanceArtifact {
    /// Closed separate review version.
    pub version: u32,
    /// Exact parser purpose, signed in its separate domain.
    pub purpose: MirrorPackAcceptancePurpose,
    /// Hosted or controlled observations; controlled cannot admit production.
    pub execution: MirrorAcceptanceExecution,
    /// SHA-256 of the complete signed prerequisite mirror artifact.
    pub mirror_artifact_sha256: String,
    /// Actual compiled source identity shared with that artifact.
    pub source_digest: String,
    /// Actual hosted or source-derived controlled script identity.
    pub script_version: String,
    /// Exact fixed parser and producer geometry.
    pub geometry: MirrorPackGeometry,
    /// Manifest of retained actual raw reports and failed attempts.
    pub report_sha256: String,
    /// Bounded positive whole-pair and selection observations.
    pub pairs: Vec<MirrorPackPairMeasurement>,
    /// Closed correctness, expiry and capacity observations.
    pub safety: Vec<MirrorPackSafetyMeasurement>,
    /// Whole-worker memory report, including SDK/JS/Wasm and graph copies.
    pub memory_observation_sha256: String,
    /// Actual whole-worker peak with one inspector and both metadata producers.
    pub peak_worker_bytes: u64,
    /// Number of actual memory observations during the full worst-case workload.
    pub memory_samples: u64,
    /// Actual Wasm heap high-water, including decoded graph and index tables.
    pub peak_wasm_bytes: u64,
    /// Actual simultaneously retained JavaScript and SDK native allocations.
    pub peak_js_sdk_bytes: u64,
    /// Both independent metadata slots actually completed during inspection.
    pub metadata_completed_during_inspection: u64,
    /// Actual maximum simultaneous provider requests observed.
    pub maximum_provider_requests: u64,
    /// Actual bytes fetched through the Native publication process.
    pub native_bulk_bytes: u64,
    /// Actual largest inspector CPU duration from runtime observations.
    pub maximum_cpu_millis: u64,
    /// Actual largest inspector wall duration.
    pub maximum_wall_millis: u64,
    /// Exact installed runtime CPU limit measured in the report.
    pub cpu_limit_millis: u64,
    /// Same complete release pack as the independently accepted mirror build.
    pub release_pack_sha256: String,
    /// First accepted observation time.
    pub issued_at: u64,
    /// Original exclusive expiry, never renewed by configuration or waits.
    pub valid_until: u64,
    /// Reviewer Ed25519 signature under the pack-specific domain.
    pub signature: String,
}

impl MirrorPackAcceptanceArtifact {
    /// Rechecks the original pack review window before each new provider read.
    ///
    /// # Errors
    /// Returns an error for an expired or future review.
    pub fn validate_dispatch_time(&self, latest_now: u64) -> Result<()> {
        ensure!(
            self.issued_at <= latest_now && latest_now < self.valid_until,
            "pack inspection immutable acceptance cutoff reached"
        );
        Ok(())
    }

    /// Checks real-report structure without granting production permission.
    ///
    /// # Errors
    /// Returns an error for mismatched release, missing cases or unsafe geometry.
    pub fn validate_unsigned(
        &self,
        mirror: &MirrorAcceptanceArtifact,
        latest_now: u64,
    ) -> Result<()> {
        mirror.validate_unsigned(latest_now)?;
        self.validate_dispatch_time(latest_now)?;
        ensure!(
            self.version == 1
                && self.execution == mirror.execution
                && self.mirror_artifact_sha256 == digest(mirror)?
                && self.source_digest == mirror.source_digest
                && self.script_version == mirror.script_version
                && self.geometry == MirrorPackGeometry::current()
                && self.release_pack_sha256 == mirror.evidence.release.release_pack_sha256,
            "pack inspection purpose, source, geometry or prerequisite changed"
        );
        for hash in [
            &self.mirror_artifact_sha256,
            &self.report_sha256,
            &self.memory_observation_sha256,
            &self.release_pack_sha256,
        ] {
            ensure!(
                valid_direct_digest(hash),
                "pack inspection report commitment absent"
            );
        }
        ensure!(
            (3..=16).contains(&self.pairs.len()),
            "pack pair observations absent or excessive"
        );
        let mut positive_cases = std::collections::BTreeSet::new();
        for pair in &self.pairs {
            ensure!(
                matches!(
                    pair.case,
                    MirrorPackSafetyCase::BaseSelection
                        | MirrorPackSafetyCase::OffsetDeltaSelection
                        | MirrorPackSafetyCase::ReferenceDeltaSelection
                ),
                "pack positive report uses a refusal case"
            );
            positive_cases.insert(pair.case);
            ensure!(
                [
                    &pair.observation_sha256,
                    &pair.pack_sha256,
                    &pair.index_sha256,
                    &pair.pack_trailer_sha256,
                    &pair.selected_result_sha256
                ]
                .into_iter()
                .all(|hash| valid_direct_digest(hash))
                    && (1..=self.geometry.pack_bytes).contains(&pair.pack_bytes)
                    && (1..=self.geometry.index_bytes).contains(&pair.index_bytes)
                    && (1..=self.geometry.decoded_graph_bytes)
                        .contains(&pair.peak_decoded_graph_bytes)
                    && (1..=self.geometry.object_bytes).contains(&pair.maximum_object_bytes)
                    && pair.maximum_object_bytes <= pair.peak_decoded_graph_bytes
                    && (1..=self.geometry.selected_objects as usize)
                        .contains(&pair.selected_oids.len())
                    && pair
                        .selected_oids
                        .iter()
                        .all(|oid| valid_direct_digest(oid))
                    && pair.selected_oids.windows(2).all(|oids| oids[0] < oids[1])
                    && pair.selected_bytes <= self.geometry.selected_bytes,
                "pack pair or selected projection observations exceed bounds"
            );
        }
        ensure!(
            positive_cases.len() == 3
                && self
                    .pairs
                    .iter()
                    .any(|pair| pair.pack_bytes == self.geometry.pack_bytes)
                && self
                    .pairs
                    .iter()
                    .any(|pair| pair.peak_decoded_graph_bytes == self.geometry.decoded_graph_bytes)
                && self
                    .pairs
                    .iter()
                    .any(|pair| pair.maximum_object_bytes == self.geometry.object_bytes),
            "pack inspection full encoded, graph or object boundary observations absent"
        );
        ensure!(
            self.safety.len() == 10,
            "pack inspection closed safety suite is incomplete"
        );
        let mut cases = std::collections::BTreeSet::new();
        for measured in &self.safety {
            ensure!(
                cases.insert(measured.case)
                    && measured.samples > 0
                    && measured.violations == 0
                    && valid_direct_digest(&measured.observation_sha256)
                    && valid_direct_digest(&measured.query_sha256)
                    && valid_direct_digest(&measured.result_sha256)
                    && (measured.case != MirrorPackSafetyCase::ExpiredReadRefusal
                        || measured.provider_dispatches == 0),
                "pack inspection safety observation missing, duplicated or dispatched after expiry"
            );
        }
        ensure!(
            self.peak_worker_bytes > 0
                && self.peak_worker_bytes < 128 * 1024 * 1024
                && self.memory_samples > 0
                && self.peak_wasm_bytes > 0
                && self.peak_wasm_bytes < self.peak_worker_bytes
                && self.peak_js_sdk_bytes > 0
                && self.peak_js_sdk_bytes < self.peak_worker_bytes
                && self
                    .pairs
                    .iter()
                    .all(|pair| self.peak_wasm_bytes
                        >= pair.peak_decoded_graph_bytes + pair.index_bytes)
                && self.metadata_completed_during_inspection >= 2
                && self.maximum_provider_requests >= 2
                && self.native_bulk_bytes == 0
                && self.maximum_cpu_millis > 0
                && self.cpu_limit_millis == mirror.evidence.workload.installed_cpu_limit_millis
                && self.maximum_cpu_millis <= self.cpu_limit_millis
                && self.maximum_wall_millis > 0
                && self.maximum_wall_millis <= 600_000,
            "pack inspection memory, capacity, Native boundary or runtime observations absent"
        );
        if let Some(crate::direct_upload::DirectProtectedProfile::Managed {
            runtime_qualification,
            ..
        }) = &mirror.protected_profile
        {
            ensure!(
                self.maximum_provider_requests
                    <= runtime_qualification
                        .maximum_parallel_provider_requests
                        .get(),
                "pack inspection exceeded accepted provider concurrency"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MIRROR_PACK_ACCEPTANCE_MAX_BYTES,
            "pack inspection review exceeds bound"
        );
        Ok(())
    }

    /// Encodes the canonical separately purposed reviewer statement.
    ///
    /// # Errors
    /// Returns an error when the closed report exceeds its control bound.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned)?;
        ensure!(
            bytes.len() <= MIRROR_PACK_ACCEPTANCE_MAX_BYTES,
            "pack inspection signature payload exceeds bound"
        );
        Ok([DOMAIN, bytes.as_slice()].concat())
    }

    /// Verifies the installed reviewer role and exact measured prerequisite.
    ///
    /// # Errors
    /// Returns an error for foreign signatures, changed pins or incomplete reports.
    pub fn verify(
        &self,
        mirror: &MirrorAcceptanceArtifact,
        trusted_public_hex: &str,
        latest_now: u64,
    ) -> Result<()> {
        mirror.verify(trusted_public_hex, latest_now)?;
        self.validate_unsigned(mirror, latest_now)?;
        ensure!(
            valid_direct_digest(trusted_public_hex)
                && self.signature.len() == 128
                && self
                    .signature
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "pack reviewer key or signature malformed"
        );
        let public: [u8; 32] = hex::decode(trusted_public_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("pack reviewer key malformed"))?;
        let signature = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(&public)?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("pack inspection acceptance signature invalid"))?;
        Ok(())
    }

    /// Requires hosted pack review for the current independently accepted build.
    ///
    /// # Errors
    /// Returns an error for controlled evidence, stale review or excessive input.
    pub fn require_production(
        &self,
        mirror: &MirrorAcceptanceArtifact,
        trusted_public_hex: &str,
        latest_now: u64,
        maximum_encoded_bytes: u64,
    ) -> Result<()> {
        self.verify(mirror, trusted_public_hex, latest_now)?;
        ensure!(
            self.execution == MirrorAcceptanceExecution::Hosted
                && maximum_encoded_bytes > 0
                && maximum_encoded_bytes <= self.geometry.pack_bytes,
            "pack inspection controlled evidence or input cannot authorize production"
        );
        Ok(())
    }
}

/// Addresses the pack-specific artifact in the existing mirror acceptance store.
///
/// # Errors
/// Returns an error for malformed deployment, source or script identity.
pub fn mirror_pack_acceptance_key(deployment: &str, source: &str, script: &str) -> Result<String> {
    let ordinary = super::mirror_acceptance_key(deployment, source, script)?;
    Ok(format!("mirror-pack-inspection-v1:{}", digest(&ordinary)?))
}

#[cfg(test)]
mod tests;
