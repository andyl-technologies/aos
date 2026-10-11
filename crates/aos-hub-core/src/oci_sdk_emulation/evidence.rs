//! Closed public commitments to independent installation and SDK observations.
//!
//! Raw process IDs, custody paths, request bodies and namespace observer reports
//! remain in the independent private evidence. This signed projection retains
//! their SHA-256 commitments and the exact public facts needed by each runtime.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{
    direct_upload::{valid_direct_digest, DirectClockMeasurement},
    storage_work::StorageObjectIdentity,
};

use super::OciSdkEmulationProfile;

/// Commits to one actual SDK conditional full read of a positive incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkObjectObservation {
    /// Actual SDK key, strong ETag, byte size and genuine local R2 version.
    pub object: StorageObjectIdentity,
    /// SHA-256 computed over the exact bytes returned by that conditional read.
    pub sha256: String,
}

impl OciSdkObjectObservation {
    /// Checks the exact positive SDK identity and full-byte commitment.
    ///
    /// # Errors
    /// Rejects malformed keys, missing real versions, weak ETags or byte bounds.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.object.key.is_empty()
                && self.object.key.len() <= 2048
                && !self.object.key.starts_with('/')
                && self.object.key.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && !part.chars().any(char::is_control)
                })
                && self.object.size > 0
                && self.object.size <= aos_oci_types::limits::MAX_JSON_BYTES as u64
                && self
                    .object
                    .provider_version
                    .as_deref()
                    .is_some_and(crate::storage_work::valid_provider_version)
                && crate::surface_write::strong_if_match_etag(&self.object.etag)?
                    == self.object.etag
                && valid_direct_digest(&self.sha256),
            "OCI SDK object observation is invalid"
        );
        Ok(())
    }
}

/// Retains public facts joined from independently observed installed processes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkInstallation {
    /// Commitment to the independent socket/process/namespace readback report.
    pub namespace_observation_sha256: String,
    /// Commitment to the independently observed Native executable and configuration.
    pub native_observation_sha256: String,
    /// Time at which the real installed processes and mapping were observed.
    pub observed_at: u64,
    /// Exact Native executable SHA-256 independently read from the live process.
    pub native_executable_sha256: String,
    /// Commitment to the exact private Native installed configuration.
    pub native_configuration_sha256: String,
    /// Exact source NAR identity retained with both compiled installations.
    pub source_nar_sha256: String,
    /// Exact Worker distribution NAR identity retained by the observer.
    pub distribution_nar_sha256: String,
    /// Actual Worker Wasm file SHA-256.
    pub wasm_sha256: String,
    /// Actual Worker Wasm length, bounded before observer allocation.
    pub wasm_byte_size: u64,
    /// Exact installed shim file SHA-256.
    pub shim_sha256: String,
    /// Exact installed runner file SHA-256.
    pub runner_sha256: String,
    /// Exact runtime configuration SHA-256 joined by the independent observer.
    pub configuration_sha256: String,
    /// Exact version-pinned Miniflare module SHA-256.
    pub miniflare_module_sha256: String,
    /// Exact installed Miniflare R2 entry worker SHA-256.
    pub miniflare_entry_worker_sha256: String,
    /// Exact installed Miniflare bucket worker SHA-256.
    pub miniflare_bucket_worker_sha256: String,
    /// Exact workerd executable read from the actual child process.
    pub workerd_executable_sha256: String,
    /// Protected Worker identity response source digest joined to installed bytes.
    pub worker_source_digest: String,
    /// Protected Worker identity response script version.
    pub worker_script_version: String,
    /// Actual selected worker name from the installed runtime mapping.
    pub worker_name: String,
    /// Actual selected SDK attachment from that same mapping.
    pub binding_name: String,
    /// Actual normalized namespace ID from that same mapping.
    pub namespace_id: String,
    /// Actual internal namespace object's ID from that same mapping.
    pub namespace_object_id: String,
    /// Actual version-pinned namespace key from that same mapping.
    pub namespace_unique_key: String,
}

/// Identifies the exact provider operations observed by the SDK fixture.
///
/// The scope makes no claim about business dispatch refusal after expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciSdkObservationScope {
    /// One create-only anchor PUT and one conditional full GET inside its original window.
    AnchorCreateAndConditionalRead,
}

/// Carries independent measured facts for the separate OCI SDK purpose.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkEmulationEvidence {
    /// Closed observed-operation scope, distinct from business expiry qualification.
    pub sdk_observation_scope: OciSdkObservationScope,
    /// Actual installation and namespace mapping observation.
    pub installation: OciSdkInstallation,
    /// Actual observed absolute UTC behavior, distinct from installed policy.
    pub clock: DirectClockMeasurement,
    /// Commitment to actual SDK anchor creation and conditional full-read receipts.
    pub sdk_observation_sha256: String,
    /// Anchor returned by the actual selected SDK attachment and full read.
    pub anchor: OciSdkObjectObservation,
    /// Number of the observed anchor effects dispatched after its original cutoff.
    ///
    /// Zero here does not qualify post-cutoff business refusal behavior.
    pub expired_effects: u64,
}

impl OciSdkEmulationEvidence {
    pub(super) fn validate(&self, profile: &OciSdkEmulationProfile, issued_at: u64) -> Result<()> {
        let installed = &self.installation;
        ensure!(
            installed.observed_at > 0
                && installed.observed_at <= issued_at
                && issued_at - installed.observed_at <= 3600
                && installed.worker_source_digest == profile.worker_source_digest
                && installed.worker_script_version == profile.worker_script_version
                && installed.worker_name == profile.worker_name
                && installed.binding_name == profile.binding_name
                && installed.namespace_id == profile.namespace_id
                && installed.namespace_object_id == profile.namespace_object_id
                && installed.namespace_unique_key == profile.namespace_unique_key
                && (1..=64 * 1024 * 1024).contains(&installed.wasm_byte_size),
            "OCI SDK installed observation or selected mapping differs"
        );
        ensure!(
            [
                &installed.namespace_observation_sha256,
                &installed.native_observation_sha256,
                &installed.native_executable_sha256,
                &installed.native_configuration_sha256,
                &installed.source_nar_sha256,
                &installed.distribution_nar_sha256,
                &installed.wasm_sha256,
                &installed.shim_sha256,
                &installed.runner_sha256,
                &installed.configuration_sha256,
                &installed.miniflare_module_sha256,
                &installed.miniflare_entry_worker_sha256,
                &installed.miniflare_bucket_worker_sha256,
                &installed.workerd_executable_sha256,
                &self.clock.observation_sha256,
                &self.sdk_observation_sha256,
            ]
            .iter()
            .all(|value| valid_direct_digest(value)),
            "OCI SDK independent observation commitment is invalid"
        );
        ensure!(
            self.clock.samples.get() >= 2
                && self.clock.uncertainty_seconds == profile.clock_policy.uncertainty_seconds
                && self.clock.maximum_observed_skew_millis.get()
                    < self.clock.uncertainty_seconds.get() * 1000
                && self.clock.expired_mutation_dispatches.get() == 0
                && self.expired_effects == 0,
            "OCI SDK observed clock or effect boundary differs"
        );
        self.anchor.validate()?;
        ensure!(
            self.anchor == profile.anchor,
            "OCI SDK exact anchor observation differs"
        );
        Ok(())
    }
}
