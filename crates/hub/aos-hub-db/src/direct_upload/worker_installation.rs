//! Independently observed installed Worker bundle and emulator executable facts.
//!
//! These are reviewer observations, not runtime self-attestation. The executor
//! checks its compiled source and current script identity; an independent report
//! additionally pins the installed bytes used for emulator measurement/traffic.
//!
//! ```text
//! measurement = {observationSha256, report: {version, executionKind,
//! deploymentId, publicOrigin, sourceDigest, scriptVersion, wasmSha256, ...}}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::*;

/// Retained report commitment and its complete installed-byte observations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerInstallationMeasurement {
    /// Exact SHA-256 of the independently retained raw installation report.
    pub observation_sha256: String,
    /// Actual installed bundle and execution facts parsed from that report.
    pub report: DirectWorkerInstallationReport,
}

/// Closed actual installation report, containing public facts and no local paths.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerInstallationReport {
    /// Closed report version, currently one.
    pub version: u32,
    /// Execution mode actually observed during installation capture.
    pub execution_kind: DirectWorkerExecutionKind,
    /// Actual captured deployment audience.
    pub deployment_id: String,
    /// Actual captured public executor origin.
    pub public_origin: String,
    /// Actual compiled source identity from protected discovery.
    pub source_digest: String,
    /// Actual current script identity from protected discovery.
    pub script_version: String,
    /// Exact immutable source NAR commitment retained by the observer.
    pub source_nar_sha256: String,
    /// Exact immutable Worker distribution NAR commitment.
    pub distribution_nar_sha256: String,
    /// SHA-256 of the installed Wasm bytes.
    pub wasm_sha256: String,
    /// Actual installed Wasm size in bytes.
    pub wasm_byte_size: WireInteger,
    /// SHA-256 of the installed generated Worker shim bytes.
    pub shim_sha256: String,
    /// Actual installed generated shim size in bytes.
    pub shim_byte_size: WireInteger,
    /// SHA-256 of actual installed runtime routing and bindings configuration.
    pub runtime_bindings_sha256: String,
    /// Actual emulator runner script commitment, absent for hosted execution.
    pub runner_sha256: Option<String>,
    /// Actual selected source-built emulator executable commitment.
    pub runtime_executable_sha256: Option<String>,
    /// Actual running process executable commitment observed independently.
    pub observed_process_executable_sha256: Option<String>,
}

impl DirectWorkerInstallationMeasurement {
    /// Checks installed observations against the exact accepted deployment.
    ///
    /// # Errors
    /// Returns an error for missing observed hashes, changed deployment/code or
    /// an emulator process different from the independently selected executable.
    pub fn validate(&self, artifact: &DirectWorkerQualificationArtifact) -> Result<()> {
        let report = &self.report;
        ensure!(
            valid_direct_digest(&self.observation_sha256)
                && report.version == 1
                && report.execution_kind == artifact.execution_kind
                && report.deployment_id == artifact.deployment_id
                && report.public_origin == artifact.public_origin
                && report.source_digest == artifact.source_digest
                && report.script_version == artifact.script_version
                && report.wasm_byte_size.get() > 0
                && report.shim_byte_size.get() > 0
                && [
                    &report.source_nar_sha256,
                    &report.distribution_nar_sha256,
                    &report.wasm_sha256,
                    &report.shim_sha256,
                    &report.runtime_bindings_sha256,
                ]
                .into_iter()
                .all(|value| valid_direct_digest(value)),
            "direct installed artifact observations incomplete or changed"
        );
        let emulator = [
            report.runner_sha256.as_deref(),
            report.runtime_executable_sha256.as_deref(),
            report.observed_process_executable_sha256.as_deref(),
        ];
        ensure!(
            match artifact.execution_kind {
                DirectWorkerExecutionKind::Hosted =>
                    emulator.into_iter().all(|value| value.is_none()),
                DirectWorkerExecutionKind::EmulatedExternal =>
                    emulator
                        .into_iter()
                        .all(|value| value.is_some_and(valid_direct_digest))
                        && report.runtime_executable_sha256
                            == report.observed_process_executable_sha256,
            },
            "direct emulator installation or actual process observations differ"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::worker_qualification::fixtures::direct_worker_qualification_fixture;
    use super::*;

    fn observed_installation(
        artifact: &DirectWorkerQualificationArtifact,
    ) -> DirectWorkerInstallationMeasurement {
        DirectWorkerInstallationMeasurement {
            observation_sha256: "91".repeat(32),
            report: DirectWorkerInstallationReport {
                version: 1,
                execution_kind: artifact.execution_kind,
                deployment_id: artifact.deployment_id.clone(),
                public_origin: artifact.public_origin.clone(),
                source_digest: artifact.source_digest.clone(),
                script_version: artifact.script_version.clone(),
                source_nar_sha256: "92".repeat(32),
                distribution_nar_sha256: "93".repeat(32),
                wasm_sha256: "94".repeat(32),
                wasm_byte_size: WireInteger::new(1024),
                shim_sha256: "95".repeat(32),
                shim_byte_size: WireInteger::new(256),
                runtime_bindings_sha256: "96".repeat(32),
                runner_sha256: None,
                runtime_executable_sha256: None,
                observed_process_executable_sha256: None,
            },
        }
    }

    #[test]
    fn observed_bundle_binds_exact_current_source_script_and_installed_sizes() {
        let (artifact, _) = direct_worker_qualification_fixture();
        let measurement = observed_installation(&artifact);
        measurement.validate(&artifact).unwrap();

        for mutation in 0..3 {
            let mut changed = measurement.clone();
            match mutation {
                0 => changed.report.source_digest = "97".repeat(32),
                1 => changed.report.script_version = "different-script".into(),
                2 => changed.report.wasm_byte_size = WireInteger::new(0),
                _ => unreachable!(),
            }
            assert!(changed.validate(&artifact).is_err());
        }
    }

    #[test]
    fn emulator_requires_independently_observed_matching_running_executable() {
        let (mut artifact, _) = direct_worker_qualification_fixture();
        artifact.execution_kind = DirectWorkerExecutionKind::EmulatedExternal;
        artifact.script_version =
            direct_worker_emulated_script_id(&artifact.source_digest).unwrap();
        let mut measurement = observed_installation(&artifact);
        assert!(measurement.validate(&artifact).is_err());

        measurement.report.runner_sha256 = Some("98".repeat(32));
        measurement.report.runtime_executable_sha256 = Some("99".repeat(32));
        measurement.report.observed_process_executable_sha256 = Some("99".repeat(32));
        measurement.validate(&artifact).unwrap();
        measurement.report.observed_process_executable_sha256 = Some("9a".repeat(32));
        assert!(measurement.validate(&artifact).is_err());
    }
}
