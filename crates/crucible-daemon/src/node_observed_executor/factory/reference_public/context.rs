//! Measures the fixed issuer context before any original native effects.
//!
//! Context selects reusable source, fixture and environment facts explicitly.
//! Original session, incarnation, process and activation identities remain in
//! the live witness and are never removed from their original records.

use std::{fs::File, io::Read, os::unix::fs::OpenOptionsExt};

use crucible_node_contract::{ContentRef, HashRef, U64, canonical};
use crucible_node_provider::ProviderError;

use super::{
    candidate::PrivateCandidate,
    unit::{SemanticQualificationUnit, UnitSourceObjects},
};
use crate::node_qualification::{ReferenceOracleContract, normative_specification};

const MAXIMUM_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// Selects the immutable source fixture included in the measured semantic unit.
#[derive(Clone, Copy)]
pub(super) enum ActorFixture {
    /// Selects the unchanged original success and hostile-body controls.
    CompletedOriginals,
    /// Selects known-window completion followed by provider-only transport loss.
    #[cfg(test)]
    KnownWindowProviderLoss,
    /// Selects one first original Begin write with its completion unread.
    #[cfg(test)]
    OriginalResponseLoss,
    /// Selects actual native consumed-prefix evidence before response loss.
    #[cfg(test)]
    NativeProgressLoss,
}

impl ActorFixture {
    /// Produces the exact reusable recipe before any native child is launched.
    pub(super) fn definition(self) -> serde_json::Value {
        match self {
            Self::CompletedOriginals => serde_json::Value::Null,
            #[cfg(test)]
            Self::KnownWindowProviderLoss => super::source_window_provider_loss::fixture(),
            #[cfg(test)]
            Self::OriginalResponseLoss => super::source_original_response_loss::fixture(),
            #[cfg(test)]
            Self::NativeProgressLoss => super::source_native_progress_loss::fixture(),
        }
    }
}

/// Measures the actual source-owned context and complete immutable fixture.
pub(super) fn measure(
    candidate: &PrivateCandidate,
    oracles: &[ReferenceOracleContract],
) -> Result<SemanticQualificationUnit, ProviderError> {
    measure_with_fixture(candidate, oracles, &serde_json::Value::Null)
}

/// Measures a separately declared source-owned adverse fixture before effects.
///
/// # Errors
/// Refuses changed source, original unit or incomplete source object closure.
pub(super) fn measure_with_fixture(
    candidate: &PrivateCandidate,
    oracles: &[ReferenceOracleContract],
    adverse_fixture: &serde_json::Value,
) -> Result<SemanticQualificationUnit, ProviderError> {
    if oracles.len() != 2 {
        return Err(ProviderError::Frame(
            "original oracle population incomplete",
        ));
    }
    let environment = canonical::canonical_json(&serde_json::json!({
        "schema":"crucible.reference.qualification-environment.v1",
        "architecture":std::env::consts::ARCH,
        "operating_system":std::env::consts::OS,
        "kernel_release":kernel_value("osrelease")?,
        "kernel_version":kernel_value("version")?,
        "kernel_type":kernel_value("ostype")?,
        "effective_uid":rustix::process::geteuid().as_raw().to_string(),
        "locale":"C", "private_directory_mode":"0700",
        "native_process_groups":"one-provider-and-one-companion-per-private-group-v1"
    }))?;
    let sources = [
        ["harness", include_str!("harness.rs")],
        ["harness_windows", include_str!("harness_windows.rs")],
        ["context", include_str!("context.rs")],
        ["candidate", include_str!("candidate.rs")],
        ["installation", include_str!("installation.rs")],
        ["launch", include_str!("launch.rs")],
        ["native", include_str!("native.rs")],
        ["custody", include_str!("custody.rs")],
        ["package", include_str!("package.rs")],
        ["graphs", include_str!("graphs.rs")],
        [
            "source_native_progress_loss",
            include_str!("source_native_progress_loss.rs"),
        ],
        [
            "source_native_progress_loss_tests",
            include_str!("source_native_progress_loss_tests.rs"),
        ],
        ["world", include_str!("world.rs")],
        ["unit", include_str!("unit.rs")],
        ["witness", include_str!("witness.rs")],
        ["lifecycle", include_str!("lifecycle_witness.rs")],
        [
            "supported_lifecycle",
            include_str!("supported_lifecycle.rs"),
        ],
        [
            "supported_execution",
            include_str!("supported_execution.rs"),
        ],
        ["runtime_retries", include_str!("runtime_retries.rs")],
        [
            "metadata_inspection",
            include_str!("metadata_inspection.rs"),
        ],
        [
            "source_metadata_reviews",
            include_str!("source_metadata_reviews.rs"),
        ],
        [
            "source_metadata_review_tests",
            include_str!("source_metadata_review_tests.rs"),
        ],
        ["issuer", include_str!("issuer.rs")],
        [
            "package_metadata_controls",
            include_str!("package_metadata_controls.rs"),
        ],
        ["source_probe", include_str!("source_probe.rs")],
        ["source_resend_plan", include_str!("source_resend_plan.rs")],
        [
            "source_resend_execution",
            include_str!("source_resend_execution.rs"),
        ],
        [
            "source_lifecycle_resend_plan",
            include_str!("source_lifecycle_resend_plan.rs"),
        ],
        [
            "source_lifecycle_resend_policy",
            include_str!("source_lifecycle_resend_policy.rs"),
        ],
        [
            "source_lifecycle_requests",
            include_str!("source_lifecycle_requests.rs"),
        ],
        [
            "source_lifecycle_world",
            include_str!("source_lifecycle_world.rs"),
        ],
        [
            "source_lifecycle_evidence",
            include_str!("source_lifecycle_evidence.rs"),
        ],
        [
            "source_lifecycle_evidence_tests",
            include_str!("source_lifecycle_evidence_tests.rs"),
        ],
        ["harness_failure", include_str!("harness_failure.rs")],
        [
            "source_window_provider_loss",
            include_str!("source_window_provider_loss.rs"),
        ],
        [
            "source_original_response_loss",
            include_str!("source_original_response_loss.rs"),
        ],
        [
            "sdk_original_response_loss",
            include_str!(
                "../../../../../crucible-node-provider/src/client/reference/original_response_loss.rs"
            ),
        ],
        [
            "sdk_original_session",
            include_str!("../../../../../crucible-node-provider/src/client/session.rs"),
        ],
        [
            "source_original_conflict_plan",
            include_str!("source_original_conflict_plan.rs"),
        ],
        [
            "source_original_conflict_policy",
            include_str!("source_original_conflict_policy.rs"),
        ],
        [
            "source_original_conflict_wire",
            include_str!("source_original_conflict_wire.rs"),
        ],
        [
            "sdk_original_conflict",
            include_str!(
                "../../../../../crucible-node-provider/src/client/session/original_conflict.rs"
            ),
        ],
        [
            "sdk_reference_original_conflict",
            include_str!(
                "../../../../../crucible-node-provider/src/client/reference/original_conflict.rs"
            ),
        ],
        [
            "sdk_conflict_transmissions",
            include_str!(
                "../../../../../crucible-node-provider/src/client/reference/conflict_transmissions.rs"
            ),
        ],
        [
            "cnp_original_conflict",
            include_str!("../../../../../crucible/src/node_adapters/cnp/original_conflict.rs"),
        ],
        [
            "sdk_session_lifecycle_resend",
            include_str!(
                "../../../../../crucible-node-provider/src/client/session/lifecycle_resend.rs"
            ),
        ],
        [
            "sdk_reference_lifecycle_resend",
            include_str!(
                "../../../../../crucible-node-provider/src/client/reference/lifecycle_resend.rs"
            ),
        ],
        [
            "cnp_lifecycle_resend",
            include_str!("../../../../../crucible/src/node_adapters/cnp/lifecycle_resend.rs"),
        ],
        [
            "preparation_resend",
            include_str!("../../../../../crucible/src/node_adapters/cnp/preparation_resend.rs"),
        ],
        [
            "sdk_session_resend",
            include_str!("../../../../../crucible-node-provider/src/client/session/resend.rs"),
        ],
        [
            "sdk_reference_resend",
            include_str!("../../../../../crucible-node-provider/src/client/reference/resend.rs"),
        ],
        [
            "sdk_transmissions",
            include_str!(
                "../../../../../crucible-node-provider/src/client/reference/transmissions.rs"
            ),
        ],
        [
            "sdk_evidence_privacy",
            include_str!("../../../../../crucible-node-provider/src/client/reference/evidence.rs"),
        ],
        [
            "source_probe_execution",
            include_str!("source_probe_execution.rs"),
        ],
        ["provider_only", include_str!("native/provider_only.rs")],
        [
            "prepared_adverse",
            include_str!("../../../../../crucible/src/node_adapters/cnp/preparation_adverse.rs"),
        ],
        ["prepared_gate", include_str!("prepared_gate_evidence.rs")],
        [
            "prepared_execution",
            include_str!("source_pre_activation_execution.rs"),
        ],
        [
            "prepared_plan",
            include_str!("source_pre_activation_probe.rs"),
        ],
        [
            "preparation_probe",
            include_str!("../../../../../crucible/src/node_adapters/cnp/preparation_probe.rs"),
        ],
    ];
    let harness = canonical::canonical_json(&serde_json::json!({
        "schema":"crucible.reference.qualification-harness.v1",
        "executable":measure_executable()?,
        "source":sources.as_slice()
    }))?;
    let source_probes = candidate
        .installations
        .iter()
        .map(super::source_probe::SourceProbePlan::build)
        .collect::<Result<Vec<_>, _>>()?;
    let prepared_plans = candidate
        .installations
        .iter()
        .map(super::source_pre_activation_probe::SourcePreActivationProbePlan::build)
        .collect::<Result<Vec<_>, _>>()?;
    let resend_plans = candidate
        .installations
        .iter()
        .map(super::source_resend_plan::SourceResendPlan::build)
        .collect::<Result<Vec<_>, _>>()?;
    let lifecycle_plans = candidate
        .installations
        .iter()
        .map(|installed| {
            let cases = (0..3)
                .map(|quantum| super::harness::window_case(installed, quantum))
                .collect::<Result<Vec<_>, _>>()?;
            super::source_lifecycle_resend_plan::SourceLifecycleResendPlan::build(
                installed,
                &candidate.activation,
                &cases,
            )
        })
        .collect::<Result<Vec<_>, ProviderError>>()?;
    let conflict_plans = candidate
        .installations
        .iter()
        .zip(&lifecycle_plans)
        .map(|(installed, lifecycle)| {
            super::source_original_conflict_plan::SourceOriginalConflictPlan::build(
                installed, lifecycle,
            )
        })
        .collect::<Result<Vec<_>, ProviderError>>()?;
    let fixtures = canonical::canonical_json(&serde_json::json!({
        "explicit_adverse_fixture":adverse_fixture,
        "original_conflict_plans":conflict_plans.iter().map(|plan|serde_json::json!({"reference":plan.reference,"bytes":plan.bytes,"objects":plan.objects.iter().map(|(reference,bytes)|serde_json::json!({"reference":reference,"bytes":bytes})).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "lifecycle_resend_plans":lifecycle_plans.iter().map(|plan|serde_json::json!({"reference":plan.fixture,"bytes":plan.bytes,"objects":plan.objects.iter().map(|(reference,bytes)|serde_json::json!({"reference":reference,"bytes":bytes})).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "transmission_archive":{"maximum_transmissions":13,"maximum_bytes":16777216,"before_original_control":true},
        "source_resend_plans":resend_plans.iter().map(|plan|serde_json::json!({"reference":plan.reference,"bytes":plan.bytes,"objects":plan.objects.iter().map(|(reference,bytes)|serde_json::json!({"reference":reference,"bytes":bytes})).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "source_probe_plans":source_probes.iter().map(|plan|serde_json::json!({"reference":plan.reference,"bytes":plan.bytes,"objects":plan.objects.iter().map(|(reference,bytes)|serde_json::json!({"reference":reference,"bytes":bytes})).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "prepared_probe_plans":prepared_plans.iter().map(|plan|serde_json::json!({"reference":plan.reference,"bytes":plan.bytes,"objects":plan.fixture_objects().iter().map(|(reference,bytes)|serde_json::json!({"reference":reference,"bytes":bytes})).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "schema":"crucible.reference.qualification-fixtures.v1",
        "supported_preparation":super::supported_lifecycle::fixture(),
        "supported_cycle":super::supported_execution::fixture(),
        "runtime_cached_recovery":super::runtime_retries::fixture(),
        "metadata_inspection":super::metadata_inspection::fixture(),
        "source_metadata_reviews":super::source_metadata_reviews::fixture(),
        "artifact_integrity_plan":candidate.installations[0].package.artifact_measurement_plan().map_err(failure)?.fixture(),
        "window_order":[["producer",0],["consumer",0],["consumer",1],["producer",1],["consumer",2],["producer",2]],
        "node_windows":oracles.iter().map(|oracle|serde_json::json!({
            "owner":oracle.owner,"quantum_ps":oracle.quantum_ps,
            "host_budget_ns":oracle.host_budget_ns,"first_quantum":oracle.first_quantum,
            "first_time_ps":oracle.first_time_ps,"initial_checksum":oracle.initial_checksum,
            "maximum_windows":oracle.maximum_windows,"maximum_input_bytes":oracle.maximum_input_bytes,
            "expected_windows":oracle.expected_windows.iter().map(|window|serde_json::json!({
                "window":window.window,"batch":window.batch,"input":window.input
            })).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "independent_checksum_oracle_source":include_str!("../../../node_qualification/reference_oracle.rs"),
        "native_collector_source":include_str!("../../../node_qualification/reference_witness.rs"),
        "input_octets":"{\"bytes_processed\":\"0\",\"checksum\":\"0\"}",
        "initial_state":"zero-checksum-zero-bytes-v1"
    }))?;
    let specification = normative_specification().map_err(failure)?.1;
    SemanticQualificationUnit::build(
        candidate.installations[0].package.clone(),
        &candidate.definition,
        &candidate.installations,
        UnitSourceObjects {
            environment,
            harness,
            fixtures,
            specification,
        },
    )
}

fn kernel_value(name: &str) -> Result<String, ProviderError> {
    let path = std::path::Path::new("/proc/sys/kernel").join(name);
    let mut bytes = Vec::with_capacity(4097);
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(ProviderError::Frame("kernel environment byte ceiling"));
    }
    String::from_utf8(bytes).map_err(|_| ProviderError::Frame("kernel environment is not UTF-8"))
}

fn measure_executable() -> Result<ContentRef, ProviderError> {
    let path = std::fs::canonicalize(std::env::current_exe()?)?;
    let mut file = File::options()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_EXECUTABLE_BYTES {
        return Err(ProviderError::Frame("actual harness executable geometry"));
    }
    let mut hasher = blake3::Hasher::new();
    let domain = b"cnp.blob.v1";
    hasher.update(b"CNP/1\0");
    let domain_length = u32::try_from(domain.len())
        .map_err(|_| ProviderError::Frame("harness hash domain overflow"))?;
    hasher.update(&domain_length.to_be_bytes());
    hasher.update(domain);
    hasher.update(&metadata.len().to_be_bytes());
    let mut length = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or(ProviderError::Frame("harness byte overflow"))?;
        if length > MAXIMUM_EXECUTABLE_BYTES {
            return Err(ProviderError::Frame("harness executable byte ceiling"));
        }
        hasher.update(&buffer[..count]);
    }
    if length != metadata.len() || file.metadata()?.len() != length {
        return Err(ProviderError::Frame(
            "harness executable changed during measurement",
        ));
    }
    Ok(ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: hasher.finalize().to_hex().to_string(),
        },
        length: U64::new(length),
        media_type: "application/octet-stream".into(),
    })
}

fn failure(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
