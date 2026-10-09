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

/// Measures the actual source-owned context and complete immutable fixture.
pub(super) fn measure(
    candidate: &PrivateCandidate,
    oracles: &[ReferenceOracleContract],
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
    let harness = canonical::canonical_json(&serde_json::json!({
        "schema":"crucible.reference.qualification-harness.v1",
        "executable":measure_executable()?,
        "source": [
            ["harness",include_str!("harness.rs")],
            ["context",include_str!("context.rs")],
            ["candidate",include_str!("candidate.rs")],
            ["installation",include_str!("installation.rs")],
            ["launch",include_str!("launch.rs")],
            ["native",include_str!("native.rs")],
            ["custody",include_str!("custody.rs")],
            ["package",include_str!("package.rs")],
            ["graphs",include_str!("graphs.rs")],
            ["world",include_str!("world.rs")],
            ["unit",include_str!("unit.rs")],
            ["witness",include_str!("witness.rs")],
            ["lifecycle",include_str!("lifecycle_witness.rs")],
            ["supported_lifecycle",include_str!("supported_lifecycle.rs")],
            ["supported_execution",include_str!("supported_execution.rs")],
            ["runtime_retries",include_str!("runtime_retries.rs")],
            ["metadata_inspection",include_str!("metadata_inspection.rs")],
            ["package_metadata_controls",include_str!("package_metadata_controls.rs")],
            ["source_probe",include_str!("source_probe.rs")],
            ["source_probe_execution",include_str!("source_probe_execution.rs")],
            ["provider_only",include_str!("native/provider_only.rs")],
            ["prepared_adverse",include_str!("../../../../../crucible/src/node_adapters/cnp/preparation_adverse.rs")],
            ["prepared_gate",include_str!("prepared_gate_evidence.rs")],
            ["prepared_execution",include_str!("source_pre_activation_execution.rs")],
            ["prepared_plan",include_str!("source_pre_activation_probe.rs")],
            ["preparation_probe",include_str!("../../../../../crucible/src/node_adapters/cnp/preparation_probe.rs")]
        ]
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
    let fixtures = canonical::canonical_json(&serde_json::json!({
        "source_probe_plans":source_probes.iter().map(|plan|serde_json::json!({"reference":plan.reference,"bytes":plan.bytes,"objects":plan.objects.iter().map(|(reference,bytes)|serde_json::json!({"reference":reference,"bytes":bytes})).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "prepared_probe_plans":prepared_plans.iter().map(|plan|serde_json::json!({"reference":plan.reference,"bytes":plan.bytes,"objects":plan.fixture_objects().iter().map(|(reference,bytes)|serde_json::json!({"reference":reference,"bytes":bytes})).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "schema":"crucible.reference.qualification-fixtures.v1",
        "supported_preparation":super::supported_lifecycle::fixture(),
        "supported_cycle":super::supported_execution::fixture(),
        "runtime_cached_recovery":super::runtime_retries::fixture(),
        "metadata_inspection":super::metadata_inspection::fixture(),
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
