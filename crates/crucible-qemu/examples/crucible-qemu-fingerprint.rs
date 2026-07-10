//! Imports and compares two provenance-bound real-QEMU fingerprint traces.
//!
//! A definition-only QEMU preflight pins the observation shape before the
//! surrounding gate launches the same fixed VM twice. This executable validates
//! the launch/build provenance and exact QMP CPU topology of both runs before
//! importing the canonical periodic and event-boundary trace schema.

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crucible_qemu::{
    QemuTraceDefinitionPreflight, QemuTraceFingerprintDefinition, QemuTraceFingerprintImport,
    QemuTraceObservationContract, QemuTraceVcpuContract, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintGateError, SingleVmFingerprintRunError, SingleVmFingerprintRunInputs,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunner,
    SingleVmFingerprintScenario, SingleVmFingerprintStream, SingleVmHostProfile,
    SingleVmNvcpuFingerprintContract, run_single_vm_fingerprint_gate,
};
use serde_json::Value;

const CONTRACT_SCHEMA: &str = "crucible.qemu.trace-comparison-contract.v1";
const PROVENANCE_SCHEMA: &str = "crucible.qemu.trace-run-provenance.v1";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-fingerprint: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 8 {
        return Err(
            "usage: crucible-qemu-fingerprint CONTRACT DEFINITION_TRACE QMP_A PROVENANCE_A TRACE_A QMP_B PROVENANCE_B TRACE_B"
                .to_owned(),
        );
    }

    let contract = ComparisonContract::read(Path::new(&args[0]))?;
    let preflight = import_definition_preflight(Path::new(&args[1]))?;
    contract.validate_preflight(preflight.observation())?;
    let first_cpu_ids = read_qmp_cpu_ids(Path::new(&args[2]))?;
    let first_provenance = RunProvenance::read(Path::new(&args[3]))?;
    let second_cpu_ids = read_qmp_cpu_ids(Path::new(&args[5]))?;
    let second_provenance = RunProvenance::read(Path::new(&args[6]))?;
    contract.validate_runs(
        &first_cpu_ids,
        &first_provenance,
        &second_cpu_ids,
        &second_provenance,
    )?;

    if first_cpu_ids != preflight.observation().qmp_cpu_ids()
        || second_cpu_ids != preflight.observation().qmp_cpu_ids()
    {
        return Err(
            "comparison-run QMP topology differs from the independent preflight".to_owned(),
        );
    }
    let observation = preflight.observation().clone();
    let definition = QemuTraceFingerprintDefinition::new(contract.cadence_icount, &observation)
        .map_err(|error| format!("invalid preflight-pinned trace definition: {error}"))?;
    let first_importer = contract.importer(&definition, observation.clone())?;
    let second_importer = contract.importer(&definition, observation)?;
    let first_trace = PathBuf::from(&args[4]);
    let second_trace = PathBuf::from(&args[7]);
    let first = import_trace(&first_importer, &first_trace)?;
    let second = import_trace(&second_importer, &second_trace)?;

    let nvcpu_contract = SingleVmNvcpuFingerprintContract::new(
        contract.vcpu_contracts.len(),
        contract.rr_switch_quantum,
    )
    .map_err(|error| format!("invalid launch-derived vCPU contract: {error}"))?;
    let run_inputs = SingleVmFingerprintRunInputs::new(
        decode_digest("guest_image_digest", &contract.guest_image_digest)?,
        contract.kernel_cmdline.clone(),
        decode_digest("seed_digest", &contract.seed_digest)?,
        decode_digest(
            "injected_input_sequence_digest",
            &contract.injected_input_sequence_digest,
        )?,
        decode_digest(
            "launch_definition_digest",
            &contract.launch_definition_digest,
        )?,
    )
    .map_err(|error| format!("invalid fixed run inputs: {error}"))?;
    let scenario = SingleVmFingerprintScenario::new_with_nvcpu_contract(
        format!("{}:{}", contract.node, contract.launch_definition_digest),
        definition.definition_digest().to_vec(),
        contract.horizon_icount,
        nvcpu_contract,
        run_inputs,
        SingleVmHostProfile::new("real-qemu-trace-gate", ["second-run-host-cpu-load"])
            .map_err(|error| format!("invalid host adversary profile: {error}"))?,
    )
    .map_err(|error| format!("invalid gate scenario: {error}"))?;
    let mut runner = ImportedTraceRunner::new(first, second, first_trace, second_trace);

    match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(report) => {
            println!("PASS");
            println!("status=partial");
            println!("definition_status=canonical-preflight-pinned");
            println!(
                "definition_digest={}",
                lower_hex(&definition.definition_digest())
            );
            println!("sample_count={}", report.sample_count);
            println!("horizon_icount={}", contract.horizon_icount);
            println!("vcpu_count={}", contract.vcpu_contracts.len());
            println!("rr_switch_quantum={}", contract.rr_switch_quantum);
            println!("fingerprint_source=real-qemu-trace-plugin-v3");
            println!("device_component=current-non-ram-qemu-vmstate");
            println!("event_boundary_sampling=true");
            println!("comparison=canonical-rust-stream");
            println!("gate_hook=run_single_vm_fingerprint_gate");
            println!("trace_identity_digests=validated-in-every-sample");
            println!("observation_contract_source=independent-definition-only-qemu-preflight");
            println!("independent_observation_contract=true");
            println!("instruction_exact_refinement=false");
            Ok(())
        }
        Err(SingleVmFingerprintGateError::BisectionFailed {
            mismatch, source, ..
        }) => {
            emit_mismatch(&mismatch);
            eprintln!(
                "bisection_window={}..{}",
                mismatch.previous_matching_icount.unwrap_or(0),
                mismatch
                    .first_different_icount
                    .unwrap_or(contract.horizon_icount)
            );
            eprintln!("localization_refinement=coarse-sample-window-only");
            Err(format!("fingerprint mismatch: {mismatch}; {source}"))
        }
        Err(error) => Err(format!("production fingerprint gate hook failed: {error}")),
    }
}

#[derive(Debug)]
struct ComparisonContract {
    node: String,
    cadence_icount: u64,
    horizon_icount: u64,
    rr_switch_quantum: u64,
    baseline_ram_bytes: u64,
    device_state_bytes: u64,
    vcpu_contracts: Vec<QemuTraceVcpuContract>,
    launch_definition_digest: String,
    guest_image_digest: String,
    kernel_cmdline: String,
    seed_digest: String,
    injected_input_sequence_digest: String,
    qemu_build_digest: String,
    trace_plugin_build_digest: String,
}

impl ComparisonContract {
    fn read(path: &Path) -> Result<Self, String> {
        let value = read_json(path)?;
        require_text(&value, "schema", CONTRACT_SCHEMA, path)?;
        let register_counts = u64_array(&value, "register_counts", path)?;
        let register_file_bytes = u64_array(&value, "register_file_bytes", path)?;
        let register_schema_hashes = hex_u64_array(&value, "register_schema_hashes", path)?;
        if register_counts.is_empty()
            || register_counts.len() != register_file_bytes.len()
            || register_counts.len() != register_schema_hashes.len()
        {
            return Err(format!(
                "comparison contract {} has inconsistent register contract arrays",
                path.display()
            ));
        }
        let vcpu_contracts = register_counts
            .into_iter()
            .zip(register_file_bytes)
            .zip(register_schema_hashes)
            .enumerate()
            .map(|(cpu_id, ((count, bytes), schema_hash))| {
                QemuTraceVcpuContract::new(cpu_id as u64, count, bytes, schema_hash)
                    .map_err(|error| format!("invalid vCPU contract {cpu_id}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let launch_definition_digest = text_field(&value, "launch_definition_digest", path)?;
        validate_digest_text("launch_definition_digest", &launch_definition_digest)?;
        Ok(Self {
            node: nonempty_text(&value, "node", path)?,
            cadence_icount: u64_field(&value, "cadence_icount", path)?,
            horizon_icount: u64_field(&value, "horizon_icount", path)?,
            rr_switch_quantum: u64_field(&value, "rr_switch_quantum", path)?,
            baseline_ram_bytes: u64_field(&value, "baseline_ram_bytes", path)?,
            device_state_bytes: u64_field(&value, "device_state_bytes", path)?,
            vcpu_contracts,
            launch_definition_digest,
            guest_image_digest: digest_text(&value, "guest_image_digest", path)?,
            kernel_cmdline: text_field(&value, "kernel_cmdline", path)?,
            seed_digest: digest_text(&value, "seed_digest", path)?,
            injected_input_sequence_digest: digest_text(
                &value,
                "injected_input_sequence_digest",
                path,
            )?,
            qemu_build_digest: digest_text(&value, "qemu_build_digest", path)?,
            trace_plugin_build_digest: digest_text(&value, "trace_plugin_build_digest", path)?,
        })
    }

    fn validate_preflight(&self, preflight: &QemuTraceObservationContract) -> Result<(), String> {
        let identity = preflight.identity();
        if preflight.qmp_cpu_ids().len() != self.vcpu_contracts.len()
            || preflight.rr_switch_quantum() != self.rr_switch_quantum
            || preflight.guest_ram_bytes() != self.baseline_ram_bytes
            || preflight.device_state_bytes() != self.device_state_bytes
            || preflight.vcpu_contracts() != self.vcpu_contracts
            || identity.launch_definition_digest() != self.launch_definition_digest
            || identity.qemu_build_digest() != self.qemu_build_digest
            || identity.trace_plugin_build_digest() != self.trace_plugin_build_digest
        {
            return Err(
                "definition-only QEMU preflight differs from the comparison contract".to_owned(),
            );
        }
        Ok(())
    }

    fn importer(
        &self,
        definition: &QemuTraceFingerprintDefinition,
        observation: QemuTraceObservationContract,
    ) -> Result<QemuTraceFingerprintImport, String> {
        QemuTraceFingerprintImport::new(
            self.node.clone(),
            definition.definition_digest().to_vec(),
            self.cadence_icount,
            self.horizon_icount,
            observation,
        )
        .map_err(|error| error.to_string())
    }

    fn validate_runs(
        &self,
        first_cpu_ids: &[u64],
        first: &RunProvenance,
        second_cpu_ids: &[u64],
        second: &RunProvenance,
    ) -> Result<(), String> {
        let expected_cpu_ids = (0..self.vcpu_contracts.len() as u64).collect::<Vec<_>>();
        if first_cpu_ids != expected_cpu_ids || second_cpu_ids != expected_cpu_ids {
            return Err(format!(
                "QMP CPU indexes must be the exact sorted set 0..{} in both runs",
                expected_cpu_ids.len()
            ));
        }
        if first.ordinal != RunOrdinal::First || second.ordinal != RunOrdinal::Second {
            return Err("run provenance ordinals must be distinct first/second".to_owned());
        }
        if first.run_id == second.run_id {
            return Err("run provenance ids must be distinct".to_owned());
        }
        for provenance in [first, second] {
            if provenance.launch_definition_digest != self.launch_definition_digest
                || provenance.qemu_build_digest != self.qemu_build_digest
                || provenance.trace_plugin_build_digest != self.trace_plugin_build_digest
            {
                return Err(format!(
                    "run provenance `{}` differs from the comparison contract",
                    provenance.run_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunOrdinal {
    First,
    Second,
}

#[derive(Debug)]
struct RunProvenance {
    ordinal: RunOrdinal,
    run_id: String,
    launch_definition_digest: String,
    qemu_build_digest: String,
    trace_plugin_build_digest: String,
}

impl RunProvenance {
    fn read(path: &Path) -> Result<Self, String> {
        let value = read_json(path)?;
        require_text(&value, "schema", PROVENANCE_SCHEMA, path)?;
        let ordinal = match text_field(&value, "ordinal", path)?.as_str() {
            "first" => RunOrdinal::First,
            "second" => RunOrdinal::Second,
            other => return Err(format!("invalid run provenance ordinal `{other}`")),
        };
        let launch_definition_digest = text_field(&value, "launch_definition_digest", path)?;
        validate_digest_text("launch_definition_digest", &launch_definition_digest)?;
        Ok(Self {
            ordinal,
            run_id: nonempty_text(&value, "run_id", path)?,
            launch_definition_digest,
            qemu_build_digest: digest_text(&value, "qemu_build_digest", path)?,
            trace_plugin_build_digest: digest_text(&value, "trace_plugin_build_digest", path)?,
        })
    }
}

struct ImportedTraceRunner {
    first: Option<SingleVmFingerprintStream>,
    second: Option<SingleVmFingerprintStream>,
    first_trace: PathBuf,
    second_trace: PathBuf,
}

impl ImportedTraceRunner {
    fn new(
        first: SingleVmFingerprintStream,
        second: SingleVmFingerprintStream,
        first_trace: PathBuf,
        second_trace: PathBuf,
    ) -> Self {
        Self {
            first: Some(first),
            second: Some(second),
            first_trace,
            second_trace,
        }
    }
}

impl SingleVmFingerprintRunner for ImportedTraceRunner {
    fn run_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, SingleVmFingerprintRunError> {
        let stream = match request.ordinal() {
            SingleVmFingerprintRunOrdinal::First => self.first.take(),
            SingleVmFingerprintRunOrdinal::Second => self.second.take(),
        };
        stream.ok_or_else(|| {
            SingleVmFingerprintRunError::new(
                "imported real-QEMU trace was requested more than once",
            )
        })
    }

    fn bisect_single_vm_fingerprint_mismatch(
        &mut self,
        _request: &SingleVmFingerprintBisectionRequest,
    ) -> Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError> {
        Err(SingleVmFingerprintBisectionError::new(format!(
            "trace-only runner localizes only the coarse sample window for first={} second={}; instruction-exact rerun and state dumps are unavailable",
            self.first_trace.display(),
            self.second_trace.display()
        )))
    }
}

fn import_trace(
    importer: &QemuTraceFingerprintImport,
    path: &Path,
) -> Result<SingleVmFingerprintStream, String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open trace {}: {error}", path.display()))?;
    importer
        .import(BufReader::new(file))
        .map_err(|error| format!("failed to import trace {}: {error}", path.display()))
}

fn import_definition_preflight(path: &Path) -> Result<QemuTraceDefinitionPreflight, String> {
    let file = File::open(path).map_err(|error| {
        format!(
            "failed to open definition preflight {}: {error}",
            path.display()
        )
    })?;
    QemuTraceDefinitionPreflight::import(BufReader::new(file)).map_err(|error| {
        format!(
            "failed to import definition preflight {}: {error}",
            path.display()
        )
    })
}

fn read_qmp_cpu_ids(path: &Path) -> Result<Vec<u64>, String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open QMP response {}: {error}", path.display()))?;
    let mut cpu_ids = None;
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line
            .map_err(|error| format!("failed to read QMP response {}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line).map_err(|error| {
            format!(
                "invalid QMP JSON {} line {}: {error}",
                path.display(),
                index + 1
            )
        })?;
        if let Some(entries) = value.get("return").and_then(Value::as_array) {
            let parsed = entries
                .iter()
                .map(|entry| {
                    entry
                        .get("cpu-index")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| {
                            format!("QMP response {} omitted numeric cpu-index", path.display())
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            cpu_ids = Some(parsed);
        }
    }
    let mut cpu_ids = cpu_ids.ok_or_else(|| {
        format!(
            "QMP response {} did not contain query-cpus-fast results",
            path.display()
        )
    })?;
    cpu_ids.sort_unstable();
    Ok(cpu_ids)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open JSON {}: {error}", path.display()))?;
    serde_json::from_reader(BufReader::new(file))
        .map_err(|error| format!("invalid JSON {}: {error}", path.display()))
}

fn text_field(value: &Value, field: &str, path: &Path) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("JSON {} field `{field}` must be text", path.display()))
}

fn nonempty_text(value: &Value, field: &str, path: &Path) -> Result<String, String> {
    let text = text_field(value, field, path)?;
    if text.is_empty() {
        Err(format!(
            "JSON {} field `{field}` must be non-empty",
            path.display()
        ))
    } else {
        Ok(text)
    }
}

fn digest_text(value: &Value, field: &str, path: &Path) -> Result<String, String> {
    let text = text_field(value, field, path)?;
    validate_digest_text(field, &text)?;
    Ok(text)
}

fn require_text(value: &Value, field: &str, expected: &str, path: &Path) -> Result<(), String> {
    let actual = text_field(value, field, path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "JSON {} field `{field}` must be `{expected}`, got `{actual}`",
            path.display()
        ))
    }
}

fn u64_field(value: &Value, field: &str, path: &Path) -> Result<u64, String> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        format!(
            "JSON {} field `{field}` must be an unsigned integer",
            path.display()
        )
    })
}

fn u64_array(value: &Value, field: &str, path: &Path) -> Result<Vec<u64>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("JSON {} field `{field}` must be an array", path.display()))?
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_u64().ok_or_else(|| {
                format!(
                    "JSON {} field `{field}[{index}]` must be an unsigned integer",
                    path.display()
                )
            })
        })
        .collect()
}

fn hex_u64_array(value: &Value, field: &str, path: &Path) -> Result<Vec<u64>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("JSON {} field `{field}` must be an array", path.display()))?
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let text = item.as_str().ok_or_else(|| {
                format!(
                    "JSON {} field `{field}[{index}]` must be hexadecimal text",
                    path.display()
                )
            })?;
            parse_hex_u64(text, &format!("{field}[{index}]"))
        })
        .collect()
}

fn parse_hex_u64(text: &str, label: &str) -> Result<u64, String> {
    if text.len() != 16 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must contain exactly 16 hexadecimal digits"
        ));
    }
    u64::from_str_radix(text, 16).map_err(|error| format!("invalid {label}: {error}"))
}

fn validate_digest_text(label: &str, text: &str) -> Result<(), String> {
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "{label} must contain exactly 64 hexadecimal digits"
        ))
    }
}

fn decode_digest(label: &str, text: &str) -> Result<Vec<u8>, String> {
    validate_digest_text(label, text)?;
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair)
                .map_err(|error| format!("invalid UTF-8 in {label}: {error}"))?;
            u8::from_str_radix(digits, 16)
                .map_err(|error| format!("invalid hexadecimal {label}: {error}"))
        })
        .collect()
}

fn emit_mismatch(mismatch: &crucible_qemu::SingleVmFingerprintMismatch) {
    eprintln!("first_differing_sample={}", mismatch.sample_index);
    eprintln!(
        "previous_matching_icount={}",
        optional_icount(mismatch.previous_matching_icount)
    );
    eprintln!(
        "first_different_icount={}",
        optional_icount(mismatch.first_different_icount)
    );
    eprintln!("first_differing_component={}", mismatch_component(mismatch));
}

fn mismatch_component(mismatch: &crucible_qemu::SingleVmFingerprintMismatch) -> String {
    match &mismatch.kind {
        crucible_qemu::SingleVmFingerprintMismatchKind::Definition { .. } => {
            "definition_digest".to_owned()
        }
        crucible_qemu::SingleVmFingerprintMismatchKind::Sample { difference, .. } => {
            difference.material_token()
        }
        crucible_qemu::SingleVmFingerprintMismatchKind::Length { .. } => "sample_count".to_owned(),
        crucible_qemu::SingleVmFingerprintMismatchKind::Final { .. } => {
            "final_fingerprint".to_owned()
        }
    }
}

fn optional_icount(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
