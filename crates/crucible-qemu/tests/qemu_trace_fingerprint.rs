//! Checks real-QEMU trace import into canonical execution-fingerprint streams.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, Cursor};

use crucible_qemu::{
    QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTraceDefinitionPreflight, QemuTraceFingerprintDefinition,
    QemuTraceFingerprintImport, QemuTraceFingerprintImportError, QemuTraceIdentityContract,
    QemuTraceObservationContract, QemuTraceProcessArgvContract, QemuTraceVcpuContract,
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintMismatchKind,
    SingleVmFingerprintSampleDifference, compare_single_vm_fingerprint_streams,
};
use serde_json::{Value, json};

#[test]
fn canonical_trace_definition_pins_complete_preflight_observation_semantics() {
    let pinned_observation = observation(2);
    let definition = QemuTraceFingerprintDefinition::new(4093, &pinned_observation)
        .expect("canonical definition should validate");
    let material = definition.canonical_material();
    assert!(material.contains("trigger[0]=periodic-aggregate-icount"));
    assert!(material.contains("trigger[1]=horizon-advance"));
    assert!(material.contains("trigger[2]=frame-delivery"));
    assert!(material.contains("trigger[3]=fault-activation"));
    assert!(material.contains("component[3]=qemu-non-ram-vmstate-sha256"));
    assert!(material.contains("rr_switch_quantum=4096"));
    assert!(material.contains("guest_ram_bytes=67108864"));
    assert!(material.contains("device_state_sections=5"));
    assert!(material.contains("device_state_schema_digest="));
    assert!(material.contains("launch_definition_digest="));
    assert!(material.contains("complete_current_device_state=true"));
    assert!(material.contains("event_boundary_sampling=true"));
    let other_observation = observation(3);
    assert_ne!(
        definition.definition_digest(),
        QemuTraceFingerprintDefinition::new(4093, &other_observation)
            .expect("alternate canonical definition should validate")
            .definition_digest(),
        "vCPU/RAM/RR/identity observation parameters must be definition-hashed"
    );
}

#[test]
fn definition_preflight_is_independent_complete_and_instruction_free() {
    let preflight = import_preflight(Cursor::new(definition_preflight(2).to_string()))
        .expect("independent definition preflight should import");
    let definition = QemuTraceFingerprintDefinition::new(4096, preflight.observation())
        .expect("preflight should build the canonical definition");
    assert!(definition.canonical_material().contains("vcpu[1].cpu_id=1"));
    assert!(
        definition
            .canonical_material()
            .contains("device_state_sections=5")
    );

    let mut incomplete = definition_preflight(2);
    incomplete["device_state_failures"] = Value::from(1);
    let error = import_preflight(Cursor::new(incomplete.to_string()))
        .expect_err("failed VMState preflight must fail closed");
    assert!(error.to_string().contains("device_state_failures"));

    let mut executed = definition_preflight(2);
    executed["observed_icount"] = Value::from(1);
    let error = import_preflight(Cursor::new(executed.to_string()))
        .expect_err("preflight after guest execution must fail closed");
    assert!(error.to_string().contains("`observed_icount` must be zero"));

    let mut running = definition_preflight(2);
    running["observed_non_running"] = Value::Bool(false);
    let error = import_preflight(Cursor::new(running.to_string()))
        .expect_err("a running preflight must fail closed");
    assert!(error.to_string().contains("observed_non_running"));

    let mut zero_register_digest = definition_preflight(2);
    zero_register_digest["register_digests"][0] = Value::from("00".repeat(32));
    let error = import_preflight(Cursor::new(zero_register_digest.to_string()))
        .expect_err("zero register digest must fail the preflight");
    assert!(error.to_string().contains("register_digests[0]"));

    let mut schema_failure = definition_preflight(2);
    schema_failure["device_state_schema_status"] = Value::from(1);
    let error = import_preflight(Cursor::new(schema_failure.to_string()))
        .expect_err("failed VMState schema observation must fail closed");
    assert!(error.to_string().contains("device_state_schema_status"));

    let mut missing_encoding = definition_preflight(2);
    missing_encoding
        .as_object_mut()
        .expect("definition fixture is an object")
        .remove("process_argv_encoding");
    let error = import_preflight(Cursor::new(missing_encoding.to_string()))
        .expect_err("missing process argv encoding must fail closed");
    assert!(error.to_string().contains("process_argv_encoding"));

    let mut wrong_digest = definition_preflight(2);
    wrong_digest["process_argv_digest"] = Value::String("56".repeat(32));
    let error = import_preflight(Cursor::new(wrong_digest.to_string()))
        .expect_err("mismatched process argv digest must fail closed");
    assert!(error.to_string().contains("process_argv_digest"));
}

#[test]
fn observation_import_rejects_process_argv_self_attestation_drift() {
    for (field, value) in [
        ("process_argv_attestation_version", Value::from(1)),
        ("process_argv_argc", Value::from(4)),
        ("process_argv_raw_bytes", Value::from(13)),
        ("process_argv_digest", Value::String("56".repeat(32))),
        ("process_argv_status", Value::from(1)),
    ] {
        let mut values = trace_values(2);
        values[0][field] = value;
        let error = importer(2)
            .import(Cursor::new(json_lines(&values)))
            .expect_err("process argv self-attestation drift must fail closed");
        assert!(error.to_string().contains(field));
    }
}

#[test]
fn real_qemu_trace_import_canonicalizes_all_vcpu_rr_ram_and_device_material() {
    let stream = importer(2)
        .import(Cursor::new(trace(2)))
        .expect("complete trace should import");

    assert_eq!(stream.samples.len(), 2);
    assert_eq!(stream.final_icount, 8192);
    assert_eq!(
        stream.final_fingerprint,
        stream.samples[1].rolling_fingerprint
    );
    let material = &stream.samples[1].nvcpu_fingerprint;
    assert_eq!(material.vcpu_registers().len(), 2);
    assert_eq!(material.vcpu_registers()[0].register_file_bytes(), 184);
    assert_eq!(
        material.vcpu_registers()[1].retired_instruction_count(),
        4096
    );
    assert_eq!(material.rr_cursor().current_vcpu(), 1);
    assert_eq!(material.rr_cursor().position_in_quantum(), 0);
    assert_eq!(material.rr_cursor().rr_switch_quantum(), 4096);
    assert_eq!(
        material.guest_memory_digest().len(),
        SINGLE_VM_FINGERPRINT_DIGEST_BYTES
    );
    assert_eq!(
        material.device_state_digest().len(),
        SINGLE_VM_FINGERPRINT_DIGEST_BYTES
    );
}

#[test]
fn real_qemu_trace_import_rejects_qmp_topology_or_incomplete_observation() {
    let error = QemuTraceVcpuContract::new(0, 24, 184, [0; 32])
        .expect_err("zero register-schema digest must fail closed");
    assert!(
        error
            .to_string()
            .contains("register-schema digest must be non-zero")
    );

    let error = importer(3)
        .import(Cursor::new(trace(2)))
        .expect_err("plugin/QMP topology mismatch must fail");
    assert!(matches!(
        error,
        QemuTraceFingerprintImportError::MalformedTrace { line: 1, .. }
    ));

    let mut values = trace_values(2);
    values[0]["device_state_complete"] = Value::Bool(false);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("disabled device observation must fail");
    assert!(error.to_string().contains("device_state_complete"));

    let mut values = trace_values(2);
    values[0]
        .as_object_mut()
        .expect("sample is an object")
        .remove("register_retired");
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("missing per-vCPU retired state must fail");
    assert!(error.to_string().contains("register_retired"));

    let mut values = trace_values(2);
    values[2]["stop_at"] = Value::from(12_288);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("terminal stop horizon drift must fail");
    assert!(error.to_string().contains("stop_at"));

    let mut values = trace_values(2);
    values[1]["register_retired"][1] = Value::from(4097);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("per-vCPU retired sum drift must fail");
    assert!(error.to_string().contains("retired instruction sum"));

    let mut values = trace_values(2);
    values[1]["register_file_bytes"][0] = Value::from(183);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("register byte-count drift must fail");
    assert!(error.to_string().contains("register_file_bytes"));

    let mut values = trace_values(2);
    values[0]["register_digests"][0] = Value::String("00".repeat(32));
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("zero register observation hash must fail");
    assert!(
        error
            .to_string()
            .contains("register_digests[0]` must be non-zero")
    );

    let mut values = trace_values(2);
    values[0]["ram_digest"] = Value::String("00".repeat(32));
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("zero RAM observation hash must fail");
    assert!(error.to_string().contains("`ram_digest` must be non-zero"));

    let mut values = trace_values(2);
    values[0]["device_state_digest"] = Value::String("00".repeat(32));
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("zero device observation hash must fail");
    assert!(
        error
            .to_string()
            .contains("`device_state_digest` must be non-zero")
    );

    let mut values = trace_values(2);
    values[2]["observed_icount"] = Value::from(8193);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("terminal logical-time overshoot must fail");
    assert!(error.to_string().contains("differs from exact horizon"));

    let mut values = trace_values(2);
    values[2]["observed_icount"] = Value::from(8191);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("terminal logical time before the horizon must fail");
    assert!(error.to_string().contains("differs from exact horizon"));

    let mut values = trace_values(2);
    values[2]["retired"] = Value::from(8191);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("terminal retired count regression must fail");
    assert!(
        error
            .to_string()
            .contains("differs from the horizon sample")
    );

    let mut values = trace_values(2);
    values.push(json!({"kind": "rr_switch"}));
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("any record after the terminal record must fail");
    assert!(
        error
            .to_string()
            .contains("record appeared after the terminal plugin stop record")
    );

    let mut values = trace_values(2);
    values[1]["rr_cursor_position"] = Value::from(4096);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("cursor exactly at the exclusive quantum boundary must fail");
    assert!(error.to_string().contains("inside rr_switch_quantum"));

    let mut values = trace_values(2);
    values[2]["rr_cursor_source"] = Value::String("live_instruction".to_owned());
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("terminal cursor must come from the last executed instruction");
    assert!(error.to_string().contains("last_executed_instruction"));

    let mut values = trace_values(2);
    values.insert(0, json!({"kind": "future_unknown_diagnostic"}));
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("unknown diagnostics must fail closed");
    assert!(
        error
            .to_string()
            .contains("unknown QEMU trace diagnostic kind")
    );

    let mut values = trace_values(2);
    values[0]["vcpu"] = Value::from(1);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("sample callback vCPU must match the RR current vCPU");
    assert!(error.to_string().contains("differs from RR current vCPU"));

    let mut values = trace_values(2);
    values[0]["rr_cursor_position"] = Value::from(3000);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("RR position cannot exceed current-vCPU retired count");
    assert!(
        error
            .to_string()
            .contains("exceeds the current vCPU retired count")
    );

    let mut values = trace_values(2);
    values[0]["qemu_build_digest"] = Value::String("40".repeat(32));
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("trace identity drift must fail");
    assert!(error.to_string().contains("qemu_build_digest"));
}

#[test]
fn real_qemu_trace_comparison_localizes_first_vcpu_register_difference() {
    let first = importer(2)
        .import(Cursor::new(trace(2)))
        .expect("baseline trace should import");
    let mut changed_values = trace_values(2);
    changed_values[1]["register_digests"][1] = Value::String("ff".repeat(32));
    let second = importer(2)
        .import(Cursor::new(json_lines(&changed_values)))
        .expect("mutated trace should remain structurally valid");

    let mismatch = compare_single_vm_fingerprint_streams(&first, &second, 8192)
        .expect_err("changed vCPU state must differ");
    assert_eq!(mismatch.sample_index, 1);
    assert_eq!(mismatch.previous_matching_icount, Some(4096));
    assert_eq!(mismatch.first_different_icount, Some(8192));
    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Sample {
            difference: SingleVmFingerprintSampleDifference::VcpuRegisterDigest { vcpu_id: 1 },
            ..
        }
    ));
}

#[test]
fn real_qemu_trace_import_accepts_retired_offset_at_exact_observed_horizon() {
    let mut values = trace_values(2);
    values[0]["retired"] = Value::from(4080);
    values[0]["register_retired"] = json!([2040, 2040]);
    values[1]["retired"] = Value::from(8176);
    values[1]["register_retired"] = json!([4088, 4088]);
    values[2]["retired"] = Value::from(8176);

    let stream = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect("retired counts may trail the exact QEMU logical-time boundary");

    assert_eq!(stream.samples.len(), 2);
    assert_eq!(stream.samples[0].icount, 4096);
    assert_eq!(stream.samples[1].icount, 8192);
    assert_eq!(stream.final_icount, 8192);
}

#[test]
fn real_qemu_trace_import_pins_vmstate_schema_not_serialized_value_length() {
    let mut values = trace_values(2);
    values[0]["device_state_bytes"] = Value::from(4100);
    values[1]["device_state_bytes"] = Value::from(4200);
    importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect("value-dependent VMState lengths may vary under one pinned schema");

    values[1]["device_state_schema_digest"] = Value::String("55".repeat(32));
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("VMState section/schema drift must fail closed");
    assert!(error.to_string().contains("section/schema coverage"));
}

#[test]
fn real_qemu_trace_import_accepts_instruction_probe_between_periodic_samples() {
    let observation = observation(2);
    let definition = QemuTraceFingerprintDefinition::new(4096, &observation)
        .expect("probe definition should validate");
    let importer = QemuTraceFingerprintImport::new(
        "node-a",
        definition.definition_digest().to_vec(),
        4096,
        6145,
        observation,
        process_argv_contract(),
    )
    .expect("instruction probe importer should validate");
    let mut values = vec![sample(4096, 0, 2), sample(6145, 1, 2), terminal(2)];
    values[0]["stop_at"] = Value::from(6145);
    values[1]["stop_at"] = Value::from(6145);
    values[1]["stop_requested"] = Value::Bool(true);
    values[1]["trigger"] = Value::String("event".to_owned());
    values[1]["event_boundary"] = Value::String("horizon-advance".to_owned());
    values[2]["stop_at"] = Value::from(6145);
    values[2]["retired"] = Value::from(6145);
    values[2]["observed_icount"] = Value::from(6145);

    let stream = importer
        .import(Cursor::new(json_lines(&values)))
        .expect("an exact instruction probe need not align to periodic cadence");

    assert_eq!(stream.samples.len(), 2);
    assert_eq!(stream.samples[0].icount, 4096);
    assert_eq!(stream.samples[1].icount, 6145);
    assert_eq!(stream.final_icount, 6145);
}

fn importer(vcpus: usize) -> QemuTraceFingerprintImport {
    let observation = observation(vcpus);
    let definition = QemuTraceFingerprintDefinition::new(4096, &observation)
        .expect("test canonical definition should validate");
    QemuTraceFingerprintImport::new(
        "node-a",
        definition.definition_digest().to_vec(),
        4096,
        8192,
        observation,
        process_argv_contract(),
    )
    .expect("test import contract should validate")
}

fn observation(vcpus: usize) -> QemuTraceObservationContract {
    let vcpu_contracts = (0..vcpus)
        .map(|vcpu| {
            QemuTraceVcpuContract::new(vcpu as u64, 24, 184, [(vcpu + 1) as u8; 32])
                .expect("test vCPU contract should validate")
        })
        .collect();
    let identity =
        QemuTraceIdentityContract::new("10".repeat(32), "20".repeat(32), "30".repeat(32))
            .expect("test trace identity should validate");
    QemuTraceObservationContract::new(
        (0..vcpus as u64).collect(),
        4096,
        64 * 1024 * 1024,
        5,
        [0x44; 32],
        vcpu_contracts,
        identity,
    )
    .expect("test observation contract should validate")
}

fn process_argv_contract() -> QemuTraceProcessArgvContract {
    QemuTraceProcessArgvContract::new(3, 12, [0x55; 32])
        .expect("test process argv contract should validate")
}

fn import_preflight<R: BufRead>(
    reader: R,
) -> Result<QemuTraceDefinitionPreflight, QemuTraceFingerprintImportError> {
    QemuTraceDefinitionPreflight::import(reader, process_argv_contract())
}

fn trace(vcpus: usize) -> String {
    json_lines(&trace_values(vcpus))
}

fn trace_values(vcpus: usize) -> Vec<Value> {
    vec![
        sample(4096, 0, vcpus),
        sample(8192, 1, vcpus),
        terminal(vcpus),
    ]
}

fn definition_preflight(vcpus: usize) -> Value {
    json!({
        "kind": "definition",
        "schema": QEMU_TRACE_FINGERPRINT_SCHEMA,
        "definition_only": true,
        "observed_non_running": true,
        "device_state_complete": true,
        "retired": 0,
        "observed_icount": 0,
        "tracked_vcpus": vcpus,
        "rr_switch_quantum": 4096,
        "launch_definition_digest": "10".repeat(32),
        "qemu_build_digest": "20".repeat(32),
        "trace_plugin_build_digest": "30".repeat(32),
        "process_argv_attestation_version": 2,
        "process_argv_encoding": "raw-unix-argv-v2",
        "process_argv_argc": 3,
        "process_argv_raw_bytes": 12,
        "process_argv_digest": "55".repeat(32),
        "process_argv_status": 0,
        "register_counts": (0..vcpus).map(|_| 24).collect::<Vec<_>>(),
        "register_file_bytes": (0..vcpus).map(|_| 184).collect::<Vec<_>>(),
        "register_digests": (0..vcpus)
            .map(|vcpu| format!("{:02x}", vcpu + 3).repeat(32))
            .collect::<Vec<_>>(),
        "register_schema_digests": (0..vcpus)
            .map(|vcpu| format!("{:02x}", vcpu + 1).repeat(32))
            .collect::<Vec<_>>(),
        "ram_bytes": 64 * 1024 * 1024,
        "ram_digest": "33".repeat(32),
        "ram_status": 0,
        "device_state_bytes": 4096,
        "device_state_digest": "43".repeat(32),
        "device_state_sections": 5,
        "device_state_schema_digest": "44".repeat(32),
        "device_state_status": 0,
        "device_state_schema_status": 0,
        "sample_register_failures": 0,
        "register_read_failures": 0,
        "device_state_failures": 0
    })
}

fn sample(retired: u64, current_vcpu: u64, vcpus: usize) -> Value {
    let digests = (0..vcpus)
        .map(|vcpu| format!("{:02x}", ((retired + vcpu as u64) % 255 + 1) as u8).repeat(32))
        .collect::<Vec<_>>();
    let register_counts = (0..vcpus).map(|_| 24).collect::<Vec<_>>();
    let register_file_bytes = (0..vcpus).map(|_| 184).collect::<Vec<_>>();
    let base = retired / vcpus as u64;
    let remainder = retired % vcpus as u64;
    let register_retired = (0..vcpus)
        .map(|vcpu| base + u64::from((vcpu as u64) < remainder))
        .collect::<Vec<_>>();
    let register_schema_digests = (0..vcpus)
        .map(|vcpu| format!("{:02x}", vcpu + 1).repeat(32))
        .collect::<Vec<_>>();
    json!({
        "schema": QEMU_TRACE_FINGERPRINT_SCHEMA,
        "launch_definition_digest": "10".repeat(32),
        "qemu_build_digest": "20".repeat(32),
        "trace_plugin_build_digest": "30".repeat(32),
        "process_argv_attestation_version": 2,
        "process_argv_encoding": "raw-unix-argv-v2",
        "process_argv_argc": 3,
        "process_argv_raw_bytes": 12,
        "process_argv_digest": "55".repeat(32),
        "process_argv_status": 0,
        "retired": retired,
        "observed_icount": retired,
        "vcpu": current_vcpu,
        "final": false,
        "tracked_vcpus": vcpus,
        "stop_at": 8192,
        "stop_requested": retired == 8192,
        "trigger": if retired == 8192 { "event" } else { "periodic" },
        "event_boundary": if retired == 8192 { Value::String("horizon-advance".to_owned()) } else { Value::Null },
        "rr_current_vcpu": current_vcpu,
        "rr_cursor_position": 0,
        "rr_switch_quantum": 4096,
        "rr_cursor_valid": true,
        "rr_cursor_source": "live_instruction",
        "stream_hash": format!("{retired:016x}"),
        "register_digests": digests,
        "register_counts": register_counts,
        "register_file_bytes": register_file_bytes,
        "register_schema_digests": register_schema_digests,
        "register_retired": register_retired,
        "ram_digest": format!("{:02x}", (retired % 255 + 1) as u8).repeat(32),
        "ram_status": 0,
        "device_state_digest": format!("{:02x}", ((retired + 1) % 255 + 1) as u8).repeat(32),
        "device_state_bytes": 4096,
        "device_state_sections": 5,
        "device_state_schema_digest": "44".repeat(32),
        "device_state_status": 0,
        "device_state_schema_status": 0,
        "device_state_complete": true,
        "device_state_failures": 0,
        "diagnostic_extended_fnv": format!("{:016x}", retired + 4),
        "ram_bytes": 64 * 1024 * 1024,
        "memory_events": retired,
        "io_events": retired / 2,
        "memory_events_enabled": true,
        "sample_register_failures": 0,
        "register_read_failures": 0
    })
}

fn terminal(vcpus: usize) -> Value {
    json!({
        "schema": QEMU_TRACE_FINGERPRINT_SCHEMA,
        "launch_definition_digest": "10".repeat(32),
        "qemu_build_digest": "20".repeat(32),
        "trace_plugin_build_digest": "30".repeat(32),
        "process_argv_attestation_version": 2,
        "process_argv_encoding": "raw-unix-argv-v2",
        "process_argv_argc": 3,
        "process_argv_raw_bytes": 12,
        "process_argv_digest": "55".repeat(32),
        "process_argv_status": 0,
        "retired": 8192,
        "observed_icount": 8192,
        "vcpu": 1,
        "final": true,
        "tracked_vcpus": vcpus,
        "stop_at": 8192,
        "stop_requested": true,
        "rr_current_vcpu": 1,
        "rr_cursor_position": 0,
        "rr_switch_quantum": 4096,
        "rr_cursor_valid": true,
        "rr_cursor_source": "last_executed_instruction"
    })
}

fn json_lines(values: &[Value]) -> String {
    let mut output = values
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    output.push('\n');
    output
}
