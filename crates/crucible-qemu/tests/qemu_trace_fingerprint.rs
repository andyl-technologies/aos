//! Checks real-QEMU trace import into canonical execution-fingerprint streams.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Cursor;

use crucible_qemu::{
    QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTraceFingerprintDefinition, QemuTraceFingerprintImport,
    QemuTraceFingerprintImportError, QemuTraceIdentityContract, QemuTraceObservationContract,
    QemuTraceVcpuContract, SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintMismatchKind,
    SingleVmFingerprintSampleDifference, compare_single_vm_fingerprint_streams,
};
use serde_json::{Value, json};

#[test]
fn provisional_trace_definition_names_its_limited_observation_semantics() {
    let baseline_observation = observation(2);
    let definition = QemuTraceFingerprintDefinition::new(4093, &baseline_observation)
        .expect("provisional definition should validate");
    let material = definition.canonical_material();
    assert!(material.contains("trigger=periodic-aggregate-icount-only"));
    assert!(material.contains("component[3]=ordered-cpu-mmio-read-write-history"));
    assert!(material.contains("rr_switch_quantum=4096"));
    assert!(material.contains("baseline_ram_bytes=67108864"));
    assert!(material.contains("launch_definition_digest="));
    assert!(material.contains("complete_current_device_state=false"));
    assert!(material.contains("event_boundary_sampling=false"));
    assert!(!material.contains("component[3]=device-state"));
    let other_observation = observation(3);
    assert_ne!(
        definition.definition_digest(),
        QemuTraceFingerprintDefinition::new(4093, &other_observation)
            .expect("alternate provisional definition should validate")
            .definition_digest(),
        "vCPU/RAM/RR/identity observation parameters must be definition-hashed"
    );
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
    let error = importer(3)
        .import(Cursor::new(trace(2)))
        .expect_err("plugin/QMP topology mismatch must fail");
    assert!(matches!(
        error,
        QemuTraceFingerprintImportError::MalformedTrace { line: 1, .. }
    ));

    let mut values = trace_values(2);
    values[0]["device_event_capture"] = Value::Bool(false);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("disabled device observation must fail");
    assert!(error.to_string().contains("device_event_capture"));

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
    values[2]["retired"] = Value::from(8193);
    let error = importer(2)
        .import(Cursor::new(json_lines(&values)))
        .expect_err("terminal horizon overshoot must fail");
    assert!(error.to_string().contains("exact configured horizon"));

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
    changed_values[1]["register_hashes"][1] = Value::String("00000000000000ff".to_owned());
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

fn importer(vcpus: usize) -> QemuTraceFingerprintImport {
    let observation = observation(vcpus);
    let definition = QemuTraceFingerprintDefinition::new(4096, &observation)
        .expect("test provisional definition should validate");
    QemuTraceFingerprintImport::new(
        "node-a",
        definition.definition_digest().to_vec(),
        4096,
        8192,
        observation,
    )
    .expect("test import contract should validate")
}

fn observation(vcpus: usize) -> QemuTraceObservationContract {
    let vcpu_contracts = (0..vcpus)
        .map(|vcpu| {
            QemuTraceVcpuContract::new(vcpu as u64, 24, 184, 0x100 + vcpu as u64)
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
        vcpu_contracts,
        identity,
    )
    .expect("test observation contract should validate")
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

fn sample(retired: u64, current_vcpu: u64, vcpus: usize) -> Value {
    let hashes = (0..vcpus)
        .map(|vcpu| format!("{:016x}", retired + vcpu as u64))
        .collect::<Vec<_>>();
    let register_counts = (0..vcpus).map(|_| 24).collect::<Vec<_>>();
    let register_file_bytes = (0..vcpus).map(|_| 184).collect::<Vec<_>>();
    let base = retired / vcpus as u64;
    let remainder = retired % vcpus as u64;
    let register_retired = (0..vcpus)
        .map(|vcpu| base + u64::from((vcpu as u64) < remainder))
        .collect::<Vec<_>>();
    let register_schema_hashes = (0..vcpus)
        .map(|vcpu| format!("{:016x}", 0x100 + vcpu as u64))
        .collect::<Vec<_>>();
    json!({
        "schema": QEMU_TRACE_FINGERPRINT_SCHEMA,
        "launch_definition_digest": "10".repeat(32),
        "qemu_build_digest": "20".repeat(32),
        "trace_plugin_build_digest": "30".repeat(32),
        "retired": retired,
        "vcpu": current_vcpu,
        "final": false,
        "tracked_vcpus": vcpus,
        "stop_at": 8192,
        "stop_requested": retired == 8192,
        "rr_current_vcpu": current_vcpu,
        "rr_cursor_position": 0,
        "rr_switch_quantum": 4096,
        "rr_cursor_valid": true,
        "rr_cursor_source": "live_instruction",
        "stream_hash": format!("{retired:016x}"),
        "register_hash": format!("{:016x}", retired + 1),
        "register_hashes": hashes,
        "register_counts": register_counts,
        "register_file_bytes": register_file_bytes,
        "register_schema_hashes": register_schema_hashes,
        "register_retired": register_retired,
        "ram_hash": format!("{:016x}", retired + 2),
        "device_event_hash": format!("{:016x}", retired + 3),
        "device_event_capture": true,
        "extended_hash": format!("{:016x}", retired + 4),
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
        "retired": 8192,
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
