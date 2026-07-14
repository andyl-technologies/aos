//! Checks `gate:single-vm-fingerprint` over the QEMU host hook.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::VecDeque;

use crucible::{
    EventLog, SchedulerEvaluationBoundaryKind, VirtualTime, event_log_causal_projection,
};
use crucible_protocol::{
    PluginNvcpuFingerprintSnapshot, PluginRoundRobinCursorSnapshot, PluginVcpuRegisterSnapshot,
};
use crucible_qemu::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintCanonicalEvent, SingleVmFingerprintDivergenceStateDump,
    SingleVmFingerprintEventBoundary, SingleVmFingerprintGateError,
    SingleVmFingerprintMismatchKind, SingleVmFingerprintProbe, SingleVmFingerprintProbeRequest,
    SingleVmFingerprintProbeRunner, SingleVmFingerprintRunError, SingleVmFingerprintRunInputs,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunStateDump,
    SingleVmFingerprintRunner, SingleVmFingerprintSample, SingleVmFingerprintSampleDifference,
    SingleVmFingerprintSampleMaterial, SingleVmFingerprintScenario,
    SingleVmFingerprintStateDumpProbe, SingleVmFingerprintStream, SingleVmFingerprintTrigger,
    SingleVmFingerprintVcpuState, SingleVmHostProfile, SingleVmNvcpuFingerprintContract,
    SingleVmNvcpuFingerprintMaterial, SingleVmQmpVcpuTopology, SingleVmRoundRobinCursor,
    SingleVmVcpuRegisterDigest, bisect_single_vm_fingerprint_with_probes,
    compare_single_vm_fingerprint_streams, compute_single_vm_sample_rolling_fingerprint,
    initial_single_vm_rolling_fingerprint, run_single_vm_fingerprint_gate,
};

#[test]
fn gate_single_vm_fingerprint_runs_fixed_scenario_twice() {
    let scenario = scenario();
    let stream = stream(&[1, 2, 3], 9);
    let mut runner = FakeRunner::new(vec![Ok(stream.clone()), Ok(stream.clone())]);

    let report = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(report) => report,
        Err(error) => panic!("identical streams should pass: {error}"),
    };

    assert_eq!(report.scenario_id, scenario.id());
    assert_eq!(report.sample_count, 3);
    assert_eq!(report.matching_final_fingerprint, digest(9));
    assert_eq!(report.first_stream, stream);
    assert_eq!(report.second_stream, stream);
    assert_eq!(
        runner
            .requests
            .iter()
            .map(SingleVmFingerprintRunRequest::ordinal)
            .collect::<Vec<_>>(),
        vec![
            SingleVmFingerprintRunOrdinal::First,
            SingleVmFingerprintRunOrdinal::Second,
        ]
    );
    assert!(
        runner
            .requests
            .iter()
            .all(|request| request.scenario() == &scenario)
    );
    assert_eq!(
        runner.requests[0].scenario().run_inputs(),
        runner.requests[1].scenario().run_inputs(),
        "both backend launches must receive the same image/cmdline/seed/input tuple"
    );
}

#[test]
fn gate_single_vm_fingerprint_content_addresses_exact_run_inputs() {
    let baseline = SingleVmFingerprintRunInputs::new(
        digest(0x31),
        "console=ttyS0",
        digest(0x32),
        digest(0x33),
        digest(0x34),
    )
    .unwrap_or_else(|error| panic!("baseline run inputs should validate: {error}"));
    let changed_cmdline = SingleVmFingerprintRunInputs::new(
        digest(0x31),
        "console=ttyS0 debug",
        digest(0x32),
        digest(0x33),
        digest(0x34),
    )
    .unwrap_or_else(|error| panic!("changed run inputs should validate: {error}"));
    let changed_input_sequence = SingleVmFingerprintRunInputs::new(
        digest(0x31),
        "console=ttyS0",
        digest(0x32),
        digest(0x35),
        digest(0x34),
    )
    .unwrap_or_else(|error| panic!("changed input sequence should validate: {error}"));

    assert_ne!(baseline.content_digest(), changed_cmdline.content_digest());
    assert_ne!(
        baseline.content_digest(),
        changed_input_sequence.content_digest()
    );
    assert!(
        baseline
            .canonical_material()
            .contains("kernel_cmdline=console=ttyS0")
    );
}

#[test]
fn gate_single_vm_fingerprint_reports_first_sample_window() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mut runner = FakeRunner::with_bisections(
        vec![Ok(first.clone()), Ok(second.clone())],
        vec![Ok(bisection_report(1, Some(4096), 8192, 6144, 6145))],
    );

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("different streams should fail"),
        Err(error) => error,
    };

    let SingleVmFingerprintGateError::Mismatch {
        mismatch,
        first_stream,
        second_stream,
        bisection,
    } = error
    else {
        panic!("sample divergence should report a mismatch");
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Sample {
            difference: SingleVmFingerprintSampleDifference::VcpuRegisterDigest { vcpu_id: 1 },
            ..
        }
    ));
    assert_eq!(mismatch.sample_index, 1);
    assert_eq!(mismatch.previous_matching_icount, Some(4096));
    assert_eq!(mismatch.first_different_icount, Some(8192));
    assert_eq!(*first_stream, first);
    assert_eq!(*second_stream, second);
    assert_eq!(bisection.sample_index(), 1);
    assert_eq!(bisection.first_different_sample_icount(), 8192);
    assert_eq!(bisection.last_matching_icount(), 6144);
    assert_eq!(bisection.first_different_icount(), 6145);
    assert_eq!(
        bisection.state_dump_content_address(),
        "blake3:ef829453fdf1558415de033f71f36740c3610012904f986bdec775b4fd096621"
    );
    assert_eq!(runner.bisection_requests.len(), 1);
    assert_eq!(
        runner.bisection_requests[0].scenario().id(),
        "contract-a-single-vm"
    );
    assert_eq!(runner.bisection_requests[0].mismatch().sample_index, 1);
    assert_eq!(runner.bisection_requests[0].first_stream(), &first);
    assert_eq!(runner.bisection_requests[0].second_stream(), &second);
}

#[test]
fn exact_probe_bisection_refines_to_one_instruction_and_content_addresses_dumped_state() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mismatch = compare_single_vm_fingerprint_streams(&first, &second, 12_288)
        .expect_err("changed second sample should define a coarse mismatch");
    let request = SingleVmFingerprintBisectionRequest::new(scenario, mismatch, first, second);
    let mut runner = ExactProbeRunner::new(6145);

    let report = bisect_single_vm_fingerprint_with_probes(&mut runner, &request)
        .expect("fallible live probes should refine the coarse mismatch");

    assert_eq!(report.last_matching_icount(), 6144);
    assert_eq!(report.first_different_icount(), 6145);
    assert_eq!(report.responsible_node(), "node-a");
    assert!(report.state_dump_content_address().starts_with("blake3:"));
    assert_eq!(report.state_dump_content_address().len(), 71);
    assert!(runner.probes.iter().any(|(_, icount)| *icount == 6144));
    assert!(runner.probes.iter().any(|(_, icount)| *icount == 6145));
    assert_eq!(runner.dumps.len(), 2);
}

#[test]
fn exact_probe_bisection_propagates_backend_failure() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mismatch = compare_single_vm_fingerprint_streams(&first, &second, 12_288)
        .expect_err("changed second sample should define a coarse mismatch");
    let request = SingleVmFingerprintBisectionRequest::new(scenario, mismatch, first, second);
    let mut runner = ExactProbeRunner::new(6145);
    runner.fail_at = Some(6144);

    let error = bisect_single_vm_fingerprint_with_probes(&mut runner, &request)
        .expect_err("a failed live probe must not be treated as a comparison result");

    assert!(error.message().contains("injected probe failure"));
    assert!(runner.dumps.is_empty());
}

#[test]
fn exact_probe_bisection_rejects_pre_execution_divergence() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[7, 2, 3], 9);
    let mismatch = compare_single_vm_fingerprint_streams(&first, &second, 12_288)
        .expect_err("changed first sample should define a genesis-based window");
    assert_eq!(mismatch.previous_matching_icount, None);
    let request = SingleVmFingerprintBisectionRequest::new(scenario, mismatch, first, second);
    let mut runner = ExactProbeRunner::new(6145);
    runner.genesis_differs = true;

    let error = bisect_single_vm_fingerprint_with_probes(&mut runner, &request)
        .expect_err("different paused genesis states must fail before instruction attribution");

    assert!(error.message().contains("low endpoint 0 already differs"));
    assert!(runner.dumps.is_empty());
}

#[test]
fn exact_probe_bisection_rejects_nonreproducible_final_endpoint() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mismatch = compare_single_vm_fingerprint_streams(&first, &second, 12_288)
        .expect_err("changed second sample should define a coarse mismatch");
    let request = SingleVmFingerprintBisectionRequest::new(scenario, mismatch, first, second);
    let mut runner = ExactProbeRunner::new(6145);
    runner.unstable_at = Some(6145);

    let error = bisect_single_vm_fingerprint_with_probes(&mut runner, &request)
        .expect_err("a changing final endpoint must invalidate refinement");

    assert!(error.message().contains("not reproducible"));
    assert!(runner.dumps.is_empty());
}

#[test]
fn exact_probe_bisection_rejects_dump_topology_shorter_than_scenario() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mismatch = compare_single_vm_fingerprint_streams(&first, &second, 12_288)
        .expect_err("changed second sample should define a coarse mismatch");
    let request = SingleVmFingerprintBisectionRequest::new(scenario, mismatch, first, second);
    let mut runner = ExactProbeRunner::new(6145);
    runner.truncate_dump_topology = true;

    let error = bisect_single_vm_fingerprint_with_probes(&mut runner, &request)
        .expect_err("a partial vCPU dump must fail scenario admission");

    assert!(error.message().contains("topology"));
}

#[test]
fn state_dump_accepts_empty_suffix_for_empty_causal_log() {
    let dump = SingleVmFingerprintRunStateDump::new(
        "node-a",
        1,
        vec![
            SingleVmFingerprintVcpuState::new(0, [0x10])
                .unwrap_or_else(|error| panic!("test vCPU state should validate: {error}")),
        ],
        Vec::new(),
        [0x40],
        0,
        Vec::new(),
    );

    assert!(dump.is_ok());
}

#[test]
fn gate_single_vm_fingerprint_reports_final_mismatch_at_horizon() {
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 2, 3], 8);
    let mismatch = match compare_single_vm_fingerprint_streams(&first, &second, 12_288) {
        Ok(()) => panic!("different final fingerprints should fail"),
        Err(mismatch) => mismatch,
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Final { .. }
    ));
    assert_eq!(mismatch.sample_index, 3);
    assert_eq!(mismatch.previous_matching_icount, Some(8192));
    assert_eq!(mismatch.first_different_icount, Some(12_288));
}

#[test]
fn same_icount_event_mismatch_uses_previous_strictly_lower_boundary() {
    let first = stream_with_same_icount_event(0x21);
    let second = stream_with_same_icount_event(0x22);

    let mismatch = compare_single_vm_fingerprint_streams(&first, &second, 8192)
        .expect_err("same-icount event state difference must be localized");

    assert_eq!(mismatch.sample_index, 1);
    assert_eq!(mismatch.first_different_icount, Some(4096));
    assert_eq!(mismatch.previous_matching_icount, None);
}

#[test]
fn gate_single_vm_fingerprint_digest_includes_all_vcpus_and_rr_cursor() {
    let definition_digest = digest(1);
    let previous = initial_rolling(&definition_digest);
    let baseline = material(0, 4096, 2, rr_cursor(0, 0, 8));
    let changed_vcpu = sample_material_with_nvcpu(
        0,
        4096,
        nvcpu_material_with_register_bytes([2, 99], rr_cursor(0, 0, 8)),
    );
    let changed_cursor = material(0, 4096, 2, rr_cursor(1, 3, 8));

    let baseline_sample = sample_from_material(&definition_digest, &previous, baseline);
    let changed_vcpu_sample = sample_from_material(&definition_digest, &previous, changed_vcpu);
    let changed_cursor_sample = sample_from_material(&definition_digest, &previous, changed_cursor);
    let recomputed = match compute_single_vm_sample_rolling_fingerprint(
        &definition_digest,
        &previous,
        &baseline_sample,
    ) {
        Ok(fingerprint) => fingerprint,
        Err(error) => panic!("sample digest should recompute: {error}"),
    };

    assert_eq!(baseline_sample.rolling_fingerprint, recomputed);
    assert_ne!(
        baseline_sample.rolling_fingerprint,
        changed_vcpu_sample.rolling_fingerprint
    );
    assert_ne!(
        baseline_sample.rolling_fingerprint,
        changed_cursor_sample.rolling_fingerprint
    );
}

#[test]
fn gate_single_vm_fingerprint_reports_rr_cursor_component() {
    let first = stream_with_cursors(&[rr_cursor(0, 0, 8), rr_cursor(0, 1, 8), rr_cursor(1, 0, 8)]);
    let second = stream_with_cursors(&[rr_cursor(0, 0, 8), rr_cursor(0, 3, 8), rr_cursor(1, 0, 8)]);

    let mismatch = match compare_single_vm_fingerprint_streams(&first, &second, 12_288) {
        Ok(()) => panic!("different RR cursor positions should fail"),
        Err(mismatch) => mismatch,
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Sample {
            difference: SingleVmFingerprintSampleDifference::RoundRobinPositionInQuantum,
            ..
        }
    ));
    assert_eq!(mismatch.sample_index, 1);
    assert_eq!(mismatch.previous_matching_icount, Some(4096));
    assert_eq!(mismatch.first_different_icount, Some(8192));
}

#[test]
fn gate_single_vm_fingerprint_rejects_missing_vcpu_material() {
    let registers = vec![vcpu_register(0, 1), vcpu_register(2, 3)];
    let error = match SingleVmNvcpuFingerprintMaterial::new(
        registers,
        rr_cursor(0, 0, 8),
        digest(4),
        digest(5),
    ) {
        Ok(_) => panic!("non-contiguous vCPU set should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
            reason: "N-vCPU fingerprint material must cover exactly vCPUs 0..N",
        }
    );
}

#[test]
fn gate_single_vm_fingerprint_rejects_cursor_outside_sampled_vcpus() {
    let cursor = rr_cursor(2, 0, 8);
    let error = match SingleVmNvcpuFingerprintMaterial::new(
        vec![vcpu_register(0, 1), vcpu_register(1, 2)],
        cursor,
        digest(4),
        digest(5),
    ) {
        Ok(_) => panic!("cursor outside sampled vCPU set should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
            reason: "round-robin current vCPU must be inside the sampled vCPU set",
        }
    );
}

#[test]
fn gate_single_vm_fingerprint_rejects_stream_missing_launched_vcpu() {
    let scenario = scenario_nvcpu(3, 8);
    let stream = stream(&[1, 2, 3], 9);
    let mut runner = FakeRunner::new(vec![Ok(stream.clone()), Ok(stream)]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("stream with too few vCPUs should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal: SingleVmFingerprintRunOrdinal::First,
            ..
        }
    ));
    assert_eq!(runner.requests.len(), 1);
}

#[test]
fn gate_single_vm_fingerprint_rejects_cursor_quantum_drift_from_launch_contract() {
    let scenario = scenario_nvcpu(2, 8);
    let stream = stream_with_cursors(&[
        rr_cursor(0, 0, 16),
        rr_cursor(0, 1, 16),
        rr_cursor(1, 0, 16),
    ]);
    let mut runner = FakeRunner::new(vec![Ok(stream.clone()), Ok(stream)]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("stream with wrong RR quantum should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal: SingleVmFingerprintRunOrdinal::First,
            ..
        }
    ));
}

#[test]
fn gate_single_vm_fingerprint_builds_material_from_plugin_and_qmp_inputs() {
    let plugin_inputs = plugin_snapshot(2, 1, 3, 8, &[1, 2]);
    let material = match SingleVmNvcpuFingerprintMaterial::from_plugin_introspection_and_qmp(
        qmp_topology(2),
        &plugin_inputs,
        8,
        digest(4),
        digest(5),
    ) {
        Ok(material) => material,
        Err(error) => panic!("plugin and QMP material should validate: {error}"),
    };

    assert_eq!(material.vcpu_registers().len(), 2);
    assert_eq!(material.rr_cursor().current_vcpu(), 1);

    let error = match SingleVmNvcpuFingerprintMaterial::from_plugin_introspection_and_qmp(
        qmp_topology(3),
        &plugin_inputs,
        8,
        digest(4),
        digest(5),
    ) {
        Ok(_) => panic!("plugin material missing QMP-reported vCPU should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
            reason: "N-vCPU fingerprint material vCPU count must match scenario -smp N",
        }
    );
}

#[test]
fn gate_single_vm_fingerprint_rejects_definition_drift() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let mut second = first.clone();
    second.definition_digest = digest(5);
    let mut runner = FakeRunner::new(vec![Ok(first), Ok(second)]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("changed definition digest should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal: SingleVmFingerprintRunOrdinal::Second,
            ..
        }
    ));
}

#[test]
fn gate_single_vm_fingerprint_compares_definition_before_samples() {
    let first = stream(&[1, 2, 3], 9);
    let mut second = stream(&[4, 5, 6], 8);
    second.definition_digest = digest(5);
    let mismatch = match compare_single_vm_fingerprint_streams(&first, &second, 12_288) {
        Ok(()) => panic!("definition drift should fail"),
        Err(mismatch) => mismatch,
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Definition { .. }
    ));
    assert_eq!(mismatch.sample_index, 0);
    assert_eq!(mismatch.previous_matching_icount, None);
    assert_eq!(mismatch.first_different_icount, None);
}

#[test]
fn gate_single_vm_fingerprint_rejects_invalid_streams() {
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), Vec::new(), 12_288, digest(9), 12_288),
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include at least one sample",
        })
    );
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(0, 4096, 1)], 4096, vec![9], 4096),
        Err(SingleVmFingerprintGateError::InvalidDigestLength {
            field: "final_fingerprint",
            len: 1,
        })
    );
    assert!(matches!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(1, 4096, 1)], 4096, digest(9), 4096,),
        Err(SingleVmFingerprintGateError::InvalidStream { .. })
    ));
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(0, 4096, 1)], 8192, digest(9), 8192),
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include a sample at the scenario horizon",
        })
    );
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(0, 4096, 1)], 2048, digest(9), 4096),
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "final fingerprint icount must be at or beyond the scenario horizon",
        })
    );
}

#[test]
fn gate_single_vm_fingerprint_rejects_truncated_backend_streams() {
    let scenario = scenario();
    let truncated = SingleVmFingerprintStream {
        definition_digest: digest(1),
        samples: vec![sample(0, 4096, 1), sample(1, 8192, 2)],
        final_icount: 12_288,
        final_fingerprint: digest(9),
    };
    let mut runner = FakeRunner::new(vec![Ok(truncated.clone()), Ok(truncated)]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("streams missing the horizon sample should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal: SingleVmFingerprintRunOrdinal::First,
            ..
        }
    ));
    assert_eq!(runner.requests.len(), 1);
}

#[test]
fn gate_single_vm_fingerprint_reports_final_icount_mismatch() {
    let first = stream(&[1, 2, 3], 9);
    let mut second = stream(&[1, 2, 3], 9);
    second.final_icount = 16_384;

    let mismatch = match compare_single_vm_fingerprint_streams(&first, &second, 12_288) {
        Ok(()) => panic!("different final icounts should fail"),
        Err(mismatch) => mismatch,
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Final { .. }
    ));
    assert_eq!(mismatch.sample_index, 3);
    assert_eq!(mismatch.previous_matching_icount, Some(8192));
    assert_eq!(mismatch.first_different_icount, Some(12_288));
}

#[test]
fn gate_single_vm_fingerprint_surfaces_backend_failure_without_extra_runs() {
    let scenario = scenario();
    let mut runner = FakeRunner::new(vec![
        Ok(stream(&[1, 2, 3], 9)),
        Err(SingleVmFingerprintRunError::new("planned backend failure")),
        Ok(stream(&[9, 9, 9], 9)),
    ]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("backend failure should stop the gate"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::RunFailed {
            ordinal: SingleVmFingerprintRunOrdinal::Second,
            ..
        }
    ));
    assert_eq!(runner.requests.len(), 2);
    assert!(runner.bisection_requests.is_empty());
}

#[test]
fn gate_single_vm_fingerprint_requires_bisection_on_mismatch() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mut runner = FakeRunner::with_bisections(
        vec![Ok(first.clone()), Ok(second.clone())],
        vec![Err(SingleVmFingerprintBisectionError::new(
            "planned bisection failure",
        ))],
    );

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("missing bisection should fail the gate"),
        Err(error) => error,
    };

    let SingleVmFingerprintGateError::BisectionFailed {
        mismatch,
        first_stream,
        second_stream,
        source,
    } = error
    else {
        panic!("bisection failure should be reported distinctly");
    };

    assert_eq!(mismatch.sample_index, 1);
    assert_eq!(source.message(), "planned bisection failure");
    assert_eq!(*first_stream, first);
    assert_eq!(*second_stream, second);
    assert_eq!(runner.bisection_requests.len(), 1);
}

#[test]
fn gate_single_vm_fingerprint_rejects_misaligned_bisection_report() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mut runner = FakeRunner::with_bisections(
        vec![Ok(first), Ok(second)],
        vec![Ok(bisection_report(2, Some(4096), 8192, 6144, 6145))],
    );

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("misaligned bisection report should fail the gate"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        SingleVmFingerprintGateError::InvalidBisectionReport {
            reason: "bisection sample index must match the first stream mismatch",
        }
    );
}

#[test]
fn gate_single_vm_fingerprint_rejects_direct_partial_dump_report() {
    let scenario = scenario();
    let report_scenario = scenario_nvcpu(1, 8);
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let report = SingleVmFingerprintBisectionReport::new(
        1,
        Some(4096),
        8192,
        6144,
        6145,
        &report_scenario,
        partial_divergence_state_dump(6145),
    )
    .unwrap_or_else(|error| panic!("partial test report should validate internally: {error}"));
    let mut runner = FakeRunner::with_bisections(vec![Ok(first), Ok(second)], vec![Ok(report)]);

    let error = run_single_vm_fingerprint_gate(&mut runner, &scenario)
        .expect_err("the final gate must reject a topology-short dump from a custom runner");

    assert_eq!(
        error,
        SingleVmFingerprintGateError::InvalidBisectionReport {
            reason: "bisection state dump must match the scenario definition, inputs, and vCPU topology",
        }
    );
}

#[derive(Debug)]
struct FakeRunner {
    streams: VecDeque<Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>>,
    bisections:
        VecDeque<Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError>>,
    requests: Vec<SingleVmFingerprintRunRequest>,
    bisection_requests: Vec<SingleVmFingerprintBisectionRequest>,
}

impl FakeRunner {
    fn new(streams: Vec<Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>>) -> Self {
        Self::with_bisections(streams, Vec::new())
    }

    fn with_bisections(
        streams: Vec<Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>>,
        bisections: Vec<
            Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError>,
        >,
    ) -> Self {
        Self {
            streams: streams.into(),
            bisections: bisections.into(),
            requests: Vec::new(),
            bisection_requests: Vec::new(),
        }
    }
}

impl SingleVmFingerprintRunner for FakeRunner {
    fn run_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, SingleVmFingerprintRunError> {
        self.requests.push(request.clone());
        match self.streams.pop_front() {
            Some(result) => result,
            None => Err(SingleVmFingerprintRunError::new("missing planned stream")),
        }
    }

    fn bisect_single_vm_fingerprint_mismatch(
        &mut self,
        request: &SingleVmFingerprintBisectionRequest,
    ) -> Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError> {
        self.bisection_requests.push(request.clone());
        match self.bisections.pop_front() {
            Some(result) => result,
            None => Err(SingleVmFingerprintBisectionError::new(
                "missing planned bisection",
            )),
        }
    }
}

#[derive(Debug)]
struct ExactProbeRunner {
    first_different_icount: u64,
    fail_at: Option<u64>,
    genesis_differs: bool,
    unstable_at: Option<u64>,
    truncate_dump_topology: bool,
    probes: Vec<(SingleVmFingerprintRunOrdinal, u64)>,
    dumps: Vec<(SingleVmFingerprintRunOrdinal, u64)>,
}

impl ExactProbeRunner {
    fn new(first_different_icount: u64) -> Self {
        Self {
            first_different_icount,
            fail_at: None,
            genesis_differs: false,
            unstable_at: None,
            truncate_dump_topology: false,
            probes: Vec::new(),
            dumps: Vec::new(),
        }
    }
}

impl SingleVmFingerprintProbeRunner for ExactProbeRunner {
    fn probe_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintProbe, SingleVmFingerprintBisectionError> {
        let prior_observations = self
            .probes
            .iter()
            .filter(|(ordinal, icount)| {
                *ordinal == request.ordinal() && *icount == request.target_icount()
            })
            .count();
        self.probes
            .push((request.ordinal(), request.target_icount()));
        if self.fail_at == Some(request.target_icount()) {
            return Err(SingleVmFingerprintBisectionError::new(
                "injected probe failure",
            ));
        }
        let mut differs = (request.target_icount() == 0 && self.genesis_differs)
            || request.target_icount() >= self.first_different_icount;
        if self.unstable_at == Some(request.target_icount()) && prior_observations > 0 {
            differs = !differs;
        }
        let byte = if !differs || request.ordinal() == SingleVmFingerprintRunOrdinal::First {
            0x51
        } else {
            0x52
        };
        SingleVmFingerprintProbe::new(
            request.ordinal(),
            "node-a",
            request.target_icount(),
            request
                .scenario()
                .fingerprint_definition_digest()
                .try_into()
                .unwrap_or_else(|_| panic!("test definition digest should have fixed width")),
            request.scenario().run_inputs().content_digest(),
            [byte; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
        )
    }

    fn dump_single_vm_fingerprint_state(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintStateDumpProbe, SingleVmFingerprintBisectionError> {
        self.dumps
            .push((request.ordinal(), request.target_icount()));
        let dump = divergence_state_dump(request.target_icount());
        let mut state = match request.ordinal() {
            SingleVmFingerprintRunOrdinal::First => dump.first().clone(),
            SingleVmFingerprintRunOrdinal::Second => dump.second().clone(),
        };
        if self.truncate_dump_topology {
            let device_byte = match request.ordinal() {
                SingleVmFingerprintRunOrdinal::First => 0x40,
                SingleVmFingerprintRunOrdinal::Second => 0x41,
            };
            state = SingleVmFingerprintRunStateDump::new(
                "node-a",
                request.target_icount(),
                vec![
                    SingleVmFingerprintVcpuState::new(0, [0x10, 0x11]).unwrap_or_else(|error| {
                        panic!("truncated vCPU state should validate: {error}")
                    }),
                ],
                Vec::new(),
                [device_byte],
                1,
                vec![canonical_event()],
            )
            .unwrap_or_else(|error| panic!("truncated state dump should validate alone: {error}"));
        }
        Ok(SingleVmFingerprintStateDumpProbe::new(
            request.ordinal(),
            request
                .scenario()
                .fingerprint_definition_digest()
                .try_into()
                .unwrap_or_else(|_| panic!("test definition digest should have fixed width")),
            request.scenario().run_inputs().content_digest(),
            state,
        ))
    }
}

fn scenario() -> SingleVmFingerprintScenario {
    scenario_nvcpu(2, 8)
}

fn scenario_nvcpu(vcpu_count: usize, rr_switch_quantum: u64) -> SingleVmFingerprintScenario {
    let contract = match SingleVmNvcpuFingerprintContract::new(vcpu_count, rr_switch_quantum) {
        Ok(contract) => contract,
        Err(error) => panic!("test N-vCPU contract should be valid: {error}"),
    };
    match SingleVmFingerprintScenario::new_with_nvcpu_contract(
        "contract-a-single-vm",
        digest(1),
        12_288,
        contract,
        SingleVmFingerprintRunInputs::new(
            digest(0x21),
            "console=ttyS0",
            digest(0x22),
            digest(0x23),
            digest(0x24),
        )
        .unwrap_or_else(|error| panic!("test run inputs should be valid: {error}")),
        SingleVmHostProfile::phase1_adversarial(),
    ) {
        Ok(scenario) => scenario,
        Err(error) => panic!("test scenario should be valid: {error}"),
    }
}

fn stream(sample_bytes: &[u8], final_byte: u8) -> SingleVmFingerprintStream {
    let samples = samples_from_bytes(sample_bytes);
    match SingleVmFingerprintStream::new(digest(1), samples, 12_288, digest(final_byte), 12_288) {
        Ok(stream) => stream,
        Err(error) => panic!("test stream should be valid: {error}"),
    }
}

fn stream_with_same_icount_event(event_state_byte: u8) -> SingleVmFingerprintStream {
    let definition_digest = digest(1);
    let mut previous = initial_rolling(&definition_digest);
    let mut samples = Vec::new();
    for (seq, icount, trigger, state_byte) in [
        (0, 4096, SingleVmFingerprintTrigger::Periodic, 0x20),
        (
            1,
            4096,
            SingleVmFingerprintTrigger::Event(SingleVmFingerprintEventBoundary::FrameDelivery),
            event_state_byte,
        ),
        (
            2,
            8192,
            SingleVmFingerprintTrigger::Event(SingleVmFingerprintEventBoundary::HorizonAdvance),
            0x23,
        ),
    ] {
        let material = SingleVmFingerprintSampleMaterial::new(
            seq,
            "node-a",
            icount,
            trigger,
            nvcpu_material_with_register_bytes([0x11, state_byte], rr_cursor(0, 0, 8)),
        )
        .unwrap_or_else(|error| panic!("same-icount material should validate: {error}"));
        let sample = sample_from_material(&definition_digest, &previous, material);
        previous = sample.rolling_fingerprint.clone();
        samples.push(sample);
    }
    SingleVmFingerprintStream::new(definition_digest, samples, 8192, digest(9), 8192)
        .unwrap_or_else(|error| panic!("same-icount stream should validate: {error}"))
}

fn stream_with_cursors(cursors: &[SingleVmRoundRobinCursor]) -> SingleVmFingerprintStream {
    let definition_digest = digest(1);
    let mut previous = initial_rolling(&definition_digest);
    let mut samples = Vec::new();
    for (index, cursor) in cursors.iter().enumerate() {
        let material = material(index as u64, 4096 * (index as u64 + 1), 2, *cursor);
        let sample = sample_from_material(&definition_digest, &previous, material);
        previous = sample.rolling_fingerprint.clone();
        samples.push(sample);
    }
    match SingleVmFingerprintStream::new(digest(1), samples, 12_288, digest(9), 12_288) {
        Ok(stream) => stream,
        Err(error) => panic!("test stream should be valid: {error}"),
    }
}

fn samples_from_bytes(sample_bytes: &[u8]) -> Vec<SingleVmFingerprintSample> {
    let definition_digest = digest(1);
    let mut previous = initial_rolling(&definition_digest);
    let mut samples = Vec::new();
    for (index, byte) in sample_bytes.iter().enumerate() {
        let cursor = rr_cursor((index % 2) as u64, index as u64, 8);
        let material = material(index as u64, 4096 * (index as u64 + 1), *byte, cursor);
        let sample = sample_from_material(&definition_digest, &previous, material);
        previous = sample.rolling_fingerprint.clone();
        samples.push(sample);
    }
    samples
}

fn sample(seq: u64, icount: u64, state_byte: u8) -> SingleVmFingerprintSample {
    let definition_digest = digest(1);
    let previous = initial_rolling(&definition_digest);
    sample_from_material(
        &definition_digest,
        &previous,
        material(seq, icount, state_byte, rr_cursor(0, 0, 8)),
    )
}

fn sample_from_material(
    definition_digest: &[u8],
    previous: &[u8],
    material: SingleVmFingerprintSampleMaterial,
) -> SingleVmFingerprintSample {
    match SingleVmFingerprintSample::from_material(definition_digest, previous, material) {
        Ok(sample) => sample,
        Err(error) => panic!("test sample should be valid: {error}"),
    }
}

fn material(
    seq: u64,
    icount: u64,
    state_byte: u8,
    rr_cursor: SingleVmRoundRobinCursor,
) -> SingleVmFingerprintSampleMaterial {
    sample_material_with_nvcpu(
        seq,
        icount,
        nvcpu_material_with_register_bytes([0x11, state_byte], rr_cursor),
    )
}

fn sample_material_with_nvcpu(
    seq: u64,
    icount: u64,
    nvcpu_fingerprint: SingleVmNvcpuFingerprintMaterial,
) -> SingleVmFingerprintSampleMaterial {
    match SingleVmFingerprintSampleMaterial::new(
        seq,
        "node-a",
        icount,
        SingleVmFingerprintTrigger::Periodic,
        nvcpu_fingerprint,
    ) {
        Ok(material) => material,
        Err(error) => panic!("test material should be valid: {error}"),
    }
}

fn nvcpu_material_with_register_bytes(
    bytes: [u8; 2],
    rr_cursor: SingleVmRoundRobinCursor,
) -> SingleVmNvcpuFingerprintMaterial {
    match SingleVmNvcpuFingerprintMaterial::new(
        vec![vcpu_register(0, bytes[0]), vcpu_register(1, bytes[1])],
        rr_cursor,
        digest(0xa1),
        digest(0xd1),
    ) {
        Ok(material) => material,
        Err(error) => panic!("test N-vCPU material should be valid: {error}"),
    }
}

fn vcpu_register(vcpu_id: u64, byte: u8) -> SingleVmVcpuRegisterDigest {
    match SingleVmVcpuRegisterDigest::new(vcpu_id, digest(byte), 64, 100 + vcpu_id) {
        Ok(register) => register,
        Err(error) => panic!("test vCPU register should be valid: {error}"),
    }
}

fn rr_cursor(
    current_vcpu: u64,
    position_in_quantum: u64,
    rr_switch_quantum: u64,
) -> SingleVmRoundRobinCursor {
    match SingleVmRoundRobinCursor::new(current_vcpu, position_in_quantum, rr_switch_quantum, 3) {
        Ok(cursor) => cursor,
        Err(error) => panic!("test RR cursor should be valid: {error}"),
    }
}

fn qmp_topology(vcpu_count: usize) -> SingleVmQmpVcpuTopology {
    match SingleVmQmpVcpuTopology::new(vcpu_count) {
        Ok(topology) => topology,
        Err(error) => panic!("test QMP topology should be valid: {error}"),
    }
}

fn plugin_snapshot(
    vcpu_count: u32,
    current_vcpu: u64,
    position_in_quantum: u64,
    rr_switch_quantum: u64,
    digest_bytes: &[u8],
) -> PluginNvcpuFingerprintSnapshot {
    let registers = digest_bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| plugin_register(index as u32, *byte))
        .collect::<Vec<_>>();
    let cursor = match PluginRoundRobinCursorSnapshot::new(
        current_vcpu,
        position_in_quantum,
        rr_switch_quantum,
        vcpu_count,
    ) {
        Ok(cursor) => cursor,
        Err(error) => panic!("test plugin cursor snapshot should be valid: {error}"),
    };
    match PluginNvcpuFingerprintSnapshot::new(registers, cursor) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("test plugin snapshot should be valid: {error}"),
    }
}

fn plugin_register(vcpu_id: u32, byte: u8) -> PluginVcpuRegisterSnapshot {
    match PluginVcpuRegisterSnapshot::new(vcpu_id, [byte; 32], 64, 100 + u64::from(vcpu_id)) {
        Ok(register) => register,
        Err(error) => panic!("test plugin register snapshot should be valid: {error}"),
    }
}

fn initial_rolling(definition_digest: &[u8]) -> Vec<u8> {
    match initial_single_vm_rolling_fingerprint(definition_digest) {
        Ok(fingerprint) => fingerprint,
        Err(error) => panic!("test initial rolling fingerprint should be valid: {error}"),
    }
}

fn bisection_report(
    sample_index: usize,
    previous_matching_icount: Option<u64>,
    first_different_sample_icount: u64,
    last_matching_icount: u64,
    first_different_icount: u64,
) -> SingleVmFingerprintBisectionReport {
    let scenario = scenario();
    match SingleVmFingerprintBisectionReport::new(
        sample_index,
        previous_matching_icount,
        first_different_sample_icount,
        last_matching_icount,
        first_different_icount,
        &scenario,
        divergence_state_dump(first_different_icount),
    ) {
        Ok(report) => report,
        Err(error) => panic!("test bisection report should be valid: {error}"),
    }
}

fn divergence_state_dump(icount: u64) -> SingleVmFingerprintDivergenceStateDump {
    let first = SingleVmFingerprintRunStateDump::new(
        "node-a",
        icount,
        vec![
            SingleVmFingerprintVcpuState::new(0, [0x10, 0x11])
                .unwrap_or_else(|error| panic!("first vCPU 0 state should validate: {error}")),
            SingleVmFingerprintVcpuState::new(1, [0x20, 0x21])
                .unwrap_or_else(|error| panic!("first vCPU 1 state should validate: {error}")),
        ],
        Vec::new(),
        [0x40, 0x41],
        1,
        vec![canonical_event()],
    )
    .unwrap_or_else(|error| panic!("first state dump should validate: {error}"));
    let second = SingleVmFingerprintRunStateDump::new(
        "node-a",
        icount,
        vec![
            SingleVmFingerprintVcpuState::new(0, [0x10, 0x11])
                .unwrap_or_else(|error| panic!("second vCPU 0 state should validate: {error}")),
            SingleVmFingerprintVcpuState::new(1, [0x20, 0xff])
                .unwrap_or_else(|error| panic!("second vCPU 1 state should validate: {error}")),
        ],
        Vec::new(),
        [0x40, 0x41],
        1,
        vec![canonical_event()],
    )
    .unwrap_or_else(|error| panic!("second state dump should validate: {error}"));
    SingleVmFingerprintDivergenceStateDump::new(first, second)
        .unwrap_or_else(|error| panic!("both-sides state dump should validate: {error}"))
}

fn partial_divergence_state_dump(icount: u64) -> SingleVmFingerprintDivergenceStateDump {
    let side = |register_byte| {
        SingleVmFingerprintRunStateDump::new(
            "node-a",
            icount,
            vec![
                SingleVmFingerprintVcpuState::new(0, [register_byte])
                    .unwrap_or_else(|error| panic!("partial vCPU state should validate: {error}")),
            ],
            Vec::new(),
            [0x40],
            1,
            vec![canonical_event()],
        )
        .unwrap_or_else(|error| panic!("partial run dump should validate alone: {error}"))
    };
    SingleVmFingerprintDivergenceStateDump::new(side(0x10), side(0x11))
        .unwrap_or_else(|error| panic!("partial dump pair should validate internally: {error}"))
}

fn canonical_event() -> SingleVmFingerprintCanonicalEvent {
    let mut log = EventLog::new();
    let append = log
        .append_evaluation_boundary(
            VirtualTime { ticks: 0 },
            SchedulerEvaluationBoundaryKind::Quantum,
        )
        .unwrap_or_else(|error| panic!("test causal event should append: {error}"));
    let projection = event_log_causal_projection(&append.entries);
    SingleVmFingerprintCanonicalEvent::from_causal_projection_entry(&projection.entries()[0])
        .unwrap_or_else(|error| panic!("test canonical event should validate: {error}"))
}

fn digest(byte: u8) -> Vec<u8> {
    vec![byte; SINGLE_VM_FINGERPRINT_DIGEST_BYTES]
}
