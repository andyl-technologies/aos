//! Focused contracts for production-flight evidence and comparison.

#![cfg(test)]

use super::*;
use crucible_device::block::BlockTransportRequestIds;
use crucible_engine::{ContentHash, MarkerId};
use std::sync::Arc;

#[test]
fn preemption_after_adjacent_sample_uses_the_next_retirement() {
    let calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_000_001,
        raw_icount: 40_000,
    };

    assert_eq!(
        align_preemption_tick(calibration, 3_000_000, 4_000_000)
            .expect("the next retirement is inside the RUN"),
        3_000_001
    );
    assert!(align_preemption_tick(calibration, 4_000_000, 4_000_000).is_err());
}

#[test]
fn preemption_alignment_rejects_invalid_calibration_and_overflow() {
    let raw_ahead = QemuLogicalTimeCalibration {
        logical_icount: 0,
        raw_icount: 1,
    };
    let raw_overflow = QemuLogicalTimeCalibration {
        logical_icount: u64::MAX,
        raw_icount: u64::MAX,
    };
    let raw_origin = QemuLogicalTimeCalibration {
        logical_icount: 0,
        raw_icount: 0,
    };
    let offset_one = QemuLogicalTimeCalibration {
        logical_icount: 501,
        raw_icount: 10,
    };

    assert!(align_preemption_tick(raw_ahead, 1_000, 2_000).is_err());
    assert!(align_preemption_tick(raw_overflow, 1_000, 2_000).is_err());
    assert!(align_preemption_tick(raw_origin, u64::MAX, u64::MAX).is_err());
    assert!(align_preemption_tick(offset_one, 0, 2_000).is_err());
}

#[test]
fn block_recovery_selector_accepts_only_the_documented_value() {
    assert!(
        !parse_block_recovery_only(None).expect("an absent selector should run the full flight")
    );
    assert!(
        parse_block_recovery_only(Some(std::ffi::OsStr::new("1")))
            .expect("the documented selector should run the focused flight")
    );

    let error = parse_block_recovery_only(Some(std::ffi::OsStr::new("true")))
        .expect_err("an undocumented selector value must fail closed");
    assert!(error.to_string().contains("must be unset or exactly 1"));
}

fn runtime_trace(target_ps: i64) -> String {
    format!(
        "crucible_sim_determinism_idle phase=request seq=1 raw=159999 virtual_ps=7999950 target_tick=8000000 deadline_ps=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n\
             crucible_sim_determinism_idle phase=complete seq=2 raw=159999 virtual_ps=8000000 target_tick=8000000 deadline_ps=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n\
             crucible_sim_determinism_idle phase=request seq=3 raw=160000 virtual_ps=8000000 target_tick={target_ps} deadline_ps=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n\
             crucible_sim_determinism_idle phase=complete seq=4 raw=160000 virtual_ps={target_ps} target_tick={target_ps} deadline_ps=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n"
    )
}

fn runtime_diagnostics(trace: String) -> RuntimeDeterminismDiagnostics {
    RuntimeDeterminismDiagnostics {
        baseline: RuntimeDeterminismBaseline {
            calibration: Ok(QemuLogicalTimeCalibration {
                logical_icount: 8_000_000,
                raw_icount: 160_000,
            }),
            idle_state: Err(Arc::new(
                crucible_qemu_host::QemuNodeError::CoverageEventLogRequired,
            )),
            timer_witness: Err(Arc::new(
                crucible_qemu_host::QemuNodeError::CoverageEventLogRequired,
            )),
            rr_current_vcpu: 0,
            rr_position_in_quantum: 7,
        },
        trace: runtime_trace::summarize_fixture(
            &mut std::io::Cursor::new(trace),
            160_000,
            8_000_000,
        )
        .expect("test runtime trace should validate"),
    }
}

#[test]
fn final_boundary_preserves_the_same_calibration_failure_after_baseline_disposal() {
    let mut diagnostics = runtime_diagnostics(runtime_trace(9_000_000));
    let source = Arc::new(crucible_qemu_host::QemuNodeError::CoverageEventLogRequired);
    let lifetime = Arc::downgrade(&source);
    diagnostics.baseline.calibration = Err(source);

    let failure = final_busy_raw_boundary(&diagnostics.baseline).unwrap_err();
    let NativeObservationError::Node(source) = &failure else {
        panic!("the original calibration failure must remain typed");
    };
    assert!(std::ptr::eq(Arc::as_ptr(source), lifetime.as_ptr()));
    let retained = std::error::Error::source(&failure)
        .unwrap()
        .downcast_ref::<Arc<crucible_qemu_host::QemuNodeError>>()
        .unwrap();
    assert!(Arc::ptr_eq(retained, source));
    assert!(std::ptr::eq(retained.as_ref(), lifetime.as_ptr()));

    drop(diagnostics);

    assert!(lifetime.upgrade().is_some());

    drop(failure);

    assert!(lifetime.upgrade().is_none());
}

#[test]
fn final_boundary_rejects_an_incoherent_logical_coordinate() {
    let mut diagnostics = runtime_diagnostics(runtime_trace(9_000_000));
    assert_eq!(
        final_busy_raw_boundary(&diagnostics.baseline).unwrap(),
        160_000
    );
    diagnostics
        .baseline
        .calibration
        .as_mut()
        .unwrap()
        .logical_icount -= 1;

    let failure = final_busy_raw_boundary(&diagnostics.baseline).unwrap_err();

    assert!(matches!(failure, NativeObservationError::Assertion(_)));
    assert!(
        failure
            .to_string()
            .contains("boundary_logical_picoseconds=7999999 expected=8000000")
    );
}

fn boundary(target: u64, rr_current_vcpu: u32, rr_position_in_quantum: u64) -> BoundaryEvidence {
    let mut sample = FingerprintSample {
        sample_icount: target,
        vcpu_count: 4,
        rr_current_vcpu,
        rr_position_in_quantum,
        rr_switch_quantum: RR_SWITCH_QUANTUM,
        ..FingerprintSample::default()
    };
    sample.vcpus[usize::try_from(rr_current_vcpu).expect("test vCPU fits usize")].register_digest
        [0] = target.to_le_bytes()[0];
    sample.device_state_digest[0] = target.to_le_bytes()[0];

    BoundaryEvidence {
        target,
        outcome: AdvanceOutcome::ReachedHorizon,
        fingerprint: ExecutionFingerprint {
            hash: ContentHash::from_bytes(&target.to_be_bytes()),
        },
        sample,
        calibration: QemuLogicalTimeCalibration {
            logical_icount: target,
            raw_icount: target / FLIGHT_TICKS_PER_INSTRUCTION,
        },
    }
}

fn boundaries_with_fractional_phase(
    lower: BoundaryEvidence,
    upper: BoundaryEvidence,
) -> Vec<BoundaryEvidence> {
    let mut fractional = lower.clone();
    fractional.target = FRACTIONAL_PHASE_LOWER_TARGET;
    fractional.sample.sample_icount = FRACTIONAL_PHASE_LOWER_TARGET;
    fractional.sample.device_state_digest[0] = FRACTIONAL_PHASE_LOWER_TARGET.to_le_bytes()[0];
    fractional.calibration.logical_icount = FRACTIONAL_PHASE_LOWER_TARGET;
    fractional.fingerprint = ExecutionFingerprint {
        hash: ContentHash::from_bytes(&FRACTIONAL_PHASE_LOWER_TARGET.to_be_bytes()),
    };

    vec![fractional, lower, upper]
}

fn idle_evidence(timer_generation: u64) -> IdleEvidence {
    let fingerprint = ExecutionFingerprint {
        hash: ContentHash::from_bytes(b"idle-evidence"),
    };

    IdleEvidence {
        setup_marker_icount: 1,
        halted_at: 2,
        deadline: 3,
        halted_fingerprint: fingerprint.clone(),
        halted_sample: FingerprintSample::default(),
        wake_outcome: AdvanceOutcome::ReachedHorizon,
        wake_fingerprint: fingerprint,
        wake_sample: FingerprintSample::default(),
        timer_fire: NativeFlightTimerObservation {
            generation: timer_generation,
            armed_deadline_ps: 4_000,
            armed_deadline_tick: 4_000,
            retirement_step_ps: 50,
            armed_raw_icount: 6,
            fired_expire_ps: 4_000,
            fired_virtual_ps: 4_000,
            fired_raw_icount: 6,
            published_wake_tick: 4_000,
            post_wake_tick: 4_000,
            completed: 1,
            reserved: 0,
        },
        on_demand_acknowledgements: 2,
    }
}

#[test]
fn idle_comparator_ignores_only_process_local_timer_generation() {
    let reference = idle_evidence(7);
    let mut candidate = idle_evidence(11);

    assert!(idle_evidence_matches_across_runs(&reference, &candidate));

    candidate.timer_fire.fired_raw_icount += 1;
    assert!(!idle_evidence_matches_across_runs(&reference, &candidate));
}

#[test]
fn comparator_reports_first_differing_boundary_component() {
    let reference = vec![boundary(2_000_001, 0, 47), boundary(2_000_051, 0, 48)];
    let mut candidate = reference.clone();
    candidate[1].sample.ram_digest[7] = 1;

    let error = compare_boundaries("negative", &reference, &candidate)
        .expect_err("changed RAM digest must be reported");
    assert!(matches!(error, NativeObservationError::Assertion(_)));
    assert_eq!(
        error.to_string(),
        "negative: boundary 1 window (2000001,2000051]: ram_digest differs"
    );
}

#[test]
fn runtime_comparator_accepts_identical_post_boundary_sequences() {
    let reference = runtime_diagnostics(runtime_trace(9_000_000));
    let candidate = runtime_diagnostics(runtime_trace(9_000_000));

    let report = compare_runtime_determinism_diagnostics([
        ("reference", &reference),
        ("hostile", &candidate),
    ]);

    assert!(report.contains("post_8m_native_sequences_identical=true rows=2"));
}

#[test]
fn runtime_comparator_reports_the_first_post_boundary_tuple() {
    let reference = runtime_diagnostics(runtime_trace(9_000_000));
    let hostile = runtime_diagnostics(runtime_trace(9_000_001));
    let report =
        compare_runtime_determinism_diagnostics([("reference", &reference), ("hostile", &hostile)]);

    assert!(report.contains("first_split=reference/hostile index=0"));
    assert!(report.contains("preceding=[]"));
    assert!(report.contains("differing=("));
    assert!(report.contains("target_tick=9000000"));
    assert!(report.contains("target_tick=9000001"));
}

#[test]
fn runtime_stream_rejects_empty_post_boundary_trace() {
    let trace = runtime_trace(9_000_000).replace("raw=160000", "raw=159999");
    let error =
        runtime_trace::summarize_fixture(&mut std::io::Cursor::new(trace), 160_000, 8_000_000)
            .expect_err("an empty post-boundary suffix must fail closed");

    assert!(
        error
            .to_string()
            .contains("post-8M native runtime trace is empty")
    );
}

#[test]
fn runtime_stream_excludes_same_raw_count_before_eight_million_picoseconds() {
    let trace = runtime_trace(9_000_000).replace("raw=159999", "raw=160000");
    let summary =
        runtime_trace::summarize_fixture(&mut std::io::Cursor::new(trace), 160_000, 8_000_000)
            .expect("runtime trace should validate");

    assert_eq!(summary.post_boundary_rows, 3);
    assert_eq!(summary.prefix[0].sequence(), 2);
}

#[test]
fn runtime_stream_rejects_malformed_or_unbounded_rows() {
    let malformed = runtime_trace(9_000_000).replace("seq=3", "seq=7");
    let error =
        runtime_trace::summarize_fixture(&mut std::io::Cursor::new(malformed), 160_000, 8_000_000)
            .expect_err("noncontiguous sequence must fail closed");
    assert!(error.to_string().contains("sequence 7 did not follow 2"));

    let oversized = format!("{}\n", "x".repeat(4096));
    let error =
        runtime_trace::summarize_fixture(&mut std::io::Cursor::new(oversized), 160_000, 8_000_000)
            .expect_err("oversized row must fail closed");
    assert!(
        error
            .to_string()
            .contains("row exceeded its fixed byte ceiling")
    );
}

#[test]
fn recovery_preserves_unauthenticated_request_identity() {
    let transition = block_recovery_hot_fork::recovery_transition();

    assert_eq!(
        transition.request_ids,
        BlockTransportRequestIds::PreserveMonotonic
    );
    assert_eq!(transition.recovery_nanos, 5_000_000_000);
}

#[test]
fn adjacent_samples_prove_one_instruction_localization() {
    let boundaries = boundaries_with_fractional_phase(
        boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47),
        boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48),
    );

    let evidence = instruction_exact_evidence(&boundaries)
        .expect("adjacent exact samples must produce localization evidence");
    assert_eq!(evidence.lower_target, 2_000_001);
    assert_eq!(evidence.upper_target, 2_000_051);
    assert_eq!(evidence.lower_rr_vcpu, evidence.upper_rr_vcpu);
    assert_eq!(evidence.lower_rr_position + 1, evidence.upper_rr_position);
    assert_eq!(
        evidence.first_differing_state_component,
        "device_state_digest"
    );
    assert!(
        evidence
            .changed_components
            .contains(&String::from("sample_icount"))
    );
    assert!(
        evidence
            .changed_components
            .contains(&String::from("vcpu[0].register_digest"))
    );
    assert_eq!(
        evidence.owning_vcpu_state_projection,
        "vcpu[0].register_digest"
    );
}

#[test]
fn fractional_phase_rejects_retired_state_change() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47);
    let upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48);
    let mut boundaries = boundaries_with_fractional_phase(lower, upper);
    boundaries[1].sample.rr_position_in_quantum += 1;

    let error = instruction_exact_evidence(&boundaries)
        .expect_err("one picosecond must not retire an instruction");
    assert!(matches!(error, NativeObservationError::Assertion(_)));
    assert!(
        error
            .to_string()
            .contains("fractional-phase sample changed retired state")
    );
}

#[test]
fn fractional_phase_requires_a_timer_projection_change() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47);
    let upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48);
    let mut boundaries = boundaries_with_fractional_phase(lower, upper);
    let phase_device_digest = boundaries[0].sample.device_state_digest;
    boundaries[1].sample.device_state_digest = phase_device_digest;

    let error = instruction_exact_evidence(&boundaries)
        .expect_err("one picosecond must advance the timer projection");
    assert!(error.to_string().contains("omitted timer projection"));
}

#[test]
fn adjacent_samples_accept_a_terminal_rr_handoff() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, RR_SWITCH_QUANTUM - 1);
    let mut upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 1, 0);
    upper.sample.vcpus[0].register_digest[0] = INSTRUCTION_EXACT_UPPER_TARGET.to_le_bytes()[0];
    upper.sample.vcpus[1].register_digest = [0; 32];
    let boundaries = boundaries_with_fractional_phase(lower, upper);

    let evidence = instruction_exact_evidence(&boundaries)
        .expect("the terminal instruction must advance to the next RR owner");
    assert_eq!(evidence.lower_rr_vcpu, 0);
    assert_eq!(evidence.upper_rr_vcpu, 1);
    assert_eq!(evidence.lower_rr_position, RR_SWITCH_QUANTUM - 1);
    assert_eq!(evidence.upper_rr_position, 0);
}

#[test]
fn adjacent_samples_reject_a_nonadvancing_rr_cursor() {
    let boundaries = boundaries_with_fractional_phase(
        boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47),
        boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 47),
    );

    let error = instruction_exact_evidence(&boundaries)
        .expect_err("an unchanged RR cursor cannot certify one retired instruction");
    assert!(error.to_string().contains("one exact RR successor"));
}

#[test]
fn adjacent_samples_reject_the_wrong_terminal_owner() {
    let boundaries = boundaries_with_fractional_phase(
        boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, RR_SWITCH_QUANTUM - 1),
        boundary(INSTRUCTION_EXACT_UPPER_TARGET, 2, 0),
    );

    let error = instruction_exact_evidence(&boundaries)
        .expect_err("a terminal handoff that skips the next owner must fail");
    assert!(error.to_string().contains("one exact RR successor"));
}

#[test]
fn adjacent_samples_reject_a_changed_quantum() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47);
    let mut upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48);
    upper.sample.rr_switch_quantum += 1;

    let error = instruction_exact_evidence(&boundaries_with_fractional_phase(lower, upper))
        .expect_err("a changed RR quantum cannot certify one instruction");
    assert!(error.to_string().contains("one exact RR successor"));
}

#[test]
fn adjacent_samples_reject_changed_ram_shape() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47);
    let mut upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48);
    upper.sample.ram_bytes += 1;

    let error = instruction_exact_evidence(&boundaries_with_fractional_phase(lower, upper))
        .expect_err("a changed RAM shape must not certify one instruction");
    assert!(
        error
            .to_string()
            .contains("changed invariant fingerprint shape: [")
    );
    assert!(error.to_string().contains("ram_bytes"));
}

#[test]
fn adjacent_samples_allow_a_single_instruction_ram_write() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47);
    let mut upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48);
    upper.sample.ram_digest[0] = 1;

    let evidence = instruction_exact_evidence(&boundaries_with_fractional_phase(lower, upper))
        .expect("a retired instruction may write RAM");
    assert!(
        evidence
            .changed_components
            .contains(&String::from("ram_digest"))
    );
}

#[test]
fn readiness_marker_authenticates_the_exact_pre_request_event() {
    let marker_icount = Icount { retired: 73 };
    let event = ObservableEvent::guest_marker(
        marker_icount,
        NodeId {
            name: String::from(FLIGHT_NODE_ID),
        },
        MarkerId::from_name(SETUP_COMPLETE_MARKER),
    );

    assert_eq!(
        authenticate_readiness_marker(&[event], Icount { retired: 74 })
            .expect("the exact pre-request marker is authenticated"),
        73
    );
}

#[test]
fn readiness_marker_rejects_unrelated_or_ambiguous_events() {
    let marker = || {
        ObservableEvent::guest_marker(
            Icount { retired: 73 },
            NodeId {
                name: String::from(FLIGHT_NODE_ID),
            },
            MarkerId::from_name(SETUP_COMPLETE_MARKER),
        )
    };
    assert!(authenticate_readiness_marker(&[marker(), marker()], Icount { retired: 74 }).is_err());
    assert!(authenticate_readiness_marker(&[marker()], Icount { retired: 72 }).is_err());
}
