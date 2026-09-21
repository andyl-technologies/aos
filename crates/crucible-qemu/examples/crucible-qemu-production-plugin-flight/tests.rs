//! Focused contracts for production-flight evidence and comparison.

use super::*;
use crucible::{ContentHash, MarkerId};
use crucible_device::block::BlockTransportRequestIds;

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

fn runtime_trace(target_ns: i64) -> String {
    format!(
        "crucible_sim_determinism_idle phase=request seq=1 raw=7999999 virtual_ns=7999999 target_ns=8000000 deadline_ns=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n\
             crucible_sim_determinism_idle phase=complete seq=2 raw=7999999 virtual_ns=8000000 target_ns=8000000 deadline_ns=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n\
             crucible_sim_determinism_idle phase=request seq=3 raw=8000000 virtual_ns=8000000 target_ns={target_ns} deadline_ns=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n\
             crucible_sim_determinism_idle phase=complete seq=4 raw=8000000 virtual_ns={target_ns} target_ns={target_ns} deadline_ns=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n"
    )
}

fn runtime_diagnostics(trace: String) -> RuntimeDeterminismDiagnostics {
    RuntimeDeterminismDiagnostics {
        baseline: RuntimeDeterminismBaseline {
            calibration: Err(String::from("test calibration")),
            idle_state: Err(String::from("test idle state")),
            timer_witness: Err(String::from("test timer witness")),
            rr_current_vcpu: 0,
            rr_position_in_quantum: 7,
        },
        trace,
    }
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
    }
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
        timer_fire: VirtualTimerFireEvidence {
            generation: timer_generation,
            armed_deadline_ns: 4,
            armed_deadline_logical_icount: 5,
            icount_scale_ns: 1,
            armed_raw_icount: 6,
            fired_expire_ns: 4,
            fired_virtual_ns: 4,
            fired_raw_icount: 6,
            published_wake_logical_icount: 5,
            post_wake_logical_icount: 5,
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
    let reference = vec![boundary(2_000_000, 0, 47), boundary(2_000_001, 0, 48)];
    let mut candidate = reference.clone();
    candidate[1].sample.ram_digest[7] = 1;

    let error = compare_boundaries("negative", &reference, &candidate)
        .expect_err("changed RAM digest must be reported");
    assert_eq!(
        error,
        "negative: boundary 1 window (2000000,2000001]: ram_digest differs"
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
    assert!(report.contains("target_ns: 9000000"));
    assert!(report.contains("target_ns: 9000001"));
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
    let boundaries = vec![
        boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47),
        boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48),
    ];

    let evidence = instruction_exact_evidence(&boundaries)
        .expect("adjacent exact samples must produce localization evidence");
    assert_eq!(evidence.lower_target, 2_000_000);
    assert_eq!(evidence.upper_target, 2_000_001);
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
fn adjacent_samples_accept_a_terminal_rr_handoff() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, RR_SWITCH_QUANTUM - 1);
    let mut upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 1, 0);
    upper.sample.vcpus[0].register_digest[0] = INSTRUCTION_EXACT_UPPER_TARGET.to_le_bytes()[0];
    upper.sample.vcpus[1].register_digest = [0; 32];
    let boundaries = vec![lower, upper];

    let evidence = instruction_exact_evidence(&boundaries)
        .expect("the terminal instruction must advance to the next RR owner");
    assert_eq!(evidence.lower_rr_vcpu, 0);
    assert_eq!(evidence.upper_rr_vcpu, 1);
    assert_eq!(evidence.lower_rr_position, RR_SWITCH_QUANTUM - 1);
    assert_eq!(evidence.upper_rr_position, 0);
}

#[test]
fn adjacent_samples_reject_a_nonadvancing_rr_cursor() {
    let boundaries = vec![
        boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47),
        boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 47),
    ];

    let error = instruction_exact_evidence(&boundaries)
        .expect_err("an unchanged RR cursor cannot certify one retired instruction");
    assert!(error.contains("one exact RR successor"));
}

#[test]
fn adjacent_samples_reject_the_wrong_terminal_owner() {
    let boundaries = vec![
        boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, RR_SWITCH_QUANTUM - 1),
        boundary(INSTRUCTION_EXACT_UPPER_TARGET, 2, 0),
    ];

    let error = instruction_exact_evidence(&boundaries)
        .expect_err("a terminal handoff that skips the next owner must fail");
    assert!(error.contains("one exact RR successor"));
}

#[test]
fn adjacent_samples_reject_a_changed_quantum() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47);
    let mut upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48);
    upper.sample.rr_switch_quantum += 1;

    let error = instruction_exact_evidence(&[lower, upper])
        .expect_err("a changed RR quantum cannot certify one instruction");
    assert!(error.contains("one exact RR successor"));
}

#[test]
fn adjacent_samples_reject_an_unrelated_state_change() {
    let lower = boundary(INSTRUCTION_EXACT_LOWER_TARGET, 0, 47);
    let mut upper = boundary(INSTRUCTION_EXACT_UPPER_TARGET, 0, 48);
    upper.sample.ram_digest[0] = 1;

    let error = instruction_exact_evidence(&[lower, upper])
        .expect_err("an unrelated RAM change must not certify one instruction");
    assert!(error.contains("changed invariant fingerprint shape or RAM state"));
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
        authenticate_readiness_marker(&[event], Icount { retired: 74 }),
        Ok(73)
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
