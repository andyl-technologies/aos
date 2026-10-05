//! Refusals and canonical comparison for the Linux ACK experiment.

use super::*;
use crucible::ContentHash;

fn calibration(ps: u64) -> QemuLogicalTimeCalibration {
    QemuLogicalTimeCalibration {
        logical_icount: ps,
        raw_icount: ps / 50,
    }
}

fn observation(target: u64, outcome: AdvanceOutcome) -> StepObservation {
    StepObservation::from_advance_outcome(VirtualTime { ticks: target }, outcome)
}

fn evidence() -> BootProbe {
    let make_boundary = |ps| BoundaryEvidence {
        target: ps,
        outcome: AdvanceOutcome::ReachedHorizon,
        fingerprint: ExecutionFingerprint {
            hash: ContentHash::from_bytes(&ps.to_le_bytes()),
        },
        sample: FingerprintSample {
            sample_icount: ps,
            ..FingerprintSample::default()
        },
        calibration: calibration(ps),
    };
    BootProbe {
        canonical: CanonicalProbe {
            control_returns: GRANTS,
            projected_grants: 0,
            initial: make_boundary(INITIAL_PS),
            final_boundary: make_boundary(FINAL_PS),
            transcript: String::from("original authenticated transcript"),
        },
        elapsed_us: 1,
        diagnostics: TranscriptDiagnostics::new().finish(),
    }
}

#[test]
fn mode_and_segment_are_explicit_and_finite() {
    assert_eq!(mode(None).ok(), Some(false));
    assert_eq!(mode(Some(std::ffi::OsStr::new("1"))).ok(), Some(true));
    for invalid in ["", "0", "true", "baseline"] {
        assert!(mode(Some(std::ffi::OsStr::new(invalid))).is_err());
    }
    assert_eq!(ceiling(1).ok(), Some(18_000_000));
    assert_eq!(ceiling(GRANTS).ok(), Some(FINAL_PS));
    assert!(ceiling(0).is_err());
    assert!(ceiling(GRANTS + 1).is_err());
}

#[test]
fn exact_return_and_proven_idle_projection_keep_distinct_coordinates() {
    let previous = calibration(100);
    let exact = observation(200, AdvanceOutcome::ReachedHorizon);
    let current = calibration(200);
    let idle = QemuNodeIdleState {
        current_icount: Icount { retired: 200 },
        next_deadline: None,
    };
    assert_eq!(
        validate_step(previous, 200, &exact, current, idle).ok(),
        Some(false)
    );

    let parked = observation(
        200,
        AdvanceOutcome::Paused {
            at: Icount { retired: 100 },
        },
    );
    let future = QemuNodeIdleState {
        current_icount: Icount { retired: 100 },
        next_deadline: Some(Icount { retired: 201 }),
    };
    assert_eq!(
        validate_step(previous, 200, &parked, previous, future).ok(),
        Some(true)
    );
    assert_eq!(parked.reached.ticks, 100);
    assert_eq!(previous.logical_icount, 100);
}

#[test]
fn projection_refuses_missing_due_or_foreign_idle_proof() {
    let previous = calibration(100);
    let parked = observation(
        200,
        AdvanceOutcome::Paused {
            at: Icount { retired: 100 },
        },
    );
    for (physical, deadline) in [(100, None), (100, Some(200)), (99, Some(201))] {
        let idle = QemuNodeIdleState {
            current_icount: Icount { retired: physical },
            next_deadline: deadline.map(|retired| Icount { retired }),
        };
        assert!(validate_step(previous, 200, &parked, previous, idle).is_err());
    }
}

#[test]
fn original_physical_return_and_output_refusals_are_preserved() {
    let previous = calibration(100);
    let current = calibration(200);
    let idle = QemuNodeIdleState {
        current_icount: Icount { retired: 200 },
        next_deadline: None,
    };
    let exact = observation(200, AdvanceOutcome::ReachedHorizon);
    let mut wrong_target = exact.clone();
    wrong_target.requested_ceiling.ticks = 201;
    assert!(validate_step(previous, 200, &wrong_target, current, idle).is_err());
    let wrong_raw = QemuLogicalTimeCalibration {
        logical_icount: 200,
        raw_icount: 1,
    };
    assert!(validate_step(previous, 200, &exact, wrong_raw, idle).is_err());
    for reason in [
        BackendPhysicalStop::GuestSelectable,
        BackendPhysicalStop::NetworkOutput,
        BackendPhysicalStop::CampaignMarker,
    ] {
        let mut output = exact.clone();
        output.physical_stop = reason;
        assert!(validate_step(previous, 200, &output, current, idle).is_err());
    }
}

#[test]
fn comparison_ignores_host_duration_but_refuses_canonical_changes() {
    let baseline = evidence();
    let mut candidate = evidence();
    candidate.elapsed_us = u128::MAX;
    assert!(compare(&baseline, &candidate).is_ok());

    candidate.canonical.control_returns += 1;
    assert!(compare(&baseline, &candidate).is_err());
    candidate = evidence();
    candidate.canonical.final_boundary.calibration.raw_icount += 1;
    assert!(compare(&baseline, &candidate).is_err());
    candidate = evidence();
    candidate.canonical.transcript.push('!');
    assert!(compare(&baseline, &candidate).is_err());
    candidate = evidence();
    candidate.canonical.projected_grants = 1;
    assert!(compare(&baseline, &candidate).is_err());
}

#[test]
fn comparison_refusal_identifies_original_field_and_retains_both_values() {
    let baseline = evidence();
    let mut candidate = evidence();
    candidate.canonical.control_returns += 1;
    let error = compare(&baseline, &candidate).expect_err("changed control count");
    let detail = error.to_string();
    assert!(detail.contains("difference=control_returns"));
    assert!(detail.contains("baseline=[control_returns=20000"));
    assert!(detail.contains("candidate=[control_returns=20001"));

    candidate = evidence();
    candidate
        .canonical
        .final_boundary
        .sample
        .rr_position_in_quantum = 1;
    let detail = compare(&baseline, &candidate)
        .expect_err("changed original sample")
        .to_string();
    assert!(detail.contains("boundary 1"));
    assert!(detail.contains("rr_position_in_quantum differs"));
    assert!(detail.contains("rr_position_in_quantum: 0"));
    assert!(detail.contains("rr_position_in_quantum: 1"));

    candidate = evidence();
    candidate.canonical.transcript.push('!');
    let detail = compare(&baseline, &candidate)
        .expect_err("changed original transcript")
        .to_string();
    assert!(detail.contains("difference=transcript_blake3"));
    assert!(detail.contains("transcript_blake3=original authenticated transcript]"));
    assert!(detail.contains("transcript_blake3=original authenticated transcript!]"));
    assert!(!detail.contains("elapsed_us"));
}

#[test]
fn comparison_refusal_stays_within_existing_result_budget() {
    let mut baseline = evidence();
    let maximum_sample = FingerprintSample {
        sample_icount: u64::MAX,
        vcpu_count: u32::MAX,
        rr_current_vcpu: u32::MAX,
        rr_position_in_quantum: u64::MAX,
        rr_switch_quantum: u64::MAX,
        component_failures: u32::MAX,
        ram_bytes: u64::MAX,
        ram_digest: [u8::MAX; 32],
        device_state_bytes: u64::MAX,
        device_state_sections: u64::MAX,
        device_state_digest: [u8::MAX; 32],
        device_state_schema_digest: [u8::MAX; 32],
        vcpus: [crucible_shmem::FingerprintSampleVcpu {
            register_digest: [u8::MAX; 32],
            register_file_bytes: u64::MAX,
            retired_instruction_count: u64::MAX,
        }; 8],
    };
    baseline.canonical.control_returns = u64::MAX;
    baseline.canonical.projected_grants = u64::MAX;
    baseline.canonical.transcript = "x".repeat(65_536);
    for boundary in [
        &mut baseline.canonical.initial,
        &mut baseline.canonical.final_boundary,
    ] {
        boundary.target = u64::MAX;
        boundary.outcome = AdvanceOutcome::Paused {
            at: Icount { retired: u64::MAX },
        };
        boundary.calibration = QemuLogicalTimeCalibration {
            logical_icount: u64::MAX,
            raw_icount: u64::MAX,
        };
        boundary.fingerprint.hash.bytes = [u8::MAX; 32];
        boundary.sample = maximum_sample;
    }
    let mut candidate = BootProbe {
        canonical: CanonicalProbe {
            control_returns: u64::MAX - 1,
            projected_grants: baseline.canonical.projected_grants,
            initial: baseline.canonical.initial.clone(),
            final_boundary: baseline.canonical.final_boundary.clone(),
            transcript: baseline.canonical.transcript.clone(),
        },
        elapsed_us: u128::MAX,
        diagnostics: baseline.diagnostics.clone(),
    };

    baseline.diagnostics.console_event_count = u64::MAX;
    baseline.diagnostics.console_byte_count = u64::MAX;
    candidate.diagnostics = baseline.diagnostics.clone();

    let detail = compare(&baseline, &candidate)
        .expect_err("bounded mismatched count")
        .to_string();
    assert!(detail.len() <= 16 * 1024, "{} bytes", detail.len());
    assert!(!detail.contains(&"x".repeat(65)));

    candidate.canonical.control_returns = baseline.canonical.control_returns;
    assert!(compare(&baseline, &candidate).is_ok());
}

#[test]
fn console_digest_binds_original_owner_coordinate_and_bytes() {
    let make_event = |owner: &str, at, bytes: &[u8]| {
        ObservableEvent::console_output(
            VirtualTime { ticks: at },
            NodeId {
                name: owner.to_owned(),
            },
            bytes,
        )
    };
    let mut original = blake3::Hasher::new();
    let events = [make_event(FLIGHT_NODE_ID, 100, b"kernel boot")];
    assert!(hash_console_events(&mut original, &events, 100).is_ok());
    let mut changed = blake3::Hasher::new();
    let changed_events = [make_event(FLIGHT_NODE_ID, 100, b"other boot")];
    assert!(hash_console_events(&mut changed, &changed_events, 100).is_ok());
    assert_ne!(original.finalize(), changed.finalize());

    for event in [
        make_event("foreign", 100, b"kernel boot"),
        make_event(FLIGHT_NODE_ID, 99, b"kernel boot"),
    ] {
        assert!(hash_console_events(&mut blake3::Hasher::new(), &[event], 100).is_err());
    }
    let marker = ObservableEvent::guest_marker(
        Icount { retired: 100 },
        NodeId {
            name: FLIGHT_NODE_ID.to_owned(),
        },
        crucible::MarkerId::from_name("unexpected"),
    );
    assert!(hash_console_events(&mut blake3::Hasher::new(), &[marker], 100).is_err());
}

fn partition_evidence(raw: [u64; 2], batches: [Vec<ObservableEvent>; 2]) -> BootProbe {
    let mut result = evidence();
    let mut combined = blake3::Hasher::new();
    let mut diagnostics = TranscriptDiagnostics::new();
    for (index, events) in batches.iter().enumerate() {
        let at = 100 * (index as u64 + 1);
        {
            let mut control = ControlTranscript::new(&mut combined, &mut diagnostics);
            control.update(&at.to_le_bytes());
            control.update(&raw[index].to_le_bytes());
        }
        hash_console_events(&mut combined, events, at).expect("validated console events");
        diagnostics.record_validated_console(events);
    }
    result.canonical.transcript = combined.finalize().to_hex().to_string();
    result.diagnostics = diagnostics.finish();
    result
}

fn console(at: u64, bytes: &[u8]) -> ObservableEvent {
    ObservableEvent::console_output(
        VirtualTime { ticks: at },
        NodeId {
            name: FLIGHT_NODE_ID.to_owned(),
        },
        bytes,
    )
}

#[test]
fn diagnostic_components_distinguish_partition_bytes_and_control_without_accepting_them() {
    let together = partition_evidence([2, 4], [vec![console(100, b"kernel boot")], vec![]]);
    let split = partition_evidence(
        [2, 4],
        [vec![console(100, b"kernel")], vec![console(200, b" boot")]],
    );

    assert_eq!(together.diagnostics.control, split.diagnostics.control);
    assert_eq!(
        together.diagnostics.console_bytes,
        split.diagnostics.console_bytes
    );
    assert_eq!(
        together.diagnostics.console_byte_count,
        split.diagnostics.console_byte_count
    );
    assert_ne!(
        together.diagnostics.framed_console,
        split.diagnostics.framed_console
    );
    assert_eq!(together.diagnostics.console_event_count, 1);
    assert_eq!(split.diagnostics.console_event_count, 2);
    assert!(compare(&together, &split).is_err());

    let changed_bytes = partition_evidence([2, 4], [vec![console(100, b"kernel Xoot")], vec![]]);
    assert_eq!(
        together.diagnostics.control,
        changed_bytes.diagnostics.control
    );
    assert_ne!(
        together.diagnostics.console_bytes,
        changed_bytes.diagnostics.console_bytes
    );
    assert!(compare(&together, &changed_bytes).is_err());

    let changed_control = partition_evidence([2, 5], [vec![console(100, b"kernel boot")], vec![]]);
    assert_ne!(
        together.diagnostics.control,
        changed_control.diagnostics.control
    );
    assert_eq!(
        together.diagnostics.console_bytes,
        changed_control.diagnostics.console_bytes
    );
    assert!(compare(&together, &changed_control).is_err());

    let detail = compare(&together, &split)
        .expect_err("original combined refusal")
        .to_string();
    assert!(detail.contains("difference=transcript_blake3"));
    assert!(detail.contains("baseline_diagnostics=[control_blake3="));
    assert!(detail.contains("candidate_diagnostics=[control_blake3="));
    assert!(!detail.contains("kernel"));
}

#[test]
fn diagnostics_cannot_change_original_success_and_forward_exact_control_bytes() {
    let baseline = evidence();
    let mut candidate = evidence();
    candidate.diagnostics.control = blake3::hash(b"different diagnostic");
    assert!(compare(&baseline, &candidate).is_ok());

    let mut original = blake3::Hasher::new();
    let mut forwarded = blake3::Hasher::new();
    let mut diagnostics = TranscriptDiagnostics::new();
    for bytes in [&b"original"[..], &100_u64.to_le_bytes()[..], &[][..]] {
        original.update(bytes);
        ControlTranscript::new(&mut forwarded, &mut diagnostics).update(bytes);
    }
    assert_eq!(original.finalize(), forwarded.finalize());
    assert_eq!(original.finalize(), diagnostics.finish().control);
}
