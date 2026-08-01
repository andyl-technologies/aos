//! Implements `gate:divergence-bisect` over seeded harness artifacts.
#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::sync::{Arc, Barrier};

use crucible_harness::divergence::{
    BisectionWindowErrorKind, DecisionTraceEntry, DivergenceBisectionError,
    DivergenceBisectionReport, DivergenceMemoryRegion, DivergenceRegister, DivergenceSide,
    DivergenceStateDump, bisect_diverging_runs, bisect_diverging_runs_with_segment_replay,
    locate_first_decision_mismatch,
};
use crucible_harness::fingerprint::{
    FingerprintSample, FingerprintSampleTrigger, FingerprintStream,
};
use crucible_harness::replay_oracle::{
    ReplayOracleCheckpointKind, ReplayOracleDivergenceError, ReplayOracleDivergenceInputs,
    ReplayOracleMaterializedCase, ReplayOracleSamplingConfig, ReplayOracleSearchBisectionError,
    ReplayOracleSearchDivergenceMaterialization, ReplayOracleSearchMaterialization,
    check_sampled_search_replay_oracle_with_bisection,
};
use crucible_harness::segment_replay::{
    ReplayCheckpoint, ReplayLogEntry, ReplaySegment, ReplaySegmentOutput,
    replay_checkpoint_segments,
};

const SEEDED_DIVERGENCE_ICOUNT: u64 = 17;

#[test]
fn gate_divergence_bisect_localizes_seeded_fault_to_exact_node_and_icount() {
    let report = seeded_bisection_report();

    assert_eq!(report.sample_index, 1);
    assert_eq!(report.node.as_deref(), Some("node-a"));
    assert_eq!(report.previous_matching_icount, Some(10));
    assert_eq!(report.first_different_sample_icount, 20);
    assert_eq!(report.first_different_icount, SEEDED_DIVERGENCE_ICOUNT);
    assert_eq!(
        report.first_different_state_diff.registers,
        vec![String::from("pc")]
    );
    assert_eq!(
        report.first_different_state_diff.memory_regions,
        vec![String::from("guest-page@0x0000000000001000")]
    );
    assert!(report.first_different_state_diff.canonical_events_differ);

    let Some(last_matching) = report.last_matching_state else {
        panic!("bisection must retain the last matching both-sides dump");
    };
    assert_eq!(last_matching.left.icount, 16);
    assert_eq!(last_matching.right.icount, 16);
    assert_eq!(last_matching.left, last_matching.right);

    assert_eq!(report.first_different_state.left.icount, 17);
    assert_eq!(report.first_different_state.right.icount, 17);
    assert_ne!(
        report.first_different_state.left,
        report.first_different_state.right
    );
}

#[test]
fn gate_divergence_bisect_is_deterministic_for_same_artifacts() {
    let first = seeded_bisection_report();
    let second = seeded_bisection_report();

    assert_eq!(first, second);
}

#[test]
fn gate_divergence_bisect_segment_replay_matches_serial_state_and_log() {
    let checkpoints = replay_checkpoints(DivergenceSide::Left);
    let serial = match replay_checkpoint_segments(&checkpoints, 20, 1, |segment| {
        Ok::<_, Infallible>(replay_segment(DivergenceSide::Left, segment))
    }) {
        Ok(report) => report,
        Err(error) => panic!("serial replay should succeed: {error}"),
    };

    let barrier = Arc::new(Barrier::new(4));
    let parallel = match replay_checkpoint_segments(&checkpoints, 20, 4, {
        let barrier = Arc::clone(&barrier);
        move |segment| {
            barrier.wait();
            Ok::<_, Infallible>(replay_segment(DivergenceSide::Left, segment))
        }
    }) {
        Ok(report) => report,
        Err(error) => panic!("parallel replay should succeed: {error}"),
    };

    assert_eq!(serial.segment_count, 1);
    assert_eq!(parallel.segment_count, 4);
    assert_eq!(parallel.final_state, serial.final_state);
    assert_eq!(parallel.canonical_log, serial.canonical_log);
}

#[test]
fn gate_divergence_bisect_coordinate_is_independent_of_segment_count() {
    let (left_stream, right_stream) = seeded_streams();
    let report = match bisect_diverging_runs_with_segment_replay(
        &left_stream,
        &right_stream,
        &left_decisions(),
        &right_decisions(),
        &replay_checkpoints(DivergenceSide::Left),
        &replay_checkpoints(DivergenceSide::Right),
        &[1, 2, 4],
        |side, segment| Ok::<_, Infallible>(replay_segment(side, segment)),
        state_dump,
    ) {
        Ok(report) => report,
        Err(error) => panic!("segmented bisection should succeed: {error}"),
    };

    assert_eq!(report.segment_counts, [1, 2, 4]);
    assert_eq!(
        report.divergence.first_different_icount,
        SEEDED_DIVERGENCE_ICOUNT
    );
}

#[test]
fn gate_divergence_bisect_reports_first_schedule_decision() {
    let report = seeded_bisection_report();
    let Some(decision) = report.first_different_decision else {
        panic!("seeded divergence must include a first differing decision");
    };

    assert_eq!(decision.index, 2);
    assert_eq!(
        decision.left.as_ref().and_then(|entry| entry.icount),
        Some(SEEDED_DIVERGENCE_ICOUNT)
    );
    assert_eq!(
        decision
            .right
            .as_ref()
            .and_then(|entry| entry.node.as_deref()),
        Some("node-a")
    );
    assert_eq!(
        decision.left.as_ref().map(|entry| entry.summary.as_str()),
        Some("fault disk-delay fired=false")
    );
    assert_eq!(
        decision.right.as_ref().map(|entry| entry.summary.as_str()),
        Some("fault disk-delay fired=true")
    );
}

#[test]
fn gate_divergence_bisect_compares_decisions_by_canonical_bytes() {
    let mut same_canonical = left_decisions();
    same_canonical[2].summary = String::from("same canonical bytes, different wording");
    assert!(
        locate_first_decision_mismatch(&left_decisions(), &same_canonical).is_none(),
        "diagnostic summary wording must not create a schedule mismatch"
    );

    let mut changed_canonical = left_decisions();
    changed_canonical[2].canonical_bytes = b"fault:disk-delay:true".to_vec();
    let Some(mismatch) = locate_first_decision_mismatch(&left_decisions(), &changed_canonical)
    else {
        panic!("changed canonical decision bytes must be localized");
    };
    assert_eq!(mismatch.index, 2);
}

#[test]
fn gate_divergence_bisect_reports_schedule_length_mismatch() {
    let left = left_decisions();
    let mut right = left_decisions();
    right.push(decision(3, "node-a", 21, "extra rng draw", b"rng:extra"));

    let Some(mismatch) = locate_first_decision_mismatch(&left, &right) else {
        panic!("extra right-hand decision must be reported as a mismatch");
    };

    assert_eq!(mismatch.index, 3);
    assert!(mismatch.left.is_none());
    assert_eq!(
        mismatch.right.as_ref().map(|entry| entry.summary.as_str()),
        Some("extra rng draw")
    );
}

#[test]
fn gate_divergence_bisect_handles_first_sample_divergence_at_zero() {
    let left = FingerprintStream {
        definition_digest: vec![0x20],
        samples: vec![sample(0, "node-b", 20, b"left-at-20")],
        final_fingerprint: b"left-final".to_vec(),
    };
    let right = FingerprintStream {
        definition_digest: vec![0x20],
        samples: vec![sample(0, "node-b", 20, b"right-at-20")],
        final_fingerprint: b"right-final".to_vec(),
    };

    let report = match bisect_diverging_runs(
        &left,
        &right,
        &[],
        &[],
        |icount| icount != 0,
        zero_divergence_state_dump,
    ) {
        Ok(report) => report,
        Err(error) => panic!("first-sample divergence should localize to zero: {error}"),
    };

    assert_eq!(report.sample_index, 0);
    assert_eq!(report.node.as_deref(), Some("node-b"));
    assert_eq!(report.previous_matching_icount, None);
    assert_eq!(report.first_different_sample_icount, 20);
    assert_eq!(report.first_different_icount, 0);
    assert!(report.last_matching_state.is_none());
    assert_eq!(report.first_different_state.left.icount, 0);
    assert_eq!(report.first_different_state.right.icount, 0);
}

#[test]
fn gate_divergence_bisect_rejects_invalid_probe_windows() {
    let (left_stream, right_stream) = seeded_streams();
    let low_already_different = bisect_diverging_runs(
        &left_stream,
        &right_stream,
        &left_decisions(),
        &right_decisions(),
        |_| false,
        state_dump,
    );
    assert!(matches!(
        low_already_different,
        Err(DivergenceBisectionError::InvalidWindow(error))
            if error.kind == BisectionWindowErrorKind::LowAlreadyDifferent
    ));

    let high_still_matching = bisect_diverging_runs(
        &left_stream,
        &right_stream,
        &left_decisions(),
        &right_decisions(),
        |_| true,
        state_dump,
    );
    assert!(matches!(
        high_still_matching,
        Err(DivergenceBisectionError::InvalidWindow(error))
            if error.kind == BisectionWindowErrorKind::HighStillMatching
    ));
}

#[test]
fn gate_divergence_bisect_rejects_final_only_fingerprint_mismatch() {
    let (left, _) = seeded_streams();
    let mut right = left.clone();
    right.final_fingerprint = b"different-final".to_vec();

    let result = bisect_diverging_runs(
        &left,
        &right,
        &left_decisions(),
        &left_decisions(),
        |icount| icount < SEEDED_DIVERGENCE_ICOUNT,
        state_dump,
    );

    assert!(matches!(
        result,
        Err(DivergenceBisectionError::FinalFingerprintMismatch)
    ));
}

#[test]
fn gate_divergence_bisect_rejects_malformed_state_dumps() {
    let (left_stream, right_stream) = seeded_streams();
    let result = bisect_diverging_runs(
        &left_stream,
        &right_stream,
        &left_decisions(),
        &right_decisions(),
        |icount| icount < SEEDED_DIVERGENCE_ICOUNT,
        duplicate_register_state_dump,
    );

    assert!(matches!(
        result,
        Err(DivergenceBisectionError::MalformedStateDump {
            side: DivergenceSide::Right,
            field: "register",
            ..
        })
    ));
}

#[test]
fn gate_divergence_bisect_rejects_matching_streams_without_repair() {
    let (left, _) = seeded_streams();
    let result = bisect_diverging_runs(
        &left,
        &left,
        &left_decisions(),
        &left_decisions(),
        |icount| icount < SEEDED_DIVERGENCE_ICOUNT,
        state_dump,
    );

    assert!(matches!(
        result,
        Err(DivergenceBisectionError::MatchingStreams)
    ));
}

#[test]
fn gate_divergence_bisect_localizes_replay_oracle_mismatch() {
    let (fat_stream, thin_stream) = seeded_streams();
    let fat_decisions = left_decisions();
    let thin_decisions = right_decisions();
    let materializations = [ReplayOracleSearchDivergenceMaterialization::new(
        ReplayOracleSearchMaterialization::new(9, replay_oracle_case()),
        ReplayOracleDivergenceInputs {
            fat_stream: &fat_stream,
            thin_stream: &thin_stream,
            fat_decisions: &fat_decisions,
            thin_decisions: &thin_decisions,
        },
    )];
    let config = replay_oracle_sampling_config();
    let error = match check_sampled_search_replay_oracle_with_bisection(
        &materializations,
        &config,
        |_, icount| icount < SEEDED_DIVERGENCE_ICOUNT,
        |_, side, icount| state_dump(side, icount),
    ) {
        Ok(_) => panic!("oracle mismatch should fail after divergence bisection"),
        Err(error) => error,
    };
    let ReplayOracleSearchBisectionError::Mismatch { localized } = error else {
        panic!("oracle mismatch should return a localized mismatch");
    };

    assert_eq!(localized.mismatch.checkpoint_id, "cp-oracle");
    assert_eq!(localized.bisection.sequence, 9);
    assert_eq!(
        localized.divergence.first_different_icount,
        SEEDED_DIVERGENCE_ICOUNT
    );
    assert_eq!(localized.divergence.node.as_deref(), Some("node-a"));
    let Some(decision) = localized.divergence.first_different_decision else {
        panic!("oracle mismatch must localize the first differing decision");
    };
    assert_eq!(decision.index, 2);
}

#[test]
fn gate_divergence_bisect_rejects_oracle_mismatch_without_divergent_streams() {
    let (fat_stream, _) = seeded_streams();
    let decisions = left_decisions();
    let materializations = [ReplayOracleSearchDivergenceMaterialization::new(
        ReplayOracleSearchMaterialization::new(9, replay_oracle_case()),
        ReplayOracleDivergenceInputs {
            fat_stream: &fat_stream,
            thin_stream: &fat_stream,
            fat_decisions: &decisions,
            thin_decisions: &decisions,
        },
    )];
    let config = replay_oracle_sampling_config();
    let result = check_sampled_search_replay_oracle_with_bisection(
        &materializations,
        &config,
        |_, icount| icount < SEEDED_DIVERGENCE_ICOUNT,
        |_, side, icount| state_dump(side, icount),
    );

    assert!(matches!(
        result,
        Err(ReplayOracleSearchBisectionError::LocalizationFailure {
            failure
        }) if matches!(
            &failure.source,
            ReplayOracleDivergenceError::Divergence {
                source: DivergenceBisectionError::MatchingStreams
            }
        )
    ));
}

fn seeded_bisection_report() -> DivergenceBisectionReport {
    let (left_stream, right_stream) = seeded_streams();
    match bisect_diverging_runs_with_segment_replay(
        &left_stream,
        &right_stream,
        &left_decisions(),
        &right_decisions(),
        &replay_checkpoints(DivergenceSide::Left),
        &replay_checkpoints(DivergenceSide::Right),
        &[1, 2, 4],
        |side, segment| Ok::<_, Infallible>(replay_segment(side, segment)),
        state_dump,
    ) {
        Ok(report) => report.divergence,
        Err(error) => panic!("seeded segmented divergence should bisect cleanly: {error}"),
    }
}

fn replay_checkpoints(side: DivergenceSide) -> Vec<ReplayCheckpoint<DivergenceStateDump>> {
    [0, 5, 10, 15, 20]
        .into_iter()
        .map(|coordinate| ReplayCheckpoint {
            coordinate,
            state: state_dump(side, coordinate),
        })
        .collect()
}

fn replay_segment(
    side: DivergenceSide,
    segment: &ReplaySegment<DivergenceStateDump>,
) -> ReplaySegmentOutput<DivergenceStateDump> {
    ReplaySegmentOutput {
        end_state: state_dump(side, segment.end_coordinate),
        canonical_log: ((segment.start_coordinate + 1)..=segment.end_coordinate)
            .map(|coordinate| ReplayLogEntry {
                coordinate,
                canonical_bytes: if side == DivergenceSide::Right
                    && coordinate >= SEEDED_DIVERGENCE_ICOUNT
                {
                    format!("right:{coordinate}").into_bytes()
                } else {
                    format!("same:{coordinate}").into_bytes()
                },
            })
            .collect(),
    }
}

fn replay_oracle_case() -> ReplayOracleMaterializedCase {
    ReplayOracleMaterializedCase {
        checkpoint_id: String::from("cp-oracle"),
        kind: ReplayOracleCheckpointKind::Fat,
        fat_checkpoint_hash: b"checkpoint".to_vec(),
        thin_checkpoint_hash: b"checkpoint".to_vec(),
        fat_configuration_hash: b"configuration".to_vec(),
        thin_configuration_hash: b"configuration".to_vec(),
        fat_ancestor_hash: b"ancestor".to_vec(),
        thin_ancestor_hash: b"ancestor".to_vec(),
        fat_schedule_delta_hash: b"delta".to_vec(),
        thin_schedule_delta_hash: b"delta".to_vec(),
        fat_hash: b"fat-runtime".to_vec(),
        thin_hash: b"thin-runtime".to_vec(),
    }
}

fn replay_oracle_sampling_config() -> ReplayOracleSamplingConfig {
    match ReplayOracleSamplingConfig::new(1, 1, "oracle-bisect") {
        Ok(config) => config,
        Err(error) => panic!("test sampling config should be valid: {error}"),
    }
}

fn seeded_streams() -> (FingerprintStream, FingerprintStream) {
    (
        FingerprintStream {
            definition_digest: vec![0x10],
            samples: vec![
                sample(0, "node-a", 10, b"same-at-10"),
                sample(1, "node-a", 20, b"left-at-20"),
                sample(2, "node-a", 30, b"left-at-30"),
            ],
            final_fingerprint: b"left-final".to_vec(),
        },
        FingerprintStream {
            definition_digest: vec![0x10],
            samples: vec![
                sample(0, "node-a", 10, b"same-at-10"),
                sample(1, "node-a", 20, b"right-at-20"),
                sample(2, "node-a", 30, b"right-at-30"),
            ],
            final_fingerprint: b"right-final".to_vec(),
        },
    )
}

fn left_decisions() -> Vec<DecisionTraceEntry> {
    vec![
        decision(0, "node-a", 4, "rng scheduler/order value=3", b"rng:3"),
        decision(1, "node-a", 10, "deliver frame seq=1", b"deliver:1"),
        decision(
            2,
            "node-a",
            SEEDED_DIVERGENCE_ICOUNT,
            "fault disk-delay fired=false",
            b"fault:disk-delay:false",
        ),
    ]
}

fn right_decisions() -> Vec<DecisionTraceEntry> {
    vec![
        decision(0, "node-a", 4, "rng scheduler/order value=3", b"rng:3"),
        decision(1, "node-a", 10, "deliver frame seq=1", b"deliver:1"),
        decision(
            2,
            "node-a",
            SEEDED_DIVERGENCE_ICOUNT,
            "fault disk-delay fired=true",
            b"fault:disk-delay:true",
        ),
    ]
}

fn decision(
    index: usize,
    node: &str,
    icount: u64,
    summary: &str,
    canonical_bytes: &[u8],
) -> DecisionTraceEntry {
    DecisionTraceEntry {
        index,
        node: Some(node.to_owned()),
        icount: Some(icount),
        summary: summary.to_owned(),
        canonical_bytes: canonical_bytes.to_vec(),
    }
}

fn state_dump(side: DivergenceSide, icount: u64) -> DivergenceStateDump {
    let diverged = icount >= SEEDED_DIVERGENCE_ICOUNT && side == DivergenceSide::Right;
    let pc = if diverged {
        SEEDED_DIVERGENCE_ICOUNT + 1
    } else {
        icount
    };
    let page_byte = if diverged { 0xee } else { 0x11 };
    let event_suffix = if diverged {
        "fault disk-delay fired=true"
    } else {
        "fault disk-delay fired=false"
    };

    DivergenceStateDump {
        icount,
        registers: vec![
            DivergenceRegister {
                name: String::from("pc"),
                bytes: pc.to_le_bytes().to_vec(),
            },
            DivergenceRegister {
                name: String::from("r0"),
                bytes: 7_u64.to_le_bytes().to_vec(),
            },
        ],
        memory_regions: vec![DivergenceMemoryRegion {
            name: String::from("guest-page"),
            start: 0x1000,
            bytes: vec![page_byte, 0x22, 0x33, 0x44],
        }],
        last_canonical_events: vec![
            String::from("rng scheduler/order value=3"),
            String::from("deliver frame seq=1"),
            String::from(event_suffix),
        ],
    }
}

fn zero_divergence_state_dump(side: DivergenceSide, icount: u64) -> DivergenceStateDump {
    let mut dump = state_dump(side, icount);
    if side == DivergenceSide::Right {
        dump.registers[0].bytes = 1_u64.to_le_bytes().to_vec();
        dump.last_canonical_events
            .push(String::from("fault at initial boundary"));
    }
    dump
}

fn duplicate_register_state_dump(side: DivergenceSide, icount: u64) -> DivergenceStateDump {
    let mut dump = state_dump(side, icount);
    if side == DivergenceSide::Right {
        dump.registers.push(DivergenceRegister {
            name: String::from("pc"),
            bytes: 99_u64.to_le_bytes().to_vec(),
        });
    }
    dump
}

fn sample(seq: u64, node: &str, icount: u64, rolling_fingerprint: &[u8]) -> FingerprintSample {
    FingerprintSample {
        seq,
        node: node.to_owned(),
        icount,
        trigger: FingerprintSampleTrigger::Periodic,
        rolling_fingerprint: rolling_fingerprint.to_vec(),
    }
}
