//! Implements `gate:coverage-guided-fuzzing` over seeded family mutation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible::{
    CoverageGuidedFuzzConfig, Decision, EngineError, EventLogCoverageFeedback,
    EventLogCoverageFeedbackConsumer, FamilySpace, FaultDensity, FaultDensityRange, Icount,
    MarkerId, NodeTemplate, ObservableEvent, ScenarioFamily, Seed, SeedSpace, TopologyShape,
    TopologySizeRange, reduce,
};

#[test]
fn gate_coverage_guided_fuzzing_is_seeded_and_reproducible() -> Result<(), Box<dyn Error>> {
    let family = fuzz_family()?;
    let config = CoverageGuidedFuzzConfig::new(Seed::from_u64(0xf00d), 4);
    let feedback = vec![coverage_feedback("guest-a", 0x4000, "first")];
    let first = family.fuzz_coverage_guided(config, &feedback)?;
    let second = family.fuzz_coverage_guided(config, &feedback)?;
    let expected_feedback =
        feedback[0].fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing);

    assert_eq!(first, second);
    assert_eq!(first.config, config);
    assert_eq!(first.iterations.len(), config.iterations as usize);
    assert_eq!(first.coverage_biased_order.len(), first.iterations.len());
    assert_eq!(
        first.coverage_biased_order[0],
        first.iterations[0].configuration_id()
    );

    for iteration in &first.iterations {
        assert!(family.space().contains(iteration.params));
        assert_eq!(iteration.scenario.params(), iteration.params);
        assert_eq!(
            iteration.configuration.def,
            iteration.scenario.scenario_def()
        );
        assert_eq!(
            iteration.schedule().decisions(),
            std::slice::from_ref(&iteration.mutation)
        );
        assert!(matches!(iteration.mutation, Decision::Override(_)));
        assert_eq!(iteration.coverage_fingerprint, expected_feedback);
        assert_ne!(
            iteration.selected_corpus_entry,
            crucible::ContentHash::default()
        );
        assert!(iteration.energy > 0);
        assert!(reduce(&iteration.configuration.def, iteration.schedule()).is_ok());
    }

    assert!(first.iterations[0].new_coverage);
    assert!(
        first.iterations[1..]
            .iter()
            .all(|iteration| !iteration.new_coverage)
    );
    assert_eq!(unique_sample_indexes(&first), BTreeSet::from([0, 1]));
    assert_eq!(
        unique_fault_plan_entry_counts(&first),
        BTreeSet::from([0, 2])
    );

    Ok(())
}

#[test]
fn gate_coverage_guided_fuzzing_prefers_first_seen_coverage() -> Result<(), Box<dyn Error>> {
    let family = fuzz_family()?;
    let config = CoverageGuidedFuzzConfig::new(Seed::from_u64(0xbeef), 3);
    let first_feedback = coverage_feedback("guest-a", 0x5000, "first");
    let second_feedback = coverage_feedback("guest-a", 0x6000, "second");
    let feedback = vec![
        first_feedback.clone(),
        second_feedback.clone(),
        first_feedback.clone(),
    ];
    let run = family.fuzz_coverage_guided(config, &feedback)?;
    let first_two_ordered = run.coverage_biased_order[..2]
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let first_two_generated = run.iterations[..2]
        .iter()
        .map(|iteration| iteration.configuration_id())
        .collect::<BTreeSet<_>>();

    assert_ne!(
        first_feedback.fingerprint(),
        second_feedback.fingerprint(),
        "fixture must present two distinct coverage projections"
    );
    assert!(run.iterations[0].new_coverage);
    assert!(run.iterations[1].new_coverage);
    assert!(!run.iterations[2].new_coverage);
    assert!(run.iterations.iter().all(|iteration| iteration.energy > 0));
    assert!(
        !run.iterations
            .iter()
            .map(|iteration| iteration.selected_corpus_entry)
            .collect::<BTreeSet<_>>()
            .is_empty()
    );
    assert_eq!(first_two_ordered, first_two_generated);
    assert_eq!(
        run.iterations[0].coverage_fingerprint,
        first_feedback.fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing)
    );
    assert_eq!(
        run.iterations[1].coverage_fingerprint,
        second_feedback.fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing)
    );

    Ok(())
}

fn fuzz_family() -> Result<ScenarioFamily, EngineError> {
    let density_one = FaultDensity::from_millionths(1)?;
    let space = FamilySpace::new(
        SeedSpace::explicit(vec![Seed::from_u64(0x11)])?,
        FaultDensityRange::new(FaultDensity::ZERO, density_one)?,
        TopologySizeRange::new(2, 2)?,
        vec![TopologyShape::Ring],
    )?;
    Ok(ScenarioFamily::new(
        space,
        NodeTemplate::fixed_icount(Icount { retired: 50 }),
    ))
}

fn coverage_feedback(
    node_name: &str,
    guest_pc: u64,
    marker_name: &str,
) -> EventLogCoverageFeedback {
    let node = crucible::NodeId {
        name: node_name.to_owned(),
    };
    let log = vec![
        crucible::test_support::condition_observation_entry_for_test(
            0,
            &ObservableEvent::coverage_block(icount(10), node.clone(), guest_pc, 0x20),
        ),
        crucible::test_support::condition_observation_entry_for_test(
            1,
            &ObservableEvent::coverage_marker(icount(11), node, marker(marker_name)),
        ),
    ];
    EventLogCoverageFeedback::from_event_log(&log)
}

fn unique_sample_indexes(run: &crucible::CoverageGuidedFuzzRun) -> BTreeSet<u64> {
    run.iterations
        .iter()
        .map(|iteration| iteration.sample_index)
        .collect()
}

fn unique_fault_plan_entry_counts(run: &crucible::CoverageGuidedFuzzRun) -> BTreeSet<usize> {
    run.iterations
        .iter()
        .map(|iteration| iteration.scenario.form().plan().entries().len())
        .collect()
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
