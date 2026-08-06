//! Gates durable corpus management for coverage-guided fuzzing.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible::{
    CoverageGuidedCorpusAdmissionDecision, CoverageGuidedCorpusConfig, CoverageGuidedFuzzConfig,
    DagStore, EngineError, EventLogCoverageFeedback, EventLogCoverageFeedbackConsumer, FamilySpace,
    Icount, MarkerId, MemoryDagStore, NodeTemplate, ObservableEvent, ReproductionArtifact,
    ScenarioFamily, Seed, SeedSpace, TopologyShape, TopologySizeRange,
};

#[test]
fn gate_coverage_guided_corpus_persists_replay_artifacts() -> Result<(), Box<dyn Error>> {
    let family = fuzz_family()?;
    let store = MemoryDagStore::new();
    let config = CoverageGuidedFuzzConfig::new(Seed::from_u64(0xc0_5015), 25);
    let corpus_config = CoverageGuidedCorpusConfig::new(Seed::from_u64(0xc0_7a05));
    let first_feedback = coverage_feedback("guest-a", 0x5000, "first");
    let second_feedback = coverage_feedback("guest-a", 0x6000, "second");
    let feedback = vec![
        first_feedback.clone(),
        second_feedback.clone(),
        first_feedback.clone(),
    ];
    let run = family.fuzz_coverage_guided_corpus(&store, config, corpus_config, &feedback)?;

    assert_eq!(run.fuzz.config, config);
    assert_eq!(run.fuzz.iterations.len(), 25);
    assert_eq!(run.admissions.len(), 25);
    assert!(run.throughput.meets_target());
    assert!(run.throughput.oracle_validated_all_mutants());
    assert_eq!(
        run.throughput.target.min_generated_mutants,
        crucible::DEFAULT_COVERAGE_GUIDED_FUZZ_THROUGHPUT_TARGET
    );
    assert_eq!(run.throughput.generated_mutants, 25);
    assert_eq!(run.throughput.deterministic_work_units, 25);
    assert_eq!(run.throughput.replay_oracle_validations, 26);
    assert_eq!(run.throughput.retained_entries, run.corpus.len() as u64);
    assert_eq!(run.throughput.store_puts, (run.corpus.len() as u64) * 2);
    assert_eq!(run.corpus.len(), 3);
    assert_eq!(store.object_count()?, run.corpus.len() * 2);

    assert!(matches!(
        run.admissions[0].decision,
        CoverageGuidedCorpusAdmissionDecision::AdmittedNewCoverage { .. }
    ));
    assert!(matches!(
        run.admissions[1].decision,
        CoverageGuidedCorpusAdmissionDecision::AdmittedNewCoverage { .. }
    ));
    assert!(matches!(
        run.admissions[2].decision,
        CoverageGuidedCorpusAdmissionDecision::PrunedSubsumedCoverage { .. }
    ));
    assert_eq!(
        run.admissions[0].coverage_fingerprint,
        first_feedback.fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing)
    );
    assert_eq!(
        run.admissions[1].coverage_fingerprint,
        second_feedback.fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing)
    );

    let coverage = run
        .corpus
        .entries()
        .values()
        .map(|entry| entry.coverage_fingerprint)
        .collect::<BTreeSet<_>>();
    assert_eq!(coverage.len(), run.corpus.len());

    for iteration in &run.fuzz.iterations {
        assert!(
            run.corpus
                .entries()
                .contains_key(&iteration.selected_corpus_entry)
        );
        assert!(iteration.energy > 0);
    }

    for entry in run.corpus.entries().values() {
        let bytes = store.get(&entry.store_key)?;
        let descriptor = store.get(&entry.descriptor_key)?;
        let artifact = ReproductionArtifact::from_compact_binary(&bytes)?;
        let replay = artifact.replay()?;

        assert_eq!(entry.artifact, artifact.id());
        assert_eq!(entry.store_key, artifact.id());
        assert!(String::from_utf8(descriptor)?.contains(&entry.artifact.to_hex()));
        assert_eq!(entry.scenario, replay.scenario);
        assert_eq!(entry.schedule, replay.schedule);
        assert_eq!(entry.replayed_state, replay.state);
        assert!(entry.energy > 0);
    }

    Ok(())
}

#[test]
fn gate_coverage_guided_corpus_is_seeded_and_deduplicated() -> Result<(), Box<dyn Error>> {
    let family = fuzz_family()?;
    let config = CoverageGuidedFuzzConfig::new(Seed::from_u64(0x5150), 25);
    let corpus_config = CoverageGuidedCorpusConfig::new(Seed::from_u64(0x5151));
    let feedback = vec![
        coverage_feedback("guest-a", 0x7000, "alpha"),
        coverage_feedback("guest-a", 0x8000, "beta"),
    ];
    let first_store = MemoryDagStore::new();
    let second_store = MemoryDagStore::new();
    let first =
        family.fuzz_coverage_guided_corpus(&first_store, config, corpus_config, &feedback)?;
    let second =
        family.fuzz_coverage_guided_corpus(&second_store, config, corpus_config, &feedback)?;

    assert_eq!(first, second);
    assert_eq!(first_store.object_count()?, second_store.object_count()?);
    assert!(first.admissions.iter().skip(2).all(|admission| matches!(
        admission.decision,
        CoverageGuidedCorpusAdmissionDecision::PrunedSubsumedCoverage { .. }
    )));
    assert_eq!(
        first
            .admissions
            .iter()
            .filter(|admission| admission.decision.is_admitted())
            .count(),
        2
    );
    assert_ne!(first.corpus.fingerprint(), crucible::ContentHash::default());

    Ok(())
}

fn fuzz_family() -> Result<ScenarioFamily, EngineError> {
    let space = FamilySpace::new(
        SeedSpace::explicit(vec![Seed::from_u64(0x11)])?,
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

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
