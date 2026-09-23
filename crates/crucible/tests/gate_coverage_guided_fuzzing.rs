//! Implements `gate:coverage-guided-fuzzing` over seeded family mutation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible::model::{
    BindingMapping, BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy,
    CpuServiceDiscipline, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
    EffectSpecification, ExactRatio, FaultBinding, FaultObjectId, FaultPhase, FaultResourceLimits,
    FaultSignalPlan, NodeEffectSpecification, PositiveU64, ResolvedFaultTarget, ResolvedTargetSet,
    SignalDomain, SignalId, SignalNode, SignalNodeKind, SignalProgram, SignalResourceLimits,
    SignalShape, SignalUnit, SignalValue, SignalValueType, TargetSelector,
};
use crucible::{
    CoverageGuidedFuzzConfig, Decision, EngineError, EventLogCoverageFeedback,
    EventLogCoverageFeedbackConsumer, FamilySpace, Icount, MarkerId, NodeTemplate, ObservableEvent,
    ReproductionArtifact, ScenarioFamily, Schedule, Seed, SeedSpace, TopologyShape,
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
        assert!(matches!(iteration.mutation, Decision::Selection(_)));
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
    assert_eq!(unique_sample_indexes(&first), BTreeSet::from([0]));
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

#[test]
fn gate_coverage_guided_fuzzing_pins_bounded_fault_plan_variants() -> Result<(), Box<dyn Error>> {
    let invalid_space = FamilySpace::new(
        SeedSpace::explicit(vec![Seed::from_u64(0x11)])?,
        TopologySizeRange::new(2, 2)?,
        vec![TopologyShape::Ring],
    )?
    .with_fault_densities(vec![2])?;
    assert!(
        ScenarioFamily::new(invalid_space, NodeTemplate::fixed_icount(icount(50)))
            .with_fault_plan(family_fault_plan()?)
            .is_err(),
        "a density beyond the admitted binding set must fail closed"
    );

    let space = FamilySpace::new(
        SeedSpace::explicit(vec![Seed::from_u64(0x11)])?,
        TopologySizeRange::new(2, 2)?,
        vec![TopologyShape::Ring],
    )?
    .with_fault_densities(vec![1, 0, 1])?;
    let family = ScenarioFamily::new(space, NodeTemplate::fixed_icount(icount(50)))
        .with_fault_plan(family_fault_plan()?)?;
    let empty = family.instantiate_sample(0)?;
    let faulted = family.instantiate_sample(1)?;

    assert_eq!(family.space().cardinality()?, 2);
    assert_eq!(empty.params().fault_density, 0);
    assert_eq!(faulted.params().fault_density, 1);
    assert!(empty.form().plan().fault_signals().bindings().is_empty());
    assert_eq!(faulted.form().plan().fault_signals().bindings().len(), 1);
    assert_ne!(
        empty.form().plan().content_hash(),
        faulted.form().plan().content_hash()
    );
    assert_ne!(empty.scenario_def().id(), faulted.scenario_def().id());
    assert_eq!(faulted, family.instantiate_sample(1)?);
    let artifact = ReproductionArtifact::capture(faulted.form(), &Schedule::empty())?;
    let replay = artifact.replay()?;
    assert_eq!(replay.scenario, faulted.scenario_def().id());
    assert_eq!(artifact.scenario_form().plan(), faulted.form().plan());

    let config = CoverageGuidedFuzzConfig::new(Seed::from_u64(0xbeef), 16);
    let run = family.fuzz_coverage_guided(config, &[])?;
    assert_eq!(run, family.fuzz_coverage_guided(config, &[])?);
    assert_eq!(
        run.iterations
            .iter()
            .map(|iteration| iteration.params.fault_density)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 1]),
    );
    for iteration in &run.iterations {
        assert_eq!(
            iteration
                .scenario
                .form()
                .plan()
                .fault_signals()
                .bindings()
                .len(),
            iteration.params.fault_density as usize,
        );
        assert!(reduce(&iteration.configuration.def, iteration.schedule()).is_ok());
    }

    Ok(())
}

fn family_fault_plan() -> Result<FaultSignalPlan, Box<dyn Error>> {
    let output = SignalId::parse("cpu-limited")?;
    let program = SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)?,
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Bool(true),
            },
        }],
        vec![output.clone()],
        SignalResourceLimits::default(),
    )?;
    let targets = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::Node {
            node: FaultObjectId::parse("node-0")?,
        }],
        false,
    )?;
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Node(NodeEffectSpecification::CpuService {
            vcpus: vec![0],
            capacity: ExactRatio::new(1, 2)?,
            quantum_instructions: PositiveU64::new("quantum_instructions", 64)?,
            service_rule: CpuServiceDiscipline::StrictCap,
        }),
    )?;
    let binding = FaultBinding::new(
        FaultObjectId::parse("family-cpu-limit")?,
        vec![output],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(targets),
        BTreeSet::from([FaultPhase::Run]),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &program,
    )?;
    Ok(FaultSignalPlan::new(
        vec![program],
        vec![binding],
        FaultResourceLimits::default(),
    )?)
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

fn unique_sample_indexes(run: &crucible::CoverageGuidedFuzzRun) -> BTreeSet<u64> {
    run.iterations
        .iter()
        .map(|iteration| iteration.sample_index)
        .collect()
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
