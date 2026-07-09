//! Gates deterministic failure-preserving minimization.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::{
    AssertionDef, AssertionId, AssertionQuantifierKind, AssertionRunVerdict, BlackBoxHostOracle,
    ChoiceTag, Configuration, ContentHash, Decision, EngineError, FaultDecision, FaultId,
    FindingDiscoveryPath, FindingReproductionArtifact, Icount, MarkerId, MinimizationConfig,
    NodeId, NodeTemplate, ObservableEvent, OfflineAssertionChecker, OverrideDecision, Plan,
    Predicate, Properties, Property, ReadyPoint, RecordedAssertionLog, ScenarioDefForm, Schedule,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogPayload, SchedulingPoint, Seed, VirtualTime,
    WhiteBoxPolicy, World, WorldNode,
};

#[test]
fn gate_minimization_shrinks_schedule_and_fault_decisions_deterministically()
-> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let original_schedule = Schedule::from_decisions([
        override_decision("guard-left", "enabled"),
        fault_decision("unused-network-loss", false),
        override_decision("critical-assertion", "fail"),
        override_decision("guard-right", "enabled"),
    ]);
    let target = failure_fingerprint_for_schedule(&scenario, &original_schedule)?
        .expect("original schedule should violate the assertion");
    let original = finding_artifact(&scenario, original_schedule, target)?;
    let config = MinimizationConfig::new(Seed::from_u64(0x5151));

    let first = original.minimize(config, |candidate| failure_oracle(target, candidate))?;
    let second = original.minimize(config, |candidate| failure_oracle(target, candidate))?;

    assert_eq!(first, second);
    assert!(first.shrank());
    assert_eq!(first.seed, config.seed);
    assert_eq!(first.target_fingerprint, target);
    assert_eq!(first.original.artifact.id(), original.artifact.id());
    assert_eq!(first.accepted_attempts(), 1);
    assert!(first.attempts.iter().any(|attempt| !attempt.accepted));
    assert!(first.attempts.iter().all(|attempt| {
        attempt.replayed_state != ContentHash::default()
            && (!attempt.accepted || attempt.observed_fingerprint == Some(target))
    }));

    let minimized_schedule = first.minimized.artifact.schedule();
    assert_eq!(minimized_schedule.len(), 1);
    assert!(matches!(
        &minimized_schedule.decisions()[0],
        Decision::Override(decision)
            if decision.point.key == "critical-assertion" && decision.choice.name == "fail"
    ));
    let accepted = first
        .attempts
        .iter()
        .find(|attempt| attempt.accepted)
        .expect("minimization should accept one candidate");
    assert_eq!(accepted.removed_indices.len(), 3);
    assert!(
        accepted
            .removed_decisions
            .iter()
            .any(|decision| matches!(decision, Decision::FaultFires(_)))
    );
    assert_eq!(
        first.minimized.discovery_path,
        FindingDiscoveryPath::CoverageGuidedFuzzing
    );
    assert_eq!(first.minimized.finding_fingerprint, target);
    assert_eq!(first.minimized.replay, first.minimized.artifact.replay()?);

    Ok(())
}

#[test]
fn gate_minimization_rejects_non_reproducing_start() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let target = finding_fingerprint("missing-start-failure");
    let original = finding_artifact(
        &scenario,
        Schedule::from_decisions([override_decision("noise-only", "left")]),
        target,
    )?;

    assert!(matches!(
        original.minimize(
            MinimizationConfig::new(Seed::from_u64(0x5152)),
            |candidate| { failure_oracle(target, candidate) }
        ),
        Err(EngineError::ReplayTargetMismatch { .. })
    ));

    Ok(())
}

#[test]
fn gate_minimization_validates_public_artifact_before_oracle() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let target = finding_fingerprint("stale-replay");
    let original = finding_artifact(
        &scenario,
        Schedule::from_decisions([override_decision("critical-assertion", "fail")]),
        target,
    )?;

    let mut stale = original.clone();
    stale.replay.state = finding_fingerprint("forged-replay-state");

    let error = stale
        .minimize(
            MinimizationConfig::new(Seed::from_u64(0x5153)),
            |_candidate| -> Result<Option<ContentHash>, EngineError> {
                panic!("oracle must not run for stale public artifact")
            },
        )
        .expect_err("stale public replay evidence should be rejected");

    assert!(matches!(
        error,
        EngineError::ReproductionArtifactReplayMismatch { .. }
    ));

    Ok(())
}

fn finding_artifact(
    scenario: &ScenarioDefForm,
    schedule: Schedule,
    fingerprint: ContentHash,
) -> Result<FindingReproductionArtifact, EngineError> {
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule,
    };
    FindingReproductionArtifact::capture(
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        fingerprint,
        scenario,
        &configuration,
    )
}

fn failure_oracle(
    target: ContentHash,
    candidate: &FindingReproductionArtifact,
) -> Result<Option<ContentHash>, EngineError> {
    let _ = candidate.artifact.replay()?;
    let fingerprint = failure_fingerprint_for_schedule(
        candidate.artifact.scenario_form(),
        candidate.artifact.schedule(),
    )?;
    Ok((fingerprint == Some(target)).then_some(target))
}

fn failure_fingerprint_for_schedule(
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
) -> Result<Option<ContentHash>, EngineError> {
    let retained = retained_event_log(schedule)?;
    let mut oracle = BlackBoxHostOracle;
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .check_run_with_oracle(scenario.properties(), &retained, &mut oracle)
        .map_err(|source| EngineError::ScenarioSerialization {
            reason: format!("assertion fold failed: {source}"),
        })?;
    let fingerprint = report
        .violations()
        .iter()
        .find(|violation| {
            violation.assertion == assertion_id("no-forbidden-marker")
                && violation.quantifier == AssertionQuantifierKind::Always
        })
        .map(assertion_fold_failure_fingerprint);
    assert!(
        matches!(report.verdict(), AssertionRunVerdict::Failed { .. }) == fingerprint.is_some()
    );
    Ok(fingerprint)
}

fn retained_event_log(schedule: &Schedule) -> Result<RecordedAssertionLog, EngineError> {
    let mut entries = schedule
        .decisions()
        .iter()
        .enumerate()
        .map(|(sequence, decision)| {
            crucible::test_support::condition_payload_entry_for_test(
                sequence as u64,
                time(sequence as u64),
                SchedulerEventLogPayload::Decision(decision.clone()),
            )
        })
        .collect::<Vec<_>>();
    let mut sequence = entries.len() as u64;
    if schedule_emits_forbidden_marker(schedule) {
        entries.push(
            crucible::test_support::condition_observation_entry_for_test(
                sequence,
                &ObservableEvent::guest_marker(
                    icount(7),
                    node("minimize-node"),
                    marker_id("forbidden"),
                ),
            ),
        );
        sequence += 1;
    }
    entries.push(crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(7),
        SchedulerEvaluationBoundaryKind::Quantum,
    ));
    RecordedAssertionLog::from_segments(vec![entries]).map_err(|source| {
        EngineError::ScenarioSerialization {
            reason: format!("retained minimization assertion log failed: {source}"),
        }
    })
}

fn schedule_emits_forbidden_marker(schedule: &Schedule) -> bool {
    let has_critical = schedule.decisions().iter().any(|decision| {
        matches!(
            decision,
            Decision::Override(override_decision)
                if override_decision.point.key == "critical-assertion"
                    && override_decision.choice.name == "fail"
        )
    });
    let guards = ["guard-left", "guard-right"]
        .into_iter()
        .filter(|guard| {
            schedule.decisions().iter().any(|decision| {
                matches!(
                    decision,
                    Decision::Override(override_decision)
                        if override_decision.point.key == *guard
                            && override_decision.choice.name == "enabled"
                )
            })
        })
        .count();
    has_critical && guards != 1
}

fn assertion_fold_failure_fingerprint(violation: &crucible::HostAssertionViolation) -> ContentHash {
    let icount = violation
        .at_icount
        .map(|value| value.retired.to_string())
        .unwrap_or_else(|| "none".to_owned());
    let node = violation
        .node
        .as_ref()
        .map(|value| value.name.as_str())
        .unwrap_or("none");
    ContentHash::from_canonical_material(
        "crucible.test.minimization.assertion-fold.v1",
        &format!(
            "assertion={}\nmessage={}\nquantifier={:?}\nicount={icount}\nvirtual_time={}\nnode={node}\ndetail={}",
            violation.assertion.name,
            violation.message,
            violation.quantifier,
            violation.at_virtual_time.ticks,
            violation.detail
        ),
    )
}

fn scenario_form() -> Result<ScenarioDefForm, EngineError> {
    let world = World::from_nodes(vec![WorldNode {
        id: node("minimize-node"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "crucible-minimization".to_owned(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 64 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::from_assertions_for_world(
            &world,
            vec![AssertionDef {
                id: assertion_id("no-forbidden-marker"),
                message: "forbidden marker must stay absent".to_owned(),
                property: Property::Always {
                    predicate: Predicate::not(Predicate::guest_marker(marker_id("forbidden"))),
                },
            }],
        )?,
        Seed::default(),
    )
}

fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

fn fault_decision(name: &str, fired: bool) -> Decision {
    Decision::FaultFires(FaultDecision {
        at: VirtualTime { ticks: 10 },
        fault: FaultId {
            name: name.to_owned(),
        },
        fired,
    })
}

fn finding_fingerprint(label: &str) -> ContentHash {
    ContentHash::from_canonical_material("crucible.test.minimization", label)
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn marker_id(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
