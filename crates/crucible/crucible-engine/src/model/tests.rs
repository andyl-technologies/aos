//! Model unit tests separated from production state and codec code.

use super::*;

#[test]
fn compact_schedule_rejects_collection_reservations_larger_than_remaining_input() {
    // An empty schedule ends with its manifest's segment count. Decision
    // counts inside a segment are covered by the segment codec tests.
    let mut outer = Schedule::empty().to_compact_binary();
    let outer_count = outer.len() - std::mem::size_of::<u64>();
    outer[outer_count..].copy_from_slice(&1_000_000_u64.to_le_bytes());
    let error = Schedule::from_compact_binary(&outer)
        .expect_err("a segment count cannot reserve beyond its encoded input");
    assert!(error.to_string().contains("remaining binary input"));
}

#[test]
fn failure_findings_ledger_orders_signed_findings_and_rejects_conflicts() -> Result<(), EngineError>
{
    let artifact_a = ContentHash::from_bytes(b"signed-finding-artifact-a");
    let artifact_b = ContentHash::from_bytes(b"signed-finding-artifact-b");
    let signature_a = failure_signature_for_test("signed-ledger/property-a");
    let signature_b = failure_signature_for_test("signed-ledger/property-b");
    let ledger = FailureFindingsLedger::from_signed_findings([
        FailureClusterFinding::new(artifact_b, signature_b),
        FailureClusterFinding::new(artifact_a, signature_a.clone()),
        FailureClusterFinding::new(artifact_a, signature_a.clone()),
    ])?;

    let mut expected = vec![artifact_a, artifact_b];
    expected.sort();
    assert_eq!(ledger.artifact_count(), 2);
    assert!(ledger.artifacts.is_empty());
    assert_eq!(
        ledger
            .signed_findings()
            .iter()
            .map(|finding| finding.reproduction_artifact)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(
        ledger
            .canonical_material()
            .contains("signed_finding_count=2")
    );
    assert!(
        ledger
            .canonical_material()
            .contains("finding.0.signature_BEGIN")
    );

    let error = FailureFindingsLedger::from_signed_findings([
        FailureClusterFinding::new(artifact_a, signature_a),
        FailureClusterFinding::new(
            artifact_a,
            failure_signature_for_test("signed-ledger/conflicting-property"),
        ),
    ])
    .expect_err("conflicting signed findings must be rejected");
    assert!(matches!(
        error,
        EngineError::UnifiedOperationEvidenceMismatch {
            operation: "failure-findings-ledger",
            ..
        }
    ));
    Ok(())
}

#[test]
fn sampled_search_offset_localizes_bisection_sequence() -> Result<(), EngineError> {
    let node = NodeId {
        name: String::from("sampled-offset-node"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("sampled-search-offset"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 222 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let decision = crate::test_support::typed_search_decision_for_test("sampled-offset/decision")?;
    let baked = baked_genesis_with_search_frontier(&world, vec![decision.clone()])?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let child = try_step(&genesis, decision)?;
    let corrupt_checkpoint = Checkpoint::from_recorded_configuration(
        &child,
        Some(&genesis),
        VirtualTime::default(),
        BTreeMap::from([(
            node.clone(),
            Icount {
                retired: 222 + child.schedule.len() as u64,
            },
        )]),
        CheckpointKind::Fat,
        BTreeMap::from([(
            node,
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.sampled-search-offset.v1",
                "wrong-fat-vm-blob",
            )),
        )]),
    )?;
    graph.cache_snapshot(&child, corrupt_checkpoint)?;
    let config = SearchReplayOracleSamplingConfig::new(
        1,
        1,
        "sampled-search-offset-localizes-bisection-sequence",
    )?;

    let error = match graph.search_with_replay_oracle_sampling_offset(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::with_budget(1),
        MaterializationTrigger::RepeatedForkSource,
        &config,
        3,
    ) {
        Ok(_) => panic!("sampled corrupt search materialization should fail with bisection"),
        Err(error) => error,
    };
    let EngineError::SearchReplayOracleMismatch { bisection, .. } = error else {
        panic!("sampled corrupt search materialization should request bisection");
    };

    assert_eq!(bisection.sequence, 3);
    assert_eq!(bisection.checkpoint, child.id());
    assert_eq!(
        bisection.reason,
        "sampled fat checkpoint differs from thin reconstruction"
    );
    Ok(())
}

fn failure_signature_for_test(property: &str) -> FailureSignature {
    let coverage = ContentHash::from_bytes(property.as_bytes());
    FailureSignature {
        failure_kind: FailureKind::PropertyViolation,
        property: Some(FailurePropertyKey {
            id: AssertionId::from_name(property),
            quantifier: AssertionQuantifierKind::Always,
        }),
        first_failing_point: FailureFirstFailingPoint {
            event_kind: String::from("assertion_state_changed"),
            faulting_node: None,
        },
        coverage_class: FailureCoverageClass::from_coverage_fingerprint(coverage),
        evidence_binding: coverage,
        causal_slice_hash: Some(coverage),
        causal_cone: Some(FailureCausalCone::from_canonical_material(property, 0)),
        at_icount_report_only: None,
    }
}

fn baked_genesis_with_search_frontier(
    world: &World,
    decisions: Vec<Decision>,
) -> Result<GenesisCheckpoint, EngineError> {
    let mut baked = bake(world)?;
    let state = baked.checkpoint.state.as_ref().ok_or(
        EngineError::CheckpointMaterializedStateIncomplete {
            checkpoint: baked.checkpoint.id,
            reason: "missing-test-genesis-state",
        },
    )?;
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier =
        SearchFrontierChoices::from_decision_sequences(decisions.into_iter().map(std::iter::once));
    baked.checkpoint.state = Some(MaterializedState::from_components_with_event_log_segments(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        scheduler,
        state.decision_rng.clone(),
        state.event_log,
        state.event_log_segments.clone(),
    ));
    Ok(baked)
}

fn delivery_at(ticks: u64) -> Decision {
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks },
        order: Vec::new(),
    })
}

#[test]
fn schedule_prefixes_share_storage_and_match_rebuilt_schedules() {
    let def = ScenarioDef::from_canonical_material("schedule-prefix-sharing", "fixture");
    let schedule = Schedule::from_decisions((0..200).map(delivery_at));

    for len in [0, 1, 63, 64, 65, 130, 199, 200] {
        let prefix = schedule.prefix(len).expect("prefix within the schedule");
        let rebuilt =
            Schedule::from_decisions(schedule.decision_history().iter().take(len).cloned());

        assert_eq!(prefix, rebuilt);
        assert_eq!(prefix.decision_chain(), rebuilt.decision_chain());
        assert_eq!(
            prefix.app_random_decisions(),
            rebuilt.app_random_decisions()
        );
        assert_eq!(
            Configuration {
                def: def.clone(),
                schedule: prefix,
            }
            .id(),
            Configuration {
                def: def.clone(),
                schedule: rebuilt,
            }
            .id()
        );
    }
}

#[test]
fn admission_digest_binds_the_exact_schedule_without_rehashing_it() {
    let def = ScenarioDef::from_canonical_material("admission-digest", "fixture");
    let first = Schedule::from_decisions([delivery_at(1), delivery_at(2)]);
    let appended = Schedule::from_decisions([delivery_at(1)]).appended(delivery_at(2));
    let reordered = Schedule::from_decisions([delivery_at(2), delivery_at(1)]);
    let configuration = |schedule: &Schedule| Configuration {
        def: def.clone(),
        schedule: schedule.clone(),
    };

    assert_eq!(first.decision_chain(), appended.decision_chain());
    assert_eq!(
        configuration(&first).admission_digest(),
        configuration(&appended).admission_digest()
    );
    assert_ne!(first.decision_chain(), reordered.decision_chain());
    assert_ne!(
        configuration(&first).admission_digest(),
        configuration(&reordered).admission_digest()
    );
    assert_ne!(
        configuration(&first).admission_digest(),
        configuration(&first.prefix(1).expect("prefix")).admission_digest()
    );
    assert_ne!(
        Configuration::genesis(def.clone()).admission_digest(),
        Configuration::genesis(ScenarioDef::from_canonical_material(
            "admission-digest",
            "other"
        ))
        .admission_digest()
    );
}

#[test]
fn memoized_configuration_id_matches_a_fresh_hash_across_appends_and_clones() {
    let def = ScenarioDef::from_canonical_material("configuration-id-memo", "fixture");
    let mut configuration = Configuration::genesis(def.clone());
    let fresh = |configuration: &Configuration| canonical::configuration_hash(configuration);

    // Each append must discard the id memoized for the shorter schedule.
    for ticks in 0..8 {
        assert_eq!(configuration.id(), fresh(&configuration));
        configuration.schedule = configuration.schedule.appended(delivery_at(ticks));
        assert_eq!(configuration.id(), fresh(&configuration));
    }

    // A clone shares the memo while it matches and drops it once it appends;
    // the original keeps answering for its own decisions.
    let original_id = configuration.id();
    let mut extended = configuration.clone();
    assert_eq!(extended.id(), original_id);
    extended.schedule = extended.schedule.appended(delivery_at(99));
    assert_ne!(extended.id(), original_id);
    assert_eq!(extended.id(), fresh(&extended));
    assert_eq!(configuration.id(), original_id);
    assert_eq!(configuration.id(), fresh(&configuration));

    // A memo computed for one definition never answers for another.
    let other_def = ScenarioDef::from_canonical_material("configuration-id-memo", "other");
    let paired_elsewhere = Configuration {
        def: other_def,
        schedule: configuration.schedule.clone(),
    };
    assert_ne!(paired_elsewhere.id(), original_id);
    assert_eq!(paired_elsewhere.id(), fresh(&paired_elsewhere));
    assert_eq!(configuration.id(), original_id);

    // Rebuilt and prefix schedules agree with a fresh hash.
    let rebuilt = Configuration {
        def: def.clone(),
        schedule: Schedule::from_decisions(
            configuration.schedule.decision_history().iter().cloned(),
        ),
    };
    assert_eq!(rebuilt.id(), original_id);
    let prefix = Configuration {
        def,
        schedule: configuration.schedule.prefix(3).expect("prefix"),
    };
    assert_eq!(prefix.id(), fresh(&prefix));
}

#[test]
fn memoized_configuration_id_leaves_schedule_bytes_and_equality_unchanged() {
    let def = ScenarioDef::from_canonical_material("configuration-id-memo", "codec");
    let schedule = Schedule::from_decisions([delivery_at(1), delivery_at(2), delivery_at(3)]);
    let unmemoized_bytes = schedule.to_compact_binary();
    let configuration = Configuration {
        def: def.clone(),
        schedule: schedule.clone(),
    };

    let id = configuration.id();
    assert_eq!(configuration.schedule.to_compact_binary(), unmemoized_bytes);
    assert_eq!(configuration.schedule, schedule);

    let decoded = Schedule::from_compact_binary(&unmemoized_bytes).expect("decode schedule");
    assert_eq!(decoded, schedule);
    let decoded_configuration = Configuration {
        def,
        schedule: decoded,
    };
    assert_eq!(decoded_configuration.id(), id);
    assert_eq!(decoded_configuration, configuration);
}
