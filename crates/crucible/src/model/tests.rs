//! Model unit tests separated from production state and codec code.

use super::*;

#[test]
fn bounded_random_fault_draw_forces_rejection_of_the_biased_prefix() {
    // 2^64 mod 10 is 6, so [0, 6) is the biased short prefix. Supplying 5
    // then 16 proves the sampler consumes and rejects the first draw before
    // accepting 16 and reducing it to residue 6.
    let mut draws = [5_u64, 16].into_iter();
    let mut consumed = 0_u64;
    let sampled = draw_bounded_u64_from(10, || {
        consumed = consumed.saturating_add(1);
        draws.next().unwrap_or(u64::MAX)
    })
    .unwrap_or_else(|error| panic!("bounded sample should succeed: {error}"));

    assert_eq!(sampled, 6);
    assert_eq!(consumed, 2, "the biased prefix draw must be rejected");
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
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("sampled-offset/decision"),
        value: 42,
    });
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
        causal_slice_hash: Some(coverage),
        causal_cone: Some(FailureCausalCone::from_canonical_material(property)),
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
    scheduler.search_frontier = SearchFrontierChoices::from_decisions(decisions);
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
