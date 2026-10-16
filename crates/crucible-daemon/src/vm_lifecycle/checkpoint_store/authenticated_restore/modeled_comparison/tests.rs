//! Complete modeled-state equality controls over canonical production fixtures.
//!
//! Placeholder VMState and RAM material is not launchable physical evidence.

use super::*;
use crate::vm_lifecycle::checkpoint_store::test_support::{
    AuthenticatedProductionCheckpointCodecFixture,
    build_authenticated_production_checkpoint_codec_fixture, test_ram_catalog_provider,
};

fn segment_objects(
    checkpoint: &mut ProductionVmExactCheckpointSet,
    signal: bool,
) -> &mut Arc<BTreeMap<ContentHash, Vec<u8>>> {
    if signal {
        &mut checkpoint.signal_artifact_objects
    } else {
        &mut checkpoint.event_log_objects
    }
}

fn load(
    directory: &Path,
    fixture: &AuthenticatedProductionCheckpointCodecFixture,
) -> Result<DecodedProductionExactCheckpoint, LifecycleApiError> {
    let source = fixture.source();
    let checkpoint = load_exact_checkpoint_set(
        directory,
        &source.scenario_def(),
        source,
        fixture.closure().identity(),
        Some(&test_ram_catalog_provider()),
    )?;
    let manifest = decode::decode_manifest_with_limits(
        fixture.closure().manifest(),
        source.plan().fault_signals().resource_limits(),
    )?;
    let expected_snapshots = manifest
        .targets
        .into_iter()
        .map(|target| {
            (
                NodeId {
                    name: target.node.into_string(),
                },
                target.snapshot,
            )
        })
        .collect();
    Ok(DecodedProductionExactCheckpoint {
        checkpoint,
        expected_snapshots,
    })
}

#[test]
fn complete_modeled_comparison_borrows_separate_decoded_owners()
-> Result<(), Box<dyn std::error::Error>> {
    let _original = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)?;
    let directory = tempfile::tempdir()?;
    let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
    let baseline = load(directory.path(), &fixture)?;
    let candidate = load(directory.path(), &fixture)?;

    assert!(!Arc::ptr_eq(
        &baseline.checkpoint.scheduler,
        &candidate.checkpoint.scheduler,
    ));
    assert!(baseline.same_modeled_continuation(fixture.source(), &candidate, fixture.source(),)?);
    Ok(())
}

#[test]
fn complete_modeled_comparison_rejects_controller_and_target_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let _original = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)?;
    let directory = tempfile::tempdir()?;
    let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
    let baseline = load(directory.path(), &fixture)?;
    let source = fixture.source();

    // Mutants change one policy field after a real canonical load. They test
    // comparison coverage, not authentication of a fabricated altered capture.
    macro_rules! rejects {
        ($role:literal, $mutate:expr) => {{
            let mut candidate = load(directory.path(), &fixture)?;
            ($mutate)(&mut candidate);
            assert!(
                !baseline.same_modeled_continuation(source, &candidate, source)?,
                "comparison omitted {}",
                $role,
            );
        }};
    }

    rejects!(
        "closure identity",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            candidate.checkpoint.identity = ContentHash::from_bytes(b"different closure");
        }
    );
    rejects!(
        "terminal verdict",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            candidate.checkpoint.terminal_verdict = Some(QuantumTerminalVerdict::Passed);
        }
    );
    rejects!(
        "terminal cause",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            candidate.checkpoint.terminal_cause = Some(CheckpointTerminalCause::OperatorStop);
        }
    );
    rejects!(
        "initial observations",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            candidate.checkpoint.initial_lifecycle_observations_pending =
                !candidate.checkpoint.initial_lifecycle_observations_pending;
        }
    );
    rejects!(
        "branch",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            candidate.checkpoint.branch = Some(ProductionVmBranchConfig {
                base: candidate.checkpoint.configuration.clone(),
                frontier: VirtualTime { ticks: 1 },
                seed: Some(Seed::from_u64(7)),
            });
        }
    );
    rejects!(
        "recorded control",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            candidate
                .checkpoint
                .recorded_controls
                .push(ProductionVmRecordedControl {
                    configuration: candidate.checkpoint.configuration.clone(),
                    node_times: BTreeMap::new(),
                    control: vec![ControlOperation {
                        sequence: 1,
                        kind: crucible::ControlOperationKind::Pause,
                    }],
                });
        }
    );
    rejects!(
        "selectable catalog",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            assert!(!candidate.checkpoint.selectable_catalog_plans.is_empty());
            candidate.checkpoint.selectable_catalog_plans.clear();
        }
    );
    rejects!(
        "fault continuation",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            assert!(candidate.checkpoint.fault_checkpoint.take().is_some());
        }
    );
    rejects!(
        "target roster",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            assert!(!candidate.checkpoint.targets.is_empty());
            candidate.checkpoint.targets.clear();
        }
    );
    rejects!(
        "node generation",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            let generation = candidate.checkpoint.node_generations.values_mut().next();
            *generation.expect("fixture generation") += 1;
        }
    );
    rejects!(
        "service state",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            let service = candidate.checkpoint.node_service_states.values_mut().next();
            *service.expect("fixture service state") = ProductionNodeServiceState::PoweredOff;
        }
    );
    rejects!(
        "restore claim",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            let claim = candidate.expected_snapshots.values_mut().next();
            *claim.expect("fixture target claim") = ContentHash::from_bytes(b"different claim");
        }
    );
    rejects!(
        "target backing",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            let target = candidate.checkpoint.targets.values_mut().next();
            target.expect("fixture target").immutable_backing =
                ContentHash::from_bytes(b"different backing");
        }
    );
    rejects!(
        "target counter",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            let target = candidate.checkpoint.targets.values_mut().next();
            target.expect("fixture target").counter += 1;
        }
    );
    rejects!(
        "target scheduler time",
        |candidate: &mut DecodedProductionExactCheckpoint| {
            let target = candidate.checkpoint.targets.values_mut().next();
            target.expect("fixture target").scheduler_time.ticks += 1;
        }
    );
    Ok(())
}

#[test]
fn complete_modeled_comparison_checks_segment_bytes_without_identity_shortcuts()
-> Result<(), Box<dyn std::error::Error>> {
    let _original = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)?;
    let directory = tempfile::tempdir()?;
    let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
    let source = fixture.source();

    for signal in [false, true] {
        let mut baseline = load(directory.path(), &fixture)?;
        let mut candidate = load(directory.path(), &fixture)?;
        let identity = ContentHash::from_bytes(b"fixed segment identity");
        *segment_objects(&mut baseline.checkpoint, signal) =
            Arc::new(BTreeMap::from([(identity, vec![1, 2])]));
        *segment_objects(&mut candidate.checkpoint, signal) =
            Arc::new(BTreeMap::from([(identity, vec![1, 2])]));
        assert!(baseline.same_modeled_continuation(source, &candidate, source)?);

        *segment_objects(&mut candidate.checkpoint, signal) =
            Arc::new(BTreeMap::from([(identity, vec![1, 3])]));
        assert!(!baseline.same_modeled_continuation(source, &candidate, source)?);
    }
    Ok(())
}

#[test]
fn complete_modeled_comparison_authenticates_both_full_source_forms()
-> Result<(), Box<dyn std::error::Error>> {
    let _original = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)?;
    let directory = tempfile::tempdir()?;
    let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
    let baseline = load(directory.path(), &fixture)?;
    let candidate = load(directory.path(), &fixture)?;
    let source = fixture.source();
    let foreign = ScenarioDefForm::from_components_with_app_random_draw_cap(
        source.world(),
        source.plan(),
        source.properties(),
        source.seed(),
        source.app_random_draw_cap() + 1,
    )?;

    assert!(
        baseline
            .same_modeled_continuation(&foreign, &candidate, source)
            .is_err()
    );
    assert!(
        baseline
            .same_modeled_continuation(source, &candidate, &foreign)
            .is_err()
    );
    Ok(())
}
