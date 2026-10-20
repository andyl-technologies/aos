//! Exercises complete rebind data and the genuinely installed Clock state path.

use super::*;
use crucible_engine::node_contract::{
    ActivationRecord, Lifecycle, SavedRuntimeActivation, SavedRuntimeOperation, SavedRuntimeOwner,
    SavedRuntimeResult,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sample() -> Result<(RuntimeSnapshot, ActivationRecord), NodeObservedError> {
    let owner = OwnerIdentity {
        owner: Id::new("owner/clock")?,
        incarnation: Id::new("original")?,
        generation: 1.into(),
    };
    let cut = Position::new(1001.into(), 0.into(), Phase::BoundaryControl);
    let case = ExpectedClockCase::new(
        &Id::new("clock")?,
        std::slice::from_ref(&owner),
        &Id::new("original/operation")?,
        Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        cut,
        false,
    )?;
    let original = RuntimeSnapshot {
        schema_version: 1,
        source_activation: SavedRuntimeActivation {
            generation: 1.into(),
            activation_id: Id::new("activation/original")?,
            world_binding_hash: canonical::hash("clock-state-data-control", b"world")?,
            owners: vec![owner.clone()],
            boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        },
        capture_cut: cut,
        capture_ordinal: 7.into(),
        owners: vec![SavedRuntimeOwner {
            identity: owner.clone(),
            lifecycle: Lifecycle::Stopped,
            operation: None,
            domains: vec![Id::new("owner/clock")?],
        }],
        operations: vec![SavedRuntimeOperation {
            operation: Id::new("original/operation")?,
            route: crucible_engine::node_contract::NodeRoute {
                node: Id::new("clock")?,
                owners: vec![owner],
            },
            request: case.request,
            input_batch: None,
            result: SavedRuntimeResult::Acknowledged(case.outcome),
            close_submission: None,
            submission_effects: None,
            scheduling_commit: Some(crucible_engine::node_contract::SavedSchedulingCommit {
                node: Id::new("clock")?,
                operation: Id::new("original/operation")?,
                retained_outputs: vec![],
            }),
        }],
        inputs: vec![],
        terminal: None,
        condition_stop: None,
    };
    let target = ActivationRecord {
        generation: 2.into(),
        activation_id: Id::new("activation/fresh")?,
        world_binding_hash: original.source_activation.world_binding_hash.clone(),
        owners: vec![OwnerIdentity {
            owner: Id::new("owner/clock")?,
            incarnation: Id::new("fresh")?,
            generation: 2.into(),
        }],
        boundary: cut,
    };
    Ok((original, target))
}

fn rebased(original: &RuntimeSnapshot, target: &ActivationRecord) -> RuntimeSnapshot {
    // Test data follows the documented Core rebind, independent of the checker.
    let mut fresh = original.clone();
    fresh.source_activation = target.into();
    fresh.owners[0].identity = target.owners[0].clone();
    fresh.operations[0].route.owners = target.owners.clone();
    if let SavedRuntimeResult::Acknowledged(outcome) = &mut fresh.operations[0].result {
        outcome.owners = target.owners.clone();
        if let Some(observation) = &mut outcome.scheduling {
            observation.owners = target.owners.clone();
        }
    }
    fresh
}

#[test]
fn complete_clock_rebind_preserves_original_ack_and_proof_bytes() -> TestResult {
    let (original, target) = sample()?;
    let fresh = rebased(&original, &target);
    authenticate_restored_history(&original, &fresh, &target)?;
    assert_ne!(original.owners, fresh.owners);
    assert_eq!(
        original.operations[0].scheduling_commit,
        fresh.operations[0].scheduling_commit
    );
    Ok(())
}

#[test]
fn complete_clock_rebind_refuses_changed_history_and_reused_authority() -> TestResult {
    let (original, target) = sample()?;
    let fresh = rebased(&original, &target);
    for mutation in 0..5 {
        let mut changed = fresh.clone();
        match mutation {
            0 => {
                changed.operations[0].request = OperationRequest::BoundarySettle {
                    start: target.boundary,
                    limit: target.boundary,
                }
            }
            1 => changed.operations[0].scheduling_commit = None,
            2 => changed.operations[0].result = SavedRuntimeResult::Pending,
            3 => changed.operations[0].route.owners = original.operations[0].route.owners.clone(),
            4 => changed.owners[0].operation = Some(Id::new("unexpected")?),
            _ => return Err("unreachable mutation".into()),
        }
        assert!(authenticate_restored_history(&original, &changed, &target).is_err());
    }
    let mut reused = target.clone();
    reused.owners = original.source_activation.owners.clone();
    assert!(
        authenticate_restored_history(&original, &rebased(&original, &reused), &reused).is_err()
    );
    Ok(())
}

#[test]
#[ignore = "requires the genuine source-built CRUCIBLE_REFERENCE_DEVICE installed catalog artifact"]
fn actual_public_clock_retires_source_and_executes_two_independent_durable_continuations()
-> TestResult {
    use crate::node_observed_executor::StoredWorldActivationPublisher;
    use crucible_store::content_store::{
        DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
    };
    use std::{sync::Arc, time::Duration};

    let root = tempfile::tempdir()?;
    let original_namespace = root.path().join("original");
    let left_namespace = root.path().join("left");
    let right_namespace = root.path().join("right");
    for namespace in [&original_namespace, &left_namespace, &right_namespace] {
        std::fs::create_dir(namespace)?;
    }
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE")?);
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        super::super::super::measure_executable(&executable)?,
        original_namespace,
        Duration::from_secs(5),
        4,
    )?;
    let profile = catalog.installed_normal_clock()?;
    let mut original = catalog
        .prepare_original_clock_qualification(&profile, ExecutionId::from_bytes([91; 16])?)?;
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "public-clock-state",
        root.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(root.path().join("refs")));
    let publisher =
        |name: &str| -> Result<StoredWorldActivationPublisher, Box<dyn std::error::Error>> {
            Ok(StoredWorldActivationPublisher::new(
                blobs.clone(),
                refs.clone(),
                RefName::new(format!("node-world-activations/{name}"))?,
            )?)
        };
    original.activate(&mut publisher("clock-state-original")?)?;
    for (name, _, _) in CASES {
        assert_eq!(original.execute_next()?, name);
    }
    original.execute_original_pause()?;
    assert!(original.pause.acknowledged);
    let mut state = OriginalClockStateProgramme::new(
        &catalog,
        root.path().join("archive"),
        [left_namespace, right_namespace],
        [
            ExecutionId::from_bytes([92; 16])?,
            ExecutionId::from_bytes([93; 16])?,
        ],
    )?;
    state.capture_and_retire_original(&mut original, &catalog)?;
    assert!(original.runtime.is_none());
    assert!(original.execute_next().is_err());
    assert_eq!(
        original
            .retired
            .as_ref()
            .ok_or("original retirement absent")?
            .remaining_owners(),
        0
    );
    state.execute_branch(0, &mut publisher("clock-state-left")?)?;
    state.execute_branch(1, &mut publisher("clock-state-right")?)?;
    state.authenticate_repeatable_continuations()?;
    assert!(state.compared_data());
    assert!(state.artifact_data().is_some());
    assert!(
        state
            .execute_branch(0, &mut publisher("clock-state-no-retry")?)
            .is_err()
    );
    Ok(())
}
